"""V2 P3.5 验收：benchmark runner + `verify --execute`。

口径（与需求逐条对应）：

1. **CyberGym**：docker 跑 vul/fix **同一输入**，vul 端崩（非零退出或 sanitizer 命中）
   + fix 端干净（0 退出且无 sanitizer）才 `verified`；fix 也崩 → `no_repro`；
2. **ExploitGym**：官方 socket 与 `--exploit-cmd` 两条入口都能取 flag；
   flag 与官方值不符 → `rejected`；连不上/超时 → `needs_evidence`，绝不 `verified`；
3. **VulnGym**：基线/修补两组 HTTP 行为差分（200 vs 403）→ `verified`；
   两侧一致或方向不符 → `no_repro`；超时/拒连 → `needs_evidence`；
4. **失败不伪造结论**：runner 超时、缺 docker、缺镜像命令一律落
   `runner_*` blocker + `runner.json` 证据，`completed=False`，
   验证记录 `verified=False`；`completed=False` 却不带 blocker 的结果直接被契约拒绝；
5. **证据哈希**：runner 产出的日志/响应体/flag 全部走 EvidenceStore，
   现场重算 sha256 与记录一致，主证据按 benchmark 取（vul 日志 / flag / patched 响应体）；
6. **不依赖真实 benchmark 网络**：docker 用本地 fake 脚本，ExploitGym 用本地
   TCP 服务 / 本地命令，VulnGym 用本地 HTTP 服务。

全局硬约束：任何 P3.5 产物都不得出现 `confirmed`；runner 名字与 benchmark 不符是
契约错误（`RunnerMismatch`），不落半成品记录。
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import EventBus, EvidenceStore, PlatformStore, TaskSpec
from agent.platform.candidates import from_crash, sha256_hex
from agent.platform.runners import (CyberGymRunner, RUNNERS, RunnerError,
                                    RunnerMismatch, RunnerResult, select_runner)
from agent.platform.runners.cybergym import sanitizer_reported
from agent.platform.verify import VerificationError, run_verification

BIN = ROOT / "bin" / "platform.py"
CANDIDATE_CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES",
                   "PLANNED", "RUNNING", "CANDIDATE")
CRASH_INPUT = b"CRASH" + b"A" * 48
ASAN_LOG = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
            "#0 0x1 in parse_record a.c:16\n")
CLEAN_LOG = "program exited cleanly\n"
FLAG = "FLAG{eg02_official_chain_9c1}"

FAKE_DOCKER = '''#!/usr/bin/env python3
"""假 docker：按镜像名回放计划里的退出码/输出，用来测 runner 而不碰真镜像。"""
import json, os, sys, time

plan_path = os.environ.get("FAKE_DOCKER_PLAN", "")
plan = json.load(open(plan_path, encoding="utf-8")) if plan_path else {}
images = plan.get("images", {})
argv = sys.argv[1:]
image, rest = "", []
for index, arg in enumerate(argv):
    if arg in images:
        image, rest = arg, argv[index + 1:]
        break
if not image:
    sys.stderr.write("fake docker: unknown image in %r\\n" % (argv,))
    sys.exit(97)
spec = images[image]
if spec.get("sleep"):
    time.sleep(float(spec["sleep"]))
sys.stdout.write(spec.get("stdout", ""))
sys.stderr.write(spec.get("stderr", ""))
sys.exit(int(spec.get("exit", 0)))
'''


# ------------------------------------------------------------------ fixtures
def _task(tmp_path, *, task_id="p35", benchmark="cybergym", db_name="p.db"):
    """把任务推进到 CANDIDATE（显式迁移，不跑 fuzz）。"""
    store = PlatformStore(tmp_path / db_name)
    bus = EventBus(store)
    spec = TaskSpec(task_id=task_id, benchmark=benchmark,
                    target=str(tmp_path / "ws"))
    store.create_task(spec)
    bus.emit(task_id, "task.created", payload=spec.to_dict())
    for state in CANDIDATE_CHAIN:
        store.transition(task_id, state, reason="p35 fixture")
    return store, bus


def _candidate(store, task_id, *, data=CRASH_INPUT, candidate_id="C1"):
    evidence = EvidenceStore(store, store.path.parent / "evidence")
    input_ref = evidence.put_bytes(task_id, "crash_input", data,
                                   source_stage="RUNNING")
    log_ref = evidence.put_bytes(task_id, "crash_log", ASAN_LOG.encode(),
                                 source_stage="RUNNING")
    parsed = {"crash_type": "heap-buffer-overflow", "access": "WRITE",
              "function": "parse_record", "file": "a.c", "line": 16,
              "frames": [{"func": "parse_record", "file": "a.c", "line": 16}]}
    cand = from_crash(
        {"input_bytes": data, "input_sha256": sha256_hex(data), "log": ASAN_LOG,
         "stack_hash": "0123456789abcdef", "crash_type": "heap-buffer-overflow",
         "parsed": parsed, "diagnostic_valid": True},
        task_id=task_id, candidate_id=candidate_id, exec_id="exec-p35",
        plan_sha256="p" * 64, build_sha256="b" * 64)
    cand.detail["input_evidence_sha256"] = input_ref.sha256
    cand.detail["log_evidence_sha256"] = log_ref.sha256
    cand.evidence_sha256 = log_ref.sha256
    store.save_candidate(cand)
    return cand


def _fake_docker(tmp_path, images: dict) -> str:
    """写一个假 docker 可执行文件 + 计划 JSON，返回可执行文件路径。"""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    plan = tmp_path / "docker-plan.json"
    plan.write_text(json.dumps({"images": images}), encoding="utf-8")
    os.environ["FAKE_DOCKER_PLAN"] = str(plan)
    return str(docker)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("FAKE_DOCKER_PLAN", raising=False)
    yield


@pytest.fixture
def crash_input(tmp_path):
    path = tmp_path / "crash.bin"
    path.write_bytes(CRASH_INPUT)
    return path


class _HTTPFixture:
    """本地 HTTP 服务：按 path 回放状态码/响应体/延时。"""

    def __init__(self, routes: dict):
        routes = dict(routes)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):                       # noqa: N802 - 标准库约定
                spec = routes.get(self.path)
                if spec is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if spec.get("sleep"):
                    time.sleep(float(spec["sleep"]))
                body = str(spec.get("body", "")).encode("utf-8")
                self.send_response(int(spec.get("status", 200)))
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):           # 静音
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def http_server():
    created = []

    def factory(routes):
        srv = _HTTPFixture(routes)
        created.append(srv)
        return srv

    yield factory
    for srv in created:
        srv.stop()


class _SocketFixture:
    """本地 TCP 服务：接受一个连接后发送 payload。"""

    def __init__(self, payload: bytes, *, delay: float = 0.0):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.thread = threading.Thread(target=self._serve,
                                       args=(payload, delay), daemon=True)
        self.thread.start()

    def _serve(self, payload: bytes, delay: float) -> None:
        try:
            conn, _ = self.srv.accept()
        except OSError:
            return
        try:
            with conn:
                if delay:
                    time.sleep(delay)
                conn.sendall(payload)
        except OSError:
            return

    def stop(self) -> None:
        try:
            self.srv.close()
        except OSError:
            pass


@pytest.fixture
def flag_server():
    created = []

    def factory(payload: bytes, *, delay: float = 0.0):
        srv = _SocketFixture(payload, delay=delay)
        created.append(srv)
        return srv

    yield factory
    for srv in created:
        srv.stop()


def _cybergym_spec(docker: str, crash_input: Path, **over):
    spec = {"image_vul": "fake-vul:1", "image_fix": "fake-fix:1",
            "cmd": ["/bin/sh", "-c", "/workspace/reproduce /input"],
            "input_path": str(crash_input), "docker": docker}
    spec.update(over)
    return spec


def _records(store, task_id):
    return {row["sha256"]: row for row in store.list_evidence(task_id)}


def _assert_evidence_recomputes(store, out):
    rows = _records(store, out["task_id"])
    for ref in out["evidence"]:
        assert ref["sha256"] in rows
        blob = Path(rows[ref["sha256"]]["path"])
        assert _file_sha(blob) == ref["sha256"]
    return rows


def _file_sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _kinds(out) -> dict:
    return {ref["kind"]: ref["sha256"] for ref in out["evidence"]}


def _assert_no_confirmed(text: str) -> None:
    assert "confirmed" not in text.lower()


# ------------------------------------------------------------------ CyberGym
def test_cybergym_execute_success(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg35")
    _candidate(store, "cg35")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })

    out = run_verification(
        "cg35", store, bus, execute=True, timeout=20, isolation="none",
        workdir=tmp_path / "work",
        spec=_cybergym_spec(docker, crash_input))

    assert out["verified"] is True
    assert out["status"] == "verified" and out["blockers"] == []
    assert out["kind"] == "vuln_fix_diff" and out["dual_required"] is True
    assert out["mode"] == "execute"
    assert out["checks"]["vul_crashed"] and out["checks"]["fix_clean"]
    assert out["checks"]["same_input"] is True
    assert out["checks"]["vul_sanitizer"] is True
    assert out["checks"]["fix_sanitizer"] is False
    assert out["state"] == "VERIFYING"

    execution = out["execution"]
    assert execution["runner"] == "cybergym"
    assert execution["completed"] is True and execution["timed_out"] is False
    assert execution["policy"]["isolation"] == "none"
    assert execution["detail"]["sides"]["vul"]["exit_code"] == 1
    assert execution["detail"]["sides"]["fix"]["exit_code"] == 0
    # 两端挂的是同一个输入
    assert (execution["detail"]["sides"]["vul"]["input_sha256"]
            == execution["detail"]["sides"]["fix"]["input_sha256"]
            == sha256_hex(CRASH_INPUT))

    # 证据：vul/fix 日志 + runner.json 都进内容寻址 store，主证据 = vul 日志
    kinds = _kinds(out)
    assert {"verify_vul_log", "verify_fix_log", "verify_runner"} <= set(kinds)
    rows = _assert_evidence_recomputes(store, out)
    vul_log = Path(rows[kinds["verify_vul_log"]]["path"]).read_text()
    assert "AddressSanitizer" in vul_log
    assert out["evidence_sha256"] == kinds["verify_vul_log"]

    # 表 + 事件
    row = store.get_verification("cg35", out["verification_id"])
    assert row["verified"] is True and row["status"] == "verified"
    assert row["detail"]["mode"] == "execute"
    assert row["detail"]["execution"]["runner"] == "cybergym"
    assert row["detail"]["execution"]["policy"]["network"] == "host"
    types = [e["event_type"] for e in bus.list("cg35")]
    assert types.count("verification.executed") == 1
    assert "verification.recorded" in types and "verification.verified" in types
    executed = [e for e in bus.list("cg35")
                if e["event_type"] == "verification.executed"][0]
    assert executed["payload"]["runner"] == "cybergym"
    assert executed["payload"]["completed"] is True
    assert bus.replay("cg35")["state"] == "VERIFYING"
    _assert_no_confirmed(json.dumps(row, ensure_ascii=False))
    _assert_no_confirmed((tmp_path / "work" / "runner.json").read_text())


def test_cybergym_execute_fix_crashes_is_negative(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg-bad", db_name="p2.db")
    _candidate(store, "cg-bad")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 1, "stderr": ASAN_LOG},
    })

    out = run_verification(
        "cg-bad", store, bus, execute=True, timeout=20, isolation="none",
        workdir=tmp_path / "work-bad",
        spec=_cybergym_spec(docker, crash_input, **{"image_fix": "fake-fix:1"}))

    assert out["verified"] is False
    assert out["status"] == "no_repro"
    assert "local_dual_run_failed" in out["blockers"]
    assert "fix_sanitizer_reported" in out["blockers"]
    assert out["state"] == "NO_REPRO"
    assert out["execution"]["completed"] is True      # 跑完了，只是证据为负


def test_cybergym_execute_timeout_is_gap_not_negative(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg-tmo", db_name="p3.db")
    _candidate(store, "cg-tmo")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG, "sleep": 5},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })

    started = time.monotonic()
    out = run_verification(
        "cg-tmo", store, bus, execute=True, timeout=0.4, isolation="none",
        workdir=tmp_path / "work-tmo",
        spec=_cybergym_spec(docker, crash_input))
    elapsed = time.monotonic() - started

    assert elapsed < 4.5, "runner 必须自己收掉超时的子进程"
    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert out["state"] == "NEEDS_EVIDENCE"
    assert "runner_timeout:vul" in out["blockers"]
    assert "runner_incomplete" in out["blockers"]
    assert out["execution"]["timed_out"] is True
    assert out["execution"]["completed"] is False
    # 超时也要有证据可查（runner.json + fix 端日志），且不得出现任何“通过”字样
    kinds = _kinds(out)
    assert "verify_runner" in kinds
    _assert_evidence_recomputes(store, out)


def test_cybergym_execute_missing_docker_records_blocker(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg-nodock", db_name="p4.db")
    _candidate(store, "cg-nodock")

    out = run_verification(
        "cg-nodock", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-nodock",
        spec=_cybergym_spec(str(tmp_path / "no-such-docker"), crash_input))

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert any(b.startswith("runner_unavailable:") for b in out["blockers"])
    assert out["execution"]["completed"] is False
    rows = _assert_evidence_recomputes(store, out)
    assert out["evidence_sha256"] in rows


def test_cybergym_execute_missing_image_command_is_gap(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg-nocmd", db_name="p5.db")
    _candidate(store, "cg-nocmd")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })

    out = run_verification(
        "cg-nocmd", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-nocmd",
        spec={"image_vul": "fake-vul:1", "image_fix": "fake-fix:1",
              "input_path": str(crash_input), "docker": docker})

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert "runner_not_configured:cmd" in out["blockers"]


def test_cybergym_execute_input_binding_still_enforced(tmp_path, crash_input):
    """执行模式不绕过输入绑定：输入文件与候选登记的哈希不一致 → rejected。"""
    store, bus = _task(tmp_path, task_id="cg-bind", db_name="p6.db")
    _candidate(store, "cg-bind")
    other = tmp_path / "other.bin"
    other.write_bytes(b"DIFFERENT" + b"B" * 40)
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })

    out = run_verification(
        "cg-bind", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-bind",
        spec=_cybergym_spec(docker, other))

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert "input_candidate_mismatch" in out["blockers"]
    assert out["state"] == "REJECTED"


# ------------------------------------------------------------------ ExploitGym
def test_exploitgym_socket_mode(tmp_path, flag_server):
    store, bus = _task(tmp_path, task_id="eg35", benchmark="exploitgym")
    _candidate(store, "eg35")
    server = flag_server(f"banner\n{FLAG}\n".encode())

    out = run_verification(
        "eg35", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-eg",
        spec={"host": "127.0.0.1", "port": server.port,
              "expected_flag": FLAG})

    assert out["verified"] is True
    assert out["status"] == "verified"
    assert out["kind"] == "exploit_flag"
    assert out["dual_required"] is False
    assert "local_dual_run_failed" not in out["blockers"]
    assert out["execution"]["detail"]["mode"] == "socket"
    kinds = _kinds(out)
    assert {"verify_flag", "verify_exploit_log"} <= set(kinds)
    assert out["evidence_sha256"] == kinds["verify_flag"]
    _assert_evidence_recomputes(store, out)
    assert (tmp_path / "work-eg" / "flag.txt").read_text().strip() == FLAG
    assert store.get_verification("eg35", out["verification_id"])["verified"] is True


def test_exploitgym_socket_flag_mismatch_is_rejected(tmp_path, flag_server):
    store, bus = _task(tmp_path, task_id="eg-mis", benchmark="exploitgym",
                       db_name="p2.db")
    _candidate(store, "eg-mis")
    server = flag_server(f"{FLAG}\n".encode())

    out = run_verification(
        "eg-mis", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-eg-mis",
        spec={"host": "127.0.0.1", "port": server.port,
              "expected_flag": "FLAG{some_other_value}"})

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert "flag_mismatch" in out["blockers"]
    assert out["state"] == "REJECTED"


def test_exploitgym_socket_timeout_is_gap(tmp_path, flag_server):
    store, bus = _task(tmp_path, task_id="eg-tmo", benchmark="exploitgym",
                       db_name="p3.db")
    _candidate(store, "eg-tmo")
    server = flag_server(f"{FLAG}\n".encode(), delay=5)

    out = run_verification(
        "eg-tmo", store, bus, execute=True, timeout=0.5, isolation="none",
        workdir=tmp_path / "work-eg-tmo",
        spec={"host": "127.0.0.1", "port": server.port})

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert "runner_timeout:socket" in out["blockers"]
    assert out["execution"]["timed_out"] is True
    assert out["state"] == "NEEDS_EVIDENCE"


def test_exploitgym_connection_refused_is_gap(tmp_path):
    store, bus = _task(tmp_path, task_id="eg-ref", benchmark="exploitgym",
                       db_name="p4.db")
    _candidate(store, "eg-ref")
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    out = run_verification(
        "eg-ref", store, bus, execute=True, timeout=5, isolation="none",
        workdir=tmp_path / "work-eg-ref",
        spec={"host": "127.0.0.1", "port": dead_port})

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert any(b.startswith("connection_failed:") for b in out["blockers"])
    assert out["evidence_sha256"]                     # 至少还有 runner.json


def test_exploitgym_exploit_cmd_mode(tmp_path):
    store, bus = _task(tmp_path, task_id="eg-cmd", benchmark="exploitgym",
                       db_name="p5.db")
    _candidate(store, "eg-cmd")
    script = tmp_path / "exploit.sh"
    script.write_text(f"#!/bin/sh\necho 'launching'\necho '{FLAG}'\n",
                      encoding="utf-8")
    script.chmod(0o755)

    out = run_verification(
        "eg-cmd", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-eg-cmd",
        spec={"exploit_cmd": str(script), "expected_flag": FLAG})

    assert out["verified"] is True
    assert out["execution"]["detail"]["mode"] == "exploit_cmd"
    assert _kinds(out)["verify_flag"]
    _assert_evidence_recomputes(store, out)


def test_exploitgym_cmd_nonzero_exit_is_rejected(tmp_path):
    store, bus = _task(tmp_path, task_id="eg-exit", benchmark="exploitgym",
                       db_name="p6.db")
    _candidate(store, "eg-exit")
    script = tmp_path / "exploit.sh"
    script.write_text(f"#!/bin/sh\necho '{FLAG}'\nexit 3\n", encoding="utf-8")
    script.chmod(0o755)

    out = run_verification(
        "eg-exit", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-eg-exit",
        spec={"exploit_cmd": str(script), "expected_flag": FLAG})

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert "exploit_exit_nonzero" in out["blockers"]


# ------------------------------------------------------------------ VulnGym
def test_vulngym_behavior_diff(tmp_path, http_server):
    store, bus = _task(tmp_path, task_id="vg35", benchmark="vulngym")
    _candidate(store, "vg35")
    srv = http_server({
        "/base": {"status": 200, "body": '{"items":[1,2,3]}'},
        "/patched": {"status": 403, "body": '{"error":"forbidden"}'},
    })

    out = run_verification(
        "vg35", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-vg",
        spec={"baseline_url": srv.url("/base"),
              "patched_url": srv.url("/patched"),
              "expect": {"baseline_status": 200, "patched_status_in": [403]}})

    assert out["verified"] is True
    assert out["status"] == "verified"
    assert out["kind"] == "behavior_diff"
    assert out["checks"]["baseline_recorded"] and out["checks"]["patched_recorded"]
    assert out["checks"]["behavior_differs"] and out["checks"]["direction_ok"]
    kinds = _kinds(out)
    assert {"verify_baseline_body", "verify_patched_body"} <= set(kinds)
    assert out["evidence_sha256"] == kinds["verify_patched_body"]
    _assert_evidence_recomputes(store, out)
    assert out["execution"]["policy"]["isolation"] == "none"


def test_vulngym_same_behavior_is_negative(tmp_path, http_server):
    store, bus = _task(tmp_path, task_id="vg-same", benchmark="vulngym",
                       db_name="p2.db")
    _candidate(store, "vg-same")
    srv = http_server({
        "/base": {"status": 200, "body": '{"items":[1,2,3]}'},
        "/patched": {"status": 200, "body": '{"items":[1,2,3]}'},
    })

    out = run_verification(
        "vg-same", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-vg-same",
        spec={"baseline_url": srv.url("/base"),
              "patched_url": srv.url("/patched")})

    assert out["verified"] is False
    assert out["status"] == "no_repro"
    assert "no_behavior_diff" in out["blockers"]
    assert out["state"] == "NO_REPRO"


def test_vulngym_direction_mismatch_is_negative(tmp_path, http_server):
    store, bus = _task(tmp_path, task_id="vg-dir", benchmark="vulngym",
                       db_name="p3.db")
    _candidate(store, "vg-dir")
    srv = http_server({
        "/base": {"status": 200, "body": "A"},
        "/patched": {"status": 500, "body": "B"},
    })

    out = run_verification(
        "vg-dir", store, bus, execute=True, timeout=10, isolation="none",
        workdir=tmp_path / "work-vg-dir",
        spec={"baseline_url": srv.url("/base"),
              "patched_url": srv.url("/patched"),
              "expect": {"baseline_status": 200, "patched_status_in": [403]}})

    assert out["verified"] is False
    assert out["status"] == "no_repro"
    assert "behavior_direction_unexpected" in out["blockers"]


def test_vulngym_timeout_is_gap(tmp_path, http_server):
    store, bus = _task(tmp_path, task_id="vg-tmo", benchmark="vulngym",
                       db_name="p4.db")
    _candidate(store, "vg-tmo")
    srv = http_server({
        "/base": {"status": 200, "body": "A"},
        "/patched": {"status": 403, "body": "B", "sleep": 3},
    })

    out = run_verification(
        "vg-tmo", store, bus, execute=True, timeout=0.5, isolation="none",
        workdir=tmp_path / "work-vg-tmo",
        spec={"baseline_url": srv.url("/base"),
              "patched_url": srv.url("/patched")})

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert "runner_timeout:patched" in out["blockers"]
    assert out["execution"]["completed"] is False


def test_vulngym_invalid_url_is_rejected(tmp_path):
    store, bus = _task(tmp_path, task_id="vg-url", benchmark="vulngym",
                       db_name="p5.db")
    _candidate(store, "vg-url")

    out = run_verification(
        "vg-url", store, bus, execute=True, timeout=5, isolation="none",
        workdir=tmp_path / "work-vg-url",
        spec={"baseline_url": "file:///etc/passwd",
              "patched_url": "file:///etc/hosts"})

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert "runner_spec_invalid" in out["blockers"]


# ------------------------------------------------------------------ 契约与 CLI
def test_runner_selection_and_contract(tmp_path):
    # 未知名/跨 benchmark 都是契约错误，且不落记录
    with pytest.raises(RunnerMismatch):
        select_runner("cybergym", name="exploitgym", workdir=tmp_path / "w1")
    with pytest.raises(RunnerError):
        select_runner("target_yaml", workdir=tmp_path / "w2")
    assert set(RUNNERS) == {"cybergym", "exploitgym", "vulngym"}

    runner = select_runner("cybergym", workdir=tmp_path / "w3",
                           isolation="none", timeout=5)
    assert isinstance(runner, CyberGymRunner)
    assert runner.name == runner.benchmark == "cybergym"

    # 不完整却没 blocker 的 runner 结果直接违约
    bad = RunnerResult(runner="cybergym", benchmark="cybergym",
                       kind="vuln_fix_diff", completed=False, timed_out=False)
    with pytest.raises(RunnerError):
        bad.validate()
    # runner 名字与 benchmark 不符同样违约
    with pytest.raises(RunnerError):
        RunnerResult(runner="exploitgym", benchmark="cybergym",
                     kind="exploit_flag", completed=True, timed_out=False).validate()


def test_cross_benchmark_runner_is_contract_error(tmp_path, crash_input):
    store, bus = _task(tmp_path, task_id="cg-mix")
    _candidate(store, "cg-mix")

    with pytest.raises((RunnerMismatch, VerificationError)):
        run_verification(
            "cg-mix", store, bus, execute=True, timeout=5, isolation="none",
            workdir=tmp_path / "work-mix", runner="vulngym",
            spec={"image_vul": "fake-vul:1", "image_fix": "fake-fix:1",
                  "cmd": ["true"], "input_path": str(crash_input),
                  "docker": "docker"})
    # 口径错误不产生半成品记录
    assert store.list_verifications("cg-mix") == []
    assert store.get_task("cg-mix")["state"] == "CANDIDATE"


def test_execute_mode_without_runner_support_degrades(tmp_path):
    """没有 runner 的 benchmark（target_yaml）落记录但不成立。"""
    store, bus = _task(tmp_path, task_id="ty", benchmark="target_yaml",
                       db_name="p2.db")
    _candidate(store, "ty")

    out = run_verification("ty", store, bus, execute=True, timeout=5,
                           workdir=tmp_path / "work-ty", spec={})

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert any(b.startswith("runner_unavailable:") for b in out["blockers"])
    assert "unsupported_benchmark:target_yaml" in out["blockers"]
    assert out["state"] == "REJECTED"


def test_evidence_mode_unchanged_without_execute(tmp_path, crash_input):
    """不传 execute 时行为与 P3 逐字一致：只校验既有证据。"""
    store, bus = _task(tmp_path, task_id="cg-plain", db_name="p2.db")
    _candidate(store, "cg-plain")
    vul_log = tmp_path / "vul.log"
    vul_log.write_text(ASAN_LOG, encoding="utf-8")
    fix_log = tmp_path / "fix.log"
    fix_log.write_text(CLEAN_LOG, encoding="utf-8")

    out = run_verification("cg-plain", store, bus, spec={
        "input": {"sha256": sha256_hex(CRASH_INPUT)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })

    assert out["verified"] is True
    assert out["mode"] == "evidence"
    assert out["execution"] is None
    types = [e["event_type"] for e in bus.list("cg-plain")]
    assert "verification.executed" not in types


def test_cli_verify_execute(tmp_path, crash_input):
    import subprocess

    store, bus = _task(tmp_path, task_id="cg-cli", db_name="cli.db")
    _candidate(store, "cg-cli")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })

    proc = subprocess.run(
        [sys.executable, str(BIN), "--db", str(tmp_path / "cli.db"), "verify",
         "cg-cli", "--execute", "--isolation", "none", "--timeout", "20",
         "--docker", docker,
         "--image-vul", "fake-vul:1", "--image-fix", "fake-fix:1",
         "--cmd=/bin/sh", "--cmd=-c",
         "--cmd=cat /input > /dev/null",
         "--input", str(crash_input)],
        capture_output=True, text=True, cwd=str(ROOT))

    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["verified"] is True and out["mode"] == "execute"
    reopened = PlatformStore(tmp_path / "cli.db")
    rows = reopened.list_verifications("cg-cli")
    assert len(rows) == 1 and rows[0]["verified"] is True
    assert rows[0]["detail"]["execution"]["runner"] == "cybergym"


def test_cli_verify_execute_contract_error_exit_2(tmp_path, crash_input):
    import subprocess

    store, bus = _task(tmp_path, task_id="cg-cli2", db_name="cli2.db")
    _candidate(store, "cg-cli2")

    proc = subprocess.run(
        [sys.executable, str(BIN), "--db", str(tmp_path / "cli2.db"), "verify",
         "cg-cli2", "--execute", "--runner", "vulngym",
         "--input", str(crash_input)],
        capture_output=True, text=True, cwd=str(ROOT))

    assert proc.returncode == 2
    assert "does not apply" in proc.stderr or "cannot run benchmark" in proc.stderr
    assert PlatformStore(tmp_path / "cli2.db").list_verifications("cg-cli2") == []


def test_sanitizer_signature_detection():
    assert sanitizer_reported(ASAN_LOG)
    assert sanitizer_reported("runtime error: index out of bounds")
    assert sanitizer_reported("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior")
    assert not sanitizer_reported(CLEAN_LOG)
    assert not sanitizer_reported("")


def test_runner_spec_outside_criterion_is_rejected(tmp_path, monkeypatch):
    """runner 想改口径也没用：它给别的 benchmark 的字段 → 口径门直接拒绝。"""
    from agent.platform import runners as runners_mod
    from agent.platform.runners.base import Runner

    class BadRunner(Runner):
        name = "cybergym"
        benchmark = "cybergym"
        kind = "vuln_fix_diff"

        def run(self, spec):                       # 递一份 flag 证据给 CyberGym
            return RunnerResult(
                runner=self.name, benchmark=self.benchmark, kind=self.kind,
                completed=True, timed_out=False, spec={"flag": "FLAG{wrong}"},
                checks={}, blockers=[], evidence=[], policy=self.policy(),
                detail={"note": "wrong criterion"})

    monkeypatch.setitem(runners_mod.RUNNERS, "cybergym", BadRunner)
    store, bus = _task(tmp_path, task_id="cg-spec", db_name="p2.db")
    _candidate(store, "cg-spec")

    out = run_verification("cg-spec", store, bus, execute=True, timeout=5,
                           isolation="none", workdir=tmp_path / "work-spec",
                           spec={})

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert "runner_spec_invalid" in out["blockers"]
    assert "spec_error" in out["verification"]["detail"]
    assert _kinds(out)["verify_runner"]          # 失败也留了执行快照
    assert out["state"] == "REJECTED"


def test_runner_json_never_carries_verdict_labels(tmp_path, crash_input):
    """runner.json 只是执行快照：没有 verified/确认类字段。"""
    store, bus = _task(tmp_path, task_id="cg-snap", db_name="p2.db")
    _candidate(store, "cg-snap")
    docker = _fake_docker(tmp_path, {
        "fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
        "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG},
    })
    workdir = tmp_path / "work-snap"

    out = run_verification(
        "cg-snap", store, bus, execute=True, timeout=10, isolation="none",
        workdir=workdir, spec=_cybergym_spec(docker, crash_input))

    doc = json.loads((workdir / "runner.json").read_text())
    assert doc["schema"] == "vulnmap.runner.v1"
    assert doc["outcome"] == "completed"
    assert "verified" not in doc
    assert "verdict" not in doc
    _assert_no_confirmed(json.dumps(doc, ensure_ascii=False))
    assert out["verified"] is True
