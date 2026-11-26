"""V2 P3.8 验收：runner spec 自动生成 + `verify --execute --auto` + `smoke`。

口径（与需求逐条对应）：

1. **自动 spec 字段映射**：CyberGym 读 `image_vul`/`image_fix` + `harness_cmd`/`entry`；
   ExploitGym 读 `image`/`mode`/`task_info`（socket 或 `exploit_cmd`）；
   VulnGym 读 `service_url` 或 `baseline_url`+`patched_url`；
2. **缺字段列 blockers**：缺什么就写什么（`runner_not_configured:*`），
   这些 blocker 属于缺口词表 → `needs_evidence`，不是负结果；
3. **本机能不能跑是事实**：没有 docker / 没有镜像 / socket 连不上 / HTTP 不可达时
   `smoke` 必须如实 `needs_evidence`，并且**不启动** runner
   （`docker run` 对缺镜像返回 125，那不能冒充“vul 端崩了”）；
4. **成功路径**：fake docker（`image inspect` + `run`）与本地 TCP/HTTP 服务下，
   `--auto` 能跑出 `verified`；`smoke --execute` 只报 `would_verify`、不落验证记录；
5. **不写 verified**：缺口路径的 `verified` 恒为 False，事件与记录里都带
   `auto`/`executed` 快照；`smoke` 产物 `persisted=false`。

全部测试使用本地 fake（docker 脚本 / TCP / HTTP），不访问真实 benchmark 网络。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
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
from agent.platform.runners.spec import (SpecError, build_runner_spec,
                                         docker_path, image_probe,
                                         load_task_json, summarize, tcp_probe)
from agent.platform.verify import run_verification

BIN = ROOT / "bin" / "platform.py"
CANDIDATE_CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES",
                   "PLANNED", "RUNNING", "CANDIDATE")
CRASH_INPUT = b"CRASH" + b"A" * 48
ASAN_LOG = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
            "#0 0x1 in parse_record a.c:16\n")
CLEAN_LOG = "program exited cleanly\n"
FLAG = "FLAG{e2e_auto_spec_7b1}"

FAKE_DOCKER = '''#!/usr/bin/env python3
"""假 docker：`image inspect` 报镜像是否存在，`run` 回放计划里的行为。"""
import json, os, sys, time

plan_path = os.environ.get("FAKE_DOCKER_PLAN", "")
plan = json.load(open(plan_path, encoding="utf-8")) if plan_path else {}
present = set(plan.get("present", []))
images = plan.get("images", {})
argv = sys.argv[1:]

if argv[:2] == ["image", "inspect"]:
    image = argv[2] if len(argv) > 2 else ""
    if plan.get("daemon_down"):
        sys.stderr.write(
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
            "Is the docker daemon running?\\n")
        sys.exit(1)
    if image in present:
        sys.stdout.write("[]\\n")
        sys.exit(0)
    sys.stderr.write("Error response from daemon: No such image: %s\\n" % image)
    sys.exit(1)

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

CG_TASK = {
    "schema": "vulnmap.task.v1", "case_id": "CG-01",
    "task_id": "arvo:44034", "benchmark": "cybergym",
    "project": "ghostscript", "image_vul": "n132/arvo:44034-vul",
    "image_fix": "n132/arvo:44034-fix",
}


# ------------------------------------------------------------------ fixtures
def _task(tmp_path, *, task_id="e2e", benchmark="cybergym",
          metadata=None, target=None, db_name="p.db"):
    store = PlatformStore(tmp_path / db_name)
    bus = EventBus(store)
    ws = Path(target) if target else (tmp_path / "ws")
    ws.mkdir(parents=True, exist_ok=True)
    spec = TaskSpec(task_id=task_id, benchmark=benchmark, target=str(ws),
                    metadata=dict(metadata or {}))
    store.create_task(spec)
    bus.emit(task_id, "task.created", payload=spec.to_dict())
    for state in CANDIDATE_CHAIN:
        store.transition(task_id, state, reason="p38 fixture")
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
        task_id=task_id, candidate_id=candidate_id, exec_id="exec-e2e",
        plan_sha256="p" * 64, build_sha256="b" * 64)
    cand.detail["input_evidence_sha256"] = input_ref.sha256
    cand.detail["log_evidence_sha256"] = log_ref.sha256
    cand.evidence_sha256 = log_ref.sha256
    store.save_candidate(cand)
    return cand


def _fake_docker(tmp_path, *, present=(), images=None, daemon_down=False) -> str:
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    plan = tmp_path / "docker-plan.json"
    plan.write_text(json.dumps({"present": list(present),
                                "images": dict(images or {}),
                                "daemon_down": bool(daemon_down)}),
                    encoding="utf-8")
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
    """本地 TCP 服务：每个连接都回同一个 payload（探测 + 正式取 flag 各一次）。"""

    def __init__(self, payload: bytes, *, delay: float = 0.0):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve,
                                       args=(payload, delay), daemon=True)
        self.thread.start()

    def _serve(self, payload: bytes, delay: float) -> None:
        while self.running:
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
                continue

    def stop(self) -> None:
        self.running = False
        try:
            self.srv.close()
        except OSError:
            pass


@pytest.fixture
def flag_server():
    created = []

    def factory(payload: bytes = FLAG.encode(), *, delay: float = 0.0):
        srv = _SocketFixture(payload, delay=delay)
        created.append(srv)
        return srv

    yield factory
    for srv in created:
        srv.stop()


def _closed_port() -> int:
    """拿一个刚关掉的端口（连接必然被拒）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _workspace(tmp_path, task_json: dict, name="ws") -> Path:
    ws = tmp_path / name
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "task.json").write_text(json.dumps(task_json, ensure_ascii=False),
                                  encoding="utf-8")
    return ws


def _kinds(out) -> dict:
    return {ref["kind"]: ref["sha256"] for ref in out["evidence"]}


def _assert_no_confirmed(text: str) -> None:
    assert "confirmed" not in text.lower()


# ------------------------------------------------------------------ spec 映射
def test_spec_cybergym_reads_task_json_and_metadata(tmp_path, crash_input):
    ws = _workspace(tmp_path, CG_TASK)
    doc = build_runner_spec(
        workspace=ws, probe=False,
        metadata={"harness_cmd": "/workspace/reproduce /input",
                  "input_path": str(crash_input)})

    assert doc["schema"] == "vulnmap.runner_spec.v1"
    assert doc["benchmark"] == doc["runner"] == "cybergym"
    assert doc["ready"] is True and doc["blockers"] == []
    assert doc["spec"]["image_vul"] == "n132/arvo:44034-vul"
    assert doc["spec"]["image_fix"] == "n132/arvo:44034-fix"
    assert doc["spec"]["cmd"] == ["/workspace/reproduce", "/input"]
    assert doc["spec"]["input_path"] == str(crash_input)
    assert doc["sources"]["image_vul"] == "task_json"
    assert doc["sources"]["harness_cmd"] == "metadata"
    assert doc["case_id"] == "CG-01" and doc["task_id"] == "arvo:44034"
    # 缺输入只是 warning：runner 允许没有输入，但判据会落 input_not_recorded
    assert doc["warnings"] == []


def test_spec_cybergym_entry_alias_and_argv(tmp_path):
    ws = _workspace(tmp_path, CG_TASK)
    doc = build_runner_spec(workspace=ws, probe=False, metadata={
        "entry": ["/bin/sh", "-c", "/workspace/reproduce /input"]})
    assert doc["spec"]["cmd"] == ["/bin/sh", "-c",
                                  "/workspace/reproduce /input"]
    # harness 字典形态
    doc2 = build_runner_spec(workspace=ws, probe=False, metadata={
        "harness": {"cmd": "python3 harness.py"}})
    assert doc2["spec"]["cmd"] == ["python3", "harness.py"]


def test_spec_cybergym_missing_fields_are_blockers(tmp_path):
    doc = build_runner_spec("cybergym", probe=False, metadata={})
    assert doc["ready"] is False and doc["status"] == "needs_evidence"
    assert "runner_not_configured:image_vul,image_fix,cmd" in doc["blockers"]
    assert doc["missing"] == ["image_vul", "image_fix", "cmd"]
    assert doc["required"] == ["image_vul", "image_fix", "cmd"]
    # 输入没声明只是 warning：能跑，但判据会缺 input
    assert any("input_path not declared" in item for item in doc["warnings"])


def test_spec_exploitgym_task_info_socket():
    doc = build_runner_spec("exploitgym", probe=False, metadata={
        "image": "cybergym/arvo:18224-vul.exp.none-nogit",
        "mode": "exp.none",
        "task_info": {"host": "127.0.0.1", "port": 9009,
                      "expected_flag": FLAG}})
    assert doc["ready"] is True
    assert doc["spec"]["mode"] == "socket"
    assert doc["spec"]["host"] == "127.0.0.1" and doc["spec"]["port"] == 9009
    # 任务级 mode 是镜像形态，不能冒充 runner 的 transport
    assert doc["spec"]["image_mode"] == "exp.none"
    assert doc["spec"]["image"] == "cybergym/arvo:18224-vul.exp.none-nogit"
    assert doc["spec"]["expected_flag"] == FLAG


def test_spec_exploitgym_task_info_address_string():
    doc = build_runner_spec("exploitgym", probe=False, metadata={
        "image": "img:1", "mode": "exp.none", "task_info": "127.0.0.1:9009"})
    assert doc["spec"]["mode"] == "socket"
    assert doc["spec"]["host"] == "127.0.0.1"
    assert doc["spec"]["port"] == 9009


def test_spec_exploitgym_task_info_file(tmp_path):
    info = tmp_path / "task_info.json"
    info.write_text(json.dumps({"exploit_cmd": "python3 exploit.py --x 1"}),
                    encoding="utf-8")
    doc = build_runner_spec("exploitgym", probe=False, metadata={
        "image": "img:1", "mode": "exp.flag", "task_info": str(info)})
    assert doc["spec"]["mode"] == "exploit_cmd"
    assert doc["spec"]["exploit_cmd"] == ["python3", "exploit.py", "--x", "1"]


def test_spec_exploitgym_missing_transport_and_mode():
    doc = build_runner_spec("exploitgym", probe=False,
                            metadata={"image": "img:1"})
    assert doc["ready"] is False
    assert doc["spec"]["image"] == "img:1"
    assert "runner_not_configured:mode" in doc["blockers"]
    assert "runner_not_configured:exploit_target" in doc["blockers"]
    assert doc["missing"] == ["mode", "exploit_target"]
    # 没有 expected_flag 是 warning（只能验形态）
    assert any("expected_flag not declared" in item for item in doc["warnings"])


def test_spec_vulngym_service_url_shared():
    doc = build_runner_spec("vulngym", probe=False, metadata={
        "service_url": "http://127.0.0.1:8080/api/items",
        "expect_baseline_status": 200, "expect_patched_status": [403, 404]})
    assert doc["ready"] is True
    assert doc["spec"]["baseline_url"] == doc["spec"]["patched_url"] == \
        "http://127.0.0.1:8080/api/items"
    assert doc["spec"]["expect"] == {"baseline_status": 200,
                                     "patched_status_in": [403, 404]}
    assert doc["spec"]["method"] == "GET"
    assert any("service_url" in item for item in doc["notes"])


def test_spec_vulngym_missing_urls():
    doc = build_runner_spec("vulngym", probe=False, metadata={})
    assert doc["ready"] is False
    assert "runner_not_configured:baseline_url,patched_url" in doc["blockers"]
    assert doc["missing"] == ["baseline_url", "patched_url"]


def test_spec_precedence_task_json_metadata_overrides(tmp_path):
    ws = _workspace(tmp_path, CG_TASK)
    doc = build_runner_spec(
        workspace=ws, probe=False,
        metadata={"image_vul": "meta:vul", "cmd": "true"},
        overrides={"image_vul": "override:vul", "docker": "/bin/true",
                   "flag": "FLAG{should_not_leak}"})
    assert doc["spec"]["image_vul"] == "override:vul"
    assert doc["spec"]["docker"] == "/bin/true"
    assert doc["sources"]["image_vul"] == "overrides"
    # 判据键不许钻进 runner spec
    assert "flag" not in doc["spec"]


def test_spec_unknown_benchmark_raises():
    with pytest.raises(SpecError):
        build_runner_spec("target_yaml", probe=False)


def test_spec_load_task_json_roundtrip(tmp_path):
    ws = _workspace(tmp_path, CG_TASK)
    doc, path = load_task_json(ws)
    assert doc["benchmark"] == "cybergym" and path.endswith("task.json")
    assert load_task_json(tmp_path / "nope") == ({}, "")


def test_spec_summarize_is_compact(tmp_path):
    doc = build_runner_spec("vulngym", probe=False, metadata={})
    brief = summarize(doc)
    assert set(brief) == {"benchmark", "runner", "case_id", "task_id", "ready",
                          "status", "blockers", "missing", "warnings", "probes"}
    assert "spec" not in brief and brief["status"] == "needs_evidence"


# ------------------------------------------------------------------ 本机探测
def test_spec_probe_missing_docker_binary():
    doc = build_runner_spec("cybergym", probe=True, metadata={
        "image_vul": "a:1", "image_fix": "b:1", "cmd": "true"},
        docker="/no/such/docker")
    assert doc["ready"] is False
    assert "docker_unavailable:/no/such/docker" in doc["blockers"]
    assert docker_path("/no/such/docker") == ""


def test_spec_probe_image_missing(tmp_path):
    docker = _fake_docker(tmp_path, present=[])
    doc = build_runner_spec("cybergym", probe=True, metadata={
        "image_vul": "n132/arvo:44034-vul", "image_fix": "n132/arvo:44034-fix",
        "cmd": "true", "docker": docker}, probe_timeout=10)
    assert doc["ready"] is False
    assert "image_not_found:n132/arvo:44034-vul" in doc["blockers"]
    assert "image_not_found:n132/arvo:44034-fix" in doc["blockers"]
    probes = {item["name"]: item for item in doc["probes"]}
    assert probes["image_vul"]["ok"] is False


def test_spec_probe_image_present(tmp_path):
    docker = _fake_docker(tmp_path, present=["a:1", "b:1"])
    doc = build_runner_spec("cybergym", probe=True, metadata={
        "image_vul": "a:1", "image_fix": "b:1", "cmd": "true",
        "docker": docker}, probe_timeout=10)
    assert doc["ready"] is True and doc["blockers"] == []
    assert all(item["ok"] for item in doc["probes"])


def test_spec_probe_daemon_down(tmp_path):
    docker = _fake_docker(tmp_path, present=[], daemon_down=True)
    state, detail = image_probe(docker, "a:1", timeout=10)
    assert state == "unavailable" and "daemon" in detail.lower()


def test_spec_probe_socket_and_http(tmp_path, flag_server, http_server):
    srv = http_server({"/ok": {"status": 200, "body": "A"}})
    live = flag_server(b"nothing here")
    ok, detail = tcp_probe("127.0.0.1", live.port, timeout=2)
    assert ok and "connectable" in detail
    doc = build_runner_spec("exploitgym", probe=True, metadata={
        "image": "img:1", "mode": "exp.none",
        "task_info": {"host": "127.0.0.1", "port": live.port}})
    assert doc["ready"] is True, doc["blockers"]

    bad = build_runner_spec("exploitgym", probe=True, metadata={
        "image": "img:1", "mode": "exp.none",
        "task_info": {"host": "127.0.0.1", "port": _closed_port()}})
    assert bad["ready"] is False
    assert any(item.startswith("connection_failed:127.0.0.1:")
               for item in bad["blockers"])

    good = build_runner_spec("vulngym", probe=True, metadata={
        "baseline_url": srv.url("/ok"), "patched_url": srv.url("/ok")})
    assert good["ready"] is True, good["blockers"]


# ------------------------------------------------------------------ verify --auto
def test_verify_auto_cybergym_success(tmp_path, crash_input):
    docker = _fake_docker(
        tmp_path, present=["fake-vul:1", "fake-fix:1"],
        images={"fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
                "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG}})
    store, bus = _task(tmp_path, task_id="cg-auto", metadata={
        "image_vul": "fake-vul:1", "image_fix": "fake-fix:1",
        "harness_cmd": "/workspace/reproduce /input",
        "input_path": str(crash_input), "docker": docker})
    _candidate(store, "cg-auto")

    out = run_verification("cg-auto", store, bus, spec={}, execute=True,
                           auto=True, timeout=20, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is True, out["blockers"]
    assert out["status"] == "verified" and out["mode"] == "execute"
    assert out["execution"]["auto"] is True
    assert out["execution"]["executed"] is True
    assert out["execution"]["completed"] is True
    assert out["auto_spec"]["ready"] is True
    assert out["auto_spec"]["spec"]["image_vul"] == "fake-vul:1"
    kinds = _kinds(out)
    assert {"verify_vul_log", "verify_fix_log", "verify_runner"} <= set(kinds)
    _assert_no_confirmed(json.dumps(out["verification"], ensure_ascii=False))


def test_verify_auto_missing_image_is_needs_evidence(tmp_path):
    docker = _fake_docker(tmp_path, present=[])
    store, bus = _task(tmp_path, task_id="cg-nomirror", metadata={
        "image_vul": "n132/arvo:44034-vul", "image_fix": "n132/arvo:44034-fix",
        "harness_cmd": "/workspace/reproduce", "docker": docker})
    _candidate(store, "cg-nomirror")

    out = run_verification("cg-nomirror", store, bus, spec={}, execute=True,
                           auto=True, timeout=20, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert out["state"] == "NEEDS_EVIDENCE"
    assert "image_not_found:n132/arvo:44034-vul" in out["blockers"]
    # 缺口在执行前就被发现：runner 没起过
    assert out["execution"]["executed"] is False
    assert out["execution"]["completed"] is False
    assert out["execution"]["auto_blockers"]
    assert "verify_runner_spec" in _kinds(out)
    assert out["verification"]["verified"] is False

    executed = [ev for ev in bus.list("cg-nomirror")
                if ev["event_type"] == "verification.executed"]
    assert len(executed) == 1
    assert executed[0]["payload"]["auto"] is True
    assert executed[0]["payload"]["executed"] is False


def test_verify_auto_missing_docker_is_needs_evidence(tmp_path):
    store, bus = _task(tmp_path, task_id="cg-nodock", metadata={
        "image_vul": "a:1", "image_fix": "b:1", "cmd": "true",
        "docker": "/no/such/docker"})
    _candidate(store, "cg-nodock")

    out = run_verification("cg-nodock", store, bus, spec={}, execute=True,
                           auto=True, timeout=10, isolation="none",
                           workdir=tmp_path / "work")

    assert out["status"] == "needs_evidence"
    assert any(item.startswith("docker_unavailable:") for item in out["blockers"])
    assert out["execution"]["executed"] is False


def test_verify_auto_exploitgym_socket_success(tmp_path, flag_server):
    live = flag_server(FLAG.encode())
    store, bus = _task(tmp_path, task_id="eg-auto", benchmark="exploitgym",
                       metadata={
                           "image": "cybergym/arvo:18224-vul.exp.none-nogit",
                           "mode": "exp.none",
                           "task_info": {"host": "127.0.0.1",
                                         "port": live.port},
                           "expected_flag": FLAG})
    _candidate(store, "eg-auto")

    out = run_verification("eg-auto", store, bus, spec={}, execute=True,
                           auto=True, timeout=10, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is True, out["blockers"]
    assert out["dual_required"] is False
    assert "local_dual_run_failed" not in out["blockers"]
    assert out["execution"]["detail"]["mode"] == "socket"
    assert out["auto_spec"]["spec"]["mode"] == "socket"


def test_verify_auto_exploitgym_unreachable_is_needs_evidence(tmp_path):
    store, bus = _task(tmp_path, task_id="eg-down", benchmark="exploitgym",
                       metadata={
                           "image": "img:1", "mode": "exp.none",
                           "task_info": {"host": "127.0.0.1",
                                         "port": _closed_port()}})
    _candidate(store, "eg-down")

    out = run_verification("eg-down", store, bus, spec={}, execute=True,
                           auto=True, timeout=5, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert any(item.startswith("connection_failed:") for item in out["blockers"])
    assert out["execution"]["executed"] is False


def test_verify_auto_vulngym_local_server(tmp_path, http_server):
    srv = http_server({"/base": {"status": 200, "body": "A"},
                       "/patched": {"status": 403, "body": "B"}})
    store, bus = _task(tmp_path, task_id="vg-auto", benchmark="vulngym",
                       metadata={
                           "baseline_url": srv.url("/base"),
                           "patched_url": srv.url("/patched"),
                           "expect": {"baseline_status": 200,
                                      "patched_status_in": [403]}})
    _candidate(store, "vg-auto")

    out = run_verification("vg-auto", store, bus, spec={}, execute=True,
                           auto=True, timeout=10, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is True, out["blockers"]
    assert out["dual_required"] is False
    inputs = out["verification"]["detail"]["inputs"]
    assert inputs["baseline_status"] == 200
    assert inputs["patched_status"] == 403
    assert "verify_patched_body" in _kinds(out)


def test_verify_auto_vulngym_unreachable_is_needs_evidence(tmp_path):
    port = _closed_port()
    store, bus = _task(tmp_path, task_id="vg-down", benchmark="vulngym",
                       metadata={
                           "baseline_url": f"http://127.0.0.1:{port}/base",
                           "patched_url": f"http://127.0.0.1:{port}/patched"})
    _candidate(store, "vg-down")

    out = run_verification("vg-down", store, bus, spec={}, execute=True,
                           auto=True, timeout=5, isolation="none",
                           workdir=tmp_path / "work")

    assert out["status"] == "needs_evidence"
    assert any(item.startswith("connection_failed:") for item in out["blockers"])


def test_verify_auto_reads_workspace_task_json(tmp_path, crash_input):
    ws = _workspace(tmp_path, CG_TASK)
    docker = _fake_docker(
        tmp_path, present=["n132/arvo:44034-vul", "n132/arvo:44034-fix"],
        images={"n132/arvo:44034-vul": {"exit": 1, "stderr": ASAN_LOG},
                "n132/arvo:44034-fix": {"exit": 0, "stdout": CLEAN_LOG}})
    # 任务 metadata 里什么都没写：images 只能来自 workspace/task.json
    store, bus = _task(tmp_path, task_id="cg-ws", target=ws)
    _candidate(store, "cg-ws")

    out = run_verification("cg-ws", store, bus, spec={
        "cmd": ["/workspace/reproduce", "/input"],
        "input_path": str(crash_input),
        "docker": docker}, execute=True, auto=True, timeout=20,
        isolation="none", workdir=tmp_path / "work")

    assert out["verified"] is True, out["blockers"]
    assert out["auto_spec"]["sources"]["image_vul"] == "task_json"
    assert out["auto_spec"]["task_json"].endswith("task.json")


def test_verify_auto_real_negative_is_not_downgraded(tmp_path, crash_input):
    """两端都干净 → no_repro（证明 auto 不是“一切皆 needs_evidence”）。"""
    docker = _fake_docker(
        tmp_path, present=["fake-vul:1", "fake-fix:1"],
        images={"fake-vul:1": {"exit": 0, "stdout": CLEAN_LOG},
                "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG}})
    store, bus = _task(tmp_path, task_id="cg-flat", metadata={
        "image_vul": "fake-vul:1", "image_fix": "fake-fix:1",
        "harness_cmd": "true", "input_path": str(crash_input),
        "docker": docker})
    _candidate(store, "cg-flat")

    out = run_verification("cg-flat", store, bus, spec={}, execute=True,
                           auto=True, timeout=20, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is False
    assert out["status"] == "no_repro"
    assert out["execution"]["executed"] is True
    assert out["execution"]["completed"] is True


def test_verify_auto_target_yaml_degrades_without_runner(tmp_path):
    store, bus = _task(tmp_path, task_id="ty-auto", benchmark="target_yaml",
                       metadata={})
    _candidate(store, "ty-auto")

    out = run_verification("ty-auto", store, bus, spec={}, execute=True,
                           auto=True, timeout=5, workdir=tmp_path / "work")

    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert any(item.startswith("runner_unavailable:") for item in out["blockers"])
    assert "unsupported_benchmark:target_yaml" in out["blockers"]


def test_verify_without_auto_is_unchanged(tmp_path, crash_input):
    """不传 auto 时仍然是 P3.5 行为：runner 缺字段只报 runner_not_configured。"""
    store, bus = _task(tmp_path, task_id="cg-plain")
    _candidate(store, "cg-plain")

    out = run_verification("cg-plain", store, bus, spec={}, execute=True,
                           timeout=5, isolation="none",
                           workdir=tmp_path / "work")

    assert out["verified"] is False
    assert out["status"] == "needs_evidence"
    assert out["auto_spec"] is None
    assert "auto" not in out["execution"]
    assert out["execution"]["executed"] is True


# ------------------------------------------------------------------ CLI smoke
def _smoke_case_dir(root: Path, name: str, task_json: dict) -> Path:
    case = root / name
    case.mkdir(parents=True, exist_ok=True)
    (case / "task.json").write_text(json.dumps(task_json, ensure_ascii=False),
                                    encoding="utf-8")
    return case


def _run(args, *, env=None, cwd=ROOT):
    return subprocess.run([sys.executable, str(BIN), *args],
                          capture_output=True, text=True, cwd=str(cwd),
                          env={**os.environ, **(env or {})})


def test_cli_smoke_reports_gaps_honestly(tmp_path):
    root = tmp_path / "workspace"
    _smoke_case_dir(root, "CG-01-fake", dict(CG_TASK, harness_cmd="/bin/true"))
    _smoke_case_dir(root, "EG-02-fake", {
        "case_id": "EG-02", "benchmark": "exploitgym",
        "image": "cybergym/arvo:44034-vul.exp.none-nogit"})
    _smoke_case_dir(root, "VG-01-fake", {
        "case_id": "VG-01", "benchmark": "vulngym"})
    docker = _fake_docker(tmp_path, present=[])

    proc = _run(["smoke", "--workspace-root", str(root), "--docker", docker],
                env={"FAKE_DOCKER_PLAN": str(tmp_path / "docker-plan.json")})

    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["schema"] == "vulnmap.smoke.v1"
    assert doc["mode"] == "dry-run" and doc["persisted"] is False
    cases = {item["case"]: item for item in doc["cases"]}
    assert set(cases) == {"CG-01", "EG-02", "VG-01"}
    for entry in cases.values():
        assert entry["status"] == "needs_evidence", entry
        assert entry["executed"] is False and entry["persisted"] is False
    assert "image_not_found:n132/arvo:44034-vul" in cases["CG-01"]["blockers"]
    assert "runner_not_configured:exploit_target" in cases["EG-02"]["blockers"]
    assert "runner_not_configured:baseline_url,patched_url" in \
        cases["VG-01"]["blockers"]
    # 不能把缺口写成负结果，也不能出现“verified: true”
    assert '"verified": true' not in proc.stdout
    assert doc["summary"] == {"needs_evidence": 3}


def test_cli_smoke_execute_vulngym_would_verify(tmp_path, http_server):
    srv = http_server({"/base": {"status": 200, "body": "A"},
                       "/patched": {"status": 403, "body": "B"}})
    root = tmp_path / "workspace"
    _smoke_case_dir(root, "VG-01-fake", {
        "case_id": "VG-01", "benchmark": "vulngym",
        "baseline_url": srv.url("/base"), "patched_url": srv.url("/patched"),
        "expect": {"baseline_status": 200, "patched_status_in": [403]}})

    proc = _run(["smoke", "VG-01", "--workspace-root", str(root),
                 "--execute", "--isolation", "none", "--timeout", "10",
                 "--workdir", str(tmp_path / "smoke")])

    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)["cases"][0]
    assert entry["status"] == "would_verify", entry
    assert entry["executed"] is True and entry["persisted"] is False
    assert entry["criterion"]["criterion_ok"] is True
    assert entry["completed"] is True
    assert '"verified": true' not in proc.stdout


def test_cli_smoke_missing_service_stays_needs_evidence(tmp_path):
    root = tmp_path / "workspace"
    port = _closed_port()
    _smoke_case_dir(root, "VG-01-fake", {
        "case_id": "VG-01", "benchmark": "vulngym",
        "baseline_url": f"http://127.0.0.1:{port}/base",
        "patched_url": f"http://127.0.0.1:{port}/patched"})

    proc = _run(["smoke", "VG-01", "--workspace-root", str(root),
                 "--execute", "--isolation", "none", "--timeout", "5",
                 "--workdir", str(tmp_path / "smoke")])

    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)["cases"][0]
    assert entry["status"] == "needs_evidence"
    assert entry["executed"] is False
    assert any(item.startswith("connection_failed:") for item in entry["blockers"])


def test_cli_smoke_unknown_case_exit_2(tmp_path):
    proc = _run(["smoke", "NOPE-99", "--workspace-root", str(tmp_path)])
    assert proc.returncode == 2
    doc = json.loads(proc.stdout)
    assert doc["errors"][0]["case"] == "NOPE-99"


def test_cli_smoke_strict_exit_1_when_not_verified(tmp_path):
    root = tmp_path / "workspace"
    _smoke_case_dir(root, "VG-01-fake", {"case_id": "VG-01",
                                         "benchmark": "vulngym"})
    proc = _run(["smoke", "VG-01", "--workspace-root", str(root),
                 "--no-probe", "--strict"])
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["cases"][0]["status"] == "needs_evidence"


def test_cli_verify_auto_end_to_end(tmp_path, crash_input):
    docker = _fake_docker(
        tmp_path, present=["fake-vul:1", "fake-fix:1"],
        images={"fake-vul:1": {"exit": 1, "stderr": ASAN_LOG},
                "fake-fix:1": {"exit": 0, "stdout": CLEAN_LOG}})
    db = tmp_path / "cli.db"
    store, _ = _task(tmp_path, task_id="cg-cli-auto", db_name="cli.db",
                     metadata={"image_vul": "fake-vul:1",
                               "image_fix": "fake-fix:1",
                               "harness_cmd": "/workspace/reproduce /input",
                               "input_path": str(crash_input),
                               "docker": docker})
    _candidate(store, "cg-cli-auto", data=CRASH_INPUT)

    proc = _run(["--db", str(db), "verify", "cg-cli-auto", "--auto",
                 "--isolation", "none", "--timeout", "20",
                 "--workdir", str(tmp_path / "work")],
                env={"FAKE_DOCKER_PLAN": str(tmp_path / "docker-plan.json")})

    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["verified"] is True and out["mode"] == "execute"
    assert out["auto_spec"]["ready"] is True
    rows = PlatformStore(db).list_verifications("cg-cli-auto")
    assert len(rows) == 1 and rows[0]["verified"] is True
    assert rows[0]["detail"]["auto_spec"]["spec"]["image_vul"] == "fake-vul:1"
