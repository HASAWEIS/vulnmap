"""V2 P3.9 验收：static / dynamic 执行器 + 显式分派 + `run --kind`。

口径（与需求逐条对应）：

1. **static 只做复核**：基于 ProgramIndex + 假设集产出 `static_review` 证据，
   结局只有 `no_repro`（复核完成、无证据缺口）或 `needs_evidence`（有缺口 /
   静态事实支撑了某条假设）；**永不** 产 Candidate，**永不** 写结论字段；
2. **dynamic 做行为差分**：VulnGym 基线/修补两侧 HTTP 打到本地 server，
   有差异 → Candidate（输入=请求文档，主证据=差分日志）、无差异 → NO_REPRO；
   服务打不通/超时 → FAILED，并把 `dynamic_spec` / `dynamic_run` 一起留证；
3. **分派显式**：`EXECUTORS` 覆盖 fuzz/replay/static/dynamic；表里没有的 kind
   一律 `executor_unavailable:<kind>`（事件 `blockers` + `exec_error` 证据），
   不静默换执行方式；
4. **CLI/planner 可测**：`run --kind static|dynamic` 走得通，`select_kind()` 与
   `planner.select_kind` 可被测试直接覆盖；
5. **状态机**：补 `RUNNING → NEEDS_EVIDENCE`（以及 `NEEDS_EVIDENCE → RUNNING`
   重跑），缺口不是负结果。

全局硬约束：任何执行器产物都不得出现 `confirmed` 之类结论；单侧/静态只到证据。
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (EventBus, PlanError, PlatformStore, TaskSpec,
                            can_transition, executor_unavailable, run_execution,
                            run_hypotheses, run_plan, run_preflight,
                            run_understand, select_kind)
from agent.platform import executors
from agent.platform import planner as planner_mod
from agent.platform.executors import (EXECUTORS, DynamicExecError,
                                      StaticExecError, executor_for)
from agent.platform.executors.dynamic import (build_spec as build_dynamic_spec,
                                              execute as execute_dynamic)
from agent.platform.executors.static import execute as execute_static
from agent.platform.program import ProgramIndex
from agent.platform.verify import normalize_spec

BIN = ROOT / "bin" / "platform.py"
FIXTURE = ROOT / "fixtures" / "discovery"

#: 与 fixture 源码（parse_record/parse_meta/memcpy/…）完全不重叠的假设：
#: 静态复核应该给出“没有落点”，从而落 NO_REPRO
NON_MATCHING_HYPOTHESIS = {
    "id": "H1",
    "statement": "upstream 服务端 glyph 解析缺少空指针检查（repo 上游 patch 未合入）",
    "falsifiable_by": "向 /glyph 发送空记录，观察是否 500 且日志里出现 panic",
    "evidence_gap": ["no_repro_log"],
    "cost": {"level": "low", "execs": 50, "seconds": 5},
    "confidence": 0.3,
    "source": "rule",
}


# ------------------------------------------------------------------ helpers
def _sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


class _Routes(BaseHTTPRequestHandler):
    """极简 HTTP 服务：路径 → (status, body)，不跟跳转也不读环境代理。"""

    routes: dict = {}

    def do_GET(self):                                  # noqa: N802 - http.server
        status, body = self.routes.get(self.path, (404, b"missing"))
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):                      # noqa: D401 - 静音
        return


@pytest.fixture()
def http_service():
    """起一个本地 HTTP server，返回 (base_url, routes)；结束时收干净。"""
    started: list[tuple] = []

    def start(routes: dict) -> str:
        handler = type("Handler", (_Routes,), {"routes": dict(routes)})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append((server, thread))
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server, thread in started:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _closed_port() -> int:
    """拿一个刚释放的本机端口：连接它必然被拒（不依赖真实网络）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _prepared(tmp_path: Path, *, task_id: str, benchmark: str, target: str,
              metadata: dict | None = None, db: str = "exec.db"):
    store = PlatformStore(tmp_path / db)
    # F1：缺失授权默认阻断，夹具显式声明
    store.create_task(TaskSpec(task_id=task_id, benchmark=benchmark,
                               target=str(target),
                               metadata={"authorized": True, **(metadata or {})}))
    bus = EventBus(store)
    assert run_preflight(task_id, store, bus)["state"] == "READY"
    assert run_understand(task_id, store, bus)["state"] == "UNDERSTANDING"
    assert run_hypotheses(task_id, store, bus)["state"] == "HYPOTHESES"
    return store, bus


def _execute(store, bus, task_id: str, tmp_path: Path, **kwargs) -> dict:
    return run_execution(task_id, store, bus,
                         workdir=tmp_path / "work",
                         evidence_root=tmp_path / "evidence", **kwargs)


def _evidence_kinds(store, task_id: str) -> set[str]:
    return {row["kind"] for row in store.list_evidence(task_id)}


def _vg_workspace(base: Path, *, baseline: str, patched: str,
                  expect: dict | None = None) -> Path:
    """VulnGym 工作区：只带 task.json（服务地址 + 期望方向）。"""
    ws = base / "VG-EXEC"
    ws.mkdir(parents=True, exist_ok=True)
    doc = {"schema": "vulnmap.task.v1", "case_id": "VG-EXEC",
           "task_id": "vulngym/demo/exec", "benchmark": "vulngym",
           "project": "demo", "component": "demo service upgrade",
           "baseline_url": baseline, "patched_url": patched,
           "method": "GET"}
    if expect:
        doc["expect"] = expect
    (ws / "task.json").write_text(json.dumps(doc, ensure_ascii=False),
                                  encoding="utf-8")
    return ws


def _cli(db: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), "--db", str(db), *args],
                          capture_output=True, text=True, timeout=180)


# ------------------------------------------------------- 1. 分派 + 状态机
def test_dispatch_table_is_explicit(tmp_path):
    """四种 kind 都有执行器；没登记的 kind 只能拿到 executor_unavailable。"""
    assert set(EXECUTORS) == {"fuzz", "replay", "static", "dynamic"}
    assert executor_for("static") == "static"
    assert executor_for("dynamic") == "dynamic"
    message = executor_unavailable("container")
    assert message.startswith("executor_unavailable:container")
    assert "dynamic" in message and "fuzz" in message   # 可用列表要说清
    with pytest.raises(PlanError) as excinfo:
        executor_for("container")
    assert "executor_unavailable:container" in str(excinfo.value)


def test_unsupported_kind_fails_loudly_not_silently(tmp_path):
    """没接执行器的 kind：PlanError + FAILED + exec_error 证据 + blockers 事件。"""
    store, bus = _prepared(tmp_path, task_id="exec-unsupported",
                           benchmark="target_yaml", target=str(FIXTURE))
    run_plan("exec-unsupported", store, bus)

    with pytest.raises(PlanError) as excinfo:
        _execute(store, bus, "exec-unsupported", tmp_path,
                 kind_override="container")
    assert "executor_unavailable:container" in str(excinfo.value)

    assert store.get_task("exec-unsupported")["state"] == "FAILED"
    finished = [e for e in bus.list("exec-unsupported")
                if e["event_type"] == "exec.finished"][-1]["payload"]
    assert finished["outcome"] == "failed"
    assert finished["blockers"] == ["executor_unavailable:container"]
    assert finished["kind"] == "container"
    # 失败也留证：exec_error 里记着 blocker
    rows = [r for r in store.list_evidence("exec-unsupported")
            if r["kind"] == "exec_error"]
    assert rows
    doc = json.loads(Path(rows[0]["path"]).read_text(encoding="utf-8"))
    assert doc["blocker"] == "executor_unavailable:container"


def test_state_machine_has_needs_evidence_edges():
    """缺口不是负结果：RUNNING 可直接落 NEEDS_EVIDENCE，补证据后能重跑。"""
    assert can_transition("RUNNING", "NEEDS_EVIDENCE")
    assert can_transition("NEEDS_EVIDENCE", "RUNNING")
    assert not can_transition("NEEDS_EVIDENCE", "CANDIDATE")


def test_planner_kind_selection_is_directly_testable(tmp_path, monkeypatch):
    """planner 的选择逻辑可被单测直接调用，也可被 monkeypatch 覆盖。"""
    empty = ProgramIndex(benchmark="target_yaml", root=str(tmp_path))
    assert select_kind(empty, "target_yaml")[0] == "static"

    mixed = ProgramIndex(benchmark="target_yaml", root=str(tmp_path),
                         source_count=2,
                         call_sites=[{"id": "a.c:1:memcpy#0"}])
    assert select_kind(mixed, "target_yaml")[0] == "fuzz"

    vg = ProgramIndex(benchmark="vulngym", root=str(tmp_path))
    assert select_kind(vg, "vulngym")[0] == "dynamic"

    # 覆盖选择 → run_plan 产出的 Plan.kind 跟着变（选择点只有一处）
    store, bus = _prepared(tmp_path, task_id="exec-plan", benchmark="target_yaml",
                           target=str(FIXTURE))
    monkeypatch.setattr(planner_mod, "select_kind",
                        lambda *a, **k: ("static", "测试覆盖：强制 static"))
    plan = run_plan("exec-plan", store, bus)["plan"]
    assert plan["kind"] == "static"
    assert "测试覆盖" in plan["reason"]


# ------------------------------------------------------------- 2. static
def test_static_review_no_repro_when_nothing_supports_hypothesis(tmp_path):
    """假设在 ProgramIndex 里没有落点、也没有证据缺口 → NO_REPRO，且不产候选。"""
    store, bus = _prepared(tmp_path, task_id="exec-static-ok",
                           benchmark="target_yaml", target=str(FIXTURE))
    store.save_hypotheses("exec-static-ok", [dict(NON_MATCHING_HYPOTHESIS)])
    run_plan("exec-static-ok", store, bus)

    out = _execute(store, bus, "exec-static-ok", tmp_path,
                   kind_override="static")

    assert out["outcome"] == "no_repro"
    assert out["state"] == "NO_REPRO"
    assert out["candidates"] == []
    assert out["gaps"] == []
    review = out["review"]
    assert review["status"] == "no_repro"
    assert review["program"]["source_count"] == 1
    assert review["program"]["call_sites"] >= 1
    assert [h["support"] for h in review["hypotheses"]] == ["no_static_support"]
    assert store.list_candidates("exec-static-ok") == []
    assert "static_review" in _evidence_kinds(store, "exec-static-ok")

    # 静态复核不留结论词：既没有 verdict 字段，也没有 confirmed 字样
    assert "confirmed" not in json.dumps(review, ensure_ascii=False).lower()
    assert not ({"verdict", "conclusion", "exploitable"} & set(review))


def test_static_review_needs_evidence_when_static_support_found(tmp_path):
    """规则生成的假设能落到 memcpy 调用点：静态支撑 ≠ 成立 → NEEDS_EVIDENCE。"""
    store, bus = _prepared(tmp_path, task_id="exec-static-gap",
                           benchmark="target_yaml", target=str(FIXTURE))
    run_plan("exec-static-gap", store, bus)

    out = _execute(store, bus, "exec-static-gap", tmp_path,
                   kind_override="static")

    assert out["outcome"] == "needs_evidence"
    assert out["state"] == "NEEDS_EVIDENCE"
    assert out["candidates"] == []
    gaps = out["gaps"]
    assert any(g.startswith("static_support_needs_dynamic:") for g in gaps)
    supported = [h for h in out["review"]["hypotheses"]
                 if h["support"] == "static_support"]
    assert supported and supported[0]["matched_sites"]
    # 支撑的假设仍然不产候选、不写结论
    assert store.list_candidates("exec-static-gap") == []
    assert "confirmed" not in json.dumps(out["review"],
                                         ensure_ascii=False).lower()


def test_static_review_reports_evidence_gaps_on_anchors_only_index(
        tmp_path, http_service):
    """VulnGym 只有 SOURCE.md/task.json 锚点：缺口要说清楚（无源码树）。"""
    base = http_service({"/vuln": (200, b"ok"), "/patched": (403, b"no")})
    ws = _vg_workspace(tmp_path, baseline=base + "/vuln", patched=base + "/patched")
    store, bus = _prepared(tmp_path, task_id="exec-static-vg", benchmark="vulngym",
                           target=base + "/vuln",
                           metadata={"workspace": str(ws)})
    run_plan("exec-static-vg", store, bus)

    out = _execute(store, bus, "exec-static-vg", tmp_path,
                   kind_override="static")

    assert out["outcome"] == "needs_evidence"
    assert out["state"] == "NEEDS_EVIDENCE"
    assert "no_source_tree" in out["gaps"]
    assert out["review"]["program"]["source_count"] == 0
    assert out["candidates"] == []


def test_static_executor_rejects_mismatched_index():
    """index 与 plan 口径不符是契约错误（抛错落 FAILED，不是 no_repro）。"""
    index = ProgramIndex(benchmark="cybergym", root=".", task_id="x")
    with pytest.raises(StaticExecError):
        execute_static({"task_id": "x", "benchmark": "target_yaml"}, index)
    with pytest.raises(StaticExecError):
        execute_static({"task_id": "x", "benchmark": "target_yaml"}, None)


def test_static_executor_failure_fails_closed(tmp_path, monkeypatch):
    """静态执行器跑不动：FAILED + exec_error，不允许降级成 NO_REPRO。"""
    store, bus = _prepared(tmp_path, task_id="exec-static-fail",
                           benchmark="target_yaml", target=str(FIXTURE))
    run_plan("exec-static-fail", store, bus)

    def boom(*args, **kwargs):
        raise StaticExecError("static review crashed on purpose")

    monkeypatch.setattr(executors, "execute_static", boom)
    with pytest.raises(StaticExecError):
        _execute(store, bus, "exec-static-fail", tmp_path, kind_override="static")

    assert store.get_task("exec-static-fail")["state"] == "FAILED"
    kinds = _evidence_kinds(store, "exec-static-fail")
    assert "exec_error" in kinds
    assert "static_review" not in kinds
    finished = [e for e in bus.list("exec-static-fail")
                if e["event_type"] == "exec.finished"][-1]["payload"]
    assert finished["outcome"] == "failed"
    assert "static review crashed" in finished["error"]


# ------------------------------------------------------------ 3. dynamic
def test_dynamic_behavior_diff_creates_candidate(tmp_path, http_service):
    """两侧状态/响应体不同 → Candidate（输入=请求文档，主证据=差分日志）。"""
    base = http_service({"/vuln": (200, b"<html>admin panel</html>"),
                         "/patched": (403, b"forbidden")})
    ws = _vg_workspace(tmp_path, baseline=base + "/vuln",
                       patched=base + "/patched",
                       expect={"baseline_status": 200,
                               "patched_status_in": [403]})
    store, bus = _prepared(tmp_path, task_id="exec-dyn-ok", benchmark="vulngym",
                           target=base + "/vuln",
                           metadata={"workspace": str(ws)})
    assert run_plan("exec-dyn-ok", store, bus)["plan"]["kind"] == "dynamic"

    out = _execute(store, bus, "exec-dyn-ok", tmp_path)

    assert out["outcome"] == "candidate"
    assert out["state"] == "CANDIDATE"
    assert out["kind"] == "dynamic"
    assert out["dynamic"]["baseline_status"] == 200
    assert out["dynamic"]["patched_status"] == 403
    assert out["dynamic"]["differs"] is True

    rows = store.list_candidates("exec-dyn-ok")
    assert len(rows) == 1
    cand = rows[0]
    assert cand["state"] == "new"
    assert cand["crash_type"] == "behavior_diff"
    assert cand["detail"]["source"] == "dynamic"
    assert cand["detail"]["dynamic"]["summary"]["patched_status"] == 403
    assert cand["detail"]["input_evidence_sha256"]
    # 候选输入就是真正打出去的请求文档（含两侧 URL），可复算
    request = cand["detail"]["dynamic"]["request"]
    assert request["baseline_url"] == base + "/vuln"
    assert request["patched_url"] == base + "/patched"
    assert cand["input_sha256"] == _sha256(json.dumps(
        request, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8"))

    kinds = _evidence_kinds(store, "exec-dyn-ok")
    assert {"dynamic_spec", "dynamic_diff", "dynamic_input", "dynamic_log",
            "exec_stats"} <= kinds
    assert any(k.startswith("dynamic_verify_") and k.endswith("_body")
               for k in kinds), kinds
    assert "confirmed" not in json.dumps(out["diff"], ensure_ascii=False).lower()

    # 判据输入可直接喂 verify：只含 vulngym 字段，不带结论
    spec_row = [r for r in store.list_evidence("exec-dyn-ok")
                if r["kind"] == "dynamic_spec"][0]
    spec = json.loads(Path(spec_row["path"]).read_text(encoding="utf-8"))
    normalized = normalize_spec("vulngym", spec)
    assert normalized["kind"] == "behavior_diff"
    assert spec["baseline"]["status"] == 200
    assert spec["patched"]["status"] == 403
    assert "verified" not in spec and "confirmed" not in spec


def test_dynamic_without_behavior_diff_is_no_repro(tmp_path, http_service):
    """两侧行为一致 → NO_REPRO（跑完了、没差异，不是失败）。"""
    base = http_service({"/same": (200, b"identical")})
    ws = _vg_workspace(tmp_path, baseline=base + "/same", patched=base + "/same")
    store, bus = _prepared(tmp_path, task_id="exec-dyn-same", benchmark="vulngym",
                           target=base + "/same", metadata={"workspace": str(ws)})
    run_plan("exec-dyn-same", store, bus)

    out = _execute(store, bus, "exec-dyn-same", tmp_path)

    assert out["outcome"] == "no_repro"
    assert out["state"] == "NO_REPRO"
    assert out["candidates"] == []
    assert store.list_candidates("exec-dyn-same") == []
    assert out["dynamic"]["differs"] is False
    assert {"dynamic_spec", "dynamic_diff", "exec_stats"} <= _evidence_kinds(
        store, "exec-dyn-same")


def test_dynamic_unreachable_service_fails_and_keeps_evidence(tmp_path):
    """服务打不通：FAILED + dynamic_spec/dynamic_run 证据，绝不写成 NO_REPRO。"""
    port = _closed_port()
    base = f"http://127.0.0.1:{port}"
    ws = _vg_workspace(tmp_path, baseline=base + "/vuln",
                       patched=base + "/patched")
    store, bus = _prepared(tmp_path, task_id="exec-dyn-dead",
                           benchmark="vulngym", target=base + "/vuln",
                           metadata={"workspace": str(ws)})
    run_plan("exec-dyn-dead", store, bus)

    with pytest.raises(DynamicExecError):
        _execute(store, bus, "exec-dyn-dead", tmp_path)

    state = store.get_task("exec-dyn-dead")["state"]
    assert state == "FAILED"
    kinds = _evidence_kinds(store, "exec-dyn-dead")
    assert {"dynamic_spec", "dynamic_run", "exec_error"} <= kinds
    finished = [e for e in bus.list("exec-dyn-dead")
                if e["event_type"] == "exec.finished"][-1]["payload"]
    assert finished["outcome"] == "failed"
    assert "no observable response" in finished["error"]
    assert finished["evidence"], "失败前拿到的证据必须登记在事件里"


def test_dynamic_requires_vulngym_benchmark():
    """dynamic 只实现 VulnGym 行为差分：别的 benchmark 直接抛错（带 spec 记录）。"""
    index = ProgramIndex(benchmark="cybergym", root=".", task_id="x")
    with pytest.raises(DynamicExecError) as excinfo:
        execute_dynamic({"task_id": "x", "benchmark": "cybergym"}, index)
    assert "vulngym" in str(excinfo.value)
    assert excinfo.value.records["dynamic_spec"]["error"] == "unsupported_benchmark"


def test_dynamic_spec_gap_is_reported_not_guessed(tmp_path):
    """没有声明任何服务地址：缺口如实报 runner_not_configured，不猜 URL。"""
    index = ProgramIndex(benchmark="vulngym", root=str(tmp_path))
    doc = build_dynamic_spec({"task_id": "x", "benchmark": "vulngym",
                              "inputs": {}}, index)
    assert doc["ready"] is False
    assert any(b.startswith("runner_not_configured:") for b in doc["blockers"])

    with pytest.raises(DynamicExecError) as excinfo:
        execute_dynamic({"task_id": "x", "benchmark": "vulngym", "inputs": {}},
                        index)
    assert "runner_not_configured" in str(excinfo.value)
    assert "dynamic_spec" in excinfo.value.records


# ---------------------------------------------------------------- 4. CLI
def test_cli_run_kind_static_end_to_end(tmp_path):
    db = tmp_path / "cli-static.db"

    for step in (("submit", "--benchmark", "target_yaml", "--target",
                  str(FIXTURE), "--task-id", "cli-static",
                  "--meta", "authorized=true"),
                 ("preflight", "cli-static"),
                 ("understand", "cli-static"),
                 ("hypotheses", "cli-static"),
                 ("plan", "cli-static")):
        proc = _cli(db, *step)
        assert proc.returncode == 0, proc.stderr or proc.stdout

    proc = _cli(db, "run", "cli-static", "--kind", "static",
                "--workdir", str(tmp_path / "work"),
                "--evidence-root", str(tmp_path / "evidence"))
    assert proc.returncode == 0, proc.stderr or proc.stdout
    out = json.loads(proc.stdout)
    assert out["kind"] == "static"
    assert out["state"] in ("NO_REPRO", "NEEDS_EVIDENCE")
    assert out["candidates"] == []
    assert "confirmed" not in proc.stdout.lower()

    # 未知 kind 在参数层就被拒（不静默执行别的抓执行方式）
    bad = _cli(db, "run", "cli-static", "--kind", "container")
    assert bad.returncode != 0
    assert "invalid choice" in (bad.stderr or "")


def test_cli_run_kind_dynamic_end_to_end(tmp_path, http_service):
    base = http_service({"/vuln": (200, b"data"), "/patched": (401, b"denied")})
    ws = _vg_workspace(tmp_path, baseline=base + "/vuln",
                       patched=base + "/patched")
    db = tmp_path / "cli-dynamic.db"

    planned = None
    for step in (("submit", "--benchmark", "vulngym", "--target",
                  base + "/vuln", "--task-id", "cli-dynamic",
                  "--meta", f"workspace={ws}", "--meta", "authorized=true"),
                 ("preflight", "cli-dynamic"),
                 ("understand", "cli-dynamic"),
                 ("hypotheses", "cli-dynamic"),
                 ("plan", "cli-dynamic")):
        proc = _cli(db, *step)
        assert proc.returncode == 0, proc.stderr or proc.stdout
        if step[0] == "plan":
            planned = json.loads(proc.stdout)
    assert planned["plan"]["kind"] == "dynamic"

    proc = _cli(db, "run", "cli-dynamic", "--kind", "dynamic",
                "--workdir", str(tmp_path / "work"),
                "--evidence-root", str(tmp_path / "evidence"))
    assert proc.returncode == 0, proc.stderr or proc.stdout
    out = json.loads(proc.stdout)
    assert out["kind"] == "dynamic"
    assert out["outcome"] == "candidate"
    assert out["state"] == "CANDIDATE"
    assert out["dynamic"]["patched_status"] == 401
