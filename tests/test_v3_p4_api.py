r"""V3 P4a 验收：研究轮次的只读 CLI / API / 页面（V3-014）。

口径：

1. **CLI 两个只读命令**：`platform research-status TASK` /
   `research-events` 输出轮次、阶段、动作、结果、证据引用；不写事件、
   不改任务、不动 `research.json` 一个字节；退出码
   `0=有研究产物 / 1=还没有研究轮次 / 2=任务不存在或产物不可用`。
2. **API 三个只读端点**：`/research`、`/research/events`、`/research/evidence`
   语义分开：`404` = 没有这个研究记录（任务不存在 / 从未跑研究循环），
   `409` = 记录存在但不可用（坏 JSON / schema 不认识 / 串任务 / 与
   `research.mapped` 登记的哈希不一致 / 报告有而事件流无）。
3. **跨任务隔离**：A 的证据哈希不算 B 的证据；B 看不到 A 的事件；
   B 目录里放 A 的报告 → 409（产物属于别的任务）。
4. **真实产物可读**：用 P2C 的入口真跑一次 `run_research`（只替身 fuzz 执行
   worker），产出的 `research.json` 由 API 与 CLI 直接读出来 —— 不是为测试
   手搓的“报告形状”。
5. **页面**：任务详情 200，出现「研究轮次」面板，只发起 GET 到
   `/research`，不读库、不改状态。

只读字段来自研究报告与事件流；本批不改 `agent/platform` 核心，也不写裁决字段。
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (Budget, EventBus, EvidenceStore,  # noqa: E402
                            PlatformStore, TaskSpec)
from agent.platform.adaptive import cli as adaptive_cli  # noqa: E402
from agent.platform.adaptive.controller import (  # noqa: E402
    PHASES as CONTROLLER_PHASES, ControllerResult, PhaseRecord, RoundRecord)
from agent.platform.adaptive.session import Diagnosis  # noqa: E402
from agent.platform.program import ProgramIndex  # noqa: E402
from vulnmap_platform.api import platform_research as research_view  # noqa: E402

STATIC = ROOT / "vulnmap_platform" / "static"
CLI = ROOT / "bin" / "platform.py"

TASK = "task-v3-p4a"
OTHER = "task-v3-p4a-other"
EVIDENCE_BODY = b'{"exec_id":"exec-r001","stats":{"execs":10}}\n'
EVIDENCE_SHA = hashlib.sha256(EVIDENCE_BODY).hexdigest()
UNREGISTERED_SHA = "b" * 64
CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED")


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture()
def platform_root(tmp_path, monkeypatch):
    """每个测试一个独立 PLATFORM_ROOT；端点按请求重新读取环境变量。"""
    root = tmp_path / "platform"
    root.mkdir()
    monkeypatch.setenv("PLATFORM_ROOT", str(root))
    monkeypatch.delenv(research_view.RESEARCH_ROOT_ENV, raising=False)
    return root


def _db(root: Path) -> Path:
    return root / "platform.db"


def _task(root: Path, task_id: str = TASK, *, state: str = "PLANNED") -> dict:
    store = PlatformStore(_db(root))
    try:
        store.create_task(TaskSpec(
            task_id=task_id, benchmark="vulngym", target=str(root),
            mode="fuzz",
            budget=Budget(max_seconds=60, max_execs=1000, max_tokens=1000,
                          max_turns=8),
            metadata={"authorized": True}))
        if state == "PLANNED":
            for dst in CHAIN:
                store.transition(task_id, dst, reason="p4a fixture")
        return store.get_task(task_id)
    finally:
        store.close()


def _report_doc(task_id: str = TASK, *, state: str = "NO_REPRO",
                stop_reason: str = "repeated_facts",
                controller_state: str = "completed") -> dict:
    """用真实 dataclass 拼出 `ControllerResult.to_dict()` 形状的报告文档。"""
    result = ControllerResult(status=controller_state, stop_reason=stop_reason)
    first = RoundRecord(round_no=1, facts_hash="f" * 16)
    first.diagnosis = Diagnosis(code="no_execution", severity="info",
                               reasons=("event_stream_empty",))
    first.actions = [{
        "action_id": "run-r01", "tool": "run_epoch", "status": "applied",
        "before_sha256": "", "after_sha256": "", "invalidations": [],
        "evidence_refs": [EVIDENCE_SHA], "candidates": 0, "error": None,
    }]
    first.compare = {"status": "unknown", "comparable": "unknown",
                     "reason": "no_previous_observation",
                     "verdict": "not_evaluated"}
    first.note = "no_execution"
    second = RoundRecord(round_no=2, facts_hash="f" * 16)
    second.diagnosis = Diagnosis(code="target_unreached", severity="warn",
                                reasons=("coverage_flat",))
    second.revision = "hr-0001"
    second.build = {"build_id": "b1", "status": "ok", "exit_code": 0,
                    "log_path": "/tmp/build.log"}
    second.smoke = {"smoke_id": "s1", "status": "passed", "kind": "script",
                    "exit_code": 0}
    second.actions = [{
        "action_id": "run-r02", "tool": "run_epoch", "status": "applied",
        "invalidations": ["execution_facts"],
        "evidence_refs": [EVIDENCE_SHA, UNREGISTERED_SHA], "candidates": 0,
        "error": None,
    }]
    second.compare = {"status": "applied", "comparable": "true",
                      "reason": "same_build", "metric": "coverage",
                      "delta": 0.0, "verdict": "not_evaluated"}
    second.stop_reason = "repeated_facts"
    second.note = "no_repro"
    result.rounds = [first, second]
    result.timeline = []
    for round_no in (1, 2):
        for phase, status in (("OBSERVE", "ok"), ("DIAGNOSE", "ok"),
                              ("PROPOSE", "ok"), ("AUTHORIZE", "ok"),
                              ("EXECUTE", "applied"), ("COLLECT", "ok"),
                              ("COMPARE", "unknown" if round_no == 1 else "applied")):
            result.timeline.append(PhaseRecord(round_no, phase, status, ""))
    result.timeline.append(PhaseRecord(2, "STOP", "repeated",
                                       "facts seen 2x"))
    return {
        "schema": adaptive_cli.SCHEMA, "schema_version": adaptive_cli.SCHEMA_VERSION,
        "task_id": task_id, "benchmark": "vulngym", "campaign": "vulngym",
        "generated_at": "2026-11-20T00:00:00+00:00",
        "state": state, "controller_state": controller_state,
        "stop_reason": stop_reason, "max_rounds": 6,
        "rounds": len(result.rounds), "executions": 2,
        "executions_applied": 2, "executions_failed": 0, "candidates": 0,
        "observed_rounds": 2, "verification_allowed": False,
        "note": adaptive_cli.NOTE, "controller": result.to_dict(),
        "deps": {}, "budget": {}, "paths": {},
    }


def _write_report(root: Path, task_id: str = TASK, **kwargs) -> tuple[Path, str]:
    doc = _report_doc(task_id, **kwargs)
    path = root / "research" / task_id / "research.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return path, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _emit_session(store: PlatformStore, task_id: str, report: Path,
                  sha: str, *, with_events: bool = True) -> None:
    if not with_events:
        return
    store.append_event(task_id, "research.started", stage="RUNNING",
                       payload={"campaign": "vulngym", "max_rounds": 6})
    store.append_event(task_id, "exec.started", stage="RUNNING", payload={
        "exec_id": "exec-r001-aaaaaaaa", "kind": "fuzz", "mode": "explore"})
    store.append_event(task_id, "exec.finished", stage="RUNNING", payload={
        "exec_id": "exec-r001-aaaaaaaa", "kind": "fuzz", "outcome": "no_repro",
        "candidates": 0, "evidence_sha256": EVIDENCE_SHA})
    store.append_event(task_id, "exec.finished", stage="RUNNING", payload={
        "exec_id": "exec-r002-bbbbbbbb", "kind": "fuzz", "outcome": "no_repro",
        "candidates": 0, "evidence_sha256": EVIDENCE_SHA})
    store.append_event(task_id, "research.mapped", stage="NO_REPRO", payload={
        "state": "NO_REPRO", "target_state": "NO_REPRO",
        "stop_reason": "repeated_facts", "rounds": 2, "executions": 2,
        "report_path": str(report), "report_sha256": sha})


def _fixture(root: Path, task_id: str = TASK, *, report: bool = True,
             with_events: bool = True, **kwargs) -> tuple[Path | None, str]:
    _task(root, task_id)
    if not report:
        return None, ""
    path, sha = _write_report(root, task_id, **kwargs)
    store = PlatformStore(_db(root))
    try:
        _emit_session(store, task_id, path, sha, with_events=with_events)
    finally:
        store.close()
    return path, sha


def _run_cli(root: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), "--db", str(_db(root)), *argv],
        capture_output=True, text=True, cwd=str(ROOT), timeout=120,
        check=False)


def _events(root: Path, task_id: str = TASK) -> list[dict]:
    store = PlatformStore(_db(root))
    try:
        return store.list_events(task_id)
    finally:
        store.close()


def _snapshot(root: Path, report: Path | None) -> dict:
    task = PlatformStore(_db(root))
    try:
        state = task.get_task(TASK)["state"]
    finally:
        task.close()
    return {"state": state, "events": len(_events(root)),
            "report": report.read_bytes() if report and report.is_file() else b""}


# ====================================================================== 0
def test_phase_order_matches_controller():
    """本层的阶段顺序只是排序表，必须与控制器 PHASES 同序（漂移即失败）。"""
    assert research_view.PHASES == CONTROLLER_PHASES


# ====================================================================== 1
def test_cli_research_status_and_events_are_read_only(platform_root):
    report, sha = _fixture(platform_root)
    before = _snapshot(platform_root, report)

    proc = _run_cli(platform_root, "research-status", TASK)
    assert proc.returncode == 0, proc.stderr
    view = json.loads(proc.stdout)
    assert view["schema"] == research_view.SCHEMA
    assert view["rounds_count"] == 2
    assert [row["round"] for row in view["rounds"]] == [1, 2]
    # 阶段：控制器时间线原样读出（含 STOP），不是 API 自己补的
    assert [row["phase"] for row in view["timeline"]][:3] == [
        "OBSERVE", "DIAGNOSE", "PROPOSE"]
    assert "STOP" in [row["phase"] for row in view["timeline"]]
    # 动作与结果
    assert [a["action_id"] for a in view["rounds"][1]["actions"]] == ["run-r02"]
    assert view["results"]["action_status"] == {"applied": 2}
    assert view["rounds"][1]["results"]["build"]["status"] == "ok"
    assert view["rounds"][1]["results"]["smoke"]["status"] == "passed"
    assert view["rounds"][1]["results"]["compare"]["status"] == "applied"
    assert view["rounds"][1]["stop_reason"] == "repeated_facts"
    # 证据引用：报告里登记过的都列出来（去重，带来源）
    refs = {row["ref"] for row in view["evidence_refs"]}
    assert refs == {EVIDENCE_SHA, UNREGISTERED_SHA}
    assert view["report"]["sha256"] == sha
    assert "verified" not in json.dumps(view, ensure_ascii=False)
    assert "confirmed" not in json.dumps(view, ensure_ascii=False)

    events = _run_cli(platform_root, "research-events", TASK)
    assert events.returncode == 0, events.stderr
    rows = [json.loads(line) for line in events.stdout.splitlines() if line.strip()]
    assert [row["event_type"] for row in rows] == [
        "research.started", "exec.started", "exec.finished", "exec.finished",
        "research.mapped"]
    assert [row["round"] for row in rows[1:4]] == [1, 1, 2]
    assert rows[2]["status"] == "no_repro"
    assert rows[2]["evidence_refs"] == [EVIDENCE_SHA]
    assert rows[0]["phase"] == "START" and rows[2]["phase"] == "EXECUTE"

    whole = _run_cli(platform_root, "research-events", TASK, "--json",
                     "--kind", "exec", "--limit", "1")
    assert whole.returncode == 0, whole.stderr
    doc = json.loads(whole.stdout)
    assert doc["count"] == 1 and doc["total_after"] == 3
    assert doc["items"][0]["event_type"] == "exec.started"

    after = _run_cli(platform_root, "research-events", TASK, "--json",
                     "--after", str(rows[2]["seq"]))
    assert json.loads(after.stdout)["items"][0]["event_type"] == "exec.finished"

    # 只读：任务状态、事件数、报告字节一个都没变
    assert _snapshot(platform_root, report) == before


# ====================================================================== 2
def test_cli_exit_codes_for_missing_report_and_unknown_task(platform_root):
    _task(platform_root)                     # 任务在，但从未跑研究循环
    proc = _run_cli(platform_root, "research-status", TASK)
    assert proc.returncode == 1
    assert "no research report" in proc.stderr
    events = _run_cli(platform_root, "research-events", TASK)
    assert events.returncode == 1

    unknown = _run_cli(platform_root, "research-status", "task-does-not-exist")
    assert unknown.returncode == 2
    assert "not found" in unknown.stderr

    bad = _run_cli(platform_root, "research-events", "task-does-not-exist")
    assert bad.returncode == 2


def test_cli_reports_conflicting_report_as_error(platform_root):
    report, _sha = _fixture(platform_root)
    report.write_text("{not json", encoding="utf-8")
    proc = _run_cli(platform_root, "research-status", TASK)
    assert proc.returncode == 2
    assert "conflict" in proc.stderr


# ====================================================================== 3
def test_api_research_status_rounds_phases_actions(client, platform_root):
    _report_path, sha = _fixture(platform_root)
    r = client.get(f"/api/platform/tasks/{TASK}/research")
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["task_id"] == TASK
    assert view["schema"] == research_view.SCHEMA
    assert view["state"] == "NO_REPRO"
    assert view["stop_reason"] == "repeated_facts"
    assert view["rounds_count"] == 2 and view["max_rounds"] == 6
    assert len(view["rounds"]) == 2
    first, second = view["rounds"]
    assert first["diagnosis"]["code"] == "no_execution"
    assert first["revision"] == "" and second["revision"] == "hr-0001"
    assert [row["phase"] for row in first["phases"]][:2] == ["OBSERVE", "DIAGNOSE"]
    assert second["actions"][0]["tool"] == "run_epoch"
    assert second["actions"][0]["evidence_refs"] == [EVIDENCE_SHA,
                                                     UNREGISTERED_SHA]
    assert view["results"]["adopted"] == 0
    assert view["results"]["compare_status"] == {"unknown": 1, "applied": 1}
    assert view["report"]["sha256"] == sha
    assert {row["ref"] for row in view["evidence_refs"]} == {EVIDENCE_SHA,
                                                             UNREGISTERED_SHA}
    assert view["links"]["events"].endswith("/research/events")
    # 只读且有边界：没有裁决字段，报告路径就是研究产物
    text = json.dumps(view, ensure_ascii=False)
    assert "verified" not in text and "confirmed" not in text
    assert view["report"]["path"].endswith("research.json")


# ====================================================================== 4
def test_api_research_events_filters_and_404(client, platform_root):
    _fixture(platform_root)
    r = client.get(f"/api/platform/tasks/{TASK}/research/events")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["count"] == 5 and doc["total_after"] == 5
    assert doc["counts"]["exec.finished"] == 2
    assert doc["rounds"] == [1, 2]
    seqs = [item["seq"] for item in doc["items"]]
    assert seqs == sorted(seqs)

    tail = client.get(f"/api/platform/tasks/{TASK}/research/events",
                      params={"after": seqs[-2]}).json()
    assert tail["count"] == 1
    assert tail["items"][0]["event_type"] == "research.mapped"

    only_exec = client.get(f"/api/platform/tasks/{TASK}/research/events",
                           params={"kind": "exec"}).json()
    assert only_exec["count"] == 3
    assert {item["kind"] for item in only_exec["items"]} == {"exec"}

    limited = client.get(f"/api/platform/tasks/{TASK}/research/events",
                         params={"limit": 2}).json()
    assert limited["count"] == 2 and limited["total_after"] == 5
    assert limited["next_after"] == limited["items"][-1]["seq"]

    assert client.get("/api/platform/tasks/nope/research/events").status_code == 404


def test_api_research_events_404_without_session(client, platform_root):
    _task(platform_root)
    r = client.get(f"/api/platform/tasks/{TASK}/research/events")
    assert r.status_code == 404
    assert "no research events" in r.json()["detail"]


def test_api_research_events_409_when_report_without_session(client, platform_root):
    """报告说跑过、事件流里没有任何研究事件 → 事件流与产物矛盾（409）。"""
    _fixture(platform_root, with_events=False)
    r = client.get(f"/api/platform/tasks/{TASK}/research/events")
    assert r.status_code == 409
    assert "no research events" in r.json()["detail"]
    # 报告本身仍然可读：只有事件视图矛盾
    assert client.get(f"/api/platform/tasks/{TASK}/research").status_code == 200


# ====================================================================== 5
def test_api_research_evidence_resolves_registered_and_flags_unresolved(
        client, platform_root):
    _fixture(platform_root)
    store = PlatformStore(_db(platform_root))
    try:
        EvidenceStore(store, platform_root / "evidence").put_bytes(
            TASK, "exec_stats", EVIDENCE_BODY, source_stage="RUNNING")
    finally:
        store.close()
    r = client.get(f"/api/platform/tasks/{TASK}/research/evidence")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["count"] == 1
    assert doc["all_present"] is True and doc["all_hash_ok"] is True
    item = doc["items"][0]
    assert item["sha256"] == EVIDENCE_SHA
    assert item["kind"] == "exec_stats"
    assert item["download"].endswith(f"/evidence/{EVIDENCE_SHA}")
    assert {row["round"] for row in item["referenced_by"]} == {1, 2}
    assert [row["action_id"] for row in item["referenced_by"]] == ["run-r01",
                                                                  "run-r02"]
    assert [row["ref"] for row in doc["unresolved"]] == [UNREGISTERED_SHA]
    assert doc["unresolved"][0]["reason"] == "not_registered_for_this_task"
    assert doc["invalid_refs"] == []

    blob = client.get(item["download"])
    assert blob.status_code == 200
    assert blob.content == EVIDENCE_BODY

    # 只读：证据与报告都没被改
    assert client.get(f"/api/platform/tasks/{TASK}/research/evidence").json() == doc


# ====================================================================== 6
def test_api_research_404_for_unknown_task_and_missing_report(client, platform_root):
    for suffix in ("", "/events", "/evidence"):
        assert client.get(f"/api/platform/tasks/nope/research{suffix}").status_code == 404
    _task(platform_root)
    assert client.get(f"/api/platform/tasks/{TASK}/research").status_code == 404
    assert client.get(
        f"/api/platform/tasks/{TASK}/research/evidence").status_code == 404


def test_api_research_409_for_broken_or_foreign_or_tampered_report(
        client, platform_root):
    report, sha = _fixture(platform_root)

    # 1) 坏 JSON
    report.write_text("{not json", encoding="utf-8")
    for suffix in ("", "/evidence"):
        r = client.get(f"/api/platform/tasks/{TASK}/research{suffix}")
        assert r.status_code == 409, suffix
        assert "not valid JSON" in r.json()["detail"]

    # 2) schema 不认识
    report.write_text(json.dumps({"schema": "nope", "task_id": TASK}),
                      encoding="utf-8")
    r = client.get(f"/api/platform/tasks/{TASK}/research")
    assert r.status_code == 409
    assert "unsupported research report schema" in r.json()["detail"]

    # 3) 报告属于别的任务（串任务）
    foreign, _ = _write_report(platform_root, OTHER)
    report.write_text(foreign.read_text(encoding="utf-8"), encoding="utf-8")
    r = client.get(f"/api/platform/tasks/{TASK}/research")
    assert r.status_code == 409
    assert "belongs to another task" in r.json()["detail"]

    # 4) 与 research.mapped 登记的哈希不一致（产物被改写）
    path, _ = _write_report(platform_root)          # 恢复合法报告
    store = PlatformStore(_db(platform_root))
    try:
        assert EventBus(store).list(TASK)           # 事件仍在
    finally:
        store.close()
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["note"] = doc.get("note", "") + " tampered"
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2,
                              sort_keys=True) + "\n", encoding="utf-8")
    r = client.get(f"/api/platform/tasks/{TASK}/research")
    assert r.status_code == 409
    assert "sha256 mismatch" in r.json()["detail"]
    assert r.json()["detail"].startswith("research report sha256 mismatch")
    assert sha                                    # 原登记哈希非空


# ====================================================================== 7
def test_cross_task_isolation(client, platform_root):
    """A/B 两个任务各自一套报告与事件；证据与轮次互不串。"""
    report_a, sha_a = _fixture(platform_root, TASK)
    report_b, sha_b = _fixture(platform_root, OTHER, state="BLOCKED",
                               stop_reason="stage_failed",
                               controller_state="blocked")
    assert sha_a != sha_b
    store = PlatformStore(_db(platform_root))
    try:
        EvidenceStore(store, platform_root / "evidence").put_bytes(
            TASK, "exec_stats", EVIDENCE_BODY, source_stage="RUNNING")
    finally:
        store.close()

    a = client.get(f"/api/platform/tasks/{TASK}/research/evidence").json()
    b = client.get(f"/api/platform/tasks/{OTHER}/research/evidence").json()
    assert a["count"] == 1 and b["count"] == 0
    assert [row["ref"] for row in b["unresolved"]] == [EVIDENCE_SHA,
                                                       UNREGISTERED_SHA]
    assert b["unresolved"][0]["reason"] == "not_registered_for_this_task"
    assert b["task_evidence_count"] == 0

    a_events = client.get(f"/api/platform/tasks/{TASK}/research/events").json()
    b_events = client.get(f"/api/platform/tasks/{OTHER}/research/events").json()
    assert a_events["task_id"] == TASK and b_events["task_id"] == OTHER
    assert a_events["count"] == b_events["count"] == 5
    assert client.get(f"/api/platform/tasks/{OTHER}/research").json()["state"] == "BLOCKED"

    # 把 A 的报告塞进 B 的目录：产物属于别的任务 → 409，不冒充 B 的轮次
    report_b.write_text(report_a.read_text(encoding="utf-8"), encoding="utf-8")
    r = client.get(f"/api/platform/tasks/{OTHER}/research")
    assert r.status_code == 409
    assert "belongs to another task" in r.json()["detail"]
    # A 自己不受影响
    assert client.get(f"/api/platform/tasks/{TASK}/research").status_code == 200


# ====================================================================== 8
class _Runner:
    """fuzz 执行 worker 替身：写执行事实（P2C 同一边界，只替身执行器本身）。"""

    def __init__(self, store, task_id):
        self.store = store
        self.task_id = task_id
        self.calls = 0
        self.evidence_sha = EVIDENCE_SHA

    def __call__(self, *, kind, mode, params, binding):
        self.calls += 1
        exec_id = f"exec-r{self.calls:03d}-abcdef"
        payload = {
            "exec_id": exec_id, "kind": kind, "mode": mode,
            "outcome": "no_repro", "candidates": 0, "seconds": 0.01,
            "fuzz": {"execs": 5, "crashes": 0, "setup_error": ""},
            "coverage": {"planned": 4, "covered": 1, "uncovered": 3,
                         "status": "partial"},
            "evidence_sha256": self.evidence_sha, "error": None,
            "budget_usage": {"seconds": 0.01, "execs": 5, "tokens": 0,
                             "turns": 1},
        }
        self.store.append_event(self.task_id, "exec.started", stage="RUNNING",
                                payload={"exec_id": exec_id, "kind": kind})
        self.store.append_event(self.task_id, "exec.finished", stage="RUNNING",
                                payload=payload)
        return {"execution_id": exec_id, "kind": kind, "mode": mode,
                "outcome": "no_repro", "candidates": 0, "fuzz": payload["fuzz"],
                "coverage": payload["coverage"], "seeds": 1,
                "dictionary_tokens": 0, "format": "raw",
                "evidence_sha256": self.evidence_sha, "error": None,
                "budget_usage": payload["budget_usage"]}


def _program_index(root: Path) -> ProgramIndex:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "gen.py").write_text("def parse(b):\n    return b\n", encoding="utf-8")
    return ProgramIndex(
        benchmark="vulngym", root=str(src), task_id=TASK,
        entry_points=[{"name": "parse", "file": "gen.py"}],
        functions=[{"name": "parse", "file": "gen.py"}],
        call_sites=[{"id": "cs-1", "file": "gen.py", "line": 1,
                     "function": "parse", "callee": "parse"}],
        formats=["raw"], source_count=1, warnings=[])


def test_real_research_report_is_readable_by_api_and_cli(client, platform_root):
    """真跑一次 `run_research`（只替身执行 worker），产物直接被 API/CLI 读出。"""
    _task(platform_root)
    store = PlatformStore(_db(platform_root))
    try:
        store.save_program_index(TASK, _program_index(platform_root))
        store.save_hypotheses(TASK, [{
            "id": "hyp-1", "statement": "raw parser", "falsifiable_by": "diff",
            "evidence_gap": [], "cost": {"level": "low"}, "confidence": 0.4,
            "source": "static", "site_id": "cs-1", "hypothesis": "memcpy",
            "window": "gen.py:1-5", "falsification": "none"}])
        runner = _Runner(store, TASK)
        out = adaptive_cli.run_research(
            TASK, store, EventBus(store),
            workdir=platform_root / "work",
            evidence_root=platform_root / "evidence",
            research_root=platform_root / "research" / TASK,
            campaign="vulngym", max_rounds=3, exec_runner=runner)
    finally:
        store.close()

    assert out["rounds"] >= 1
    assert runner.calls >= 1
    report = platform_root / "research" / TASK / "research.json"
    assert report.is_file()
    assert out["report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()

    r = client.get(f"/api/platform/tasks/{TASK}/research")
    assert r.status_code == 200, r.text
    view = r.json()
    assert view["rounds_count"] == out["rounds"]
    assert view["executions"] >= 1
    assert view["report"]["sha256"] == out["report_sha256"]
    assert "OBSERVE" in [row["phase"] for row in view["phases"]]
    assert all(row["phases"] for row in view["rounds"])
    tools = [a["tool"] for row in view["rounds"] for a in row["actions"]]
    assert "run_epoch" in tools
    # 真产物里的证据引用指向执行证据（本轮已登记，能解析）
    refs = [row["ref"] for row in view["evidence_refs"]]
    assert EVIDENCE_SHA in refs
    store = PlatformStore(_db(platform_root))
    try:
        EvidenceStore(store, platform_root / "evidence").put_bytes(
            TASK, "exec_stats", EVIDENCE_BODY, source_stage="RUNNING")
    finally:
        store.close()
    ev = client.get(f"/api/platform/tasks/{TASK}/research/evidence").json()
    assert ev["count"] >= 1
    assert ev["all_present"] is True and ev["all_hash_ok"] is True

    proc = _run_cli(platform_root, "research-status", TASK)
    assert proc.returncode == 0, proc.stderr
    cli_view = json.loads(proc.stdout)
    assert cli_view["report"]["sha256"] == out["report_sha256"]
    assert cli_view["stop_reason"] == out["stop_reason"]

    events = _run_cli(platform_root, "research-events", TASK, "--json")
    assert events.returncode == 0, events.stderr
    doc = json.loads(events.stdout)
    assert doc["counts"].get("exec.finished", 0) == runner.calls
    assert doc["rounds"]


# ====================================================================== 9
def test_task_page_has_read_only_research_timeline(client, platform_root):
    _fixture(platform_root)
    r = client.get("/platform-task.html")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    page = r.text
    assert "研究轮次" in page
    assert "研究轮次" and "research-panel" in page
    assert "/research" in page and "loadResearch" in page
    assert "app.js" in page and "style.css" in page
    assert "sqlite" not in page.lower()
    for verb in ("DELETE", "PUT", "PATCH", "postJSON("):
        assert verb not in page, f"任务详情页出现写动作：{verb}"

    paths = {getattr(route, "path", "") for route in client.app.routes}
    for expected in ("/api/platform/tasks/{task_id}/research",
                     "/api/platform/tasks/{task_id}/research/events",
                     "/api/platform/tasks/{task_id}/research/evidence"):
        assert expected in paths
    # 任务详情响应把研究入口一起给出来（页面无需硬编码路由）
    detail = client.get(f"/api/platform/tasks/{TASK}").json()
    assert detail["links"]["research"].endswith("/research")
