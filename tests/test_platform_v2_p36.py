"""V2 P3.6 验收：预算强制（TERMINATED）+ 取消（CANCELLED）+ 失败不降级。

口径（与需求逐条对应）：

1. **预算强制**：`max_seconds / max_execs / max_tokens / max_turns` 四个上限
   都在执行前预检（还没跑就拒绝）、执行中按 fuzz stats / 耗时结算；
   越限写 `budget.exceeded` + `task.terminated`（`reason=budget_*`）+ 状态 `TERMINATED`；
2. **执行中截断**：本次执行的秒数被夹到剩余额度（`exec.started.caps.seconds`），
   `max_execs` / 截止时间 / 取消探针交给执行器在片边界判定；
3. **取消**：`RUNNING`/`PLANNED` 可取消 → `CANCELLED`（`task.cancel_requested` +
   `task.cancelled` + `cancel_snapshot` 证据）；终态拒绝取消；
   运行中被取消优先于任何结果升级，**不落 NO_REPRO**；
4. **失败不降级**：执行器失败落 `FAILED` + `exec_error` 证据，
   绝不冒充“预算内无崩溃”；
5. **证据保留**：超限/取消/失败都留事件与证据（含已产生的崩溃输入/日志），
   sha256 可现场复算；
6. **预算内正常完成**：`NO_REPRO` / `CANDIDATE` 语义与 P2 一致，且
   `exec.finished.budget.exceeded` 为空、`budget_usage` 落在上限内。

全局硬约束：任何 P3.6 产物都不得出现 `confirmed`；取消/超限都不会被记成 negative result。
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

from agent.platform import (Budget, EventBus, PlatformStore, TaskError,
                            TaskSpec, TERMINAL, cancel_task, can_transition,
                            run_execution, run_hypotheses, run_plan,
                            run_preflight, run_understand,
                            usage_from_events)
from agent.platform import executors
from agent.platform.budget import BudgetExceeded, BudgetGuard
from agent.platform.executors.fuzz import FuzzExecError
from agent.platform.lifecycle import (BUDGET_SNAPSHOT_KIND,
                                      CANCEL_SNAPSHOT_KIND, EXEC_ERROR_KIND,
                                      EXEC_STATS_KIND)

BIN = ROOT / "bin" / "platform.py"
FIXTURE = ROOT / "fixtures" / "discovery"

CRASH_INPUT = b"CRASH" + b"A" * 48
ASAN_LOG = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0\n"
            "#0 0x1 in parse_record a.c:16\n")


# ------------------------------------------------------------------ fixtures
def _planned(tmp_path, *, task_id="p36", budget=None, db_name="p36.db"):
    """把任务推进到 PLANNED（真跑 D0/D1/规划，不跑 fuzz）。"""
    store = PlatformStore(tmp_path / db_name)
    bus = EventBus(store)
    spec = TaskSpec(task_id=task_id, benchmark="target_yaml",
                    target=str(FIXTURE), budget=budget or Budget(),
                    metadata={"authorized": True})
    store.create_task(spec)
    bus.emit(task_id, "task.created", payload=spec.to_dict())
    assert run_preflight(task_id, store, bus)["state"] == "READY"
    assert run_understand(task_id, store, bus)["state"] == "UNDERSTANDING"
    assert run_hypotheses(task_id, store, bus)["state"] == "HYPOTHESES"
    assert run_plan(task_id, store, bus)["state"] == "PLANNED"
    return store, bus


def _run(tmp_path, store, bus, task_id="p36", **kw):
    kw.setdefault("workdir", tmp_path / "work" / task_id)
    kw.setdefault("evidence_root", tmp_path / "evidence")
    return run_execution(task_id, store, bus, **kw)


def _stats(**over) -> dict:
    base = {"execs": 10, "crashes": 0, "timeouts": 0, "new_coverage_bits": 8,
            "workers": 2, "first_crash_seconds": None, "corpus_files": 3,
            "crash_files": 0, "setup_errors": 0, "setup_error": None,
            "slices": 1, "stopped": "completed"}
    base.update(over)
    return base


def _crash(*, stack_hash="a" * 16, crash_type="heap-buffer-overflow") -> dict:
    return {
        "input_sha256": hashlib.sha256(CRASH_INPUT).hexdigest(),
        "input_bytes": CRASH_INPUT,
        "input_path": "/tmp/crash-1.bin",
        "log": ASAN_LOG,
        "log_path": "/tmp/crash-1.log",
        "parsed": {"crash_type": crash_type, "access": "WRITE",
                   "function": "parse_record", "file": "a.c", "line": 16,
                   "frames": [{"func": "parse_record", "file": "a.c",
                               "line": 16}]},
        "crash_type": crash_type,
        "stack_hash": stack_hash,
        "diagnostic_valid": True,
    }


def _result(*, execs=10, crashes=None, seconds=0.05, stopped="completed") -> dict:
    crashes = list(crashes or [])
    return {
        "ok": True,
        "format": "json",
        "seconds": seconds,
        "budget": {"seconds": seconds, "workers": 2, "timeout": 2.0},
        "build": {"binary": "/tmp/fuzzbin", "sha256": "b" * 64,
                  "cmd": ["cc"], "harness": "path_fuzz"},
        "seeds": 3,
        "dictionary_tokens": 4,
        "stats": _stats(execs=execs, crashes=len(crashes),
                        crash_files=len(crashes), stopped=stopped),
        "coverage": {"planned": 1, "covered": 1, "uncovered": 0,
                     "status": "complete"},
        "crashes": crashes,
        "paths": {"workdir": "w", "corpus": "c", "crashes": "cr",
                  "stats": "s"},
    }


def _patch(monkeypatch, fake):
    monkeypatch.setattr(executors, "execute_fuzz", fake)


def _events(bus, task_id, event_type=None):
    rows = bus.list(task_id)
    return [e for e in rows if event_type is None
            or e["event_type"] == event_type]


def _evidence(store, task_id, kind=None):
    rows = store.list_evidence(task_id)
    return [r for r in rows if kind is None or r["kind"] == kind]


def _payload(store, task_id, kind):
    """读回一份快照证据并校验 sha256 可复算。"""
    rows = _evidence(store, task_id, kind)
    assert rows, f"missing evidence kind={kind}"
    row = rows[-1]
    data = Path(row["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == row["sha256"]
    return json.loads(data.decode("utf-8"))


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), *args],
                          capture_output=True, text=True)


# ------------------------------------------------------- 1. 四个上限：执行前
def test_budget_seconds_precheck_terminates(tmp_path, monkeypatch):
    """已用秒数触顶：执行前就终止，执行器一次都不许被调用。"""
    store, bus = _planned(tmp_path, task_id="p36-sec",
                          budget=Budget(max_seconds=1))
    bus.emit("p36-sec", "exec.started", stage="RUNNING",
             payload={"exec_id": "exec-old", "budget": {"seconds": 5.0}})
    bus.emit("p36-sec", "exec.finished", stage="RUNNING",
             payload={"exec_id": "exec-old", "outcome": "no_repro",
                      "seconds": 5.0, "fuzz": {"execs": 10}})

    calls: list[dict] = []

    def fake(plan, index, hypotheses, **kwargs):  # pragma: no cover - 不该被调用
        calls.append(kwargs)
        return _result()

    _patch(monkeypatch, fake)
    out = _run(tmp_path, store, bus, "p36-sec")

    assert calls == []
    assert out["outcome"] == "budget_exceeded"
    assert out["state"] == "TERMINATED"
    task = store.get_task("p36-sec")
    assert task["state"] == "TERMINATED"
    assert task["terminal_reason"] == "budget_seconds"
    assert bus.replay("p36-sec")["state"] == "TERMINATED"

    exceeded = _events(bus, "p36-sec", "budget.exceeded")
    assert exceeded and exceeded[-1]["payload"]["reason"] == "budget_seconds"
    terminated = _events(bus, "p36-sec", "task.terminated")
    assert terminated and terminated[-1]["payload"]["reason"] == "budget_seconds"
    assert terminated[-1]["payload"]["from"] == "PLANNED"
    # 终止不是负结果：没有 NO_REPRO、没有候选
    assert store.list_candidates("p36-sec") == []
    assert [t["to"] for t in bus.replay("p36-sec")["transitions"]][-1] == "TERMINATED"

    snapshot = _payload(store, "p36-sec", BUDGET_SNAPSHOT_KIND)
    assert snapshot["reason"] == "budget_seconds"
    assert snapshot["limits"]["max_seconds"] == 1
    assert snapshot["used"]["seconds"] >= 5.0
    assert terminated[-1]["payload"]["evidence_sha256"] == _evidence(
        store, "p36-sec", BUDGET_SNAPSHOT_KIND)[-1]["sha256"]


def test_budget_tokens_precheck_terminates(tmp_path, monkeypatch):
    """max_tokens：LLM 用量从事件流累加，超限在执行前终止。"""
    store, bus = _planned(tmp_path, task_id="p36-tok",
                          budget=Budget(max_tokens=1000))
    bus.emit("p36-tok", "model.used", stage="HYPOTHESES",
             payload={"tokens": 1500, "model": "local"})
    assert usage_from_events(bus.list("p36-tok"))["tokens"] == 1500

    _patch(monkeypatch, lambda *a, **k: pytest.fail("执行器不该被调用"))
    out = _run(tmp_path, store, bus, "p36-tok")
    assert out["state"] == "TERMINATED"
    assert store.get_task("p36-tok")["terminal_reason"] == "budget_tokens"

    # 显式传入的 tokens_used 走同一口径
    store2, bus2 = _planned(tmp_path, task_id="p36-tok2",
                            budget=Budget(max_tokens=1000), db_name="p36b.db")
    out2 = _run(tmp_path, store2, bus2, "p36-tok2", tokens_used=2000)
    assert out2["state"] == "TERMINATED"
    assert store2.get_task("p36-tok2")["terminal_reason"] == "budget_tokens"


def test_budget_turns_precheck_terminates(tmp_path, monkeypatch):
    """max_turns：每次 exec.started 记一回合，没有回合可用就不再开跑。"""
    store, bus = _planned(tmp_path, task_id="p36-turn",
                          budget=Budget(max_turns=1))
    bus.emit("p36-turn", "exec.started", stage="RUNNING",
             payload={"exec_id": "exec-old"})
    _patch(monkeypatch, lambda *a, **k: pytest.fail("执行器不该被调用"))
    out = _run(tmp_path, store, bus, "p36-turn")
    assert out["state"] == "TERMINATED"
    assert store.get_task("p36-turn")["terminal_reason"] == "budget_turns"
    assert _events(bus, "p36-turn", "task.terminated")[-1]["payload"][
        "reason"] == "budget_turns"


# --------------------------------------------------- 2. 执行中：截断 + 结算
def test_budget_caps_requested_seconds(tmp_path, monkeypatch):
    """本次执行秒数被夹到剩余额度，并写进 exec.started.caps。"""
    store, bus = _planned(tmp_path, task_id="p36-cap",
                          budget=Budget(max_seconds=30))
    seen: dict = {}

    def fake(plan, index, hypotheses, **kwargs):
        seen.update(kwargs)
        return _result(execs=10)

    _patch(monkeypatch, fake)
    out = _run(tmp_path, store, bus, "p36-cap", seconds=120.0)

    assert seen["seconds"] == pytest.approx(30.0, abs=0.5)  # 120s → 剩余 30s
    assert seen["max_execs"] == 1_000_000     # 默认 exec 上限的剩余额度
    assert seen["deadline"] is not None
    started = _events(bus, "p36-cap", "exec.started")[-1]["payload"]
    assert started["caps"]["requested_seconds"] == 120.0
    assert started["caps"]["seconds"] == pytest.approx(30.0, abs=0.5)
    assert started["budget"]["seconds"] == pytest.approx(30.0, abs=0.5)
    # 截断后仍跑得完 → 正常结果，不是 TERMINATED
    assert out["outcome"] == "no_repro"
    assert out["state"] == "NO_REPRO"


def test_budget_execs_terminates_after_run(tmp_path, monkeypatch):
    """fuzz stats 的 execs 超限：终止，但已产生的候选/证据全部保留。"""
    store, bus = _planned(tmp_path, task_id="p36-execs",
                          budget=Budget(max_execs=100))
    seen: dict = {}

    def fake(plan, index, hypotheses, **kwargs):
        seen.update(kwargs)
        return _result(execs=250, crashes=[_crash()])

    _patch(monkeypatch, fake)
    out = _run(tmp_path, store, bus, "p36-execs")

    assert seen["max_execs"] == 100            # 剩余额度交给执行器做片边界截断
    assert out["outcome"] == "budget_exceeded"
    assert out["state"] == "TERMINATED"
    task = store.get_task("p36-execs")
    assert task["terminal_reason"] == "budget_execs"
    assert bus.replay("p36-execs")["state"] == "TERMINATED"

    finished = _events(bus, "p36-execs", "exec.finished")[-1]["payload"]
    assert finished["outcome"] == "budget_exceeded"
    assert finished["fuzz"]["execs"] == 250
    assert finished["budget"]["used"]["execs"] == 250
    assert finished["budget"]["exceeded"] == "budget_execs"
    assert finished["error"] and "budget_execs" in finished["error"]

    # 证据不丢：候选与崩溃输入/日志都还在
    candidates = store.list_candidates("p36-execs")
    assert len(candidates) == 1 and candidates[0]["state"] == "new"
    kinds = {row["kind"] for row in _evidence(store, "p36-execs")}
    assert {"crash_input", "crash_log", EXEC_STATS_KIND,
            BUDGET_SNAPSHOT_KIND} <= kinds
    assert _events(bus, "p36-execs", "candidate.created")
    snapshot = _payload(store, "p36-execs", BUDGET_SNAPSHOT_KIND)
    assert snapshot["used"]["execs"] == 250
    assert snapshot["stats"]["execs"] == 250
    assert "NO_REPRO" not in [t["to"] for t in
                              bus.replay("p36-execs")["transitions"]]


def test_executor_side_cap_is_termination_not_no_repro(tmp_path, monkeypatch):
    """执行器因额度截断而停（stopped=execs）：同样落 TERMINATED，不冒充跑完。"""
    store, bus = _planned(tmp_path, task_id="p36-stop",
                          budget=Budget(max_execs=1000))
    _patch(monkeypatch,
           lambda *a, **k: _result(execs=500, stopped="execs"))
    out = _run(tmp_path, store, bus, "p36-stop")
    assert out["outcome"] == "budget_exceeded"
    task = store.get_task("p36-stop")
    assert task["state"] == "TERMINATED"
    assert task["terminal_reason"] == "budget_execs"
    assert store.list_candidates("p36-stop") == []


# --------------------------------------------------------------- 3. 正常完成
def test_within_budget_completes_as_candidate(tmp_path, monkeypatch):
    """预算内跑出崩溃：CANDIDATE，budget.exceeded 为空。"""
    store, bus = _planned(tmp_path, task_id="p36-ok")
    _patch(monkeypatch, lambda *a, **k: _result(execs=120,
                                                crashes=[_crash()]))
    out = _run(tmp_path, store, bus, "p36-ok")

    assert out["outcome"] == "candidate"
    assert out["state"] == "CANDIDATE"
    assert len(out["candidates"]) == 1
    assert out["budget"]["exceeded"] is None
    finished = _events(bus, "p36-ok", "exec.finished")[-1]["payload"]
    assert finished["outcome"] == "candidate"
    assert finished["budget"]["exceeded"] is None
    assert finished["budget_usage"]["execs"] == 120
    assert not _events(bus, "p36-ok", "task.terminated")
    assert _events(bus, "p36-ok", "candidate.created")
    assert bus.replay("p36-ok")["state"] == "CANDIDATE"


def test_within_budget_no_crash_is_no_repro(tmp_path, monkeypatch):
    """预算内无崩溃：NO_REPRO（与 P2 同一口径，不是预算终止）。"""
    store, bus = _planned(tmp_path, task_id="p36-clean")
    _patch(monkeypatch, lambda *a, **k: _result(execs=120))
    out = _run(tmp_path, store, bus, "p36-clean")
    assert out["outcome"] == "no_repro"
    assert store.get_task("p36-clean")["state"] == "NO_REPRO"
    assert store.get_task("p36-clean")["terminal_reason"].startswith(
        "no crash within budget")
    assert not _events(bus, "p36-clean", "task.terminated")


# ------------------------------------------------------------------- 4. 取消
def test_cancel_planned_task(tmp_path):
    """PLANNED 可取消：取消请求 + 取消事件 + 快照证据 + 状态 CANCELLED。"""
    store, bus = _planned(tmp_path, task_id="p36-cancel")
    out = cancel_task("p36-cancel", store, bus, reason="operator stop",
                      actor="cli", evidence_root=tmp_path / "evidence")

    assert out["state"] == "CANCELLED"
    assert out["from"] == "PLANNED"
    task = store.get_task("p36-cancel")
    assert task["state"] == "CANCELLED"
    assert task["terminal_reason"] == "cancelled: operator stop"
    assert bus.replay("p36-cancel")["state"] == "CANCELLED"

    requested = _events(bus, "p36-cancel", "task.cancel_requested")
    cancelled = _events(bus, "p36-cancel", "task.cancelled")
    assert requested and cancelled
    assert requested[-1]["payload"]["from"] == "PLANNED"
    assert cancelled[-1]["payload"]["reason"] == "operator stop"
    assert cancelled[-1]["payload"]["evidence_sha256"] == out["evidence_sha256"]

    snapshot = _payload(store, "p36-cancel", CANCEL_SNAPSHOT_KIND)
    assert snapshot["from"] == "PLANNED"
    assert snapshot["reason"] == "operator stop"
    assert snapshot["events"] >= 1
    assert snapshot["budget"]["max_seconds"] >= 1

    # 取消后不能再执行（run 只受理 PLANNED）
    with pytest.raises(Exception):
        _run(tmp_path, store, bus, "p36-cancel")


def test_cancel_while_running_is_not_downgraded(tmp_path, monkeypatch):
    """RUNNING 被取消：exec.finished(cancelled)，状态保持 CANCELLED，不落 NO_REPRO。"""
    store, bus = _planned(tmp_path, task_id="p36-cancel-run")

    def fake(plan, index, hypotheses, **kwargs):
        cancel_task("p36-cancel-run", store, bus, reason="operator stop",
                    actor="api", evidence_root=tmp_path / "evidence")
        return _result(execs=20, crashes=[_crash()])

    _patch(monkeypatch, fake)
    out = _run(tmp_path, store, bus, "p36-cancel-run")

    assert out["outcome"] == "cancelled"
    assert store.get_task("p36-cancel-run")["state"] == "CANCELLED"
    assert bus.replay("p36-cancel-run")["state"] == "CANCELLED"
    finished = _events(bus, "p36-cancel-run", "exec.finished")[-1]["payload"]
    assert finished["outcome"] == "cancelled"
    assert "error" in finished and finished["error"] in (None, "")
    # 取消也要如实记账：已经跑掉的 execs 不能凭空消失
    assert finished["budget_usage"]["execs"] == 20
    # 停止前的崩溃证据仍在
    assert store.list_candidates("p36-cancel-run")
    kinds = {row["kind"] for row in _evidence(store, "p36-cancel-run")}
    assert {"crash_input", "crash_log", EXEC_STATS_KIND,
            CANCEL_SNAPSHOT_KIND} <= kinds
    transitions = [t["to"] for t in bus.replay("p36-cancel-run")["transitions"]]
    assert "NO_REPRO" not in transitions and "CANDIDATE" not in transitions


def test_cancel_terminal_task_refused(tmp_path):
    """终态不可取消：状态/事件/证据都不变。"""
    store, bus = _planned(tmp_path, task_id="p36-done")
    _patch_terminal = None  # noqa: F841 - 仅为可读性
    store.transition("p36-done", "RUNNING", reason="t")
    store.transition("p36-done", "FAILED", reason="boom")
    before_events = len(bus.list("p36-done"))
    before_evidence = len(_evidence(store, "p36-done"))

    with pytest.raises(TaskError):
        cancel_task("p36-done", store, bus, reason="late")

    assert store.get_task("p36-done")["state"] == "FAILED"
    assert len(bus.list("p36-done")) == before_events
    assert len(_evidence(store, "p36-done")) == before_evidence


def test_cancelled_and_terminated_are_terminal_states():
    """状态机：PLANNED/RUNNING 可取消/终止，CANCELLED/TERMINATED 无出边。"""
    for src in ("PLANNED", "RUNNING"):
        assert can_transition(src, "CANCELLED")
        assert can_transition(src, "TERMINATED")
    assert "CANCELLED" in TERMINAL and "TERMINATED" in TERMINAL
    for src in ("CANCELLED", "TERMINATED", "CLOSED", "FAILED"):
        assert src in TERMINAL
        assert not can_transition(src, "CANCELLED")
        assert not can_transition(src, "RUNNING")


# ------------------------------------------------------ 5. 失败不降级 + 证据
def test_execution_failure_keeps_failed_and_evidence(tmp_path, monkeypatch):
    """执行器失败：FAILED + exec_error 证据，绝不落 NO_REPRO。"""
    store, bus = _planned(tmp_path, task_id="p36-fail")

    def boom(*args, **kwargs):
        raise FuzzExecError("build failed: missing compiler")

    _patch(monkeypatch, boom)
    with pytest.raises(FuzzExecError):
        _run(tmp_path, store, bus, "p36-fail")

    task = store.get_task("p36-fail")
    assert task["state"] == "FAILED"
    assert bus.replay("p36-fail")["state"] == "FAILED"
    finished = _events(bus, "p36-fail", "exec.finished")[-1]["payload"]
    assert finished["outcome"] == "failed"
    assert "build failed" in finished["error"]
    assert not _events(bus, "p36-fail", "task.terminated")
    error_doc = _payload(store, "p36-fail", EXEC_ERROR_KIND)
    assert "build failed" in error_doc["error"]
    assert error_doc["type"] == "FuzzExecError"
    transitions = [t["to"] for t in bus.replay("p36-fail")["transitions"]]
    assert "NO_REPRO" not in transitions


# ----------------------------------------------------------------- 6. 预算账本
def test_budget_guard_ledger_semantics():
    """账本口径：预检 >= 限额，结算 > 限额（正好用满不算超限）。"""
    budget = {"max_seconds": 10, "max_execs": 100, "max_tokens": 50,
              "max_turns": 2}
    guard = BudgetGuard(budget, used={"seconds": 10.0, "execs": 100,
                                      "tokens": 50, "turns": 2})
    with pytest.raises(BudgetExceeded):
        guard.precheck()
    snapshot = guard.snapshot()
    # 正好用满：严格口径不算“超限”，但预检口径已经没有额度
    assert snapshot["exceeded"] is None
    assert "budget_seconds" in snapshot["at_limit"]
    assert snapshot["remaining"]["seconds"] == 0
    assert snapshot["violations"] == []

    at_limit = BudgetGuard({"max_seconds": 10, "max_execs": 100,
                            "max_tokens": 50, "max_turns": 2})
    at_limit.begin()
    live = at_limit.absorb(execs=0)      # 0 用量，结算不报错
    assert live["execs"] == 0
    assert at_limit.cap_seconds(120.0) == pytest.approx(10.0, abs=0.5)


# ------------------------------------------------------------------- 7. CLI
def test_cli_cancel_and_budget(tmp_path):
    """CLI：cancel 可取消，终态再 cancel 退出码 2；budget 只读报账。"""
    db = tmp_path / "cli.db"
    submit = _run_cli("--db", str(db), "submit", "--task-id", "cli-p36",
                      "--benchmark", "target_yaml",
                      "--target", str(FIXTURE),
                      "--budget-seconds", "30", "--budget-execs", "5",
                      "--budget-tokens", "100", "--budget-turns", "2",
                      "--meta", "authorized=true")
    assert submit.returncode == 0, submit.stderr

    proc = _run_cli("--db", str(db), "cancel", "cli-p36",
                    "--reason", "operator stop", "--actor", "cli",
                    "--evidence-root", str(tmp_path / "evidence"))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["state"] == "CANCELLED" and out["from"] == "RECEIVED"

    status = json.loads(_run_cli("--db", str(db), "status",
                                 "cli-p36").stdout)
    assert status["task"]["state"] == "CANCELLED"
    assert status["replay"]["state"] == "CANCELLED"
    assert status["budget_usage"]["max_execs"] == 5

    budget = json.loads(_run_cli("--db", str(db), "budget",
                                 "cli-p36").stdout)
    assert budget["limits"]["max_turns"] == 2
    assert budget["used"]["turns"] == 0
    assert budget["exceeded"] is None

    again = _run_cli("--db", str(db), "cancel", "cli-p36")
    assert again.returncode == 2
    assert "cancel failed" in again.stderr


@pytest.mark.skipif(not FIXTURE.exists(), reason="discovery fixture missing")
def test_cli_run_terminates_on_budget_execs(tmp_path):
    """CLI 端到端：max_execs 极小时真跑一次也只会落 TERMINATED（退出码 3）。"""
    db = tmp_path / "run.db"
    evidence = tmp_path / "evidence"
    steps = (
        ("submit", "--task-id", "cli-run-p36", "--benchmark", "target_yaml",
         "--target", str(FIXTURE), "--budget-execs", "1",
         "--meta", "authorized=true"),
        ("preflight", "cli-run-p36"),
        ("understand", "cli-run-p36"),
        ("hypotheses", "cli-run-p36"),
        ("plan", "cli-run-p36"),
    )
    for argv in steps:
        proc = _run_cli("--db", str(db), *argv)
        assert proc.returncode in (0, 1), proc.stderr
        assert "failed" not in proc.stderr, proc.stderr

    proc = _run_cli("--db", str(db), "run", "cli-run-p36",
                    "--seconds", "1", "--evidence-root", str(evidence),
                    "--workdir", str(tmp_path / "work"))
    assert proc.returncode == 3, (proc.returncode, proc.stderr, proc.stdout)
    out = json.loads(proc.stdout)
    assert out["outcome"] == "budget_exceeded"
    assert out["state"] == "TERMINATED"
    assert out["terminated"]["reason"] == "budget_execs"

    events = [json.loads(line) for line in
              _run_cli("--db", str(db), "events", "cli-run-p36").stdout
              .splitlines() if line.strip()]
    terminated = [e for e in events if e["event_type"] == "task.terminated"]
    assert terminated and terminated[-1]["payload"]["reason"] == "budget_execs"
    assert any(row["kind"] == BUDGET_SNAPSHOT_KIND
               for row in json.loads(_run_cli("--db", str(db), "evidence",
                                              "cli-run-p36").stdout))
