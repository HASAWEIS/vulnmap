r"""V3-P2C 验收：`platform run --research` 的研究循环接线。

口径对应《V3 完整升级方案》§4（双循环）、§5（执行感知）、§8（版本事务）、
§12（独立验证：

1. **PLANNED 走研究循环**：任务从 `PLANNED` 出发，`run --research` 真跑
   `OBSERVE → DIAGNOSE → PROPOSE → AUTHORIZE → STAGE/BUILD/SMOKE/ADOPT
   → EXECUTE → COLLECT → COMPARE → STOP`；第 1 轮没执行事实 → `no_execution`，
   第 1 轮的 miss 改变第 2 轮动作（改 `seed_params.json`、raw→magic）→ 真构建
   （`py_compile`）+ 真冒烟 → 工程采纳 → 第 2 轮命中 → `candidate_ready`。
2. **状态按结果映射**：`CANDIDATE` 只表示“可以交给既有 verify”；
   `list_verifications()==[]`、`list_candidates()==[]`，`research.json` 里没有
   任何漏洞结论字段。
3. **相同事实有限停止**：runner 恒 no_repro → 只跑 2 个 epoch，第 3 轮 OBSERVE
   即 `repeated_facts`，没有第 3 次 EXECUTE。
4. **无证据不伪造**：worker 只在返回值里“声称跑过”（事件流里没有
   `exec.started/exec.finished`）→ 快照 unknown → 落 `NEEDS_EVIDENCE`，
   不给 `NO_REPRO`。
5. **失败保留**：执行器失败（`exec.finished(outcome=failed, error=...)`）→
   `BLOCKED`，不降级成负结果。
6. **CLI 参数**：`--research / --max-rounds / --campaign` 真的进到
   `run_research()`；退出码按映射状态给出。

构建/冒烟是真实 `subprocess.run`（`py_compile` + 本地 python 脚本）；
只有 **执行 worker**（fuzz 执行器）用替身，与 P2b 的边界一致：P2C 不宣称跑过
CG/EG/VG 真实目标。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import EventBus, PlatformStore, TaskSpec, Budget  # noqa: E402
from agent.platform.adaptive import cli as cli_mod  # noqa: E402
from agent.platform.adaptive.cli import map_state, run_research  # noqa: E402
from agent.platform.adaptive.controller import (ControllerResult,  # noqa: E402
                                                RoundRecord)
from agent.platform.program import ProgramIndex  # noqa: E402
from bin import platform as platform_cli  # noqa: E402

TASK = "task-v3-p2c"

#: 任务原件：`gen.py` 按 seed_params.json 的 format 产出前缀，
#: `smoke.py` 只有 format=magic 才返回 0（这是“目标侧行为”的判据）。
GEN_PY = (
    "import json\n"
    "from pathlib import Path\n"
    "def build(i=0):\n"
    "    p=json.loads(Path('seed_params.json').read_text())\n"
    "    return (b'MAGIC' if p.get('format')=='magic' else b'raw')+bytes([i])\n"
)
SMOKE_PY = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "import gen\n"
    "p=json.loads(Path('seed_params.json').read_text())\n"
    "if p.get('format')!='magic':\n"
    "    print('target not reached'); sys.exit(1)\n"
    "print('smoke ok')\n"
)
SEED_PARAMS_RAW = '{"format":"raw"}\n'
ORIGIN_FILES = {"gen.py": GEN_PY, "smoke.py": SMOKE_PY,
                "seed_params.json": SEED_PARAMS_RAW}
SEED_PARAMS_MAGIC = json.dumps(
    {"format": "magic", "seed_count": 2,
     "constraints": {"prefix": "MAGIC", "length": 8}},
    ensure_ascii=False, indent=2, sort_keys=True) + "\n"

BUILD_CMD = [sys.executable, "-m", "py_compile", "gen.py", "smoke.py"]
SMOKE_CMD = [sys.executable, "smoke.py"]


# ------------------------------------------------------------------ fixture
def _origin(base: Path) -> Path:
    origin = base / "origin"
    origin.mkdir(parents=True, exist_ok=True)
    for rel, body in ORIGIN_FILES.items():
        (origin / rel).write_text(body, encoding="utf-8")
    return origin


def _index(base: Path) -> ProgramIndex:
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "gen.py").write_text("def parse(b):\n    return b\n",
                                encoding="utf-8")
    return ProgramIndex(
        benchmark="vulngym", root=str(src), task_id=TASK,
        entry_points=[{"name": "parse", "file": "gen.py"}],
        functions=[{"name": "parse", "file": "gen.py"}],
        call_sites=[{"id": "cs-1", "file": "gen.py", "line": 1,
                     "function": "parse", "callee": "parse"}],
        formats=["raw"], source_count=1, warnings=[])


def _planned_task(base: Path, *, commands: bool = True
                  ) -> tuple[PlatformStore, dict]:
    """把任务推到 PLANNED：状态机逐跳迁移（不用 plan 的规划器，只测运行侧）。"""
    origin = _origin(base)
    store = PlatformStore(base / "platform.db")
    metadata = {"authorized": True}
    if commands:
        metadata.update({"build_command": BUILD_CMD, "smoke_command": SMOKE_CMD})
    store.create_task(TaskSpec(
        task_id=TASK, benchmark="vulngym", target=str(origin), mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=100000, max_tokens=100000,
                      max_turns=12), metadata=metadata))
    for dst in ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED"):
        store.transition(TASK, dst, reason="p2c fixture")
    store.save_program_index(TASK, _index(base))
    store.save_hypotheses(TASK, [{
        "id": "hyp-1", "statement": "magic parser", "falsifiable_by": "diff",
        "evidence_gap": [], "cost": {"level": "low"}, "confidence": 0.5,
        "source": "static", "site_id": "cs-1", "hypothesis": "memcpy",
        "window": "gen.py:1-5", "falsification": "none"}])
    return store, store.get_task(TASK)


class FakeRunner:
    """执行 worker 替身：按第几次调用决定 hit，并把执行事实写进事件流。

    与 P2b 同一边界：只替身 fuzz 执行器本身；构建/冒烟/日志仍是真实执行。
    `emit=False` 用于“只声称跑过、事件流里没有事实”的反例。
    """

    def __init__(self, store, *, task_id=TASK, hit_from=None, emit=True,
                 fail=False):
        self.store = store
        self.task_id = task_id
        self.hit_from = hit_from
        self.emit = bool(emit)
        self.fail = bool(fail)
        self.calls: list[dict] = []

    def __call__(self, *, kind, mode, params, binding):
        n = len(self.calls) + 1
        exec_id = f"exec-{n:04d}"
        hit = bool(self.hit_from is not None and n >= int(self.hit_from))
        fuzz = {"execs": 10, "crashes": 1 if hit else 0, "timeouts": 0,
                "new_coverage_bits": 5 if hit else 0, "workers": 1,
                "corpus_files": 2, "crash_files": 0, "setup_errors": 0,
                "setup_error": "", "slices": 1, "stopped": "completed"}
        coverage = {"planned": 10, "covered": 7 if hit else 2,
                    "uncovered": 3 if hit else 8, "status": "partial",
                    "pcs": 20, "mapped_locations": 7 if hit else 2, "error": ""}
        build = {"sha256": binding.identity.get("build_id") or "corpusbuild"}
        self.calls.append(dict(params))
        if self.fail:
            error = "FuzzExecError: build failed: fixture"
            if self.emit:
                self._emit("exec.started", {
                    "exec_id": exec_id, "kind": kind, "plan_sha256": "p" * 40,
                    "benchmark": "vulngym", "target": "gen"})
                self._emit("exec.finished", {
                    "exec_id": exec_id, "kind": kind, "outcome": "failed",
                    "plan_sha256": "p" * 40, "candidates": None, "seconds": 0.1,
                    "build": None, "fuzz": {}, "coverage": {},
                    "error": error, "budget_usage": {"seconds": 0.1,
                                                     "turns": 1}})
            return {"execution_id": exec_id, "kind": kind, "mode": mode,
                    "outcome": "failed", "candidates": None, "build": None,
                    "fuzz": {}, "coverage": {}, "seeds": None,
                    "dictionary_tokens": None, "format": None,
                    "budget_usage": {"seconds": 0.1, "turns": 1},
                    "evidence_sha256": None, "error": error}
        outcome = "candidate" if hit else "no_repro"
        if self.emit:
            self._emit("exec.started", {
                "exec_id": exec_id, "kind": kind, "plan_sha256": "p" * 40,
                "benchmark": "vulngym", "target": "gen"})
            self._emit("exec.finished", {
                "exec_id": exec_id, "kind": kind, "outcome": outcome,
                "plan_sha256": "p" * 40, "candidates": 1 if hit else 0,
                "seconds": 0.2, "build": build, "fuzz": fuzz,
                "coverage": coverage, "seeds": 2, "dictionary_tokens": 3,
                "format": "raw", "budget_usage": {"seconds": 0.2, "execs": 10,
                                                  "tokens": 0, "turns": 1},
                "evidence_sha256": ("e" if hit else "m") * 64,
                "target_reached": hit, "error": None, "tokens": 0})
        return {"execution_id": exec_id, "kind": kind, "mode": mode,
                "outcome": outcome, "candidates": 1 if hit else 0,
                "build": build, "fuzz": fuzz, "coverage": coverage,
                "seeds": 2, "dictionary_tokens": 3, "format": "raw",
                "budget_usage": {"seconds": 0.2, "execs": 10, "tokens": 0,
                                 "turns": 1},
                "evidence_sha256": ("e" if hit else "m") * 64,
                "target_reached": hit, "error": None}

    def _emit(self, event_type: str, payload: dict) -> None:
        self.store.append_event(self.task_id, event_type, stage="RUNNING",
                                payload=payload)


def _research(base: Path, *, runner=None, max_rounds=4, campaign="vulngym",
              **kwargs) -> tuple[dict, PlatformStore]:
    store, _task = _planned_task(base)
    bus = EventBus(store)
    out = run_research(
        TASK, store, bus, workdir=base / "work",
        evidence_root=base / "evidence", research_root=base / "research",
        campaign=campaign, max_rounds=max_rounds, exec_runner=runner, **kwargs)
    return out, store


def _transitions(store: PlatformStore) -> list[tuple[str, str]]:
    return [(ev["payload"]["from"], ev["payload"]["to"])
            for ev in store.list_events(TASK)
            if ev["event_type"] == "state.changed"]


def _events(store: PlatformStore, event_type: str) -> list[dict]:
    return [ev for ev in store.list_events(TASK)
            if ev["event_type"] == event_type]


def _round_phases(out: dict, phase: str) -> list[dict]:
    return [item for item in out["controller"]["timeline"]
            if item["phase"] == phase]


# ====================================================================== 1 + 2
def test_two_rounds_from_planned_reach_candidate_without_writing_verdict(tmp_path):
    """PLANNED 出发：首轮 miss → 改副本+真构建/真冒烟 → 第 2 轮命中 → CANDIDATE。"""
    store, _task = _planned_task(tmp_path)
    runner = FakeRunner(store, hit_from=2)
    out = run_research(
        TASK, store, EventBus(store), workdir=tmp_path / "work",
        evidence_root=tmp_path / "evidence",
        research_root=tmp_path / "research", campaign="vulngym",
        max_rounds=4, exec_runner=runner)

    # ---- 两轮，两轮语义不同 ----
    assert out["state"] == "CANDIDATE"
    assert out["controller_state"] == "completed"
    assert out["stop_reason"] == "candidate_ready"
    assert out["rounds"] == 2
    assert out["executions"] == 2
    assert out["candidates"] == 1
    assert out["verification_allowed"] is True
    assert len(runner.calls) == 2

    rounds = out["controller"]["rounds"]
    assert rounds[0]["diagnosis"]["code"] == "no_execution"
    assert rounds[0]["revision"] == ""            # attempt 0 不改副本
    assert rounds[0]["adopted"] is False
    assert rounds[1]["diagnosis"]["code"] == "target_unreached"
    assert rounds[1]["revision"].startswith("hr-")
    assert rounds[1]["adopted"] is True           # 工程采纳（不是漏洞结论）
    assert rounds[1]["build"]["status"] == "ok"
    assert rounds[1]["smoke"]["status"] == "passed"

    # 第 2 轮动作真的换了策略：raw → magic + 字典
    second_tools = [action["tool"] for action in rounds[1]["actions"]]
    assert "run_epoch" in second_tools
    assert "set_dictionary" in second_tools
    assert [a for a in rounds[1]["actions"] if a["tool"] == "run_epoch"][0][
        "status"] == "applied"

    # 副本里确实是 magic（真 stage/commit 的结果）
    ws_root = tmp_path / "research" / "ws"
    assert (ws_root / "current" / "seed_params.json").read_text(
        encoding="utf-8") == SEED_PARAMS_MAGIC
    assert (ws_root / "store" / "adoptions.jsonl").is_file()
    adoption = json.loads(
        (ws_root / "store" / "adoptions.jsonl").read_text(
            encoding="utf-8").strip().splitlines()[0])
    assert adoption["scope"] == "engineering"

    # ---- 状态迁移与事件（研究循环自己走的那两跳，前面的准备跳不算） ----
    assert _transitions(store)[-2:] == [("PLANNED", "RUNNING"),
                                        ("RUNNING", "CANDIDATE")]
    assert store.get_task(TASK)["state"] == "CANDIDATE"
    assert _events(store, "research.started")
    mapped = _events(store, "research.mapped")
    assert mapped and mapped[-1]["payload"]["state"] == "CANDIDATE"
    assert _events(store, "research.finished")        # 控制器自己发的那条
    assert _events(store, "exec.started") and _events(store, "exec.finished")

    # ---- 不写裁决、不建候选 ----
    assert store.list_verifications(TASK) == []
    assert store.list_candidates(TASK) == []
    report = tmp_path / "research" / "research.json"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    doc = json.loads(text)
    assert doc["schema"] == "vulnmap.research.run.v1"
    assert doc["state"] == "CANDIDATE"
    assert doc["note"]
    assert "verified" not in text
    assert "confirmed" not in text
    assert doc["controller"]["verification"]["allowed"] is True
    # 报告里的哈希可按字节复算
    assert out["report_sha256"] == hashlib.sha256(
        report.read_bytes()).hexdigest()


# ====================================================================== 3
def test_same_facts_stop_after_two_epochs(tmp_path):
    """相同事实有限停止：2 个 epoch 后第 3 轮 OBSERVE 即 repeated_facts。"""
    store, _task = _planned_task(tmp_path)
    runner = FakeRunner(store)
    out = run_research(
        TASK, store, EventBus(store), workdir=tmp_path / "work",
        evidence_root=tmp_path / "evidence",
        research_root=tmp_path / "research", campaign="vulngym",
        max_rounds=6, exec_runner=runner)

    assert out["stop_reason"] == "repeated_facts"
    assert out["controller_state"] == "completed"
    assert out["rounds"] == 3
    assert out["executions"] == 2
    assert out["candidates"] == 0
    assert out["verification_allowed"] is False
    assert len(runner.calls) == 2                    # 第 3 轮没有再执行
    assert not [item for item in out["controller"]["timeline"]
                if item["phase"] == "EXECUTE" and item["round"] == 3]
    # 有真实观测 + 真执行、无候选 → NO_REPRO（这是停止原因，不是漏洞结论）
    assert out["state"] == "NO_REPRO"
    assert out["observed_rounds"] >= 1
    assert store.get_task(TASK)["state"] == "NO_REPRO"
    assert store.list_verifications(TASK) == []


# ====================================================================== 4
def test_claimed_execution_without_events_is_never_no_repro(tmp_path):
    """只在返回值里“跑过”、事件流里没有事实 → NEEDS_EVIDENCE，不伪造负结果。"""
    store, _task = _planned_task(tmp_path)
    runner = FakeRunner(store, emit=False)
    out = run_research(
        TASK, store, EventBus(store), workdir=tmp_path / "work",
        evidence_root=tmp_path / "evidence",
        research_root=tmp_path / "research", campaign="vulngym",
        max_rounds=4, exec_runner=runner)

    assert out["state"] == "NEEDS_EVIDENCE"
    assert out["observed_rounds"] == 0
    assert out["executions"] >= 1                    # 动作确实被调用过
    assert out["verification_allowed"] is False
    assert out["stop_reason"] != "candidate_ready"
    assert store.get_task(TASK)["state"] == "NEEDS_EVIDENCE"
    assert _events(store, "exec.finished") == []      # 事件流里没有任何执行事实
    doc = json.loads((tmp_path / "research" / "research.json").read_text(
        encoding="utf-8"))
    assert doc["observed_rounds"] == 0
    assert doc["state"] == "NEEDS_EVIDENCE"


# ====================================================================== 5
def test_executor_failure_is_blocked_and_not_downgraded(tmp_path):
    """执行器失败（error 进事件）→ BLOCKED，绝不落 NO_REPRO。"""
    store, _task = _planned_task(tmp_path)
    runner = FakeRunner(store, fail=True)
    out = run_research(
        TASK, store, EventBus(store), workdir=tmp_path / "work",
        evidence_root=tmp_path / "evidence",
        research_root=tmp_path / "research", campaign="vulngym",
        max_rounds=4, exec_runner=runner)

    assert out["state"] == "BLOCKED"
    assert out["controller_state"] == "blocked"
    assert out["stop_reason"] == "execution_error"
    assert out["candidates"] == 0
    assert store.get_task(TASK)["state"] == "BLOCKED"
    assert store.list_verifications(TASK) == []
    finished = _events(store, "exec.finished")
    assert finished and finished[-1]["payload"]["outcome"] == "failed"
    assert "error" in finished[-1]["payload"]


# ====================================================================== 6
def test_map_state_table():
    """映射表逐项：CANDIDATE 只在 allowed 时给，失败/预算/取消各走各的。"""
    candidate = ControllerResult(
        status="completed", stop_reason="candidate_ready",
        rounds=[RoundRecord(round_no=1)])
    from agent.platform.adaptive.policy import VerificationRequest
    candidate.verification = VerificationRequest(
        allowed=True, candidate_refs=("e" * 64,), diagnosis="candidate_observed")
    assert map_state(candidate, epochs=1, observed=1) == "CANDIDATE"

    blocked_verify = ControllerResult(
        status="blocked", stop_reason="verification_blocked",
        rounds=[RoundRecord(round_no=1)])
    blocked_verify.verification = VerificationRequest(
        allowed=False, blockers=("no_evidence_ref",))
    assert map_state(blocked_verify, epochs=1, observed=1) == "NEEDS_EVIDENCE"

    assert map_state(ControllerResult(status="cancelled",
                                      stop_reason="cancelled")) == "CANCELLED"
    assert map_state(ControllerResult(status="budget",
                                      stop_reason="budget")) == "TERMINATED"
    assert map_state(ControllerResult(status="failed",
                                      stop_reason="error:RuntimeError")) == "FAILED"
    assert map_state(ControllerResult(status="blocked",
                                      stop_reason="policy_blocked")) == "BLOCKED"
    # 完成但没有任何可信观测 → 不给 NO_REPRO
    assert map_state(ControllerResult(status="completed",
                                      stop_reason="repeated_facts"),
                     epochs=2, observed=0) == "NEEDS_EVIDENCE"
    assert map_state(ControllerResult(status="completed",
                                      stop_reason="repeated_facts"),
                     epochs=0, observed=2) == "NEEDS_EVIDENCE"
    assert map_state(ControllerResult(status="completed",
                                      stop_reason="repeated_facts"),
                     epochs=2, observed=2) == "NO_REPRO"


# ====================================================================== 7
def test_run_research_requires_planned_and_program_index(tmp_path):
    """前置条件不成立时不动状态（不是运行期失败的替代品）。"""
    store, _task = _planned_task(tmp_path)
    store.transition(TASK, "RUNNING", reason="fixture: not planned")
    with pytest.raises(cli_mod.ResearchError):
        run_research(TASK, store, EventBus(store),
                     research_root=tmp_path / "research")
    assert store.get_task(TASK)["state"] == "RUNNING"

    other = PlatformStore(tmp_path / "noindex.db")
    other.create_task(TaskSpec(task_id=TASK, benchmark="vulngym",
                               target=str(tmp_path / "origin"),
                               metadata={"authorized": True}))
    for dst in ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED"):
        other.transition(TASK, dst, reason="fixture")
    with pytest.raises(cli_mod.ResearchError) as excinfo:
        run_research(TASK, other, EventBus(other),
                     research_root=tmp_path / "research2")
    assert "ProgramIndex" in str(excinfo.value)
    assert other.get_task(TASK)["state"] == "PLANNED"


# ====================================================================== 8
def test_cli_research_flags_are_wired(tmp_path, monkeypatch):
    """`run --research --max-rounds --campaign` 真的进到 run_research()。"""
    base = tmp_path
    _planned_task(base)
    seen: dict = {}

    def fake_run_research(task_id, store, bus, **kwargs):
        seen.update(kwargs, task_id=task_id)
        return {"task_id": task_id, "state": "CANDIDATE", "schema": "x"}

    monkeypatch.setattr(cli_mod, "run_research", fake_run_research)
    code = platform_cli.main([
        "--db", str(base / "platform.db"), "run", TASK, "--research",
        "--max-rounds", "2", "--campaign", "cg-x", "--seconds", "0.5"])
    assert code == 0
    assert seen["task_id"] == TASK
    assert seen["max_rounds"] == 2
    assert seen["campaign"] == "cg-x"
    assert seen["seconds"] == 0.5

    # 映射状态决定退出码：TERMINATED=3、BLOCKED/FAILED/NEEDS_EVIDENCE=1
    for state, expected in (("TERMINATED", 3), ("BLOCKED", 1),
                            ("FAILED", 1), ("NEEDS_EVIDENCE", 1),
                            ("CANDIDATE", 0), ("NO_REPRO", 0)):
        monkeypatch.setattr(
            cli_mod, "run_research",
            lambda task_id, store, bus, _s=state, **kw: {"state": _s})
        assert platform_cli.main([
            "--db", str(base / "platform.db"), "run", TASK,
            "--research"]) == expected, state

    # 前置条件不成立（状态不是 PLANNED）→ 退出码 2、状态不动
    monkeypatch.undo()
    store = PlatformStore(base / "platform.db")
    store.transition(TASK, "FAILED", reason="fixture")
    assert platform_cli.main([
        "--db", str(base / "platform.db"), "run", TASK,
        "--research"]) == 2
    assert store.get_task(TASK)["state"] == "FAILED"


# ====================================================================== 9
def test_cli_research_end_to_end_writes_report(tmp_path, monkeypatch):
    """真走 CLI：替身只换 fuzz 执行器，overlay/构建/冒烟/报告全是真的。"""
    base = tmp_path
    store, _task = _planned_task(base)

    def factory(**kwargs):
        return FakeRunner(kwargs["store"], task_id=kwargs["task_id"],
                          hit_from=2)

    monkeypatch.setattr(cli_mod, "FuzzEpochRunner", factory)
    code = platform_cli.main([
        "--db", str(base / "platform.db"), "run", TASK, "--research",
        "--max-rounds", "4", "--campaign", "vulngym", "--seconds", "0.2"])
    assert code == 0
    report = base / "research" / TASK / "research.json"
    assert report.is_file()
    doc = json.loads(report.read_text(encoding="utf-8"))
    assert doc["state"] == "CANDIDATE"
    assert doc["campaign"] == "vulngym"
    assert doc["executions"] == 2
    assert doc["deps"]["workspace"]["mode"] == "created"
    # 报告如实记“用的是 fuzz 执行器”这条路径（本用例替身了 worker 类本身）
    assert doc["deps"]["executor"]["source"] == "executors.fuzz.execute"
    assert store.get_task(TASK)["state"] == "CANDIDATE"
    assert store.list_verifications(TASK) == []
    assert store.list_candidates(TASK) == []


# ====================================================================== 10
def test_without_build_commands_overlay_is_skipped_and_reported(tmp_path):
    """没有构建/冒烟命令 → 不建 overlay（报告写明原因），循环仍有限停止。"""
    store, _task = _planned_task(tmp_path, commands=False)
    runner = FakeRunner(store)
    out = run_research(
        TASK, store, EventBus(store), workdir=tmp_path / "work",
        evidence_root=tmp_path / "evidence",
        research_root=tmp_path / "research", campaign="vulngym",
        max_rounds=4, exec_runner=runner)

    assert out["deps"]["workspace"]["mode"] == "none"
    assert out["deps"]["workspace"]["reason"] == "no_build_or_smoke_command"
    assert not (tmp_path / "research" / "ws" / "workspace.json").exists()
    # 没有副本 → 不产生 STAGE/BUILD/SMOKE 阶段（不假装改过 harness）
    phases = {item["phase"] for item in out["controller"]["timeline"]}
    assert not phases & {"STAGE", "BUILD", "SMOKE", "ADOPT", "REVERT"}
    assert out["executions"] >= 1
    assert out["rounds"] >= 2
    assert [action for action in out["controller"]["rounds"][0]["actions"]
            if action["tool"] == "run_epoch"]
    assert store.get_task(TASK)["state"] == out["state"]
    assert store.list_verifications(TASK) == []
