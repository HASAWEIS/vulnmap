r"""V3 P1「目标语义拆分」回归：`program_started / input_processed / checkpoint_reached`。

口径（`docs/V3-TARGET-SEMANTICS.md`）：

- 三段事实**各自独立**：`program_started`（进程真的起来）/ `input_processed`
  （输入真的被处理，需探针）/ `checkpoint_reached`（目标分支或检查点命中，
  需显式探针或显式字段）；
- `target_reached` 只是 `checkpoint_reached` 的兼容别名，**不能**由
  `coverage_bits` / `execs` / `new_coverage_bits` / 崩溃数推出；
- 没有字段一律 `unknown`（`None`），**不填 False**；Fuzz 执行器没有输入/检查点
  探针时 `input_processed` / `checkpoint_reached` 恒为 unknown；
- 诊断侧：`program_started=false` → `program_not_started`；
  `input_processed=false` → `input_not_processed`；`checkpoint_reached=false` →
  `target_unreached`；`checkpoint_reached=unknown` → `coverage_unknown`
  （理由 `target_reached_unknown`）；`checkpoint_reached=true` 才是命中。

三组回归（夹具 `fixtures/target_semantics/` 是真跑的无害解析器 + 真探针）：

| 组 | 三元组 | 期望 |
|---|---|---|
| 启动但未命中 | `true / true / false` | `target_unreached`，`target_reached=false` |
| 确认命中 | `true / true / true` | `low_coverage`/`progress`，`target_reached=true` |
| 无观测手段 | `true / unknown / unknown` | `coverage_unknown`，**报告里是 unknown 不是 false** |

三组的快照 / 观测 / 诊断必须互不相同（同一份事实不许被压成同一个结论）。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures" / "target_semantics"))

import probe as target_probe                                    # noqa: E402

from agent.platform.adaptive.contracts import UNKNOWN           # noqa: E402
from agent.platform.adaptive.session import (ContextRole,      # noqa: E402
                                             DiagnoseRole, Diagnosis)
from agent.platform.adaptive.snapshot import (                  # noqa: E402
    OBSERVED_FIELDS, TrustedExecutionSnapshot)
from agent.platform.executors import (EXEC_FACT_FIELDS,         # noqa: E402
                                      EXEC_PROBE_FIELDS,
                                      exec_probe_facts,
                                      execution_fact_view)
from agent.platform.store import PlatformStore                  # noqa: E402
from agent.platform.task import Budget, TaskSpec                # noqa: E402

TASK = "task-v3-target-semantics"
EXEC = "exec-sem-0001"
SEM_FIELDS = ("program_started", "input_processed", "checkpoint_reached")


# ------------------------------------------------------------------ fixtures
def _store(tmp_path):
    store = PlatformStore(tmp_path / "platform.db")
    store.create_task(TaskSpec(
        task_id=TASK, benchmark="vulngym", target="fixtures/target_semantics",
        mode="fuzz",
        budget=Budget(max_seconds=60, max_execs=1000, max_tokens=1000,
                      max_turns=4),
        metadata={"authorized": True}))
    return store, store.get_task(TASK)


def _snapshot(tmp_path, facts, *, exec_id=EXEC, stats=None,
              coverage=None, outcome="no_repro", extra=None):
    """把一次执行写成事件流，再由快照层读回来（不直接构造快照对象）。"""
    store, _ = _store(tmp_path)
    store.append_event(TASK, "exec.started", stage="RUNNING", payload={
        "exec_id": exec_id, "kind": "fuzz", "plan_sha256": "p" * 40,
        "benchmark": "vulngym", "target": "fixtures/target_semantics",
        "budget": {"seconds": 5.0, "workers": 1, "timeout": 2.0},
        "workdir": "/tmp/sem-work"})
    finish = {
        "exec_id": exec_id, "kind": "fuzz", "outcome": outcome,
        "plan_sha256": "p" * 40, "candidates": 0, "seconds": 0.2,
        "build": {"sha256": "b" * 64, "build_id": "b" * 64,
                  "harness": "covfuzz"},
        "fuzz": dict(stats if stats is not None else {
            "execs": 40, "crashes": 0, "timeouts": 0, "new_coverage_bits": 3,
            "setup_error": "", "stopped": "completed"}),
        "coverage": dict(coverage or {"status": "unavailable"}),
        "seeds": 3, "dictionary_tokens": 2, "format": "raw",
        "evidence_sha256": "e" * 64, "error": None,
        "budget_usage": {"seconds": 0.2, "execs": 40, "tokens": 0, "turns": 1},
    }
    finish.update({name: facts.get(name) for name in EXEC_PROBE_FIELDS})
    finish.update(dict(extra or {}))
    store.append_event(TASK, "exec.finished", stage="RUNNING", payload=finish)
    return TrustedExecutionSnapshot.collect(store, TASK, execution_id=exec_id)


def _triple(snapshot) -> tuple:
    return tuple(snapshot.get(f"input.{name}") for name in SEM_FIELDS)


def _report(snapshot) -> dict:
    """报告口径：快照输入组 + 观测 + 诊断（三组必须在这里也能看出差别）。"""
    observation = ContextRole().observe(snapshot)
    diagnosis = DiagnoseRole().diagnose(observation)
    return {
        "snapshot": {name: snapshot.get(f"input.{name}") for name in SEM_FIELDS},
        "target_reached": snapshot.get("input.target_reached"),
        "observation_source": snapshot.get("input.observation_source"),
        "unknown_inputs": [path for path in snapshot.unknown_paths()
                           if path.startswith("input.")],
        "observation": {name: getattr(observation, name) for name in SEM_FIELDS}
        | {"target_reached": observation.target_reached},
        "diagnosis": diagnosis.to_dict(),
    }


# ============================================================ 1. 夹具三段事实
def test_fixture_probe_emits_three_distinct_triples(tmp_path):
    """真跑无害解析器：三组用例的三段事实互不相同，且只在有探针时给 bool。"""
    triples = {name: tuple(target_probe.case_facts(
        name, probe_dir=tmp_path)[field] for field in SEM_FIELDS)
        for name in target_probe.CASES}
    assert triples["started_no_checkpoint"] == (True, True, False)
    assert triples["checkpoint_hit"] == (True, True, True)
    # 无观测手段：输入/检查点只能是 None（unknown），不是 False
    assert triples["no_probe"] == (True, None, None)
    assert len(set(triples.values())) == 3


def test_probe_reports_program_started_false_when_target_missing(tmp_path):
    """进程根本没起来 → program_started=False（这是观测，不是猜测）。"""
    result = target_probe.run_target(
        "MAGIC VMAP1\nEND\n", probe_path=tmp_path / "p.jsonl",
        interpreter=str(tmp_path / "no-such-interpreter"))
    assert result["facts"] == {"program_started": False,
                               "input_processed": None,
                               "checkpoint_reached": None}


# ============================================================ 2. 三段写进事件
def test_exec_probe_facts_never_infers_input_or_checkpoint(tmp_path):
    """fuzz 只补 program_started：execs>0 不推 input_processed / checkpoint_reached。"""
    facts = exec_probe_facts({"execs": 90, "new_coverage_bits": 12,
                              "crashes": 3, "setup_error": ""})
    assert facts["program_started"] is True
    assert facts["input_processed"] is None
    assert facts["checkpoint_reached"] is None
    assert facts["target_reached"] is None       # 兼容别名也只能来自 checkpoint

    # 启动失败：execs=0 且带 setup_error 才是 False（显式证据）
    failed = exec_probe_facts({"execs": 0, "setup_error": "isolation: segv"})
    assert failed["program_started"] is False
    assert failed["input_processed"] is None
    assert failed["checkpoint_reached"] is None

    # 连 execs 都没有：三段全 unknown
    assert exec_probe_facts({}) == {"program_started": None,
                                    "input_processed": None,
                                    "checkpoint_reached": None,
                                    "target_reached": None}


def test_exec_probe_facts_prefers_explicit_executor_fields(tmp_path):
    """执行器显式给探针 → 原样采用（不因为 execs=0 就把 checkpoint 改掉）。"""
    facts = exec_probe_facts({"execs": 0, "program_started": True,
                              "input_processed": True,
                              "checkpoint_reached": False})
    assert facts == {"program_started": True, "input_processed": True,
                     "checkpoint_reached": False, "target_reached": False}


def test_exec_fact_fields_and_view_carry_semantics():
    """`exec.finished` 的字段表与只读视图都带三段事实（同源声明）。"""
    assert set(EXEC_PROBE_FIELDS) <= set(EXEC_FACT_FIELDS["finish"])
    assert set(EXEC_PROBE_FIELDS) <= set(EXEC_FACT_FIELDS["fuzz"])
    view = execution_fact_view(
        {"exec_id": EXEC, "kind": "fuzz"},
        {"exec_id": EXEC, "kind": "fuzz", "program_started": True,
         "input_processed": True, "checkpoint_reached": False,
         "fuzz": {"execs": 4}})
    assert view["program_started"] is True
    assert view["input_processed"] is True
    assert view["checkpoint_reached"] is False
    assert view["target_reached"] is False
    assert view["target_reached_source"] == "checkpoint_reached"
    assert view["flags"]["checkpoint_reached_observed"] is True


def test_legacy_target_reached_maps_to_checkpoint_only():
    """旧字段 `target_reached` 只当 `checkpoint_reached` 的旧拼写，不另立语义。"""
    view = execution_fact_view(
        {"exec_id": EXEC, "kind": "fuzz"},
        {"exec_id": EXEC, "kind": "fuzz", "target_reached": True,
         "fuzz": {"execs": 4}})
    assert view["checkpoint_reached"] is True
    assert view["target_reached"] is True
    assert view["target_reached_source"] == "legacy_target_reached"


# ============================================================ 3. 快照口径
def test_snapshot_three_groups_differ(tmp_path):
    """同一套快照管线读出三种不同结论（不是三种说法，是三种事实）。"""
    groups = {}
    for name in target_probe.CASES:
        base = tmp_path / name
        base.mkdir()
        facts = target_probe.case_facts(name, probe_dir=base)
        groups[name] = _snapshot(base, facts)

    started_only = groups["started_no_checkpoint"]
    assert _triple(started_only) == ("true", "true", "false")
    assert started_only.get("input.target_reached") == "false"
    assert started_only.get("input.observation_source") == "checkpoint_probe"

    hit = groups["checkpoint_hit"]
    assert _triple(hit) == ("true", "true", "true")
    assert hit.get("input.target_reached") == "true"

    blind = groups["no_probe"]
    assert _triple(blind) == ("true", "unknown", "unknown")
    assert blind.get("input.target_reached") == "unknown"
    assert blind.get("input.observation_source") == "no_checkpoint_probe"
    # 无观测手段 → 明确登记为 unknown 路径（不是被悄悄填成 false）
    assert "input.input_processed" in blind.unknown_paths()
    assert "input.checkpoint_reached" in blind.unknown_paths()
    assert "input.target_reached" in blind.unknown_paths()
    assert "input.checkpoint_reached" not in started_only.unknown_paths()

    assert len({_triple(s) for s in groups.values()}) == 3


def test_snapshot_reports_new_fields_in_schema_and_observed(tmp_path):
    """三字段进 `_GROUP_PATHS` / `OBSERVED_FIELDS`：快照与 unknown 清单都能看到。"""
    assert set(EXEC_PROBE_FIELDS) <= set(OBSERVED_FIELDS["input"])
    snap = _snapshot(tmp_path, {"program_started": True,
                                "input_processed": None,
                                "checkpoint_reached": None})
    doc = snap.to_dict()
    assert doc["schema"].endswith("execution_snapshot.v1")
    for name in SEM_FIELDS:
        assert name in doc["groups"]["input"], name
    assert doc["groups"]["input"]["program_started"] == "true"
    assert doc["groups"]["input"]["input_processed"] == UNKNOWN
    # 程序起来了就是实质观测（不再需要覆盖读数来“证明跑过”）
    assert snap.observed() is True
    assert "input.input_processed" in doc["unknowns"]

    # 空的诚实快照里，三字段同样是 unknown 而不是 false
    empty = TrustedExecutionSnapshot.empty(TASK)
    for name in SEM_FIELDS:
        assert empty.get(f"input.{name}") == UNKNOWN
        assert f"input.{name}" in empty.unknown_paths()


def test_coverage_bits_and_execs_never_imply_checkpoint(tmp_path):
    """覆盖涨了、执行很多次、还崩了：都不许把 `checkpoint_reached` 变成 true/false。"""
    snap = _snapshot(tmp_path, {"program_started": None,
                                "input_processed": None,
                                "checkpoint_reached": None},
                     stats={"execs": 999, "crashes": 4, "timeouts": 1,
                            "new_coverage_bits": 512, "setup_error": "",
                            "stopped": "completed"},
                     coverage={"status": "complete", "planned": 9,
                               "covered": 9, "uncovered": 0})
    assert snap.get("input.program_started") == "true"     # execs>0 只能证这个
    assert snap.get("input.input_processed") == UNKNOWN
    assert snap.get("input.checkpoint_reached") == UNKNOWN
    assert snap.get("input.target_reached") == UNKNOWN
    assert snap.get("coverage.covered") == 9               # 覆盖读数照给
    assert "input.checkpoint_reached" in snap.unknown_paths()


def test_setup_error_alone_does_not_claim_checkpoint_unreached(tmp_path):
    """setup_error 只能证明“进程没起来”，不能顺手把检查点写成 false。"""
    snap = _snapshot(tmp_path, {"program_started": None,
                                "input_processed": None,
                                "checkpoint_reached": None},
                     stats={"execs": 0, "setup_error": "isolation: exec failed",
                            "stopped": ""},
                     outcome="failed")
    assert snap.get("input.program_started") == "false"
    assert snap.get("input.input_processed") == UNKNOWN
    assert snap.get("input.checkpoint_reached") == UNKNOWN
    assert snap.get("input.target_reached") == UNKNOWN


# ============================================================ 4. 诊断口径
def test_three_reports_are_distinct(tmp_path):
    """报告（快照 + 观测 + 诊断）三组显示不同：命中/未命中/不知道。"""
    reports = {}
    for name in target_probe.CASES:
        base = tmp_path / f"report-{name}"
        base.mkdir()
        facts = target_probe.case_facts(name, probe_dir=base)
        reports[name] = _report(_snapshot(base, facts, exec_id=f"exec-{name}"))

    assert reports["started_no_checkpoint"]["diagnosis"]["code"] == \
        "target_unreached"
    assert reports["checkpoint_hit"]["diagnosis"]["code"] in (
        "low_coverage", "progress")
    assert reports["no_probe"]["diagnosis"]["code"] == "coverage_unknown"
    assert reports["no_probe"]["diagnosis"]["reasons"] == \
        ["target_reached_unknown"]

    # 报告里的三段事实与快照一致，且三组互不相同
    for name, report in reports.items():
        assert report["observation"] == report["snapshot"] | {
            "target_reached": report["target_reached"]}, name
    assert len({tuple(sorted(report["snapshot"].items()))
                for report in reports.values()}) == 3
    assert len({report["diagnosis"]["code"] for report in reports.values()}) == 3
    # 来源标签只说明“怎么知道的”（探针在/不在），结论差异看三段事实与诊断
    assert {report["observation_source"] for report in reports.values()} == {
        "checkpoint_probe", "no_checkpoint_probe"}


def test_blind_report_says_unknown_not_false(tmp_path):
    """无观测手段：报告里必须是 unknown（字符串），不是 false/0。"""
    base = tmp_path / "blind"
    base.mkdir()
    report = _report(_snapshot(base, target_probe.case_facts(
        "no_probe", probe_dir=base)))
    assert report["snapshot"]["input_processed"] == "unknown"
    assert report["snapshot"]["checkpoint_reached"] == "unknown"
    assert report["target_reached"] == "unknown"
    assert False not in (report["snapshot"]["input_processed"],
                         report["snapshot"]["checkpoint_reached"])
    assert "unknown" in report["diagnosis"]["reasons"][0]
    assert report["diagnosis"]["severity"] == "warn"


def test_program_started_false_is_reported_as_not_started(tmp_path):
    """program_started=false → `program_not_started`（不是 target_unreached 的替身）。"""
    snap = _snapshot(tmp_path, {"program_started": False,
                                "input_processed": None,
                                "checkpoint_reached": None},
                     stats={"execs": 0, "setup_error": "isolation: exec failed"},
                     outcome="failed")
    report = _report(snap)
    assert report["observation"]["program_started"] == "false"
    assert report["diagnosis"]["code"] == "program_not_started"
    assert report["diagnosis"]["reasons"] == ["program_started=false"]


def test_input_processed_false_is_reported_as_not_processed(tmp_path):
    """input_processed=false → `input_not_processed`；此时不能说“目标没命中”。"""
    snap = _snapshot(tmp_path, {"program_started": True,
                                "input_processed": False,
                                "checkpoint_reached": None})
    report = _report(snap)
    assert report["diagnosis"]["code"] == "input_not_processed"
    assert report["diagnosis"]["reasons"] == ["input_processed=false"]
    assert report["target_reached"] == "unknown"


def test_checkpoint_hit_is_only_evidence_of_reaching(tmp_path):
    """只有 `checkpoint_reached=true` 才让 target_reached 变 true。"""
    base = tmp_path / "hit"
    base.mkdir()
    snap = _snapshot(base, target_probe.case_facts("checkpoint_hit",
                                                  probe_dir=base))
    report = _report(snap)
    assert report["snapshot"]["checkpoint_reached"] == "true"
    assert report["target_reached"] == "true"
    assert report["diagnosis"]["code"] != "target_unreached"


def test_diagnosis_code_vocabulary_contains_new_codes():
    """新增两条诊断码在固定词表里（不靠自由字符串）。"""
    for code in ("program_not_started", "input_not_processed"):
        Diagnosis(code=code)                      # 不在词表里会 ValueError
    with pytest.raises(ValueError):
        Diagnosis(code="target_maybe_reached")
