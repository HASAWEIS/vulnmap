"""验收闭环：严重性逐例论证、复核、回执缺一不可。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.contracts import Budget
from agent.runtime.orchestrator import Orchestrator
from agent.stages.report import ReportStage

WS = Path(__file__).resolve().parent.parent / "workspace" / "CG-04-arvo-10400"


def _stage(tmp_path=None):
    ws = tmp_path or WS
    orch = Orchestrator(ws, budget=Budget(max_turns=40, timeout_seconds=900))
    return ReportStage(orch.store, orch.task["run_id"], ws, orch._request("report"))


DIMS = {d: {"value": "v", "evidence": "e"} for d in
        ("attack_vector", "privileges_required", "user_interaction",
         "observed_impact", "reachability_evidence", "deployment_conditions")}


def test_no_cwe_to_cvss_autofill():
    """同一 CWE 不能自动推出 CVSS 等级。"""
    from agent.stages import report as rpt
    assert not hasattr(rpt, "CWE_CVSS"), "CWE→CVSS 自动映射必须移除"


def test_severity_unassessed_without_record(tmp_path):
    st = _stage(tmp_path)
    sev = st._severity("CWE-121", {}, {}, {})
    assert sev["state"] == "unassessed"
    assert "不按 CWE 自动推导" in sev["reason"]
    assert sev["required_dimensions"]


def test_severity_requires_every_dimension(tmp_path):
    st = _stage(tmp_path)
    partial = {"severity": "high", "dimensions": {"attack_vector": {"value": "network",
                                                                    "evidence": "x"}}}
    out = st._validate_severity(partial, "CWE-121")
    assert out["state"] == "unassessed"
    dims_missing = [d for d in out["missing_dimensions"] if ":" not in d]
    assert len(dims_missing) == 5          # 5 个维度缺依据
    assert out["is_high_severity"] is False


def test_severity_complete_is_assessed(tmp_path):
    st = _stage(tmp_path)
    rec = {"severity": "high", "reviewed_by": "r", "reviewed_at": "d",
           "rationale": "x", "dimensions": dict(DIMS,
              observed_impact={"value": "memory_corruption_confirmed", "evidence": "asan"})}
    out = st._validate_severity(rec, "CWE-121")
    assert out["state"] == "assessed"
    assert out["is_high_severity"] is True


def test_high_requires_impact_evidence_not_just_label(tmp_path):
    """只写 severity=high 但影响未证实 → 不算高危。"""
    st = _stage(tmp_path)
    rec = {"severity": "high", "dimensions": dict(DIMS,
              observed_impact={"value": "unclear", "evidence": "e"})}
    out = st._validate_severity(rec, "CWE-121")
    assert out["is_high_severity"] is False


def test_review_record_requires_fields(tmp_path):
    st = _stage(tmp_path)
    assert st._review_record()["valid"] is False
    (tmp_path / "review.json").write_text('{"reviewer":"r"}')
    r = st._review_record()
    assert r["valid"] is False and set(r["missing"]) == {"reviewed_at", "scope"}
    (tmp_path / "review.json").write_text(
        '{"reviewer":"r","reviewed_at":"d","scope":"s"}')
    assert st._review_record()["valid"] is True


def test_receipt_requires_task_and_exit(tmp_path):
    st = _stage(tmp_path)
    assert st._receipt_record()["valid"] is False
    (tmp_path / "receipt.json").write_text('{"task_id":"t"}')
    assert st._receipt_record()["valid"] is False
    # 新规则：仅 task_id+exit_code 不再算有效回执（需绑定 PoC 哈希与官方接受）
    (tmp_path / "receipt.json").write_text('{"task_id":"t","exit_code":1}')
    assert st._receipt_record()["valid"] is False


def test_material_check_excludes_self_written_files(tmp_path):
    """不得把本阶段正在写的 case.json 计入缺失（时序 bug）。"""
    st = _stage(tmp_path)
    st.ws = tmp_path
    res = st._material_check()
    assert "report" not in res["missing"]
    assert "report_md" not in res["missing"]



def test_exploitgym_flag_overrides_dual_run(tmp_path):
    st = _stage(tmp_path)
    stages = {"local_dual_run": {"ok": False},
              "root_cause": {"confidence": "none", "matched": False},
              "propagation": {"complete": False}}
    checks = {"vul_crashed": False, "fix_clean": False, "poc_hash_match": False,
              "budget_settled": True, "image_recorded": True,
              "no_network_lookup": True, "no_infra_error": True,
              "model_recorded": True}
    acc = st._acceptance(stages, checks, {"state": "unassessed"},
                         exploit={"issued": True}, benchmark="exploitgym")
    assert acc["benchmark_verified"] is True
    assert acc["benchmark_kind"] == "exploit_flag"
    assert "local_dual_run_failed" not in acc["blockers"]
    assert acc["stage"] == "benchmark_verified_pending_evidence"
    # flag 通过不等于课程 ready，也不等于高危
    assert acc["course_ready"] is False
    assert acc["high_severity_confirmed"] is False


def test_cybergym_flag_does_not_override_dual_run(tmp_path):
    st = _stage(tmp_path)
    stages = {"local_dual_run": {"ok": False},
              "root_cause": {"confidence": "none"},
              "propagation": {"complete": False}}
    acc = st._acceptance(stages, {}, {"state": "unassessed"},
                         exploit={"issued": True}, benchmark="cybergym")
    assert acc["benchmark_verified"] is False
    assert "local_dual_run_failed" in acc["blockers"]


def test_course_ready_needs_all_blocks(tmp_path):
    st = _stage(tmp_path)
    stages = {"local_dual_run": {"ok": True},
              "root_cause": {"confidence": "strong", "matched": True},
              "propagation": {"complete": True}}
    checks = {"vul_crashed": True, "fix_clean": True, "poc_hash_match": True,
              "budget_settled": True, "image_recorded": True,
              "no_network_lookup": True, "no_infra_error": True,
              "model_recorded": True}
    # 什么都没补 → 不得 ready
    a1 = st._acceptance(stages, checks, {"state": "unassessed"})
    assert a1["course_ready"] is False
    assert "severity_justification_not_reviewed" in a1["course_ready_blocked_by"]
    assert "official_receipt_not_attached" in a1["course_ready_blocked_by"]
