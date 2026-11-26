"""harness UB 必须与目标缺陷分开计数；因果链只认 strong。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage

PASS_STRONG = {"local_dual_run": {"ok": True}, "root_cause": {"confidence": "strong"},
               "propagation": {"complete": True}}
PASS_WEAK = {"local_dual_run": {"ok": True}, "root_cause": {"confidence": "weak"},
             "propagation": {"complete": True}}
HIGH = {"state": "assessed", "missing_dimensions": [], "is_high_severity": True}


def _st(tmp_path):
    st = ReportStage.__new__(ReportStage)
    st.ws = tmp_path
    st.layout = {"artifacts": tmp_path / "artifacts"}
    (tmp_path / "artifacts" / "verify").mkdir(parents=True, exist_ok=True)
    st._review_record = lambda: {"valid": True}
    st._receipt_record = lambda: {"valid": True}
    st._material_check = lambda: {"complete": True}
    return st


def test_harness_entry_classified_as_harness_ub(tmp_path):
    st = _st(tmp_path)
    dc = st._defect_class({"subject": "LLVMFuzzerTestOneInput"})
    assert dc["value"] == "harness_ub" and dc["counts_as_target_defect"] is False


def test_normal_function_is_target_defect(tmp_path):
    st = _st(tmp_path)
    assert st._defect_class({"subject": "ReadMNGImage"})["value"] == "target_defect"


def test_harness_ub_cannot_be_course_ready(tmp_path):
    st = _st(tmp_path)
    acc = st._acceptance(PASS_STRONG, {}, HIGH,
                         st._defect_class({"subject": "LLVMFuzzerTestOneInput"}))
    assert acc["course_ready"] is False
    assert acc["high_severity_confirmed"] is False
    assert any("harness" in b for b in acc["course_ready_blocked_by"])


def test_weak_root_cause_does_not_close_chain(tmp_path):
    """10400 的 root=weak 不再记为因果链闭合。"""
    st = _st(tmp_path)
    acc = st._acceptance(PASS_WEAK, {}, HIGH)
    assert acc["causal_chain_verified"] is False
    assert acc["local_verified"] is True


def test_strong_root_cause_closes_chain(tmp_path):
    st = _st(tmp_path)
    acc = st._acceptance(PASS_STRONG, {}, HIGH)
    assert acc["causal_chain_verified"] is True
    assert acc["high_severity_confirmed"] is True
