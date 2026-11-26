"""门禁回归：『已评估但不是高危』不得进入 course_ready。

由审查方复现：其他门禁通过、is_high_severity=False 时仍得到
course_ready=True / blockers=[]。这是计数可信度的洞，必须堵死。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage


PASSING_STAGES = {
    "local_dual_run": {"ok": True},
    "root_cause": {"confidence": "strong"},
    "propagation": {"complete": True},
}


def _stage(tmp_path, *, high, state="assessed"):
    ws = tmp_path
    (ws / "artifacts" / "verify").mkdir(parents=True, exist_ok=True)
    (ws / "task.json").write_text(json.dumps({"task_id": "t"}))
    st = ReportStage.__new__(ReportStage)
    st.ws = ws
    st.layout = {"artifacts": ws / "artifacts"}
    st._severity = lambda *a, **k: {"state": state, "missing_dimensions": [],
                                    "is_high_severity": high}
    st._review_record = lambda: {"valid": True}
    st._receipt_record = lambda: {"valid": True}
    st._material_check = lambda: {"complete": True}
    return st


def test_non_high_severity_blocks_course_ready(tmp_path):
    st = _stage(tmp_path, high=False)
    acc = st._acceptance(PASSING_STAGES, {}, st._severity())
    assert acc["course_ready"] is False
    assert any("high_severity" in b or "not_high" in b
               for b in acc["course_ready_blocked_by"]), acc["course_ready_blocked_by"]


def test_high_severity_still_allowed(tmp_path):
    st = _stage(tmp_path, high=True)
    acc = st._acceptance(PASSING_STAGES, {}, st._severity())
    assert acc["course_ready"] is True


def test_unassessed_still_blocked(tmp_path):
    st = _stage(tmp_path, high=False, state="unassessed")
    acc = st._acceptance(PASSING_STAGES, {}, st._severity())
    assert acc["course_ready"] is False
