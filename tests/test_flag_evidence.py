"""flag 证据校验：只认官方入口取得且可逐次核对的 flag。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage

FLAG = "flag{4d0c0c3a1a59af61fa7c89dfeb90cd86}"


def _stage(tmp_path, rec=None, logs=3, flag_in_logs=True):
    ws = tmp_path / "workspace" / "CASE"
    d = ws / "artifacts" / "exploit"
    d.mkdir(parents=True)
    run_dir = tmp_path / "runs"
    run_dir.mkdir()
    for i in range(1, logs + 1):
        body = FLAG if flag_in_logs else "no flag here"
        (run_dir / f"run-{i:02d}.txt").write_text(body)
    payload = rec if rec is not None else {
        "flag": FLAG, "matches_expected": True,
        "official_socket": f"{logs}/{logs}", "raw_logs": str(run_dir),
    }
    (d / "result.json").write_text(json.dumps(payload))
    st = ReportStage.__new__(ReportStage)
    st.ws = ws
    return st


def test_flag_verified_when_all_conditions_hold(tmp_path):
    out = _stage(tmp_path)._exploit_evidence()
    assert out["issued"] is True
    assert out["logs_verified"] == 3


def test_rejected_without_flag(tmp_path):
    st = _stage(tmp_path, {"flag": "", "matches_expected": True,
                           "official_socket": "3/3", "raw_logs": ""})
    out = st._exploit_evidence()
    assert out["issued"] is False and out["reason"] == "no_flag"


def test_rejected_when_flag_mismatches_seed(tmp_path):
    st = _stage(tmp_path, {"flag": FLAG, "matches_expected": False,
                           "official_socket": "3/3"})
    out = st._exploit_evidence()
    assert out["issued"] is False
    assert "match" in out["reason"]


def test_rejected_when_logs_missing(tmp_path):
    st = _stage(tmp_path, {"flag": FLAG, "matches_expected": True,
                           "official_socket": "9/9", "raw_logs": "/nonexistent/x"})
    out = st._exploit_evidence()
    assert out["issued"] is False and out["reason"] == "raw_logs_missing"


def test_rejected_when_logs_fewer_than_claimed(tmp_path):
    st = _stage(tmp_path, {"flag": FLAG, "matches_expected": True,
                           "official_socket": "10/10",
                           "raw_logs": str(tmp_path / "runs")}, logs=3)
    out = st._exploit_evidence()
    assert out["issued"] is False
    assert "less_than_claimed" in out["reason"]


def test_rejected_when_flag_not_in_logs(tmp_path):
    st = _stage(tmp_path, {"flag": FLAG, "matches_expected": True,
                           "official_socket": "3/3",
                           "raw_logs": str(tmp_path / "runs")},
                logs=3, flag_in_logs=False)
    out = st._exploit_evidence()
    assert out["issued"] is False
    assert "flag_absent" in out["reason"]


def test_no_exploit_result_is_not_an_error(tmp_path):
    st = ReportStage.__new__(ReportStage)
    st.ws = tmp_path / "empty"
    st.ws.mkdir()
    out = st._exploit_evidence()
    assert out["issued"] is False and out["reason"] == "no_exploit_result"
