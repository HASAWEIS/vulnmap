"""报告必须与日志一致：不得写"未使用 LLM"而日志里有调用。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage
from agent.store import Store


def _stage(tmp_path):
    st = ReportStage.__new__(ReportStage)
    st.ws = tmp_path
    st.layout = {"artifacts": tmp_path / "artifacts"}
    st.store = Store(tmp_path / "db.sqlite")
    st.run_id = "r1"
    st.store.create_run("r1", "t", "cybergym", str(tmp_path))
    return st


def test_llm_enabled_false_when_no_calls(tmp_path):
    st = _stage(tmp_path)
    assert st._llm_enabled({"llm": {"enabled": False}}) is False


def test_llm_enabled_true_from_logs_even_if_config_says_false(tmp_path):
    """核心回归：配置写 false，但日志里有 LLM 调用 -> 必须报 true。"""
    st = _stage(tmp_path)
    # action_key 是哈希、outcome 才是 'llm_ok'——按 action_key 前缀匹配会永远查不到
    st.store.record_attempt("r1", "locate", 2, "79158dc808517d07", "llm_ok", 1.0,
                            detail=json.dumps({"llm": {"model": "deepseek-flash",
                                                       "tokens": 1018}}))
    assert st._llm_enabled({"llm": {"enabled": False}}) is True
    assert st._llm_call_count() == 1


def test_llm_enabled_true_when_config_says_true(tmp_path):
    st = _stage(tmp_path)
    assert st._llm_enabled({"llm": {"enabled": True}}) is True


def test_llm_call_count_zero_without_logs(tmp_path):
    st = _stage(tmp_path)
    assert st._llm_call_count() == 0


# ---- 模型贡献字段语义 ----

def _contrib(st, locate, verify, added=None):
    st._pinpoint_verified = lambda a, b: {"verified": False}
    return st._model_contribution(locate, verify or {})


def test_rejected_proposal_same_as_final_is_explained_not_contradictory(tmp_path):
    st = _stage(tmp_path)
    locate = {"claims": [{"subject": "ReadMNGImage"}],
              "claims_llm": [],
              "agreement": {"added_by_llm": []},
              "llm": {"status": "ok", "rejected": [
                  {"identifier": "ReadMNGImage",
                   "reason": "conditional_active_definition_unconfirmed"}]}}
    rec = _contrib(st, locate, {}, [])
    assert rec["final_subject"] == "ReadMNGImage"
    assert rec["final_subject_from"] == "rule"
    assert rec["llm_rejected_coincides_with_final"] == ["ReadMNGImage"]
    assert "不计入模型贡献" in rec["coincidence_note"]
    assert rec["verified_new_contribution"] is False


def test_no_coincidence_note_when_names_differ(tmp_path):
    st = _stage(tmp_path)
    locate = {"claims": [{"subject": "ReadMNGImage"}], "claims_llm": [],
              "agreement": {"added_by_llm": []},
              "llm": {"status": "ok", "rejected": [
                  {"identifier": "OtherFunc", "reason": "x"}]}}
    rec = _contrib(st, locate, {}, [])
    assert rec["llm_rejected_coincides_with_final"] == []
    assert rec["coincidence_note"] == ""
