"""llm_enabled 必须与 attempts.detail 的实际调用记录一致。

背景（真实现场）：`report.py` 的 `_llm_enabled()` 曾用
`outcome LIKE 'llm%'` 过滤 attempts，但 llm 记录实际可能写在
`outcome='completed'` 的行里，真正的标记在 detail JSON 的 llm 键——
导致 workspace/CG-08-arvo-10147 的报告写 llm_enabled=false，而库里明明
有 llm.status=ok。这里把三种口径钉死：有 ok 记录 -> True；只有
prompt_version 之类元信息 -> False；无记录且配置 false -> False。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.stages.report import ReportStage, llm_record_is_ok  # noqa: E402
from agent.store import Store  # noqa: E402


def _stage(tmp_path):
    st = ReportStage.__new__(ReportStage)
    st.ws = tmp_path
    st.layout = {"artifacts": tmp_path / "artifacts"}
    st.store = Store(tmp_path / "db.sqlite")
    st.run_id = "r1"
    st.store.create_run("r1", "t", "cybergym", str(tmp_path))
    return st


def _llm_ok_detail(**extra):
    detail = {"llm": {"role": "locate", "status": "ok", "model": "deepseek-flash",
                      "prompt_version": "locate-llm-p1", "tokens": 666,
                      "prompt_tokens": 590, "completion_tokens": 76}}
    detail["llm"].update(extra)
    return json.dumps(detail)


def test_llm_enabled_true_when_detail_has_status_ok(tmp_path):
    """核心回归：detail 里有 llm.status=ok -> True（即使 task.json 写 false）。"""
    st = _stage(tmp_path)
    st.store.record_attempt("r1", "locate", 2, "k1", "llm_ok", 1.0, _llm_ok_detail())
    assert st._llm_enabled({"llm": {"enabled": False}}) is True
    assert st._llm_call_count() == 1


def test_llm_enabled_true_when_outcome_is_completed(tmp_path):
    """现场 bug：llm 记录挂在 outcome='completed' 的行上，只按 outcome 前缀查会漏。"""
    st = _stage(tmp_path)
    st.store.record_attempt("r1", "locate", 2, "k2", "completed", 1.0, _llm_ok_detail())
    assert st._llm_enabled({}) is True
    assert st._llm_call_count() == 1


def test_llm_enabled_false_when_detail_only_mentions_prompt_version(tmp_path):
    """只改 prompt_version、没真调模型 -> 必须 False（不许被字符串包含骗过去）。"""
    st = _stage(tmp_path)
    st.store.record_attempt("r1", "locate", 1, "k3", "completed", 1.0,
                            json.dumps({"llm": {"role": "locate",
                                                "prompt_version": "locate-llm-p1"}}))
    assert st._llm_enabled({"llm": {"enabled": False}}) is False
    assert st._llm_call_count() == 0


def test_llm_enabled_false_without_records_and_config_false(tmp_path):
    """没有任何 llm 记录，配置也写 false -> False。"""
    st = _stage(tmp_path)
    st.store.record_attempt("r1", "recon", 1, "k4", "completed", 0.5,
                            json.dumps({"checkpoint": {}, "seconds": 0.5}))
    assert st._llm_enabled({"llm": {"enabled": False}}) is False
    assert st._llm_enabled({}) is False
    assert st._llm_call_count() == 0


def test_llm_enabled_false_when_status_is_error(tmp_path):
    """调用失败（status=error）不能算"用过 LLM 决策"。"""
    st = _stage(tmp_path)
    st.store.record_attempt("r1", "locate", 2, "k5", "llm_error", 1.0,
                            json.dumps({"llm": {"status": "error", "model": "deepseek-flash"}}))
    assert st._llm_enabled({}) is False
    assert st._llm_call_count() == 0


def test_llm_enabled_config_true_still_supplements(tmp_path):
    """日志缺失时，task.json 的显式 true 仍作补充依据。"""
    st = _stage(tmp_path)
    assert st._llm_enabled({"llm": {"enabled": True}}) is True
    assert st.llm_enabled_default is False


def test_llm_record_is_ok_tolerates_garbage():
    """脏数据不得抛异常：非 dict / 空 status / 缺 trace 字段都判 False。"""
    assert llm_record_is_ok(None) is False
    assert llm_record_is_ok("ok") is False
    assert llm_record_is_ok({"status": "  "}) is False
    assert llm_record_is_ok({"status": "OK"}) is True
    assert llm_record_is_ok({"model": "deepseek-flash"}) is True
    assert llm_record_is_ok({"role": "locate"}) is False
