"""全局模型预算：跨阶段请求数/token/墙钟，超限即终止。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.budget import GlobalModelBudget
from agent.errors import BudgetExhausted


def test_counts_calls_and_tokens():
    g = GlobalModelBudget()
    g.note_call(100)
    g.note_call(50)
    assert g.usage() == {"requests": 2, "tokens": 150}


def test_request_cap_blocks_before_call():
    g = GlobalModelBudget(max_requests=2)
    g.note_call(1)
    g.note_call(1)
    with pytest.raises(BudgetExhausted) as exc:
        g.precheck()
    assert "requests" in str(exc.value)


def test_token_cap_blocks():
    g = GlobalModelBudget(max_tokens=100)
    g.note_call(150)
    with pytest.raises(BudgetExhausted) as exc:
        g.precheck()
    assert "tokens" in str(exc.value)


def test_wall_clock_blocks(monkeypatch):
    g = GlobalModelBudget(max_seconds=10)
    g._started -= 20          # 模拟已运行 20 秒
    with pytest.raises(BudgetExhausted) as exc:
        g.precheck()
    assert "wall-clock" in str(exc.value)


def test_snapshot_reports_exhausted():
    g = GlobalModelBudget(max_requests=1)
    g.note_call(1)
    assert g.snapshot()["exhausted"] is True


def test_guard_installed_around_call_json(monkeypatch):
    """call_json 必须在发请求前拦截，而不是发完再记账。"""
    from agent import llm
    sent = []
    g = GlobalModelBudget(max_requests=0)
    llm.set_global_budget(g)
    try:
        with pytest.raises(BudgetExhausted):
            llm.call_json(llm.LlmConfig(api_key="k"), system="s", user="u",
                          prompt_version="p")
        assert sent == []
    finally:
        llm.set_global_budget(None)


def test_guard_none_means_unlimited(monkeypatch):
    from agent import llm
    llm.set_global_budget(None)
    r = llm.call_json(llm.LlmConfig(api_key=""), system="s", user="u",
                      prompt_version="p")
    assert r.status == "failed" and r.error == "no_api_key"


def test_history_usage_reads_real_llm_attempts(tmp_path):
    """预算要从 attempts 继承历史用量；标记在 outcome，不在 action_key。"""
    import json as _json
    from agent.store import Store
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "t", "cybergym", str(tmp_path))
    st.record_attempt("r1", "locate", 2, "deadbeef", "llm_ok", 1.0,
                      detail=_json.dumps({"llm": {"tokens": 500}}))
    st.record_attempt("r1", "recon", 1, "cafe", "completed", 0.5)
    g = GlobalModelBudget().bind(st, "r1")
    assert g.usage() == {"requests": 1, "tokens": 500}
