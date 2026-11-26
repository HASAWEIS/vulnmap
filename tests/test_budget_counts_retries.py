"""预算口径：必须按**真实传输请求数**计，不是按调用客户端的次数。

由审查方复现：max_requests=1 / max_retries=1 时，
transport_attempts=2 而 budget_count=1 —— 预算被少算一半。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent import llm
from agent.budget import GlobalModelBudget


def _patch_transport(monkeypatch, fail_times: int):
    """前 fail_times 次抛网络异常，之后返回正常响应。"""
    calls = {"n": 0}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            import json
            return json.dumps({
                "model": "m",
                "choices": [{"message": {"content": '{"ok":1}'},
                             "finish_reason": "stop"}],
                "usage": {"total_tokens": 7, "prompt_tokens": 5, "completion_tokens": 2},
            }).encode()

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] <= fail_times:
            raise TimeoutError("simulated timeout")
        return Resp()

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_budget_counts_every_transport_attempt(monkeypatch):
    calls = _patch_transport(monkeypatch, fail_times=1)
    g = GlobalModelBudget(max_requests=10)
    llm.set_global_budget(g)
    try:
        res = llm.call_json(llm.LlmConfig(api_key="k", max_retries=1),
                            system="s", user="u", prompt_version="p")
    finally:
        llm.set_global_budget(None)
    assert res.status == "ok"
    assert calls["n"] == 2, "确实发生了两次传输"
    assert g.usage()["requests"] == 2, f"预算只记了 {g.usage()['requests']} 次"


def test_budget_blocks_when_retry_exhausts_cap(monkeypatch):
    _patch_transport(monkeypatch, fail_times=1)
    g = GlobalModelBudget(max_requests=1)
    llm.set_global_budget(g)
    try:
        llm.call_json(llm.LlmConfig(api_key="k", max_retries=1),
                      system="s", user="u", prompt_version="p")
        # 第一次调用用掉 2 次传输，已超上限 -> 再调用必须被拦
        with pytest.raises(Exception):
            llm.call_json(llm.LlmConfig(api_key="k", max_retries=1),
                          system="s", user="u", prompt_version="p")
    finally:
        llm.set_global_budget(None)


def test_tokens_still_counted(monkeypatch):
    _patch_transport(monkeypatch, fail_times=0)
    g = GlobalModelBudget()
    llm.set_global_budget(g)
    try:
        llm.call_json(llm.LlmConfig(api_key="k"), system="s", user="u", prompt_version="p")
    finally:
        llm.set_global_budget(None)
    assert g.usage()["tokens"] == 7
