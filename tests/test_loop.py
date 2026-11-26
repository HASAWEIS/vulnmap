"""模型闭环：去重、有效轮次统计、失败后换策略提示。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent import llm, loop


def _fake_llm(responses):
    it = iter(responses)

    def call(cfg, *, system, user, prompt_version):
        return llm.LlmResult(status="ok", content=next(it), model="m",
                             prompt_version=prompt_version, tokens=10,
                             finish_reason="stop")
    return call


def _recipe(seg: int) -> str:
    return ('{"encoding":"recipe","format":"mvg","fields":{"segments":%d},'
            '"rationale":"r"}' % seg)


def test_duplicate_input_is_rejected_not_executed(monkeypatch):
    same = _recipe(8)
    monkeypatch.setattr(loop.llm_mod, "call_json", _fake_llm([same, same, same]))
    executed = []
    r = loop.run_loop(config=llm.LlmConfig(api_key="k"), claim={}, context="",
                      fmt="mvg", max_rounds=3,
                      execute=lambda d: (executed.append(d) or
                                         {"vul_exit": 0, "verdict": "not_triggered"}))
    assert len(executed) == 1
    assert r["duplicates_rejected"] == 2
    assert r["effective_rounds"] == 1


def test_distinct_inputs_all_executed(monkeypatch):
    # 每次用不同 segments，才会得到不同字节
    resps = [_recipe(n) for n in (2, 3, 4)]
    monkeypatch.setattr(loop.llm_mod, "call_json", _fake_llm(resps))
    executed = []
    r = loop.run_loop(config=llm.LlmConfig(api_key="k"), claim={}, context="",
                      fmt="mvg", max_rounds=3,
                      execute=lambda d: (executed.append(d) or
                                         {"vul_exit": 0, "verdict": "not_triggered"}))
    assert len(executed) == 3
    assert r["duplicates_rejected"] == 0
    assert r["effective_rounds"] == 3


def test_success_stops_loop(monkeypatch):
    resps = [_recipe(n) for n in (2, 5, 9)]
    monkeypatch.setattr(loop.llm_mod, "call_json", _fake_llm(resps))
    r = loop.run_loop(config=llm.LlmConfig(api_key="k"), claim={}, context="",
                      fmt="mvg", max_rounds=3,
                      execute=lambda d: {"vul_exit": 1, "fix_exit": 0,
                                         "verdict": "pass", "feedback": "ok"})
    assert r["succeeded"] is True
    assert r["total_rounds"] == 1


def test_prompt_asks_to_change_hypothesis_after_repeated_failure():
    """连续两轮未触发后，提示必须要求换假设，而不是再试同类输入。"""
    hist = [
        loop.LoopRound(round_id=1, verdict="not_triggered", vul_exit=0),
        loop.LoopRound(round_id=2, verdict="not_triggered", vul_exit=0),
    ]
    prompt = loop.build_prompt({"subject": "F"}, "ctx", hist, "mvg")
    assert "CHANGE THE HYPOTHESIS" in prompt


def test_no_hypothesis_change_hint_on_first_attempt():
    prompt = loop.build_prompt({"subject": "F"}, "ctx", [], "mvg")
    assert "CHANGE THE HYPOTHESIS" not in prompt
    assert "This is the first attempt" in prompt
