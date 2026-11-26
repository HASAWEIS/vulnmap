r"""p5 输出纪律 + 降载重试（S5-d B5）。

S5-c 实测：种子块让模型啰嗦化，3 轮全部 finish_reason=length、completion 打满 8000，
0 轮执行。这里的验收点：
1. 提示里写死输出预算（content 只放 hex、<=240 字符、<=2 条种子、rationale <=60 词）；
2. finish_reason=length 或解析失败 -> 先降载重试一次（seed 2->1、上下文砍半），
   重试提示必须真的更短，而不是只在文案里声称；
3. 仍失败才记 llm_incomplete；
4. 每次模型调用都留 finish_reason / completion_tokens / prompt_chars / retry_round。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import harness, llm
from agent.stages.verify import (COMPACT_DIRECTIVE, OUTPUT_BUDGET_DIRECTIVE,
                                 _parse_reply, run_diverse_loop)

CONTRACT = {"min_size": 20, "max_size": 100, "confidence": "exact"}
SEEDS = [
    {"name": "result_ad_complex", "size": 30, "sha256": "a" * 64,
     "source": "tests/misc/test_chpw_message.c", "structure": harness.AD_POLICY_30},
    {"name": "result_ad_all", "size": 30, "sha256": "b" * 64,
     "source": "tests/misc/test_chpw_message.c", "structure": harness.AD_POLICY_30},
]


def _hex_reply(size: int = 30, byte: str = "00", rationale: str = "r") -> str:
    return json.dumps({"encoding": "hex", "content": byte * size,
                       "rationale": rationale})


class ScriptedLlm:
    """按脚本返回 LlmResult；记录每轮提示与调用参数。"""

    def __init__(self, steps):
        # steps: 每项是 dict(status=, content=, finish_reason=, completion_tokens=)
        self.steps = list(steps)
        self.prompts = []
        self.calls = 0

    def __call__(self, *, system, user, prompt_version):
        self.prompts.append(user)
        step = self.steps[min(self.calls, len(self.steps) - 1)]
        self.calls += 1
        return llm.LlmResult(
            status=step.get("status", "ok"),
            content=step.get("content", ""),
            model="deepseek-flash", prompt_version=prompt_version,
            tokens=int(step.get("total_tokens", 500)),
            prompt_tokens=int(step.get("prompt_tokens", 200)),
            completion_tokens=int(step.get("completion_tokens", 300)),
            finish_reason=step.get("finish_reason", "stop"),
            error=step.get("error", ""))


def _length_step():
    return {"status": "incomplete", "content": "", "finish_reason": "length",
            "completion_tokens": 8000, "error": "finish_reason=length"}


def _ok_step(content=None):
    return {"status": "ok", "content": content or _hex_reply(), "finish_reason": "stop",
            "completion_tokens": 120}


def _execute_ok(data):
    return {"vul_exit": 0, "fix_exit": None, "verdict": "not_triggered",
            "feedback": "vul_exit=0 | reason=no_defect_diagnosis"}


def _seed_block(n_max=2):
    return harness.seed_prompt(SEEDS, CONTRACT, max_show=n_max)


def _run(llm_stub, *, execute=None, max_rounds=3, seed_block=None, seeds=None):
    return run_diverse_loop(
        claim={"subject": "krb5_chpw_message"}, context="SOURCE EVIDENCE " * 40,
        fmt="unknown", execute=execute or _execute_ok, call_llm=llm_stub,
        max_rounds=max_rounds,
        seed_block=_seed_block() if seed_block is None else seed_block,
        seeds=SEEDS if seeds is None else seeds, contract=CONTRACT)


def test_prompt_states_hard_output_budget():
    fake = ScriptedLlm([_ok_step()])
    _run(fake, max_rounds=1)
    prompt = fake.prompts[0]
    assert "OUTPUT BUDGET" in prompt
    assert "HEX ONLY" in prompt
    assert "240 hex" in prompt
    assert "AT MOST 2 seeds" in prompt
    assert "at most 60 words" in prompt
    assert "\"encoding\":\"hex\"" in prompt
    # 预算指令在提示里只出现一次，避免自相矛盾的重复约束
    assert prompt.count(OUTPUT_BUDGET_DIRECTIVE) == 1


def test_hex_content_is_decoded_to_bytes():
    data, rationale, _field = _parse_reply(_hex_reply(30, "ab", "mutate min_length"),
                                          "unknown", False)
    assert data == bytes.fromhex("ab" * 30)
    assert rationale == "mutate min_length"
    # 非法 hex 必须报错，不能静默变成 text
    bad = json.dumps({"encoding": "hex", "content": "zz"})
    try:
        _parse_reply(bad, "unknown", False)
    except ValueError:
        pass
    else:
        raise AssertionError("bad hex must raise ValueError")


def test_length_truncation_triggers_compact_retry():
    fake = ScriptedLlm([_length_step(), _ok_step()])
    result = _run(fake, max_rounds=1)
    assert fake.calls == 2
    assert result["rounds"][0]["verdict"] == "not_triggered"
    assert result["rounds"][0]["retry_round"] == 1
    assert result["retried_rounds"] == 1
    assert result["executed_rounds"] == 1
    assert result["llm_incomplete_rounds"] == 0
    # 重试提示必须真的更短
    first_chars = result["rounds"][0]["llm_calls"][0]["prompt_chars"]
    retry_chars = result["rounds"][0]["llm_calls"][1]["prompt_chars"]
    assert retry_chars < first_chars
    assert COMPACT_DIRECTIVE in fake.prompts[1]
    # 种子从 2 条降到 1 条
    assert "seed 2:" in fake.prompts[0]
    assert "seed 2:" not in fake.prompts[1]
    assert "seed 1:" in fake.prompts[1]


def test_double_length_failure_records_llm_incomplete_with_metadata():
    fake = ScriptedLlm([_length_step(), _length_step()])
    result = _run(fake, max_rounds=1)
    rec = result["rounds"][0]
    assert rec["verdict"] == "llm_incomplete"
    assert result["llm_incomplete_rounds"] == 1
    assert result["executed_rounds"] == 0
    assert rec["finish_reason"] == "length"
    assert rec["completion_tokens"] == 8000
    assert rec["prompt_chars"] > 0
    assert rec["retry_round"] == 1
    assert len(rec["llm_calls"]) == 2
    for call in rec["llm_calls"]:
        for key in ("finish_reason", "completion_tokens", "prompt_chars", "retry_round"):
            assert key in call


def test_unparsable_reply_also_triggers_retry():
    bad = json.dumps({"encoding": "hex", "content": "zz"})
    fake = ScriptedLlm([_ok_step(bad), _ok_step()])
    result = _run(fake, max_rounds=1)
    assert fake.calls == 2
    assert result["rounds"][0]["verdict"] == "not_triggered"
    assert result["retried_rounds"] == 1
    assert result["invalid_output_rounds"] == 0


def test_unparsable_on_both_attempts_is_invalid_output():
    bad = json.dumps({"encoding": "hex", "content": "zz"})
    fake = ScriptedLlm([_ok_step(bad), _ok_step(bad)])
    result = _run(fake, max_rounds=1)
    assert result["rounds"][0]["verdict"] == "invalid_model_output"
    assert result["invalid_output_rounds"] == 1
    assert result["executed_rounds"] == 0


def test_no_retry_when_first_reply_is_fine():
    fake = ScriptedLlm([_ok_step(_hex_reply(30, "00")), _ok_step(_hex_reply(30, "11"))])
    result = _run(fake, max_rounds=2)
    assert fake.calls == 2                     # 每轮一次，没有重试
    assert result["retried_rounds"] == 0
    assert result["executed_rounds"] == 2
    assert result["total_calls"] == 2


def test_result_aggregates_executed_and_calls():
    fake = ScriptedLlm([_length_step(), _ok_step(_hex_reply(30, "00")),
                        _ok_step(_hex_reply(30, "11"))])
    result = _run(fake, max_rounds=2)
    assert result["executed_rounds"] == 2
    assert result["retried_rounds"] == 1
    assert result["total_calls"] == 3
    assert result["rounds"][0]["llm_calls"][1]["retry_round"] == 1
    assert result["rounds"][1]["llm_calls"][0]["retry_round"] == 0


def test_seed_block_is_bounded_in_first_prompt():
    fake = ScriptedLlm([_ok_step()])
    _run(fake, max_rounds=1)
    prompt = fake.prompts[0]
    # 提示里最多 2 条种子参与（p5 要求），且必然带 hex 与窗口
    assert prompt.count("hex: ") <= 2
    assert "20..100" in prompt
