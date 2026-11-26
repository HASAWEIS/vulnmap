"""verify 模型闭环的去重与「换假设」约束。

S2 双跑实测：3 轮里第 2、3 轮与第 1 轮逐字节相同（duplicate_input_rounds）。
这里的验收点：
1. 每轮输入 sha256 必须落进 rounds（可审计，不靠推断）；
2. 重复输入判 duplicate_input，不执行，并把「换假设」写成下一轮提示的硬指令；
3. 连续 2 轮重复则终止，并写明 terminal_reason。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import llm
from agent.stages.verify import (DUPLICATE_MAX_CONSECUTIVE, run_diverse_loop)


def _recipe(seg: int, rationale: str = "r") -> str:
    return ('{"encoding":"recipe","format":"mvg","fields":{"segments":%d},'
            '"rationale":"%s"}' % (seg, rationale))


class FakeLlm:
    """记录每次提示，按脚本返回；顺带统计调用次数。"""

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts: list[str] = []

    def __call__(self, *, system, user, prompt_version):
        self.prompts.append(user)
        n = len(self.prompts) - 1
        content = self.responses[min(n, len(self.responses) - 1)]
        return llm.LlmResult(status="ok", content=content, model="m",
                             prompt_version=prompt_version, tokens=7,
                             finish_reason="stop")


def _run(responses, *, executed=None, max_rounds=3, verdict="not_triggered",
         duplicate_max_consecutive=None):
    fake = FakeLlm(responses)
    ran = executed if executed is not None else []
    kw = {"max_rounds": max_rounds}
    if duplicate_max_consecutive is not None:
        kw["duplicate_max_consecutive"] = duplicate_max_consecutive

    def execute(data):
        ran.append(data)
        return {"vul_exit": 0, "fix_exit": None, "verdict": verdict,
                "feedback": "vul_exit=0"}

    result = run_diverse_loop(claim={"subject": "ConvertPrimitiveToPath"},
                              context="ctx", fmt="mvg", execute=execute,
                              call_llm=fake, **kw)
    return result, fake, ran


def test_every_round_records_input_sha256():
    result, fake, ran = _run([_recipe(8), _recipe(9), _recipe(12)])
    assert len(result["rounds"]) == 3
    for rec in result["rounds"]:
        assert rec["input_sha256"], rec
        assert len(rec["input_sha256"]) == 64
    # 三轮是三条不同输入：distinct 必须为 3，且全部真实执行过
    assert result["distinct_inputs"] == 3
    assert len(ran) == 3
    assert result["effective_rounds"] == 3


def test_duplicate_input_is_judged_and_not_executed():
    same = _recipe(8)
    result, fake, ran = _run([same, same, same])
    verdicts = [r["verdict"] for r in result["rounds"]]
    assert verdicts == ["not_triggered", "duplicate_input", "duplicate_input"]
    # 重复输入不执行：只有第 1 轮真跑了双端
    assert len(ran) == 1
    assert result["duplicates_rejected"] == 2
    assert result["duplicate_input_rounds"] == 2
    assert result["distinct_inputs"] == 1
    assert result["effective_rounds"] == 1
    dup = [r for r in result["rounds"] if r["duplicate"]]
    assert all(r["reason"] and r["required_action"] == "change_hypothesis" for r in dup)
    assert all(r["input_sha256"] == result["rounds"][0]["input_sha256"] for r in dup)


def test_duplicate_reason_is_written_back_into_next_prompt():
    same = _recipe(8)
    # 第 3 轮复读第 1 轮 -> 判 duplicate；重复原因必须进第 4 轮提示
    result, fake, _ran = _run([same, _recipe(9), same, _recipe(12)], max_rounds=4)
    assert "DUPLICATE_INPUT_REJECTED" not in fake.prompts[0]
    assert "DUPLICATE_INPUT_REJECTED" not in fake.prompts[1]
    assert "DUPLICATE_INPUT_REJECTED" not in fake.prompts[2]
    assert result["rounds"][2]["verdict"] == "duplicate_input"
    # 第 4 轮提示：重复原因 + 明确的「换假设」要求，不是静默忽略
    assert "DUPLICATE_INPUT_REJECTED" in fake.prompts[3]
    assert result["rounds"][0]["input_sha256"][:16] in fake.prompts[3]
    assert "CHANGE THE HYPOTHESIS" in fake.prompts[3]
    # 换假设后闭环继续，不因一次重复被终止
    assert result["terminated_early"] is False
    assert result["rounds"][3]["verdict"] == "not_triggered"


def test_hypothesis_change_after_duplicate_is_allowed_to_continue():
    same = _recipe(8)
    result, fake, ran = _run([same, same, _recipe(9), _recipe(12)], max_rounds=4)
    verdicts = [r["verdict"] for r in result["rounds"]]
    assert verdicts == ["not_triggered", "duplicate_input",
                        "not_triggered", "not_triggered"]
    # 换假设后的新输入照常执行
    assert len(ran) == 3
    assert result["distinct_inputs"] == 3
    assert result["terminated_early"] is False


def test_two_consecutive_duplicates_terminate_loop_with_reason():
    same = _recipe(8)
    result, fake, ran = _run([same, same, same, _recipe(9)], max_rounds=4)
    assert DUPLICATE_MAX_CONSECUTIVE == 2
    assert result["terminated_early"] is True
    assert result["consecutive_duplicate_termination"] is True
    assert "duplicate_input_rounds" in result["terminal_reason"]
    assert "连续 2 轮" in result["terminal_reason"]
    # 第 3 轮就终止：第 4 轮不再调用模型
    assert len(fake.prompts) == 3
    assert result["total_rounds"] == 3
    assert len(ran) == 1


def test_pass_stops_loop_and_marks_winner():
    fake = FakeLlm([_recipe(8), _recipe(9)])

    def execute(data):
        return {"vul_exit": 1, "fix_exit": 0, "verdict": "pass", "feedback": "ok"}

    result = run_diverse_loop(claim={"subject": "F"}, context="ctx", fmt="mvg",
                              execute=execute, call_llm=fake, max_rounds=3)
    assert result["succeeded"] is True
    assert result["winner_round"] == 1
    assert result["total_rounds"] == 1
    assert len(fake.prompts) == 1
