r"""诊断优先级规则（`DiagnoseRole`）：终止态 > 零执行 > 目标/覆盖。

口径见 `docs/RULE-DIAGNOSIS-PRIORITY.md`（本文件的断言逐条对应那张优先级表）：

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 优先级表 | `test_priority_ladder_is_total_order` | 一条链、每个位置只产一个码；重叠旗标按 `cancelled > budget_stopped > error > timeout` 取第一个 |
| 2 取消 | `test_cancelled_is_execution_error` | `fault.cancelled=true` → `execution_error(reasons=("cancelled",))`，不再是 `coverage_unknown` |
| 3 预算中止 | `test_budget_stopped_is_execution_error` | `fault.budget_stopped=true` → `execution_error(reasons=("budget_stopped",))`；deadline 形态（timeout 同时为真）仍由它赢 |
| 4 零执行 | `test_zero_trials_is_no_execution_even_when_snapshot_is_ok` | `trials==0` → `no_execution`（不再要求 `snapshot_status=="unknown"`）；但 `program_started=="true"` 说明跑过 → 只能 `coverage_unknown` |
| 5 零执行且已取消 | `test_zero_trials_with_cancelled_is_execution_error_not_no_execution` | 两个状态重叠时只出 `execution_error`：取消是“跑没跑完”，比“没跑过”更硬 |
| 6 候选优先 | `test_candidate_survives_terminal_state` | 取消/报错/预算中止之前已出候选 → `candidate_observed`（正证据不被终止态抹掉） |
| 7 不矛盾 | `test_overlapping_states_never_produce_two_diagnoses` | 任意旗标组合都只得到一个码，且在 `DIAGNOSIS_CODES` 内；同样输入两次结果逐字段相同 |
| 8 未回归 | `test_unrelated_branches_are_unchanged` | `config_not_effective` / 目标三段 / `config_unverified` / `progress` / `low_coverage` 的落点与理由一字不变 |
| 9 收紧后的兜底 | `test_coverage_unknown_requires_trials_and_no_terminal_fault` | `coverage_unknown` 只表示“真跑过一次且没异常终止、目标态未知” |

全部离线、不联网、零模型调用。
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive.session import (          # noqa: E402
    DIAGNOSIS_CODES, DiagnoseRole, Diagnosis, Observation)


def _obs(**kwargs) -> Observation:
    kwargs.setdefault("task_id", "t-priority")
    kwargs.setdefault("round_no", 1)
    kwargs.setdefault("facts_hash", "0" * 16)
    return Observation(**kwargs)


def _code(**kwargs) -> Diagnosis:
    return DiagnoseRole().diagnose(_obs(**kwargs))


# ------------------------------------------------------------------ 1 优先级表
def test_priority_ladder_is_total_order():
    """终止态四旗标的重叠判定：第一个命中的赢，理由里写明是哪一个。"""
    role = DiagnoseRole()
    assert role.TERMINAL_FAULT_ORDER == ("cancelled", "budget_stopped",
                                         "error", "timeout")
    flags = role.TERMINAL_FAULT_ORDER
    for size in range(1, len(flags) + 1):
        for combo in itertools.combinations(flags, size):
            diagnosis = _code(fault={name: "true" for name in combo}, trials=2,
                              snapshot_status="ok")
            assert diagnosis.code == "execution_error", combo
            # 只认第一个命中：组合里越靠前的旗标赢
            winner = next(name for name in flags if name in combo)
            assert diagnosis.reasons == (role.TERMINAL_REASONS[winner],), combo


# ---------------------------------------------------------------------- 2 取消
def test_cancelled_is_execution_error():
    diagnosis = _code(fault={"cancelled": "true"}, trials=1,
                      program_started="true", input_processed="true",
                      snapshot_status="ok")
    assert diagnosis.code == "execution_error"
    assert diagnosis.severity == "blocked"
    assert diagnosis.reasons == ("cancelled",)

    # 三值语义：false / unknown 不许被当成“取消”
    for value in ("false", "unknown", None, ""):
        assert _code(fault={"cancelled": value}, trials=1,
                     snapshot_status="ok").code != "execution_error"
    # 布尔 True 与字符串 "true" 等价（快照侧两种拼写都出现过）
    assert _code(fault={"cancelled": True}, trials=1,
                 snapshot_status="ok").reasons == ("cancelled",)


# ------------------------------------------------------------------ 3 预算中止
def test_budget_stopped_is_execution_error():
    diagnosis = _code(fault={"budget_stopped": "true"}, trials=2,
                      snapshot_status="ok")
    assert diagnosis.code == "execution_error"
    assert diagnosis.reasons == ("budget_stopped",)

    # deadline 形态：快照同时写 timeout=true 与 budget_stopped=true，
    # 按优先级由 budget_stopped 赢（码不变，理由可复核）
    deadline = _code(fault={"budget_stopped": "true", "timeout": "true"},
                     trials=2, snapshot_status="ok")
    assert deadline.code == "execution_error"
    assert deadline.reasons == ("budget_stopped",)

    # 纯超时（不是预算形态）仍然报 timeout
    assert _code(fault={"timeout": "true"}, trials=2,
                 snapshot_status="ok").reasons == ("timeout",)


# -------------------------------------------------------------------- 4 零执行
def test_zero_trials_is_no_execution_even_when_snapshot_is_ok():
    """快照采到了但一次都没跑：仍然是零执行，不是覆盖未知。"""
    diagnosis = _code(trials=0, snapshot_status="ok")
    assert diagnosis.code == "no_execution"
    assert diagnosis.severity == "info"
    assert diagnosis.reasons == ("no_execution_facts",)
    # 旧行为（要求 snapshot_status=unknown）也照旧成立
    assert _code(trials=0, snapshot_status="unknown").code == "no_execution"

    # 反例（`docs/V3-TARGET-SEMANTICS.md` 的无观测手段组）：程序真的起来了，
    # 只是报告路径没有 SessionState、`trials` 恒 0 —— 这时不能倒过来说“没执行”
    blind = _code(trials=0, snapshot_status="ok", program_started="true")
    assert blind.code == "coverage_unknown"
    assert blind.reasons == ("target_reached_unknown",)


# --------------------------------------------------------- 5 零执行且已取消
def test_zero_trials_with_cancelled_is_execution_error_not_no_execution():
    diagnosis = _code(trials=0, snapshot_status="ok",
                      fault={"cancelled": "true"})
    assert diagnosis.code == "execution_error"
    assert diagnosis.reasons == ("cancelled",)
    # 同一份事实只给一个结论：不会再冒出 no_execution
    assert diagnosis.code != "no_execution"


# ------------------------------------------------------------------ 6 候选优先
@pytest.mark.parametrize("fault", [
    {"cancelled": "true"},
    {"budget_stopped": "true"},
    {"error": "true"},
    {"timeout": "true"},
    {"cancelled": "true", "budget_stopped": "true", "error": "true",
     "timeout": "true"},
])
def test_candidate_survives_terminal_state(fault):
    """取消/报错之前已经出了候选：那是不容抹掉的正证据。"""
    diagnosis = _code(candidates=2, trials=3, snapshot_status="ok", fault=fault)
    assert diagnosis.code == "candidate_observed"
    assert diagnosis.candidates == 2
    assert diagnosis.reasons == ("candidates=2",)


# -------------------------------------------------------------------- 7 不矛盾
def test_overlapping_states_never_produce_two_diagnoses():
    """任意旗标/计数/目标态组合：一个码、在词表内、可复算、不来回跳。"""
    role = DiagnoseRole()
    flags = DiagnoseRole.TERMINAL_FAULT_ORDER
    seen = set()
    for mask in range(1 << len(flags)):
        fault = {name: "true" for index, name in enumerate(flags)
                 if mask & (1 << index)}
        for trials in (0, 1):
            for candidates in ("unknown", 0, 1):
                observation = _obs(fault=fault, trials=trials,
                                   candidates=candidates, snapshot_status="ok")
                first = role.diagnose(observation)
                second = role.diagnose(observation)
                assert first.code in DIAGNOSIS_CODES
                assert first.to_dict() == second.to_dict()   # 确定性、幂等
                seen.add(first.code)
    # 该组合空间里不允许出现“两个结论都像”的码：终止态一律 execution_error
    assert "execution_error" in seen and "no_execution" in seen


# ------------------------------------------------------------------ 8 未回归
def test_unrelated_branches_are_unchanged():
    # 配置没生效：仍然排在候选/目标之前
    assert _code(config={"status": "not_effective", "planned": "a" * 8},
                 candidates=1, trials=2).code == "config_not_effective"
    # 目标三段
    assert _code(program_started="false", trials=1).code == \
        "program_not_started"
    assert _code(program_started="true", input_processed="false",
                 trials=1).code == "input_not_processed"
    assert _code(program_started="true", input_processed="true",
                 checkpoint_reached="false", trials=1).code == "target_unreached"
    # setup_error 仍然是 target_unreached 的理由，不是新码
    assert _code(program_started="true", input_processed="true",
                 checkpoint_reached="false", trials=1,
                 fault={"setup_error": "true"}).reasons == ("setup_error",)
    # 目标命中后的增益判定
    assert _code(checkpoint_reached="true", trials=1,
                 coverage={"delta": 0.5}).code == "progress"
    assert _code(checkpoint_reached="true", trials=1,
                 coverage={"delta": 0.0}).code == "low_coverage"
    # 改了配置却没加载回报：仍排在零执行之前（t07 形态不被降级）
    assert _code(config={"status": "unknown", "planned": "a" * 8},
                 trials=0).code == "config_unverified"
    # 报错理由拼写不变
    assert _code(fault={"error": "true"}, trials=1).reasons == ("error:true",)


# ------------------------------------------------------------ 9 收紧后的兜底
def test_coverage_unknown_requires_trials_and_no_terminal_fault():
    """兜底码只剩一种含义：真跑过、没异常终止、目标态未知。"""
    assert _code(trials=1, snapshot_status="ok").code == "coverage_unknown"
    # 反例三条：零执行、终止态、目标已命中——都不许落到这个码
    assert _code(trials=0, snapshot_status="ok").code == "no_execution"
    assert _code(trials=1, fault={"cancelled": "true"}).code == \
        "execution_error"
    assert _code(trials=1, checkpoint_reached="true").code == \
        "low_coverage"
    # `program_started` 已知为 true 但没试验计数：跑过，只是没读数
    assert _code(trials=0, program_started="true").code == "coverage_unknown"
