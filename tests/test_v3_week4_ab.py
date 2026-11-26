r"""V3 第 4 周回归：规则 vs 模型只读建议的 A/B 对照与建议门禁（V3-020）。

被测实现：`agent/platform/adaptive/compare.py` 的 W4 段（`run_ab` /
`ab_task` / `ab_regression_tasks` / `FakeProvider` / `FakeClock` /
`render_ab_markdown`）。口径见该模块 docstring 与 `docs/V3-W4-AB.md`。

八组用例 / 九条断言（全部离线，不联网、不需要任何 key）：

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 控制变量 | `test_ab_arms_share_regression_set_config_budget_and_rules` | 两臂 control 摘要逐字相同；回归集 id 顺序一致；指标行顺序 == `AB_METRICS`；规则臂真的走 `DiagnoseRole`（原两个盲区 `w4-t08`/`w4-t09` 已按 `docs/RULE-DIAGNOSIS-PRIORITY.md` 修好，现给出 `no_execution`/`execution_error` 且判对） |
| 2 成功/模型有稳定收益 | `test_ab_stable_gain_opens_gate_but_never_auto_applies` + `test_frozen_regression_set_no_longer_shows_stable_gain` | 增益场景改用“规则臂结构性答不对”的两条任务（规则 0/2、模型 2/2，两个分层增益都 +1）→ 门禁 `default_arm="model"` 且 `auto_apply=False`；冻结回归集上规则臂 10/10、模型追平 → `stable_gain` 不再通过（门禁不动，如实断言） |
| 3 失败/无稳定收益 | `test_ab_model_without_stable_gain_defaults_to_rules` | 模型只会背规则诊断 → `stable_gain` 不通过 → `default_arm="rules"`；更差（全答一个码）时 `no_task_regression` 也拦下 |
| 4 无建议 | `test_ab_no_suggestion_is_retained_not_counted_as_wrong` | 10 条 `no_suggestion` 全进 `retained`；`correct=None` 不进分母；`answered.model == 0`；门禁 `answered_coverage` 不通过 |
| 5 预算耗尽 | `test_ab_budget_exhaustion_is_retained` | 全局 `max_calls` 截断 → 剩余任务 `budget_exhausted` 且留档；provider 自报 `budget_exhausted` 只影响该任务 |
| 6 错误采纳 | `test_ab_wrong_adoption_blocks_gate` | 诊断对但执行 gold 禁止的 `run_epoch` → `wrong_adoptions=1`、`wrong_reasons` 含 `forbidden_action:run_epoch`、门禁只留这一条理由 |
| 7 建议被拒 / 环境错误 | `test_ab_rejected_and_environment_errors_are_retained` | 不认识的诊断码 + 不存在的工具 → `status="rejected"` 且两条原因都在；裁决字段夹带 → 动作被剥掉（`adopted=0`）；provider 抛异常 → `environment_error`；未声明离线的 provider 一次都不调用 |
| 8 不产裁决 / 确定性 | `test_ab_document_is_deterministic_and_never_claims_verdict` | 两次运行（`FakeClock`）逐字节相同；`verdict="not_evaluated"`；整份文档不含 `"verified": true` / `"confirmed"`；人工规则写 `allow_auto_apply=true` 也被拒并记 blocker；markdown 里有门禁表与“自动应用：否” |

口径（**不因绿灯放宽**）：未作答的四类状态各自留档、不进分母；`wrong_adoptions>0`
一票否决（不再看收益）；模型建议永不自动应用，门禁只决定“下一轮的建议源”
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive import compare as ab
from agent.platform.adaptive.compare import (
    AB_METRICS,
    FakeClock,
    FakeProvider,
    ab_regression_tasks,
    ab_task,
    render_ab_markdown,
    run_ab,
)
from agent.platform.adaptive.session import (DiagnoseRole,   # noqa: E402
                                             Observation)

CONFIG = {"mode": "explore", "seed_format": "raw", "max_rounds": 3}


def _rules_miss_tasks() -> list[dict]:
    """规则臂**结构性**答不对、模型能答对的两条任务（分层 even/odd 各一条）。

    用途：演示“模型有稳定增益 → 门禁打开”。冻结回归集里 10 条任务修好诊断
    优先级后规则臂已经答满 10/10，模型最多追平，因此**不能**再用那份回归集
    演示增益（这是修 A 臂的必然结果，见 `docs/AB-ERROR-REVIEW.md` §5.6）。

    gold 用 `no_signal`：`DiagnoseRole` 是固定优先级规则，从来不产出该码
    （词表里有、分支里没有），所以规则臂在这两条上恒错，而门禁/判定口径不变。
    """
    return [
        ab_task("x-t01", observation={"trials": 2, "snapshot_status": "ok"},
                gold={"diagnosis": "no_signal",
                      "actions": ["get_task_facts"]}),
        ab_task("x-t02", observation={"trials": 2, "snapshot_status": "ok"},
                gold={"diagnosis": "no_signal",
                      "actions": ["get_task_facts"]}),
    ]


def _params(action: str) -> dict:
    """gold 动作的最小合法参数（`finish_research` 是唯一必填项）。"""
    if action == "finish_research":
        return {"reason": "candidate observed in execution feedback"}
    return {}


def _gold_script(tasks: list[dict]) -> dict:
    """理想 provider：诊断与动作都照人工 gold 说。"""
    script = {}
    for task in tasks:
        gold = task["gold"]
        script[task["task_id"]] = {
            "diagnosis": {"code": gold["diagnosis"]},
            "actions": [{"action": name, "params": _params(name)}
                        for name in gold["actions"]],
        }
    return script


def _run(script_or_provider, *, tasks=None, **kwargs):
    tasks = tasks if tasks is not None else ab_regression_tasks()
    provider = script_or_provider
    if isinstance(provider, dict):
        provider = FakeProvider(provider)
    kwargs.setdefault("clock", FakeClock())
    kwargs.setdefault("config", CONFIG)
    return run_ab(tasks=tasks, provider=provider, **kwargs), tasks, provider


def _status(record: dict) -> str:
    return str(record.get("status") or "")


# --------------------------------------------------------------------- 1 控制变量
def test_ab_arms_share_regression_set_config_budget_and_rules():
    doc, tasks, _ = _run(_gold_script(ab_regression_tasks()))
    controls = doc["controls"]

    # 同一份回归集：id 顺序一致，两臂摘要逐字相同
    assert controls["regression_set"] == [task["task_id"] for task in tasks]
    assert controls["arms"]["rules"] == controls["arms"]["model"]
    assert controls["arms_share_controls"] is True
    assert controls["digest"] == controls["arms"]["rules"]
    assert controls["initial_config"]["sha256"] == ab._ab_digest(CONFIG)
    assert controls["budget"]["max_rounds"] == 3
    assert controls["human_rules"]["allow_auto_apply"] is False

    # 指标表口径：固定七行、固定顺序
    assert [row["metric"] for row in doc["summary"]["metrics"]] == list(
        AB_METRICS)
    assert doc["schema"] == ab.AB_SCHEMA

    # A 臂真的是现有规则：诊断码来自 `DiagnoseRole`
    rules = {row["task_id"]: row for row in doc["summary"]["per_task"]["rules"]}
    assert rules["w4-t01"]["diagnosis"] == "no_execution"
    assert rules["w4-t05"]["diagnosis"] == "execution_error"
    assert rules["w4-t03"]["diagnosis"] == "input_not_processed"
    # 两个原已知规则盲区（`docs/AB-ERROR-REVIEW.md` §5）已按优先级规则修好：
    # 零执行 → no_execution；执行被取消 → execution_error
    assert rules["w4-t08"]["diagnosis"] == "no_execution"
    assert rules["w4-t09"]["diagnosis"] == "execution_error"
    assert rules["w4-t08"]["correct"] is True
    assert rules["w4-t09"]["correct"] is True
    # 规则臂真的走 `DiagnoseRole`：优先级表见 docs/RULE-DIAGNOSIS-PRIORITY.md
    empty = DiagnoseRole().diagnose(Observation(task_id="t", round_no=1,
                                               facts_hash="0" * 16,
                                               trials=0,
                                               snapshot_status="ok"))
    assert empty.code == "no_execution"


# --------------------------------------------------------------------- 2 成功
def test_ab_stable_gain_opens_gate_but_never_auto_applies():
    # 用“规则臂结构性答不对、模型答得对”的两条任务演示增益：冻结回归集上
    # 规则臂已 10/10，模型最多追平（见 `_rules_miss_tasks` 的说明）
    tasks = _rules_miss_tasks()
    doc, _, provider = _run(_gold_script(tasks), tasks=tasks)
    summary = doc["summary"]
    gate = doc["gate"]

    assert summary["correct"] == {"rules": 0, "model": 2}
    assert summary["answered"] == {"rules": 2, "model": 2}
    assert summary["correct_over_total"] == {
        "rules": {"correct": 0, "total": 2, "ratio": 0.0},
        "model": {"correct": 2, "total": 2, "ratio": 1.0},
    }
    assert summary["wrong_adoptions"]["model"] == 0
    assert summary["strata"]["even"]["gain"] == 1
    assert summary["strata"]["odd"]["gain"] == 1

    assert gate["default_arm"] == "model"
    assert gate["model_advisory_allowed"] is True
    assert gate["reasons"] == []
    assert all(check["ok"] for check in gate["checks"])

    # 门禁通过 ≠ 能写：自动应用恒为 False，且应用仍要过隔离/授权验收门
    assert gate["auto_apply"] is False
    assert gate["proposal_gate"]["status"] == "advisory"
    assert gate["proposal_gate"]["applied"] is False
    assert "proposal_gate:advisory" in gate["auto_apply_blockers"]

    # 成本侧：规则臂 0 调用；模型臂按轮次计费，金额有价格支撑
    cost = summary["cost"]
    assert cost["calls"]["rules"] == 0
    assert cost["calls"]["model"] == sum(
        row["executed_rounds"] for row in _records(doc, "model"))
    assert cost["tokens"]["model"] > 0
    assert cost["usd"]["model"] == pytest.approx(0.0025 * cost["calls"]["model"])
    assert cost["usd_known"] is True
    assert len(provider.calls) == cost["calls"]["model"]

    usd_row = next(row for row in summary["metrics"]
                   if row["metric"] == "model_usd")
    assert usd_row["direction"] == "worse"          # 成本总是模型更高


def _records(doc: dict, arm: str) -> list[dict]:
    return [item[arm] for item in doc["tasks"]]


def test_frozen_regression_set_no_longer_shows_stable_gain():
    """修好 A 臂的必然结果：冻结回归集上模型最多追平，`stable_gain` 不再通过。

    这正是 `docs/AB-ERROR-REVIEW.md` §5.6 登记的门禁语义缺陷
    （`gain = model_correct − rules_correct`），本轮**不动**门禁，只如实断言。
    """
    tasks = ab_regression_tasks()
    doc, _, _ = _run(_gold_script(tasks), tasks=tasks)
    summary = doc["summary"]

    assert summary["correct"] == {"rules": 10, "model": 10}
    assert summary["strata"]["even"]["gain"] == 0
    assert summary["strata"]["odd"]["gain"] == 0
    assert doc["gate"]["default_arm"] == "rules"
    assert doc["gate"]["reasons"] == ["stable_gain"]
    assert doc["gate"]["auto_apply"] is False


# --------------------------------------------------------------------- 3 失败
def test_ab_model_without_stable_gain_defaults_to_rules():
    tasks = ab_regression_tasks()
    # 只会背规则诊断、不提动作：正确数追平规则，但没有增益
    rules_diag = {"w4-t01": "no_execution", "w4-t02": "program_not_started",
                  "w4-t03": "input_not_processed",
                  "w4-t04": "candidate_observed", "w4-t05": "execution_error",
                  "w4-t06": "progress", "w4-t07": "config_not_effective",
                  "w4-t08": "no_execution", "w4-t09": "execution_error",
                  "w4-t10": "low_coverage"}
    tie = {task["task_id"]: {"diagnosis": {"code": rules_diag[task["task_id"]]},
                            "actions": []} for task in tasks}
    doc, _, _ = _run(tie, tasks=tasks)
    # 规则臂现在 10/10（`w4-t08`/`w4-t09` 已按优先级规则修好），背诊断的模型追平
    assert doc["summary"]["correct"] == {"rules": 10, "model": 10}
    assert doc["summary"]["wrong_adoptions"]["model"] == 0
    assert doc["gate"]["default_arm"] == "rules"
    assert doc["gate"]["reasons"] == ["stable_gain"]
    assert doc["gate"]["model_advisory_allowed"] is False

    # 更差的模型：全答一个码 → 回归检查也拦
    worse = {task["task_id"]: {"diagnosis": {"code": "no_execution"},
                               "actions": []} for task in tasks}
    doc, _, _ = _run(worse, tasks=tasks)
    reasons = doc["gate"]["reasons"]
    assert doc["gate"]["default_arm"] == "rules"
    assert "no_task_regression" in reasons
    assert "stable_gain" in reasons
    detail = next(check for check in doc["gate"]["checks"]
                  if check["name"] == "no_task_regression")["detail"]
    assert "w4-t04" in detail and "w4-t10" in detail


# --------------------------------------------------------------------- 4 无建议
def test_ab_no_suggestion_is_retained_not_counted_as_wrong():
    tasks = ab_regression_tasks()
    empty = {task["task_id"]: {"status": "no_suggestion"} for task in tasks}
    doc, _, _ = _run(empty, tasks=tasks)
    summary, gate = doc["summary"], doc["gate"]

    assert summary["status_counts"]["model"]["no_suggestion"] == len(tasks)
    assert summary["retained"]["no_suggestion"] == [
        task["task_id"] for task in tasks]
    assert summary["answered"]["model"] == 0
    assert summary["correct"]["model"] == 0
    assert summary["accuracy"]["model"] is None
    # 分母是总任务数：答 0 条就是 0/10，不粉饰成“没有数据”
    assert summary["correct_over_total"]["model"] == {
        "correct": 0, "total": 10, "ratio": 0.0}
    # 没作答不是“答错”：correct 一律 None，错误采纳 0
    assert all(row["correct"] is None for row in _records(doc, "model"))
    assert summary["wrong_adoptions"]["model"] == 0

    assert gate["default_arm"] == "rules"
    assert "answered_coverage" in gate["reasons"]
    assert gate["auto_apply"] is False
    # 规则臂照常跑完，统计真实 provider 调用次数（有调用，但没有可用建议）
    assert summary["cost"]["calls"]["model"] == len(tasks)
    assert summary["correct"]["rules"] == 10


# --------------------------------------------------------------------- 5 预算耗尽
def test_ab_budget_exhaustion_is_retained():
    tasks = ab_regression_tasks()
    doc, _, _ = _run(_gold_script(tasks), tasks=tasks, budget={"max_calls": 5})
    summary, gate = doc["summary"], doc["gate"]

    assert summary["cost"]["calls"]["model"] == 5
    assert summary["status_counts"]["model"]["ok"] == 3      # 3 条一轮任务
    assert len(summary["retained"]["budget_exhausted"]) == 7
    assert summary["retained"]["budget_exhausted"] == [
        task["task_id"] for task in tasks[3:]]
    assert all(row["correct"] is None
               for row in _records(doc, "model")[3:])
    assert gate["default_arm"] == "rules"
    assert "answered_coverage" in gate["reasons"]
    assert summary["budget"]["max_calls"] == 5

    # provider 自报预算耗尽：只把该任务记成预算耗尽，后续任务照跑
    half = _gold_script(tasks)
    half["w4-t05"] = {"status": "budget_exhausted"}
    doc, _, _ = _run(half, tasks=tasks)
    assert doc["summary"]["retained"]["budget_exhausted"] == ["w4-t05"]
    assert doc["summary"]["status_counts"]["model"]["ok"] == 9
    assert doc["gate"]["default_arm"] == "rules"     # 覆盖 9/10 够，但增益不足以稳
    assert "w4-t05" not in [row["task_id"] for row in
                            doc["summary"]["per_task"]["model"]
                            if row["correct"] is True]


# --------------------------------------------------------------------- 6 错误采纳
def test_ab_wrong_adoption_blocks_gate():
    tasks = ab_regression_tasks()
    script = _gold_script(tasks)
    # 诊断正确，但执行了一个 gold 明令禁止的动作（execution_error 下原样重跑）
    script["w4-t05"] = {"diagnosis": {"code": "execution_error"},
                        "actions": [{"action": "run_epoch", "params": {}}]}
    doc, _, _ = _run(script, tasks=tasks)
    summary, gate = doc["summary"], doc["gate"]

    # 规则臂只剩 1 次错误采纳（`w4-t03` 的 forbidden run_epoch）
    assert summary["wrong_adoptions"] == {"rules": 1, "model": 1}
    row = next(item for item in _records(doc, "model")
               if item["task_id"] == "w4-t05")
    assert row["correct"] is True
    assert row["wrong_adoption"] == 1
    assert "forbidden_action:run_epoch" in row["wrong_reasons"]

    assert gate["default_arm"] == "rules"
    # 模型侧越权 → 一票否决；同时规则臂 10/10 使 `stable_gain` 结构性为 0
    # （§5.6 登记的门禁语义缺陷，本轮不动门禁，只如实记两条理由）
    assert gate["reasons"] == ["no_model_wrong_adoption", "stable_gain"]
    assert gate["model_advisory_allowed"] is False
    assert gate["auto_apply"] is False

    # 规则臂自己的错误采纳一并如实记账（不改判、不掩盖）
    rules_row = next(item for item in _records(doc, "rules")
                     if item["task_id"] == "w4-t03")
    assert rules_row["wrong_adoption"] == 1
    assert "forbidden_action:run_epoch" in rules_row["wrong_reasons"]


# --------------------------------------------------------------------- 7 被拒 / 环境错误
def test_ab_rejected_and_environment_errors_are_retained():
    tasks = ab_regression_tasks()
    script = _gold_script(tasks)
    # 不认识的诊断码 + 不存在的工具 → 整条建议被拒
    script["w4-t04"] = {"diagnosis": {"code": "made_up_code"},
                        "actions": [{"action": "delete_everything",
                                     "params": {}}]}
    # 裁决字段夹带 → 动作被剥掉，诊断仍可用（但没动作就不算采纳）
    script["w4-t10"] = {"diagnosis": {"code": "low_coverage"},
                        "actions": [{"action": "run_epoch",
                                     "params": {"verified": True}}]}
    # provider 崩了 → 环境错误
    script["w4-t06"] = RuntimeError("connection reset by peer")
    doc, _, _ = _run(script, tasks=tasks)
    summary = doc["summary"]

    assert summary["retained"]["rejected"] == ["w4-t04"]
    t04 = next(item for item in _records(doc, "model")
               if item["task_id"] == "w4-t04")
    assert _status(t04) == "rejected"
    assert t04["adopted"] == 0 and t04["correct"] is None
    assert any("invalid_diagnosis" in reason for reason in t04["rejected"])
    assert any("delete_everything" in reason for reason in t04["rejected"])

    t10 = next(item for item in _records(doc, "model")
               if item["task_id"] == "w4-t10")
    assert _status(t10) == "ok" and t10["adopted"] == 0
    assert any("verdict_fields" in reason for reason in t10["rejected"])

    assert summary["retained"]["environment_error"] == ["w4-t06"]
    t06 = next(item for item in _records(doc, "model")
               if item["task_id"] == "w4-t06")
    assert _status(t06) == "environment_error"
    assert "RuntimeError" in t06["error"]
    assert doc["gate"]["default_arm"] == "rules"

    # 未声明离线的 provider：一次都不调用，整臂记环境错误
    class _NetworkProvider(FakeProvider):
        offline = False

    provider = _NetworkProvider(_gold_script(tasks))
    doc, _, _ = _run(provider, tasks=tasks)
    assert provider.calls == []
    assert doc["summary"]["status_counts"]["model"]["environment_error"] == \
        len(tasks)
    assert doc["summary"]["cost"]["calls"]["model"] == 0
    assert "offline_provider" in doc["gate"]["reasons"]
    assert doc["arms"]["model"]["offline"] is False


# --------------------------------------------------------------------- 8 确定性
def test_ab_document_is_deterministic_and_never_claims_verdict():
    tasks = ab_regression_tasks()
    first, _, _ = _run(_gold_script(tasks), tasks=tasks, label="w4")
    second, _, _ = _run(_gold_script(tasks), tasks=tasks, label="w4")
    body = json.dumps(first, ensure_ascii=False, sort_keys=True)
    assert body == json.dumps(second, ensure_ascii=False, sort_keys=True)

    # 不产裁决：文档里就没有自裁决字段
    assert first["verdict"] == ab.AB_VERDICT == "not_evaluated"
    assert '"verified": true' not in body
    assert "confirmed" not in body
    assert all("verified" not in key for key in first["summary"])

    # 人工规则里写 allow_auto_apply=true 也照样不自动应用
    granted, _, _ = _run(_gold_script(tasks), tasks=tasks,
                         human_rules={"allow_auto_apply": True})
    assert granted["gate"]["auto_apply"] is False
    assert any("allow_auto_apply" in item
               for item in granted["gate"]["auto_apply_blockers"])

    markdown = render_ab_markdown(first)
    assert "## 第 4 周 A/B（现有规则 vs 模型只读建议）" in markdown
    assert "自动应用：否（模型建议永不自动应用）" in markdown
    assert "### 门禁检查" in markdown
    # 冻结回归集：规则臂 10/10，模型追平 → `stable_gain` 不再通过（门禁不动）
    assert "| stable_gain | 未通过 |" in markdown
    assert "| 正确诊断数 | 10 | 10 |" in markdown
    assert markdown == render_ab_markdown(second)

    # “门禁通过”这条渲染路径仍要覆盖：用规则臂结构性答不对的两条任务跑一次
    open_tasks = _rules_miss_tasks()
    open_doc, _, _ = _run(_gold_script(open_tasks), tasks=open_tasks,
                          label="w4")
    open_markdown = render_ab_markdown(open_doc)
    assert open_doc["gate"]["default_arm"] == "model"
    assert "| stable_gain | 通过 |" in open_markdown
    assert "| 正确诊断数 | 0 | 2 |" in open_markdown

    # 规范化入口：缺 gold / 空回归集 / 重名都是编程错误，不是“降级成未知”
    with pytest.raises(ab.ABError):
        ab_task("t", observation={}, gold={})
    with pytest.raises(ab.ABError):
        run_ab(tasks=[], provider=FakeProvider({}))
    duplicate = [ab_task("same", observation={},
                         gold={"diagnosis": "no_execution"})] * 2
    with pytest.raises(ab.ABError):
        run_ab(tasks=duplicate, provider=FakeProvider({}))
