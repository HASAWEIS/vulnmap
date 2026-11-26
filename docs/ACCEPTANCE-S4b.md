# S4-b 阶段验收报告（2026-11-10）

审查对象：S4-b「干净任务复现模型贡献」——CG-09 / arvo:53666（krb5，正式集）
审查方式：冻结记录核对 + 运行结果比对 + 代码漂移检查
结论：**S4-b 未通过；S4 整体仍未通过**（S4-a 仅在开发样本成立）

---

## 1. 结果

| 项 | 值 |
|---|---|
| verdict | `generated_but_unverified` |
| rounds | 3（预算耗尽，非重复终止） |
| distinct_inputs | 3 |
| duplicates_rejected | 0 |
| verified_new_contribution | **false** |
| 失败原因 | `model_loop_candidates_all_unverified` |

**改进被证实有效的一半**：S2 基线是 3 轮 2 重复（effective=1），本轮 3 轮 3 个不同 sha —— `run_diverse_loop` 的“换假设”约束确实生效。
**但没解决的另一半**：换输入 ≠ 换对假设，3 个候选全部未触发。

---

## 2. 根因（子智能体给出的诊断，我认可）

| # | 卡点 | 证据 |
|---|---|---|
| B1 | loop 不知道 harness 输入契约 | `src/krb5/fuzzing/Fuzz_chpw.c` 规定 `20 <= Size <= 100`；第 3 轮给 1 字节，直接落在窗口外，`vul_exit=0` |
| B2 | 规则路径 0 claim | 本例是 UTF-8 规范化逻辑缺陷，无 memcpy/边界写特征，format=unknown 无构造器 |
| B3 | 反馈信息不足 | 前两轮纯 ASCII 走 normalize 成功分支，只拿到 `no_defect_diagnosis`，模型没有可用的“错在哪”信号 |
| B4 | 贡献链条要求候选自身 pass | 第一步不成立，后续 `added_by_llm` 无法升级为 verified |

---

## 3. 冻结整改确认（S2 的两项条件已闭环）

- `FREEZE.code.agent_files` 钉了 **31 个** `agent/**/*.py` 的 sha256（不再是 7 个）；
- `credential_source` 已记录：`{type:"local-dsh", env_var:"DEEPSEEK_API_KEY", origin:"~/.dsh/.credentials.yaml refs", secret_recorded:false}`；
- 代码漂移 0，产物由 agent 落盘，无手写 case.json。

---

## 4. 结论

- S4-b 失败是**能力失败，不是流程失败**：冻结、双跑、失败保留、诊断都做到了；
- S4 整体仍不通过：模型贡献只在开发样本（10096）成立，干净任务上未复现；
- 下一步若继续攻 S4，必须先补 **harness 契约提取**（把 `Size` 上下界、输入通道、格式提示注入 loop 提示），否则模型只能盲猜输入长度。

**一句话：这轮证明了“换假设”机制有效，也证明了“没有 harness 契约的换假设”仍然打不中。**
