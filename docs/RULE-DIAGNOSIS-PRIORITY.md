# 规则诊断优先级（RULE-DIAGNOSIS-PRIORITY）

> 输入：`agent/platform/adaptive/session.py`（`DiagnoseRole.diagnose`）、
> `docs/AB-ERROR-REVIEW.md` §5（上一轮写死的改进规格）、
> `docs/V3-TARGET-SEMANTICS.md`（目标语义三段）、
> `docs/V3-W2-CONFIG.md` §5.2（配置效果插入位置）、
> `agent/platform/adaptive/compare.py`（`_ab_judge` / `ab_regression_tasks` / `_ab_gate`）、
> `tests/test_v3_week4_ab.py`、`tests/test_v3_target_semantics.py`。
>
> 产物：`experiments/rule-regression/`（`before.json` / `after.json` /
> `diff.json` / `report.md` + 两个可复算脚本）。
>
> 纪律：不改 fixture / `gold` / `forbid` / `budget` / `human_rules` / 门禁阈值；
> 不换模型、不改 provider、不动 `stable_gain`；不 `git commit`；不产漏洞结论
> （`verdict` 概念不适用）。本文件不含时间戳：同一输入两次生成逐字节相同。

---

## 0. 结论先行

| 问题 | 答案 | 依据 |
|---|---|---|
| 优先级是什么 | **`config_not_effective` → `candidate_observed` → `cancelled` > `budget_stopped` > `error` > `timeout`（同码 `execution_error`）→ 目标三段 → `config_unverified` → `trials==0`/`no_execution` → 目标命中后的 `progress`/`low_coverage` → `coverage_unknown`** | §1（`session.py:440-553`） |
| 重叠状态会不会互相矛盾 | **不会**：一条链、位置即优先级、只产一个码；四旗标重叠由 `TERMINAL_FAULT_ORDER` 取第一个命中的，理由里写明赢家 | §1.2、`tests/test_rule_diagnosis_priority.py` 13 例 |
| 改了什么 | `session.py` 一个类（三处：优先级 docstring、终止态闸门、零执行条件）+ 测试 + 本文件 + `experiments/rule-regression/` | §3 |
| 冻结回归集上 `correct 7→9`、`wrong_adoption 3→1` 成立吗 | **成立**，且逐任务只动了 `w4-t08`、`w4-t09` 两行；`invalid_retries` 4→4、`action_recall_mean` 0.375→0.375 | §4（14 条判定全绿，`verdict=accept`） |
| 门禁会变绿吗 | **不会，而且是结构性的**：`stable_gain = model_correct − rules_correct`，修好 A 臂只会让增益更负。本轮**不动**门禁，只如实记录 | §6 |
| 有没有顺手发现的问题 | 有两条：字面实现 §5.1 会把“无观测手段”误报成 `no_execution`（已加守卫）；`trials` 仍是二值计数、`coverage.status` 仍不参与判定 | §5.3、§9 |

一句话：**“覆盖未知”只能表示“真的跑过一次、且没被取消/中止/报错打断、目标态未知”**；
把这句不变量写进一条显式优先级链之后，规则臂在冻结回归集上的 3 次错误采纳降到 1 次。

---

## 1. 优先级表（唯一权威口径）

`DiagnoseRole.diagnose` 是一条**线性**链：从上往下第一个命中的分支返回，后面的分支
不再执行。位置就是优先级，不存在“两个结论都成立”的写法。

| # | 条件（全部来自 `Observation`，不做推断） | 码 | severity | `reasons` | 依据 |
|---|---|---|---|---|---|
| 1 | `config.status == "not_effective"` | `config_not_effective` | blocked | `loaded!=<planned>` | `V3-W2-CONFIG.md` §5.2 |
| 2 | `candidates > 0`（`int` 且非 `bool`） | `candidate_observed` | info | `candidates=N` | `AB-ERROR-REVIEW.md` §5.8 R2 |
| 3 | `fault.cancelled == "true"` | `execution_error` | blocked | `cancelled` | 本轮新增 |
| 4 | `fault.budget_stopped == "true"` | `execution_error` | blocked | `budget_stopped` | 本轮新增 |
| 5 | `fault.error == "true"` | `execution_error` | blocked | `error:true` | 既有 |
| 6 | `fault.timeout == "true"` | `execution_error` | blocked | `timeout` | 既有 |
| 7 | `program_started == "false"` | `program_not_started` | warn | `program_started=false` | `V3-TARGET-SEMANTICS.md` |
| 8 | `input_processed == "false"` | `input_not_processed` | warn | `input_processed=false` | 同上 |
| 9 | `checkpoint_reached`（空则回落 `target_reached`）`== "false"` | `target_unreached` | warn | `setup_error` / `target_not_reached` | 同上 |
| 10 | 目标 `== "true"` 且 `coverage.delta > 0` | `progress` | info | `delta=N` | 同上 |
| 11 | 目标 `== "true"` 且无正增益 | `low_coverage` | info | `target_reached_without_measurable_gain` | 同上 |
| 12 | 配置已改（`planned` 有值）但 `status ∉ {effective, not_effective}` | `config_unverified` | warn | `loaded_config_sha256_unreported` | `V3-W2-CONFIG.md` §5.2 |
| 13 | `trials == 0` **且** `program_started != "true"` | `no_execution` | info | `no_execution_facts` | 本轮收紧 |
| 14 | 其余 | `coverage_unknown` | warn | `target_reached_unknown` | 收紧后的兜底 |

`DIAGNOSIS_CODES` **词表不变**（12 个码，一个不加、一个不减）。`cancelled` /
`budget_stopped` 不是新码，而是同一个码 `execution_error` 的两种可复核理由——
这样 `gold`（`w4-t09` 期望 `execution_error`）与判定层零改动。

### 1.1 终止态闸门的内部顺序

```
TERMINAL_FAULT_ORDER = ("cancelled", "budget_stopped", "error", "timeout")
TERMINAL_REASONS     = {"cancelled": "cancelled", "budget_stopped": "budget_stopped",
                        "error": "error:true", "timeout": "timeout"}
```

第一个命中的旗标赢，`reasons` 里只留它——**不并列、不合并**。理由拼写保留既有
词（`error:true` / `timeout`）以免动到既有复盘文档与 `gold` 的对照口径。

为什么 `budget_stopped` 排在 `timeout` 前面：快照层对 `stopped=="deadline"`
**同时**写 `timeout=true` 与 `budget_stopped=true`（`snapshot.py:_fill_fault`），
deadline 本质上就是预算（时间预算）用完；两条都成立时选对运维更有信息量的那条，
码不变。

### 1.2 实际会重叠的状态，各自的赢家

| 重叠 | 赢家 | 为什么 |
|---|---|---|
| `cancelled` + `budget_stopped` | `execution_error` / `cancelled` | 快照层二者互斥（一个 `stopped` 值）；仍给出确定顺序，防御性 |
| `budget_stopped` + `timeout`（deadline） | `execution_error` / `budget_stopped` | 见 §1.1 |
| `cancelled` + `error` | `execution_error` / `cancelled` | 取消是更上游的终止原因；码相同，只有理由不同 |
| `cancelled` + `candidates>0` | `candidate_observed` | 取消前已经出的候选是真观测，不能被“没跑完”抹掉（§5.8 R2） |
| `cancelled` + `trials==0` | `execution_error` / `cancelled` | “跑没跑完”比“没记录到试验”更硬（本轮重点用例） |
| `cancelled` + `config_status=not_effective` | `config_not_effective` | 输入被污染时，连“这轮有没有跑完”都不该拿来下结论 |
| `cancelled` + `program_started=false` | `execution_error` / `cancelled` | 取消导致的“没起来”是结果，不是独立诊断 |
| `trials==0` + `program_started=true` | `coverage_unknown` | 跑过但没有试验计数（报告路径没有 `SessionState`）→ 不能倒过来说“没执行” |
| `trials==0` + `checkpoint_reached=true` | `progress` / `low_coverage` | 正证据优先于“计数为零”；两者同时出现说明快照自相矛盾 |
| `candidates>0` + `config_status=not_effective` | `config_not_effective` | `V3-W2-CONFIG.md` §5.2 的既有口径，本轮不动 |

---

## 2. 四条不变量（为什么这样排，而不是别的排法）

| ID | 不变量 | 落点 | 反例（会误伤什么） |
|---|---|---|---|
| **I1** | **输入净化优先**：配置没生效 → 所有观测不可解释，连候选也不算 | 第 1 位 | 让候选顶掉 `config_not_effective`，`w4-t07` 类会从 blocked 降级成 info |
| **I2** | **正证据不被终止态抹掉**：已经发生的候选，取消/报错之后仍然算数 | 第 2 位 | 取消分支插到候选之前 → “取消前已出候选”被盖掉（§5.8 R2） |
| **I3** | **终止态只管“没跑完”，不管“跑过的东西”**：让所有**基于“没有”**的结论失效，而不是让所有结论失效 | 第 3-6 位 | 把“无 coverage 读数”也当 `execution_error` → §5.8 R1 实测 `correct 7→4` |
| **I4** | **缺失证据不冒充观测**：没观测到 ≠ 观测到 false；计数为零 ≠ 没执行 | 第 12-13 位 | `trials==0` 提前到 `config_unverified` 之前 → `w4-t07` 被降级；只认 `trials==0` 不看 `program_started` → 无观测手段组被误报 §5.3 |

---

## 3. 改动清单

### 3.1 业务代码（只动一处类）

`agent/platform/adaptive/session.py`：

| 行 | 改动 | 行数量级 |
|---|---|---|
| `440-472` | `DiagnoseRole` docstring：把“固定优先级”写成显式编号链 + 两条设计理由 | 文案 |
| `474-479` | 新增 `TERMINAL_FAULT_ORDER` / `TERMINAL_REASONS` 两个类常量 | +7 |
| `490-496` | `config_not_effective` 提到链首（原在 error/timeout 之后） | 移动 |
| `497-502` | `candidate_observed` 提到终止态之前（原在 config 之后） | 移动 |
| `503-508` | 终止态闸门：四旗标顺序判定，全部落 `execution_error`，理由区分 | +11（替换原 6 行 error/timeout） |
| `544-551` | `trials == 0` 去掉 `snapshot_status=="unknown"` 前置，加 `program_started != "true"` 守卫 | 1 行条件 |

`DIAGNOSIS_CODES` 词表、`Diagnosis` 结构、`SeedRole`、`propose()`、
`_facts_hash` **零改动**。

### 3.2 测试（`tests/`，允许改）

**新增** `tests/test_rule_diagnosis_priority.py`（13 个用例，全部离线零模型调用），
按 §1 的优先级表逐条对应：

| 组 | 用例 | 覆盖要求 |
|---|---|---|
| 1 | `test_priority_ladder_is_total_order` | 四旗标 15 种组合：只出一个码 + 赢家理由正确 |
| 2 | `test_cancelled_is_execution_error` | 取消；`false`/`unknown`/`None`/`""` 不被误判；`True` 与 `"true"` 等价 |
| 3 | `test_budget_stopped_is_execution_error` | 预算中止；deadline 形态；纯超时仍是 `timeout` |
| 4 | `test_zero_trials_is_no_execution_even_when_snapshot_is_ok` | 零执行；旧条件（`snapshot_status=unknown`）不回归；`program_started=true` 时回落 `coverage_unknown` |
| 5 | `test_zero_trials_with_cancelled_is_execution_error_not_no_execution` | **零执行且已取消**：只有一个结论 |
| 6 | `test_candidate_survives_terminal_state` | 5 种终止态下候选都不被抹掉 |
| 7 | `test_overlapping_states_never_produce_two_diagnoses` | 32 组旗标 × 2 计数 × 3 候选态的笛卡尔积：码在词表内、两次调用逐字段相同 |
| 8 | `test_unrelated_branches_are_unchanged` | config / 目标三段 / `setup_error` / `progress` / `low_coverage` / `config_unverified` 落点与理由不变 |
| 9 | `test_coverage_unknown_requires_trials_and_no_terminal_fault` | 兜底码的三条反例（零执行、终止态、目标命中） |

**更新** `tests/test_v3_week4_ab.py`（**只改规则臂期望值，不改夹具/`gold`/门禁**）：

| 用例 | 旧断言 | 新断言 | 理由 |
|---|---|---|---|
| 1 控制变量 | `w4-t08/t09 → coverage_unknown`，`correct=False` | `w4-t08 → no_execution`、`w4-t09 → execution_error`，`correct=True` | 两处盲区正是本轮修的，旧断言是在锁死缺陷 |
| 2 成功/增益 | 冻结集 `rules 8 / model 10`，门禁打开 | 改用 `_rules_miss_tasks()`（规则臂结构性答不对的两条任务：`gold=no_signal`）→ `rules 0 / model 2`，门禁打开 | 冻结集上规则臂已 10/10，模型最多追平，**无法**再演示增益（§6） |
| 2 新增 | — | `test_frozen_regression_set_no_longer_shows_stable_gain`：`10/10`、两侧增益 0、`reasons==["stable_gain"]` | 把“修好 A 臂 → 门禁变红”写成断言，而不是把门禁调松 |
| 3 无稳定收益 | `rules_diag` 里 `t08/t09=coverage_unknown`；`{rules:8, model:8}` | `t08=no_execution`、`t09=execution_error`；`{rules:10, model:10}` | 同上 |
| 4 无建议 | `correct.rules == 8` | `== 10` | 同上 |
| 6 错误采纳 | `wrong_adoptions == {rules:3, model:1}`；`reasons==["no_model_wrong_adoption"]` | `{rules:1, model:1}`；`["no_model_wrong_adoption","stable_gain"]` | 规则臂只剩 `w4-t03` 一条；`stable_gain` 因 A 臂答满而结构性为 0（§6） |
| 8 确定性 | markdown 里 `stable_gain 通过`、`正确诊断数 8 | 10` | 冻结集断言 `未通过` / `10 | 10`，另用 `_rules_miss_tasks()` 覆盖“通过”这条渲染路径 | 同上；渲染覆盖率不下降 |

### 3.3 明确没动的

`compare.py`（`_ab_judge` / `_ab_fact_keys` / `_ab_gate` / `ab_regression_tasks`）、
`real_ab.py`、`llm_provider.py`、`fixtures/`、10 条 fixture 的 `gold`/`forbid`、
`controls.budget`/`human_rules`、`stable_gain` 与其余门禁阈值、`vulnmap_platform/`
（web 静态页）。本文所有数字都可从 `experiments/rule-regression/*.json` 复算。

---

## 4. 冻结回归集：规则臂前后指标

口径：`run_ab(provider=None)` → **B 臂每次调用都不发生**（每任务 `environment_error`），
A 臂同回归集、同预算（`max_rounds=2 / max_calls=24 / max_tokens=50000 / max_usd=0.03`）、
同初始配置（`{}`）、同人工规则（默认值）。三个控制 sha256 与上一轮复盘逐字节相同：

| 控制变量 | 值 | 与 `ab-error-review.json` |
|---|---|---|
| `regression_set_sha256` | `5a14d283…52ea` | ✅ 相同（未改夹具） |
| `initial_config.sha256` | `44136fa3…ff8a` | ✅ 相同 |
| `controls.digest` | `ed77f668…a29f` | ✅ 相同 |

### 4.1 主指标

| 指标 | 改前（`before.json`） | 改后（`after.json`） | Δ | §5.5 目标 |
|---|---|---|---|---|
| `answered` | 9 | 9 | — | ==9 ✅ |
| `correct` | **7** | **9** | **+2** | ==9 ✅ |
| `wrong_adoptions` | **3** | **1** | **−2** | ==1 ✅ |
| `adopted` | 7 | 6 | −1 | 不作阈值（`t09` 空计划，§5.8 R4） |
| `invalid_retries` | 4 | 4 | — | ==4 ✅ |
| `action_recall_mean` | 0.375 | 0.375 | 0.0 | ≥0.375 ✅（没用空计划换分） |
| `calls` / `tokens` / `usd` | 0 / 0 / 0.0 | 0 / 0 / 0.0 | — | 0 ✅ |
| `retained` | `budget_exhausted=[w4-t04]` | 同 | — | 集合不变 ✅ |
| 分层 `rules_correct`（even/odd） | 4 / 3 | 5 / 4 | +1 / +1 | — |

剩余那 1 次错误采纳：`w4-t03`，`input_not_processed` + 模板无条件带 `run_epoch`
（`gold.forbid` 明令禁止）。这是 §5.3 里排队的“第二个变量（动作侧 guard）”，本轮不动。

### 4.2 逐任务 diff：只允许两行变化（实测就是两行）

| 任务 | 改前 | 改后 |
|---|---|---|
| `w4-t08`（`trials=0`，快照 `ok`） | `coverage_unknown` / `wrong=diagnosis_mismatch` / `correct=False` | `no_execution` / `wrong=[]` / `correct=True` / 动作不变 |
| `w4-t09`（`fault.cancelled=true`） | `coverage_unknown` / `["diagnosis_mismatch","forbidden_action:run_epoch"]` / `correct=False` | `execution_error` / `wrong=[]` / `adopted=0` / `correct=True` |
| 其余 8 条（含 `t04` 的 `budget_exhausted`、`t01` 的 `no_execution`） | — | **`(diagnosis, actions, wrong_reasons, invalid_retries)` 逐字段不变** |

### 4.3 验收判定（`diff.json` 的 14 条，全绿）

`correct_7_to_9`、`wrong_adoption_3_to_1`、`remaining_wrong_only_t03_forbidden`、
`only_t08_t09_changed`、`invalid_retries_unchanged_4`、`answered_unchanged_9`、
`retained_unchanged`、三个 `control_*_unchanged`、`controls_frozen`、
`rules_zero_cost`、`no_model_calls`、`action_recall_not_lowered` → `verdict=accept`。

### 4.4 确定性

同一份代码连跑两次 `run_rules_arm.py`，`after.json` 逐字节相同
（`cmp` 通过）；产物里不含 `elapsed_seconds` 等墙钟量，只有诊断码/动作/计数/摘要。

---

## 5. 预期 vs 实测（含一处真实偏差）

### 5.1 `AB-ERROR-REVIEW.md` §5.4 的预测

| 项 | §5.4 预测 | 本轮实测 | 结论 |
|---|---|---|---|
| `correct` | 9 | 9 | ✅ |
| `wrong_adoption` | 1（只剩 `t03 forbidden_action`） | 1（`t03`） | ✅ |
| `adopted` | 6 | 6 | ✅ |
| `invalid_retries` | 4 | 4 | ✅ |
| `action_recall_mean` | 0.375 | 0.375 | ✅ |
| 变化行 | 只 `t08`/`t09` | 只 `t08`/`t09` | ✅ |

### 5.2 与 §5.2 挂点表的差异（**本轮有意加严，需记账**）

§5.2 只要求“`cancelled`/`budget_stopped` → `execution_error`”，并把插入点定在
`candidate_observed` 之后。本轮按“优先级链”要求补了两件事：

1. 四旗标之间给出**确定顺序**（§1.1），而不再是“谁先写谁赢”；
2. 把 `error`/`timeout` 也并入同一个闸门——否则 `cancelled`+`error` 会由
   `error:true` 抢先，与“`cancelled > budget_stopped > execution_error`”的
   要求不符。

副作用（已核实，冻结集内**零**影响）：`error`/`timeout` 与 `config_not_effective`、
`candidates>0` 的相对位置发生了变化——见 §7.1。冻结回归集里没有任何一条任务同时
带 `error/timeout` 与 `candidates>0` 或 `not_effective`（`w4-t05` 只有 `error`，
`w4-t07` 只有 `config`），所以 §4.2 的两行结论不受影响。

### 5.3 实现过程中发现的一处**真实冲突**（不记账就会误伤）

按 §5.1 的字面规格（`trials==0` → `no_execution`，去掉 `snapshot_status=="unknown"`）
实现后，`tests/test_v3_target_semantics.py` 立刻红了 2 条：

| 用例 | 现象 | 根因 |
|---|---|---|
| `test_three_reports_are_distinct` | “无观测手段”组从 `coverage_unknown` 变成 `no_execution` | 报告路径 `ContextRole().observe(snapshot)` **没有** `SessionState`，`Observation.trials` 恒 `0`；而该组 `program_started="true"`（程序真的跑过，只是没有输入/检查点探针） |
| `test_blind_report_says_unknown_not_false` | `reasons[0]` 从 `target_reached_unknown` 变成 `no_execution_facts` | 同上 |

处理：把零执行条件收紧为 **`trials == 0` ∧ `program_started != "true"`**。
`gold`/fixture/门禁都没动，冻结集指标也不变（`w4-t08` 的 `program_started` 是
`unknown`，仍走 `no_execution`）。这条守卫的语义是：**`trials` 是计数，不是观测**；
它为零只能说明“没记到试验”，不能推翻“程序确实起来过”这种显式观测。
（顺带印证 §4 E7：`trials` / `snapshot_status` 不参与 `facts_hash`，本身也不该
单独承担判定。）

---

## 6. 门禁：为什么它变红，以及本轮为什么不修

| 检查 | 改后 | 说明 |
|---|---|---|
| `no_model_wrong_adoption` | 取决于 B 臂 | 本轮 B 臂不跑（`provider=None`），不比较 |
| `answered_coverage` | ✅ 0.9 | — |
| `no_task_regression` | ✅（冻结集上规则臂不再有“对→错”的反向行） | — |
| `stable_gain` | ❌（even 5−4=+1 对规则侧，但 `model−rules`：模型最多追平 → 0） | `gain = model_correct − rules_correct`（`compare.py:1937-1944`） |
| `read_only_real_provider` / `engine_available` | ✅ | — |

`stable_gain` 用的是“模型能否**超过**规则”，而本轮把规则修好了，所以：

- 在 10 条冻结任务上，`rules=10`、`model` 最好也只能 10 → 两个分层增益都是 0；
- 因此 `stable_gain` 从“规则 8 / 模型 10 时通过”变成“恒不通过”。

这不是质量回退，而是门禁**语义**问题（`AB-ERROR-REVIEW.md` §5.6 已登记：同一道门
同时承担“质量回归”和“换源收益”两个角色）。本轮按约束**不碰门禁**，只做两件事：

1. `test_frozen_regression_set_no_longer_shows_stable_gain` 把“追平 → 门禁红”写成断言；
2. 增益/门禁通过的渲染路径改用 `_rules_miss_tasks()`（`gold=no_signal`，规则臂
   结构性答不对）继续覆盖，避免测试因为“A 臂变好”而失去覆盖面。

---

## 7. 与既有文档的关系（两处 supersede + 一处不变）

### 7.1 `docs/V3-W2-CONFIG.md` §5.2 的插入位置（**已 supersede**）

| | 旧链 | 新链 |
|---|---|---|
| 前三位 | `execution_error → config_not_effective → candidate_observed` | `config_not_effective → candidate_observed → execution_error` |

理由：§1 的 I2（候选不被终止态抹掉）与 §5.2 的“`not_effective` 推翻候选”同时成立时，
只有“配置 → 候选 → 终止态”这一种排法能同时满足两者。影响面被压到最小：

- `not_effective` 与候选的相对位置**没变**（仍是 config 在前，§5.2 原意保留）；
- `error`/`timeout` 与候选/配置的相对位置变了——但冻结集与现有单测里没有这种
  组合（§5.2 实测），且三者的 `severity` 都是 `blocked`、`propose()` 都产空计划
  （`session.py:829-833`），动作侧零差异。

### 7.2 `docs/AB-ERROR-REVIEW.md` §5.1 的改进规格（**已落地，并加严**）

规格原句：“`fault.cancelled=true` / `fault.budget_stopped=true` → 强制
`execution_error`；`trials==0` → 强制 `no_execution`”。落地情况：

- 前半句：落地为**终止态闸门**，并补上四旗标的确定顺序（§1.1）；
- 后半句：落地为 `trials==0 ∧ program_started != "true"`（§5.3 的守卫）；
- `coverage_unknown` 兜底分支**一字未改**，改完自动等价于
  “`trials>0` ∧ 无终止态 ∧ 目标态未知”，与码注释自洽。

### 7.3 `docs/V3-TARGET-SEMANTICS.md`（**不变，且是本轮的硬约束**）

“无观测手段 → `coverage_unknown`，报告里是 unknown 不是 false”这条本轮被 §5.3 的
守卫保住；目标三段的判定顺序与理由拼写一字未动。

---

## 8. 复现清单

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 规则臂冻结回归（零模型调用）：改前 / 改后
#    改前需要 session.py 的旧版（本仓库无 git；旧逻辑见 docs/AB-ERROR-REVIEW.md §5.2）
python3 experiments/rule-regression/run_rules_arm.py \
    --out experiments/rule-regression/before.json --label before
python3 experiments/rule-regression/run_rules_arm.py \
    --out experiments/rule-regression/after.json  --label after

# 2) 前后对比 + 14 条验收判定（verdict 必须是 accept）
python3 experiments/rule-regression/compare_regression.py

# 3) 优先级规则单测（13 例）
python3 -m pytest tests/test_rule_diagnosis_priority.py -q

# 4) 受影响的口径测试
python3 -m pytest tests/test_v3_week4_ab.py tests/test_v3_target_semantics.py \
                 tests/test_v3_week2_config.py tests/test_v3_p2_session.py -q

# 5) 确定性：连跑两次逐字节相同
python3 experiments/rule-regression/run_rules_arm.py --out /tmp/a1.json --label after
python3 experiments/rule-regression/run_rules_arm.py --out /tmp/a2.json --label after
cmp /tmp/a1.json /tmp/a2.json && echo deterministic
```

| 复核项 | 结论 |
|---|---|
| 冻结回归 `verdict` | ✅ `accept`（14/14） |
| 逐任务 diff 只两行 | ✅ `w4-t08`、`w4-t09` |
| 三个控制 sha256 未漂移 | ✅ 与 `ab-error-review.json` 相同 |
| 规则臂成本 | ✅ `calls=tokens=usd=0` |
| 夹具 / `gold` / `forbid` / 门禁 | ✅ 零改动 |
| 全量测试 | 1541 passed / 8 skipped / **17 failed**；17 条全部是 `tests/test_platform*.py` 的**静态页面外壳**断言（`index.html` 缺 `renderShell(` / `stat-keys` / `platform-tasks.html`）。判定为既有红：本轮改动文件只有 §3 列出的那些，`vulnmap_platform/static/` 未落一笔，且这些测试不 import `adaptive.session` / `compare`（`grep -l 'DiagnoseRole|adaptive.session' tests/test_platform*.py` 无命中） |

---

## 9. 明确不做 / 已知未覆盖

| ID | 事项 | 为什么本轮不做 |
|---|---|---|
| N1 | `w4-t03` 的 `run_epoch` 越权（动作侧 guard） | §5.3 排队的**第二个变量**；同期改就不是单变量 |
| N2 | `stable_gain` 拆成“质量回归”与“换源收益”两道门 | 改门禁；只登记（§6） |
| N3 | `retained.budget_exhausted` 无臂标签（E9）、`status≠ok` 清零 `wrong_reasons`（E5） | 判定层（`compare.py`）问题，禁改 |
| N4 | `_AB_FACT_KEYS` 不含 `trials`/`snapshot_status`（E7） | 判定层；本轮不依赖“事实变没变”判据 |
| N5 | `no_signal` 在词表里有、在规则里**没有分支**（`DiagnoseRole` 从不产出它） | 属 E1 的码语义重叠，需要单独一轮定口径；本轮只在测试里把它当作“规则结构性缺口”的构造点 |
| N6 | 多轮 `t09` 变体：`execution_error` 不在 `propose()` 的 miss 元组（`session.py:792-795`）→ 取消后 `attempt` 不递增 | §5.8 R5 已登记的二阶效应；冻结集 `t09` 单轮，零影响 |
| N7 | `coverage.status`（`unsupported`/`complete`/`unknown`）尚未参与任何分支 | 本轮只按 `trials` + 目标三态判定；若将来要区分“没探针”与“没跑”，入口应在这里（而非再加一个布尔） |
| N8 | `fault.outcome`（`no_repro` / `timeout` / `failed`…）未参与判定 | 现有 `gold` 用 `execution_error` 覆盖“报错/超时”，`outcome` 目前只进 `facts_hash` |

---

## 10. 一句话总结

**优先级不是“谁先写谁赢”，而是一条可复核的链**：先把“事实能不能算数”判掉
（配置没生效），再保“已经发生的正证据”（候选），再判“跑没跑完”（取消 > 预算中止 >
报错 > 超时，同码不同理由），最后才在“目标三段 / 覆盖增益 / 零执行 / 覆盖未知”
之间落子。冻结回归集上这一条链把规则臂的 `correct` 从 7 提到 9、错误采纳从 3 降到 1，
且逐任务只动了两行——而 `stable_gain` 变红是它的**必然结果**，不是本轮的失败。
