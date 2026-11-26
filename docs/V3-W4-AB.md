# V3 第 4 周：规则 vs 模型只读建议的 A/B 对照与建议门禁（V3-020）

对应《VULNMAP-V3 完整升级方案》§4「双循环与状态模型」、§8「实验自修改与版本事务」、
§12「独立验证」与 §18.1 门禁；前置为第 3 周的执行证据交接
（[V3-W3-HANDOFF.md](V3-W3-HANDOFF.md)）与 P4b 的五指标对照
（[V3-P4-REPORT-COMPARE.md](V3-P4-REPORT-COMPARE.md)）。

第 3 周把“执行证据”做成了可复核的交接链，但**谁来决定下一步做什么**仍只有一条路：
`adaptive.session.DiagnoseRole` 的固定优先级规则。第 4 周补的是“拿模型建议跟这套规则
放在同一张表上比”的最小框架，并且**只在能证明它更好的时候**才允许它成为默认建议源。

这一周只做五件事，全部在“事后记账 + 离线对照”这一侧：

1. **对照框架**：同一回归集、同一初始配置、同一预算、同一人工规则下跑两臂
   （A=现有规则，B=模型只读建议），见 §1。
2. **七项指标**：正确诊断数/总任务、无效重试、耗时、模型调用/tokens/费用、错误采纳数，
   外加四条**保留类**（环境错误 / 无建议 / 建议被拒 / 预算耗尽），见 §2。
3. **建议门禁**：错误采纳 > 0 或模型无**稳定**收益 → 默认规则；`auto_apply` 恒为
   `False`，模型建议永不自动应用，见 §3。
4. **测试**：`tests/test_v3_week4_ab.py`，8 组用例覆盖成功/失败/无建议/预算耗尽/
   错误采纳/建议被拒/环境错误/确定性，见 §6。
5. **文档**：本文。

边界一句话：**没有新增任何运行期能力**。`run_ab()` 不跑目标、不执行工具、不写库、
不调外部服务；两臂都只消费调用方给的观测与 provider 返回值。`verify.py` /
`benchmark_policy` / 执行器 / DB schema / 写端点 / `adaptive/controller.py` 一个字没改。

---

## 0. 实施清单

| 项 | 状态 | 验收口径 | 落点 | tests |
|---|---|---|---|---|
| W4-1 两臂同一份输入 | 已实施 | 回归集 / 初始配置 / 预算 / 人工规则只定义一次；两臂摘要逐字相同（`arms_share_controls=true`）；指标行顺序 == `AB_METRICS` | `compare.py`（`run_ab` / `_ab_controls`） | `test_ab_arms_share_regression_set_config_budget_and_rules` |
| W4-2 A 臂就是现有规则 | 已实施 | A 臂延迟导入 `adaptive.session.DiagnoseRole` + `ResearchSession.propose`，诊断码/动作都来自真实实现（不抄一份规则表） | `compare.py`（`_ab_engine` / `_ab_rules_task`） | 同上（断言 `w4-t08/t09` 的规则输出是 `coverage_unknown`） |
| W4-3 B 臂只读且离线 | 已实施 | 建议逐条过 `Registry.get()` + `spec.validate()` + 裁决字段剥离；`provider.offline is True` 是硬门，否则整臂环境错误、**一次都不调用** | `compare.py`（`_ab_validate_suggestion` / `FakeProvider`） | `test_ab_rejected_and_environment_errors_are_retained` |
| W4-4 七项指标 | 已实施 | 七行固定顺序；未知一律 `null`+`known=false`+`reason`（费用无价格表就是未知，不填 0） | `compare.py`（`_ab_metric_row` / `_ab_summary`） | `test_ab_stable_gain_opens_gate_but_never_auto_applies` |
| W4-5 四条保留类 | 已实施 | 环境错误/无建议/被拒/预算耗尽按 task 列进 `summary.retained`，且 `correct=None` **不进分母** | 同上 | `test_ab_no_suggestion_is_retained_not_counted_as_wrong` / `test_ab_budget_exhaustion_is_retained` |
| W4-6 错误采纳一票否决 | 已实施 | `wrong_adoptions>0` → `gate.reasons` 只留 `no_model_wrong_adoption`，默认规则 | `compare.py`（`_ab_judge` / `_ab_gate`） | `test_ab_wrong_adoption_blocks_gate` |
| W4-7 稳定收益判定 | 已实施 | 只答“没有错误采纳 + 覆盖够 + **每个分层都有严格增益**”才算稳定；否则默认规则 | `_ab_gate` + `_ab_summary.strata` | `test_ab_model_without_stable_gain_defaults_to_rules` |
| W4-8 永不自动应用 | 已实施 | `gate.auto_apply` 恒 `False`；人工规则写 `allow_auto_apply=true` 也被拒并记 blocker；应用仍走 `handoff.ProposalGate`（本次恒 `advisory`） | `_ab_gate` | `test_ab_stable_gain_opens_gate_but_never_auto_applies` / `test_ab_document_is_deterministic_and_never_claims_verdict` |
| W4-9 不产裁决 | 已实施 | `verdict` 恒 `"not_evaluated"`；整份文档不出现 `"verified": true` / `confirmed` | `run_ab` | `test_ab_document_is_deterministic_and_never_claims_verdict` |
| W4-10 确定性 | 已实施 | 同一输入两次运行 `json.dumps(sort_keys=True)` 逐字节相同（耗时用注入 `FakeClock`） | `run_ab` / `FakeClock` | 同上 |

改动边界：

| 文件 | 变化 |
|---|---|
| `agent/platform/adaptive/compare.py` | 追加 W4 段：`AB_*` 常量、`ABError`、`ab_task` / `ab_regression_tasks` / `FakeProvider` / `FakeClock` / `run_ab` / `render_ab_markdown` + 私有辅助（`_ab_engine` / `_ab_rules_task` / `_ab_model_task` / `_ab_judge` / `_ab_summary` / `_ab_gate` / `_ab_controls`）。P4b 的 `build_compare` / `compare_arms` / `render_markdown` **未改一行** |
| `tests/test_v3_week4_ab.py` | 新增。8 组用例，全部离线 |
| `docs/V3-W4-AB.md` | 本文 |

**未改**：`verify.py`、`benchmark_policy`、`adaptive/controller.py`、`adaptive/policy.py`、
`adaptive/session.py`、`adaptive/tools.py`、`adaptive/handoff.py`、`store.py` schema、
任何写端点。

---

## 1. 对照框架：同一份输入，两条决策路径

### 1.1 两臂定义

| 臂 | 是什么 | 事实来源 | 能不能写 |
|---|---|---|---|
| **A `rules`** | 现有确定性规则：`DiagnoseRole.diagnose()` 给诊断码，`ResearchSession.propose()` 给动作计划 | 真实现（延迟导入，不抄规则表） | 只产记录；不写盘、不执行 |
| **B `model`** | 模型**只读建议**：调用方注入的 provider 给「诊断码 + 动作建议」，逐条过闸 | provider 返回值（`FakeProvider` 或任何 `offline=True` 的实现） | **永不能写**：通过闸也只进建议清单 |

B 臂的每条建议都要过三道闸（`_ab_validate_suggestion`）：

1. **诊断码**：必须落在 `adaptive.session.DIAGNOSIS_CODES` 里，否则 `invalid_diagnosis:<code>`；
2. **工具与参数**：`Registry.get(name)`（未注册 → `ActionRejected`）+ `spec.allowed_modes`
   + `spec.validate(params)`——与 A 臂同一份工具 schema，没有第二套口径；
3. **裁决字段**：`policy.prune_verdict_fields(params)`，夹带 `verified/confirmed/verdict/...`
   的建议整体丢掉（`action[i]:verdict_fields:...`），**不剥干净再用**。

过不了闸的进 `record.rejected`，**不采纳**；一条可用诊断码或动作都没有 → 该任务状态
`rejected`（有原因）或 `no_suggestion`（什么都没给）。

### 1.2 为什么 B 臂必须离线（硬门）

`run_ab()` 只认 `provider.offline is True` 的对象：

| provider 情况 | 结果 |
|---|---|
| `FakeProvider(...)`（`offline=True`） | 正常跑；脚本外的 task 一律回 `{"status": "no_suggestion"}` |
| 任何没声明 `offline=True` 的对象 | **一次都不调用**；整臂每任务记 `environment_error`（`provider_not_offline`）；门禁 `offline_provider` 不通过 |
| provider 抛异常 | 该任务 `environment_error`（异常类型进 `record.error`），后续任务继续跑 |
| provider 返回非 mapping | 该任务 `environment_error`（`provider_returned_non_mapping`），调用次数照记 |

这条门是“禁止真实 key”的机械落点：框架本身不建 client、不读环境变量、不 import 任何
网络库；只有调用方显式塞一个自称离线的 provider 才跑得起来，而测试与文档里的 provider
全部是 `FakeProvider`（脚本化、确定性、`tokens/usd` 是构造参数）。

> `FakeProvider` 的 `usd=0.0025/次`、`tokens_in=900 / tokens_out=150` 是**构造参数**，
> 不是真实账单；文档里所有金额都标注为 fake 单价。

### 1.3 控制变量（`controls`）

```python
controls = {
  "regression_set": [task_id, ...],          # 顺序即分层依据
  "regression_set_sha256": sha256(任务三件套),
  "initial_config": {"keys": [...], "sha256": sha256(config)},
  "budget": {...}, "human_rules": {...},
  "digest": sha256(上面全部),
  "arms": {"rules": digest, "model": digest},
  "arms_share_controls": True,
}
```

两臂**没有各自的一份**：`digest` 算一次，两臂抄同一份。`arms_share_controls` 是
“两臂摘要相等”的判定结果，不是口号——想造出“两臂预算不同”的对照，只能改框架本身。

`budget` 四项（默认见 `AB_DEFAULT_BUDGET`）：`max_rounds`（单任务轮数上限）、
`max_calls`（全局模型调用上限）、`max_tokens`、`max_usd`；四项都按
“`<= 0` 表示不限”解释（默认值全是正数，所以默认是**限**的）。

`human_rules` 六项（默认见 `AB_DEFAULT_RULES`）：

| 键 | 默认 | 作用 |
|---|---|---|
| `require_no_wrong_adoption` | `true` | 错误采纳一票否决 |
| `min_answered_ratio` | `0.8` | 模型至少要答完这么多任务，否则覆盖不够 |
| `require_stable_gain` | `true` | 要求“每个分层都有严格增益” |
| `allow_auto_apply` | `false` | **永远是 false**：写 true 会被框架拒绝并记 blocker |
| `max_suggestions_per_round` | `1` | 与 `ResearchSession._with_advisor` 的“每轮最多一条”对齐 |
| `adoption_policy` | `counterfactual` | 采纳是**反事实记账**（见 §2.5），不是真写 |

---

## 2. 七项指标与四条保留类

### 2.1 指标表

| 指标 | 事实来源 | 公式 / 规则 | 方向 |
|---|---|---|---|
| `correct_diagnoses` | 两臂每任务**最后一轮**的诊断码 vs `gold.diagnosis` | 只在 `status="ok"`（答完全部轮次）时计入；`answered` 是分母，`tasks_total` 是总任务数 | 越高越好 |
| `invalid_retries` | 每任务逐轮的**事实指纹**（`_AB_FACT_KEYS`） | 第 2..n 轮里 `facts_hash` 与上一轮相同 → 计一次“无效重试”（重跑没有新事实） | 越低越好 |
| `elapsed_seconds` | 注入的 `clock()` | 每任务 `end - start` 求和；默认 `perf_counter`，测试用 `FakeClock(0.01)` | 越低越好 |
| `model_calls` | provider 实际被调用次数 | 每轮一次；`no_suggestion` / 已发生的调用都计数 | 越低越好 |
| `model_tokens` | provider 返回的 `usage.tokens_in + tokens_out` | 拿不到就是 0 计数（不编造），但金额会转成“未知” | 越低越好 |
| `model_usd` | provider 返回的 `usd`（或 `usage.usd`） | 任一次调用没有价格 → 整臂 `usd=null` + `reason="model_unknown"`（**不是 0 元**） | 越低越好 |
| `wrong_adoptions` | `_ab_judge` | 采纳了但：诊断 ≠ gold，或提了 gold 明令 `forbid` 的动作，或提了 gold 没允许的**执行类**动作 | 越低越好 |

“执行类动作”= `run_epoch / replay_input / finish_research`；`get_task_facts /
get_execution_facts / read_source_window / compare_trials / propose_seed_spec /
materialize_seeds / set_dictionary` 属于**规划类**，采纳它们不判错（它们不改执行、
不写结论）。这条切分的理由是“错在动手，不在多看两眼”。

### 2.2 正确诊断数 / 总任务

- 字面形状：`summary.correct_over_total[arm] = {"correct", "total", "ratio"}`
  （理想 provider：规则 `8/10 = 0.8`、模型 `10/10 = 1.0`）；
- `accuracy` 分母是 `answered`（答了才谈准不准），`correct_over_total.ratio` 分母是
  `tasks_total`（覆盖多少任务）——两个数都在，谁也不能替谁；
- 状态不是 `ok` 的任务 `correct=None`——**没答不算答错**，也不进准确率分母；
- `gold` 由**人工规则**给（回归集里写死），不是拿 A 臂输出当答案——否则 A 臂恒 100%，
  对照就没有意义。

### 2.3 无效重试：用事实指纹，不用“第几次”

`facts_hash` 只覆盖进展事实（与 `ContextRole._facts_hash` 同口径的键集合）：
`program_started / input_processed / checkpoint_reached / target_reached / coverage /
candidates / fault / config / input_facts`。**轮数、试验次数、执行 id、耗时都不在指纹里**，
所以“同一条反馈再跑一遍”会被认出来，而“换了一次配置”不会。

### 2.4 模型调用 / tokens / 费用：结算时机写在明处

- 调用**前**只判 `max_calls`（可数）；
- tokens / usd 只有 provider 自己知道，所以按**调用后结算**判耗尽（与 `llm_gateway`
  的 reserve→settle 同构）：超了就本轮任务记 `budget_exhausted`，其后任务也记
  `budget_exhausted` 并停止调用；
- 费用没有价格表时是**未知**，不是 0：`_ab_usage` 拿不到数字就把 `usd_known=False`
  一路带到聚合（`summary.cost.usd_known`）。

### 2.5 错误采纳：反事实记账

`adoption_policy="counterfactual"`：框架**不写工作副本**，只记“如果这条建议被采纳，
它错没错”。所以：

- `adopted` = 该臂这一轮真的提了动作（空计划不算采纳）；
- `wrong_adoption` ∈ {0,1} 每任务每臂，`wrong_reasons` 给具体原因
  （`diagnosis_mismatch` / `forbidden_action:run_epoch` / `unexpected_action:...`）；
- A 臂同样记账：规则在 `input_not_processed` 下原样 `run_epoch` 也是错误采纳
  （回归集里 gold 明确 `forbid` 了它）——两臂用同一把尺子。

### 2.6 四条保留类（`summary.retained`）

| 状态 | 触发 | 记录 | 后果 |
|---|---|---|---|
| `environment_error` | provider 抛异常 / 返回非 mapping / 未声明离线 / 规则引擎导入失败 | 该 task 进 `retained.environment_error`，`error` 带异常类型 | `correct=None`，不进分母；门禁 `answered_coverage` 受影响 |
| `no_suggestion` | provider 没给可用诊断码也没给动作（含脚本缺失） | `retained.no_suggestion` | 同上（**不判成答错**） |
| `rejected` | 诊断码不认识 / 工具不存在 / 参数过不了 schema / 夹带裁决字段且**没有任何可用部分** | `retained.rejected` + `record.rejected` 原因列表 | 同上 |
| `budget_exhausted` | `max_rounds` / `max_calls` / `max_tokens` / `max_usd` 任一触顶，或 provider 自报 | `retained.budget_exhausted` | 同上；已发生的调用照记账 |

“保留”的具体含义：**一条都不删、不折算、不并进答错**。分母里它缺席，账单里它在场。

---

## 3. 建议门禁

### 3.1 六项检查

| 检查 | 通过条件 | 不通过时的后果 |
|---|---|---|
| `no_model_wrong_adoption` | 模型 `wrong_adoptions == 0` | **一票否决**：不再看收益，直接默认规则 |
| `answered_coverage` | `answered.model / tasks_total >= min_answered_ratio`（默认 0.8） | 默认规则（答不完就没有可比性） |
| `no_task_regression` | 不存在“规则答对而模型答错”的任务 | 默认规则（不拿整体收益抵单个任务的退步） |
| `stable_gain` | **每个分层**（偶数位 / 奇数位任务）的 `gain = model_correct - rules_correct > 0` | 默认规则（“总分高”也可能是单层侥幸） |
| `offline_provider` | `provider.offline is True` | 默认规则（真实 key 一律不进场） |
| `engine_available` | 规则引擎可导入 | 默认规则（没有 A 臂就没有对照） |

全通过 → `gate.default_arm="model"`、`model_advisory_allowed=true`；否则
`gate.default_arm="rules"`、`model_advisory_allowed=false`，`reasons` 列出未通过项。

### 3.2 `auto_apply` 恒为 `False`

```python
auto_apply = False        # 无分支、无开关
```

`gate.auto_apply_blockers` 只有两个来源：

- `proposal_gate:advisory`——`handoff.ProposalGate().admit(scope="engineering",
  action="model_suggestion")` 的判定结果原样放进 `gate.proposal_gate`；未验收（隔离/授权）
  时它恒是 `advisory`，`applied=False`；
- `human_rule:allow_auto_apply=true 被框架拒绝`——只有调用方**显式**写
  `allow_auto_apply=true` 时才出现，且**不改变** `auto_apply`（这是“拒绝”，不是“接受”）。

所以门禁通过只说明一件事：**下一轮默认建议源换成模型**。写权限一点没动，落盘仍要过
`ProposalGate` 的两项验收（第 3 周的口径）。

### 3.3 语义边界

| 门禁通过 | 门禁不通过 |
|---|---|
| 控制器下一轮**默认采用**模型建议（仍只进建议清单，`advisory`） | 控制器继续用现有规则；模型建议**不进入**下一轮 |
| 不写库、不 stage、不建 revision、不写 adoption | 同左 |
| `verdict` 仍是 `not_evaluated` | 同左 |

---

## 4. 回归集：10 条任务，gold 由人工规则给

`ab_regression_tasks()` 是**静态夹具**（不是随机生成），10 条任务覆盖 10 个诊断码：

| task | 轮数 | 观测要点 | gold 诊断 | gold 动作 | 规则臂答对？ |
|---|---|---|---|---|---|
| `w4-t01` | 1 | `trials=0`、快照未采集 | `no_execution` | `run_epoch`、`get_task_facts` | ✅ |
| `w4-t02` | 1 | `program_started=false` | `program_not_started` | `get_execution_facts`、`run_epoch` | ✅ |
| `w4-t03` | 2 | 两轮都 `input_processed=false`（第 2 轮无新事实） | `input_not_processed` | 换种子四件套，`forbid: run_epoch` | ✅（但错误采纳 1） |
| `w4-t04` | 3 | 前两轮未命中（同事实），第 3 轮 `candidates=2` | `candidate_observed` | `finish_research`、`get_execution_facts`，`forbid: run_epoch` | ✅ |
| `w4-t05` | 1 | `fault.error=true` | `execution_error` | 读事实两件，`forbid: run_epoch` | ✅ |
| `w4-t06` | 2 | 两轮 `coverage.delta=0.5`（第 2 轮无新事实） | `progress` | `run_epoch`、`compare_trials` | ✅ |
| `w4-t07` | 1 | `config.status=not_effective` | `config_not_effective` | `get_task_facts`、`read_source_window`，`forbid: run_epoch` | ✅ |
| `w4-t08` | 2 | `trials=0` 但快照已采集（`snapshot_status="ok"`） | `no_execution` | `run_epoch`、`get_task_facts` | ❌ `coverage_unknown` |
| `w4-t09` | 1 | `fault.cancelled="true"` | `execution_error` | 读事实 + `finish_research`，`forbid: run_epoch` | ❌ `coverage_unknown` |
| `w4-t10` | 1 | 命中但 `coverage.delta=0.0` | `low_coverage` | 换种子 + `run_epoch` | ✅ |

### 4.1 两个规则盲区（gold 与 A 臂不同的地方，逐字段写明）

**`w4-t08`**：`DiagnoseRole` 的 `no_execution` 分支条件写的是
`trials == 0 and snapshot_status == UNKNOWN`；当快照**采到了**（`snapshot_status="ok"`）
但一次执行都没有时，规则会一路落到 `coverage_unknown`。人工规则认为“零执行事实”就是
`no_execution`（码自己的注释：`还没有任何执行事实`），所以 gold 取 `no_execution`。

**`w4-t09`**：`fault.cancelled` / `fault.budget_stopped` 不在诊断规则里。执行被取消时
规则给 `coverage_unknown`，但这会被下游误读成“跑过了、覆盖不明”；人工规则取
`execution_error`（**没跑完不能记成 no_repro，也不能记成覆盖未知**）。

这两个盲区是本轮 A/B 唯一能产生“模型有增益”的地方——也就是说，**A 臂 8/10 已经是对
现有规则的如实计分**，不是把规则写弱了来衬托模型。想改 gold 就先改这两段的理由，
让 A/B 重新算。

### 4.2 分层（稳定性）口径

`summary.strata` 按**回归集顺序的奇偶位**切两层（`even` / `odd`），每层 5 条：

| 分层 | 任务 | 规则答对 | 模型答对 | 增益 |
|---|---|---|---|---|
| `even` | t01/t03/t05/t07/t09 | 4 | 5 | +1 |
| `odd` | t02/t04/t06/t08/t10 | 4 | 5 | +1 |

两个盲区正好落在不同分层里，所以“只答对一层”的模型（例如只对 `w4-t08` 有把握）会被
`stable_gain` 拦下。这条判定不依赖统计显著性——本轮的样本量（10 条单次运行）撑不起
显著性，所以只做**分层一致性**这个更弱的检查，并在 §8 明确写出“不做显著性”。

---

## 5. 实现口径

### 5.1 入口

```python
from agent.platform.adaptive.compare import (
    ab_task, ab_regression_tasks, FakeProvider, FakeClock, run_ab, render_ab_markdown)

doc = run_ab(tasks=ab_regression_tasks(), provider=FakeProvider(script),
             config={"mode": "explore"}, budget={"max_calls": 32},
             human_rules={}, label="w4", clock=FakeClock())
```

- `tasks`：`[ab_task(task_id, observation=..., gold={...})]` 或
  `[{"task_id", "rounds"|"observation", "gold"}]`；
- `provider`：`provider(payload) -> Mapping`，`payload = {schema, task_id, round_no,
  observation}`（observation 里带 `facts_hash`）；必须 `offline=True`；
- `run_ab` 抛 `ABError` 的只有编程错误：回归集为空、任务重名、gold 缺诊断码、
  任务不是 mapping。**事实缺失一律降级成未知，不抛**。

### 5.2 状态机（每臂每任务）

```text
ok ──┬─ 答完全部轮次 → correct = (诊断 == gold)
     ├─ 到 max_rounds → budget_exhausted
     ├─ 全局调用/tokens/usd 触顶 → budget_exhausted（并停止后续任务）
     ├─ provider 抛异常/返回非 mapping → environment_error
     ├─ provider 报 budget_exhausted → budget_exhausted
     ├─ 建议全部过不了闸 → rejected
     └─ 什么都没给 → no_suggestion
```

`ok` 是**唯一**进 `correct` 分母的状态；其余四种只进 `retained` 与 `status_counts`。

### 5.3 确定性

- 文档里没有时间戳；`elapsed_seconds` 来自注入的 `clock()`，测试用 `FakeClock`；
- 所有 dict 在比较/渲染前都走 `json.dumps(sort_keys=True)` 口径的摘要；
- 两次 `run_ab` 同一批输入 → `json.dumps(doc, sort_keys=True)` 逐字节相同
  （`test_ab_document_is_deterministic_and_never_claims_verdict`）；
- `render_ab_markdown` 是纯函数，同样输入同一份文本。

---

## 6. 测试（`tests/test_v3_week4_ab.py`）

8 个测试函数、8 条用例，全部离线（无网络、无 key、无临时目录）：

| 用例 | 断言要点（按当前测试文件） |
|---|---|
| `test_ab_arms_share_regression_set_config_budget_and_rules` | `controls.regression_set` 顺序 == 回归集；`arms.rules == arms.model == digest`；`arms_share_controls is True`；`initial_config.sha256` 可复算；指标行顺序 == `AB_METRICS`；A 臂诊断码来自真 `DiagnoseRole`（t01/t03/t05 命中，t08/t09 是 `coverage_unknown` 盲区） |
| `test_ab_stable_gain_opens_gate_but_never_auto_applies` | 规则 8/10、模型 10/10；`wrong_adoptions.model == 0`；两层增益各 +1；`gate.default_arm == "model"`、`reasons == []`、六项检查全过；`auto_apply is False`、`proposal_gate.status == "advisory"`；`calls.model == Σ executed_rounds`；`usd.model == 0.0025 × calls` |
| `test_ab_model_without_stable_gain_defaults_to_rules` | 只背规则诊断 → 8/8 且 `reasons == ["stable_gain"]`；全答一个码 → `no_task_regression` 也在理由里，`detail` 指出退步任务 |
| `test_ab_no_suggestion_is_retained_not_counted_as_wrong` | 10 条 `no_suggestion` 全进 `retained`；`answered.model == 0`；`accuracy.model is None`；所有 `correct is None`；`wrong_adoptions.model == 0`；`reasons` 含 `answered_coverage`；**调用次数仍是 10**（有调用没建议） |
| `test_ab_budget_exhaustion_is_retained` | `max_calls=5` → 前 3 条 `ok`、其余 7 条 `budget_exhausted` 且 id 列表逐条对上；`correct=None`；`reasons` 含 `answered_coverage`；provider 自报预算耗尽只影响该任务（9 ok / 1 exhausted） |
| `test_ab_wrong_adoption_blocks_gate` | 诊断对但提 `run_epoch`（t05 gold `forbid`）→ `wrong_adoptions == {rules:3, model:1}`；`wrong_reasons` 含 `forbidden_action:run_epoch`；`reasons == ["no_model_wrong_adoption"]`（干净的一票否决）；规则臂自己的错误采纳如实记账（t03） |
| `test_ab_rejected_and_environment_errors_are_retained` | 坏诊断码 + 不存在的工具 → `status="rejected"`、两条原因都在、`adopted=0`；夹带 `verified:true` 的动作被剥（`adopted=0`、`rejected` 含 `verdict_fields`）；provider 抛 `RuntimeError` → `environment_error`；`offline=False` 的 provider **一次都没被调用**、整臂 10 条环境错误 |
| `test_ab_document_is_deterministic_and_never_claims_verdict` | 两次运行逐字节相同；`verdict == "not_evaluated"`；文档里没有 `"verified": true`、没有 `confirmed`；`allow_auto_apply=true` 仍 `auto_apply is False` 且 blocker 里有它；markdown 含门禁表与“自动应用：否”；`ABError` 三条路径（缺 gold / 空集 / 重名） |

复跑：

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_v3_week4_ab.py -q
python3 -m pytest tests/test_v3_p4_report.py tests/test_v3_week3_handoff.py \
                 tests/test_v3_week2_config.py -q
python3 -m pytest -q                     # 全量
```

---

## 7. 数字（实测，不预填）

实测环境：Python 3.12.14，pytest 9.1.1，`/home/root_bupt/桌面/file/vulnmap`
（无 `.git`，基线以文件哈希锚定）。下表由 §9 的命令连续跑完；树再变即失效，必须重跑。

| 运行 | 结果 |
|---|---|
| `pytest tests/test_v3_week4_ab.py -q` | **8 passed**（0.09s） |
| `pytest tests/test_v3_p4_report.py tests/test_v3_week3_handoff.py tests/test_v3_week2_config.py -q` | **35 passed**（4.52s） |
| `pytest -q`（全量） | **1515 passed, 8 skipped**（127.12s） |
| `wc -l agent/platform/adaptive/compare.py` | **2242**（前 1082 行为 P4b 段，逐字节未改；其后是 W4 段与新的 `__all__`） |
| `wc -l tests/test_v3_week4_ab.py` | **365** |
| `wc -l docs/V3-W4-AB.md` | **515**（本文自身） |
| 回归集 | **10** 条任务 / **10** 个诊断码 / 15 轮观测 |
| 理想 provider（照 gold 作答，`FakeClock(0.01)`） | 规则 **8/10**、模型 **10/10**（`correct_over_total.ratio` = 0.8 / 1.0，`accuracy` 同值）；`invalid_retries` 4 / 4；`wrong_adoptions` **3 / 0**；`adopted` 7 / 10 |
| 同上：成本 | 规则 **0** 调用 / 0 tokens / **0.0 USD**；模型 **15** 调用 / **15750** tokens / **0.0375 USD**（fake 单价 0.0025/次） |
| 同上：耗时（`FakeClock`） | 两臂各 **0.1**（每任务结束各取一次时钟，10×0.01；真实运行用 `perf_counter`，数值不进确定性口径） |
| 同上：分层 | `even` 4→5（+1）、`odd` 4→5（+1）→ `stable_gain` 通过 |
| 同上：门禁 | `default_arm="model"`、`auto_apply=False`、`proposal_gate=advisory` |
| 只背规则诊断的模型 | 8/8，`reasons == ["stable_gain"]` → 默认规则 |
| 全答 `no_execution` 的模型 | 2/10，`reasons` 含 `no_task_regression` + `stable_gain` → 默认规则 |
| 无建议 | 10 条 `no_suggestion` 全留档；`answered.model=0`、`accuracy.model=null`；`default_arm="rules"` |
| `max_calls=5` | 3 条 `ok`、7 条 `budget_exhausted`；`calls.model=5` |
| 错误采纳 1 次 | `wrong_adoptions={rules:3, model:1}` → `reasons == ["no_model_wrong_adoption"]` |

口径：本文**不写“提升百分比”**——10 条单次运行的样本量撑不起显著性结论，而门禁的判据是
“没有错误采纳 + 每层都有严格增益”，不是“分数更高”。`verdict` 恒为 `not_evaluated`。

---

## 8. 边界（明确不做）

1. **不做显著性检验**：只有分层一致性（`stable_gain`），没有置信区间、没有重复采样。
   要做显著性得先有“同一回归集多次重复”，本轮没有。
2. **不跑目标、不执行工具**：`run_ab()` 的输入是观测与 provider 返回值；它不知道
   fuzzer 存在。真实执行仍归 `executors/` 与 `bin/platform.py run`。
3. **不写库、不写工作副本**：采纳是反事实记账（`adoption_policy="counterfactual"`）；
   想真应用还是走 `ProposalGate` + 控制器 stage/revision 的那条链。
4. **不接真实模型**：`offline=True` 是硬门；本轮没有任何 API key 读取路径。
   真接模型是“换 provider 实现”的事，不是改本框架。
5. **不做跨 campaign 聚合**：一次 `run_ab` 一个回归集；包与包之间不互相引用。
6. **不改 A 臂规则**：`DiagnoseRole` 一处没动。两个盲区是**记录在案**的，不是本轮修的。
7. **不替 `verify` 提前签字**：`verdict` 恒 `not_evaluated`；文档与 JSON 里都没有
   `"verified": true`。
8. **`max_suggestions_per_round` 只是口径对齐**：B 臂每轮只取第一条可用建议的语义
   与 `ResearchSession._with_advisor` 一致；本轮实现是“provider 返回什么就过什么”，
   没有做“多条里挑一条”的策略。

---

## 9. 怎么复核

下面每条命令都在当前树上跑过，输出见各步之后的注释（占位符只有仓库路径）。全程离线，
不读环境变量、不建网络连接。

```bash
cd /home/root_bupt/桌面/file/vulnmap

# ① 本周测试
python3 -m pytest tests/test_v3_week4_ab.py -q
# → 8 passed

# ② 理想 provider：门禁给“默认模型建议”，但 auto_apply 仍是 False
python3 - <<'PY'
from agent.platform.adaptive.compare import (ab_regression_tasks, FakeProvider,
                                             FakeClock, run_ab)
tasks = ab_regression_tasks()
def params(a):
    return {"reason": "candidate observed"} if a == "finish_research" else {}
script = {t["task_id"]: {"diagnosis": {"code": t["gold"]["diagnosis"]},
                         "actions": [{"action": a, "params": params(a)}
                                     for a in t["gold"]["actions"]]}
          for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(script), clock=FakeClock())
print("correct:", doc["summary"]["correct"])
print("wrong:", doc["summary"]["wrong_adoptions"],
      "| invalid_retries:", doc["summary"]["invalid_retries"])
print("cost:", doc["summary"]["cost"])
print("gate:", doc["gate"]["default_arm"], "| auto_apply:", doc["gate"]["auto_apply"],
      "| proposal_gate:", doc["gate"]["proposal_gate"]["status"])
PY
# → correct: {'rules': 8, 'model': 10}
# → wrong: {'rules': 3, 'model': 0} | invalid_retries: {'rules': 4, 'model': 4}
# → cost: {'calls': {'rules': 0, 'model': 15}, 'tokens': {'rules': 0, 'model': 15750}, 'usd': {'rules': 0.0, 'model': 0.0375}, 'usd_known': True}
# → gate: model | auto_apply: False | proposal_gate: advisory

# ③ 无稳定收益 / 错误采纳：两条都退回规则
python3 - <<'PY'
from agent.platform.adaptive.compare import (ab_regression_tasks, FakeProvider,
                                             FakeClock, run_ab)
tasks = ab_regression_tasks()
tie = {t["task_id"]: {"diagnosis": {"code": "no_execution"}, "actions": []}
       for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(tie), clock=FakeClock())
print("worse:", doc["summary"]["correct"], "| gate:", doc["gate"]["default_arm"],
      "| reasons:", doc["gate"]["reasons"])
bad = {t["task_id"]: {"diagnosis": {"code": t["gold"]["diagnosis"]},
                      "actions": [{"action": "run_epoch", "params": {}}]}
       for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(bad), clock=FakeClock())
print("wrong adoption:", doc["summary"]["wrong_adoptions"],
      "| gate:", doc["gate"]["default_arm"], "| reasons:", doc["gate"]["reasons"])
PY
# → worse: {'rules': 8, 'model': 2} | gate: rules | reasons: ['no_task_regression', 'stable_gain']
# → wrong adoption: {'rules': 3, 'model': 5} | gate: rules | reasons: ['no_model_wrong_adoption']

# ④ 保留四类：无建议 / 预算耗尽 / 被拒 / 环境错误
python3 - <<'PY'
from agent.platform.adaptive.compare import (ab_regression_tasks, FakeProvider,
                                             FakeClock, run_ab)
tasks = ab_regression_tasks()
none = {t["task_id"]: {"status": "no_suggestion"} for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(none), clock=FakeClock())
print("no_suggestion:", len(doc["summary"]["retained"]["no_suggestion"]),
      "| answered:", doc["summary"]["answered"],
      "| accuracy:", doc["summary"]["accuracy"],
      "| reasons:", doc["gate"]["reasons"])
doc = run_ab(tasks=tasks, provider=FakeProvider({}), clock=FakeClock(),
             budget={"max_calls": 1})
print("max_calls=1:", doc["summary"]["status_counts"]["model"],
      "| calls:", doc["summary"]["cost"]["calls"]["model"])
boom = {t["task_id"]: RuntimeError("boom") for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(boom), clock=FakeClock())
print("env errors:", len(doc["summary"]["retained"]["environment_error"]),
      "| gate:", doc["gate"]["default_arm"])
class _Online(FakeProvider):
    offline = False
doc = run_ab(tasks=tasks, provider=_Online({}), clock=FakeClock())
print("online provider:", doc["summary"]["status_counts"]["model"],
      "| calls:", doc["summary"]["cost"]["calls"]["model"])
PY
# → no_suggestion: 10 | answered: {'rules': 10, 'model': 0} | accuracy: {'rules': 0.8, 'model': None} | reasons: ['answered_coverage', 'stable_gain']
# → max_calls=1: {'ok': 0, 'no_suggestion': 1, 'rejected': 0, 'budget_exhausted': 9, 'environment_error': 0} | calls: 1
# → env errors: 10 | gate: rules
# → online provider: {'ok': 0, 'no_suggestion': 0, 'rejected': 0, 'budget_exhausted': 0, 'environment_error': 10} | calls: 0

# ⑤ 渲染：一张表 + 门禁表 + “自动应用：否”
python3 - <<'PY'
from agent.platform.adaptive.compare import (ab_regression_tasks, FakeProvider,
                                             FakeClock, run_ab, render_ab_markdown)
tasks = ab_regression_tasks()
script = {t["task_id"]: {"diagnosis": {"code": t["gold"]["diagnosis"]},
                         "actions": []} for t in tasks}
doc = run_ab(tasks=tasks, provider=FakeProvider(script), clock=FakeClock(), label="w4")
md = render_ab_markdown(doc)
print("\n".join(line for line in md.splitlines() if line.startswith("- 自动应用")))
print([line for line in md.splitlines() if line.startswith("| 正确诊断数")])
print("verdict:", doc["verdict"], "| verified in doc:", "verified" in repr(doc))
PY
# → - 自动应用：否（模型建议永不自动应用）
# → ['| 正确诊断数 | 8 | 10 | 2.0 | 更好 | — |']
# → verdict: not_evaluated | verified in doc: False
```

补充自检：`compare.py` 的 W4 段不 import 任何网络库，`grep -n "import requests\|urllib\|socket" agent/platform/adaptive/compare.py` 应为空；`run_ab` 里没有写盘调用（`open(` / `Path(` 均不出现）。
