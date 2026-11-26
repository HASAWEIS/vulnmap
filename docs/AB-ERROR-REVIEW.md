# A/B 错误采纳复盘（AB-ERROR-REVIEW）

> 输入：`experiments/real-ab-fixed-20261125/real-ab.json`（`result_source=real`、`deepseek-flash`、
> 10 任务回归集、两臂共享控制变量）、`experiments/real-ab-fixed-20261125/real-ab.md`、
> `docs/V3-REAL-AB.md`、`docs/V3-W4-AB.md`、`agent/platform/adaptive/compare.py`、
> `agent/platform/adaptive/session.py`、`agent/platform/adaptive/llm_provider.py`。
> 机读版：`experiments/ab-error-review.json`（本文件与它逐字段同源，冲突以 JSON 为准）。
> 纪律：不改业务代码、不改 fixture/gold/门禁、不 `git commit`、不产漏洞结论（`verdict` 概念不适用）。
> 本文件不含时间戳：同一输入两次生成逐字节相同。

## 0. 结论先行

| 问题 | 答案 | 依据 |
|---|---|---|
| 两臂各错采纳几次？ | **各 3 次**（10 任务，`w4-t04` 两臂都是 `budget_exhausted`，不进分母） | `summary.wrong_adoptions={rules:3, model:3}`；逐任务 `_ab_judge` 结果逐条对齐 |
| 6 次错采纳里，规则侧根因占几条？ | **3 条**（`rules/w4-t08`、`rules/w4-t09`、`rules/w4-t03`），其中 `t09` 与模型臂**同因** | 见 §2、§3 |
| 模型侧独有的错是哪类？ | **越权收尾** 1 条（`t07` `finish_research`）+ **码语义误判** 1 条（`t10` `no_signal`） | 见 §2.4、§2.6 |
| 有没有“评测任务本身模糊”的？ | **1 条主因**（`t10`：`no_signal` ↔ `low_coverage` 重叠）+ **1 条次因**（`t07` 的 `forbid` 清单不全） | 见 §3、§4 E1/E2 |
| 下一轮验证什么？ | **一个**最小改进：规则诊断的“执行未完整结束”证据门槛（`cancelled`/`budget_stopped` → `execution_error`；`trials==0` → `no_execution`），**0 行 B 臂改动、0 次模型调用** | 见 §5 |
| 预期效果 | rules：`correct 7→9`、`wrong_adoption 3→1`（仅剩 `t03` 的 `forbidden_action`）、`invalid_retries` 4 不变 | 本机内存替换 `DiagnoseRole.diagnose` 重跑，见 §5.4 |
| 门禁会通过吗？ | **不会，且是结构性的**：`stable_gain = model_correct − rules_correct`，修好 A 臂只会让分层增益更负 | 见 §5.6（这是门禁语义缺陷，登记不动手） |

一句话：**本轮 6 次错采纳里只有 2 次是真“建议质量”问题（模型越权收尾、码语义误判），
其余 4 次（含两条两臂同因）都是规则侧的“采集了不用/条件写窄/模板无条件重跑”。
下一轮只修最便宜、覆盖面最大、且能被逐字段证明零误伤的那一处。**

---

## 1. 事实基线与可信度

| 项 | rules | model | 说明 |
|---|---|---|---|
| 正确诊断数 | 7 | 7 | 分母 `answered=9`（`w4-t04` 两臂都 `budget_exhausted`） |
| 作答 | 9 | 9 | `status=ok` 9 条 |
| 采纳 | 7 | 9 | `adopted = bool(最终轮 actions)` |
| 错误采纳 | **3** | **3** | `wrong_adoptions` |
| 无效重试 | 4 | 4 | 夹具驱动（见 §4 E8） |
| 动作召回（本文新增守门指标） | 0.375 | 0.475 | `\|actions ∩ gold.actions\| / \|gold.actions\|` 的 10 任务均值 |
| 调用 / tokens / 费用 | 0 / 0 / 0 | 14 / 30570 / $0.0129726 | model 耗时 ≈1.37 万倍（30.615s vs 0.002233s） |
| 分层增益 | — | even 0、odd 0 | `gain = model_correct − rules_correct` |

复算纪律（本文所有数字都过一次独立复算，不是照抄）：

- 用独立脚本从 JSON 重算 `correct/adopted/answered/wrong/invalid/cost/strata`，与 `summary` **逐项一致**；
- 用 `_ab_judge`（`compare.py:1281`）对 live `ab_regression_tasks()` 重跑判定，与 JSON 里 20 条记录**零差异**；
- 用同一预算（`max_rounds=2 / max_calls=24 / max_tokens=50000 / max_usd=0.03`）本机重跑规则臂，复现 `correct=7 / wrong=3 / invalid=4`；
- `regression_set_sha256=5a14d283…`、`initial_config.sha256=44136fa3…`、`controls.digest=ed77f668…` 三者复算一致（无陈旧夹具）。

判定口径（读表之前先认这三行，`compare.py:1281-1316`）：

| 字段 | 口径 | 行号 |
|---|---|---|
| `correct` | **只判最后一轮** `diagnosis == gold.diagnosis` | 1297 |
| `adopted` | 最后一轮动作列表非空即 1；**空计划不算采纳** | 1298-1299 |
| `wrong_adoption` | `adopted ∧ (diagnosis_mismatch ∨ forbidden_action ∨ unexpected_action)`；命中 `forbid` 后不再判 unexpected | 1301-1313 |
| 动作分类 | 规划类（`propose_seed_spec/materialize_seeds/set_dictionary/get_task_facts/get_execution_facts/read_source_window/compare_trials`）永不计错；执行类 = `run_epoch/replay_input/finish_research`，**只有 gold 明确允许才算没采纳错** | 1143-1150、1308-1312 |

---

## 2. 六条错误采纳逐条复盘

### 2.1 总表

| # | 臂 | 任务 | 诊断 | gold | 最终轮动作 | `wrong_reasons` | 归因 |
|---|---|---|---|---|---|---|---|
| 1 | rules | `w4-t03` | `input_not_processed` ✅ | 同 | 种子四件套 + **`run_epoch`** | `forbidden_action:run_epoch` | 规则盲点（动作模板） |
| 2 | rules | `w4-t08` | `coverage_unknown` ❌ | `no_execution` | 种子四件套 + `run_epoch` | `diagnosis_mismatch` | 规则盲点（分支条件窄） |
| 3 | rules | `w4-t09` | `coverage_unknown` ❌ | `execution_error` | 种子三件 + **`run_epoch`** | `diagnosis_mismatch`、`forbidden_action:run_epoch` | 规则盲点（采集不用） |
| 4 | model | `w4-t07` | `config_not_effective` ✅ | 同 | `get_task_facts` + **`finish_research`** | `unexpected_action:finish_research` | 模型过度建议 |
| 5 | model | `w4-t09` | `coverage_unknown` ❌ | `execution_error` | `get_execution_facts` + **`run_epoch`** | `diagnosis_mismatch`、`forbidden_action:run_epoch` | 规则盲点（两臂同因） |
| 6 | model | `w4-t10` | `no_signal` ❌ | `low_coverage` | `get_execution_facts`、`get_task_facts` | `diagnosis_mismatch` | 评测任务模糊（主）+ 模型误判（次） |

### 2.2 `rules / w4-t03` — 诊断对，动作越界

- **事实**：两轮 `program_started=true, input_processed=false, trials=1→2, snapshot_status=ok`（`compare.py:1647-1659`）。
- **gold**：`input_not_processed`；动作 `get_task_facts + 换种子三件`；`forbid=["run_epoch"]`；note「输入没被处理：换种子，不要原样重跑（无效重试）」。
- **期望差异**：gold 要的是“换种子后停手”，臂给的是“换种子**再原样重跑一次**”。同一输入的第 2 轮 `facts_hash` 未变，正是 gold 明令禁止的无效重试形态。
- **机制**：`DiagnoseRole.diagnose` 在这里判对（`session.py:484-487`），问题在规划模板：`propose` 对一组 miss 码**无条件**追加 `run_epoch`（`session.py:757-761` 的 miss 元组 + `791-792`），根本不看“事实有没有变”。
- **动作**：本轮不改。它是**第二个变量**（动作侧 guard），排在 §5 的诊断轮验收之后。
- **为什么不是“模型更聪明”**：B 臂在同一任务只给 `get_task_facts`（`adopted=1`、`wrong=0`），说明提示词硬规则 3（`llm_provider.py:695-697`「`input_processed=false` 时应换种子」）已经覆盖此形态——规则补上同样的约束即可，不需要模型。

### 2.3 `rules / w4-t08` — 分支条件比诊断码语义更窄

- **事实**：两轮 `trials=0, snapshot_status="ok"`（快照采到了，但一次执行都没有；`compare.py:1708-1714`）。
- **gold**：`no_execution`（码自身的注释就是「还没有任何执行事实」，`session.py:46`）。
- **期望差异**：gold 要“先跑一次”；臂给 `coverage_unknown`，下游读成“跑过了、覆盖不明” → 换种子重跑。**语义把“没跑”说成“跑了”**，这是比动作错误更贵的错。
- **机制**：`session.py:514` 写的是 `trials == 0 and snapshot_status == UNKNOWN`；只要快照采到，条件就不成立，于是落到 `517-519` 的 `coverage_unknown` 兜底。
- **动作**：**下一轮唯一改进的第一处**（去掉 `snapshot_status` 条件）。

### 2.4 `rules / w4-t09` — 事实采集了，诊断从不消费

- **事实**：单轮 `program_started=true, input_processed=true, fault.cancelled="true", trials=1`（`compare.py:1715-1723`）。
- **gold**：`execution_error`；动作 `get_execution_facts + finish_research`；`forbid=["run_epoch"]`；note「执行被取消时不能报 coverage_unknown」。
- **期望差异**：gold 要“承认没跑完 + 只读事实后收尾”；臂给 `coverage_unknown` **并重跑**（双重错：诊断错 + 动作撞 forbid）。
- **机制**：`fault.cancelled` / `fault.budget_stopped` 早在 `session.py:283-284` 就被采集了，但 `DiagnoseRole.diagnose` 只看 `fault.error` / `fault.timeout`（`461-466`），其余一路落兜底 `coverage_unknown`（`517`）。这是“采集了不用”，不是“没能力判”。
- **动作**：**下一轮唯一改进的第二处**（`cancelled/budget_stopped → execution_error`）；动作侧的 `run_epoch` 由同一改判自然消失（`execution_error` 分支给空计划，`session.py:796-797`）。

### 2.5 `model / w4-t07` — 越权收尾（诊断对）

- **事实**：单轮 `config.status=not_effective`（planned `a*8` / loaded `b*8`），`compare.py:1698-1707`。
- **gold**：`config_not_effective`；动作 `get_task_facts + read_source_window`；`forbid=["run_epoch"]`；note「执行器加载的不是计划配置：**本轮结论不算数**」。
- **期望差异**：gold 要“继续核查配置”；臂在读事实后直接 `finish_research` —— 把“本轮结论作废”读成“研究结束”。
- **机制**：`finish_research` 属 `AB_EXECUTING_ACTIONS`（`compare.py:1148`），未在 `gold.actions` 白名单里 → `unexpected_action`（`1308-1312`）。提示词里没有任何“结论作废时禁止终结”的约束（`llm_provider.py:695-698` 只约束了 `run_epoch` 与 `candidates>0`）。
- **动作**：本轮不动 B 臂（不换模型、不刷分）。同时登记评测口径缺口 **E2**：`forbid` 只显式列了 `run_epoch`，`finish_research` 靠白名单反推才被禁——同一类越权一处显式一处隐式。

### 2.6 `model / w4-t09` — 两臂共同错因

- **事实/gold**：与 §2.4 同任务同事实。
- **期望差异**：gold 要 `execution_error` + 只读；臂给 `coverage_unknown` + `run_epoch`。
- **机制**：B 臂拿到的 payload 只有 `{task_id, round_no, observation}`（`compare.py:1470-1473`），`cancelled` 是事实里的字段但**没有任何一条提示词规则说它意味着什么**；于是模型只能复读规则兜底的“覆盖未知”。**这是规则缺口外溢到模型，不是模型能力差。**
- **动作**：由 §5 的规则修复关掉根因；B 臂本轮不重跑。

### 2.7 `model / w4-t10` — 码语义重叠（主因在夹具）

- **事实**：单轮 `checkpoint_reached=true, coverage={delta:0.0, metric_kind:edge}, trials=2`（`compare.py:1724-1732`）。
- **gold**：`low_coverage`；动作 换种子 + `run_epoch`；note「命中但无可比增益：换种子再试」。
- **期望差异**：gold 要“继续推进（换种子）”；臂答 `no_signal` 并只给只读动作 → 方向偏保守，研究停摆。
- **机制**：`DIAGNOSIS_CODES` 里 `no_signal`=「事实不足且没有新信息」，`low_coverage`=「有覆盖但无可比增益」（`session.py:53-57`）。夹具只给了 `delta=0.0` 这一个读数，没有 `coverage.covered>0` 之类的“命中锚点”，两条码都能自圆其说。规则侧能判对是因为它读 `checkpoint_reached` 的顺序（`498-506`）；这属于“规则对口、模型不对口径”。
- **动作**：本轮**不改夹具**（改夹具=换变量）。登记 **E1**；下一轮之后单独一轮处理“码语义边界 + 夹具补锚点”。

---

## 3. 三类归因

| 类别 | 条数 | 判据 | 条目 |
|---|---|---|---|
| **规则盲点** | 3（含 1 条两臂同因） | 规则分支/模板的前提比诊断码语义更窄，或采集了事实却不消费 | `rules/w4-t08`（条件窄）、`rules/w4-t09` + `model/w4-t09`（采集不用）、`rules/w4-t03`（模板无条件重跑） |
| **模型过度建议** | 1 | 诊断正确，但提了执行/结论类动作而 gold 未授权 | `model/w4-t07`（`finish_research`） |
| **评测任务本身模糊** | 1（主因）+ 1（次因） | 夹具/gold 没把两码或两动作区隔开 | `model/w4-t10`（`no_signal` ↔ `low_coverage`）；`model/w4-t07` 的 `forbid` 清单不全（次因） |

三条推论（写下来是为了防止下一轮用错变量）：

1. **规则侧 3 条里有 2 条（`t08`、`t09`）是同一个不变量被写窄了**：`coverage_unknown` 只应表示“真的跑过一次、且没异常终止”。修这一处同时清掉 `t08` 与 `t09`（两臂同因）。
2. **模型侧唯一的能力类问题是“收尾权越界”，不是诊断能力**：`t07` 诊断对；`t10` 是评测口径问题；`t09` 是复读规则。所以“换更强模型”在这份数据上没有可归因的收益空间——**不换模型是数据结论，不是纪律要求**。
3. **动作层是结构性偏差，不是偶发手滑**：规则臂动作召回均值只有 **0.375**（模型 0.475）。规划器对 miss 码统一发“种子四件套 + `run_epoch`”，而 gold 大量要的是“读事实/读源码/收尾”。`t03` 只是这个模板在 `forbid` 下的第一次撞墙。

---

## 4. 判定层口径缺陷（不是臂的错，但要先记账）

| ID | 严重度 | 事实 | 影响 | 本轮处理 |
|---|---|---|---|---|
| **E1** | 中 | `no_signal` 与 `low_coverage` 在 `t10` 形态下语义重叠（`session.py:53-57`，夹具无锚点） | `model/t10` 被记 1 次 mismatch，实为夹具缺区分点 | 否（登记，单独一轮） |
| **E2** | 中 | `gold.forbid` 只列 `run_epoch`；`finish_research` 靠 `AB_EXECUTING_ACTIONS` 白名单反推才被禁（`compare.py:1148`、`1308-1312`） | 同一类越权一处显式一处隐式；改工具表会静默改判据 | 否 |
| **E3** | 高 | `w4-t04` fixture 有 3 轮（`compare.py:1660-1671`），预算 `max_rounds=2` → **结构性不可达** | `correct` 上限恒为 9；该任务占 1/10 预算却产生不了任何增益；本机把 `max_rounds` 提到 3 时规则臂立刻 `candidate_observed/correct=true` | 否（改预算=改控制变量，须单独一轮并重算 `controls.digest`） |
| **E4** | 高 | `adopted = bool(actions)`（`compare.py:1298-1299`）：零动作既不会错采纳也不扣分 | `rules/t05`、`rules/t07` 零动作仍 `correct=true`；**任何后置拒收都能把错误建议洗成静默**，指标被压低而不是被修正 | 否（但 §5 的验收加了“动作召回不得下降”作对冲） |
| **E5** | 高 | `status≠ok` 时 `wrong_reasons` 整体清零（`compare.py:1290-1294` 早退） | `w4-t04` 两臂轮内都提了 `forbid` 的 `run_epoch`，`wrong_reasons=[]` 完全不可见；与 E3 叠加成记分盲区 | 否 |
| **E6** | 中 | 只判最后一轮（`compare.py:1297` + 逐轮覆盖 `1364-1365/1515-1516`） | `t03` 第 1 轮也提了 `run_epoch`，多轮任务的过程错误无记账位 | 否 |
| **E7** | 中 | `_AB_FACT_KEYS`（`compare.py:1245-1247`）不含 `trials` / `snapshot_status` | `w4-t01`(trials=0, snapshot=unknown) 与 `w4-t08`(trials=0, snapshot=ok) 的 `facts_hash` **同为 `44136fa355b3678a`**（= `sha256("{}")[:16]`），而两者 gold 诊断不同 → “有没有新事实”判据对这两个字段失明 | 否（但它是动作侧 guard 的前置条件，见 §5.7 R6'） |
| **E8** | 低 | `invalid_retries` 由夹具轮数决定（`1366-1367/1517-1518`），两臂同为 4 | 不是“谁更聪明”的证据，只是夹具记账 | 否（§5 把它设成 `==4` 硬阈值，不当收益） |
| **E9** | 低 | `retained.budget_exhausted=["w4-t04","w4-t04"]`，逐臂各 append 一次、无臂标签（`1813-1816`） | 读者会误读成两个任务 | 否 |

**这一节的用途**：下一轮判“改进有没有效”时，**只允许用 §5 列出的指标**；不许拿 `adopted` 下降、`wrong_reasons` 变空、`retained` 变化当收益证据——那三条都可以被人为制造（E4/E5）。

---

## 5. 下一轮：只验证一个最小改进

### 5.1 改进规格（一句话）

> **`coverage_unknown` 的成立前提收紧为“`trials>0` 且 `fault` 无异常终止”**：
> `fault.cancelled=true` / `fault.budget_stopped=true` → 强制 `execution_error`；
> `trials==0` → 强制 `no_execution`（不再要求 `snapshot_status==unknown`）。

两个子句是**同一个不变量**（“覆盖未知”只能表示“真的跑过一次、且没异常终止”），
所以算**一个**变量，不是两个。

### 5.2 挂点（只描述改哪里，本轮不动代码）

| 挂点 | 现状 | 改法 | 约束 |
|---|---|---|---|
| `session.py:466` | `error`(461)/`timeout`(464) 之后直接进 config 判定 | 插入 `cancelled=="true"` → `execution_error(reasons=("cancelled",))`、`budget_stopped=="true"` → `execution_error(("budget_stopped",))`（≤6 行） | **必须**在 `475-478`（`candidates>0 → candidate_observed`）**之后**，否则“取消前已出候选”会被盖掉 |
| `session.py:514` | `if trials == 0 and snapshot_status == UNKNOWN:` | 去掉 `and snapshot_status == UNKNOWN`（1 行） | 只认精确 `0`，不写 `in (0, None)`；位置保持在 `511-513`（`config_unverified`）之后，否则 `t07` 类被降级 |
| `session.py:517-519` | `coverage_unknown` 兜底 | **不改**。改完它自动等价于“`trials>0` ∧ 无异常终止 ∧ 目标态 unknown”，与码注释自洽且不会变死码 | — |
| `session.py:757-792` | miss 码统一发“种子四件套 + `run_epoch`” | **不改**（第二个变量） | `t09` 走 `execution_error` → 空计划，越权动作自然消失 |
| `compare.py`（判定/白名单/facts_hash/门禁）、`real_ab.py`、`llm_provider.py`、10 条 fixture、`gold`/`forbid`、`budget`/`human_rules` | — | **零改动** | 改任何一个就不再是单变量 |

### 5.3 为什么是它（不是动作 guard，也不是提示词）

| 候选 | 能清几条 | 代价 | 结论 |
|---|---|---|---|
| **① 诊断证据门槛（选中）** | rules 3 条里 **2 条**（`t08`、`t09`），且 `t09` 两臂同因 | 规则分支，`calls/tokens/usd` 恒 0；确定性、方差 0 | **选中** |
| ② 动作 guard（`input_not_processed` 且事实未变时砍 `run_epoch`） | 1 条（`t03`），且 `t03` 诊断本来就对 → 不改 `correct` | 需改规划模板 | 排队第 2 轮 |
| ③ 提示词/后置校验（禁 `finish_research`、禁 `no_signal`） | 模型侧 1–2 条 | 必须重跑真实模型（14 calls / 30570 tok / $0.01397），且有采样漂移；且硬规则 3/4 已写在提示词里（`llm_provider.py:695-698`），模型照样违反 | 边际收益低，且属“用模型刷分” |
| ④ 改 gold / 删 `forbid` / 放宽门禁 | “清零” | — | 明令不做（`docs/V3-W4-AB.md` §4.1 已定死） |

关键算术：`stable_gain` 用的是 `gain = model_correct − rules_correct`（`compare.py:1866`），
**修 A 臂只会让分层增益变负**。所以本轮**没有**“门禁变绿”这条验收路径——这是门禁语义
（“模型是否取代规则当默认源”），不是质量指标。见 §5.6。

### 5.4 本机复跑证据（内存 monkeypatch，不写业务文件）

| 口径 | rules `correct` | `wrong_adoption` | `adopted` | `invalid_retries` | 动作召回 |
|---|---|---|---|---|---|
| 基线（复现 JSON） | 7 | 3 | 7 | 4 | 0.375 |
| 改后（本机重跑） | **9** | **1** | 6 | 4 | 0.375 |

逐任务变化**只有两行**：

| 任务 | 基线 | 改后 |
|---|---|---|
| `w4-t08` | `coverage_unknown` / `wrong=1` | `no_execution` / `wrong=0` / `correct` |
| `w4-t09` | `coverage_unknown` + `run_epoch` / `wrong=1` | `execution_error` / `adopted=0` / `wrong=0` / `correct` |

其余 8 条（含 `t04` 的 `budget_exhausted`）`(diagnosis, actions, wrong_reasons, invalid_retries)` **逐字段不变**。
动作召回均值 0.375 → 0.375：`t09` 从“乱重跑”变“空计划”，但它的动作召回本来就是 0，
**没有用沉默换分**（这也是 §4 E4 的对冲）。

### 5.5 指标（含统计口径）

| 类 | 指标 | 基线 | 目标/阈值 |
|---|---|---|---|
| 主 | `rules.wrong_adoptions` | 3 | **==1**，且剩余 `wrong_reasons` 只有 `w4-t03` 的 `forbidden_action:run_epoch` |
| 主 | `rules.correct_diagnoses` | 7 | **==9** |
| 主 | 逐任务 `(diagnosis, actions, wrong_reasons)` diff | — | **只允许 `t08`、`t09` 两行变化**；`t01/t02/t03/t05/t06/t07/t10` 逐字段相同 |
| 守门 | `answered_ratio` | 0.9 / 0.9 | ≥0.8 两臂 |
| 守门 | `invalid_retries` | 4 / 4 | **==4** 两臂（不是 ≤4：夹具决定，升了就说明改判触发了额外轮） |
| 守门 | `retained` 集合 | `budget_exhausted=[w4-t04]` | 同一集合，无新保留类 |
| 守门（反作弊） | `action_recall_mean(rules)` | 0.375 | **≥0.375**（不许用空计划换低错误采纳） |
| 成本 | rules `calls/tokens/usd` | 0/0/0 | 0/0/0 |
| 成本 | model `calls/tokens/usd`（若重跑） | 14 / 30570 / $0.0129726 | ≤14 / ≤32100 / ≤$0.01362（增幅 ≤5%） |
| 控制 | 三个 sha256（`regression_set` / `initial_config` / `controls.digest`） | `5a14d283…` / `44136fa3…` / `ed77f668…` | **逐字节相同**，变了该轮作废 |

统计口径：

- **同一份 10 任务回归集**，两臂共享 `controls`；`w4-t04` 恒定 `budget_exhausted`、不进分母，
  `correct` 上限 9、`answered` 上限 9，**不要把它算进增益**；
- 规则臂**确定性**（同输入同输出，方差 0）→ A 臂 Δ 用精确值判，不做显著性；
- B 臂若重跑，漂移只用于“不得变差”的容差，不参与判定；
- 单变量可机械校验：diff 只落 `session.py` 两处（≤6 行插入 + 1 行条件），
  其余文件 diff 为空，且 B 臂 14 条 `observation_sha256` 与上轮 trace 逐条相同
  （payload 只含 `{schema, task_id, round_no, observation}`，`compare.py:1470-1473`，**不含规则诊断**）。

### 5.6 预期门禁（写清楚，免得下一轮把“红”当失败）

| 检查 | 改后 | 说明 |
|---|---|---|
| `no_model_wrong_adoption` | ❌（model=3） | B 臂本轮不动机，`t07/t09/t10` 仍在 |
| `answered_coverage` | ✅ 0.9 | — |
| `no_task_regression` | ❌（`w4-t10`） | 规则侧修复不影响该条 |
| `stable_gain` | ❌（even −1、odd −1） | 修好 A 臂使 `model_correct − rules_correct` 变负 |
| `read_only_real_provider` / `engine_available` | ✅ | — |

结论：**在“不换模型 + B 臂只读”的硬约束下，这三项门禁本轮结构性不可满足**，
它们是“换建议源”的开关，不是质量门。本轮的验收标准 = §5.5 的 A 臂本地口径 + 不得变差守门。
（顺带登记一条设计问题：`stable_gain` 同时承担“质量回归”和“换源收益”两个角色，
修 A 臂必然让它变红 → 建议下一轮之后拆成两道门。本轮只登记，不动代码。）

### 5.7 停止条件（硬阈值）

**判有效（accept，7 条全中）**

1. `rules.correct == 9`；
2. `rules.wrong_adoption == 1`，且 `wrong_reasons` 只剩 `w4-t03 forbidden_action:run_epoch`；
3. `t01/t02/t03/t05/t06/t07/t10` 的 `(diagnosis, actions, wrong_reasons)` 与基线**完全一致**；
4. `invalid_retries` 两臂 == 4；`answered_ratio` 两臂 ≥0.8；`retained` 集合不变；
5. rules `calls=tokens=usd=0`；若重跑 B 臂，`calls ≤14 / tokens ≤32100 / usd ≤$0.01362`；
6. 三个 control sha256 与基线相同；
7. `action_recall_mean(rules) ≥ 0.375`。

**判无效（reject，任一即停，且本轮不得追加第二个改动）**

- `rules.correct ≤ 7`（增益 < +2：落点被更早分支吃掉）；
- `rules.wrong_adoption ≥ 2`（`t08`/`t09` 一条都没清掉）；
- 任一当前答对的任务翻错（条件 3 失败）；
- `invalid_retries > 4` / `answered_ratio < 0.8` / 出现新保留类；
- 任一 control sha256 变化 → **变量漂移，该轮作废**（记“作废”，不记“改进失败”）。

**判需拆轮**：`correct == 8 且 wrong == 2`、且只有 `t08` 或 `t09` 之一转对 →
两个子句各自独立，本轮记“部分证伪”，下一轮只保留已证的那一条，另一条单独一轮；
**不得在同一轮再加第二个 guard**。

**判回退**：条件 3 失败或 control sha256 变化 → 立即回退该分支，结论写“否证”，
不改 `gold`、不改门禁、不加新约束。

**“一次只看一个变量”的机械判据**：diff 只落在 `session.py` 两处（≤6 行插入 + 1 行条件）；
`compare.py` / `real_ab.py` / `llm_provider.py` / fixtures / `gold` / `budget` / `human_rules` diff 为空；
B 臂 14 条 `observation_sha256` 与上轮 trace 逐条相同。

### 5.8 风险与反例

| ID | 误伤 | 机制 | 退路 |
|---|---|---|---|
| R1 | `t01/t02/t03/t07` | 把“**无 coverage 读数** → `execution_error`”照字面实现：coverage 缺失是常态。本机实测该变体 `correct 7→4`、`wrong 3→0` —— 错采纳清零是假象，4 条正确诊断被换成 `execution_error` | 触发条件**只认** `fault` 的取消/预算停止/error/timeout，绝不认 coverage 缺失；守门条件 3 就是这条闸门 |
| R2 | `t04` 类（取消前已出候选） | `cancelled` 分支若插在 `session.py:475-478` 之前会盖掉 `candidate_observed` | 插入点固定在 478 之后；本回归集无此形态，真实任务有 |
| R3 | `t07` 类（改配置无加载回报） | `trials==0` 若提到 `511-513` 之前，会把 `config_unverified` 降级成 `no_execution` | 落点保持在其后；条件只写 `trials == 0` |
| R4 | `t09` 自身：`adopted 1→0` | `execution_error` 给空计划；judge 视空计划为 `adopted=0`（E4） | 方向正确（gold 只允许只读+收尾）；所以 `adopted` 不进阈值，且同轮记录 `action_recall=0.375` 不变 |
| R5 | 多轮 `t09` 变体 | `execution_error` 不在 `propose` 的 miss 元组（`757-761`）→ `attempt` 不递增 → 取消后下一轮不换种子格式 | 本回归集 `t09` 单轮，零影响；登记为二阶效应，**本轮不修**（否则就是第二个变量） |
| R6' | 未来的动作侧 guard | `_AB_FACT_KEYS` 不含 `trials`/`snapshot_status`（E7）→ “事实有没有变”对这两个字段失明，`t01`/`t08` 同 hash | 本轮不依赖该判据；动作 guard 上线前必须先扩 `_AB_FACT_KEYS`，否则 guard 会误放/误拦 |

---

## 6. 明确不做

1. **不换模型、不换 provider、不改 prompt**——本轮 B 臂输入零变化，是“单变量”的一部分；
2. **不动 `compare.py`** 的判定、动作白名单、`facts_hash`、门禁阈值（包括不为了让门禁变绿而放宽 `stable_gain`）；
3. **不动 fixture / `gold` / `forbid` / `budget` / `human_rules`**（`w4-t04` 的 `max_rounds` 也不动，见 E3）；
4. **不把“规则修好”写成“模型没收益”**：本轮只证明“`t08`/`t09` 是规则缺口，不是模型能力”；
5. **不用 E4/E5 的漏洞刷分**：不靠空计划、不靠 `status≠ok` 早退清零来降低 `wrong_adoption`；
6. **不做显著性宣传**：规则臂方差 0，用精确值判；10 条任务单次运行不支撑“提升 x%”的说法；
7. **不 `git commit`**。

---

## 7. 复现清单

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 事实复算：逐任务错采纳 + 计数（与 summary 对齐）
python3 - <<'PY'
import json
d = json.load(open('experiments/real-ab-fixed-20261125/real-ab.json'))['doc']
for t in d['tasks']:
    for arm in ('rules', 'model'):
        r = t[arm]
        if r['wrong_adoption']:
            print(arm, t['task_id'], r['diagnosis'], '<-gold', t['gold']['diagnosis'],
                  r['wrong_reasons'], r['actions'])
print(d['summary']['wrong_adoptions'], d['summary']['correct'], d['summary']['invalid_retries'])
PY

# 2) 判定口径：读 _ab_judge / 白名单 / 门禁
sed -n '1143,1150p;1281,1316p;1899,1955p' agent/platform/adaptive/compare.py

# 3) 规则分支（盲点位置）
sed -n '454,520p;755,795p' agent/platform/adaptive/session.py

# 4) 单变量证据：B 臂 payload 不含规则诊断
sed -n '1470,1478p' agent/platform/adaptive/compare.py

# 5) 本机重跑（基线复现 + 改后预测，内存 monkeypatch，不写业务文件）
#    见 experiments/ab-error-review.json 的 replay_evidence 段
```

| 复核项 | 结论 |
|---|---|
| `summary` 与逐任务记录可复算 | ✅ 20 条记录零差异 |
| fixture 与 JSON 是否陈旧 | ✅ `gold` 10/10 与 `ab_regression_tasks()` 逐字段相同 |
| 两臂控制变量是否同源 | ✅ `arms.rules == arms.model == controls.digest` |
| 单变量是否成立（规则改动不影响 B 臂） | ✅ payload 不含诊断；14/14 `observation_sha256` 可对比 |
| 是否改了业务代码 / fixture / gold | ❌ 未改（本复盘只新增 `docs/AB-ERROR-REVIEW.md` 与 `experiments/ab-error-review.json`） |

---

### 附：与既有文档的关系

- `docs/V3-W4-AB.md` §4.1 已把 `w4-t08`/`w4-t09` 定为“两个规则盲区”，本复盘**不改这个结论**，
  只补上“这两个盲区在真实模型跑里各自产生了哪些记账”（`t09` 还是两臂同因）以及“修它们的顺序与代价”。
- `docs/V3-REAL-AB.md` §0 的口径（`auto_apply` 恒 `False`、错误采纳一票否决、`verdict=not_evaluated`）全部继承；
  本文不新增任何裁决字段。
- 本复盘新增的两个**派生指标**（`action_recall_mean`、逐任务 diff 闸门）只作守门与反作弊，
  不进 `compare.py` 的指标表，也不进任何分母。
