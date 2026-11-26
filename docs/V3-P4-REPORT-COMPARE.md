# V3 P4b：研究报告进 CasePack、五指标对照与三类事实分离（V3-015 / V3-016）

对应《VULNMAP-V3 完整升级方案》§4「双循环与状态模型」、§9「统一数据契约」、
§12「独立验证」与 §18.1 门禁，前置 P4a（[V3-P4-API-TIMELINE.md](V3-P4-API-TIMELINE.md)）。
P4a 把研究轮次用只读视图暴露出来；P4b 只做三件事，**都在“事后记账”这一侧**：

1. **研究报告进 CasePack**（V3-015）：有 `research.json` 时，包内追加
   `research.json` + `research/{timeline,rounds,decisions,evidence_refs}.json` + `compare.json`，
   并把它们纳入 `content_sha256`；没有研究产物时清单一个字都不变。
2. **五指标对照**（V3-016）：`agent/platform/adaptive/compare.py` 把**已经发生的执行事实**
   并排放成一张表，逐项给「研究循环 / 单次 fuzz / Δ / 方向 / 是否可比 / 说明」。
3. **三类事实分离**：工程采纳、漏洞验证、研究进展在 `report.md` / `report.html` 里各占一节，
   互不代签。

边界一句话：本次改动没有新增任何运行期能力——研究循环仍只由
`bin/platform.py run <task> --research` 驱动，`verify.py` / `benchmark_policy` / 执行器 /
DB schema / 写端点**一个字没改**；新代码只读既有台账，产出派生文档。

---

## 0. 实施清单

| 项 | 状态 | 验收口径 | 落点 | tests |
|---|---|---|---|---|
| P4b-1 研究报告进 CasePack（V3-015） | 已实施 | 有产物：包内 9 + 6 个文件、`research.json` 与源文件字节相同、`casepack.json.research` 18 个键、`research.sha256` 可 `sha256` 复算、研究产物进 `content_sha256`、`reports` 台账 sha 与 `content_sha256` 一致 | `agent/platform/casepack.py`（`RESEARCH_FILES` / `research_files()` / `_research_block` / `build_casepack`） | `test_casepack_packs_research_artifacts_with_recomputable_hashes` |
| P4b-2 无产物不伪造 | 已实施 | 包内仍只有原 9 个文件；`research.status == "absent"`；不写 `research/` 目录、不写空轮次；`research_files()` 返回空元组 | 同上（`_research_block` 的 absent 分支） | `test_casepack_without_research_keeps_base_files_and_reports_absent` |
| P4b-3 五指标与公式（V3-016） | 已实施 | `time_to_first_crash / coverage / candidates / action_acceptance / repeat_rate` 按公式给值；未知一律 `null` + `known=false` + `reason` | `agent/platform/adaptive/compare.py`（`metrics_from_report` / `metrics_from_events` / `merge_metrics` / `compare_arms`） | `test_compare_five_metrics_follow_contract_formulas` |
| P4b-4 负结果与可比性 | 已实施 | Δ=0 的轮次、未知指标、无基准、指标口径不同，全部留在 `negative_results` / `comparability.reasons` | 同上（`_round_negatives` / `compare_arms` / `build_compare`） | `test_compare_keeps_negative_results_and_comparability_reasons` |
| P4b-5 不伪造裁决 | 已实施 | 报告写 `verification_allowed=true` 时，包级结论仍是“未验证”；`verdict` 恒为 `not_evaluated`；整包不出现自裁决字段 | `casepack.py`（`_pack_verdict`）+ `compare.py`（`verdict` 字面量 + `NOTE`） | `test_casepack_never_forges_verified_or_confirmed` |
| P4b-6 三类事实分离 | 已实施 | `report.md` / `report.html` 各有「研究进展」「工程采纳」「漏洞验证」三节；动作次数只出现在“研究进展”并标注“不推断” | `casepack.py`（`_render_research_md` / `_render_decisions_md` / `_render_vulnerability_md` / `render_report_html`） | `test_report_sections_separate_engineering_verification_and_progress` |
| P4b-7 确定性 | 已实施 | 四个研究派生文档 + `compare.json` 无时间戳、固定键序，同一输入重算字节相同；`report.html` 是“所记录快照”的确定性函数 | `casepack.py`（`_json_bytes` + `_pick` 固定键集合）+ `compare.py`（文档不含 `ts`） | `test_research_artifacts_and_html_are_deterministic` |
| P4b-8 冲突即拒绝 | 已实施 | 坏 JSON / schema 不认识 / 串任务 / 与 `research.mapped.report_sha256` 不一致 → `CasePackError`，且不写包、不写台账 | `casepack.py`（`load_research`） | `test_casepack_rejects_conflicting_research_artifacts[bad_json/unknown_schema/foreign_task/hash_mismatch]` |
| P4b-9 `controller: null` 也是真产物 | 已实施 | 预算预检就耗尽的研究运行写出 `controller: null` + `rounds: 0`；打包接受它：`status="ok"`、`rounds=0`、`controller_absent=true`、`timeline.counts.phases=0`，不替它编轮次 | `casepack.py`（`load_research` 的 `controller is not None` 分支 + `_research_block` 的 `controller_absent`） | 见 §4「不算冲突」一侧；`test_casepack_packs_research_artifacts_*` 覆盖正常报告路径 |

改动边界：`agent/platform/adaptive/compare.py`（新增）、`agent/platform/casepack.py`
（追加研究产物支持）、`tests/test_v3_p4_report.py`（新增）、`docs/V3-P4-REPORT-COMPARE.md`（本文）。
**未改** `agent/platform/verify.py`、`benchmark_policy`、`executors/`、`store.py` 的 schema、
任何写端点，也未改 `research.json` 的写入格式（`adaptive/cli.py` 不在本批改动里）。

### 0.1 文件清单

| 文件 | 变化 |
|---|---|
| `agent/platform/adaptive/compare.py` | 新增。纯标准库的对照实验模块：两个臂 × 五个指标 + 逐轮账 + 负结果；不导入 `agent.platform.*`，不产裁决 |
| `agent/platform/casepack.py` | 改动。`RESEARCH_FILES` / 四个派生 schema 名 / `research_dir()` / `research_files()` / `load_research()` / `research_views()` / `_timeline_view` / `_rounds_view` / `_decisions_view` / `_evidence_refs_view` / `_compare_view` / `_compare_summary` / `_research_block` / `_render_research_md` / `_render_decisions_md` / `_render_vulnerability_md` / `_compare_md`；`build_casepack` 新增 `research_root` / `baseline` / `require_research` 三个参数 |
| `tests/test_v3_p4_report.py` | 新增。8 个测试函数（`test_casepack_rejects_conflicting_research_artifacts` 参数化 4 条），共 11 条用例；全部用临时 `PLATFORM_ROOT` |
| `docs/V3-P4-REPORT-COMPARE.md` | 本文 |

---

## 1. 为什么必须“三类事实分离”

研究循环一次运行会同时产生三种性质完全不同的事实。把它们写进一个结论字段，
就会出现“动作跑得多，所以更可信”这种不成立的推理，因此三类事实分开记、分开渲染：

| 类别 | 唯一事实来源 | 回答的问题 | 不回答什么 |
|---|---|---|---|
| 工程采纳 | `adaptive/policy.py` 的 `engineering()` 结论 → `adoptions.jsonl`（`scope=engineering`）+ 控制器每轮 `engineering` 决策 | 这份改动副本**能不能构建**、冒烟是否假阳性、执行有没有观测（有 `compare` 时还要求可比且 Δ>0） | 有没有漏洞、能不能复现 |
| 漏洞验证 | `verifications` / `reviews` 两张既有台账 | benchmark 判据是否通过、复核是否 accept | 研究循环跑了几轮、动作被采纳多少 |
| 研究进展 | `research.json` 的 `controller.rounds` / `controller.timeline`、事件流、`compare.json` | 走了哪些阶段、诊断出什么、提了哪些动作、覆盖率怎么动 | 任何裁决 |

### 1.1 “动作次数 = 工作量，不是智能”

这条口径在代码里是**写死的常量**，不是注释里的君子协定：

```python
# agent/platform/adaptive/compare.py
COUNTS_NOTE = "动作数/轮数只当工作量记账，不推断“更聪明”；没有基准就没有对照"
```

`compare.json` 的 `counts_are_not_intelligence` 块只放三组计数与一句 note：

| 字段 | 内容 | 说明 |
|---|---|---|
| `actions_proposed.research` / `.single_fuzz` | 两臂提出的动作数 | 拿不到就是 `null`，不填 0（纯事件臂即 `null`） |
| `actions_per_candidate.*` | `proposed / candidates`；`candidates <= 0` 或缺失 → `null` | 分母是 0 时不给“无穷效率” |
| `rounds.research` / `.single_fuzz` | 两臂轮数 | 单次 fuzz 臂没有轮次概念 → `null` |
| `note` | 上面那句常量 | 原样进 markdown / html |

渲染侧各出现一次：`report.md` 的「研究进展」小节写“动作数只记工作量，不推断智能”，
`report.html` 的同一节写“动作数与轮数只记工作量，不推断“更聪明””；
`verdict` 与包级 `_pack_verdict` 都不读这些计数。

### 1.2 为什么 `compare` 的 `verdict` 只能是 `not_evaluated`

对照实验的输入是“一次研究循环”对“一次单次 fuzz”。用它去回答“研究循环是否更好”，
至少要三样现在没有的东西：同一任务上的多次重复（样本量）、预先登记的判定阈值、
以及在两臂之间保持一致的执行预算与目标版本。它们一项都不在本批范围内，所以：

1. `compare.py` 的模块 docstring 把这条写在第 1 条口径里：“`verdict` 恒为
   `"not_evaluated"`；不写任何自我裁决字段，也不调用 `verify`”；
2. `compare_arms()` 与 `build_compare()`（含异常降级路径）都写 `"verdict": "not_evaluated"`；
   `render_markdown()` 把它渲染成“结果判定：`not_evaluated`（只记事实，不出结论）”；
3. `doc["note"]` 固定为
   `"对照实验只比事实；本文件不产漏洞结论，裁决字段一律不在此产生"`（`NOTE` 常量）；
4. 唯一能产生裁决的地方仍是 `verifications` / `reviews`；研究报告的 `verification_allowed`
   只表示“可以交给 `verify`”，`_research_block` 原样转述成 `verification_allowed`
   而不换算成任何结论；
5. `test_casepack_never_forges_verified_or_confirmed` 对整包每个文件扫
   `"(verified|confirmed)": true`，并对逐行出现的 `confirmed` 要求必须是否定句。

换句话说：**这条链上没有任何一处把“跑得多”翻译成“更可信”**，也没有一处替 `verify` 提前签字。

---

## 2. CasePack 追加的六个文件

只在任务目录下存在 `research.json` 时才追加；五个派生文档同源（同一份 `research.json`
+ 本任务事件 + 本任务证据清单 + 既有验证/复核台账），**不含时间戳**、键集合固定
（`_pick()` 缺字段给 `None`、键永远在），因此同一批输入重算字节相同。

| 文件 | schema | 关键字段 | 确定性口径 |
|---|---|---|---|
| `research.json` | `vulnmap.research.run.v1` | 研究报告原文（`controller.rounds` / `controller.timeline` / `rounds` / `executions` / `candidates` / `stop_reason` / `verification_allowed`） | **原样复制字节**（`research["bytes"]`），保留它自带的 `generated_at`；包内 sha256 = 盘上 sha256 = `research.mapped.report_sha256` |
| `research/timeline.json` | `vulnmap.casepack.research.timeline.v1` | `state` / `controller_state` / `stop_reason` / `rounds` / `max_rounds` / `timeline[]{round,phase,status,detail}` / `phases[]{phase,count,statuses}` / `phase_order_ok` / `counts{phases,rounds,distinct_phases}` / `note` | 阶段行按 `controller.timeline` 原序；`phases` 按阶段名排序；`statuses` 是计数 dict；`phase_order_ok` 与 `adaptive.controller.PHASES` 比对（导入失败 → `null`，不当通过；`AUTHORIZE` 允许越位，因为它是授权回调）；`controller: null` 时 0 行、`counts` 全 0 |
| `research/rounds.json` | `vulnmap.casepack.research.rounds.v1` | 每轮 `round` / `facts_hash` / `diagnosis{code,severity,candidates,reasons,evidence_refs}` / `plan{actions,requests,revision,note}` / `actions[]{action_id,tool,status,reason,hypothesis_id,evidence_refs}` / `revision` / `build` / `smoke` / `engineering{scope,adopt,subject,failed,reasons}` / `adopted` / `reverted` / `compare{status,comparable,reason,metric,delta,verdict}` / `invalidations` / `stop_reason` / `note` / `evidence_refs`；外层 `counts{rounds,adopted,reverted,candidate_rounds,actions,action_status}` | 动作/构建/冒烟只摘固定键；`evidence_refs` 用 `sorted(set(...))`；`action_status` 用 `dict(sorted(...))`；负结果（未采纳、被回退、Δ=0、无候选）一条不删 |
| `research/decisions.json` | `vulnmap.casepack.research.decisions.v1` | `engineering{adoptions[],round_decisions[],invalid[],counts}` / `research_progress{rounds,executions,executions_applied,executions_failed,observed_rounds,candidates,actions,action_status,stop_reason,controller_state,verification_allowed}` / `vulnerability{verifications,verified,reviews,accepted,note}` | 采纳账读 `<ws>/store/adoptions.jsonl`（只读、按行号定位）；`scope != "engineering"` 或坏行进 `invalid`，不静默丢；`round_decisions` 只收 `scope` 或 `adopt` 有值的轮次；三段各自独立 |
| `research/evidence_refs.json` | `vulnmap.casepack.research.evidence_refs.v1` | `counts{refs,unique,registered,resolved,unresolved,invalid}` / `refs[]{ref,round,action_id,tool,source,registered,present,hash_ok,kind,path}` / `unresolved[]{ref,reason,referenced_by}` / `invalid[]` / `note` | 引用只有**在本任务** `task_evidence` 里登记过才算命中；跨任务同名哈希进 `unresolved`（`not_registered_for_this_task`）；非 64 位十六进制进 `invalid`（`not_sha256`）；`refs` 按 `(round, action_id, source, ref)` 排序，`unresolved`/`invalid` 按 key 排序 |
| `compare.json` | `vulnmap.adaptive.compare.v1` | `arms{research,single_fuzz}` / `comparable` / `comparability{comparable,reasons}` / `metrics[]`（五项）/ `counts_are_not_intelligence` / `rounds[]` / `negative_results[]` / `verdict` / `note` / `label` / `task_id` | 不写事件 `ts`（只用来算时长）；`arms` 是纯 JSON 深拷贝；`negative_results` 顺序 = 指标顺序 + 轮次顺序 + 可比性原因顺序 |

### 2.1 `casepack.json` 里的 `research` 块（18 个键）

| 键 | 有产物（`status="ok"`） | 无产物（`status="absent"`） |
|---|---|---|
| `status` | `"ok"` | `"absent"` |
| `path` | `"research.json"` | `""` |
| `sha256` | 包内文件哈希（= 源文件哈希） | `""` |
| `recorded_sha256` | `research.mapped` 里登记的值（没登记为 `""`） | `""` |
| `match` | `true` / `false` / `null`（见 §4.2） | `null` |
| `task_id` | 报告里的任务号 | 打包入参 |
| `state` | 报告 `state` | 不出现 |
| `controller_state` | 报告 `controller_state`（`controller: null` 时为 `""`） | 不出现 |
| `controller_absent` | `doc["controller"] is None` | 不出现 |
| `rounds` | `timeline.counts.rounds`（`controller: null` 时 0） | `0` |
| `executions` | 报告 `executions` | `0` |
| `candidates` | 报告 `candidates` | `0` |
| `stop_reason` | 报告 `stop_reason` | `""` |
| `verification_allowed` | 报告事实（不等于已验证） | `false` |
| `phase_order_ok` | 时间线比对结果 | 不出现 |
| `files` | 六个研究产物相对路径 | `[]` |
| `compare` | `{verdict, comparable}` 两项摘要 | 不出现 |
| `note` | “原样复制 + 确定性派生 + allowed 不是已验证” | “没有研究产物：run --research 之后才有轮次可打包” |

absent 分支是上面 18 键的**子集**（13 个键），不带 `state` / `controller_state` /
`controller_absent` / `phase_order_ok` / `compare`。

`casepack.json` 顶层另有两处研究相关字段：

- `research_files`：六个相对路径的列表（无产物时 `[]`）；
- `counts.research_files`：`6`（无产物时 `0`）；
- 顶层 `compare`：`_compare_summary()` 产出的**摘要**，不是第二份事实——
  `{schema, file:"compare.json", verdict, comparable, metrics[{metric,known,delta}],
  negative_results: <条数>, note:"摘要；完整对照文档见 compare.json，两处不各自记一套事实"}`；
  无产物时 `{schema, file:"", verdict:"not_evaluated", comparable:false, note}`。
  完整文档只有 `compare.json` 一份。

---

## 3. 内容哈希口径的变化

`content_sha256` 的定义没变：
对**除 `casepack.json` 自身以外**本次生成的 `(相对路径, sha256, size)` 有序列表
按 `json.dumps(..., indent=2, sort_keys=True) + "\n"` 取 sha256。变的是**列表长度**：

| 场景 | 进包文件 | `content_sha256` 覆盖 |
|---|---|---|
| 无研究产物 | `FILES` 原样 9 个（`task.json` / `state.json` / `events.jsonl` / `candidates.json` / `verifications.json` / `reviews.json` / `evidence/manifest.json` / `report.md` / `report.html`） | 9 个 |
| 有研究产物 | 上述 9 个 + `research_files()` 的 6 个 | 15 个 |

- `FILES` **没有被改写**：没有研究产物的任务，包清单与 P3 完全一致，哈希口径不受影响；
- `research_files(research=None)`：`research_files()` → `()`，`research_files(bundle)` → 六个相对路径；
  由 `build_casepack` 用 `research_bundle` 传进来；
- 生成列表是 `tuple(FILES) + research_files(research_bundle)`，`files` 按 `path` 排序后算哈希，
  所以两个场景都不会因为拼接顺序产生不同结果；
- **`reports` 台账**：`store.save_report(report_id, task_id, str(out), content_sha256)` 的 `sha256`
  列就是 `content_sha256`（台账 ↔ 磁盘的唯一纽带）；
  `_record_report_html` 幂等补 `reports.report_html_sha256` 列，存 `report.html` 单文件哈希，
  这样“台账 → 包 → 网页”三段能单独对上，而 `SCHEMA_VERSION` / `PRAGMA user_version` 仍是 4；
- **`report.ready` 事件**（提交后事件）payload 里带 `content_sha256`、`report_html_sha256`、
  `files`（15 或 9 个路径）、`counts`、`verdict`，以及
  `research{status, sha256, files}`——验收时不必打开包就能知道这一包有没有研究产物；
- `casepack.json` 自身：`generated_at` 存在、`path` 是绝对路径，因此它**不参与**
  `content_sha256`（`SELF_FILE` 被排除），派生文档里也不写它。

---

## 4. 冲突即拒绝（不半写），以及“哪些不算冲突”

`load_research()` 在**写盘之前**跑完四道校验，任何一道不过就 `CasePackError`：

| 冲突 | 拒绝点 | 消息关键词 |
|---|---|---|
| 不是合法 JSON（含非 UTF-8） | `json.loads` 失败 | `不是合法 JSON` |
| 顶层不是对象 | 类型检查 | `顶层必须是对象` |
| `schema` 不认识 | `!= vulnmap.research.run.v1` | `schema 不认识` |
| 属于别的任务 | `task_id` 与打包入参不一致 | `属于另一个任务` |
| `controller` 既不是对象也不是 `null` | 类型检查 | `controller 必须是对象或 null` |
| `controller` 是对象但 `rounds` / `timeline` 不是列表 | 结构检查 | `controller.rounds` / `controller.timeline` `必须是列表` |
| 与 `research.mapped.report_sha256` 不一致 | `_recorded_report_sha()` 取**最后一条** `report_path` 与本次路径相同的事件 | `sha256 不一致` |

### 4.1 不算冲突：`controller: null` 是合法产物

`run_research` 在“执行前预算预检就耗尽”时写出的 `research.json` 就是
`controller: null` + `rounds: 0`——**控制器没跑，这是真产物，不是坏报告**。
`load_research()` 只在 `controller` 是对象时才校验 `rounds` / `timeline` 是列表，因此打包接受它：

| 落点 | 结果 |
|---|---|
| `casepack.json.research.status` | `"ok"` |
| `casepack.json.research.rounds` | `0` |
| `casepack.json.research.controller_absent` | `true` |
| `research/timeline.json` 的 `counts` | `{phases: 0, rounds: 0, distinct_phases: 0}` |
| `research/rounds.json` 的 `counts` | 全 0（`rounds` / `actions` / `adopted` / `reverted` / `candidate_rounds`） |
| `report.md`「研究进展」 | 控制器显示 `—`、停止原因照抄、轮次 0；不编轮次 |

与 P4a 的口径不同，且这个差异是有意的：P4a 的只读视图要求“可渲染轮次”，
`vulnmap_platform/api/platform_research.py::load_report` 对 `controller` 不是 Mapping 的报告
一律 `409 research report has no controller block`
（见 [V3-P4-API-TIMELINE.md](V3-P4-API-TIMELINE.md) §3.1 的 409 列与 §5 校验表）；
归档要求“保住真产物”，所以 CasePack 接受它并按 0 轮如实打包。

### 4.2 `match` 的三个取值

| 值 | 含义 | 会不会出现在包里 |
|---|---|---|
| `true` | 与 `research.mapped` 里登记、且 `report_path` 对得上的 `report_sha256` 一致 | 会 |
| `false` | 不一致 → `load_research()` 已抛 `CasePackError`，打包根本不会完成 | **不会**（包内不出现 `false`） |
| `null` | 事件流里没有 `report_path` 对得上的登记（例如产物被 `--research-root` 放到别处且没发事件） | 会 |

三条附带口径：

1. **只认登记过的那一条路径**：`_recorded_report_sha()` 只认 `report_path == 本次读取路径`
   的事件，取**最后一条**；没登记过（`recorded == ""`）时**不判定不一致**，`match` 如实给 `null`，
   而不是伪造 `true`；
2. **不猜“更像新的”轮次**：哈希不符就是说产物被改写或不是同一轮，不试图找另一份报告顶替；
3. **“不半写”的口径**：`load_research` 在 `out.mkdir()` 与任何 `_write` 之前执行，
   所以失败时既没有包目录、也没有 `casepack.json`、也没有 `reports` 台账行
   （`store.list_reports(task_id) == []`）。唯一可能已经发生的是 `REVIEW → REPORTED`
   状态迁移——它发生在读取研究产物之前，属于既有 P3 行为（测试因此允许状态停在
   `REVIEW` / `NO_REPRO` / `REPORTED`）；
4. `require_research=True` 时“没有 `research.json`”本身也是错误（消息提示
   `run <task> --research`）；默认 `False`——研究循环从没跑过不是错误，包内 `status` 记 `absent`。

---

## 5. compare.py：五个指标与公式

两个臂：`research`（研究循环）、`single_fuzz`（单次 fuzz）；臂标签 `研究循环` / `单次 fuzz`。
所有入口对坏输入都是“降级成未知”，不抛未捕获异常（`build_compare` 兜底成双臂全未知 +
`error:<TypeName>` 记在 `notes`）。

| 指标 | 事实来源 | 公式 / 规则 | 方向 |
|---|---|---|---|
| `time_to_first_crash` | 事件：优先 `exec.finished.payload.fuzz.first_crash_seconds`（`metric_kind="fuzz_seconds"`）；否则用事件 `ts`（ISO8601）算首个 `candidates>0` 的 `exec.finished` 减首个 `exec.started`（`metric_kind="wall_clock_seconds"`） | 有多条 `first_crash_seconds` 取 `min`；两种口径**只各自比**，跨口径 → `metric_kind_mismatch` 且 `known=false`；都没有 → `null` + `no_clock_facts` | 越低越好 |
| `coverage` | 报告：`controller.final.coverage` 优先，缺项用最后一条轮 `compare` 的 `covered/uncovered/delta` 补；事件：最后一条带数字 `coverage` 的 `exec.finished` | 比较时 `delta` 优先，两侧都有 `delta` 才用它；否则退回 `covered`（JSON 里 `basis` 记 `"delta"` / `"covered"`）；一个数字都没有 → 三项全 `null` + `no_coverage_facts`。`delta == 0.0` 是**事实** | 越高越好 |
| `candidates` | 报告顶层 `candidates`；事件：逐条 `exec.finished.payload.candidates`（int 直接取、list 取 `len`）累加 | 两臂都取自“顶层字段”（不是带 `known` 的子块）；缺失 → `no_candidate_facts` | 越高越好 |
| `action_acceptance` | 报告逐轮 `actions[]` 的 `status` | `applied / proposed`，`proposed = applied + rejected + skipped + failed + unknown`（`noop` 与 `applied` 同属被采纳，见 `ToolOutcome.applied`）；`proposed == 0` → `null` + `no_actions` | 越高越好 |
| `repeat_rate` | `repeats.same_facts`（报告轮记录里同一 `facts_hash` 的重复次数）+ `repeats.skipped_actions`（`status == "skipped"` 的动作数） | `(same_facts + skipped_actions) / (rounds + proposed)`；上限截到 `1.0`；分母 ≤ 0 → `null` + `no_rounds_or_actions` | 越低越好 |

可比性判定（`compare_arms`）：

- 两侧同名指标都 `known=True`，且 `metric_kind` 一致，才 `known=True`；
- 只一侧有事实 → `reason` 取缺那一侧的原因；两臂都缺且原因不同 → `"a|b"` 连接，两侧原因都留下；
- `delta = treatment - baseline`；`ratio = treatment / baseline`，`baseline == 0` 时 `ratio = null`（**不是** `inf`）；
- `|delta| <= 1e-9` → `same`；否则按方向极性给 `better` / `worse`。

### 5.1 `known=false` + `reason` 清单

| 情形 | reason | 出处 |
|---|---|---|
| 报告中没有任何时钟事实 | `no_clock_facts` | `metrics_from_report` 恒附 `report_has_no_clock` 说明（报告本来不记首次崩溃秒数） |
| 事件里有 `exec.finished` 但没有可算的崩溃时刻 | `no_crash_seen` / `no_exec_finished`（`notes`） | `metrics_from_events` |
| 事件里算了墙上时钟 | `time_from_wall_clock`（`notes`），值本身 `known=true` | 同上 |
| 覆盖率没有任何数字 | `no_coverage_facts` | 两个入口的 `_coverage_block` |
| 覆盖率登记了口径但不在 `branch/edge/bits`（含别名）里 | `coverage_metric_kind_unmapped`（`notes`），`metric_kind` 留空 | `metrics_from_events` |
| 候选数缺失 | `no_candidate_facts` | `_values("candidates")` |
| 报告臂“有轮次但一个动作都没提” | `no_actions` | `metrics_from_report`（`proposed == 0`） |
| 臂完全没拿到动作账（含纯事件臂） | `no_action_facts` | `_blank_arm` 的默认值，`metrics_from_events` 不改它 |
| 轮次或动作缺失、或分母 ≤ 0 | `no_rounds_or_actions` | `repeat_rate` 计算 |
| 没有基准臂 | `no_baseline`（同时进 `comparability.reasons` 与 `notes`） | `_looks_absent` + `build_compare` |
| 两侧没有任何一个可比指标 | `no_shared_metric` | `compare_arms` |
| 两侧口径不同 | `metric_kind_mismatch`（时间与覆盖率都适用） | `_metric_row` |

`notes` 里另外会出现 `no_report` / `report_not_mapping` / `empty_report` / `rounds_unknown` /
`candidates_unknown` / `actions_unknown` / `facts_hash_absent` / `coverage_unknown` /
`no_events` / `no_exec_started` / `events_have_no_actions` /
`from_events:<key>` / `baseline=provided|absent` / `error:<TypeName>`。

### 5.2 逐轮账（`rounds[]`）

每轮一行：`round` / `coverage_delta` / `candidates`（该轮动作里 `candidates` 累加）/ `actions_applied` /
`gain` / `note`。`gain` 的判定：无 `delta` → 有候选则 `candidate` 否则 `unknown`；
`|delta| <= 1e-9` → 有候选则 `candidate` 否则 `none`；`delta != 0` → 有候选则 `both` 否则 `coverage`。
它回答“这一轮动了什么”，不回答“有没有效”。

### 5.3 渲染

`render_markdown(doc)` 输出一段可直接拼进 `report.md` 的片段（`casepack._compare_md()` 是
唯一调用方，markdown 口径只有一处）：标题 `## 对照实验（研究循环 vs 单次 fuzz）`、
`- 结果判定：not_evaluated（只记事实，不出结论）`、可比性、不可比原因、
一张七列表（指标 / 研究循环 / 单次 fuzz / Δ / 方向 / 可比 / 说明）、
`### 动作次数不是智能`、`### 逐轮账（研究循环）`、`### 负结果`。
表里未知一律写 `未知`（不写 0）；数值用 `f"{v:.6f}".rstrip("0")`，
所以 `0.0` 显示为 `0.0`、`3/5` 显示为 `0.6`。

> 渲染取舍：某行 `known=false` 时，时间与覆盖率两列**两侧都显示 `未知`**，
> 即使一侧其实有数字（真实值仍在 `compare.json` 的 `treatment` / `baseline` 里）。
> 这是“不可比的行不并列数字”的呈现选择，不是数据丢失。

---

## 6. 负结果保留：未知不填 0，零增益不隐藏

| 情形 | 怎么留 | 具体落点 |
|---|---|---|
| 未知指标 | `null` + `known=false` + `reason`，**绝不填 0**；同时进 `negative_results[{"item": <metric>, "reason": ...}]` | 例：报告侧首次崩溃耗时恒为 `null`（报告不记秒数），事件补上才算事实 |
| 两臂都不可比 | `comparable=false`，`comparability.reasons` 列**全部**原因（`no_baseline`、每个 `<metric>:<reason>`、`no_shared_metric`），一条不省略 | `build_compare` 追加 `{"item":"compare","reason":"no_baseline"}` / `no_shared_metric` |
| Δ=0 的轮次 | `rounds[]` 里保留 `coverage_delta = 0.0`，并追加 `negative_results[{"item":"round:2","reason":"coverage_delta_zero"}]` | `_round_negatives`；`gain == "none"` 的轮次记 `no_gain` |
| 被跳过 / 被拒的动作 | `actions` 分桶里 `skipped` / `rejected` 各占一格，`action_acceptance` 的分子只算被采纳的 | `_action_counts` |
| 重复事实 | `repeats.same_facts` 与 `repeat_rate` 直接体现“这轮没带来新事实” | 轮记录里 `facts_hash` 相同即计入 |
| 没有基准 | 不补 0、不补空臂：`comparable=false` + `no_baseline`，`counts_are_not_intelligence` 的 `single_fuzz` 侧为 `null` | `_looks_absent` |
| 报告没给 `facts_hash` | `same_facts = 0` 并写 `facts_hash_absent`（说明这是“没观测到重复”，不是“确定无重复”） | `metrics_from_report` |
| 研究产物缺失 | 包内 `status="absent"`、不写空轮次、`report.md` / `report.html` 写明“字段如实缺失” | `_research_block` / `_render_research_md` |

关于 `0` 的三条硬规则：

1. `coverage.delta == 0.0`、`candidates == 0`、`first_crash_seconds == 0` 只要是被记录下来的读数，
   就按事实处理，照常参与 Δ 与 `same` 判定；
2. `ratio` 的分母是 0 时给 `null`，不给 `inf`，也不给一个“很大”的数；
3. `known=false` 的字段永远进不了 `delta`——`test_compare_five_metrics_follow_contract_formulas`
   对 `action_acceptance.delta` 直接断言“未知一侧的 Δ 不能写成 0”。

---

## 7. 报告里的三个小节

`report.md` 的小节顺序（`_render_report`）：

```text
# Case Pack: <task>
## 任务
## 事件流
## 研究进展          ← 轮次表 / 阶段汇总 / 动作状态计数（标注“不推断”）
## 对照实验（研究循环 vs 单次 fuzz）   ← compare.render_markdown() 原文（有研究产物时）
## 候选
## 工程采纳          ← adoptions.jsonl + controller 轮决策（scope=engineering）
## 漏洞验证          ← 唯一裁决来源：verifications / reviews
## 复核
## 证据清单
## 口径声明
```

`report.html` 的 `<h2>` 顺序：包级摘要 → 事件流 → **研究进展** → **对照实验** → 候选 →
**工程采纳** → **漏洞验证** → 复核 → 证据清单 → 口径声明。三段各自渲染：

| 小节 | 渲染函数 | 只讲什么 | 明确不讲什么 |
|---|---|---|---|
| 研究进展 | `_render_research_md` + `_compare_md` | 报告 sha256 与 `research.mapped` 是否一致、控制器状态/停止原因/轮次/执行/候选、阶段顺序、阶段汇总、逐轮诊断/候选/动作数/采纳/回退/覆盖 Δ、动作状态计数、五指标对照与负结果 | 有没有漏洞 |
| 工程采纳 | `_render_decisions_md` | 采纳口径（能构建、冒烟不假阳性、执行有观测）、`adoptions.jsonl` 与 `controller.round` 两类来源的 adopt/failed/reasons、无效采纳记录条数 | 漏洞结论、动作次数当能力 |
| 漏洞验证 | `_render_vulnerability_md` | 验证记录/复核条数与 `verified`/`accept` 计数、研究循环 `verification_allowed` 只作转述、逐条验证表 | 工程采纳、采纳率、动作次数 |

`verification_allowed=true` 时，漏洞验证段仍显示“只表示可以交给 verify，未验证”；
`_pack_verdict()` 只从 `verifications` / `reviews` 数数，研究循环的轮次与动作不进这个函数。

`report.html` 的可复算口径（沿用 P3，**已裁定**）：

| 条件 | 现状 |
|---|---|
| 无 `<script>` | 模板中 0 处 |
| 无外部资源 | 0 个 `<link>`、0 个 `http(s)://`、0 个 `src=` |
| 样式内联 | 单个 `<style>` 块 + `:root{color-scheme:light}` |
| 无渲染时间戳 | 模板里没有任何时间字段 |
| 台账里的字段一律转义 | 全部经 `_h()`（`html.escape(..., quote=True)`） |
| 确定性口径 | `report.html` 是**它所记录的那批台账快照**的确定性函数：用包自身记录的快照重渲染，逐字相同；不是“同一任务连续两次打包字节相同” |

> 为什么不是“连续打包字节相同”：页面渲染“事件数”，而打包本身会 append 一条
> `report.ready`，所以第二次打包看到的快照就多一条事件。这条差异**不是**不确定性，
> 是 P3 已定的口径（html 是快照的函数）；包内 `report.html` 的 sha256 与
> `reports.report_html_sha256` 始终与各自那一包对齐。

---

## 8. 测试（`tests/test_v3_p4_report.py`）

8 个测试函数，`test_casepack_rejects_conflicting_research_artifacts` 参数化 4 条，共 11 条用例；
全部离线：真实 SQLite（临时 `PLATFORM_ROOT`）、真实 `build_casepack`、真实 `compare` 模块，
研究报告由**真实 dataclass**（`ControllerResult` / `RoundRecord` / `Diagnosis` / `Decision`）
拼出后落盘，不碰仓库 `.platform`。

| 用例 | 断言要点（按当前测试文件） |
|---|---|
| `test_casepack_packs_research_artifacts_with_recomputable_hashes` | 9 个基础文件 + 6 个研究产物都在包内且都进 `files`；`set(RESEARCH_RELS) <= set(research_files(pack_doc["research"]))`；`research.json` 字节等于源文件；逐文件 `sha256`/`size` 与磁盘一致；`research` 块 11 个必备键 + `status="ok"` + `task_id` + `sha256 == 源文件哈希` + `recorded_sha256 == sha` + `match is True` + `rounds=3/executions=2/candidates=1/stop_reason="repeated_facts"/verification_allowed=false`；`content_sha256` 可由 `files` 复算；`reports` 台账 sha 与之相等；`timeline.phases` 含 `OBSERVE`/`STOP`；`rounds` 三轮且每轮含 `diagnosis/plan/actions/compare/adopted/reverted/invalidations/evidence_refs`；`decisions` 有 `adoptions` 账、所有 `scope` ⊆ `{engineering}`、**独立分离段**按 `{verifications, verified, reviews}` 三键定位且 `verifications=0`/`verified=0`；`evidence_refs` 命中已登记证据、未登记引用也列出且 `registered/hash_ok` 均假并带 `reason`；`compare.json` 是 `vulnmap.adaptive.compare.v1`、`verdict=not_evaluated`、五项顺序正确 |
| `test_casepack_without_research_keeps_base_files_and_reports_absent` | `files` 恰好等于 `FILES`；`research` 块必备键齐全且 `status="absent"`、`sha256`/`recorded_sha256` 为空、`match in (False, None)` 且 `match is not True`、计数 0、`verification_allowed=false`、无 `research/` 目录、`casepack.json` 文本里没有 `timeline`、`tuple(research_files(None)) == ()` |
| `test_compare_five_metrics_follow_contract_formulas` | 报告臂：`rounds=3`、`executions=2`、`candidates=1`、`stopped=repeated_facts`、`actions={proposed:5,applied:3,rejected:1,skipped:1,failed:0,unknown:0}`、`action_acceptance=3/5`、`same_facts=2`、`repeat_rate=(2+1)/(3+5)` 且 ≤1、`coverage.covered=5/uncovered=7/delta=0.0`、`time_to_first_crash` 未知且 `!= 0`；事件臂：`executions=1`、`candidates=3`、首次崩溃 `1.5` 且 `metric_kind=fuzz_seconds`、`coverage.covered=12`（取最后一条）、采纳率 `known=false` 且带 `reason`、重复率 `no_rounds_or_actions`；另造“有轮次无动作”的报告断言 `proposed=0` → `action_acceptance.reason == "no_actions"`；合并：`source="report+events"`、已知覆盖不被事件盖掉；对照：五指标顺序、`candidates.delta=-2`/`ratio≈1/3`/`worse`、未知侧 `delta is None`、`counts` 的 `single_fuzz` 侧 `in (0, None)`、note 含“工作量/不推断”、整篇无 `verified`/`confirmed` 键 |
| `test_compare_keeps_negative_results_and_comparability_reasons` | 无基准：`comparable=false`、`reasons` 与 `notes` 都含 `no_baseline`；轮 2/3 `coverage_delta == 0.0` 且 `gain="none"`；`negative_results` 非空、每条都有 `reason`、含指向第 2/3 轮的条目（`_mentions_round` 接受显式 `round` 字段或 item 内轮号）且 reason 含 coverage/delta/gain/zero 之一、含 `time_to_first_crash` 与 `compare`；两臂全空：`no_shared_metric`、全部 `known=false`、`delta`/`ratio` 全 `null`；`fuzz_seconds` 与 `wall_clock_seconds` 混比：`reason` 含 `metric_kind_mismatch`、`delta=null`、`direction="unknown"`，事件侧无 coverage 时 `coverage.reason="no_coverage_facts"` 而非 0 |
| `test_casepack_never_forges_verified_or_confirmed` | 报告 `verification_allowed=true` 时块里照抄 true，但 `verdict.benchmark_verified=false`、`verified=0`、`accepted_by_review=false`；整包逐文件扫 `"(verified\|confirmed)": true` 无命中、且不出现 `"status": "verified"`；逐行出现的 `confirmed` 必须处在否定句里（含 不/未/无/非/not/never/≠）；`report.html` 的 `benchmark_verified` 渲染为“否” |
| `test_report_sections_separate_engineering_verification_and_progress` | `report.md` 有「工程采纳」「漏洞验证」「研究进展」三节（`###` 子标题算本节内容）；`report.html` 的 `<h2>` 含三个标题；“漏洞验证”段不含 `action_acceptance`/`repeat_rate`/`接受率`，且不匹配 `COUNT_CLAIMS`（把采纳/动作次数写成数字结论的四种写法）、不出现结论性 `verified 1`；“研究进展”段含 `轮次…<数字>` 与“动作”字样、并带“不推断/工作量”；“工程采纳”段来自 `engineering`、不含 `confirmed`/`verified` |
| `test_research_artifacts_and_html_are_deterministic` | ①四个派生文档 + `research.json` 两次打包逐字节相同；派生文件不含 `generated_at` 也不含 `"at"` 字段，`research.json` 保留 `generated_at`；②`report.html` 用同一批入参渲染两次字节相同，且等于“用包自身记录的快照（`_pack_snapshot`）重渲染”的字节；页面里 `<dt>事件数</dt><dd><state.events></dd>` 存在、无 `<script`；③第二次打包 `content_sha256 == files 重算 == reports 台账最后一条` |
| `test_casepack_rejects_conflicting_research_artifacts[bad_json]` | 坏 JSON → `CasePackError`，消息含 `json`；无 `casepack.json`、`reports` 为空、状态停在 `REVIEW`/`NO_REPRO`/`REPORTED` |
| `test_casepack_rejects_conflicting_research_artifacts[unknown_schema]` | `schema=vulnmap.research.run.v999` → 错误含 `schema`；同上不半写 |
| `test_casepack_rejects_conflicting_research_artifacts[foreign_task]` | 报告 `task_id` 是别的任务 → 错误含 `任务`/`task`/`belong`；同上不半写 |
| `test_casepack_rejects_conflicting_research_artifacts[hash_mismatch]` | 报告尾巴被改写（与 `research.mapped` 登记不符）→ 错误含 `sha256`/`hash`/`digest`/`哈希`；同上不半写 |

复跑：

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_v3_p4_report.py -q
python3 -m pytest tests/test_v3_p4_api.py tests/test_v3_p2_session.py \
                 tests/test_v3_p2c_research_cli.py tests/test_v3_p3.py -q
python3 -m pytest -q                     # 全量
```

---

## 9. 数字（实测，不预填）

实测环境：Python 3.12.14，pytest 9.1.1，`/home/root_bupt/桌面/file/vulnmap`
（无 `.git`，基线以文件哈希锚定）。下表由同一批命令连续跑完（起测 `2026-11-20 18:35:49 +0800`）；
数字与树绑定：树再变即失效，必须重跑。

| 运行 | 结果 |
|---|---|
| `pytest tests/test_v3_p4_report.py -q` | **11 passed**（0.91s） |
| `pytest tests/test_v3_p4_api.py tests/test_v3_p2_session.py tests/test_v3_p2c_research_cli.py tests/test_v3_p3.py -q` | **67 passed**（7.29s） |
| `pytest -q`（全量） | **1438 passed, 8 skipped**（115.41s） |
| `pytest tests/test_v3_p4_api.py -q`（P4a 基线对照） | **14 passed**（2.56s） |
| `wc -l agent/platform/adaptive/compare.py` | **1087** |
| `wc -l agent/platform/casepack.py` | **1411** |
| `wc -l tests/test_v3_p4_report.py` | **1003** |
| `wc -l docs/V3-P4-REPORT-COMPARE.md` | **633**（本文自身） |
| 有研究产物的包：`files` 条数 | **15**（9 基础 + 6 研究产物） |
| 无研究产物的包：`files` 条数 | **9**（`FILES` 原样） |
| 有研究产物的包：`content_sha256` | 每次打包重算，可由包内 `files` 列表复算；同一批输入重算必得同一值（见 §8 用例 1 与用例 7） |
| 无研究产物的包：`content_sha256` | 同上；**无研究产物时哈希只覆盖 9 个文件** |
| `research.json` 三层哈希（实测一次打包） | 源文件 sha256 = 包内 sha256 = `research.mapped.report_sha256`，三处逐字相同（每次新造 fixture 的源哈希不同，因此这里不写死数字） |

口径：本文不写“提升百分比”之类的数字——`compare` 不产裁决，任何“研究循环比单次 fuzz 好 N%”
都不是这份实现能得出的结论。

> 测准提示：本文写作期间 `compare.py` 行数与全量用例数都在变（1029 → 1087、1423 → 1438），
> 说明树仍在并行推进。复核请以**当次**重跑的输出为准，不要拿本文的数字当基线。

---

## 10. 实现口径与已知边界（只报告，未改代码）

这些是**当前真实实现**的取舍，写在这里是为了让复核者不必从代码里再猜一遍。

| # | 项 | 当前实现口径 | 说明 |
|---|---|---|---|
| 1 | 采纳率未知的两种 reason | 报告臂 `proposed == 0` → `no_actions`；臂完全没拿到动作账（含纯事件臂）→ `no_action_facts` | 契约只写了前一种；两种都表示“没有可算的分母”，测试分别断言 |
| 2 | 事件臂的计数是 `None` 不是 `0` | `counts_are_not_intelligence` 里 `single_fuzz` 的 `actions_proposed` / `rounds` 为 `null` | 契约 §1.4 示例写 0、§0.3 又不许把未知填成 0；实现取 `null`，测试断言 `in (0, None)` |
| 3 | `decisions.json` 的分离段键名是 `vulnerability` | 三段键为 `engineering` / `research_progress` / `vulnerability`，后者内容为 `verifications` / `verified` / `reviews` / `accepted` / `note` | 测试不按键名找，而按 `{verifications, verified, reviews}` 三键定位该段 |
| 4 | `research.compare` 是两项摘要 | `casepack.json.research.compare = {verdict, comparable}`；完整对照只在 `compare.json`；顶层另有一份 `_compare_summary()` 摘要（含五项 `{metric,known,delta}` 与负结果条数） | 三处都只是“摘要/引用”，事实只有 `compare.json` 一份 |
| 5 | `_recorded_report_sha` 只认路径对得上的最后一条 | 只取 `report_path == 本次读取路径` 的 `research.mapped`，取最后一条；没登记 → `recorded=""`、`match=null` | 研究目录可被 `--research-root` 改到别处，事件是唯一知道产物落在哪的记录 |
| 6 | 包内 research 臂通常是 `source="report"` | `_compare_view` 把该任务**全部**事件传进 `build_compare`；`merge_metrics` 只在主文档缺事实时才补，补上了才把 `source` 改成 `"report+events"` | 本次 fixture 的包内 `source="report"`（报告已带 coverage 与 executions、事件也没有 `first_crash_seconds`，没有字段被补） |
| 7 | 覆盖率的可比性也看 `metric_kind` | `_metric_row` 对 `time_to_first_crash` 与 `coverage` 都做口径比对；一侧 `metric_kind=""` 也算不同 → `metric_kind_mismatch` | 契约只对时间写了这条；实现对覆盖率同样保守 |
| 8 | Δ=0 轮次的负结果条目形如 `round:2` | `_round_negatives` 把轮号编进 `item`（`reason="coverage_delta_zero"` / `no_gain`） | 测试用 `_mentions_round()` 接受“显式 `round` 字段”或“item 内含轮号”两种写法 |
| 9 | `report.html` 跨包字节会变 | 页面渲染“事件数”，打包自身 append `report.ready`，第二次打包快照多一条事件 | **已裁定**为 P3 口径：html 是所记录快照的确定性函数（见 §7） |
| 10 | `bin/platform.py casepack` 未暴露三个新参数 | CLI 只有 `--out` / `--evidence-root` / `--close`；`research_root` / `baseline` / `require_research` 只能从 Python API 传 | 见 §11 第 3 条：基准臂目前只能由调用方在代码里给 |
| 11 | 契约未写、实现已有的可选字段/能力 | 指标行额外带 `unknown_arms`、`basis`、`metric_kind{baseline,treatment}`；`COVERAGE_KINDS` 收 `branches/edges/bit` 等别名；`merge_metrics` 还补 `applied`/`failed`；`_report_rounds` 会退回报告顶层 `rounds` 列表；报告覆盖率优先 `controller.final.coverage`；`phase_order_ok` 允许 `AUTHORIZE` 越位、导入失败给 `null`；`metrics_for_store()` 便捷函数 | 都是“多给事实”，不改语义 |

---

## 11. 仍然没做（本轮边界）

1. **`compare` 只做“单任务对单基准”，不产裁决**：一次比一个任务的 `research.json`
   对一份调用方给的单次 fuzz 事实；`verdict` 恒为 `not_evaluated`，不做显著性、不给结论、
   不替换 `verifications` / `reviews`。
2. **`casepack` 不跑研究循环、不补证据**：打包只读盘上已有的 `research.json`；没有产物就记
   `absent`，不替你跑 `run --research`；`evidence_refs` 只解析**本任务**已登记过的哈希，
   未登记引用进 `unresolved`，不回头补登记、不复制 blob。
3. **`baseline` 必须调用方显式给**：`build_casepack(baseline={...})` 的
   `{"label","report","events"}` 三件都由调用方准备；缺省即“没有基准”
   （`comparable=false` + `no_baseline`），绝不从别处借一条基线。**CLI 侧没有这个参数**
   （`bin/platform.py casepack` 只有 `--out` / `--evidence-root` / `--close`），
   所以从命令行打不出带基准臂的包，基准臂目前只能从 Python API 传。
4. **不做跨 campaign / 跨任务的聚合**：没有“这批任务平均如何”“多个 campaign 对比”；
   一次一个任务，包与包之间不互相引用。
5. **没有 HTTP 视图与页面**：`compare.json` 只在包内，P4a 的三条只读 GET 不返回对照实验；
   页面也不画这张表。
6. **时间指标在报告单臂上恒缺**：`research.json` 不记“首次崩溃秒数”，只从报告出发
   `time_to_first_crash` 永远是 `no_clock_facts`；要它已知，必须把事件流一起传进
   `build_compare`（且事件里真有 `fuzz.first_crash_seconds` 或可算的 `ts`）。
7. **事件臂没有动作与事实哈希**：`metrics_from_events` 的 `repeats` 恒为 0 并写
   `events_have_no_actions` / `rounds_unknown`；纯事件臂的采纳率与重复率不可得。
8. **`phase_order_ok` 的漂移检测是“未知不算通过”**：`adaptive.controller` 导入失败时给
   `null`，不冒充 `true`；但也没有把漂移做成错误。
9. **`controller: null` 的产物只能“按 0 轮归档”**：不接受它的轮次视图能补出轮次（也不该补），
   P4a 的只读端点对它仍是 `409`；两边口径不同是有意的，见 §4.1。
10. **`adoptions.jsonl` 之外的采纳来源没有**：工程采纳只认这份台账与控制器轮决策；
    `scope` 不是 `engineering` 的行进 `invalid`，不改写、不搬运。

---

## 12. 怎么复核

下面每条命令都已在当前树上跑过，输出见各步之后的注释（占位符只有仓库路径）。
演示数据由测试 fixture 现造，只写 `/tmp`，不碰仓库 `.platform`。

```bash
cd /home/root_bupt/桌面/file/vulnmap
export P4B=/tmp/p4b-check && rm -rf "$P4B"

# ① 造一个演示任务（复用测试 fixture：真 SQLite + 真 research.json + 真事件）
python3 - <<'PY'
import importlib.util, os, sys
from pathlib import Path
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("t", "tests/test_v3_p4_report.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
root = Path(os.environ["P4B"]); root.mkdir(parents=True, exist_ok=True)
store, bus, rs_root, report, sha = t._research_fixture(root)
print("db:", store.path, "\ntask:", t.TASK, "\nreport:", report, "\nsha256:", sha)
PY
# → db: /tmp/p4b-check/platform/platform.db
# → task: task-v3-p4b
# → report: /tmp/p4b-check/platform/research/task-v3-p4b/research.json
# → sha256: <64 位十六进制>（每次造新 fixture 都不同）

export DB=$P4B/platform/platform.db TASK=task-v3-p4b

# ② 打包（有研究产物 → 15 个文件）
python3 bin/platform.py --db "$DB" casepack "$TASK" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("files:", len(d["files"]), "| research:", d["research"]["status"], "| match:", d["research"]["match"], "| controller_absent:", d["research"]["controller_absent"], "| content_sha256:", d["content_sha256"])'
# → files: 15 | research: ok | match: True | controller_absent: False | content_sha256: <每次打包重算，下一步复算>

# ③ 逐文件哈希 + content_sha256 复算 + research 块形状
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
out = Path(os.environ["DB"]).parent / "casepacks" / os.environ["TASK"]
pack = json.loads((out / "casepack.json").read_text("utf-8"))
bad = [f["path"] for f in pack["files"]
       if hashlib.sha256((out / f["path"]).read_bytes()).hexdigest() != f["sha256"]]
print("哈希不符:", bad)
listed = sorted(pack["files"], key=lambda f: f["path"])
body = json.dumps(listed, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
print("content_sha256 可复算:", hashlib.sha256(body.encode()).hexdigest() == pack["content_sha256"])
print("research 块键数:", len(pack["research"]),
      "| research_files:", pack["research_files"],
      "| counts.research_files:", pack["counts"]["research_files"])
print("compare 摘要 metric 行:", json.dumps(pack["compare"]["metrics"], ensure_ascii=False))
PY
# → 哈希不符: []
# → content_sha256 可复算: True
# → research 块键数: 18 | research_files: ['research.json', 'research/timeline.json', ...] | counts.research_files: 6
# → compare 摘要 metric 行: [{"delta": null, "known": false, "metric": "time_to_first_crash"}, …]

# ④ 三层哈希对齐：源文件 = 包内 = 事件登记
sha256sum "$P4B/platform/research/$TASK/research.json" \
          "$P4B/platform/casepacks/$TASK/research.json"
python3 - <<'PY'
import json, os, sqlite3
conn = sqlite3.connect(os.environ["DB"])
rows = [json.loads(r[0]) for r in conn.execute(
    "select payload_json from task_events where event_type='research.mapped'")]
print("research.mapped:", [(r.get("report_sha256"), r.get("report_path")) for r in rows])
PY
# → 两个 sha256sum 行相同；research.mapped 的 report_sha256 与之相同

# ⑤ 五指标对照（不读库，只喂 dict）：verdict 必须是 not_evaluated
python3 - <<'PY'
import json, os
from pathlib import Path
from agent.platform.adaptive.compare import build_compare, render_markdown
root = Path(os.environ["DB"]).parent / "research" / os.environ["TASK"]
doc = build_compare(research_report=json.loads((root / "research.json").read_text("utf-8")))
print(doc["verdict"], doc["comparable"], doc["comparability"]["reasons"])
print(render_markdown(doc))
PY
# → not_evaluated False ['no_baseline', 'time_to_first_crash:no_clock_facts', …]
# → 表里未知写“未知”，负结果列出 round:2 / round:3 的 coverage_delta_zero

# ⑥ 冲突即拒绝：改写报告 → CasePackError（exit 2），且不留包、不写台账
rm -rf "$P4B/conflict"
python3 - <<'PY'
import importlib.util, os, sys
from pathlib import Path
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location("t", "tests/test_v3_p4_report.py")
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
t._research_fixture(Path(os.environ["P4B"]) / "conflict")
PY
python3 - <<'PY'
import json, os
from pathlib import Path
p = Path(os.environ["P4B"]) / "conflict/platform/research/task-v3-p4b/research.json"
d = json.loads(p.read_text("utf-8")); d["note"] += " tampered"
p.write_text(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8")
PY
python3 bin/platform.py --db "$P4B/conflict/platform/platform.db" casepack task-v3-p4b; echo "exit=$?"
python3 - <<'PY'
import os, sqlite3
from pathlib import Path
out = Path(os.environ["P4B"]) / "conflict/platform/casepacks/task-v3-p4b"
print("casepack.json 存在:", (out / "casepack.json").exists(),
      "| reports 行数:", sqlite3.connect(os.environ["P4B"] + "/conflict/platform/platform.db")
      .execute("select count(*) from reports").fetchone()[0])
PY
# → casepack failed: research.json 与 research.mapped 登记的 sha256 不一致: …（产物被改写或不是同一轮）
# → exit=2
# → casepack.json 存在: False | reports 行数: 0

# ⑦ 文本与页面：三节分离、无自裁决、无脚本、无外部资源
python3 - <<'PY'
import os, re
from pathlib import Path
out = Path(os.environ["DB"]).parent / "casepacks" / os.environ["TASK"]
md = (out / "report.md").read_text("utf-8"); html = (out / "report.html").read_text("utf-8")
print("md 小节:", [l for l in md.splitlines() if l.startswith("## ")])
print("html h2:", re.findall(r"<h2[^>]*>(.*?)</h2>", html))
print("confirmed 次数 md/compare/decisions:",
      md.lower().count("confirmed"),
      (out / "compare.json").read_text("utf-8").lower().count("confirmed"),
      (out / "research/decisions.json").read_text("utf-8").lower().count("confirmed"))
print("自裁决字段命中:", re.findall(r'"(verified|confirmed)"\s*:\s*true', md + html, re.I))
print("script/link/http/src:", html.count("<script"), html.count("<link"),
      html.count("http://"), html.count("https://"), html.count("src="))
print("benchmark_verified 渲染:",
      "否" in html[html.find("benchmark_verified"):html.find("benchmark_verified") + 240])
PY
# → md 小节: ['## 任务', '## 事件流', '## 研究进展', '## 对照实验（研究循环 vs 单次 fuzz）', '## 候选', '## 工程采纳', '## 漏洞验证', '## 复核', '## 证据清单', '## 口径声明']
# → html h2: ['包级摘要', '事件流', '研究进展', '对照实验（研究循环 vs 单次 fuzz）', '候选', '工程采纳', '漏洞验证', '复核', '证据清单', '口径声明']
# → confirmed 次数 md/compare/decisions: 0 0 0
# → 自裁决字段命中: []
# → script/link/http/src: 0 0 0 0 0
# → benchmark_verified 渲染: True
```

页面/文本侧还可以直接搜：`report.md` 里 `## 研究进展` / `## 工程采纳` / `## 漏洞验证` 三节；
`report.html` 的 `<h2>` 顺序与 `<script`（应为 0）；`compare.json` 的 `verdict` 必须是
`not_evaluated`，包内任何文件都不应出现 `"verified": true` / `"confirmed": true`。
