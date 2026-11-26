# CG-07 / CG-18 采样参数取证（`param-forensics-20261125`）

> **一句话结论**：两例的 `verify` 模型闭环调用**确实**没有逐调用落盘采样参数，D2 仍不通过——
> 但这次把"缺什么、为什么缺、能推到哪一步"逐条钉死了：
> CG-07 有 **3 条**已记录调用（1 locate 完整 / 2 轮闭环无参数），
> CG-18 有 **8 条**（2 locate 完整 / **6 次闭环调用**，不是上批写的 3 条）；
> CG-18 的 `max_tokens=8000` 由 `finish_reason=length ∧ completion_tokens=8000` **实测推导**得出，
> 这是本批唯一新增的"实测参数"；`temperature=0.0` / `response_format=json_object` 是**结构性可证**
> （`agent/llm.py` mtime 早于两个 run 启动 + `configs/llm.json` 已证不存在），
> `top_p` / `seed` 是**客户端从不发送**，`request_id` 是**客户端结构上不产出**。
> **上批 CG-07 的 `prompt_version="verify-llm-loop-p5"` 是无依据外推，本轮降级为 `missing`。**
> `strict_submittable` 重算后不变：**CG-07 = false、CG-18 = false**（A/B/C/D1/D3/D4 未变，仅 D2 复核更细）。

> 机读：[calls.json](../experiments/param-forensics/calls.json)（逐调用表）、
> [search_log.json](../experiments/param-forensics/search_log.json)（检索网格）、
> [integrity.json](../experiments/param-forensics/integrity.json)（源文件哈希）、
> [d2_verdict.json](../experiments/param-forensics/d2_verdict.json)（D2 重算）。
> 交叉核验（独立复算员，只读）：[crosscheck-teammate.json](../experiments/param-forensics/crosscheck-teammate.json)——
> 与主链结论一致（3/8 条调用、轮级 token 闭合、`max_tokens=8000` 精确、`request_id/top_p/seed` 从未出现、
> `prior-run` 快照哈希对齐），并补充了两处代码修订差异（见 §2.4、§3.6）。
> 脚本：[extract_calls.py](../experiments/param-forensics/extract_calls.py) →
> [build_artifacts.py](../experiments/param-forensics/build_artifacts.py) →
> [recompute_d2.py](../experiments/param-forensics/recompute_d2.py)。
> 上游判据：[COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) §2.2；批次文档：[COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md)。

---

## 0. 结论表

| 项 | CG-07（arvo:10096） | CG-18（arvo:12420） |
|---|---|---|
| 交付 run | `r-67cd794848e503af4c82` | 交付 `s7e-libidn2-20261111T212000` / 模型闭环在 `s7d-arvo12420-20261111T2055` |
| 轨迹库 | `.runtime/vulnmap.db` `d62828d6…bcdac4`（94208 B） | `9d416735…6a1a08`（102400 B） |
| **已记录调用** | **3**（locate 1 + 闭环 2 轮） | **8**（locate 2 + 闭环 6 次） |
| 逐调用参数完整 | 1 / 3 | 2 / 8 |
| 交付 PoC 是否来自模型闭环 | **是**（round 2，`a9fce3b5…61ddf`，500049 B） | **否**（rule 候选 `d9ba75e1…b0bc9`，260 B；闭环 3 轮全 `invalid_model_output`） |
| verify 阶段判定 | **decisive**（交付 PoC = 模型闭环 round 2 输出） | non_decisive（PoC 来自 rule，闭环全失败） |
| run-time verify.py 形状 | **旧版**（无 `llm_calls` 账本） | **= 当前版**（有账本、有 `calls=/finish=/prompt_chars=` note） |
| `max_tokens` | **missing_no_proof** | round1 调用1 **measured_derived=8000**；其余 5 次 inferred_same_cfg_object |
| **D2** | **fail**（decisive + missing） | **fail**（6 条已记录调用缺参数） |
| `strict_submittable` | **false** | **false** |

```text
strict_submittable = A ∧ B ∧ C ∧ D1 ∧ D2 ∧ D3 ∧ D4
CG-07  A true  B true  C true  D1 true  D2 false  D3 true  D4 true  →  false
CG-18  A true  B true  C true  D1 true  D2 false  D3 true  D4 true  →  false
（A/B/C/D1/D3/D4 直接沿用 course-review-batch/evidence/<CASE>/verification.json，
  原始证据未改动；D2 由 experiments/param-forensics/recompute_d2.py 按逐调用表重算）
```

---

## 1. 取证方法与"采信/不采信"边界

| 采信（原始请求 / 运行时快照 / 结构化日志） | 不采信（只进 inferred 栏或整段不用） |
|---|---|
| `attempts.detail_json`（`llm` / `model_loop_round` / `llm_calls`） | 当前 `agent/llm.py` 的 `LlmConfig` 默认值当"实测值"用 |
| `blackboard.content`（结构化 note，含 `calls=/finish=/prompt_chars=`） | `configs/versions.json` 的 `prompt_version` 当"该 run 实跑版本"用 |
| `artifacts/verify/result.json` 与 `artifacts.prior-run/verify/result.json`（DB `artifacts` 表可对哈希） | `task.json.model` 当"实际请求的 model"用（env 通道未排除） |
| `artifacts/run_summary*.json`（含 `.bak-regate-*`、`prior-run/`） | 任何"应该是 T=0 / 应该是 8000"式补猜 |
| `logs/*`（vul/fix 运行日志、`report.error.json`） | 别的 run / 别的实验目录里的同名调用记录 |
| `artifacts` 表 sha256 / `checkpoints.binding` 输入哈希 | `case.json.model_contribution.llm_calls`（口径是 `detail.llm` 计数，漏闭环调用） |

只读手段：SQLite `file:…?mode=ro`、`sha256sum`、`stat`、逐列 needle 扫描（见 `search_log.json`）。
**本轮没有重跑任何案例**，也没有改写任何原始证据（`integrity.json` + `review.json` 的 17 条 refs 全部复核通过）。

---

## 2. CG-07：3 条调用，2 条无参数

### 2.1 调用清单

| # | attempt_id | stage | round / n | status | 用量（落盘） | 输入绑定 | 输出绑定 | 参数 |
|---|---|---|---|---|---|---|---|---|
| 1 | `423039a30afb44901a92` | locate | n=2 | `llm_ok` / `status=ok` | 549（493+56），`finish=stop`，`requests=1` | 无请求哈希（prompt 未落盘）；`prompt_version=locate-llm-p1` | `raw` 结构化输出可哈希（见 `calls.json`） | **完整**（7 项全落盘） |
| 2 | `8e7cc75425e3723e823f` | verify | round 1 / n=4 | `llm_status=ok`，`verdict=invalid_model_output` | `llm_tokens=1931`（**轮内合计，无分项**） | 无（`input_sha256` 字段不存在） | 无（`sha256=""`）；`rationale` 仅存 300 字符截断 | **missing**（7 项全缺） |
| 3 | `ecfaa6a72bc0a3b3a6b4` | verify | round 2 / n=4 | `llm_status=ok`，`verdict=pass` | `llm_tokens=1617`（轮内合计） | 无 | **有**：`sha256=a9fce3b5…61ddf`（= 交付 PoC，`delivered_poc_match=true`） | **missing** |

证据定位符：`attempts/<attempt_id>/detail.llm`、`attempts/<attempt_id>/detail.model_loop_round`；
交叉：`artifacts/verify/result.json`（`adb0f410…`，DB `artifacts` 表同哈希）`model_loop.rounds[0..1]`、
`blackboard@be05d0868ad099edaaae`（round 1 note）、`blackboard@091a4b64750fecbb223a`（round 2 note）。

### 2.2 逐字段：记录了什么、能推到什么

| 字段 | locate（调用 1） | verify 闭环（调用 2–3） |
|---|---|---|
| `model` | **实测** `deepseek-flash` | 未落盘；同 run 同进程 locate 已实测 → `recorded_absent_inferred_same_process` |
| `prompt_version` | **实测** `locate-llm-p1` | **missing_no_proof**；候选 `[p5(当前), p1(旧 run_loop 默认)]`，均非实测（见 §2.4） |
| `temperature` | **实测** `0.0` | 未落盘，但 `structural_proven=0.0` |
| `max_tokens` | **实测** `1200` | **missing_no_proof** |
| `response_format` | **实测** `json_object` | 未落盘，但 `structural_proven=json_object` |
| `base_url` | **实测** `https://api.deepseek.com/v1` | 未落盘；同进程推断同值 |
| `max_retries` | **实测** `1` | 未落盘；同进程推断 1 |
| `top_p` | 客户端从不发送（`absent_by_design`） | 同 |
| `seed` | 客户端从不发送（`absent_by_design`） | 同 |
| `request_id` | **客户端结构上不产出**（`never_captured_by_client`） | 同 |

`temperature=0.0` / `response_format=json_object` 的**结构性证明链**（两条独立证据）：

1. `agent/llm.py` 的 `LlmConfig.request_body()` **无条件**写 `temperature=cfg.temperature` 与
   `response_format={"type":"json_object"}`，`top_p`/`seed` 从不出现；
2. `agent/llm.py` mtime = `2026-11-10T18:17:14+08:00`，**早于**该 run 启动
   `2026-11-10T18:50:40`（`runs.created_at=1794307840.626`）→ run 时跑的传输层 = 现在这份；
3. `cfg.temperature` 的来源只有三处：`LlmConfig` 默认 `0.0`、`configs/llm.json`、
   `task.json.llm`——`configs/llm.json` **不存在**（`configs/` 目录 mtime `2026-11-09T17:24:41`，
   创建/删除都会改目录 mtime，故 11-09 之后该目录没增删过文件），`task.json` 无 `llm` 键，
   `load_config()` **不读** temperature 的环境变量。

> 注意这条链证明的是"**发送什么**"，不是"**落盘了什么**"。V2 §2.2 D2b 要的是后者，
> 所以它**不**把 CG-07 的 verify 补齐成 pass，只是把"未知"缩小到"未落盘"。

### 2.3 缺失项与原因

| 缺失字段 | 原因 | 是否可补 |
|---|---|---|
| `model` / `base_url` / `max_retries`（调用 2–3） | 闭环记录只有 `round/llm_status/llm_tokens/sha/size/verdict/feedback` | 只能靠同进程 locate 记录旁证；**不可回填** |
| `max_tokens`（调用 2–3） | 无 `finish_reason`/`completion_tokens` 分项，`llm_tokens` 是轮内合计 | **不可推导**（见 §2.4） |
| `prompt_version`（调用 2–3） | 闭环记录无该字段 | 不可回填 |
| `request_id`（全部） | `LlmResult` 无此字段，`call_json` 不解析响应 id | 结构性缺失，历史数据不可能有 |
| LLM 请求体哈希（全部） | prompt 正文未落盘 | 不可 |
| `rationale` 全文（调用 2） | 落盘时 `[:300]` 截断 | 不可 |

### 2.4 纠正：上批 `prompt_version="verify-llm-loop-p5"` 无依据

判据：run-time 代码形状是否 = 当前 `agent/stages/verify.py`。

| 观测 | 当前代码应有 | CG-07 实测 | 结论 |
|---|---|---|---|
| `model_loop_round` 字段 | `+ input_sha256 / duplicate / distinct / llm_calls / retry_round / finish_reason / completion_tokens / prompt_chars` | **全无** | run-time 是旧版 |
| `blackboard` note（`_note`） | `round N: <verdict> <feedback> (calls=…, finish=…, prompt_chars=…)` | `round 1: invalid output must_use_recipe…`（**无** `calls=`/`finish=`/`prompt_chars=`，且 verdict 措辞是 `invalid output`） | run-time 是旧版 |
| `result.json.model_loop` 返回键 | 含 `max_rounds / executed_rounds / total_calls / retried_rounds / seeds_used …` | **只有** `rounds/transcript/total_rounds/effective_rounds/duplicates_rejected/succeeded/winner_*/total_tokens/format/claim_subject` | run-time 是旧版 |
| note 文本来源 | 当前 `verify.py` 走 `run_diverse_loop`，`_note` 必带 `calls=` | `round 1: invalid output must_use_recipe…` 与 **`agent/loop.py:186`** 的 `log` 语句逐字一致 | run-time 走**旧 `run_loop` 路径** |
| 该路径是否还在用 | `run_loop` 在当前仓库 **0 个调用点**（grep 只剩定义），`loop.py:145` 默认 `prompt_version="verify-llm-loop-p1"`、`max_tokens=8000` | — | 旧路径常量只能作**候选** |

→ 该 run 的闭环 prompt 版本**没有任何落盘证据**；上批把当前常量（p5）写成它的 `prompt_version`，
属"用当前代码回填历史"。本轮改为 `prompt_version="missing"` + `prompt_version_detail.status=missing_no_proof`，
并记录**两个候选**：`verify-llm-loop-p5`（当前 `verify.py`）与 `verify-llm-loop-p1`（旧 `run_loop` 默认值）——
注意旧路径的默认值是 **p1**，与上批写的 p5 **相反**，这正说明"拿当前常量回填"会给出错误标签。
同理，旧 `run_loop` 的 `max_tokens=8000` 默认值与当前 `_model_loop` 的 `replace(cfg, max_tokens=8000)`
都**不能**外推成该 run 的 `max_tokens`：轮内合计 `1931 / 1617 ≪ 8000` 说明两次都没打满上限，
上限值不可测（只能给下界）。

---

## 3. CG-18：8 条调用，6 次闭环调用（上批只数了 3 条）

### 3.1 关键发现：`llm_calls` 逐调用账本一直在库里

`attempts.detail.model_loop_round.llm_calls[]` 逐次记录
`retry_round / status / finish_reason / completion_tokens / prompt_tokens / tokens / prompt_chars / error`。
上批把每轮当成 1 条调用（只取了轮级 `llm_tokens`），**实际每轮 2 次调用**（`retry_round=0` 原始 +
`retry_round=1` 降载重试）。

### 3.2 调用清单（6 次闭环 + 2 次 locate）

| # | attempt_id | run | round | call | status | `finish_reason` | prompt | completion | tokens | 备注 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `e0419f26415f5c118c90` | s7d | 1 | 1 | **incomplete** | **length** | 1718 | **8000** | 9718 | **打满输出上限** |
| 2 | `e0419f26415f5c118c90` | s7d | 1 | 2 | ok | stop | 1120 | 52 | 1172 | 降载重试 |
| 3 | `10c1c3ec5a7dbe7e4905` | s7d | 2 | 1 | ok | stop | 1845 | 76 | 1921 | |
| 4 | `10c1c3ec5a7dbe7e4905` | s7d | 2 | 2 | ok | stop | 1247 | 63 | 1310 | |
| 5 | `968c619ead36b071510d` | s7d | 3 | 1 | ok | stop | 1948 | 68 | 2016 | |
| 6 | `968c619ead36b071510d` | s7d | 3 | 2 | ok | stop | 1350 | 52 | 1402 | |
| 7 | `e8ba23e5dd3ab2ab6a21` | s7d | — | locate | ok | stop | 611 | 59 | 670 | 参数**完整** |
| 8 | `6998e4ef845a6295f173` | s7e | — | locate | ok | stop | 611 | 61 | 672 | 参数**完整** |

**闭合校验（脚本硬断言，不平即退出 1）**：

```
round1: 9718+1172 = 10890 == llm_tokens(round1)      ✓
round2: 1921+1310 =  3231 == llm_tokens(round2)      ✓
round3: 2016+1402 =  3418 == llm_tokens(round3)      ✓
6 次合计 17539 == result.json.model_loop.total_tokens ✓   total_calls=6 ✓   retried_rounds=3 ✓
```

证据定位符：`attempts/<id>/detail.model_loop_round.llm_calls[i]`；
交叉快照 `artifacts.prior-run/verify/result.json`（`8c19e090…cbf990d`，与 DB `artifacts` 表中
`s7d` 的 verify 产物哈希一致）；`blackboard@…`（3 条"模型闭环"note，`calls=2, finish=stop, prompt_chars=…`）。

> **为什么要用 `prior-run` 快照**：现盘 `artifacts/verify/result.json` 是 `s7e` 的
> （`2061899…c37266b`，2722 B，无 `model_loop`），`s7d` 的 11807 B 版本只活在
> `artifacts.prior-run/` 与 DB `artifacts` 表里。只看现盘会漏掉 CG-18 的全部闭环证据。

### 3.3 `max_tokens=8000` 的实测推导（本批唯一新增实测参数）

```
调用 1（attempt e0419f…，round1 call1）：
  finish_reason = "length"        ← 只有打满 max_tokens 才会是 length
  completion_tokens = 8000        ← 生成量恰好等于上限
  ⇒ max_tokens = 8000（该次调用）
```

这不是"应该是 8000"，是"上限被打满且终止原因被记录"。范围限定：
**只对这一次调用构成实测**；其余 5 次由"同一 `_model_loop` 内 6 次调用共用同一个
`dataclasses.replace(cfg, max_tokens=8000)` 对象"降级为 `inferred_same_cfg_object`。

旁证（说明这不是巧合）：`blackboard` round 1 note 记 `finish=stop`（该轮最后一次调用的
`finish_reason`），而账本里 round1 call1 是 `length` → 说明 note 取的是**最后一次**调用；
p5 的"打满 → 降载重试"设计正是为此。这也是 CG-18 的 run-time 代码 = 当前版的行为证据。

**传输层等同当前版（可逐字对证）**：该次调用落盘的 `error` 恰为 `"finish_reason=length"`，
与 `agent/llm.py:197-198`（`if res.finish_reason == "length": res.status, res.error =
"incomplete", "finish_reason=length"`）**字面完全一致**；连同 `retry_round`/`prompt_chars`
字段形状，三级证据（字段形状 + note 文本 + error 字面）共同锁定 run-time 代码。

**但 run-time 的 `verify.py` 是 p5 家族的较早修订，不是当前这份**（两处可证差异见 §3.6）——
所以 `prompt_version` 仍只作候选、`max_tokens` 的"其余 5 次"仍只作 `inferred`。

### 3.4 逐字段

| 字段 | locate（7–8） | verify 闭环（1–6） |
|---|---|---|
| `model` | **实测** `deepseek-flash` | 未落盘；同 run 同进程推断（s7d 的 locate 在 s7d 闭环之前） |
| `prompt_version` | **实测** `locate-llm-p1` | **missing_corroborated_by_behavior**（p5 两处特征都可观测，仍未落盘） |
| `temperature` | **实测** `0.0` | `structural_proven=0.0` |
| `max_tokens` | **实测** `1200` | 调用 1 **measured_derived=8000**；调用 2–6 `inferred_same_cfg_object=8000` |
| `response_format` | **实测** `json_object` | `structural_proven=json_object` |
| `base_url` | **实测** `https://api.deepseek.com/v1` | 同进程推断 |
| `max_retries` | **实测** `1` | 推断 1；p5 的"重试"是 loop 层第二次调用，不是 HTTP 重试 |
| `top_p` / `seed` | 不发送 | 不发送 |
| `request_id` | 不产出 | 不产出 |

### 3.5 与交付的关系

`s7d` 三轮闭环全部 `invalid_model_output`（`executed_rounds=0`、`distinct_inputs=0`），
交付 PoC `libidn2-4i-65.bin`（260 B，`d9ba75e1…`）来自 `s7e` 的 **rule** 候选
（`attempts.bbfed788e77a3aa4490a`，`proposed_by=rule`），故 `decisive_stages=[]`。
**D2 的失败点因此不是 D2c（decisive 缺失），而是 D2b（6 条已记录调用缺逐调用参数）。**

### 3.6 交叉核验（独立复算员 + 代码修订差异）

独立复算员（只读、不同 agent）在自己的文件里复算了同一批数字，结论与主链一致：

| 核验点 | 主链 | 独立复算 | 判定 |
|---|---|---|---|
| 调用条数 | CG-07 3 / CG-18 8 | 3 / 8 | 一致 |
| 轮级 token 闭合 | 10890/3231/3418；合计 17539 | 同 | 一致 |
| `max_tokens` 推导 | CG-18 一次精确 8000 | 同（并明确"不是下界"） | 一致 |
| `request_id / top_p / seed` | 从未出现 | 同（并排除 `seeds_used` 语料种子误判） | 一致 |
| `prior-run` 快照 | `8c19e090…` = DB `artifacts@e7be91c1…` | sha256sum 复核一致 | 一致 |
| 代码版本 | CG-07 旧路径 / CG-18 较早修订 | 同，并给出两处更细差异 | **补强** |

独立复算补出的两处 **CG-18 run-time/当前代码差异**（本轮已吸收进 `calls.json.code_shape_evidence`）：

1. `transcript.llm` **缺 `parse_fmt` / `raw_reply`** —— 当前 `verify.py:283-284` 必写且无剥离逻辑；
2. **运行期强制 recipe** —— `must_use_recipe:format_has_builder` 只在 `require_recipe=True` 时抛出
   （`round 1`、`round 3` 都抛了），而当前 `verify.py:186` 写死 `require_recipe = False`。

→ 结论：CG-18 的 run-time `verify.py` 是 **p5 家族较早修订**，与当前版本"同族但不等同"。
这不改变 `max_tokens=8000`（由该次调用的 `finish_reason/completion_tokens` 实测导出，与代码无关），
也不改变 `prompt_version` 的 `missing` 定性（常量只作候选）。

**另一条必须写明的口径**：locate 的 `attempts.detail.llm.params` 是客户端的
`public_params()`（**发送配置自报**），不是服务端回执。它证明"代码把哪些值放进了请求体"，
**不**证明"服务端按此执行"。D2b 要的是"已记录调用的参数完整"，自报块满足这一条；
但任何"该 run 确实以 T=0 采样"的表述都应带上这个限定。


---

## 4. 逐调用缺失汇总（D2b 口径）

> D2b 只认"**逐调用落盘**"。结构性证明 / 同进程推断 / 实测推导都记在 `inferred` 栏，
> **不**把 `incomplete` 改写成 `complete`。

| 字段 | CG-07（3 条） | CG-18（8 条） | 该字段的定性 |
|---|---|---|---|
| `model` | 2 缺 / 1 有 | 6 缺 / 2 有 | 可同进程旁证，不可实测回填 |
| `prompt_version` | 2 缺 / 1 有 | 6 缺 / 2 有 | 闭环从不落该字段 |
| `temperature` | 2 缺 / 1 有 | 6 缺 / 2 有 | 结构性可证 0.0 |
| `max_tokens` | 2 缺 / 1 有 | 6 缺 / 2 有（其中 1 次可实测推导 8000） | CG-07 不可推导 |
| `response_format` | 2 缺 / 1 有 | 6 缺 / 2 有 | 结构性可证 json_object |
| `base_url` | 2 缺 / 1 有 | 6 缺 / 2 有 | 可同进程旁证 |
| `max_retries` | 2 缺 / 1 有 | 6 缺 / 2 有 | 可同进程旁证 |
| `request_id` | 3 缺 | 8 缺 | **客户端结构上不产出** |
| `top_p` / `seed` | 不适用 | 不适用 | 客户端从不发送 |
| LLM 请求体哈希 | 3 缺 | 8 缺 | prompt 未落盘；CG-18 仅存 `prompt_chars` |
| LLM 输出哈希 | 1 有（round2 = PoC） | 0（3 轮 `sha256=""`） | — |

---

## 5. 参数矩阵与复核件更新（只加证据）

| 文件 | 变更 | 新 sha256 |
|---|---|---|
| `experiments/course-review-batch/evidence/CG-07/model_params.json` | 重建为 `vulnmap.model_params.v2`：逐调用三栏（`recorded`/`inferred`/`basis`）、绑定 `attempt_id/round/输入/输出`、`corrections_vs_prev_batch`、`forensics` 指针 | `ea317836…b2c882` |
| `experiments/course-review-batch/evidence/CG-18/model_params.json` | 同上；闭环 3 条 → **6 条**；新增 `max_tokens=8000` 实测推导 | `c5c660cd…d81e8e` |
| `workspace/CG-07-arvo-10096/review.json` | `REF-PARAMS` 哈希/大小更新；新增 `param_forensics` 证据块；**未改任何 caveat 与判定** | `b81c1009…acab11` |
| `workspace/S7-CG18-arvo-12420/review.json` | 同上 | `a75ec350…0739d8` |

**哈希链影响（必须一起报）**：这 4 个文件在 `experiments/course-review-batch/MANIFEST.sha256`
里的旧条目**必然失效**（`sha256sum -c` 会报 4 行"失败"，其余 48 行仍成功）。
新值见 [`MANIFEST.supersede.sha256`](../experiments/param-forensics/MANIFEST.supersede.sha256)；
批次清单/`summary.json` 本轮**未改写**（不在允许改动范围），故 `summary.json.review_sha256`
与 `review_refs.json` 仍是旧值——按本表覆盖，不要按旧清单判断篡改。

`recompute_batch.py --check` 复跑结果（权威计算器，只算不写）：

```text
strict_submittable_true=4（CG-29/30/31/36）  strict_submittable_false=2（CG-07/CG-18）
external_independent_true=0   external_status_pending=6   caveats_total=114   DOC 错误=0
退出码 1（= 校验通过但存在 false，本批正常值）
```

---

## 6. 未采信 / 未做

| 项 | 处置 | 原因 |
|---|---|---|
| 用 `configs/llm.json` / 当前 `LlmConfig` 默认值填历史参数 | **不做** | 回填即伪造；本批只写 `inferred` + 依据 |
| 用 `task.json.model` 当"实际请求 model" | **不做** | `LLM_MODEL` 环境变量未随 run 落盘，无法排除 |
| 重跑以补参数 | **不做** | 历史调用不可复现；重跑要落**新** run 的参数，不能改写旧 DB |
| 改 DB / logs / `case.json` / `severity.json` / `propagation.json` | **未做** | 原始证据只读；`integrity.json` 与 17 条 refs 复核通过 |
| 改业务代码（`verify._model_loop` 落 `cfg.public_params()`） | **未做** | 属业务代码；本任务只做取证。建议另开任务（见 §7） |
| 修 `MANIFEST.sha256` / `summary.json` / `review_refs.json` | **未做** | 不在允许范围；改用 `MANIFEST.supersede.sha256` 覆盖 |
| `git commit` | **无** | 任务书禁止；且仓库根不是 git 工作区 |

---

## 7. 要让 D2 过的唯一正路（不属本任务，只记录）

1. `VerifyStage._model_loop` 里把 `cfg.public_params()` + `loop_prompt_version` 写进
   `model_loop_round`（以及 `llm_calls[]` 每次调用），一行 `json.dumps` 的事；
2. `llm.LlmResult` 增加 `request_id` 并从响应体取 `id`，`to_record()` 一并落盘；
3. 重跑受影响案例，让新 run 自带参数——**历史 run 的 `missing` 永久保留**（不可回填）。

---

## 8. 复跑与校验

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 抽取（只读 DB；轮级 token 不平即退出 1）
python3 experiments/param-forensics/extract_calls.py
# 2) 重建参数矩阵 + review.json 的 D2 证据块（会打印新哈希）
python3 experiments/param-forensics/build_artifacts.py
# 3) D2 / strict_submittable 重算
python3 experiments/param-forensics/recompute_d2.py
# 4) 批次权威计算器只算不写（期望退出码 1）
python3 experiments/course-review-batch/recompute_batch.py --check

# 5) 原始证据未被改写
sha256sum -c experiments/param-forensics/MANIFEST.param-forensics.sha256
```

退出码契约：`extract_calls.py` 0=抽取成功 / 1=轮级 token 不平；
`recompute_d2.py` 0=算完；`recompute_batch.py --check` 1=通过但有 false（本批正常）。
