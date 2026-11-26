# 平台 v2 P3.9：static / dynamic 执行器 —— 把“已规划但没执行器”的两个 kind 接上

> 范围：P2 的 planner 会选 `static` / `dynamic`，但 `executors/__init__.py` 只有
> fuzz（P2）与 replay（P3.7）两条真路径，其余 kind 一律 fail-closed。
> 于是两类任务永远停在 `PLANNED → FAILED`：**没有源码树可 fuzz 的 VulnGym 目标**、
> **没有危险调用点只能静态复核的目标**。
> P3.9 把这两条接上，并且把分派本身写死成可审计的表：
> **① static 只读复核（不产 candidate，不写结论）；② dynamic 打两侧 HTTP 行为差分
> （产 candidate 或 no_repro，打不通就 FAILED 并留证）；③ 没登记的 kind 必须报
> `executor_unavailable:<kind>`，不许静默换执行方式。**
> 前置：[PLATFORM-V2-P2.md](PLATFORM-V2-P2.md) 的 Plan/执行编排、
> [PLATFORM-V2-P35.md](PLATFORM-V2-P35.md) 的 runner 与判据口径、
> [PLATFORM-V2-P37.md](PLATFORM-V2-P37.md) 的 replay 执行器、
> [PLATFORM-V2-E2E.md](PLATFORM-V2-E2E.md) 的 runner spec 生成。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/executors/static.py](../agent/platform/executors/static.py) | `review()` / `execute()` / `StaticExecError`：ProgramIndex + 假设集只读复核 → `static_review` 文档（程序事实 / 锚点 / 调用点 / 每条假设的落点 / `gaps` / `status`） |
| [agent/platform/executors/dynamic.py](../agent/platform/executors/dynamic.py) | `build_spec()` / `execute()` / `DynamicExecError`：VulnGym 两侧 HTTP → 差分事实 + `candidate`/`no_repro`；失败用 `records` 带走已拿到的证据 |
| [agent/platform/executors/\_\_init\_\_.py](../agent/platform/executors/__init__.py) | 显式分派表 `EXECUTORS`；`executor_for()` / `executor_unavailable()`；static / dynamic 两条编排分支（证据 kind、`exec_stats`、状态迁移、预算记账）；失败路径把 `exc.records` 先落库再写 FAILED |
| [agent/platform/planner.py](../agent/platform/planner.py) | 公开 `select_kind()`（`select()` 内部只调它一处）；kind 理由文案按 static/dynamic/replay/fuzz 分开 |
| [agent/platform/task.py](../agent/platform/task.py) | 状态机补 `RUNNING → NEEDS_EVIDENCE`、`NEEDS_EVIDENCE → RUNNING` |
| [agent/platform/\_\_init\_\_.py](../agent/platform/__init__.py) | 导出 `EXECUTORS` / `executor_unavailable` / `StaticExecError` / `DynamicExecError` / `select_kind` |
| [tests/test_platform_v2_exec.py](../tests/test_platform_v2_exec.py) | 16 项验收：分派/状态机/static 四态/dynamic 五态/CLI 两条端到端 |

## 2. 两个空档

| 空档 | 现象 | P3.9 的答案 |
|---|---|---|
| VulnGym 目标选 `dynamic` | 仓库内无源码/harness，fuzz 构建不了；`dynamic` 没执行器 → FAILED | dynamic 执行器：`task.json`/metadata 的基线/修补 URL → 两侧 HTTP → 差分 |
| target.yaml 目标选 `static` | 没有入口也没有危险调用点，fuzz 无从下手；`static` 没执行器 → FAILED | static 执行器：拿 ProgramIndex + 假设集做只读复核，把“缺什么证据”说清楚 |
| 分派靠 `if kind not in ("fuzz","replay")` | 新增 kind 时容易忘了登记，错误信息也不统一 | `EXECUTORS` 表 + `executor_unavailable:<kind>` 单一词形 |

## 3. static：只读复核，不产候选

### 3.1 它回答什么

~~~text
ProgramIndex（源码树/入口/危险调用点/上游锚点）
    +  假设集（≤8 条可证伪命题）
        ↓  只读，不构建/不执行/不联网/不写 workspace
static_review 文档
   ├── program      : source_count / entry_points / functions / call_sites / coverage_mode
   ├── anchors      : SOURCE.md·task.json 锚点（repo/commit/file/line/symbol + 是否可本仓复算）
   ├── sites        : 前 12 个危险调用点（callee/function/file/line/category/controlled/reachable）
   ├── hypotheses   : 每条假设的静态落点（matched_sites / matched_anchors / support）
   ├── gaps         : 证据缺口（见 §3.3）
   └── status       : no_repro | needs_evidence
~~~

落点算法是**词面匹配**，不是数据流分析：把假设的 `statement` / `falsifiable_by` /
`evidence_gap` 里的 ASCII 标识符（长度 ≥ 3）抽出来，与调用点的
`callee/function/file`、锚点的 `file/resolved_file/symbol` 求交集。
命中 → `support=static_support`；否则 `no_static_support`；抽不到标识符 → `locatable=false`。
**没有 LLM、没有猜测、没有“大概可能”**——宁可说“定位不到”，也不编一条落点。

### 3.2 结局只有两种

| 条件 | 结局 | 状态 |
|---|---|---|
| 没有缺口，且没有任何假设被静态事实支撑 | `no_repro` | `NO_REPRO` |
| 有缺口（§3.3）或某条假设被支撑 | `needs_evidence` | `NEEDS_EVIDENCE` |

`static_support` 只意味着“值得去跑动态取证”，**不是**漏洞成立；
所以它只能把任务推到 `NEEDS_EVIDENCE`（要补动态证据），绝不会推到 `CANDIDATE`。

### 3.3 证据缺口（`gaps`）

| 缺口 | 触发 |
|---|---|
| `no_hypotheses` | 假设集为空（没有可复核的命题） |
| `no_program_facts` | 既无源码树也无锚点（连“在复核什么”都说不清） |
| `no_source_tree` | 只有锚点（典型 VulnGym：行号必须按 repo+commit 去上游复算） |
| `no_call_sites` | 有源码但没有识别到危险调用点（静态覆盖面不足） |
| `anchor_unverified:<file>:<line>,…` | 锚点在 workspace 内无法复算（列前 3 条） |
| `hypothesis_unlocatable:<id>` | 假设文本里没有能对到代码的标识符 |
| `static_support_needs_dynamic:<id>` | 静态找到落点，但仍需动态证据 |

### 3.4 硬约束

- **不产 Candidate**：静态复核没有输入、没有崩溃、没有服务响应，把它写成候选就是伪造执行；
- **不写结论字段**：`verdict/confirmed/exploitable/conclusion/...`
  （[hypotheses.VERDICT_KEYS](../agent/platform/hypotheses.py) 是唯一口径）一个都不出现；
- **失败要炸**：plan/index 契约不符（缺 `task_id`/`benchmark`、index 属于别的 task、
  benchmark 不一致）→ `StaticExecError` → FAILED + `exec_error`，
  绝不把“没法复核”降级成 `no_repro`；
- **只读**：产物是内存文档，由编排层落成内容寻址的 `static_review` 证据。

## 4. dynamic：两侧 HTTP 行为差分

### 4.1 spec 从哪来（只翻译，不发明）

复用 P3.8 的 `build_runner_spec()`（`probe=False`：不在 spec 阶段联网）：

~~~text
plan.inputs.{baseline_url,patched_url,service_url,method,headers,expect}
        ↑ 覆盖
workspace/task.json          （baseline_url / patched_url / service_url / method / expect）
        ↑
任务 metadata
        ↓
VulnGym runner spec  →  blockers / missing / warnings / sources
~~~

- 没有任何默认值能凭空造出地址：缺字段就是 `runner_not_configured:baseline_url,patched_url`；
- `service_url` 会同时填两侧（spec 里 `notes` 明说“同一地址用于两侧”），
  这种任务通常只能得到 `no_repro`——**不拿 plan.target 去顶替修补侧**；
- `expect` 只透传方向期望（`baseline_status` / `patched_status_in`），
  由判据函数决定要不要用。

### 4.2 请求策略（继承 P3.5 runner）

| 项 | 规则 | 理由 |
|---|---|---|
| 方法 | `method`（默认 GET） | 与 task.json 声明一致 |
| 跳转 | **不跟随**，3xx 原样记账 | “拦截页 302 到登录页”不能被当成 200 |
| 代理 | `ProxyHandler({})` 显式关闭 | 宿主 `HTTP_PROXY` 不得把请求带出本机 |
| 响应体 | 截断 1 MiB，`body_sha256` 现场复算 | 证据可复算 |
| 断开 | `connection_closed=True`（本身是有效差分信号） | “修补后直接断开”要能被表达 |
| 超时 | `runner_timeout:<side>`，`completed=False` | 缺口，不是负结果 |
| 隔离 | 交给 runner 的 `policy` 快照（bwrap/unshare/none） | 与其它 runner 同口径 |

### 4.3 结局判定

判据事实源仍然是 [verify.evaluate_vulngym](../agent/platform/verify.py)，
dynamic 只搬它的 `inputs`（两侧状态/体哈希）与 `checks`（布尔判定），**不搬结论**：

| 观测 | 结局 | 状态 | 证据 |
|---|---|---|---|
| 两侧都有响应，`behavior_differs=True` | `candidate` | `CANDIDATE` | `dynamic_input`（请求文档）+ `dynamic_log`（差分日志）+ `dynamic_diff` + `dynamic_spec` + 两侧 body |
| 两侧都有响应，行为一致 | `no_repro` | `NO_REPRO` | `dynamic_diff` + `dynamic_spec` + `exec_stats` |
| 某一侧没响应（`*_recorded=False`） | `DynamicExecError` | `FAILED` | `dynamic_spec` + `dynamic_run` + `exec_error` |
| 两侧都没响应（都断开/都超时） | `DynamicExecError` | `FAILED` | 同上（**不是** no_repro） |
| 没有服务地址 / benchmark 不是 vulngym | `DynamicExecError` | `FAILED` | `dynamic_spec`（含 `blockers` 或 `unsupported_benchmark`） |

候选形态（[candidates.py](../agent/platform/candidates.py) 原样吃下）：

~~~text
input_sha256 = sha256(canonical(请求文档：method + 两侧 URL + headers))
crash_type   = "behavior_diff"           # 不冒充 ASAN/栈溢出
stack_hash   = sha256(canonical(差分摘要))  # 去重签名，不是 root cause
evidence_sha256 = sha256(差分日志)
detail.source   = "dynamic"
detail.dynamic  = {request, summary, blockers, runner, seconds}
~~~

`dynamic_spec` 落库的就是可喂 `verify --spec` 的判据输入
（`{benchmark:"vulngym", baseline:{status,body_sha256,…}, patched:{…}, expect:{…}}`），
**里面没有 `verified`/`confirmed`**：验证仍是 verify 的动作。

### 4.4 失败也留证

`DynamicExecError` 带 `records`（`dynamic_spec` / `dynamic_run`），
编排层在写 FAILED 之前先把它们落成证据，并把哈希写进 `exec.finished.evidence`。
理由：服务打不通时最需要复盘的是“打了什么、回执是什么”，
而 `exec_error` 里只有错误字符串。

## 5. 分派：一张表，一个错误词形

~~~python
EXECUTORS = {"fuzz": execute_fuzz, "replay": execute_replay,
             "static": execute_static, "dynamic": execute_dynamic}
~~~

- `run --kind` / `kind_override` 只影响本次执行，不改写已存 Plan（审计进 `exec.started`）；
- 表里没有的 kind：`PlanError("executor_unavailable:<kind>（可用: …）")`
  → FAILED + `exec_error`（`blocker=executor_unavailable:<kind>`）
  + `exec.finished.blockers=["executor_unavailable:<kind>"]`；
- 新增 kind 的顺序是**先登记执行器**，再让 planner 选它；
  否则任务会如实失败，而不是被悄悄换成 fuzz。

## 6. 状态机补充

~~~text
RUNNING ──有缺口/静态支撑──→ NEEDS_EVIDENCE ──补证据后重跑──→ RUNNING
RUNNING ──两侧无差异──────→ NO_REPRO
RUNNING ──有差异──────────→ CANDIDATE
RUNNING ──跑不动──────────→ FAILED
~~~

`NEEDS_EVIDENCE` 与 `NO_REPRO` 都是终态，但语义不同：
前者是“缺证据（静态缺口/单侧没响应）”，后者是“跑完没差异”。
两者都保留事件与证据；`NEEDS_EVIDENCE` 额外开放 `→ RUNNING`（补上证据就能重跑）。

## 7. CLI 与 planner 可测性

~~~bash
# 静态复核（任意 benchmark；缺证据就 NEEDS_EVIDENCE）
python3 bin/platform.py --db .platform/platform.db run TASK --kind static

# VulnGym 行为差分（spec 来自 workspace/task.json 或 --meta）
python3 bin/platform.py --db .platform/platform.db run TASK --kind dynamic
~~~

- `run --kind` 的 choices 仍是 `static/dynamic/fuzz/replay`，未知 kind 在参数层就被拒；
- `planner.select_kind(index, benchmark, target)` 是公开函数，`select()` 只调它一处：
  单测可以直接断言“有调用点 → fuzz / 只有锚点 → static / vulngym → dynamic”，
  也可以 monkeypatch 它来验“选择点只有一处”（Plan.kind 跟着变）。

## 8. 证据与事件契约

| 证据 kind | 谁写 | 内容 |
|---|---|---|
| `static_review` | static 分支 | 复核文档（程序事实/锚点/调用点/假设落点/gaps/status） |
| `dynamic_spec` | dynamic 分支 | 可喂 `verify --spec` 的 vulngym 判据输入（失败时含 blockers） |
| `dynamic_diff` | dynamic 分支 | 差分文档（request/expect/checks/blockers/summary/log/sides/policy） |
| `dynamic_run` | dynamic 分支（仅失败） | runner 结果快照（两侧 sides / checks / policy / evidence） |
| `dynamic_input` / `dynamic_log` | dynamic 分支 | 候选输入（请求文档）与主证据（差分日志） |
| `dynamic_verify_{baseline,patched}_body` | dynamic 分支 | 两侧响应体（≤1 MiB，sha256 可复算） |
| `exec_stats` | 两个分支 | 本次执行的统计快照（`static` / `dynamic` 段 + 证据哈希） |
| `exec_error` | 失败路径 | 错误类型/消息/`blocker`/失败前证据哈希/预算快照 |

`exec.finished` 的 payload 新增 `kind`、`static`/`dynamic` 摘要、`gaps`、
`spec_evidence_sha256` / `diff_evidence_sha256` / `body_evidence_sha256`、
失败路径的 `blockers` 与 `evidence`。**任何产物都不含 `confirmed`。**

## 9. 验收

~~~bash
python3 -m pytest tests/test_platform_v2*.py -q     # 197 passed
~~~

`tests/test_platform_v2_exec.py`（16 项）：

| # | 覆盖 |
|---|---|
| 1–2 | 分派表显式（4 个 kind）+ 未登记 kind 报 `executor_unavailable:container`（PlanError/FAILED/证据/事件 blockers） |
| 3 | 状态机 `RUNNING → NEEDS_EVIDENCE`、`NEEDS_EVIDENCE → RUNNING` |
| 4 | planner 选择可直接断言 + monkeypatch 覆盖（Plan.kind 跟着变） |
| 5–6 | static `no_repro`（假设无落点、无缺口）与 `needs_evidence`（静态支撑 / 锚点-only 无源码树） |
| 7–8 | static 契约失败（index 口径不符、index 缺失）与执行器异常 → FAILED + `exec_error` |
| 9–10 | dynamic 有差异 → CANDIDATE（候选字段 + 5 类证据 + spec 可喂 `normalize_spec`）；无差异 → NO_REPRO |
| 11 | dynamic 服务打不通 → FAILED + `dynamic_spec`/`dynamic_run`/`exec_error`（不是 NO_REPRO） |
| 12–13 | dynamic 只实现 vulngym（benchmark 不符抛错）；缺地址报 `runner_not_configured`，不猜 URL |
| 14–16 | CLI `run --kind static` 端到端、`run --kind dynamic` 端到端、未知 kind 参数层拒绝 |

## 10. 边界（明确不做）

- **不做构建/不跑 fuzz**：static 只读，dynamic 只打两侧 HTTP；
- **不产结论**：static 连候选都不产；dynamic 产的候选 `state=new`，
  `verified` 仍只由 [verify](../agent/platform/verify.py) + [benchmark_policy](../agent/benchmark_policy.py) 推导；
- **不改 API/UI**：本轮只动 `agent/platform`、`bin/platform.py` 的 `run --kind` 语义与测试/文档；
- **两侧同址**：`service_url` 同时填两侧时只会得到 `no_repro`（诚实，不编造修补行为）；
- **不做数据流/污点分析**：static 的落点是词面匹配，宁可报缺口也不编结论；
- **不做真实 benchmark 网络**：验收全部用本地 HTTP server / 关闭端口，
  不依赖 VulnGym 实例可达。
