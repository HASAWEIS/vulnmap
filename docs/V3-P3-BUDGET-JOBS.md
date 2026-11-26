# V3 P3：预算原子预留、Campaign 子 Job、恢复对账与安全反例

P3 的四项交付（V3-010..V3-013）解决的是“研究循环跑起来之后，怎么保证**成本不重复扣、
任务不乱跑、崩溃后能对账、取消能真的停**”。P2b 已经把 `OBSERVE → … → ADOPT/REVERT/STOP`
跑通（见 [V3-P2B-SESSION.md](V3-P2B-SESSION.md)、[V3-P2C-RESEARCH-CLI.md](V3-P2C-RESEARCH-CLI.md)），
但那时候：

- 预算是 `DeclaredBudget` 内存账本，**没有事务**：两个 worker 同时读到“还剩 1 个回合”就会双花；
- 模型调用没有任何统一入口，没有价格表，也没有“usage 缺失怎么办”的口径；
- 子 Job 不存在，进程崩了以后没人知道“这次执行到底算不算发生过”；
- 取消只改任务状态 + 对启动器进程组发一个信号，管不住 campaign 层已经发出去的东西。

P3 把这四件事补齐，并且**没有改** `verify.py` / benchmark policy：判据一个字没放松，
新增的模块只做账、租约、对账和守卫。

本文件同时记录了一轮**独立红队审计**（`p3-auditor`）的结论与修复（见 §9）：审计打穿了
5 处真实缺陷（主循环没接事务账本、`recover` 在 RUNNING 路径直接抛异常并中断整轮、
`bytes` 回包绕过密钥扫描、四处 fence 校验缺口、启动器侧缺 `self_pid` 守卫），
这些都已修复并补了回归测试，测试数从 18 长到 30。

> 交付时仓库里还有**另一个会话在并行做 P4**（`adaptive/compare.py`、`adaptive/report.py`、
> `casepack.py`、`tests/test_v3_p4_*.py` 在我们收尾时仍在改动）。全量回归最后一条
> `test_v3_p4_report.py::test_research_artifacts_and_html_are_deterministic` 曾经红过，
> 单独跑该文件是 11 passed——那是对方的在飞改动，P3 没有碰这些文件。

## 0. 实施清单

| 项 | 内容 | 落点 | 验收 |
|---|---|---|---|
| V3-010 | run/task/finding/action 层级原子预留；模型调用统一走预算/权限 | `agent/platform/adaptive/budget.py`、`llm_gateway.py`；主循环接线 `controller.py`、`cli.py` | T11 |
| V3-011 | campaign_jobs 表 / lease / fencing，关联既有启动器 `jobs` | `adaptive/jobs.py`、`agent/platform/store.py`、`vulnmap_platform/api/platform_jobs.py` | T12 / T13 |
| V3-012 | UNKNOWN 先对账外部副作用，不盲目重放；已完成复用 | `adaptive/recovery.py` | T13 |
| V3-013 | 取消/超时/失败回收；伪造身份/越权/跨任务反例 | `agent/platform/lifecycle.py` | T07 / T09 / T12 |

规模（实测 `wc -l`，不估算）：`budget.py` 894、`llm_gateway.py` 958、`jobs.py` 336、
`recovery.py` 339、`lifecycle.py` 481（P2 段 1–180，P3 段从第 181 行起共 301 行）、
`store.py` 1259、`controller.py` 881、`cli.py` 820、`platform_jobs.py` 428、
`tests/test_v3_p3.py` 989。

## 1. 预算：层级、原子性、三态结算（V3-010）

### 1.1 数据模型

`BudgetLedger` 自己建两张表（`SCHEMA_SQL`，可与平台库同文件，也可独立文件）：

```text
budget_scopes(scope_id PK, level, parent_id, limits_json, used_json,
              reserved_json, currency, price_version, created_at, updated_at)
budget_reservations(reservation_id PK, scope_id, chain_json, level, action_id,
                    tool, amount_json, charged_json, state, usage_missing,
                    idempotency_key, note, created_at, updated_at, settled_at)
```

- 层级固定 `run ⊃ task ⊃ finding ⊃ action`；`chain()` 拒绝**层级倒挂**
  （action 挂在 run 下面）与环，深度上限 8。
- `limits` 里没声明的键放行（“没有限额”不等于“0 限额”）；`usd` 与
  `seconds/execs/tokens/turns` 是同一张表的键，金额不另开一套字段。

### 1.2 原子预留

`reserve()` 的全部动作在一个 `BEGIN IMMEDIATE` 事务里：读祖先链 → 逐层校验
`used + reserved + want ≤ limit` → 写一条 `budget_reservations` → 逐层累加
`reserved`。并发预留只有拿到写锁的那个能成功：

```python
# tests/test_v3_p3.py::test_budget_reserve_is_atomic_under_parallelism
32 个线程各 reserve({"turns": 1})，限额 8  →  granted == 8（不是 7，也不是 9）
```

原子性不是靠 Python 锁，而是靠 SQLite 写事务——**换进程也成立**（审计用 16 个真
`python3 -c` 进程复核：8 次成功、56 次被拒，`reserved` 恰好 8.0）。

### 1.3 结算三态：真实 / 保守 / 退还

| 路径 | 语义 | 触发 |
|---|---|---|
| `settle(rid, usage)` | 按 provider 真值扣 | provider 给出 usage |
| `settle(rid, None)` | **按预留额保守扣**，`usage_missing=true` | 缺 usage / 失败 / 协议错误 |
| `release(rid, reason)` | 退还预留，零扣账 | 动作被拒绝、或证明没有发出去 |

- **绝不填 0**：缺 usage 时 charged 取预留额。0 的含义是“确实没花”，不是“不知道花多少”。
- **失败也收费**：`Registry` 的 handler 抛异常时照样 `settle(want)`。
- **重复结算幂等**：同一条预留第二次 `settle()` 返回 `already=True`，不再累加。
- **幂等键**：`reserve(..., idempotency_key=...)` 同键返回同一条记录（重试不重复扣）。
  但若那条预留**还开着**（另一个执行者正在用），第二次来会被拒
  （`reservation_in_flight`）——否则并发下会拿同一条预留发两次真实请求而不花钱。
- **没预留的键也扣**：`settle(rid, {"turns": 1, "tokens": 900})` 里 `tokens` 没预留过
  也照样计账（记进 `overage`），账要真实，不能只在 note 里提一句。
- **被拒动作必须退还**：`Registry` 在 `ActionRejected` 分支调端口
  `release_pending()`，否则一次参数错误就永久占住额度（审计实测：被拒一次占掉一半额度）。

### 1.4 预算终止不改结果真假

`exhausted(scope_id)` 返回 `BudgetStop`，其中 `affects_result_truth` **恒为 False**：

- 预算不够时动作是 `rejected / budget_exceeded`，不是 `failed`，更不是 `no_repro`；
- 已经产生的 `ActionResult` 不会被预算终止改写；
- `BudgetStop` 只带 `reason / level / scope / remaining / violations`，没有任何裁决字段。

### 1.5 价格表

`PriceTable(version, currency, models={model: {input_per_1k, output_per_1k}})`。
默认 `EMPTY_PRICES`（版本 `unconfigured`、空表）——**不编造单价**。

规则：scope 或祖先声明了 `usd` 上限、而价格表不认识该模型 → 付费调用 `rejected /
price_unknown`（不预留、不调用）。宁可走规则模式，也不写一个假的 0 元账单。

### 1.6 接进生产路径（审计前的最大漏洞）

P3 第一版只把账本做出来，**研究主循环还在用 `DeclaredBudget`**——审计用两个线程证明
它仍然能双花（两个 `check` 都 True、`used=2` 超过上限 1）。现在：

- `ResearchController.__init__` 在没有显式 `budget` 时，按 `store.path` 建
  `BudgetLedger`，`ensure_chain(run=campaign, task=task_id, limits=task budget)`
  并返回 `LedgerBudget`（拿不到真库的纯离线替身才回退 `DeclaredBudget`）；
- `cli.run_research` 把账本落到 `paths["root"]/budget.db`，`run=campaign`、
  `task=task_id`，限额来自任务预算；
- 两条路径都用 `seed_usage()` 把**历史事件里的用量**作为起点（只抬不降），
  换账本不会让预算“凭空回血”；
- 回归断言：`test_controller_default_budget_is_transactional` 直接检查
  `isinstance(controller.budget, LedgerBudget)` 且占满额度后 `check()` 被拒。

## 2. 模型网关：唯一出口（V3-010）

`LLMGateway.call()` 是研究侧唯一允许调 provider 的地方，八段顺序固定：

```text
① 权限/白名单 → ② 缓存 → ③ 取 key → ④ 事务预留 → ⑤ 调用（失败也计费）
→ ⑥ 密钥卫生 → ⑦ 结算（真值/保守）→ ⑧ 成功才入缓存
```

| 分支 | status | charged | 说明 |
|---|---|---|---|
| `grant` 无 `L2` | `rejected` | `{}` | 外部访问未授权：不预留、不取 key、不调用 |
| 无 client / 无 key | `skipped` | `{}` | `error.code="no_key"`、`error.fallback="rule"` |
| usage 齐全 | `ok` | `{tokens, turns, usd}`（`usd` 仅价格表认识该模型时） | `usage_source="provider"` |
| 缺任一 usage 字段 | `ok` | 预留额 | `usage_source="unknown"`、`usage_missing=true` |
| client 抛异常 | `failed` | 预留额 | `client_error`：钱已花出去，照样记账 |
| 回包非 Mapping | `failed` | 预留额 | `protocol_error` |
| 回包含 key 原文（含 `bytes`） | `failed` | 预留额 | 文本 `[redacted]`、`secret_in_output`、不入缓存 |
| 缓存命中 | `ok` | `{}` | `cached=true`、`usage_source="cached"`、零预留零调用 |
| 已结算幂等键复用 | `rejected` | `{}` | `idempotent_replay` |
| 同键预留仍开着 | `rejected` | `{}` | `reservation_in_flight`（并发时只允许一个执行者） |

**密钥卫生**：key 只在 ③ 取一次，作为局部变量传给 client，随后丢弃；`ModelCall` 与
`snapshot()` 只有 `key_ref`（`platform-credential:llm`）与 `key_present`，`key_scope="platform"`。
`_secret_paths()` 递归 `Mapping/list/str/**bytes**`（bytes 是审计打穿的洞：以前
`b"echo:"+key` 会原样进结果与缓存），只报位置不报内容；`_scrub()` 把 bytes 解码后再打码。
测试断言：结果 JSON、`snapshot()`、临时目录里的文件都不含 key 原文。

**子调用计入同一 campaign 预算**：`gateway.child(action_id=…)` 在 `action:<id>` 上挂子
scope，`reserve()` 沿 `action → finding → task → run` 逐层扣。action 层不能再挂 action
（`scope_order`），父网关要建在 finding/task 层。

**缓存键**：`digest_of({model, prompt, system, tools, temperature, max_tokens, policy_version})`。
换 policy 版本即失效。

## 3. Campaign 子 Job：lease / fencing / 关联启动器（V3-011）

### 3.1 与既有 `jobs` 的分工

| 台账 | 视角 | 回答的问题 |
|---|---|---|
| `vulnmap_platform` 的 `jobs` | 启动器（进程） | pid 活着吗、退出码多少、日志在哪 |
| `campaign_jobs`（新） | campaign（实验） | 谁拥有这次执行、租约到什么时候、第几代 fence、结果能不能复用 |

`campaign_jobs.launcher_job_id` 指回 `jobs.job_id`；`jobs` 表新增 `campaign`、`job_key`
两列（老库用 `PRAGMA table_info` 幂等 `ALTER TABLE` 补齐）。启动器状态机
（`PENDING/RUNNING/EXITED/FAILED/CANCELLED`）**一个字没改**。

### 3.2 状态机

```text
PENDING --claim(fence+1, attempt+1)--> RUNNING --finish--> SUCCEEDED | FAILED
   ^                                      |
   |                                      +--lease 过期/所有权不明--> UNKNOWN
   |                                                                    |
   +-------------- reconcile(PENDING, fence+1)--------------------------+
                                                                        |
                              reconcile(SUCCEEDED/FAILED) --终态-------> 终态
任意非终态 --cancel(fence+1, 撤租约)--> CANCELLED
```

`SUCCEEDED / FAILED / CANCELLED` 是终态；**`UNKNOWN` 不是**。只从 PENDING 认领：
RUNNING 的租约过期是“所有权不明”，必须先落 UNKNOWN 再对账。

### 3.3 身份与幂等提交

`finish()` 的落库条件是 **owner + fence + status=RUNNING + execution** 全对：

- owner 不对 → `stale_owner`；fence 不对 → `stale_fence`；job 已终态 →
  `terminal_already_set`；
- job **已绑定** `execution_id` 时，提交必须声明**同一个** id：既不能声明别的
  （`cross_execution`），也不能不声明（审计发现的空串绕过已封堵）；
- 绑定/关联这两个写口（`set_campaign_job_execution`、`attach_campaign_launcher`）
  **强制要求当前 owner+fence**（否则谁都能改掉执行身份、把取消指到别人的进程）；
- `mark_campaign_job_unknown` 带 fence 时校验 generation：旧 lease 的 `abandon`
  不能把新 owner 的 RUNNING 打掉。

去重：`create_campaign_job` 用 `request_hash` 查 `SUCCEEDED`，命中返回
`reused=True`；换 `job_key` 绕不过去。

**迟到结果**：`campaign_job_late(job_key, owner, fence, status, payload_json, reason)`
只归档，终态不变（`late=True`、`accepted=False`）。

## 4. 恢复与副作用对账（V3-012）

`recovery.recover(store, boot_id=..., apply=...)` 对每个 job 给出一个
`RecoveryAction`，`apply=False` 是 shadow（只出计划，不改库）。

| job 现状 | 证据 | 动作 |
|---|---|---|
| 终态 | — | `reuse`（不重跑） |
| `PENDING` | — | `dispatch`（从未执行过） |
| `RUNNING`，租约未过期且本进程 | — | `hold`（可能只是慢） |
| `RUNNING`，进程还活着 | launcher `RUNNING` | `hold`（不抢活着的进程） |
| `RUNNING`，租约过期 | artifact 在 | **先 `mark_unknown`**，再对账成 `SUCCEEDED`（复用，`replayed=0`） |
| `RUNNING`，租约过期 | 启动器非 0 退出、副作用 `none` | **先 `mark_unknown`**，再对账成 `FAILED` |
| `UNKNOWN` | artifact 在 | `reconcile → SUCCEEDED` |
| `UNKNOWN` | 副作用 `possible`/`external`、证据不足 | `hold` + `needs_manual=true`（**禁止自动重放**） |
| `UNKNOWN` | 启动器 `MISSING`、副作用 `none` | `requeue → PENDING`（唯一允许重派的自动路径） |
| `UNKNOWN` | 证据不足 | `hold` + `needs_manual=true` |
| 有 `cancel_requested_at` | — | `cancel`（撤 lease） |

- 两个探针由调用方注入（`launcher_probe` / `evidence_probe`）；探针缺失或抛错一律当
  **事实不明**（`unknown`），不是当“没跑”。
- **单个 job 落地失败不中断整轮**：`_apply` 抛异常时把该条降级成
  `hold / apply_failed:<原因>` + `needs_manual`，后面的 job 继续处理（审计发现的
  “RUNNING 直接 reconcile → 契约拒绝 → 整轮扫描中断”已修）。
- **人工入口同样有副作用闸门**：`reconcile_job(verdict="PENDING")` 对
  `external/possible` 的 job 只返回 `hold`，要重派必须 `force=True`。
- `recover(..., lease_reaper=ledger)` 会顺手 `expire_open_reservations()`：崩溃留下的
  未结算预留不会永久占额。

## 5. 取消、超时、失败回收与安全反例（V3-013）

### 5.1 取消序列（`lifecycle.cancel_task_full`）

顺序固定，写进返回值与证据（`RECLAIM_ORDER`）：

```text
① 事件 task.cancel_requested
② 拒绝新 job / 撤销 lease（cancelled + fence+1，之后认领一律失败）
③ 终止进程组（SIGTERM → 宽限 → 若仍存活再 SIGKILL；组不在则对 pid 单发）
④ 保存证据（cancel_snapshot：job 列表、信号、预算用量、事件数）
⑤ 事件 task.cancelled + 状态 CANCELLED
```

`kill_process_tree()` 有两条硬规则：pid 为 0/空 → 什么都不做；**pid 等于调度进程自己 →
跳过**（`skipped="self_pid"`）。启动器侧 `platform_jobs._signal_process` 也有同样的守卫
（审计实测：脏 pid 会让 API 进程被自己的 SIGTERM 杀掉，`rc=-15`）。

`reclaim_expired_leases()` 把过期租约的 RUNNING 标 UNKNOWN 并发 `job.unknown` 事件；
`reclaim_failed_task()` 走“撤 lease → 杀进程树 → 证据 → FAILED”，落 `FAILED` 而不是 `NO_REPRO`。

### 5.2 安全反例（稳定错误码）

| 反例 | 入口 | 错误码 |
|---|---|---|
| 请求带别人的 `task_id` | `guard_task_scope` | `cross_task` |
| 冒用/空 owner 提交结果 | `guard_job_owner` | `forged_identity` |
| 用旧 fence 提交（迟到） | `guard_job_owner` | `stale_fence` |
| 终态之后再提交 | `guard_job_owner` | `late_result` |
| 提交别的/空的 `execution_id` | `guard_job_owner` / `finish` | `cross_execution` |
| `L3`（裁决/可信面） | `guard_permission` | `privilege_denied` |
| `L2` 但没 `allow_external` | `guard_permission` | `privilege_denied` |
| 改绑执行身份 / 关联启动器不带 owner+fence | `store.set_campaign_job_execution` / `attach_campaign_launcher` | `forged_identity` |
| 终态改写成别的结论 | `reconcile_campaign_job` | `terminal_override` |
| 对非 UNKNOWN 对账 | `reconcile_campaign_job` | `not_unknown` |
| 重派外部副作用未对账的 job | `reconcile_campaign_job` | `external_effect_unresolved` |

错误码表：`LifecycleError.CODES`、`CampaignJobError.CODES`（构造期校验，写了表外的码
直接算编程错误）。

## 6. 事件

| 事件 | 何时 |
|---|---|
| `task.cancel_requested` | 取消序列第一步（带 `order`：整个回收顺序） |
| `task.cancelled` | 取消落终态（带证据 sha256、job 计数、启动器信号） |
| `task.failed` | 失败回收落 FAILED（带证据 sha256） |
| `job.unknown` | 租约过期/所有权不明（带 job_key、campaign、fence） |

`budget.reserved / budget.settled` 目前只在账本表里（`budget_reservations`）：
一次动作的账已经由 `ActionResult.budget`（`reserved/used/port`）随结果带出，
再写一条事件属于重复记账（§10 列为未做项）。

## 7. 测试（`tests/test_v3_p3.py`，30 项）

| 测试 | 覆盖 |
|---|---|
| `test_budget_reserve_is_atomic_under_parallelism` | T11 原子预留（32 线程 / 限额 8） |
| `test_budget_hierarchy_charges_children_and_missing_usage` | T11 层级汇总、保守扣账、退还、幂等结算 |
| `test_budget_failed_action_is_charged_and_stop_keeps_result_truth` | T11 失败计费、`BudgetStop` 不改真假、预算不够是 rejected |
| `test_budget_idempotency_in_flight_is_refused` | T11 同键在飞时拒绝（并发不漏扣） |
| `test_rejected_action_releases_reserved_quota` | T11 被拒动作退还额度 |
| `test_handler_declared_rejection_does_not_charge` | T11 handler 自报 rejected 也不扣钱 |
| `test_registry_charges_extra_usage_keys` | T11 未预留的 key 也如实扣（overage） |
| `test_llm_gateway_settles_real_usage_and_charges_failures` | T11 真值/缺 usage/失败三分支 |
| `test_llm_gateway_enforces_permission_prices_and_key_hygiene` | T11 权限、价格表、无 key 回退、key 不进结果/工作区、缓存零扣 |
| `test_llm_gateway_idempotent_replay_is_refused_not_free` | T11 幂等键不能白嫖 |
| `test_gateway_bytes_output_cannot_smuggle_key` | 审计回归：bytes 回包打码 + 不入缓存 |
| `test_llm_gateway_child_calls_count_against_ancestors` | T11 子调用三层同时扣 |
| `test_campaign_job_claims_are_fenced_and_late_results_are_archived` | T12 认领唯一、续租、迟到不覆盖终态 |
| `test_campaign_job_expired_lease_goes_unknown_before_requeue` | T12/T13 过期→UNKNOWN→对账→重派→旧 lease 失效 |
| `test_campaign_job_links_launcher_and_reuses_successful_request` | T09/T12 execution 绑定、请求去重、启动器关联 |
| `test_finish_requires_execution_identity_once_bound` | 审计回归：空 execution_id 不能绕过 |
| `test_store_binding_helpers_require_owner_and_fence` | 审计回归：改绑/关联/abandon 都要 owner+fence |
| `test_reconcile_cannot_requeue_external_side_effects` | 审计回归：external 只能 force 重派 |
| `test_recovery_reuses_finished_and_reconciles_unknown_with_evidence` | T13 已完成复用、artifact 对账、`replayed=0` |
| `test_recovery_never_replays_external_side_effects` | T13 外部副作用禁止自动重放；`none` 才重派 |
| `test_recovery_applies_running_jobs_without_aborting_the_scan` | 审计回归：RUNNING 对账能落地、单点失败不中断整轮 |
| `test_recovery_manual_requeue_respects_side_effect_gate` | 审计回归：人工重派也要过副作用闸门 |
| `test_recovery_shadow_mode_and_cancel_requested` | T13 shadow 不改库、取消后迟到归档 |
| `test_recovery_decide_is_pure_and_handles_live_lease` | T13 判定是纯函数、活进程不抢 |
| `test_cancel_task_full_kills_process_tree_and_keeps_terminal` | T12 真进程树、撤 lease、证据、迟到不改终态 |
| `test_reclaim_expired_and_failed_task` | T12 超时回收 → UNKNOWN + `job.unknown`；失败回收 → FAILED |
| `test_lifecycle_guards_reject_forgery_and_cross_task` | T07/T09 六类反例 + 越权 |
| `test_store_rejects_terminal_override_and_unknown_verdict` | T07 终态不可改写、非 UNKNOWN 不能对账 |
| `test_controller_default_budget_is_transactional` | 审计回归：主循环默认预算就是事务账本 |
| `test_platform_jobs_cancel_never_signals_self` | 审计回归：启动器侧 self_pid 守卫 |

进程/租约/账本都是真实实现（真 SQLite 事务、真 `SIGTERM/SIGKILL`、真子进程），
只有“外部模型客户端”和“启动器进程启动”两处是可控替身。

## 8. 兼容性

- `PlatformStore.SCHEMA_VERSION` 4 → **5**（新增 `SCHEMA_P4`：`campaign_jobs`、
  `campaign_job_late` 与索引）。老库打开时幂等执行 `CREATE TABLE IF NOT EXISTS`。
  `tests/test_platform_v2_p45.py` 里写死的 `user_version == 4` 改成与
  `store.SCHEMA_VERSION` 比较——那条测试的本意是“API 侧 jobs 表不改变 PlatformStore
  的 schema 版本”，不是钉死数字。
- `jobs` 表新增 `campaign` / `job_key` 两列，读路径仍用 `mode=ro`；GET 不建库的
  约束没变。
- `lifecycle.cancel_task()` / `terminate_budget()` 签名与行为不变（P3.6 的测试照跑）。
- `controller`/`cli` 的默认预算对象从 `DeclaredBudget` 换成 `LedgerBudget`：
  `BudgetPort` 协议没变（`check/settle/snapshot`），显式传入 `budget=` 的调用方
  （含 P2b 测试）行为不变。
- 新模块位于 `agent/platform/adaptive/`，`adaptive.__init__` 追加导出；
  `verify.py`、`policy.py` 的判据没有改动。

## 9. 独立红队审计：打穿了什么、怎么修的

审计方（只读、脚本在 `/tmp/p3audit/`）对最终状态的结论与修复：

| 审计项 | 结论 | 修复 |
|---|---|---|
| 预算双花（线程/进程/幂等/重复 settle/退款） | PASS | —（16 个真进程复核通过） |
| **主循环没接事务账本** | FAIL | `controller._ledger_budget()` + `cli.run_research` 换 `LedgerBudget` + `seed_usage()`；新增 `test_controller_default_budget_is_transactional` |
| **幂等键并发 = 一次免费调用** | FAIL | `reserve()` 对“同键仍 open”抛 `reservation_in_flight`；新增 `test_budget_idempotency_in_flight_is_refused` |
| **被拒动作永久占额** | FAIL | `Registry` 在 `ActionRejected` 分支 `release_pending()`；新增 `test_rejected_action_releases_reserved_quota` |
| 跨线程 settle 静默不扣 / 未预留键不扣 | FAIL（低危） | `LedgerBudget` 增加“最近一条 open 预留”回退；`settle()` 对 extra 键也扣并记 `overage`；`ToolOutcome(status="rejected")` 改为退还而不是结算 |
| **bytes 回包把 key 带进结果与缓存** | FAIL | `_secret_paths`/`_scrub` 支持 bytes，`text` 归一成 str；新增 `test_gateway_bytes_output_cannot_smuggle_key` |
| **空 `execution_id` 绕过 T09** | FAIL | 已绑定 execution 时提交必须声明同一个 id；新增回归测试 |
| **改绑/关联不带 owner+fence** | FAIL | 两个写口强制 owner+fence（`forged_identity`） |
| **旧 fence 的 abandon 打掉新 owner** | FAIL | `mark_campaign_job_unknown` 校验 fence |
| **`reconcile(PENDING)` 可重派 external** | FAIL | 契约层 `external_effect_unresolved` + 人工入口闸门（`force=True` 才放行） |
| **`recover` 在 RUNNING 路径抛异常、中断整轮** | FAIL | `_apply` 先 `mark_unknown` 再对账；`recover` 逐 job try/except 降级为 `hold/apply_failed` |
| **启动器侧 cancel 无 self_pid 守卫** | FAIL | `platform_jobs._signal_process` 返回 `skipped:self_pid`；新增回归测试 |
| 取消是否干净（终态/认领/迟到） | PASS | — |
| 文档与代码一致 | FAIL（5 处） | 本文件已按下列修正：P3 段行号、`finish` 的 execution 条件、§4 的 RUNNING 行、`usd` 只在价格表认识模型时出现、被拒动作退还预留；`killpg` 后仍会对 pid 补发也是文档写错，已改 |

审计还指出 `assert_no_secret` 目前无人调用（属报告侧工具），保留但标注为工具函数。

## 10. 仍然没做（明确边界）

1. **多机/多进程共享账本**：原子性靠 SQLite `BEGIN IMMEDIATE`，单机多 worker 成立；
   跨机要换 Postgres 或集中式租约服务。
2. **预算事件流**：账本表是唯一事实源，`budget.reserved/settled` 未单独发事件。
3. **UNKNOWN 对账的完整证据链**：探针由调用方注入，目前只有 launcher 视图与 artifact
   视图，没有核对容器/镜像 digest 这类执行身份。
4. **外部副作用的具体分类器**：只有 `none/possible/external` 三档，登记靠调用方；
   真实“网络 flag 提交”的探针没写。
5. **`campaign_jobs` 的 HTTP 读视图**：本阶段只有 store/jobs 层与 `platform_jobs` 的
   campaign 过滤，没有新增端点（P4 的 V3-014）。
6. **模型网关的真实 provider 客户端**：`client` 是注入的，仓库没绑具体厂商 SDK，
   也没做流式/重试预算（重试要重新预留，已写进错误 hint）。
7. **`uuid` 不能用**：`uuid` 会 `import platform`，被 `bin/platform.py` 截胡成循环
   import（全量回归第一次跑出 35 个 CLI 失败）。P3 的 id 一律 `os.urandom(...).hex()`。

## 11. 怎么复核

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_v3_p3.py -q                 # 30 passed
python3 -m pytest tests/test_v3_p2_session.py tests/test_v3_p2_contracts.py \
                 tests/test_v3_p2c_research_cli.py \
                 tests/test_platform_v2_p36.py tests/test_platform_v2_p45.py -q
python3 -m pytest -q                                     # 全量（P3 交付时 1421 passed / 8 skipped，另见 §9 的并行 P4 说明）
python3 -c "from agent.platform.adaptive import BudgetLedger, CampaignJobs, LLMGateway; print('ok')"
```

手工验证原子性/杀进程树时，注意 `tests/test_v3_p3.py` 里的 `FakeProc` 与
`_tree_script`：前者替身启动器（只为让 watcher 落终态），后者是**真**父子进程树。
