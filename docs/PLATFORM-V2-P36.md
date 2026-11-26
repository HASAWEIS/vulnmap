# 平台 v2 P3.6：预算强制 + 取消路径 —— 让“跑不下去”成为一等状态

> 范围：P0–P3.5 已经有了完整链路（准入 → 理解 → 假设 → 规划 → 执行 → 候选 → 验证 →
> 复核 → Case Pack），但**预算只写在 Plan 里、没人执行**，**RUNNING 也没有退出开关**。
> P3.6 把两件事变成状态机里的硬约束：
> 预算用尽 → `TERMINATED`（`reason=budget_*`），人工取消 → `CANCELLED`；
> 两者都不是“没跑出结果”，因此**永远不写 NO_REPRO**。
> 前置：[PLATFORM-V2-P2.md](PLATFORM-V2-P2.md) 的执行编排、
> [PLATFORM-V2-P35.md](PLATFORM-V2-P35.md) 的证据口径、
> [PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §3 状态机。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/budget.py](../agent/platform/budget.py) | `BudgetGuard` 账本 + 判定：`max_seconds/max_execs/max_tokens/max_turns`，用量从事件流推导，预检（`>=`）/结算（`>`）双口径 |
| [agent/platform/lifecycle.py](../agent/platform/lifecycle.py) | `cancel_task()` / `terminate_budget()` / `snapshot_evidence()`：先落证据再改状态，`cancel_snapshot` / `budget_snapshot` 可复算 |
| [agent/platform/task.py](../agent/platform/task.py) | 状态机新增 `CANCELLED` / `TERMINATED`（均终态）+ `CANCELLABLE` 集合 + `PLANNED/RUNNING → TERMINATED` 边 |
| [agent/platform/executors/__init__.py](../agent/platform/executors/__init__.py) | 执行前预检 → 秒数夹紧 → `exec.started.caps` → 片边界结算 → `budget.exceeded` + `task.terminated`；取消优先；失败写 `exec_error` 证据 |
| [agent/platform/executors/fuzz.py](../agent/platform/executors/fuzz.py) | 分片跑 D2（`_run_slices`）：每片后按 execs / 截止时间 / `should_stop()` 判定，`stats.stopped` 记账 |
| [agent/platform/store.py](../agent/platform/store.py) | `summary()` 增 `budget_usage`（上限 + 已用 + 严格口径超限项） |
| [bin/platform.py](../bin/platform.py) | 新命令 `cancel`、`budget`（只读）；`run --tokens-used`；`run` 超限退出码 3 |
| [tests/test_platform_v2_p36.py](../tests/test_platform_v2_p36.py) | 16 项验收：四个上限（预检/结算/截断）、取消（PLANNED/RUNNING/终态）、失败不降级、预算内完成、CLI 端到端 |

## 2. 为什么预算要进状态机

P2 的 `Plan.budget` 只是**请求值**（seconds/workers/timeout），执行器拿到就跑满，
跑完把结果落成 `CANDIDATE` 或 `NO_REPRO`。这留下三个洞：

| 洞 | 后果 | P3.6 的答案 |
|---|---|---|
| 任务级上限没人执行 | `TaskSpec.Budget` 是装饰品，一个任务可以无限跑 | 执行前预检 + 执行中结算，越限 `TERMINATED` |
| 超限被当成“没崩溃” | 预算切断的执行会落 `NO_REPRO`，把“没跑完”伪装成“不可复现” | 超限一律 `budget_*` + `task.terminated`，候选/证据照样留 |
| 没有退出开关 | `RUNNING` 只能等它自己结束 | `cancel` → `CANCELLED`，运行中在片边界探到即停 |

因此 `TERMINATED` 不是 `FAILED` 的子类，也不是 `NO_REPRO` 的变体：
`FAILED` 是“跑不起来/跑炸了”，`NO_REPRO` 是“跑完了没崩”，
`TERMINATED` 是“**预算不给了**”——三者在事件、证据、终态原因上都可区分。

## 3. 预算账本：从事件流推出来

不新增表。用量一律由 `task_events` 推导，所以进程重启、跨进程取消后账本依旧一致：

| 用量键 | 来源 |
|---|---|
| `seconds` | `exec.finished.payload.seconds` 累加（执行中的耗时另由 `BudgetGuard.elapsed()` 补） |
| `execs` | `exec.finished.payload.fuzz.execs` 累加 |
| `tokens` | `exec.finished.payload.tokens` + `model.used/llm.used` 等事件的 `payload.tokens`，以及 `run --tokens-used` 的显式值 |
| `turns` | `exec.started` 事件条数（每次执行 = 一回合） |

判定有**两个口径**，这是 P3.6 最容易搞错的地方：

~~~python
violations(budget, used, strict=False)   # used >= limit：没有额度再开一次执行（预检）
violations(budget, used, strict=True)    # used >  limit：真正超限（执行后结算）
~~~

- **预检**用非严格口径：`used == limit` 时已经不允许再开跑，直接 `TERMINATED`；
- **结算**用严格口径：一次执行正好把额度用满，仍按真实结果落 `CANDIDATE/NO_REPRO`，
  不会被误记成超限终止。

## 4. 执行编排：截断 → 分片 → 结算

`run_execution()` 的顺序（全部在 `PLANNED` 上游先判定，越限不写 `RUNNING`）：

1. **执行前预检**：`BudgetGuard(task.budget, used=usage_from_events(...)).precheck()`；
   越限 → `budget.exceeded` + `task.terminated`，状态 `PLANNED → TERMINATED`，返回
   `outcome=budget_exceeded`，执行器一次都不调用；
2. **额度夹紧**：`seconds = min(请求秒数, 剩余秒数)`，同时算 `deadline`（单调时钟）与
   `max_execs = 剩余 exec 额度`，全部写进 `exec.started.caps`；
3. **执行中**：`executors/fuzz.py` 把长跑切成片（默认 5 s/片），每片后看
   `累计 execs`、`deadline`、`should_stop()`（读状态机是否 `CANCELLED`），
   命中就停，并把 `stats.stopped` 记成 `execs/deadline/cancelled/completed`；
4. **结算**：`guard.absorb(execs=fuzz.execs)`（严格口径）；`stopped` 属于
   `execs/deadline` 说明执行器是被额度切断的，同样按 `budget_*` 终止——不冒充“跑完”；
5. **落结果**：预算内 → `CANDIDATE/NO_REPRO`（与 P2 逐字一致）；
   超限 → `task.terminated` + `TERMINATED`；取消 → 保持 `CANCELLED`。

> 片边界是唯一能安全插入判定的位置：`covfuzz.run_parallel` 是一次阻塞调用，
> 它内部没有回调。切片的代价只是多次 `mp.Process` 启动（每片 worker 数不变），
> 换来的是 `max_seconds`/`max_execs`/取消信号不必等整段跑完才生效。

## 5. 取消路径

~~~text
RECEIVED / PREFLIGHT / READY / UNDERSTANDING / HYPOTHESES / PLANNED / RUNNING /
CANDIDATE / VERIFYING / REVIEW / REPORTED  ──cancel──▶ CANCELLED（终态）
CLOSED / BLOCKED / FAILED / NO_REPRO / NEEDS_EVIDENCE / REJECTED /
CANCELLED / TERMINATED                     ──cancel──▶ TaskError（状态/事件/证据全不动）
~~~

- 主路径是 `RUNNING/PLANNED`，其余非终态也开放取消（同一个 `CANCELLABLE` 集合）；
- 终端状态 `CANCELLED`/`TERMINATED` 没有任何出边，`BLOCKED` 的“补材料重入”也不适用；
- 顺序固定为**证据 → 事件 → 状态**：

~~~text
task.cancel_requested  {from, reason, actor, usage}
   ↓  cancel_snapshot（canonical JSON + sha256 进证据库）
state.changed PLANNED|RUNNING → CANCELLED（terminal_reason = "cancelled: <reason>"）
   ↓
task.cancelled         {from, reason, actor, evidence_sha256}
~~~

- 运行中被取消（另一个进程 `platform cancel`）：执行器在下一个片边界看到
  `should_stop()`，`exec.finished(outcome=cancelled)`，**不写 NO_REPRO/CANDIDATE**，
  已产生的崩溃输入/日志照常进证据库，已跑掉的 execs/耗时也会记进账本
  （`budget_usage`，取消只记账不判定）；
- 片边界还有一道“worker 提前收工”的短路：worker 崩溃即停 / abort / 起不来时
  （`stats.stopped=workers_exited`）不再开新片，保持 P2 “一次 `run_parallel` 就是一轮”
  的语义；只有确实在长跑的 worker 才会进下一片；
- 取消与预算同时发生：**取消优先**（`terminate_budget` 只发 `budget.exceeded`，
  不再改状态，`task.terminated.payload.note` 写明原因）。

## 6. 失败 / 超时 / 取消都不降级

| 情形 | 状态 | 关键事件 | 证据 |
|---|---|---|---|
| 构建失败、执行器缺失 | `FAILED` | `exec.finished(outcome=failed)` | `exec_error`（错误类型/消息/预算快照） |
| 预算用尽（四个上限） | `TERMINATED` | `budget.exceeded` + `task.terminated` | `budget_snapshot` + `exec_stats`（+ 已产候选） |
| 人工取消 | `CANCELLED` | `task.cancel_requested` + `task.cancelled` + `exec.finished(cancelled)` | `cancel_snapshot` + `exec_stats` |
| 跑完没崩 | `NO_REPRO` | `exec.finished(outcome=no_repro)` | `exec_stats` |
| 跑完有崩溃 | `CANDIDATE` | `candidate.created` + `exec.finished(outcome=candidate)` | 崩溃输入/日志 + `exec_stats` |

三种非正常结束**都保留 `exec_stats` 快照**（本节新增），所以事后能回答
“停在哪一片、跑了多少 exec、覆盖到哪、当时预算是多少”。

## 7. 契约与口径

- `BudgetExceeded.reason ∈ {budget_seconds, budget_execs, budget_tokens, budget_turns}`，
  由 `REASON_BY_KEY` 唯一映射，写进 `task.terminated.payload.reason` 与
  `tasks.terminal_reason`；
- `Budget.max_*` 仍要求 `> 0`（`task.py` 原有校验），P3.6 不放松；
- `run_execution(tokens_used=...)` 只参与判定，不写回任何记录；
- `budget.exceeded` 与 `task.terminated` 都是**只写事件**：不产 Candidate、不产结论；
- `summary()` / `platform budget` 的 `used` 与强制判定同源（同一份事件流），
  不存在“显示值和判定值不一致”；
- 任何 P3.6 产物都不出现 `confirmed`，单端 fuzz 仍只到 `Candidate(state=new)`。

## 8. 使用示例

~~~bash
# 提交时就把预算钉死
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark target_yaml --target fixtures/discovery --task-id fx-p36 \
  --budget-seconds 120 --budget-execs 50000 --budget-tokens 200000 --budget-turns 3

python3 bin/platform.py --db .platform/platform.db preflight fx-p36
python3 bin/platform.py --db .platform/platform.db understand fx-p36
python3 bin/platform.py --db .platform/platform.db hypotheses fx-p36
python3 bin/platform.py --db .platform/platform.db plan fx-p36

# 跑一次；预算很紧时秒数会被自动夹到剩余额度
python3 bin/platform.py --db .platform/platform.db run fx-p36 --seconds 60
# 超限时退出码 3，输出 outcome=budget_exceeded + terminated{reason: budget_execs}

# 只读看账本（上限/已用/剩余/是否触顶）
python3 bin/platform.py --db .platform/platform.db budget fx-p36

# 取消（RUNNING/PLANNED 都可以；终态会失败退出码 2）
python3 bin/platform.py --db .platform/platform.db cancel fx-p36 --reason "operator stop"

# 取证：事件流 + 证据清单
python3 bin/platform.py --db .platform/platform.db events fx-p36
python3 bin/platform.py --db .platform/platform.db evidence fx-p36
~~~

## 9. 验收

~~~bash
python3 -m pytest tests/test_platform_v2*.py -q
# 103 passed（P0 7 + P1 13 + P2 11 + P3 11 + P4 19 + P3.5 26 + P3.6 16）
~~~

P3.6 的 16 项（`tests/test_platform_v2_p36.py`）：

| 断言点 | 口径 |
|---|---|
| 超 `max_seconds` | 执行前 `TERMINATED`，`terminal_reason=budget_seconds`，执行器零调用，`budget_snapshot` 可复算 |
| 超 `max_tokens` | LLM 用量从事件流累加；`run --tokens-used` 同口径 |
| 超 `max_turns` | `exec.started` 计回合，无额度即终止 |
| 秒数夹紧 | 请求 120 s → 实际 30 s（剩余额度），`exec.started.caps` 留证 |
| 超 `max_execs` | 执行后结算 → `TERMINATED`；已产候选、崩溃输入/日志、`exec_stats` 全留 |
| 执行器被额度截断 | `stopped=execs` → `TERMINATED`，不冒充“跑完” |
| 预算内完成 | `CANDIDATE` / `NO_REPRO`，`budget.exceeded=null`，`candidate.created` 齐 |
| 取消 `PLANNED` | `CANCELLED` + `cancel_requested`/`cancelled` + `cancel_snapshot` |
| 取消 `RUNNING` | `exec.finished(cancelled)`，状态保持 `CANCELLED`，不落 `NO_REPRO/CANDIDATE` |
| 终态取消 | `TaskError`，状态/事件/证据不变 |
| 失败 | `FAILED` + `exec_error` 证据，迁移序列里没有 `NO_REPRO` |
| CLI | `cancel`（终态再取消退出码 2）、`budget` 只读、`run` 超限退出码 3、真跑一次也是 `TERMINATED` |

## 10. 边界（P3.6 刻意不做）

- **不做抢占式 kill**：取消/超限在片边界生效，不会给 worker 发信号强杀；
  原因见 §4——`covfuzz.run_parallel` 是阻塞调用，强杀需要改 Discovery 的进程模型；
- **不改 Discovery**：`covfuzz.run_parallel` 一行未动，分片在 `executors/fuzz.py` 外层做；
- **不新增表/迁移**：用量全部由事件流推导，`SCHEMA_VERSION` 仍是 4；
- **不改 API/UI**：`cancel` 只有 CLI 入口；`STATES` 扩展后 P4 的只读接口自动兼容
  （状态过滤/统计来自同一个 `STATES`），但没有新增写接口；
- **不做预算的“续期”语义**：`TERMINATED`/`CANCELLED` 是终态，要重跑就新提交任务；
- **不改判据**：预算/取消只影响“跑到哪”，`verified`/`confirmed` 的推导链一个字没动。
