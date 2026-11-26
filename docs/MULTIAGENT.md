# 多智能体架构（v1，参考 BinSight）

> 背景：本项目此前按“阶段”不断 spawn，累计 8 个 teammate、11 个 task，管理成本高于收益。
> 本文件把 BinSight 的**任务队列 + Worker lease + Executor 注册表**模型落到 vulnmap，替代“按阶段开人”。

---

## 0. 先说清 BinSight 到底是什么架构

它不是 agent-to-agent 互相派活，而是：

`%text
Task 表（DB） → Worker 进程 claim（lease） → Executor 按 stage 执行 → 产物入 content-addressed store
                                      ↑
                             AgentRuntimeRouter（claude-code / dsh）按角色调用模型
`%

对应源码：

| 机制 | BinSight 位置 |
|---|---|
| 任务状态机与租约 | `runtime/runner.py`（`_claim_and_start` / `_takeover_lease`） |
| 执行器注册表 | `executors/__init__.py`（30+ executor） |
| 运行时路由 | `agents/router.py` + `agents/contracts.py` |
| 检查点 | `persistence` 的 `task_checkpoints` |
| 产物存储 | `artifacts/local.py`（sha256 内容寻址） |

**结论：借鉴的是“队列 + 租约 + 执行器”，不是“多 Agent 群聊”。**

---

## 1. 本项目的三层结构

| 层 | 职责 | 落点 |
|---|---|---|
| 角色层 | 谁能做什么、能写哪里 | `agent/team.py` 的 role + write scope |
| 任务层 | 待办、租约、重试、验收 | `team_tasks` / `team_attempts` 两张表 |
| 执行层 | 真正跑命令、落产物、过验收 | `Stage` 与 `experiments/*` 脚本 |

角色只有三个，长期常驻：

| 角色 | 权限 | 典型任务 |
|---|---|---|
| `auditor` | 只读：审计、台账、测试、比对 | check_consistency、eval_set、leak_scan |
| `builder` | 写：限定 write scope | 构造器、loop、harness 提取 |
| `reviewer` | 只读 + 出结论 | 严重性裁决、验收报告 |

---

## 2. 任务状态机（与 Runner 对齐）

`%text
queued → leased → running → done
            │        ├→ failed（可重试，最多 max_attempts）
            │        └→ cancelled
            └→ lease 过期 → queued（可被其他 Worker 接管）
`%

规则：

1. **先入队再干活**：任何子智能体任务必须先写 `team_tasks`；
2. **lease 领取**：默认 900 秒，心跳续租；过期自动回收；
3. **写域互斥**：`scope` 有交集的两个活动任务不能被同时持有（`_scope_conflict`）；
4. **完成必须带产物哈希**：`complete(artifact_sha=...)` 缺一不可；
5. **失败计数**：同一任务最多 3 次，超限进 `failed`，不再自动重试。

---

## 3. 队列 API（已实现）

`%python
from agent.team import TeamQueue

q = TeamQueue("experiments/team.db")
q.enqueue(task_id="s5-cg08", role="builder", subject="CG-08 构造器",
          scope="agent/builders/cg08.py,tests/test_cg08.py",
          acceptance="pytest tests/test_cg08.py -q")

task = q.claim("builder-1", lease_seconds=900)   # 原子领取
q.start(task.id, "builder-1")
q.heartbeat(task.id, "builder-1")
q.complete(task.id, "builder-1", artifact_sha=sha, result="pass")
`%

测试：`tests/test_team_queue.py` 5 项（领取一次、写域冲突、租约接管、产物必填、重试上限）。

---

## 4. 与“按阶段 spawn”的差别

| 维度 | 旧做法（本项目前 11 个 task） | 新做法 |
|---|---|---|
| 成员数量 | 8 个 teammate，按阶段开 | **2 个常驻**（auditor / builder）+ 1 个 reviewer |
| 任务记录 | 只在对话里 | `team_tasks` 表，可查历史 |
| 写冲突 | 靠人工约定 | `scope` 互斥，claim 时拦截 |
| 失败重试 | 重新 spawn | lease + attempts，最多 3 次 |
| 完成标准 | 口头说“做完了” | `acceptance` 命令 + `artifact_sha` |
| 中断恢复 | 对话丢失即丢 | lease 过期自动回收，任务仍在队列 |

---

## 5. 执行器（Executor）怎么对应

BinSight 用 `ExecutorRegistry` 把 stage 映射到执行器；我们不需要 30 个，只要 6 个：

| Executor | 角色 | 输入 | 验收 |
|---|---|---|---|
| `audit_consistency` | auditor | workspace/* | 0 mismatch |
| `audit_evalset` | auditor | PROVENANCE | 互斥 + manifest 完整 |
| `build_constructor` | builder | claim + 格式 | 双端通过 |
| `extract_harness` | builder | fuzzer 源码 | 契约置信度 ≥ exact |
| `severity_draft` | reviewer | case.json | 6 维 + CVSS 复算 |
| `reproduce_case` | auditor | case 目录 | 重放 3/3 |

注册方式与 BinSight 一致：`dict[str, Executor]`，按 task.role 分发。

---

## 6. 预算、心跳与止损

| 项 | 规则 |
|---|---|
| lease | 900s，心跳每 120s；过期回收 |
| attempts | 3 次；第 3 次失败进 `failed` 并写原因 |
| 预算 | 沿用 `BudgetLease`；单任务 tokens/时间单独记账 |
| 止损 | 同一任务连续 2 次无新增产物 → 终止，写 `no_progress` |

---

## 7. 迁移计划

1. **P0（本次）**：`agent/team.py` 落地 + 测试通过；后续任务一律先入队；
2. **P1**：把 3 个角色固化为 `experiments/workers/{auditor,builder,reviewer}.md` 的职责说明；
3. **P2**：写一个 `experiments/team_worker.py` 的 CLI（claim → 执行 → complete），让子智能体只负责“执行”，不再各自造流程；
4. **P3**：把 `STATUS.md` 增加一列“任务队列状态”（queued/running/failed 数）。

---

## 8. 反模式（本轮踩过的）

1. **按阶段开人**：S0 开了 4 个，其实 2 个够；
2. **同文件并发**：两个 builder 同时改 `verify.py` 的风险，靠人工避免，现在由 scope 拦截；
3. **口头验收**：子智能体说“完成了”，但没跑 acceptance 命令；
4. **失败就换人**：没有 attempts 记录，无法判断是能力问题还是环境问题。

**一句话：把“派活”从对话搬到队列，把“完成”从口头搬到验收命令。**