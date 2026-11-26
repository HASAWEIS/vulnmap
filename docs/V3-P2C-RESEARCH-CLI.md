# V3 P2c：研究循环的 CLI 接线（PLANNED → ResearchController → 映射终态）

对应《VULNMAP-V3 完整升级方案》§4「双循环与状态模型」、§5「执行感知」、
§8「实验自修改与版本事务」、§9「统一数据契约」、§12「独立验证」与 §18.1 门禁。
P2a 交付动作契约与可信快照，P2b 交付副本/慢循环/独立采纳；**P2c 把这条循环
接到真实入口上**：`python3 bin/platform.py run <task> --research`。

---

## 0. 实施清单

| 项 | 状态 | 验收口径 | 落点 |
|---|---|---|---|
| P2C-1 `run --research / --max-rounds / --campaign` | 已实施 | 三个参数真的进到 `run_research()`；PLANNED 任务不再走单次 `run_execution` | `bin/platform.py`（`cmd_run` / `_cmd_run_research` / 参数表） |
| P2C-2 控制器依赖装配 | 已实施 | task / store / `TaskWorkspace`（任务 overlay）/ `ProgramIndex` / `CorpusStore` / exec_runner / 预算 / 取消钩子全部由任务事实构造，报告里逐项可查 | `agent/platform/adaptive/cli.py`（`paths_for` / `open_workspace` / `open_corpus` / `run_research`） |
| P2C-3 exec_runner 接 fuzz 短切片 | 已实施 | 真调 `executors.fuzz.execute`；`exec.started/exec.finished` 进事件流；失败写 `exec_error` 证据，不降级成负结果 | `cli.FuzzEpochRunner` |
| P2C-4 输出与状态映射 | 已实施 | 输出 `ControllerResult` + `research.json` + `research.started/finished/mapped` 事件；状态按唯一映射表落库；不写 verified/confirmed、不建候选 | `cli.map_state` / `cli._settle_state` / `cli._report_body` |
| P2C-5 两轮反馈与有限停止 | 已实施 | 首轮 miss → 改副本 → 真构建/真冒烟 → 第二轮命中 → `CANDIDATE`；相同事实在第 3 轮停 | `tests/test_v3_p2c_research_cli.py`（用例 1/2） |
| P2C-6 无证据不伪造 | 已实施 | 只在返回值里“跑过”、事件流里没有执行事实 → `NEEDS_EVIDENCE`，不给 `NO_REPRO` | 同上（用例 3/4/5） |
| P2C-7 构建/冒烟失败不再崩控制器 | 已实施 | `build()`/`smoke()` 抛 `WorkspaceError` → `stage_failed`/`harness_error` + `BLOCKED`，并如实消费失效 | `adaptive/controller.py`（BUILD/SMOKE 的 `try/except WorkspaceError`） |
| P2C-8 语料端口复读 | 已实施 | fuzz 执行器用自己的构建身份 `begin()` 之后，外部语料端口能读到磁盘真相 | `adaptive/corpus.py`（`CorpusStore.reload()`） |

改动边界：`bin/platform.py`、`agent/platform/adaptive/`（新增 `cli.py`，
`controller.py` 的 BUILD/SMOKE 错误处理，`corpus.py` 的 `reload()`，
`__init__.py` 导出）、`tests/`、`docs/`。
**未改** `agent/platform/verify.py`、`benchmark_policy`、`executors/` 的执行语义
（只调用 `executors.fuzz.execute`）、API 层、DB schema。

---

## 1. 为什么必须接到真入口

P2b 的慢循环只有测试能跑：`ResearchController` 需要 8 个依赖，没有任何 CLI
路径把它装配起来。于是“自修研究”只存在于 pytest 里，平台层还是单次
`run_execution`。P2c 因此只做一件事：**把依赖装配、执行 worker、状态映射、
报告落盘点接死**，并且不允许这条路径比既有 `run` 松任何一档判据。

三条硬线：

1. **入口只认 PLANNED**：不是 `PLANNED` 就 `ResearchError`（CLI 退出 2），
   状态一个字节都不动——“没开始”和“跑失败了”必须分得开。
2. **执行事实只信事件流**：`run_epoch` 的反馈里写“我跑过了”不算数，
   `exec.started/exec.finished` 才进 `TrustedExecutionSnapshot`。
   没有事件 → 快照 unknown → 映射到 `NEEDS_EVIDENCE`。
3. **状态映射是唯一表**：`map_state()` 是控制器结果到平台状态的唯一解释器，
   CLI 退出码也由它派生，不允许第二处“顺手判一下”。

---

## 2. CLI

```bash
# PLANNED 任务 → 研究循环（默认 6 轮，campaign = 任务 benchmark）
python3 bin/platform.py run task-xxx --research

# 指定轮数与 campaign、显式给 overlay 的构建/冒烟命令
python3 bin/platform.py run task-xxx --research \
    --max-rounds 8 --campaign cg-p2c \
    --research-root .platform/research/task-xxx \
    --build-cmd 'python3 -m py_compile gen.py smoke.py' \
    --smoke-cmd 'python3 smoke.py'
```

| 参数 | 语义 | 缺省 |
|---|---|---|
| `--research` | 走 `ResearchController`（不再单次 `run_execution`）；`--kind` / `--replay-cmd` 不参与 | 关 |
| `--max-rounds` | 慢循环最多轮数（`0` = 控制器默认 6） | `0` |
| `--campaign` | 研究 campaign：进 `Binding`、语料分代、报告 | 任务 `benchmark` |
| `--research-root` | 研究目录（`ws/` `work/` `corpus/` `research.json`） | `<db 目录>/research/<task>` |
| `--research-origin` | overlay 的原件目录 | `task.target`（是目录时） |
| `--build-cmd` / `--smoke-cmd` | overlay 的构建/冒烟命令（空格分隔，按 shell 规则拆） | `metadata.build_command` / `metadata.smoke_command` |
| `--seconds` / `--workers` / `--timeout` | epoch 切片上限（被 `EPOCH_SECONDS=5.0` 与 worker 上限夹紧） | `0`（按控制器默认 0.2s/1 worker） |
| `--isolation` / `--require-isolation` | 传给 fuzz 执行器的隔离口径 | `auto` / 关 |
| `--tokens-used` | 本次之前已消耗 token（参与 `max_tokens` 预检） | `0` |

退出码：`0`=映射到 `CANDIDATE`/`NO_REPRO`；`1`=`BLOCKED`/`FAILED`/`NEEDS_EVIDENCE`；
`2`=前置条件不成立（状态不动）；`3`=`TERMINATED`（预算，与既有 `run` 的语义一致）。

---

## 3. 依赖装配（`cli.run_research`）

```text
paths_for()      → <root>/{ws, work, corpus, research.json} + evidence 目录
open_workspace() → TaskWorkspace.create()/open()（原件只读、副本可写）
open_corpus()    → CorpusStore.begin(build_identity(ProgramIndex 摘要))
plan_for_runner()→ 已存 Plan（没有就按任务事实合成，不造假字段）
FuzzEpochRunner  → executors.fuzz.execute（短切片 + 事件 + 证据）
BudgetGuard      → 执行前 precheck；DeclaredBudget 进控制器
cancel 钩子      → is_cancelled(store, task_id)（读状态机，不读内存）
```

### 3.1 overlay 只在“真能改真能跑”时才建

`open_workspace()` 的判据是**同时**有构建命令与冒烟命令、且原件目录可读：

| 情况 | `deps.workspace.mode` | 后果 |
|---|---|---|
| 有 `--build-cmd`/`--smoke-cmd` 或 `metadata.build_command`/`smoke_command` | `created` / `reused` | 慢循环可 stage→commit→build→smoke→adopt/revert |
| 缺任一命令 | `none` + `reason=no_build_or_smoke_command` | 不建副本；`observation.workspace` 为空 → 不产生 `RevisionPlan`，只做种子/执行/停止 |
| 原件不是目录 | `none` + `reason=origin_not_a_directory:…` | 同上 |

理由：`ADOPT/REVERT` 的唯一依据是“真构建 + 真冒烟”。没有命令还建一个
“构建永远失败”的副本，等于把 `stage_failed` 写进每一轮，报告里学不到东西。

已存在的副本以 `ws/workspace.json` 为准（`reused`）；换命令必须换工作区，
报告里会写 `workspace_command_mismatch:reuse_existing`，不静默用旧命令。

### 3.2 `FuzzEpochRunner`：短切片 + 事件 + 证据

```python
out = fuzz.execute(plan, index, hypotheses, workdir=work/epoch-NNN,
                   seconds=min(params, seconds_cap), workers, timeout,
                   isolation=..., require_isolation=...,
                   should_stop=cancel, max_slice=min(seconds, 5.0),
                   task_id=..., campaign=..., corpus_root=...)
```

- 事件：`exec.started`（plan/预算/隔离/绑定哈希）+ `exec.finished`
  （`outcome / candidates / build / fuzz / coverage / evidence_sha256 /
  stack_hashes / crash_type / budget_usage`）。快照只读这两条，所以
  “跑过”是可复核事实。
- 证据：完整执行文档（stats/coverage/seed_pool/corpus/crash 摘要）落
  `exec_stats` 证据；失败落 `exec_error` 证据（`exec.finished(outcome=failed)`
  + `error`），**绝不**写 `no_repro`。
- 目标语义三段按执行事实写（`exec_probe_facts()` 唯一出口）：fuzz 只能补
  `program_started`（`execs>0` → `true`；`execs=0` 且 `setup_error` → `false`）；
  `input_processed` / `checkpoint_reached` **恒为 `null`**（fuzz 执行器没有输入/
  检查点探针），`target_reached` 只由 `checkpoint_reached` 派生，也是 `null`。
  `execs>0`、`new_coverage_bits>0`、崩溃数都**不**能推出“命中”；
  口径见 `docs/V3-TARGET-SEMANTICS.md`。
- epoch 结束后调 `corpus.reload()`：fuzz 执行器用它自己的构建身份
  `begin()` 过语料，外部端口必须复读磁盘真相，才能保证 `corpus_hash`
  不是内存里的旧一代。

---

## 4. 状态映射（`cli.map_state`，唯一解释器）

| 控制器结果 | 平台状态 | 说明 |
|---|---|---|
| `status=cancelled` | `CANCELLED` | 已成终态则不改 |
| `status=budget` | `TERMINATED` | 走 `terminate_budget()`：`budget.exceeded` 证据 + `task.terminated`，reason 取 `remaining:<key><=0` |
| `status=failed` | `FAILED` | 控制器崩溃如实落（`error:<Type>`） |
| `stop_reason ∈ {candidate_ready, verification_blocked}` 且 `verification.allowed` | `CANDIDATE` | 只表示“可以交给既有 verify”，**不是**已验证 |
| 同上但 `allowed=false` | `NEEDS_EVIDENCE` | blockers 留在报告里（例如 `no_evidence_ref`） |
| `status=blocked` | `BLOCKED` | `policy_blocked` / `execution_error` / `stage_failed` / `harness_error` / `engineering_rejected` |
| 任一轮出现 `execution_error` 或动作 `failed` | `BLOCKED` | 失败不得被映射成负结果 |
| `completed` + 有可信观测 + 有执行轮 + 无候选 | `NO_REPRO` | 这是**循环停止原因**，不是漏洞结论 |
| 其余（没有可信观测 / 一轮执行都没有） | `NEEDS_EVIDENCE` | “只在返回值里声称跑过”的循环只能到这里 |

`NO_REPRO` 的两个前提是算出来的，不是声明的：

- `observed_rounds > 0`：至少一轮 OBSERVE 拿到了 `applied` 快照
  （控制器阶段明细里的 `snapshot=applied`）；
- `executions > 0`：至少一个 `run_epoch` 动作是 `applied/failed`（被
  `same_facts_same_action` 跳过的动作不算执行）。

状态迁移被状态机拒绝时（例如别的进程已把任务打成终态），写
`research.map_failed` 事件并保持原状态——失败原样保留，不硬改。

---

## 5. 输出与事件

CLI 输出（stdout，一份 JSON）：

```text
schema / task_id / benchmark / campaign / state / controller_state / stop_reason
max_rounds / rounds / executions / executions_applied / executions_failed
candidates / observed_rounds / verification_allowed / note
controller   ← ControllerResult.to_dict()（rounds / timeline / revisions /
               verification / invalidations / final / budget / error）
deps         ← workspace / index / corpus / executor / paths
budget       ← BudgetGuard.snapshot()
paths + report_path + report_sha256
```

`research.json`（`<research-root>/research.json`，原子写，`report_sha256` 可按
文件字节复算）是同一份文档：`note` 明确写着“不写裁决字段、不建候选记录，
候选只通过 `verification.allowed` 交给既有 verify”。

事件：

| 事件 | 阶段 | 关键 payload |
|---|---|---|
| `research.started` | `RUNNING` | campaign / max_rounds / workspace / index_sha256 / corpus / executor / paths |
| `exec.started` / `exec.finished` | `RUNNING` | 见 §3.2（快照唯一输入） |
| `research.finished` | 控制器 status | stop_reason / rounds / revisions / duration |
| `research.mapped` | 终态 | state / target_state / stop_reason / executions / candidates / observed_rounds / verification_allowed / report_path / report_sha256 |
| `research.map_failed` | 当前态 | target_state / error（映射被状态机拒绝时） |
| `state.changed` | 终态 | `PLANNED→RUNNING→<映射状态>` |
| `budget.exceeded` + `task.terminated` | `TERMINATED` | 预算快照证据哈希 |

**不写**的东西：`verifications` 表、`candidates` 表、任何 `verified/confirmed`
字段（报告里连字面量都不出现，测试用整篇文本断言）。

---

## 6. 测试（`tests/test_v3_p2c_research_cli.py`）

9 个用例。构建/冒烟是真实 `subprocess.run`（`py_compile` + 本地 python 脚本）；
只有 **fuzz 执行 worker** 用替身（与 P2b 边界一致：不宣称跑过 CG/EG/VG 真实目标）。

| 用例 | 断言要点 |
|---|---|
| `test_two_rounds_from_planned_reach_candidate_without_writing_verdict` | 从 `PLANNED` 出发 2 轮：r1 `no_execution` 不改副本 → r2 `target_unreached` → `seed_params.json` raw→magic → build `ok` → smoke `passed` → `adopted`（`adoptions.jsonl` 里 `scope=engineering`）→ 命中 → `CANDIDATE` + `verification.allowed`；迁移 `PLANNED→RUNNING→CANDIDATE`；`list_verifications()==[]`、`list_candidates()==[]`；`research.json` 全文不含 `verified`/`confirmed`；`report_sha256` 可复算 |
| `test_same_facts_stop_after_two_epochs` | 恒 no_repro → 2 个 epoch、第 3 轮 OBSERVE 即 `repeated_facts`、没有第 3 次 EXECUTE；有观测 → `NO_REPRO`（不是 `NEEDS_EVIDENCE`，也不是候选） |
| `test_claimed_execution_without_events_is_never_no_repro` | worker 只返回“跑过”、事件流为空 → `observed_rounds=0` → `NEEDS_EVIDENCE`；`exec.finished` 事件为空 |
| `test_executor_failure_is_blocked_and_not_downgraded` | `exec.finished(outcome=failed,error=…)` → `BLOCKED`/`execution_error`，不是 `NO_REPRO` |
| `test_map_state_table` | 映射表逐项（含 `allowed=false` → `NEEDS_EVIDENCE`、预算/取消/失败、无观测/无执行 → `NEEDS_EVIDENCE`） |
| `test_run_research_requires_planned_and_program_index` | 不是 `PLANNED` / 没有 `ProgramIndex` → `ResearchError`、状态不动 |
| `test_cli_research_flags_are_wired` | `--research --max-rounds 2 --campaign cg-x --seconds 0.5` 真的进到 `run_research()`；退出码按映射状态（`TERMINATED=3`、`BLOCKED/FAILED/NEEDS_EVIDENCE=1`、`CANDIDATE/NO_REPRO=0`、前置失败 `2`） |
| `test_cli_research_end_to_end_writes_report` | 真走 `bin/platform.py main([...])`：只替身 worker 类，overlay/构建/冒烟/报告/状态全真；`research.json` 落在 `<research-root>/research.json` |
| `test_without_build_commands_overlay_is_skipped_and_reported` | 没有构建/冒烟命令 → `deps.workspace.mode=none` + `reason=no_build_or_smoke_command`，不建 `ws/`，没有 STAGE/BUILD/SMOKE/ADOPT/REVERT 阶段，循环仍有限停止 |

复跑：

```bash
python3 -m pytest tests/test_v3_p2c_research_cli.py -q
python3 -m pytest tests/test_v3_p2_session.py tests/test_v3_p2_contracts.py -q
python3 -m pytest -q          # 全量
```

---

## 7. 已修的两处“接上才发现”的问题

### 7.1 `controller.py`：BUILD/SMOKE 抛错不再把控制器打崩

原来只有 `_stage()` 包在 `try/except` 里，`workspace.build()` / `smoke()` 抛
`WorkspaceError`（没配 `build_command`、构建目录不在、`smoke` 前置不满足）
会直接冒到控制器的 `except Exception`，整轮细节丢失、失效也没消费：

```python
try:
    build = self.workspace.build(revision, grant=ctx.grant)
except WorkspaceError as exc:
    → BUILD failed / stop_reason=stage_failed / status=blocked / 消费失效后停
try:
    smoke = self.workspace.smoke(revision, build=build, grant=ctx.grant)
except WorkspaceError as exc:
    → SMOKE failed / stop_reason=harness_error / status=blocked / 消费失效后停
```

### 7.2 `corpus.py`：`CorpusStore.reload()`

fuzz 执行器每次 `begin()` 都会按**自己的构建身份**重开一代语料（P1 口径：
身份变了就归档重建）。外部端口（控制器的 `ctx.corpus`、`make_binding` 的
`corpus.snapshot()`）不能拿自己那份内存 manifest 冒充磁盘真相，所以 epoch
结束后调 `reload()` 复读。没有这个口子，`corpus_hash/corpus_version` 会停在
研究进程刚启动时的那一代。

---

## 8. 仍然没做

1. **真实 CG/EG/VG 目标的研究长跑**：`FuzzEpochRunner` 已真接
   `executors.fuzz.execute`，但本批没有可构建的 CG/EG/VG 目标来跑；
   `research.json` 里 `deps.workspace.mode=none` 时循环只做种子/执行/停止，
   不宣称任何目标被驱动过。
2. **overlay 的构建命令自动生成**：`target.yaml` 的 `build` 段描述的是
   `covfuzz.build` 的参数，不是 shell 命令；把它翻译成 overlay 的
   `build_command/smoke_command` 属于 P3（与 benchmark runner 一起做）。
   当前口径：CLI 参数或 `metadata.build_command/smoke_command` 显式给。
3. **四个“测试工件”工具**（`write_harness_candidate` / `edit_generator` /
   `build_candidate` / `smoke_candidate`）仍未注册：stage/build/smoke 是控制器
   内部、要求 L1 的副本操作，加进工具表会改 `tool_schema_hash`（P2a 口径）。
4. **`campaign/epoch/agent_decisions` 新表**：本批只写 `research.json` 与事件；
   DB 迁移留给 P3。
5. **金额预算**：平台 `Budget` 没有金额字段，`remaining_usd` 仍是 `unknown`。
6. **LLM 顾问接线**：`ResearchSession(advisor=...)` 仍是注入式，CLI 未接
   （P2b 的范围没变：顾问只建议、校验后才进计划）。

---

## 9. 数字（实测，不预填）

实测环境：Python 3.12.14，pytest 9.1.1，`/home/root_bupt/桌面/file/vulnmap`（无 `.git`，
基线以文件哈希锚定）。数字与树绑定：树再变即失效，必须重跑。

| 运行 | 结果 |
|---|---|
| `pytest tests/test_v3_p2c_research_cli.py -q` | **9 passed** |
| `pytest tests/test_v3_p2c_research_cli.py tests/test_v3_p2_session.py tests/test_v3_p2_contracts.py tests/test_v3_p1_seed.py tests/test_platform_v2.py tests/test_platform.py tests/test_platform_v2_exec.py -q` | **129 passed** |
| `pytest -q`（全量） | **1368 passed / 8 skipped / 0 failed / 0 error**，103.06s |

P2b 文档记录的基线是 `1337 passed / 8 skipped`；本次新增 9 条 P2c 用例，其余增量
来自并行执行线在同一棵树上落盘的用例（本批未删除、未跳过任何既有用例）。

---

## 10. 怎么复核

1. **看映射**：`python3 bin/platform.py run <task> --research` 的 stdout 里
   `state / controller_state / stop_reason / executions / observed_rounds /
   verification_allowed` 必须与 `research.json` 一致；`report_sha256` 用
   `sha256sum research.json` 复算。
2. **看“真跑过”**：`events` 里必须有配对的 `exec.started/exec.finished`，
   且 `exec.finished` 带 `build/coverage/evidence_sha256`；没有这些事实的
   循环只能落 `NEEDS_EVIDENCE`。
3. **看没写裁决**：`sqlite3 <db> "select * from verifications"` 为空、
   `candidates` 为空；`research.json` 全文不含 `verified`/`confirmed`。
4. **看失败没被吞**：故意让执行器失败（或把 `--build-cmd` 写成不存在的命令）→
   状态是 `BLOCKED`，不是 `NO_REPRO`。
