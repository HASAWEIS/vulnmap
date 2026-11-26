# 平台 v2 P2：Plan 选择 + D2 执行器 + Candidate

> 范围：把 `HYPOTHESES` 之后的“实验规划 → 执行观测 → 候选”接成可运行的一段：
> `PLANNED → RUNNING → CANDIDATE / NO_REPRO / FAILED`。
> P2 唯一接通的执行器是 **fuzz**（包 Discovery D2）；static/dynamic/replay 只规划、不执行。
> 本阶段仍然**不产确认结论**：单端 fuzz 只能得到 `Candidate(state=new/needs_evidence)`，独立验证在 P3。
> 前置：P0 的 TaskState/EventBus/EvidenceStore，P1 的 ProgramIndex/假设集
> （[PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §5、[PLATFORM-V2-P1.md](PLATFORM-V2-P1.md)）。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/planner.py](../agent/platform/planner.py) | `Plan` 契约（kind/target/budget/reason）+ 确定性选择 + `plan.selected` 编排 |
| [agent/platform/executors/fuzz.py](../agent/platform/executors/fuzz.py) | 包 Discovery D2：构建 harness → 种子/字典 → `run_parallel` → 覆盖率 → 收集崩溃 |
| [agent/platform/executors/__init__.py](../agent/platform/executors/__init__.py) | 执行编排：状态迁移、`exec.started/finished`、`candidate.created`、证据与候选落库 |
| [agent/platform/candidates.py](../agent/platform/candidates.py) | `Candidate` 契约（id/task/input_sha256/crash_type/stack_hash/evidence_sha256/state） |
| [agent/platform/store.py](../agent/platform/store.py) | `plans` 表、`candidates` 补列迁移、plan/candidate 读写方法 |
| [bin/platform.py](../bin/platform.py) | `plan` / `run` / `candidates` 子命令 |
| [tests/test_platform_v2_p2.py](../tests/test_platform_v2_p2.py) | 11 项验收：Plan、Candidate 契约/迁移、CLI 全链路、NO_REPRO、FAILED、证据校验 |

## 2. Plan 契约

| 字段 | 类型 | 说明 |
|---|---|---|
| `task_id` | str | 所属任务，必须与 ProgramIndex 的 task_id 一致 |
| `benchmark` | `cybergym`/`exploitgym`/`vulngym`/`target_yaml` | 决定执行语义 |
| `kind` | `static`/`dynamic`/`fuzz`/`replay` | 下一步执行方式 |
| `target` | str | 目标路径或 URL（与 TaskSpec 一致） |
| `budget` | `{seconds, execs, workers, timeout}` | 计划预算，全部 > 0，有上限夹紧 |
| `reason` | str | 为什么选这个 kind/预算（含“确认结论留给 P3”声明） |

扩展：`schema=vulnmap.plan.v1`、`hypothesis_ids`、`inputs{target,root,workspace,target_yaml}`、`reasons[]`、`created_at`、`sha256`（内容哈希，忽略自身）。

### 2.1 选择规则（确定性，不联网、不执行）

| benchmark | 条件 | kind | 理由 |
|---|---|---|---|
| `vulngym` | 任意 | `dynamic` | 只有 HTTP 服务与静态锚点，本仓无源码/harness；P2 只规划（执行器 P3） |
| `cybergym`/`exploitgym` | `source_count == 0` | `replay` | workspace 未解包，先恢复工作区再重放 |
| `cybergym`/`exploitgym` | 有入口/调用点 | `fuzz` | benchmark 自带 ASAN/harness 构建路径 |
| `cybergym`/`exploitgym` | 有源码但无入口/调用点 | `replay` | 先按 `build.sh` 确认构建与入口，避免空跑 |
| `target_yaml` | 有调用点 | `fuzz` | D0/D1 能给出构建与种子依据 |
| `target_yaml` | 只有入口 | `fuzz` | 静态不充分，扩动态覆盖后再看新 sink |
| `target_yaml` | 无入口也无调用点 | `static` | 无法构建 harness，先静态复核 |

### 2.2 预算

优先级：CLI 覆盖（`plan --seconds/--workers/--timeout`）→ `target.yaml` 的 `fuzz` 段 →
假设 `cost.execs` → 默认值。夹紧区间：`seconds ≤ 60`、`workers ≤ 8`、
`timeout ≤ 60`、`execs ≤ 1,000,000`。执行时 `run --seconds/--workers/--timeout`
可再覆盖一次，覆盖值写进 `exec.started.payload.overrides`，不篡改已存 Plan。

### 2.3 事件

`plan` 要求 `HYPOTHESES`；保存 Plan → `→ PLANNED` → 发 `plan.selected`
（payload：kind/benchmark/target/budget/reason/hypothesis_ids/sha256/inputs）。

## 3. fuzz 执行器（包 Discovery D2）

执行器只做“接线”，不重写 Discovery：

1. `targetspec.load/to_build_spec`（target.yaml）或 Discovery `detect_build`（CG/EG workspace）；
2. `covfuzz.build`：ASAN + trace-pc/trace-cmp，`mode=api` 生成最小 harness，`mode=main` 用目标 main；
3. 种子：取前 3 个调用点走 `agents.propose_seeds`（规则，无 LLM），无调用点时用通用种子；
4. 字典：目标源码窗口/假设窗口的字符串与数字常量（`covfuzz.dictionary_from_*`）；
5. `covfuzz.run_parallel`：多 worker、64KB 输入上限、2s 超时、崩溃即停该 worker；
6. 覆盖率：`covfuzz.attribute_coverage`（COV_PCS → addr2line → 调用点）；
   覆盖率失败只记 `coverage.error`，不吞掉已产生的候选；
7. 崩溃收集：读 `crash-*.bin/.log`，用 D3 口径 `triage.parse_log` + `triage.stack_hash`
   解析与去重（同 `stack_hash` 只留一条）。

失败语义：

- 构建失败 → `FuzzExecError(... build failed ...)` → `exec.finished(outcome=failed)` → `FAILED`；
- 隔离里目标从未起来（`setup_error` 且零覆盖）→ 同样 `FAILED`，不能记成负结果；
- 预算内没有崩溃 → `NO_REPRO`（负结果保留，不删事件/不写候选）。

执行产物（工作目录 `--workdir`，默认 `<db 目录>/work/<task>`）：
`build/`、`corpus/`、`crashes/`、`stats/`、`covwork/`、`dictionary.json`。
每次执行前清空 build/corpus/crashes/stats/covwork，保证同一任务重跑不混入上次崩溃。

## 4. Candidate 契约

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | `C1..Cn` | 本次执行内稳定编号（按 stack_hash/input 排序，同栈去重） |
| `task` | str | 任务 id（同时存 `task_id` 别名，便于 SQLite 查询） |
| `input_sha256` | 64 hex | 崩溃输入完整内容哈希 |
| `crash_type` | str | ASAN/UBSAN 分类（如 `unknown-crash`、`heap-buffer-overflow`、`undefined-behavior`） |
| `stack_hash` | str | 与 D3 同口径（type\|function\|file:line 的 sha1 前 16 位），仅用于去重 |
| `evidence_sha256` | 64 hex | 主证据（ASAN 崩溃日志）内容哈希 |
| `state` | `new`/`needs_evidence`/`rejected` | D3 诊断有效 → `new`；无效诊断（未知类型/缺根因帧）→ `needs_evidence`；P3 才推进验证状态 |

扩展：`schema=vulnmap.candidate.v1`、`exec_id`、`detail{source,input_size,input_evidence_sha256,log_evidence_sha256,input_path,log_path,access,access_size,function,file,line,frames,diagnostic_valid,scope=single_build_only,plan_sha256,build_sha256}`、`created_at`。

硬约束（代码强制）：

1. `input_sha256`/`evidence_sha256` 必须是 64 位十六进制；`crash_type`/`stack_hash` 非空；
2. `state` 只能是上述三值，`confirmed/verified/exploitable` 一律拒绝；
3. 任何层级出现 `verdict/confirmed/exploitable/severity/...` 键直接拒绝（`from_dict` 会丢未知键，所以校验在原始 doc 上做）；
4. 候选只引用证据哈希，不复制日志；`scope=single_build_only` 明示“单端执行”。

证据写入：每次执行对每条去重后的崩溃写两份 EvidenceStore 记录——
`crash_input`（原始字节）与 `crash_log`（ASAN 日志），`source_stage=RUNNING`；
`Candidate.evidence_sha256 = crash_log 的 sha256`，`detail.input_evidence_sha256`
指向输入证据。任何一条都能用 `sha256(文件内容)` 复算。

## 5. SQLite 迁移（P2）

P0/P1 的表原样保留；每次 open 幂等执行：

~~~sql
CREATE TABLE IF NOT EXISTS plans(
  task_id TEXT PRIMARY KEY,
  benchmark TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  seconds REAL NOT NULL DEFAULT 0,
  execs INTEGER NOT NULL DEFAULT 0,
  workers INTEGER NOT NULL DEFAULT 0,
  timeout REAL NOT NULL DEFAULT 0,
  sha256 TEXT NOT NULL DEFAULT '',
  doc_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_task ON candidates(task_id);
CREATE INDEX IF NOT EXISTS idx_candidates_stack ON candidates(task_id, stack_hash);
~~~

P0 的 `candidates` 表缺 P2 需要的列；SQLite 的 `ADD COLUMN` 不支持
`IF NOT EXISTS`，因此按 `PRAGMA table_info(candidates)` 逐列补齐：
`state TEXT NOT NULL DEFAULT 'new'`、`exec_id TEXT NOT NULL DEFAULT ''`、
`detail_json TEXT NOT NULL DEFAULT '{}'`。旧行自动得到 `state='new'`，P0 数据不动。

P0 的 `candidates.candidate_id` 是单列主键，而 `C1..Cn` 是**任务内编号**：
落库时写成 `<task_id>::C1`，读回/CLI 仍暴露任务内 id，这样两个任务各自有 `C1`
也不会撞主键；老库里的裸 `C0` 行原样可读。

store 新方法：`save_plan / get_plan / save_candidate / get_candidate / list_candidates`；
`summary()` 增加 `plan` 摘要、`candidates` 计数与 `candidate_states` 分布。

## 6. 状态机与事件顺序

~~~text
HYPOTHESES ──plan──→ PLANNED ──run──→ RUNNING ──有崩溃──→ CANDIDATE
                                          └──无崩溃──→ NO_REPRO
                                          └──失败────→ FAILED
~~~

| 阶段 | 事件 | 说明 |
|---|---|---|
| plan | `state.changed(HYPOTHESES→PLANNED)` → `plan.selected` | 先落库再迁移，再发事件 |
| run 开始 | `state.changed(PLANNED→RUNNING)` → `exec.started` | payload 含 exec_id/budget/overrides/plan_sha256 |
| 产出候选 | `candidate.created` × n | payload 含 id/state/crash_type/stack_hash/input_sha256/evidence_sha256/exec_id |
| 正常结束 | `exec.finished(outcome=candidate\|no_repro)` → `state.changed(→CANDIDATE/NO_REPRO)` | payload 含 fuzz 统计/覆盖率/构建哈希 |
| 失败 | `exec.finished(outcome=failed, error=...)` → `state.changed(RUNNING→FAILED)` | 事件保留、可回放；`FAILED→READY` 才允许重入 |

- `run` 要求 `PLANNED`，`plan` 要求 `HYPOTHESES`；跳步直接退出码 2 且状态不变；
- P2 没有 dynamic/static/replay 执行器：这类 Plan 点 `run` 会先进入 `RUNNING`，
  再以 `executor ... not available in P2` 落 `FAILED`——不假装执行过；
- `EventBus.replay` 只认 `state.changed`，未知事件不参与状态重建，重放两次结果一致。

## 7. 使用示例

~~~bash
DB=.platform/platform.db
python3 bin/platform.py --db $DB submit \
  --benchmark target_yaml --target fixtures/discovery --task-id fx1
python3 bin/platform.py --db $DB preflight fx1
python3 bin/platform.py --db $DB understand fx1
python3 bin/platform.py --db $DB hypotheses fx1
python3 bin/platform.py --db $DB plan fx1

# 受控短跑：1 秒、1 worker；产物默认落 <db 目录>/work/fx1 与 <db 目录>/evidence
python3 bin/platform.py --db $DB run fx1 --seconds 1 --workers 1
python3 bin/platform.py --db $DB candidates fx1
python3 bin/platform.py --db $DB status fx1
python3 bin/platform.py --db $DB events fx1
python3 bin/platform.py --db $DB evidence fx1
~~~

实测（本机，`fixtures/discovery`）：

- `run --seconds 1 --workers 2`：0.5s 内产出 `C1`，`crash_type=unknown-crash`、
  `access=WRITE`、栈首帧 `parse_record`、覆盖率 4/4；
- 无崩溃目标（只做格式检查/校验和）：1.2s 结束，`execs=97`、`crashes=0` → `NO_REPRO`；
- 语法错误的源目标：gcc 失败 → `FAILED`，`exec.finished.error` 保留完整构建错误。

## 8. 验收

~~~bash
python3 -m pytest tests/test_platform_v2.py tests/test_platform_v2_p1.py \
  tests/test_platform_v2_p2.py -q
# 31 passed
~~~

| 测试 | 钉住的事实 |
|---|---|
| `test_plan_from_fixture_selects_fuzz` | Plan 字段/预算/哈希可复算、`plan.selected` 事件、规划不夹带结论 |
| `test_plan_budget_and_kind_validation` | 非法 kind/预算/结论文本全部拒绝 |
| `test_plan_kind_rules_cover_static_and_replay` | static/replay/fuzz 的确定性选择规则（四类 kind 都有入口） |
| `test_plan_vulngym_selects_dynamic_without_execution` | VG 锚点 → `dynamic`，规划阶段无 `exec.started` |
| `test_candidate_contract_and_rejects_verdict` | 字段完整、`state=new`、拒绝 `confirmed/verified` 与 verdict 键 |
| `test_candidate_table_migration_and_roundtrip` | P0 旧库补列幂等、旧行 `state=new`、候选往返读写 |
| `test_cli_plan_run_candidates_fixture` | 1s fixture 全链路到 `CANDIDATE`；事件顺序、证据 sha 可校验、无确认结论 |
| `test_run_no_crash_enters_no_repro` | 无崩溃 → `NO_REPRO`，无候选、事件保留、可回放 |
| `test_run_requires_plan_and_plan_requires_hypotheses` | 跳步拒绝且状态不变 |
| `test_build_failure_marks_failed_and_keeps_state` | 构建失败 → `FAILED`，错误进事件，状态可回放 |
| `test_unsupported_executor_kind_fails_closed` | P2 缺 dynamic 执行器时明确失败，不假装跑过 |

## 9. 边界（P2 刻意不做）

- **不产确认结论**：`Candidate(state=new/needs_evidence)` 只代表“单端构建上崩了”；`confirmed` 必须来自
  P3 的 vuln/fix 双端或服务行为差分，本阶段代码级拒绝 verdict 字段；
- **不重写 Discovery**：D0/D1/D2/D3 只被调用；`agent/discovery/` 零修改；
- **只接通 fuzz**：static/dynamic/replay 有 Plan 没有执行器，调用即 `FAILED`；
- **不做独立复核**：不跑干净重建 3/3、不做 fix 端对照（P3）；
- **有界覆盖**：覆盖率归属只重跑 corpus 的前 400 个输入；失败记为
  `coverage.status=unavailable`，不影响候选事实；
- **VulnGym 不执行**：P2 无 HTTP 执行器/授权探测，dynamic 计划只落库；
- **预算诚实**：`seconds/workers/timeout` 覆盖值写进 `exec.started`，不修改已存 Plan。
