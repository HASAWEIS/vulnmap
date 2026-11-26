# 平台 v2 升级方案：从“流水线”到“任务状态机 + 证据总线”

> 目标图：B 端到端运行流程（任务接入 → 目标准入 → 程序理解 → 假设集 → 实验规划 → 执行观测 → 候选 → 独立验证 → 研究评估 → 报告台账；右侧 TaskState / AnalysisContext / EvidenceStore / EventBus / Case Pack）。
> 结论：这张图不是“再加几个阶段”，而是把平台从**阶段脚本**升级成**可恢复、可审计、可适配多 benchmark 的任务运行时**。

## 1. 图的本质

1. **任务状态机**：TaskState 记录阶段、预算、终止原因；失败进入 blocked / no_repro / rejected，不丢状态。
2. **证据总线**：EvidenceStore 按内容哈希存日志/输入/报告；EventBus 记录每个阶段事件；Reviewer/Report/UI 只读消费。
3. **适配层**：VulnGym（静态定位）、CyberGym（ARVO harness + vul/fix）、ExploitGym（exp/none/flag）只是同一运行时的三种验证器。

当前 Discovery 已有 D0–D5、Fuzz、triage、report，但它是 **campaign 脚本**，不是任务运行时：没有 TaskSpec、准入闸门、事件流、统一 Candidate/Verification/CasePack，也没有 VulnGym 适配。

## 2. 现状 vs 目标

| 目标图节点 | 现有资产 | 差距 |
|---|---|---|
| 任务接入（Web/API/CLI + 预算） | 旧 bin/vulnmap.py + workspace；Discovery CLI | 无统一 TaskSpec/队列/预算；Web 只读 |
| 目标准入（镜像/源码/服务/授权） | 旧 checkpoint / 镜像 digest；Discovery D0 | 无显式 preflight 闸门与 blocked 状态 |
| 程序理解（Targetselector → ProgramIndex → 调用图/入口） | Discovery D0/D1；旧 recon/locate | 没有统一 ProgramIndex 契约 |
| 假设集（≤8 条可证伪 + 证据缺口/成本） | Discovery D1.5（LLM/规则） | 有假设，但缺假设预算/证据缺口字段与硬上限约束 |
| 实验规划（静态/动态/Fuzz/Replay） | Discovery 默认 fuzz；旧 verify 有 builder/模型循环 | 没有显式 Plan 选择与理由 |
| 执行与观测（harness→build→smoke→fuzz→container） | Discovery build/fuzz；旧 docker vul/fix | 缺统一 execution 事件与阶段化 harness/smoke |
| 候选生成（VulnerabilityCandidate） | crashes + triage | 缺统一 candidate 对象（输入/哈希/栈/证据引用） |
| 独立验证（同输入 vuln vs fix） | 旧平台双端；Discovery 只做干净重建 3/3；P3 判据 + P3.5 runner | Discovery 没有 fix 端，不能独立验证；P3 只校验证据、不产证据 |
| 研究与评估（Reviewer） | Discovery 规则/可选 LLM 复核 | 缺独立 Reviewer 与“证据完整性”门禁 |
| 报告与台账（HTML/PDF/MD/Case Pack） | Discovery report/DB；旧 LEDGER | 缺 Case Pack（JSON+报告+轨迹+哈希） |
| 状态与证据（右侧五块） | 文件目录 + SQLite | 缺 TaskState/EventBus/EvidenceStore 统一抽象 |
| 适配层 | 旧 CG/EG；Discovery target.yaml | VulnGym 未接；CG/EG 未接 Discovery 运行时 |

## 3. 目标架构

~~~text
bin/platform.py                 # submit / run / verify / smoke / status / casepack
agent/platform/
  task.py                       # TaskSpec, Budget, TaskState 状态机
  preflight.py                  # 镜像/源码/服务/授权检查，失败 blocked
  program.py                    # ProgramIndex: 入口/调用图/危险点/格式
  hypotheses.py                 # ≤8 条可证伪假设 + 证据缺口 + 成本
  planner.py                    # 选 static / dynamic / fuzz / replay，记录理由
  executors/
    static.py                   # P3.9：ProgramIndex + 假设集只读复核（static_review）
    dynamic.py                  # P3.9：VulnGym 基线/修补 HTTP 行为差分（candidate/no_repro）
    fuzz.py                     # 包 Discovery D2
    replay.py                   # P3.7：旧 PoC + 旧日志重放（命令 / docker）
    container.py                # 旧 docker runner
  candidates.py                 # VulnerabilityCandidate
  verify.py                     # VerificationAgent: vuln vs fix / flag / 行为差分
  runners/                      # P3.5：真的把证据跑出来（只产证据，不产结论）
    base.py                     # RunnerResult + 隔离/超时/网络策略 + blocker 词表
    cybergym.py                 # docker vul/fix 同输入 + sanitizer 判读
    exploitgym.py               # 官方 socket / exploit_cmd 取 flag
    vulngym.py                  # 基线/修补两组 HTTP 行为差分
    spec.py                     # P3.8：task.json/metadata → runner spec + 本机可用性探测
  review.py                     # Reviewer: 完整性/根因/回报
  evidence.py                   # content-addressed store + manifest
  events.py                     # append-only EventBus
  casepack.py                   # Case Pack 打包
  adapters/
    cybergym.py                 # ARVO 源码 + vul/fix + harness
    exploitgym.py               # socket/flag
    vulngym.py                  # HTTP 服务 + 行为差分
    target_yaml.py              # Discovery 通用源码目标
  service.py                    # FastAPI: 任务提交/查询/SSE/证据下载
~~~

### 状态机

~~~text
RECEIVED
  → PREFLIGHT ──失败──→ BLOCKED
  → READY
  → UNDERSTANDING
  → HYPOTHESES
  → PLANNED ──取消──→ CANCELLED / ──预算用尽──→ TERMINATED
  → RUNNING ──失败──→ FAILED / BLOCKED
            ──取消──→ CANCELLED / ──预算用尽──→ TERMINATED
            ──没差异──→ NO_REPRO / ──缺证据──→ NEEDS_EVIDENCE（补证据后可回 RUNNING）
  → CANDIDATE
  → VERIFYING ──不可复现──→ NO_REPRO
  → REVIEW ──证据不足──→ NEEDS_EVIDENCE
  → REPORTED
  → CLOSED
~~~

每次迁移写 EventBus 事件：task.created、preflight.failed、program.indexed、hypothesis.proposed、plan.selected、exec.finished、candidate.created、verification.failed、review.completed、report.ready；
P3.6 增补 budget.exceeded、task.terminated、task.cancel_requested、task.cancelled。TaskState 只存当前阶段/预算/终止原因，历史在事件流里，可重放。

状态机的终态分三种语义，不可混用：FAILED=跑不起来/跑炸了，NO_REPRO=跑完没崩，
TERMINATED=预算不给了（budget_seconds/execs/tokens/turns），CANCELLED=人工取消。
后两者都是终态、都保留事件与证据，且都不是“负结果”。

### 证据模型

- EvidenceStore：evidence/&lt;sha256&gt; 存原始文件；manifest 记录 kind/size/sha256/source_stage；
- 每个 Candidate 只引用证据哈希，不复制日志；
- Case Pack = task.json + state.json + events.jsonl + candidates.json + evidence/manifest.json + report.md/html + 轨迹；
- Reviewer/Report/UI 全部只读引用，不修改状态。

## 4. 适配层怎么接

| benchmark | 准入 | 程序理解 | 执行 | 独立验证 |
|---|---|---|---|---|
| CyberGym | repo-vul.tar.gz + vul/fix 镜像 | 源码 + build.sh | harness/build/ASAN | 同输入 vuln 崩 / fix 干净 |
| ExploitGym | 同上 + socket | 源码/二进制 | exploit 运行 | flag 获取 / 失败分类 |
| VulnGym | 服务 URL + 授权 | SOURCE.md 锚点/上游 commit | HTTP 请求序列 | 行为差分（如 403 vs 断开） |
| target.yaml | 本地源码/二进制 | D0/D1 | Discovery harness/fuzz | 干净重建 3/3（单端，只能算弱验证） |

**关键约束**：Discovery 的“干净重建 3/3”不是独立验证；它只能证明崩溃可复现。要进目标图的 VerificationAgent，必须有 fix 端或行为差分。

P3.5 之后，上表“执行/独立验证”两列不再是纸面设计：[agent/platform/runners](../agent/platform/runners/)
把三类 benchmark 的执行动作收敛成一个受控壳（docker / socket / HTTP），
产出的是**判据输入**而不是结论——`verified` 仍只由
[benchmark_policy.py](../agent/benchmark_policy.py) 推导。

## 5. 迁移路径

### P0：契约与状态（已实现）
- 新增 [agent/platform](agent/platform)：TaskSpec / Budget / TaskState / EventBus / EvidenceStore；
- SQLite 表：tasks / task_events / evidence / task_evidence，预留 candidates / verifications / reviews / reports；
- CLI：[bin/platform.py](bin/platform.py) submit / preflight / status / events / evidence / attach / replay / transition；
- 验收：一个任务从 RECEIVED 到 BLOCKED/READY 的事件可重放（tests/test_platform_v2.py）；
  授权 `metadata.authorized` 严格解析且**缺失默认阻断**（验收整改 F1，见
  [ACCEPTANCE-FIXES-20261118.md](ACCEPTANCE-FIXES-20261118.md)）。

P0 使用示例：

~~~bash
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark cybergym --target workspace/CG-01-arvo-44034 \
  --task-id cg01-v2 --meta authorized=true \
  --meta task_id=arvo:44034 --meta image_vul=n132/arvo:44034-vul
python3 bin/platform.py --db .platform/platform.db preflight cg01-v2
python3 bin/platform.py --db .platform/platform.db status cg01-v2
python3 bin/platform.py --db .platform/platform.db events cg01-v2
python3 bin/platform.py --db .platform/platform.db replay cg01-v2
~~~

状态机：RECEIVED → PREFLIGHT → READY / BLOCKED；BLOCKED 补齐材料后可重入 PREFLIGHT（重试只追加事件）；
后续阶段按 §3 的迁移表推进，非法迁移直接拒绝。

### P1：ProgramIndex + 假设（已实现，细节见 [PLATFORM-V2-P1.md](PLATFORM-V2-P1.md)）
- ProgramIndex（agent/platform/program.py）：`benchmark/root/entry_points/functions/call_sites/coverage/formats/source_count` 统一契约；
  - target_yaml 复用 Discovery D0/D1 全量扫描；CG/EG 读 workspace task.json + src/ 做有界扫描并记账截断；
  - VulnGym 读 SOURCE.md/task.json，输出静态定位锚点（repo/commit/file/line/symbol + verified）；
- hypotheses（agent/platform/hypotheses.py）：硬上限 ≤8，字段 `id/statement/falsifiable_by/evidence_gap/cost/confidence/source`；
  规则为默认、D1.5 LLM 可选且失败严格回退；代码级拒绝 verdict 字段与 verdict 文本；
- SQLite：新增 `program_indexes` / `hypotheses`，`CREATE ... IF NOT EXISTS` 幂等迁移，P0 表与数据不动；
- CLI：`understand`（READY→UNDERSTANDING，发 program.indexed）、`hypotheses`（UNDERSTANDING→HYPOTHESES，发 hypothesis.proposed）、`program`（只读 dump）；非法迁移拒绝；
- 验收：`tests/test_platform_v2_p1.py`（13 项）+ P0 `tests/test_platform_v2.py`（7 项，共 20 passed），CG-01/VG-01/fixture 均生成同一契约产物；
- 未做（留 P2/P3）：preflight 深度准入（镜像 digest / socket / 服务授权探测）、旧 recon 资产合并；planner 已在 P2 落地。

### P2：执行器 + Candidate（已实现，细节见 [PLATFORM-V2-P2.md](PLATFORM-V2-P2.md)）
- planner（agent/platform/planner.py）：按 benchmark + ProgramIndex + 假设集确定性选择
  `static / dynamic / fuzz / replay`，给出目标与预算，写 `plans` 表并发 `plan.selected`；
- executors/fuzz：包 Discovery D2（target.yaml/detect_build → `covfuzz.build` →
  `run_parallel` → `attribute_coverage`），只读复用，不改 Discovery 核心；
- candidates：`Candidate(id/task/input_sha256/crash_type/stack_hash/evidence_sha256/state)`，
  崩溃输入与 ASAN 日志进 EvidenceStore，候选只引用证据哈希；`state` 只到 `new`；
- SQLite：新增 `plans`，P0 `candidates` 幂等补 `state/exec_id/detail_json`；
- CLI：`plan`（HYPOTHESES→PLANNED）、`run`（PLANNED→RUNNING→CANDIDATE/NO_REPRO/FAILED）、
  `candidates`；事件 `plan.selected / exec.started / exec.finished / candidate.created`；
- 验收：`tests/test_platform_v2_p2.py`（11 项），P0+P1+P2 共 31 passed；
- 边界：单端 fuzz 只产 Candidate，不给 confirmed；dynamic/static/replay 有 Plan 无执行器（P3）。

### P3：独立验证 + Reviewer + Case Pack（已实现，细节见 [PLATFORM-V2-P3.md](PLATFORM-V2-P3.md)）
- verify（agent/platform/verify.py）：按 benchmark 选判据，判据事实源仍是
  [agent/benchmark_policy.py](../agent/benchmark_policy.py)——
  CyberGym `vuln_fix_diff`（同输入 vuln 崩 / fix 干净）、ExploitGym `exploit_flag`
  （官方 flag，**不要求** fix 端，EG-02 类不被双端规则误杀）、VulnGym `behavior_diff`
  （基线/修补行为差分）；口径混用与 `kind` 不符一律 `VerificationError`，
  target_yaml 无独立判据 → `rejected`；证据入口为**文件/退出码/flag**（或 `--spec`），
  写 `verifications` 表 + `verification.recorded / verification.verified|failed`；
- review（agent/platform/review.py）：8 项只读检查（证据完整性/哈希可复算/根因落地/
  验证结论/输入绑定/判据一致…），**只能降级不能升级**——验证未通过时不可能 `accept`，
  复核不改写验证记录；写 `reviews` 表 + `review.completed`；
- casepack（agent/platform/casepack.py）：打包 task/state/events.jsonl/candidates/
  verifications/reviews/evidence manifest/report.md/casepack.json，
  `content_sha256` 可复算并写 `reports` 台账（`report.ready` 为提交后事件）；
- SQLite：P0 表不动，`reviews` 幂等补 `detail_json`，新增 P3 索引，
  `verifications/reviews/reports` 主键按 `<task>::` 命名空间落库（`SCHEMA_VERSION=4`）；
- CLI：`verify` / `review` / `casepack`（＋只读 `verifications` / `reviews` / `reports`）；
- 状态机：`CANDIDATE → VERIFYING → REVIEW → REPORTED → CLOSED`，
  失败落 `REJECTED / NO_REPRO / NEEDS_EVIDENCE`；
- 验收：`tests/test_platform_v2_p3.py`（11 项），P0+P1+P2+P3 共 **42 passed**
  （`python3 -m pytest tests/test_platform_v2*.py -q`）；
- 边界：P3 只校验证据、不执行目标；任何模块都不写 `confirmed`，
  单端 fuzz 永远只是 Candidate。

### P3.5：benchmark runner —— 证据现场跑出来（已实现，细节见 [PLATFORM-V2-P35.md](PLATFORM-V2-P35.md)）
- runners（[agent/platform/runners](../agent/platform/runners/)）：`RunnerResult` 契约 +
  三类执行壳——CyberGym `docker run` 双端（同一输入挂 `/input:ro`，退出码 + sanitizer 判读）、
  ExploitGym 官方 socket 或 `exploit_cmd`（flag 形态抽取）、VulnGym 基线/修补两组 HTTP
  （单次 GET、不跟跳转、禁代理）；
- 口径不变：runner 只产 `spec/checks/blockers`，`verified` 仍由 `benchmark_policy` 推导；
  合并规则只做与运算（判据成立 ∧ runner 跑完 ∧ 无 blocker ∧ 无口径类 blocker）；
- 隔离/超时/网络显式化：宿主侧复用 Discovery 的 bwrap/unshare（断网 + 只读根 + cap-drop），
  `container` 不参与包裹层（CyberGym 跑的就是镜像），`require-isolation` fail-closed；
  默认 60 s/步、上限 3600 s、按进程组收；策略快照进 `detail.execution.policy` 与 `runner.json`；
- 失败不伪造结论：超时/缺镜像/缺命令/连不上 → `runner_*` blocker + `runner.json` 证据 +
  `needs_evidence`；runner 名与 benchmark 不符是契约错误（`RunnerMismatch`，不落记录）；
- verify（[agent/platform/verify.py](../agent/platform/verify.py)）：`run_verification(execute=True)`
  选 runner → 归一 → 复用同一套判据 → 写 `verification.executed` 事件；
  不传 `--execute` 时与 P3 逐字兼容（`detail.mode=evidence`）；
  另修一处口径漏洞：ExploitGym 拿到 flag 但利用命令非零退出，不再被判成立；
- CLI：`verify --execute`（`--runner/--timeout/--isolation/--require-isolation/
  --image-vul/--image-fix/--docker/--cmd/--host/--port/--exploit-cmd/
  --baseline-url/--patched-url`）；
- 验收：`tests/test_platform_v2_p35.py`（26 项，全本地 fake docker / TCP / HTTP，
  不依赖真实 benchmark 网络），P0–P4+P3.5 共 **87 passed**；
- 边界：不做 build、不接真实 benchmark 网络、不写 `confirmed`、不改 Discovery/旧平台。

### P3.6：预算强制 + 取消路径（已实现，细节见 [PLATFORM-V2-P36.md](PLATFORM-V2-P36.md)）
- budget（[agent/platform/budget.py](../agent/platform/budget.py)）：`BudgetGuard` 账本，
  四个上限 `max_seconds / max_execs / max_tokens / max_turns`；
  用量全部由事件流推导（`exec.started` 记回合、`exec.finished` 累加秒数/execs/tokens），
  不新增表；预检用 `used >= limit`、结算用 `used > limit` 双口径；
- 编排（[agent/platform/executors](../agent/platform/executors/)）：执行前预检（越限不写 RUNNING）→
  本次秒数夹到剩余额度（`exec.started.caps`）→ 执行器分片跑 D2，
  每片后按累计 execs / 单调截止点 / 取消探针判定 → 结算；越限写
  `budget.exceeded` + `task.terminated`（`reason=budget_*`）+ `budget_snapshot` 证据，
  状态 `TERMINATED`，**不落 NO_REPRO**；
- lifecycle（[agent/platform/lifecycle.py](../agent/platform/lifecycle.py)）：
  `cancel_task`（RUNNING/PLANNED 及非终态 → CANCELLED，终态 `TaskError`）、
  `terminate_budget`；顺序固定为证据 → 事件 → 状态；
  RUNNING 被外部取消时执行器在片边界停止，`exec.finished(outcome=cancelled)`，
  不升级成 CANDIDATE/NO_REPRO；
- 失败不降级：执行器失败仍是 `FAILED` + `exec_error` 证据（含错误类型/消息/预算快照），
  并且现在三种非正常结束（失败/超限/取消）都留 `exec_stats` 快照；
- 状态机（[agent/platform/task.py](../agent/platform/task.py)）：新增 `CANCELLED`、`TERMINATED`
  两个终态与 `CANCELLABLE` 集合，`PLANNED/RUNNING → TERMINATED` 边；
  `STATES` 扩展后 P4 的只读接口自动兼容，未改 API/UI；
- CLI：`cancel`（`--reason/--actor`）、`budget`（只读账本）、`run --tokens-used`；
  `run` 预算终止时退出码 3；`status()` 增 `budget_usage`；
- 验收：`tests/test_platform_v2_p36.py`（16 项），P0–P4+P3.5+P3.6 共 **103 passed**；
- 边界：不做抢占式 kill（片边界生效）、不改 Discovery、不新增表（`SCHEMA_VERSION=4` 不变）、
  终态不可续期（重跑请新提交任务）。

### P3.7：源码包自动解包 + 旧 PoC 重放（已实现，细节见 [PLATFORM-V2-P37.md](PLATFORM-V2-P37.md)）
- program（[agent/platform/program.py](../agent/platform/program.py)）：CG/EG workspace 只有
  `repo-vul.tar.gz` 时，`understand` 自动解包到 `<workspace>/.unpacked/<sha256[:16]>/`
  （内容寻址缓存 + manifest + 原子换入），并把解包树的 `src_root` 接进 D0/D1——
  `source_count/entry_points/call_sites` 来自真实源码；成员校验先于写盘：
  绝对路径 / `..` / 盘符 / NUL / 符号链接·硬链接·设备 / 成员数 20 万 / 解包 2 GiB
  一律 `UnpackError`，恶意包不会在 workspace 外留下任何文件；
- program：镜像 digest 写进 `ProgramIndex.images`（CG 双端、EG 只有 vul），
  来源 `casekit.image_for` + `checkpoint.image_digest`；docker inspect 失败
  **不阻断**静态索引，只记 `warnings`（与 P3.5 runner 的“缺镜像=blocker”分工明确）；
- ProgramIndex 契约向后兼容扩展：`images` / `unpack` / `warnings`（旧文档缺字段按空值补齐，
  `sha256` 仍可复算）；
- replay（[agent/platform/executors/replay.py](../agent/platform/executors/replay.py)）：
  `discover_pocs()` 只读发现旧 PoC（`artifacts/verify` 等 10 个目录、后缀/前缀认领、
  与 `logs/` 旧日志三级绑定、按 sha256 去重、确定性排序、`result.json` 条目优先），
  `execute()` 重放一条：命令来源 `--replay-cmd` → `plan.inputs.replay.cmd` →
  `VULNMAP_REPLAY_CMD` → docker（`--network none`，PoC 挂 `/tmp/poc:ro`），
  超时按进程组收、日志尾部 2 MiB、`stack_hash` 用 replay 自己的归一化口径（不冒充 D3）；
  产出 Candidate 记录 + 判据 `spec`（cybergym `vul.asan` 对齐 `evaluate_cybergym` 的
  `vul_crashed`，`fix` 留空 → verify 落 `needs_evidence`）；
- 编排（[agent/platform/executors/__init__.py](../agent/platform/executors/__init__.py)）：
  `run_execution(kind_override=, replay_cmd=)`；按 kind 分派（fuzz 原路径逐字保留，
  static/dynamic 仍 fail-closed）；证据 `replay_input` / `replay_log` / `replay_spec`，
  候选 `detail.source="replay"`；状态 `CANDIDATE / NO_REPRO`，`ReplayError` → `FAILED`，
  预算/取消沿用 P3.6；
- planner（[agent/platform/planner.py](../agent/platform/planner.py)）：CG/EG 有旧 PoC
  时**优先 `kind=replay`**（即使有源码），`inputs.replay` 记 `pocs[≤8]{path,source,
  sha256,size,log,log_sha256}` + `poc_path` + `cmd/argv`；
- CLI（[bin/platform.py](../bin/platform.py)）：`understand --unpack-cache`、
  `run --kind {static,dynamic,fuzz,replay}` 与 `--replay-cmd`；
- 验收：`tests/test_platform_v2_p37.py`（22 项：解包/缓存/路径穿越/源文件计数/
  digest warning/replay 三态/CLI 端到端），`python3 -m pytest tests/test_platform_v2*.py -q`
  → **125 passed**；
- 边界：不做构建（解包不跑 `build.sh`）、不改 Discovery/API/UI、不伪造 fix 端、
  不写 `confirmed`、不自动清理缓存。

### P3.8：runner spec 自动生成 + `smoke`（已实现，细节见 [PLATFORM-V2-E2E.md](PLATFORM-V2-E2E.md)）
- spec（[agent/platform/runners/spec.py](../agent/platform/runners/spec.py)）：
  `build_runner_spec()` 把 `workspace/<case>/task.json` + 任务 metadata + 显式覆盖翻译成
  runner spec——CyberGym 读 `image_vul`/`image_fix` + `harness_cmd`/`entry`（别名/字典/字符串
  都能拆成 argv），ExploitGym 读 `image`/`mode`/`task_info`（dict、JSON 文本、文件路径、
  `host:port` 四种形态，产出 `socket` 或 `exploit_cmd`），VulnGym 读
  `service_url` 或 `baseline_url`+`patched_url`；覆盖只透传该 benchmark 的 runner 键白名单，
  判据键不钻进 spec，`sources` 逐键记录来源；
- 缺口分层：`blockers`（缺字段/缺本机能力 → **不执行**）、`missing`（缺哪些字段）、
  `warnings`（能跑但证据会不完整：缺 `input_path`/`expected_flag`/`expect`）；
  所有 blocker 都落在 P3.5 的 `runner_*`/`docker_unavailable`/`image_not_found`/
  `connection_failed`/`http_error`/`runner_timeout` 词表里 → `needs_evidence`；
- 本机探测（`probe=True`）：`docker image inspect` 判镜像存在/daemon 掉线（**不是**
  让 `docker run` 用 125 退出码冒充“vul 端崩了”）、`create_connection` 判 socket、
  一次禁代理/不跟跳转的 GET 判基线/修补 URL；镜像缺失、服务不可达一律缺口；
- 编排（[agent/platform/verify.py](../agent/platform/verify.py)）：`verify --execute --auto`
  = 先翻译 spec → 有缺口就 `_spec_gap_execution()`（runner 不起，写
  `<workdir>/runner-spec.json` 作为 `verify_runner_spec` 证据）→ 否则走 P3.5 原链路；
  判据仍是 `benchmark_policy` 唯一事实源，记录带 `detail.auto_spec` 与
  `execution{auto,executed,auto_blockers}`，事件 `verification.executed` 同步携带；
  缺口路径 `verified=False` + `needs_evidence`，负结果仍是 `no_repro`（不会被洗成缺口）；
- CLI（[bin/platform.py](../bin/platform.py)）：`verify --auto/--workspace/--no-probe`；
  新增 `smoke [cases…] [--execute] [--strict] [--workspace-root] [--docker] [--no-probe]`，
  默认对 CG-01 / EG-02 / VG-01 做 dry-run，逐案例给 `status/missing/blockers/probes/spec`，
  `--execute` 成功也只报 `would_verify`（`persisted=false`，不建库、不写 `verifications`）；
- 实测（本机无 arvo 镜像、无 EG/VG 实例）：CG-01 `image_not_found` ×2 +
  `runner_not_configured:cmd`；EG-02 `runner_not_configured:mode,exploit_target`；
  VG-01 `runner_not_configured:baseline_url,patched_url` —— 三条都是 `needs_evidence`，
  退出码 0，没有一条被写成 `no_repro`；
- 验收：`tests/test_platform_v2_e2e.py`（35 项：字段映射/缺字段/优先级/无 docker/
  缺镜像/daemon 掉线/假 socket/本地 HTTP/auto 成功与缺口/CLI `--auto`/`smoke` 三态），
  `python3 -m pytest tests/test_platform_v2*.py -q` → **181 passed**；
- 边界：不猜默认值、不构建镜像、不把缺口当负结果、`smoke` 不落记录、
  不改 Discovery/API/旧案例。

### P3.9：static / dynamic 执行器 + 显式分派（已实现，细节见 [PLATFORM-V2-EXEC.md](PLATFORM-V2-EXEC.md)）
- static（[agent/platform/executors/static.py](../agent/platform/executors/static.py)）：
  ProgramIndex + 假设集只读复核 → `static_review` 证据（程序事实/锚点/危险调用点/
  每条假设的落点/`gaps`/`status`）；落点算法是词面匹配（不编数据流），
  结局只有 `no_repro`（无缺口且无支撑）与 `needs_evidence`（缺口或静态支撑）；
  **不产 Candidate、不写任何结论字段**；plan/index 口径不符 → `StaticExecError` → FAILED；
- dynamic（[agent/platform/executors/dynamic.py](../agent/platform/executors/dynamic.py)）：
  `task.json`/metadata → VulnGym spec（复用 P3.8 的 `build_runner_spec(probe=False)`，
  只翻译不发明）→ runner 打两侧 HTTP（不跟跳转、禁代理、断开/超时如实记账）→
  判据函数给的事实 + 布尔 → 有差异 `candidate`（输入=请求文档、主证据=差分日志，
  `crash_type=behavior_diff`、`detail.source="dynamic"`）/ 无差异 `no_repro`；
  某侧没响应、两侧都没响应、缺地址、benchmark 不符 → `DynamicExecError` → FAILED，
  并先落 `dynamic_spec`/`dynamic_run` 再写 `exec_error`（**失败也留证**，
  绝不把“服务打不通”洗成 `no_repro`）；
- 分派（[agent/platform/executors/__init__.py](../agent/platform/executors/__init__.py)）：
  `EXECUTORS = {fuzz, replay, static, dynamic}` + `executor_for()` / `executor_unavailable()`；
  未登记的 kind 一律 `executor_unavailable:<kind>`（PlanError → FAILED →
  `exec_error.blocker` + `exec.finished.blockers`），不静默换执行方式；
  static/dynamic 各自有 `exec_stats` 段与证据哈希，预算/取消沿用 P3.6；
- planner（[agent/platform/planner.py](../agent/platform/planner.py)）：公开
  `select_kind()`，`select()` 只调它一处（单测可断言、可 monkeypatch）；
  kind 理由文案按 static/dynamic/replay/fuzz 分开；
- 状态机（[agent/platform/task.py](../agent/platform/task.py)）：补
  `RUNNING → NEEDS_EVIDENCE` 与 `NEEDS_EVIDENCE → RUNNING`——缺口不是负结果，
  补证据后可重跑；
- CLI（[bin/platform.py](../bin/platform.py)）：`run --kind static|dynamic` 真的接通
  （choices 未变，未知 kind 仍在参数层拒绝）；
- 验收：`tests/test_platform_v2_exec.py`（16 项：分派/状态机/static 四态/
  dynamic 五态/CLI 两条端到端，本地 HTTP server + 关闭端口，不碰真实网络），
  `python3 -m pytest tests/test_platform_v2*.py -q` → **197 passed**；
- 边界：不做构建/不跑 fuzz、static 连候选都不产、dynamic 只实现 VulnGym、
  不改 API/UI、`service_url` 同址只给 `no_repro`。

### P4：Web/API 与只读消费（已实现，细节见 [PLATFORM-V2-P4.md](PLATFORM-V2-P4.md)）
- FastAPI 新增 `/api/platform` 路由（[vulnmap_platform/api/platform_tasks.py](vulnmap_platform/api/platform_tasks.py)，
  在 [app.py](vulnmap_platform/api/app.py) 静态挂载前注册）：
  - `POST /tasks` 提交（只建 RECEIVED + `task.created`，不执行目标）；
  - `GET /tasks` / `/tasks/{id}` / `/{id}/events` / `/{id}/evidence` / `/{id}/casepack`
    为只读查询，`/{id}/evidence/{sha256}` 与 `/{id}/casepack/file?name=` 只读下载；
  - `POST /{id}/preflight` 是显式准入门（RECEIVED/BLOCKED → READY/BLOCKED，BLOCKED 为重试）；
  - `POST /{id}/run` 是显式执行触发：只受理 PLANNED，执行交给 `bin/platform.py run` 子进程；
- 新增五个只读页面（复用 [style.css](vulnmap_platform/static/style.css) 与
  [app.js](vulnmap_platform/static/app.js)）：任务列表/提交、任务详情（状态/预算/时间线）、
  事件流、证据浏览器、CasePack/报告；[index.html](vulnmap_platform/static/index.html) 与
  `app.js` 的 `VIEWS` 加入“V2 任务”入口；
- 只读三约束：GET 不建库、GET 不改状态（测试对比 GET 前后 state/事件/证据/候选）、
  页面不直接读 SQLite（提交/准入/触发只打 API）；
- 现有 Discovery 五页保留为“执行证据视图”，与任务视图并列，不合并口径；
- 数据源仍是 `<PLATFORM_ROOT>/platform.db`（默认 `.platform/platform.db`），
  与 P0–P3 CLI 同库，`SCHEMA_VERSION=4` 不变；
- 验收：`tests/test_platform_v2_p4.py`（19 项），P0+P1+P2+P3+P4 共 **61 passed**
  （`python3 -m pytest tests/test_platform_v2*.py -q`）；
  含 Discovery 页面/API 的全量口径为 90 passed（`tests/test_platform_v2*.py
  tests/test_platform_discovery.py`）；8102 实测五页 200、提交→准入→查询链路可用；
- 边界：不做鉴权/SSE，页面不提供“一键执行”，CasePack 只给路径 + 哈希 + 下载。

### P4.5：执行作业化 + 事件推送 + 可选 token（已实现，细节见 [PLATFORM-V2-P45.md](PLATFORM-V2-P45.md)）
- jobs（[vulnmap_platform/api/platform_jobs.py](vulnmap_platform/api/platform_jobs.py)）：
  P4 的 `POST /run` 只 `Popen` 一次就把 pid 扔掉，P4.5 把执行落成台账——
  `platform.db` 新增 `jobs` 表（`job_id / task_id / pid / status / started / finished / log`
  + `exit_code / argv_json / note / created_at / updated_at`），由 API 侧
  `CREATE TABLE IF NOT EXISTS` 自建，`agent/platform` 核心与 `SCHEMA_VERSION=4` 一行未改；
  启动器状态 `PENDING / RUNNING / EXITED(0) / FAILED(非 0) / CANCELLED`：
  pid 活着即 `RUNNING`，watcher 线程等进程结束写退出码，已 `CANCELLED` 的行不被回写；
  日志固定 `<PLATFORM_ROOT>/runs/<task_id>.log`，`GET /jobs/{id}` 给末 4 KB tail；
  `_spawn_process` 可注入（测试用本机小脚本，pid/退出码/SIGTERM 都是真的）；
  不做 TTL 回收与队列调度，一个任务同时只允许一条活作业；
- 两套状态分工（这一轮最容易搞错的地方）：`status` 是启动器视角，`state` 永远是
  `task_events` 重放结果，响应带 `status_source="event_stream"`；`finished` 表示任务到终态、
  `job_finished` 表示进程侧结束，二者可同时为假/一真一假，谁也不覆盖谁；
- API（[vulnmap_platform/api/platform_tasks.py](vulnmap_platform/api/platform_tasks.py)）：
  `POST /tasks/{id}/run` 改为建一行 job 并返回 `job`（保留旧 `pid`/`log`/`state` 字段），
  同一任务存在活作业时再 run → 409；新增 `GET /api/platform/jobs?task_id=&limit=`、
  `GET /api/platform/jobs/{id}`、`POST /api/platform/jobs/{id}/cancel`、
  `GET /api/platform/tasks/{id}/stream`（SSE）；任务详情多 `jobs` 字段；
  读路径用 `mode=ro`、库不存在给空/404，P4 的“GET 不建库、GET 不改状态”继续成立；
- 取消是双动作（[agent/platform/lifecycle.py](agent/platform/lifecycle.py) 仍在状态机一侧）：
  先 `cancel_task()`（`task.cancel_requested` → 证据快照 → `state.changed→CANCELLED` →
  `task.cancelled`），再对**进程组**发 SIGTERM；重复取消/任务已终态 409、未知 job 404；
  进程已结束的 job 只取消任务状态（`job_cancelled=false`），作业行保留进程事实；
- SSE：`GET /tasks/{id}/stream` 为 `text/event-stream`，帧序
  `retry: 1000 → event: hello → event: task_event(id=<seq>) → event: state（事件流状态 +
  最近作业摘要）→ event: ping（每 50 tick）→ event: end`
  （`reason ∈ terminal|once|max_events|timeout|db missing`）；参数
  `after / once / timeout（0=不限） / max_events / poll`，未知任务在开流前 404；
  [platform-task.html](vulnmap_platform/static/platform-task.html) 与
  [platform-events.html](vulnmap_platform/static/platform-events.html) 改用 `EventSource`
  跟随，不再定时轮询；
- 可选 token（[vulnmap_platform/api/platform_auth.py](vulnmap_platform/api/platform_auth.py)）：
  `PLATFORM_API_TOKEN` 未设置 → 写操作本地开放，响应体 `auth:{mode:"open",…}` 且 HTTP 头
  `X-Platform-Auth: open`；设置后写操作（提交/preflight/run/cancel）必须
  `Authorization: Bearer`，缺失 401（带 `WWW-Authenticate`）、不匹配 403；GET 一律开放；
  token 每请求重读、`hmac.compare_digest` 比较；
  [app.js](vulnmap_platform/static/app.js) 的 `writeJSON()` 从 `localStorage.platform_token`
  取 token 并加 Bearer 头；
- 验收：`tests/test_platform_v2_p45.py`（21 项：作业生命周期 6 / 取消 3 / SSE 5 / 认证 3 /
  页面与路由 4），`python3 -m pytest tests/test_platform_v2*.py tests/test_platform_discovery.py -q`
  → **210 passed**（V2 181 + Discovery 29，V2 侧在 P3.8 之后由 146 增至 181）；
- 边界：不做多用户/角色；不做 WebSocket；不做作业重试与队列调度（一个任务同时只允许
  一条活作业）；不把 job 状态当任务状态（事件流唯一裁判）；不改 `agent/platform` 与 schema 版本；
  不自动清理 jobs 行、不做 SIGKILL 升级。

### P4.6：CasePack 网页报告 + 写操作默认只开本机（已实现，细节见 [PLATFORM-V2-CASEPACK.md](PLATFORM-V2-CASEPACK.md)）
- Case Pack（[agent/platform/casepack.py](agent/platform/casepack.py)）在 `report.md` 之外
  多渲染 `report.html`：同一批台账快照 → 同一份字节（无渲染时间戳）、样式内联、
  无脚本/外链/图片（零外部资源）、台账字段全部 `html.escape`；页面给任务摘要、
  包级摘要、事件流、候选/验证/复核表、证据清单与口径声明，不新造 `confirmed`；
- `report.html` 进 `FILES` → 自动进 `content_sha256`、`casepack.json.files` 与
  `report.ready` 事件；包内 `report` 段给 `html_sha256`/`html_size`/`html_external_refs`；
  `reports` 台账额外记 `report_html_sha256`（单文件哈希），列由 casepack 侧
  `_ensure_columns()` 幂等补齐，`store.py` 未改、`SCHEMA_VERSION=4` 不变；
- API（[vulnmap_platform/api/platform_tasks.py](vulnmap_platform/api/platform_tasks.py)）：
  `/tasks/{id}/casepack` 多 `report_html_sha256`（盘上）/`report_html_sha256_recorded`
  （台账）/`report_html_ok` 与 md/html 下载链接，`/casepack/file?name=report.html`
  按 `text/html` 下发；任务详情 `casepack` 段同步；
- 写操作默认收口（[vulnmap_platform/api/platform_auth.py](vulnmap_platform/api/platform_auth.py)）：
  `PLATFORM_API_TOKEN` 未设置时只受理回环客户端（`127.0.0.1` / `::1` / `localhost` /
  `*.localhost`，TestClient 的 `testclient` 等价），远端写请求 **403** 并提示设置 token；
  带 `X-Forwarded-For`/`X-Real-IP`/`Forwarded` 的回环按远端处理（uvicorn 默认
  `proxy_headers=True` 会先把客户端改写成转发来源，此时按真实来源判定），
  `PLATFORM_TRUST_PROXY=1` 只用于“地址仍是回环、只是带头”的场景；设置 token 后只认 Bearer（缺失 401 / 不匹配 403），
  与本机/远端无关；GET 始终开放；响应多 `auth.write_scope` 与 `X-Platform-Write-Scope`；
- 验收：`tests/test_platform_v2_casepack.py`（9 项：HTML 内容/哈希 3、API 1、认证默认 4、
  打包门槛 1），`python3 -m pytest tests/test_platform_v2*.py tests/test_platform_discovery.py -q`
  → **235 passed**（V2 206 + Discovery 29）；
- 边界：不做 PDF/截图、不做前端框架与图表、不做多用户/审计主体、不做 TLS/反代解析；
  默认回环限制只作用于写操作；`serve.py` 默认 `--host 127.0.0.1`，显式 `--host 0.0.0.0`
  时对外暴露请设 token。

## 6. 不要做什么

- 不要重写 Discovery：D0–D5 作为 fuzz executor 复用；
- 不要重写旧平台：vuln/fix runner、checkpoint、预算、LEDGER 作为 adapter/基础库复用；
- 不要用“干净重建 3/3”冒充 vuln/fix 独立验证；
- 不要把 EventBus 做成日志文本：必须是可查询、可重放的结构化事件；
- 不要先做 UI：没有 TaskState/Evidence 的 UI 只是又一层展示。

## 7. 验收指标

| 指标 | 目标 |
|---|---|
| 任务可恢复 | 进程重启后按事件流恢复阶段与预算 |
| 证据可审计 | 每个结论能追到 evidence sha256 |
| 验证独立 | 结论必须引用 vul/fix 或行为差分证据；`--execute` 下证据由 runner 现场产出并哈希落库 |
| 多 benchmark | 同一任务运行时接 CG/EG/VG/target.yaml |
| spec 可自证 | `verify --auto` / `smoke` 从 task.json+metadata 生成 runner spec；缺字段/缺镜像/服务不可达一律如实 `needs_evidence`，`smoke` 不落验证记录 |
| 负结果保留 | blocked/no_repro/rejected 都进 Case Pack |
| 源码可理解 | 只有 repo-vul.tar.gz 的 CG/EG workspace 也能产出非空 ProgramIndex（解包树入 D0/D1，缓存键=包 sha256） |
| 旧证据可重放 | 有旧 PoC 时 planner 优先 replay；重放产出 Candidate + 可喂 `verify --spec` 的判据输入，跑不动一律 FAILED |
| 执行器不缺位 | fuzz/replay/static/dynamic 四个 kind 都有执行器；表里没有的 kind 报 `executor_unavailable:<kind>`（PlanError → FAILED），不静默换执行方式 |
| 静态不产结论 | static 只产 `static_review` 证据与 NO_REPRO/NEEDS_EVIDENCE，候选为 0、无 verdict/confirmed 字段；缺口列入 `gaps`（无源码树/锚点未复算/假设定位不到） |
| 差分可复核 | dynamic 两侧请求不跟跳转、禁代理；有差异产 Candidate（请求文档 + 差分日志 + `dynamic_spec` 可喂 `verify --spec`），服务打不通一律 FAILED 并留 `dynamic_spec`/`dynamic_run` |
| 预算可执行 | 任务级四个上限在执行前预检、执行中按 fuzz stats/耗时结算；超限落 TERMINATED（budget_*），不冒充 no_repro |
| 可取消 | RUNNING/PLANNED 可取消（终态拒绝）；取消/超限都留事件 + 证据快照 |
| UI 只读 | 页面无写状态接口，状态由运行时产生 |
| 执行可跟踪 | 每次 run 落一行 jobs（job_id/pid/status/退出码/日志 tail），进程事实可查，取消先落事件再给进程组发 SIGTERM |
| 事件可推送 | `/tasks/{id}/stream` 为 `text/event-stream`，`after=` 续传、`once=1` 单趟，页面用 `EventSource` 跟随而非轮询 |
| 写操作可鉴权 | `PLATFORM_API_TOKEN` 设置后写操作要求 `Authorization: Bearer`（缺失 401 / 不匹配 403）；未设置时写操作默认只开本机回环（远端 403 + 提示设 token），响应与响应头如实标注 `open` / `loopback` |
| 报告可人读 | Case Pack 同时给 `report.md` 与自包含的 `report.html`（确定性渲染、零外部资源、字段全转义）；两份都进 `content_sha256`，`reports` 另记 `report_html_sha256` 可单文件复核 |
