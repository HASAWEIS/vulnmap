# V3 P2b：受限实验副本、慢循环与独立采纳（V3-007 / V3-008 / V3-009）

对应《VULNMAP-V3 完整升级方案》§4「双循环与状态模型」、§5「执行感知」、
§8「实验自修改与版本事务」、§9「统一数据契约」、§12「独立验证」与 §18.1 门禁。
P2a 已交付单一动作契约与可信快照；P2b 把“快照 → 诊断 → 改副本 → 真构建/冒烟 →
执行 → 比较 → 采纳/回退 → 停止”这条慢循环接通，并且**不放松任何判据**。

| 项 | 状态 | 验收口径 | 测试 |
|---|---|---|---|
| V3-007 受限实验副本与修订 | 已实施 | 原件不变；stage/build/smoke/revert 真实执行；失效被消费（T05/T06/T07） | `tests/test_v3_p2_session.py` |
| V3-008 研究会话与慢循环 | 已实施 | 真实首轮反馈改变第二轮动作；相同事实有限停止（T04/T10/T14） | 同上 |
| V3-009 独立采纳与 harness 假阳性门 | 已实施 | 工程采纳与漏洞验证分开；自崩/建模不冒充通过（T08/T14/T15） | 同上 |

改动边界：

- 新增 `agent/platform/adaptive/{revision,workspace,session,controller,policy}.py`；
- `adaptive/tools.py` 只给 `make_binding()` 增加两个**可选**关键字
  （`harness_revision` / `build_id`，默认回退到语料 build_id），不新增工具、
  不改工具 schema、不改 `REGISTRY` 的 10 个工具与 `tool_schema_hash` 的既有口径；
- `adaptive/__init__.py` 追加导出；
- 新增测试与本文档；
- **未改** `agent/platform/verify.py`、`benchmark_policy`、执行器执行语义
  （`executors/`）、API 层、DB schema。

复跑命令：

```bash
python3 -m pytest tests/test_v3_p2_session.py -q
python3 -m pytest tests/test_v3_p2_contracts.py tests/test_v3_p1_seed.py -q
python3 -m pytest -q          # 全量回归
```

---

## 1. 为什么 P2b 必须“真跑”而不是再写一层接口

P2a 的教训是“schema 里支持、执行器不支持”：只要新能力只停在返回值里，
控制器不消费、构建不真跑、回退只改指针，那么“自修复”就只是文档。
P2b 因此把三个“必须落盘”的事实做成可复核的账：

1. **副本是真的**：`origin/` 逐文件 0444，任何写操作只能落 `current/`；
   每次 build/smoke 都在 `revisions/<id>/` 的副本目录里 `subprocess.run`，
   日志文件带哈希，退出码与耗时进账。
2. **回退是重建而不是改历史**：`revert()` 把目标 revision 的 manifest 复制回工作树，
   再登记一个**新** revision（`reverted_to` 指回目标）；旧快照不改不删。
3. **采纳有账**：`adoptions.jsonl` 只记 `policy.engineering()` 的工程结论；
   候选只触发 `verification_request()`，控制器**不写** `verified/confirmed`，
   也不在本循环里调用 `verify`。

---

## 2. `revision.py`：版本事务

### 2.1 内容即身份

`HarnessRevision` 是 frozen dataclass，字段：

| 字段 | 语义 |
|---|---|
| `parent_id` | 父 revision（根为空）；父不存在 → 拒收 |
| `manifest` | 全量文件清单 `(path, sha256, size, mode)`，按路径排序去重 |
| `diff` | 相对父快照的可重建 unified diff（二进制只记哈希变化） |
| `reason` / `hypothesis_id` / `action_id` / `tool` | 为什么改、服务哪条假设、由谁触发 |
| `environment` | 环境身份（toolchain / policy_version / round …） |
| `reverted_to` | 回退型 revision 指回目标 |

`revision_id = "hr-" + sha256(identity_doc)[:16]`，`identity_doc` 不含 `created_at`
和 `diff`。`from_dict()` 会**重算** `revision_id`，篡改任一字段 → `RevisionError`；
`RevisionStore.add()` 对同 id 不同内容也直接拒绝——旧 revision 不可改写。

manifest 只描述内容（路径/哈希/大小），POSIX 读写位由 `verify_manifest()` 单独检查，
避免“原件 0444、副本 0644”让同一份内容算出两个 manifest。

### 2.2 构建/冒烟事实与 revision 分离

`BuildRecord` 与 `SmokeRecord` 是可追加的事实，不修改 revision：

| 记录 | 关键字段 | 口径 |
|---|---|---|
| `BuildRecord` | `build_id` / status(`ok/failed/setup_error/timeout`) / exit_code / duration / log_path / log_sha256 / workdir | `build_id = "bd-" + sha256(manifest + command + toolchain + env_digest)[:16]`，是构建身份也是缓存键 |
| `SmokeRecord` | `smoke_id` / status(`passed/failed/harness_error/setup_error/timeout`) / kind / exit_code / log_sha256 | `harness_failed=True` 时只能让结论更弱 |

同一 revision 可以有多条构建/冒烟记录（例如回退后重跑）；`latest_build/latest_smoke`
取最后一条，`builds()/smokes()` 保留全部。

### 2.3 账本与完整性

`RevisionStore` 用只追加的 `revisions.jsonl / builds.jsonl / smokes.jsonl /
adoptions.jsonl`，`current.json` 只存“当前选中的工作版本”。`verify_manifest()`
逐文件复核哈希、大小、只读位并报告多/少/改：
`missing:` / `changed:` / `size:` / `writable:` / `extra:`。

---

## 3. `workspace.py`：任务 overlay 副本

### 3.1 布局

```
<root>/
  workspace.json          # task_id / 命令 / 超时 / toolchain / 原件路径
  origin/                 # 原件副本，文件 0444（“原件没变”的对照）
  current/                # 唯一可写工作副本
  revisions/<hr-id>/      # 不可变快照，文件 0444
  builds/<hr-id>-NN/      # 构建目录（副本，可写）
  logs/                   # build/smoke 完整日志
  store/                  # 上述 jsonl 台账
```

### 3.2 原件只读是“算出来的”

- `create()` 读原件（有界：4096 文件 / 4 MiB 单文件 / 64 MiB 总量，符号链接直接拒绝），
  逐文件写 `origin/` 并 `chmod 0444`，同时写 `current/`（0644）。
- `stage()` 只写 `current/`，路径经 `safe_relpath()`：拒绝绝对路径、`..`、反斜杠、
  控制字符；`origin/`、`revisions/`、`builds/` 不在写入口上。
- `origin_integrity()` 用基线 revision 的 manifest 逐文件比对 `origin/`：多、少、
  改、可写都会出现在 `problems` 里。测试同时验证“直接 `open(origin/x,'w')` →
  `PermissionError`”。

### 3.3 stage → commit

```python
ws.stage({"seed_params.json": '{"format": "magic"}'}, grant=ctx.grant, reason=...)
rev = ws.commit(reason=..., hypothesis_id=..., action_id=..., tool=...)
```

- `stage` 返回每个文件的 `before_sha256/after_sha256/size/created`；
- `commit` 用 `current/` 全量 manifest 与父快照算 diff，登记新 revision，
  快照到 `revisions/<id>/` 后设 0444；内容与父相同 → `WorkspaceError("no_change")`；
- `commit/revert` 都把 `build/smoke/coverage_baseline/corpus_members`
  记入 `RevisionStore` 的待消费集合。

### 3.4 build：真实执行

`build()` 把 revision 快照复制到 `builds/<id>-NN/`，在副本目录里：

```python
subprocess.run(cmd, cwd=workdir, capture_output=True, text=True,
               timeout=..., env=clean_env, shell=False)
```

- 环境只给 `PATH/LANG/TZ/HOME/TMPDIR`；名字含
  `KEY/TOKEN/SECRET/PASSWORD/CREDENTIAL/COOKIE/AUTH/SESSION` 的变量一律不继承；
- 退出码映射：`0 → ok`；`126/127 → setup_error`；超时 `→ timeout`；其余 `→ failed`；
- 完整 stdout/stderr 落到 `logs/`，超过 256 KiB 截断并标 `truncated`；
  `log_sha256` 可按文件字节复算；
- 没有配置 `build_command` → `WorkspaceError("setup_error: ...")`，不假装构建。

### 3.5 smoke：harness 自崩与目标行为分开

`classify_smoke(exit_code, output)`：

| 条件 | status | kind |
|---|---|---|
| exit 0 | `passed` | — |
| 输出含 `Traceback (most recent call last)` / `SyntaxError` / `ImportError` / `SMOKE:harness_error` | `harness_error` | `harness_error` |
| exit 2（用法错误，例如 argparse） | `harness_error` | `usage_error` |
| exit 126/127 | `setup_error` | `setup_error` |
| 其他非 0 | `failed` | `target` |

`SmokeRecord.harness_failed` 为真时，`policy.engineering()` / `false_positive()` /
`verification_request()` 都不会放行——**装置坏了不等于目标有问题，更不等于通过**。

### 3.6 revert：选父版本重建工作树

1. 目标 = 指定 revision 或当前 revision 的父；
2. `rmtree(current/)` 后按目标 manifest 逐文件落盘（0644）；
3. 复核目标快照 `verify_manifest()` 与工作树 manifest；
4. 登记**新** revision：`manifest=目标.manifest`、`parent=当前`、
   `reverted_to=目标`，diff = 当前快照 → 目标快照；
5. 旧 revision 的 `revisions/<id>/` 不改不删，只读。

### 3.7 失效传播

| 变更 | revision.invalidations | 控制器怎么消费 |
|---|---|---|
| harness/生成器（commit） | `build, smoke, coverage_baseline, corpus_members` | 本轮真跑 build+smoke；新 `build_id` 作为新基线；本轮 `materialize_seeds` 视为语料复验 |
| revert | 同上 | 记录 `coverage_baseline = revert:<id>`；语料标记 `deferred:revalidation_required`（停止前不再声明可比） |
| execution（run_epoch） | `execution_facts, trial_compare, coverage_baseline` | COLLECT 用新 execution 重建事实；COMPARE 调 `compare_trials` 或声明无缓存可失效 |
| 语料物化（`materialize_seeds`） | `input_dedup, corpus_members` | 由同一动作本身落实 |
| 字典（`set_dictionary`） | `input_dedup` | 由同一动作本身落实 |

每轮 `record.invalidations` 的每条都有 `scope / handled_by / status`；
`status=unhandled` 表示没有落实，`deferred:` 前缀表示“承认失效但停止前不复验”。

---

## 4. `session.py`：Context / Seed / Diagnose

### 4.1 输入是快照

`ContextRole.observe(snapshot)` 只读 `TrustedExecutionSnapshot`：

- 目标语义三段（各三值、互不派生）：`program_started` / `input_processed` /
  `checkpoint_reached`；`target_reached` 只是 `checkpoint_reached` 的兼容别名
  （口径见 `docs/V3-TARGET-SEMANTICS.md`）；
- `coverage`：status/covered/uncovered/delta/comparable/
  metric_kind/baseline_id；`candidates`：只认 `fault.candidates` 的整数，缺失为 unknown；
- `fault`：outcome/setup_error/timeout/error 全部三值（`false` 不再被当成“有错误”）；
- `input`：format/seeds/dictionary_tokens/input_consumed（语料喂进执行器，**不是**
  input_processed）/corpus_*/三段事实；
- `revision/workspace`：当前 revision、最新 build/smoke 状态、`origin_ok`、当前文件表。

`facts_hash` 只对**进展事实**取指纹：program_started、input_processed、
checkpoint_reached（+ 兼容别名 target_reached）、coverage 六项、candidates、
fault 四项、input_consumed。时间、轮数、`execution_id`、trials 数量、corpus 版本
都不进去——换 action_id 重跑同一状态不算进展（§11）。三段事实分别进指纹，
所以“进程起来了”“输入被处理了”“检查点命中了”是三种不同的进展。

### 4.2 诊断优先级

| 优先级 | 条件 | code | 控制器动作 |
|---|---|---|---|
| 1 | `fault.error == "true"` | `execution_error` | 停 `blocked`，不当作 no_repro |
| 2 | `fault.timeout == "true"` | `execution_error` | 同上 |
| 3 | `candidates > 0` | `candidate_observed` | 停 `candidate_ready`，只交独立验证 |
| 4 | `program_started == "false"` | `program_not_started` | 修启动/隔离后重跑（不当作“没命中”） |
| 5 | `input_processed == "false"` | `input_not_processed` | 换输入/种子（目标没处理输入） |
| 6 | `checkpoint_reached == "false"` | `target_unreached` | 改 seed/生成器后重跑 |
| 7 | `checkpoint_reached == "true"` 且 delta>0 | `progress` | 继续补种子/字典 |
| 8 | `checkpoint_reached == "true"` | `low_coverage` | 换输入策略 |
| 9 | 无 trial 且快照 unknown | `no_execution` | 先建立最小语料并跑第一轮 |
| 10 | 其余（含 `checkpoint_reached == "unknown"`） | `coverage_unknown`（理由 `target_reached_unknown`） | 换策略或补探针，仍无进展则由 facts 守卫停 |

### 4.3 确定性种子序列

`attempt 0/1/2 → raw / magic / framed`（`SeedRole`）；attempt 0 一律先按原配置执行，
拿到反馈后才允许改副本。默认生成器编辑只改**已存在**的种子参数文件
（`seed_params.json` / `harness/seed_params.json` / `configs/seed.json`），
没有可改文件就返回 `None`，不凭空造配置。

### 4.4 LLM 只是建议

`ResearchSession(advisor=...)` 的返回值逐条校验：

1. `action` 必须已注册；
2. `params` 必须过同一份 `ToolSpec` schema；
3. 模式必须在 `allowed_modes` 内；
4. `verified/confirmed/pass/verdict/...` 出现即拒绝（`prune_verdict_fields`）；
5. 每轮最多采纳一条附加建议，身份仍由 `Binding` 注入。

校验失败/抛异常只记 `advisor_errors`，确定性计划不受影响；`llm_suggestions`
只统计真正被采纳的条数。

---

## 5. `controller.py`：慢循环

### 5.1 阶段与顺序

`OBSERVE → DIAGNOSE → PROPOSE → AUTHORIZE → [STAGE → BUILD → SMOKE →
ADOPT/REVERT] → EXECUTE → COLLECT → COMPARE → STOP`

方括号段只在本轮有 `RevisionPlan` 时发生；有副本变更时先“改副本→真构建→真冒烟→
工程采纳/回退”再执行，保证执行用的是**已采纳**的 build；采纳后动作会按新
`Binding` 重新签发。

- 每轮重新签发 `Binding`（`epoch = round`），`harness_revision/build_id` 来自当前
  采用的 revision 与其最后一次成功构建；采纳新 revision 后**重新签发**动作
  （`session.remint`），新 build 仍是新身份（§9）。
- 动作执行仍走 `Registry.invoke()`：身份、权限、模式、预算、失效一处不少。
- `$ref` 只能引用本轮已经成功执行的动作 payload；解析不到 → `unresolved_ref`，
  绝不把 `None` 当参数传下去。

### 5.2 停止矩阵

| 条件 | `stop_reason` | `status` |
|---|---|---|
| 观察到候选 | `candidate_ready` / `verification_blocked` | completed / blocked |
| 同一 `facts_hash` 出现 `max_same_facts` 次 | `repeated_facts` | completed |
| 预算端口剩余 ≤ 0 | `budget` | budget |
| `cancel()` 为真 | `cancelled` | cancelled |
| 达到 `max_rounds` | `max_rounds` | completed |
| 执行报错/超时 | `execution_error` | blocked |
| 无授权动作 | `policy_blocked` | blocked |
| 构建/冒烟被策略拒绝 | `harness_error` / `engineering_rejected` | blocked |
| 引擎异常 | `error:<Type>` | failed |

相同动作守卫：`fingerprint = (facts_hash, action, digest(params))`；同一指纹再次出现
时该动作记 `skipped(same_facts_same_action)` 并跳过；整轮动作全被跳过且没有可改副本
→ `repeated_actions` 停止（换 `action_id` 重试不算进展）。

### 5.3 ADOPT / REVERT

- ADOPT 只记录 `policy.engineering()` 的 `Decision`（scope=`engineering`）到
  `adoptions.jsonl`，并打印失败检查项；不写任何漏洞字段。
- 策略拒绝时调用 `workspace.revert(to_revision=revision.parent_id)`：
  smoke 是 `harness_error` 或 build 失败 → `harness_error` 停止；
  其他（例如 `origin_unchanged` 失败）→ `engineering_rejected` 停止。

### 5.4 预算与取消

- `DeclaredBudget` 按任务预算建立（`max_seconds/max_execs/max_tokens/max_turns/max_usd`），
  跨轮持久；每轮开始与结束都检查 `remaining`，`run_epoch` 的结算进同一账本。
- `cancel` 是零参可调用对象；每轮开始检查，取消优先于结果升级。

---

## 6. `policy.py`：工程采纳与漏洞验证分离

### 6.1 工程采纳的检查项

`AdoptionPolicy.engineering(revision, build, smoke, origin, compare, trial, claimed_payload)`
的每条检查都可复核：

| 检查 | 通过条件 |
|---|---|
| `origin_unchanged` | `workspace.origin_integrity().ok` |
| `revision_present` / `revision_digest` | revision 存在且 `revision_id == compute_id()` |
| `build_ok` | `BuildRecord.ok` |
| `smoke_passed` | `SmokeRecord.ok` 且 `harness_failed == False` |
| `harness_healthy` | 冒烟没有 traceback/用法错误 |
| `execution_evidence` | trial 有 `outcome` 或 `execution_id`；`build_id` 与本次构建一致（防跨 build 复用） |
| `measurable_gain` | 仅在提供 compare 时要求：`status=applied`、`comparable=true`、`delta>min` |
| `no_verdict_claim` | payload 里没有 `verified/confirmed/...`（有则剥掉并判失败） |

`adopt` 只是工程结论（可构建/驱动有效/有收益），**不产生** `verified`。

### 6.2 候选 → 独立验证

`verification_request(diagnosis, candidates, engineering, mode, evidence_refs)` 只在
以下全部成立时 `allowed=True`：诊断是 `candidate_observed`、candidates>0、
工程决策已采纳、研究循环仍处 `explore`、有候选证据引用。返回 `mode="verify"`，
明确写着“allowed=true 只表示可以交给既有 verify；不代表已验证”。

### 6.3 裁决只读

`verdict(records=...)` / `verdict(store=..., task_id=...)` 只认：

- `schema == "vulnmap.verification.v1"`；
- `status ∈ {verified,no_repro,needs_evidence,rejected}`；
- `verified` 与 `status=verified` **同时**为真；
- 不含 `confirmed` 字段。

伪造记录（schema 错、状态自相矛盾、带 confirmed）→ 出现在 `invalid`，不算 verified。
空记录 → `status="not_verified"`，且不解释成 `no_repro`。
`review_claim({"verified": true})` 永远 `adopt=False`，理由
`verdict_claim_forbidden` / `verdict_only_from_verify`。

### 6.4 harness 假阳性门

`false_positive()` 显式拒绝：

| 场景 | 失败检查 |
|---|---|
| smoke 是 `harness_error` | `harness_healthy`、`smoke_passed` |
| 构建失败 | `build_ok` |
| trial 的 build_id 与本次 build 不一致（拿旧覆盖冒充新 build） | `execution_evidence` |
| 跨 build 比较 | `comparable` |
| 自报 `verified/confirmed` | `no_verdict_claim` |

**建模不执行**（trial 既无 outcome 也无 execution_id）同样被 `execution_evidence` 拒绝。

---

## 7. 测试（`tests/test_v3_p2_session.py`）

14 个用例，全部真实执行（仅隔离执行 worker 用 `FakeRunner` 替身写入
`exec.started/finished` 事件；build/smoke 仍是真实 `subprocess.run`）：

| 用例 | T 码 | 断言要点 |
|---|---|---|
| `test_v3_007_origin_read_only_and_never_changes` | V3-007 / T08 | `origin/` 0444、`os.access(W_OK)=False`、直接 `open(...,"w")` → `PermissionError`；build/smoke → stage/commit → build/smoke → revert 后 `origin_integrity().problems == []`，逐文件字节/manifest 与初始一致，输入原件也未被改写 |
| `test_stage_commit_build_smoke_really_execute` | T05 | stage 改 `seed_params.json` → commit（parent/diff/changed_against）；build exit 0、日志非空且 `log_sha256` 可复算；smoke 改前 `failed(kind=target)`、改后 `passed`；快照内容=改后内容且 0444 |
| `test_committed_revision_is_immutable` | T06 / T08 | frozen；同 id 不同 manifest → `revision_tampered`；chmod +w 篡改快照 → `verify_manifest` 报 `changed:`；篡改后的 doc `from_dict` 被拒 |
| `test_revert_rebuilds_worktree_without_rewriting_history` | T05 | `working_manifest == base.manifest`；`reverted_to` 指向目标；旧快照字节/manifest 未变；revert 重新登记四条失效；revision 账本只增 |
| `test_harness_invalidations_are_consumed_by_controller` | T06 | 带 revision 的一轮里 `build/smoke/coverage_baseline/corpus_members` 全 `handled` 且 `handled_by` 非空；`revision.invalidations == CHANGE_INVALIDATIONS["harness"]`；跑完待消费集合为空 |
| `test_two_round_feedback_changes_action_and_reaches_candidate` | T04（核心） | r1 `no_execution`/不改副本；r2 `target_unreached` → `format raw→magic` → build ok → smoke passed → adopted；runner 2 次；`candidate_ready` + `verification.allowed`；`list_verifications()==[]` |
| `test_repeated_facts_stop_the_loop` | T10 | runner 恒 no_repro → 只调 2 次，第 3 轮 OBSERVE 即 `repeated_facts`，EXECUTE 只在 1/2 轮 |
| `test_broken_harness_is_reverted_and_not_adopted` | T05 / T08 | 注入坏 `gen.py`（py_compile 过、smoke traceback）→ `harness_error`、不采纳、工作树回父 revision、`stop_reason=harness_error`、`status=blocked`、无 verify 记录；该轮 `corpus_members=deferred` |
| `test_policy_rejects_harness_false_positive` | T08 | `harness_failed` → adopt False 且 failed 含 `smoke_passed/harness_healthy`；跨 build trial → `execution_evidence` 失败；自报 verified → 两条理由；嵌套裁决字段被剥 |
| `test_verdict_comes_only_from_verify_records` | T15 | 空 → `not_verified`；3 条伪造（schema/状态矛盾/confirmed）全进 `invalid`；真实 `Verification` 形状 → verified；全程不写库 |
| `test_mode_and_trusted_field_isolation` | T14 | verify 下 `run_epoch`、explore 下 `replay_input` 均 `mode_not_allowed`；`verified` 参数 → `trusted_field_forbidden`；advisor 夹带 verified/binding 被丢弃 |
| `test_repeated_action_under_same_facts_is_skipped` | T10 | 事实恒定 + 每轮同一动作 → 第 2 轮 `skipped(same_facts_same_action)`、runner 只执行 1 次、`repeated_actions` 停止 |
| `test_budget_and_cancel_hooks` | T11 | `turns=1` → 第 1 轮结算后停（rounds=1、runner=1）；`cancel=True` → cancelled、runner 0 次、无 EXECUTE |
| `test_advisor_only_suggests` | T14 / T04 | 合法建议 `purpose=advisor`、`llm_suggestions=1`；advisor 抛异常只记 `advisor_errors`，确定性动作序列与 revision 不变 |

边界口径：`FakeRunner` 只替代**执行 worker**（P2b 不起真 fuzzer，也不宣称跑过
CG/EG/VG 真实目标）；构建/冒烟/日志/只读位/旧 revision 全部按真实文件与退出码断言。


---

## 8. 仍然没做（留给 P3/P4）

1. **四个“测试工件”工具**（`write_harness_candidate` / `edit_generator` /
   `build_candidate` / `smoke_candidate`）没有加进 `REGISTRY`：P2b 的 stage/build/smoke
   是控制器内部、要求 L1 的任务副本操作；若加工具会改 `tool_schema_hash` 与 P2a
   工具表口径，留给 P3 与预算/授权一起接。
2. **campaign/epoch/agent_decisions 等新表**：本轮只写 `adoptions.jsonl`、构建/冒烟
   jsonl 与（可选）`research.finished` 事件；DB 迁移属于 P3。
3. **真实目标 runner**：`ctx.exec_runner` 仍由调用方注入；P2b 的验收用真实
   `subprocess` 跑本地 build/smoke，执行反馈由 fake worker 写事件，未宣称跑过
   CG/EG/VG 真实目标。
   → **P2c 已接入口**：`run --research` 的 `FuzzEpochRunner` 真调
   `executors.fuzz.execute`（短切片 + `exec.started/finished` 事件 +
   `exec_stats/exec_error` 证据），依赖装配与状态映射见
   [`V3-P2C-RESEARCH-CLI.md`](V3-P2C-RESEARCH-CLI.md)；CG/EG/VG 真实目标长跑
   仍未跑（本机无可用构建命令）。
4. **collector 字段**：`isolation/network/sanitizer/cmd` 仍依赖 worker 在
   `exec.started/finished` 里补；快照如实报 unknown。
   → P2c 的 worker 已补 `isolation`（其余仍 unknown：fuzz 执行器不产出
   network/sanitizer 声明）。
5. **PatchWorkflow / 经验库 / A–E 实验矩阵**：不在 P2b 范围。
6. **金额预算**：`DeclaredBudget` 支持 `usd`，平台 `Budget` 无金额字段，
   `remaining_usd` 恒为 unknown。

---

## 9. 复跑与基线对照

```bash
python3 -m pytest tests/test_v3_p2_session.py -q
python3 -m pytest tests/test_v3_p2_contracts.py tests/test_v3_p1_seed.py -q
python3 -m pytest -q
```

P2a 交付时全量为 `1307 passed, 8 skipped`；P2b 新增的验收用例全部通过，
全量结果见下表（以最后一次实际运行为准，不预填）。

实际运行（2026-11-19，Python 3.12.14，pytest 9.1.1）：

| 命令 | 结果 |
|---|---|
| `pytest tests/test_v3_p2_session.py -q` | **14 passed** |
| `pytest tests/test_v3_p2_contracts.py tests/test_v3_p1_seed.py -q` | **61 passed**（contracts 53 + P1 8） |
| `pytest -q`（全量） | **1337 passed, 8 skipped** |

全量相对 P2a 的 `1307 passed, 8 skipped` 增加 30 项：14 条 P2b 验收 + 并行
执行线补的 16 条契约/回归用例；P2b 未删除、未跳过任何既有用例。
