# V3 P2a：单一动作契约与可信执行快照（V3-005 / V3-006）

对应《VULNMAP-V3 完整升级方案》§5「执行感知」、§6「工具与权限」、§7「种子与语料」、
§8「实验自修改与版本事务」、§9「统一数据契约」，落地 P2 的前两项：

| 项 | 状态 | 验收口径 | 测试 |
|---|---|---|---|
| V3-005 单一动作契约与 Registry | 已实施 | schema/handler/权限/invalidations 同源；伪造身份拒绝（T07/T14） | `tests/test_v3_p2_contracts.py` |
| V3-006 可信执行快照与查询 | 已实施 | unknown 不变 0；跨 execution 游标拒绝（T03/T09） | 同上 |

改动边界：新增 `agent/platform/adaptive/{contracts,tools,snapshot}.py` 并更新
`adaptive/__init__.py`；`agent/platform/executors/__init__.py` 只在文件末尾追加
**只读钩子**（`EXEC_FACT_FIELDS` / `execution_fact_view`），未改执行语义、事件字段、
状态迁移与返回值；新增测试与本文档。`verify/`、`policy`、API 层未改。

复跑命令：

```bash
python3 -m pytest tests/test_v3_p2_contracts.py -q     # 57 passed
python3 -m pytest tests/test_v3_p1_seed.py -q          # 8 passed（P1 未回归）
python3 -m pytest -q                                   # 1341 passed, 8 skipped
```

---

## 1. 为什么需要“单一契约”

方案 §6 的原始问题是：**“schema 里支持、执行器不支持”**。在 V2 的执行路径上，
参数校验、权限、计费、失效范围分散在编排层、执行器与 CLI 里，任一处新增工具
就会出现“模型看到的能力”和“真正能做的事”两套口径。

P2a 的做法是把这四件事压到一个声明 `ToolSpec` 上，并且在**构造期**对账：

```
handler 签名  ──┐
params 类型表 ──┼─► ToolSpec.__post_init__ ─► schema（模型可见）+ required
changes       ──┤                              + invalidations
permission    ──┘                              + 权限层级
```

任何一处不一致都会在 **import 期**抛 `ToolError`，而不是等某个回合跑完才发现
（binsight-next 的旧问题正是“handler 内部重置局部标志，主循环根本读不到”）。

### 1.1 `ToolSpec` 的六条构造期约束

| # | 约束 | 失败表现 |
|---|---|---|
| 1 | `params` 键集合 == handler 实参集合（不含 `ctx`） | `schema/handler 不对账` |
| 2 | `required` 由签名推出（无默认值者必填），不接受手工声明 | 同上 |
| 3 | 每个参数声明必须有合法 `type`；默认值本身要通过该类型校验 | `默认值非法` |
| 4 | `permission ∈ {L0,L1,L2}`，`L3` 连注册都过不去 | `permission L3 永不暴露` |
| 5 | `changes` 必须命中 `CHANGE_INVALIDATIONS`，显式 `invalidations` 必须与派生值完全相等 | `失效范围必须同源` |
| 6 | `cost` 只允许出现在 L1 工具上（只读工具不计费） | `只读工具不允许计费` |
| 7 | schema 的 `default` 必须与 handler 默认值相等（handler 无默认却声明 default、或 handler 非 None 默认却没声明 → 都失败） | `默认值不同源` |
| 8 | 不许把裁决/可信字段（`NEVER_DECLARABLE`：status/verdict/verified/confirmed/pass/trusted/evidence_sha256/oracle）声明成参数 | `不许把裁决/可信字段声明成参数` |
| 9 | `allowed_modes` 只能是 explore/verify/空 | `unknown mode` |

`handler` 还必须：第一个参数叫 `ctx`、不能用 `*args/**kwargs`（否则 schema 无法派生）、
必须返回 `ToolOutcome`（返回别的类型 → `failed`，不会被当成成功）。

### 1.2 派生出的 schema 长这样

```python
REGISTRY.schema("run_epoch")
# {"schema": "vulnmap.adaptive.tool.v1", "name": "run_epoch", "group": "experiment",
#  "type": "object", "additionalProperties": False,
#  "properties": {"kind": {...enum: fuzz/replay/static/dynamic}, "seconds": {...},
#                 "workers": {...}, "timeout": {...}, "hypothesis_id": {...}},
#  "required": [], "permission": "L1", "changes": "execution",
#  "invalidations": ["execution_facts","trial_compare","coverage_baseline"],
#  "modes": ["explore"], ...}
```

`REGISTRY.tool_schema_hash` 是整张表的摘要，进 `Binding.identity.tool_schema_hash`——
**改 schema 就是新绑定**（方案 §9：工具 schema 属于绑定身份的一部分）。

---

## 2. 动作请求 / 结果：模型能说什么，系统能承诺什么

### 2.1 `ActionRequest`（模型唯一能提交的东西）

| 字段 | 含义 | 谁填 |
|---|---|---|
| `action_id` | 幂等键（`^[A-Za-z0-9][A-Za-z0-9._:-]{1,120}$`） | 模型 |
| `action` | 工具名（必须已注册） | 模型 |
| `binding` | **服务端下发的身份**，原样带回 | 服务端（模型只回带） |
| `params` | 工具参数（按派生 schema 校验） | 模型 |
| `evidence_refs` | 引用的证据哈希 | 模型 |
| `hypothesis_id` | 本动作服务的假设 | 模型 |
| `budget` | “我最多能花这么多”的上限 | 模型 |

### 2.2 `Binding`：身份不是字符串，是算出来的

`binding_hash = "b" + sha256(schema | task/campaign/epoch/job/execution |
source_sha256/harness_revision/build_id/image/benchmark/target/policy_version/tool_schema_hash)[:32]`

- `Binding.__post_init__` **重算**摘要：调用方给了一个 hash 但与内容不一致 → 直接
  `ActionRejected("forged_identity")`。“改一个字段再沿用旧 hash”这条路走不通。
- `from_dict()` 拒绝未知字段（防止夹带 `trusted=true` 之类）。
- `same_scope()` 区分 `forged_identity`（换任务）与 `cross_execution`（换执行）。

### 2.3 `ActionResult`：五态

| 状态 | 语义 | 是否算成功 | 是否登记失效 |
|---|---|---|---|
| `applied` | 动作生效，内容真的变了 | 是 | 是 |
| `noop` | 跑了，但内容没变（同内容重复提交） | 是 | 否 |
| `rejected` | 没让做（身份/权限/模式/参数/预算） | 否 | 否 |
| `failed` | 做了没成（handler 抛错、文件读不到） | 否 | 否（会话外副作用例外，见 2.4） |
| `unknown` | 事实不足（没 execution、没覆盖指标） | 否 | 否 |

`applied` / `noop` 的判定**不靠 handler 自报**：变更类工具（`MUTATING_CHANGES`）
在 handler 前后各取一次 `SessionState.fingerprint()`，内容相同即降级为 `noop` 并清空
失效登记。这样“重复提交同一个字典/种子/结束理由”不会制造假进展（§11：时间戳、
轮数变化、同一日志换摘要都不算进展）。

### 2.4 拒绝/失败不留半截变更

`Registry.invoke` 在调用 handler 前存一份 `SessionState` 快照：

| 情况 | 会话工件 | 预算 |
|---|---|---|
| `rejected`（含 handler 内可修正拒绝） | 回滚到动作前 | 不扣（没做事） |
| `failed`（handler 抛错 / 返回非 `ToolOutcome` / 未声明变更） | 回滚到动作前 | 按预留保守扣账（usage 不明，不填 0） |
| `failed` + 显式 `changed_fields` + **会话外副作用类别**（`EXTERNAL_EFFECT_CHANGES`：corpus/harness/build_identity） | **只保留声明过的会话字段**（`seeds`/`corpus` 等），没声明的字段（例如顺手改的 `dictionary`）照样回滚 | 同上，且失效照登记 |
| `unknown` | 保留（只读工具本来就不改） | 按 `budget_used` 或预留结算 |
| `applied` / `noop` | 保留 | 按 `budget_used` 或预留结算 |

语料是内容寻址、只增不改的，文件写到一半不会回退；但**会话台账**不会留下
“看起来做了一半”的工件——下一次动作读到的是干净状态。

「failed + changed_fields 不回滚」的滥用面被三层收窄：
1. **只对 `EXTERNAL_EFFECT_CHANGES`（corpus/harness/build_identity）生效**；
2. **只保留声明过的那几个会话字段**——corpus 类工具顺手改了 `dictionary`
   但只声明 `seeds`，字典照样回滚（`test_external_effect_keeps_only_declared_
   fields`，按字段判定而不是按类别一刀切）；
3. 载荷必须自洽：`materialize_seeds` 报 `materialized` 列表，测试去
   `corpus.resolve()` 核对真的存在。

回滚过的失败结果**不再对外声明** `changed_fields` / `invalidations`
（`payload.rolled_back = true`）：那份变更不存在了，声明它只会让上层去失效
一个没发生的变化（N4）。

`ActionResult.to_dict()` 固定给出：`status/ok/binding_hash/execution_id/
before_sha256/after_sha256/changed_fields/invalidations/payload/error/budget/
evidence_refs/created_at`。`error` 恒为 `{code, reason, field, hint}` 四段——
拒绝必须给**可修正**的原因，而不是一句“失败”。

---

## 3. 权限：L0–L3 与“授权是授权，不是字符串”

`grant_for(metadata)` 的判定顺序（fail-closed）：

| 层级 | 何时进入 grant | 说明 |
|---|---|---|
| L0 只读 | 恒有 | 读的是自己任务的受绑定事实 |
| L1 隔离实验 | `authorization.resolve(metadata).ok` 为真 | 显式 `authorized=true/1/yes/on`；缺失即阻断（沿用 `MISSING_POLICY=block`） |
| L2 外部/部署 | 且 `allow_external` 用同一套严格解析为真 | 字符串 `"false"` 不会因为非空而放行 |
| L3 裁决 | **永不** | 注册期就拒绝（`NEVER_EXPOSED`） |

权限判定复用 `agent/platform/authorization.py` 的解析器，不另写一套 `bool()` 判断——
F1 事故（`bool("false") is True`）不允许在工具闸门上重演。

### 3.1 受信字段

`RESERVED_PARAMS = {task_id, campaign, epoch, job_id, binding, binding_hash,
status, verdict, verified, confirmed, pass, trusted, evidence_sha256,
authorized, policy, oracle}`

两层防护，顺序固定：

1. **构造期**：`NEVER_DECLARABLE` 里的裁决字段**不允许被任何 spec 声明成参数**——
   不是“声明了再比对”，而是根本进不了工具表；
2. **运行期**：`RESERVED_PARAMS` 里其余受信字段（task_id/campaign/epoch/job_id/
   binding/binding_hash/authorized/policy/oracle）若出现在 `params` 而工具未声明，
   直接 `rejected/trusted_field_forbidden`。

`finish_research` 因此**不可能**写出 `verified=true`：schema 里没有，硬塞被第二层挡住，
想加参数在第一层就被 `ToolError` 拒掉。

唯一例外是身份参数（`get_execution_facts.execution_id`）：声明过的身份参数必须与
`ctx.binding.execution_id` 相等，否则 `rejected/cross_execution`。

### 3.2 闸门顺序与会话工具集合

`Registry.invoke` 的判定顺序固定为：

```
action 已注册 → unsupported → 身份/绑定 → 权限 → 模式 → tools_allowed
             → 参数 schema → 预算预留 → handler → 结算/失效
```

- 权限与模式排在参数校验**之前**：越权或越模式的调用方拿不到 schema 细节，
  错误信息里也不会透出“这个参数该写什么”；
- `ctx.tools_allowed is None` = 不限（自建工具表的测试/离线场景）；
  非 None 时工具必须在集合内，否则 `rejected/tool_not_allowed`
  （`make_context` 默认给全表，所以“忘了收窄”不会静默放开）。

---

## 4. 失效范围：写出来，还要被消费

`INVALIDATION_SCOPES` 是全部失效域；`CHANGE_INVALIDATIONS` 是“变更类别 → 必须失效的域”
（严格照抄方案 §8 的表格）：

| 变更类别 | 失效范围 | 可保留 |
|---|---|---|
| `seed` | `input_dedup`, `coverage_baseline` | 相同 build、历史语料原件 |
| `dictionary` | `input_dedup` | 同上 |
| `corpus` | `input_dedup`, `corpus_members` | 同上 |
| `harness` / `build_identity` | `build`, `smoke`, `coverage_baseline`, `corpus_members` | 历史 revision 与原始候选 |
| `execution` | `execution_facts`, `trial_compare`, `coverage_baseline` | 已归档旧证据（不合并 PC 位图） |
| `program` | `program_context` | 原 finding 证据 |
| `proposal` / `none` | 无 | — |

工具不允许自带一套 `invalidations`（构造期就拒绝），运行时也只接受
`INVALIDATION_SCOPES` 内的域；`applied`（以及“failed 但声明了外部变更”）的结果会把
spec 的失效域并入并登记到 `Registry` 的待消费集合，控制器必须
`consume_invalidations()` 取走并清空。**只返回不消费 = 没生效**（§8 要求控制器真正消费）。

待消费集合按 `task_id` 隔离（`_pending: dict[task_id, list]`）：
`consume_invalidations(task_id=...)` 只取该任务的，A 任务的 `input_dedup`
不会被 B 任务的控制器顺手取走；不带参数的调用仍返回全并集（便于审计/测试）。

---

## 5. 首批工具（10 个）

| 工具 | 组 | 权限 | 变更类别 | 失效范围 | 关键拒绝原因 |
|---|---|---|---|---|---|
| `get_task_facts` | read | L0 | none | — | `store_unavailable` |
| `get_execution_facts` | read | L0 | none | — | `cross_execution` / `unknown_group` |
| `read_source_window` | read | L0 | none | — | `source_path_outside_root` / `source_unreadable`(failed) / `source_too_large`(>4MiB) |
| `propose_seed_spec` | input | L1 | proposal | — | `unknown_hypothesis` / `site_mismatch` / `too_many_specs` |
| `materialize_seeds` | input | L1 | corpus | `input_dedup`,`corpus_members` | `unknown_seed_spec` / `corpus_unavailable` |
| `set_dictionary` | input | L1 | dictionary | `input_dedup` | `invalid_params`（非 ASCII / 超长 / 超量） |
| `run_epoch` | experiment | L1 | execution | `execution_facts`,`trial_compare`,`coverage_baseline` | `mode_not_allowed` / `executor_unavailable` / `budget_exceeded` |
| `replay_input` | experiment | L1 | execution | 同上 | `unknown_input` / `mode_not_allowed` |
| `compare_trials` | experiment | L0 | none | — | `unknown_trial` / `invalid_params` |
| `finish_research` | close | L1 | proposal | — | `trusted_field_forbidden` / `invalid_params` |

### 5.1 探索与独立验证分开（T14）

| 工具 | 允许模式 | 理由 |
|---|---|---|
| `run_epoch` | 仅 `explore` | 研究 Agent 不能跑探索当验证 |
| `replay_input` | 仅 `verify` | 重放是验证侧动作，需要独立上下文 |
| 其余 | `explore` / `verify` / 空 | 只读或收口 |

模式不匹配 → `rejected/mode_not_allowed`，并在 hint 里写明“探索与独立验证必须分开”。

### 5.2 隔离执行靠注入，不靠假装

`run_epoch` / `replay_input` 通过 `ctx.exec_runner` 调用隔离 worker。没绑定 worker 时是
**可修正的拒绝**（`executor_unavailable`），绝不返还一个编造的成功结果。
`tools.EXEC_KINDS` 与 `executors.EXECUTORS` 的一致性由测试对账，
避免“工具表里能选 qemu、执行器里根本没有”。

`run_epoch` 把执行反馈归一成 trial：

```python
{"trial_id": "t-001", "kind": "fuzz", "mode": "explore", "build_id": "...",
 "execution_id": "...", "outcome": "no_repro", "candidates": 0,
 "metrics": {"coverage_status": "...", "covered": <int|unknown>,
             "new_coverage_bits": <int|unknown>, "execs": ..., "crashes": ...},
 "unknowns": ["covered", "execs", ...], "budget_used": {...}}
```

反馈里没给的指标进 `unknowns`，不填 0；`compare_trials` 只在**同一 build** 且两侧都有
读数时给 `delta`，其余一律 `unknown` 并把 `verdict` 固定为 `not_evaluated`
（对照不是裁决）。

### 5.3 语料写入走既有 `CorpusStore`

`materialize_seeds` 用 `canonical_json({hypothesis_id, site_id, spec_id, index,
constraints})` 生成确定字节，交给 `CorpusStore.add(..., hypothesis_id=..., site_id=...,
source=f"seed_spec:{spec_id}")`：内容寻址、可反查父假设、重复内容只登记不落新文件
（全部重复 → `noop`）。`replay_input` 只接受 `corpus.resolve()` 得到的哈希——
**没登记过的字节不许重放**。

---

## 6. 可信执行快照（TrustedExecutionSnapshot）

### 6.1 七组事实

| 组 | 字段（节选） | 默认来源 |
|---|---|---|
| identity | task/campaign/epoch/job/execution、plan_sha256、source_sha256、harness_revision、build_id、image、policy_version、binding_hash | declared |
| config | engine、kind_override、sanitizer、command、isolation、network、workdir、tools_allowed、budget_declared | declared |
| program | index_sha256、source_root、entry_points、functions、call_sites、formats、source_count、truncated、notes | observed |
| input | corpus_version/hash/build、corpus_comparable、input_consumed、**program_started / input_processed / checkpoint_reached**、target_reached（= checkpoint_reached 的兼容别名）、observation_source、seeds、dictionary_tokens、format | observed |
| coverage | status、metric_kind、baseline_id、covered/uncovered/planned、delta、sampling、truncated、comparable、error、evidence_sha256 | observed |
| fault | outcome、setup_error、timeout、cancelled、budget_stopped、sanitizer_type、candidates、candidate_signature、log_ref、error | observed |
| budget | limits、remaining_{seconds,execs,tokens,turns,usd}、used_*、violations、tools_allowed、denials | declared |

来源四分类（`observed/declared/synthetic/assumed`）逐组记录在 `sources` 里；
`assumed` 槽位留给上层模型假设，本模块永不产出——**快照自身不冒充“模型知道”**。

“有观测”用**实质字段**判定（`OBSERVED_FIELDS`），**排除合成标签**：
`input.observation_source`、`fault.*_detail`、`coverage.status/sampling/error`
都是“我怎么知道的”，不是“知道了什么”。只有一个空 `exec.finished`
（`{"exec_id": ...}`）时 `observed() == False`，`status` 仍是 `unknown`。

`status`（快照整体）只有 **看到 `exec.finished` 且执行侧有实质观测**才是 `applied`：

| 情形 | `status` | `complete` |
|---|---|---|
| 只有 `exec.started`（还在跑） | `unknown` | false |
| 有 finish + outcome/统计 | `applied` | true |
| 有 finish 但所有观测都缺失 | `unknown` | true |
| 完全没有 execution | `unknown` | false |

“正在跑”不能被上层读成“跑过并得到结论”，所以 `status` 依赖 `complete`；
而已经结束的执行至少有 `fault.outcome`，不会被误判成 `unknown`。

### 6.2 unknown 的三条硬规则

1. **缺数据 → unknown**：字段不存在、值为空串、空集合都落成 `unknown` 并登记到
   `unknowns`（点分路径，如 `coverage.delta`）。真的 0 保持 0（例如
   `fault.candidates=0` 是“确实 0 个候选”）。
2. **覆盖不可用 ≠ 覆盖为 0**：`coverage.status == "unavailable"` 时
   `covered/uncovered/planned/metric_kind` 全为 `unknown`，只有 `status` 与 `error`
   是观测值。**光有 `status == "complete"` 不算有指标**：必须真的带了读数端口
   （`COVERAGE_PORTS` 之一），否则 `metric_kind/covered/truncated/comparable`
   一律 `unknown`——`{"status":"complete","baseline_id":"x"}` 这种“声称完成了但
   什么都没报”的 payload 不能推出任何可比结论。
3. **覆盖读数推不出目标命中**：`target_reached` 只由 `checkpoint_reached`
   派生（见 `docs/V3-TARGET-SEMANTICS.md`）。`new_coverage_bits` 无论 0 还是
   >0、`execs` 无论多少、崩溃多少个，都**不能**把 `checkpoint_reached` 变成
   `true`/`false`：没有显式探针就是 `unknown`，并记
   `observation_source="no_checkpoint_probe"`。目标语义三段
   （`program_started` / `input_processed` / `checkpoint_reached`）各自三值、
   互不派生；`execs>0` 只能证明 `program_started=true`。

派生三值 `coverage.comparable`：`metric_kind` 或 `baseline_id` 缺一 → `unknown`
（没有基线就不宣称可比）；有截断 → `false`；齐备 → `true`。标记为 `synthetic`。

`budget.remaining_usd` 恒为 `unknown`——没有价格表就不写金额（§11）。

### 6.3 游标与跨 execution 拒绝（T09）

- 快照带 `Cursor(execution_id, seq)`；`collect(cursor=...)` 在三处拒绝拼接：
  1. `cursor.execution_id != execution_id` → `SnapshotError(cross_execution)`；
  2. 用某个 execution 的游标去读另一个 execution → 同上；
  3. `snapshot.merge(other)` 且 `other.execution_id != self.execution_id` → 同上。
- 游标只能前进（`advance()` 回退即报错）；`cursor.seq` 之后没有新事件时
  `events=0`，但**已有事实仍然是已知的**——`events=0` 不等于“没有事实”。
- 窗口里出现别的 execution 的事件时，只计数（`foreign_executions`），不并入事实；
  完成标志 `complete` 只在看到同 execution 的 `exec.finished` 时为真，否则是部分快照。
- 工具层再拦一次：`get_execution_facts(execution_id=...)` 与绑定不一致 → `rejected`。

### 6.4 字段名只在执行器声明一次

`executors.execution_fact_view(start, finish)` 是**只读纯函数**：不写事件、不改状态、
不产证据，把 `exec.started` / `exec.finished` 的 payload 归一成事实视图，缺失字段
一律 `None`（不是 0/False），并用 `present` / `flags` 区分：
- `error=None`（观测到“没有 error”）vs 压根没有 `error` 字段；
- `fuzz.stopped` 存在与否决定 `timeout/cancelled/budget_stopped` 能不能算。

快照通过 `_exec_view()` 优先用这个钩子，钩子不可用才退回最小视图（纯离线单模块仍可用）。
`EXEC_FACT_FIELDS` 声明字段名单，新增执行事件字段时只改这一处。

---

## 7. 测试（57 项）

| 组 | 用例 | 断言要点 |
|---|---|---|
| schema 同源 | `test_tool_table_schema_is_derived_from_handler` | 每个 spec 的 properties/required 与 handler 签名逐项相等；失效域 == `CHANGE_INVALIDATIONS[changes]` |
| | `test_handler_signature_drift_fails_at_registration` | 漂移/缺 ctx/`**kwargs` → 构造期 `ToolError` |
| | `test_invalidations_and_permission_must_be_declared_once` | 自写失效域、L3、只读计费 → `ToolError` |
| | `test_tool_schema_hash_tracks_schema_changes` | 改 schema → hash 变；同 schema → 稳定 |
| | `test_exec_kinds_mirror_installed_executors` | `EXEC_KINDS == executors.EXECUTORS` |
| 伪造身份 | `test_forged_identity_is_rejected[task/epoch/hash]` | 三种改法全部 `rejected`，payload 空、无失效 |
| | `test_trusted_fields_cannot_be_written_by_model` | `verified`/`status` → `trusted_field_forbidden`，`session.finished` 仍 None |
| | `test_permission_gate_follows_authorization` | 未授权 → 只有 L0；L1 拒绝；L2 需 `allow_external` |
| | `test_missing_identity_is_rejected` | 不带 binding → `missing_identity` |
| | `test_binding_rejects_smuggled_identity_parts` | 夹带 `identity.trusted` / 未声明字段 → 拒绝 |
| | `test_binding_identity_covers_tool_schema` | 换工具表 → 新 `binding_hash`，旧绑定被拒 |
| unknown | `test_unknown_is_not_zero_when_coverage_unavailable` | `covered/uncovered/metric_kind/delta/comparable` 全 unknown |
| | `test_zero_coverage_bits_does_not_mean_target_missing` | `bits=0` 与 `bits>0` 都不改 `checkpoint_reached`（恒 unknown） |
| 目标语义 | `tests/test_v3_target_semantics.py`（16 条） | 三段事实拆分、`checkpoint_reached` 唯一来源、三组报告互不相同 |
| | `test_no_execution_yet_reports_unknown` | 工具返回 `status=unknown` + `no_execution_facts` |
| | `test_snapshot_marks_sources_and_unknown_paths` | 来源分类正确；iso/network/command 是 unknown 而非编造 |
| 跨 execution | `test_cross_execution_cursor_is_rejected` | 续读/合并/工具参数三条路径全拒 |
| | `test_cursor_only_moves_forward` | 回退报错；无新事件不等於无事实 |
| invalidations | `test_invalidations_are_declared_consumed_and_idempotent` | 登记 → 消费清空；重复提交 `noop` 且不再登记 |
| | `test_materialize_seeds_writes_corpus_and_invalidates` | 真写语料、可由内容反查父假设、重复 `noop` |
| | `test_rejected_actions_leave_no_invalidations` | 拒绝不产生失效登记 |
| 参数/模式 | `test_param_validation_is_uniform` | 7 类非法参数都给 `invalid_params` + 正确 `field` |
| | `test_unknown_tool_and_unsupported_are_rejected` | 未注册/未接通 → `rejected` |
| | `test_explore_and_verify_modes_are_separated` | 探索态跑 `replay_input`、验证态跑 `run_epoch` 均拒 |
| 回滚 | `test_failed_handler_rolls_back_and_charges` | 抛错/读后拒绝都回滚工件；崩溃按预留扣账、拒绝不扣 |
| 预算 | `test_budget_hook_blocks_and_settles` | 预留不足即拒（worker 未被调用）；结算记账；请求预算只能当上限 |
| | `test_handler_level_rejections_have_reasons` | 6 类 handler 拒绝都有 code/reason/hint |
| | `test_executor_absence_is_a_rejection_not_a_fake_run` | 无 worker → 拒绝，`trials` 仍空 |
| 事实/对照 | `test_task_facts_are_observed_counts` | 计数来自真实查询；用量来自事件流（1.5s） |
| | `test_compare_trials_refuses_cross_build_delta` | 跨 build → `comparable=false`、`delta=unknown`、`verdict=not_evaluated` |
| | `test_finish_research_only_records_reason` | 返回值集合固定，无裁决字段 |
| 形状/钩子 | `test_action_result_shape_and_five_states` | 五态语义与 `ok/is_unknown` 一致；非法状态 `ToolError` |
| | `test_fact_view_hook_matches_snapshot_inputs` | 钩子字段齐全、快照确实用同一视图 |
| | `test_tool_context_budget_port_matches_task_budget` | 预算端与任务预算同源 |
| 复审回归 | `test_complete_status_without_metric_is_unknown` | status=complete 但无读数 → 指标/截断/可比全 unknown |
| | `test_running_execution_has_no_result_status` | 只有 start → `status=unknown`、`complete=false`、观测来源 unknown |
| | `test_untracked_denials_are_unknown_not_empty` | 未追踪 → unknown；追踪过且空 → `[]` |
| | `test_tools_allowed_is_enforced` | 集合外的工具 → `tool_not_allowed`，无副作用 |
| | `test_partial_corpus_write_is_failed_not_rejected` | 部分写入 → `failed` + 磁盘/台账一致 + `corpus_members` 失效 |
| | `test_failed_with_changes_only_spares_external_effects` | 会话内变更自报 changed_fields 仍回滚、不登记失效 |
| | `test_default_values_must_match_handler_signature` | 默认值两套口径 → 构造期 `ToolError` |
| | `test_adjudication_fields_can_never_be_declared` | 裁决字段不得声明为参数 |
| | `test_merge_refuses_cross_task` | 跨任务 `cross_execution`、跨绑定 `binding_mismatch` |
| 复审回归（二轮） | `test_empty_finish_event_is_not_a_conclusion` | 空 finish → `complete=true` 但 `observed=false`/`status=unknown` |
| | `test_synthetic_labels_alone_do_not_upgrade_status` | 只有标签字段不抬状态；coverage 仍 unknown |
| | `test_rolled_back_failure_declares_nothing` | 回滚后 `changed_fields/invalidations` 为空 + `payload.rolled_back` |
| | `test_external_effect_keeps_only_declared_fields` | 只保留声明过的会话字段，顺手改的字典回滚 |
| 正向 | `test_source_window_is_bounded_and_hashed` | 行号/截断/哈希正确；超宽 `max_lines` 拒绝 |
| | `test_execution_facts_group_filter` | 组过滤生效；未知组 `unknown_group` |
| | `test_run_epoch_records_unknown_metrics` | 反馈缺指标 → trial 记 unknown |
| | `test_verify_mode_replays_registered_input` | 验证态重放已登记输入，`reproduced=true`，可反查父假设 |

---

## 8. 仍然没做（留给 P2b / P3）

1. ~~**workspace/revision（V3-007）**~~：已在 P2b 落地
   [`V3-P2B-SESSION.md`](V3-P2B-SESSION.md) §2/§3——overlay 副本、manifest、diff、
   真实 build/smoke 与回退。`write_harness_candidate` / `edit_generator` /
   `build_candidate` / `smoke_candidate` 四个“测试工件”工具**仍未注册**：
   P2b 把 stage/build/smoke 做成控制器内部、要求 L1 的任务副本操作，
   加工具会改 `tool_schema_hash` 与 P2a 工具表口径，留给 P3 与预算/授权一起接。
2. ~~**session/controller（V3-008）**~~：已在 P2b 落地
   [`V3-P2B-SESSION.md`](V3-P2B-SESSION.md) §4/§5——Context/Seed/Diagnose、
   确定性慢循环、`consume_invalidations()` 的真实消费者、相同事实有限停止。
3. **collector 补字段**：`isolation` / `network` / `sanitizer` / `cmd` 目前事件里没有，
   快照如实报 `unknown`。P2b 由 worker 在 `exec.started` 里补上后，快照自动跟着变
   （只改 `executors.execution_fact_view` 一处）。
4. **金额预算**：`DeclaredBudget` 支持 `usd` 键，但平台 `Budget` 没有金额字段，
   `remaining_usd` 恒为 `unknown`——没有价格表就不谎称成本受控。
5. **经验库/对照实验（P4）**：A–E 组实验矩阵与报告未在本批范围内。
6. **P0 环境缺口**：8102 连接与三类真实 runner 的问题不属于 P2a，本次未触碰，
   也未据此宣称任何线上状态。

---

## 9. 数字与树绑定

本文档里的测试数字是**在 P2a 改动落盘后实测**的结果，不是长期配额：

| 运行 | 结果 | 说明 |
|---|---|---|
| `pytest tests/test_v3_p2_contracts.py -q` | 53 passed | 本批新增用例 |
| `pytest tests/test_v3_p1_seed.py -q` | 8 passed | P1 未回归 |
| `pytest -q`（全量） | 1341 passed / 8 skipped / 0 failed / 0 error | 约 97 s |

本仓库按 `docs/V3-P0-BASELINE.md` 的约定允许多条执行线并行改同一棵树：
本次 P2a 期间 `agent/platform/adaptive/` 下已出现 P2b 的
`workspace.py` / `revision.py` / `session.py` / `controller.py` / `policy.py`
（另一条执行线的产物，本批未触碰、未被本批测试依赖），
`adaptive/__init__.py` 也已由该线追加导出。树再变时上述数字即失效，必须重跑，
不能把这里的通过数当成“永远成立”的验收凭证。

本批**未**做的事项见 §8；下一批（P2b：受限副本与修订、研究会话与慢循环）
在此基础上接 `ToolSpec` 的新工具（`write_harness_candidate` / `edit_generator` /
`build_candidate` / `smoke_candidate`），不需要改本批契约。

---

## 10. 复审记录

两轮独立复审（只读，探针只写 `/tmp`，未改仓库），结论与处置：

### 10.1 第一轮：FAIL（4 阻断 + 15 非阻断）

| 编号 | 问题 | 处置 |
|---|---|---|
| B1 | `coverage.status="complete"` 但无任何读数时，`metric_kind/truncated/comparable` 被推断出来 | 改 `COVERAGE_PORTS` 判定 + `covered` 进可比性判据 |
| B2 | 只有 `exec.started` 却报 `applied`，唯一非 unknown 值是合成标签 | `status` 依赖 `complete`，观测来源不再编造 |
| B3 | `denials`/`tools_allowed` 伪装成“追踪过且为空” | `None`=未追踪（unknown）；新增 `tool_not_allowed` 闸门 |
| B4 | `materialize_seeds` 部分写入却报 `rejected`，台账与磁盘不一致 | 改 `failed` + 声明变更 + 登记 `corpus_members` |

同轮一并修：默认值与 handler 签名同源对账、裁决字段禁止声明为参数
（`NEVER_DECLARABLE`）、`merge` 跨任务/跨绑定拒绝、闸门顺序（权限先于参数）、
失效按 task 隔离、源码读取 4 MiB 上限。

### 10.2 第二轮：PASS-WITH-NOTES（0 阻断）

定版 md5：`contracts.py 532131ca` / `snapshot.py 0831cd8d` / `tools.py e31a5068` /
`tests/test_v3_p2_contracts.py 42682751`（复审复核 B1–B4 全部闭合，含真值路径未被
误杀、跨 execution 的 finish 不污染别的 execution）。

| 编号 | 问题 | 处置 |
|---|---|---|
| N1 | `status` 对“空 finish”过度乐观（合成标签让守卫恒真） | 新增 `observed()` + `OBSERVED_FIELDS`（排除标签字段）；空 finish → `unknown` |
| N2 | 免回滚按**工具类别**整块放行，corpus 类工具可顺手改字典 | 改为**按字段**：只保留 `changed_fields` 声明过的那几个会话字段 |
| N3 | corpus 类工具“部分写入后 raise 拒绝”仍无条件回滚 | `materialize_seeds` 已改为返回 `failed`，不再抛拒绝；规则本身按 N2 收窄 |
| N4 | 回滚后的 failed 仍带 `invalidations` | 回滚分支清空 `changed_fields/invalidations`，`payload.rolled_back=true` |
| N5 | `controller.py` 消费失效未带 `task_id` | P2b 文件，**本批未改**（该线每个 controller 自建 Registry，当前无跨任务窃取） |
| N6 | 全量用例依赖全局 `REGISTRY` 的 pending 顺序 | 加模块级 autouse fixture，每例前后清空 |
| N7 | `tests/test_verify_no_falsepass.py` 直接写仓库内 `workspace/` | 与本批无关（既有文件），**未改**；已知全量跑会动工作树 |
| N8 | `session.py` 把 running 诊断成 no_execution | P2b 文件，**本批未改** |

N5/N7/N8 属于另一条执行线或更早的既有文件，本批只登记、不改动——避免与并行
执行线的写入互相覆盖。它们都不构成 P2a 的阻断项。
