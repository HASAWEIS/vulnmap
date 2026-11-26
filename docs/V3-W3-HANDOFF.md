# V3 第 3 周：原始执行证据 → 待复核项 → 独立复核者的交接

> 适用范围：`agent/platform/adaptive/handoff.py`（新增）、`adaptive/controller.py`
> （只加验收闸）、`adaptive/cli.py`（只加跑完之后的自动开项与研究报的 `handoff` 段）、
> `agent/platform/verify.py`（只加只读钩子）、
> `agent/platform/store.py`（只加两张表与读写方法）、
> `agent/platform/casepack.py` / `agent/platform/review.py`（只加交接接入）、
> `tests/test_v3_week3_handoff.py`、本文。
> 本文是这套口径的**唯一出处**；第 1 周目标三态见 `docs/V3-TARGET-SEMANTICS.md`，
> 第 2 周配置口径见 `docs/V3-W2-CONFIG.md`，三套字段互不冒充。
> **不动**：`verify` 的判据与 `benchmark_policy`、执行器的执行语义、对外 API 形态。

---

## 0. 这一周解决什么

第 1 周把「跑过 / 输入被处理 / 检查点命中」拆成三段三值事实，第 2 周把「配置改了」
与「配置生效了」拆开。但**证据链本身**仍然可以是一条口述：

| 现象 | 后果 |
|---|---|
| 执行证据只有执行器的返回值/模型转述 | 「复核过的那次执行」与「执行器真正跑完的那次」之间没有对账手段：没有 `run_id`/`execution_id`/`evidence_sha256` 三段同一身份，任何一次转述都能冒充任意一次执行 |
| 复核入口吃的是候选摘要 | 复核者核的是模型写的摘要，摘要说得圆就「通过」——复核者看到的不是原始记录，而是被加工过的说法 |
| 报告把未核验写成结论 | 报告里没有「未核验」这一档：`pending`/缺证据的项与已验证项同一张表、同一种排版，包级 `benchmark_verified` 只数「有没有」 |

本周加三条硬约束：

1. **三段同一身份**：`run_id` / `execution_id` / `evidence_sha256` 全部由**原始
   记录本体**复算得出，调用方只能校验、不能声明；
2. **复核者只读原始记录**：`IndependentVerifier` 不读 `research.json`、候选摘要、
   模型自述或任何 `summary/claim/conclusion` 字段；递摘要即
   `model_summary_not_accepted`；
3. **未核验只标状态**：待复核项落库即 `pending`，只有复核者判 `accepted` 才进报告
   的可追溯结论；`pending` / `needs_evidence` 如实标注、不算结论、不进
   `benchmark_verified`。

一句话：**一次执行只有一个身份，复核者只看原始记录，没核验的项不许写成结论。**

---

## 1. 三段同一身份（`run_id` / `execution_id` / `evidence_sha256`）

```python
RAW_SCHEMA      = "vulnmap.adaptive.raw_execution.v1"
SCHEMA          = "vulnmap.adaptive.handoff.v1"
ITEM_SCHEMA     = "vulnmap.adaptive.review_item.v1"
VERDICT_SCHEMA  = "vulnmap.adaptive.handoff_verdict.v1"
SCHEMA_VERSION  = 1
RAW_KIND        = "raw_execution"        # 封存记录在证据库里的 kind
RAW_SOURCES     = ("exec.finished",)     # 只有这类事件能当原始来源
RUN_ID          = re.compile(r"^run-[0-9a-f]{16}$")
```

| 身份 | 从哪来 | 谁算的 | 不成立时 |
|---|---|---|---|
| `execution_id` | 执行侧写在 `exec.started` / `exec.finished` 的 `payload.exec_id` | 执行侧（`EventBus.emit`）写入，交接侧只读 | `execution_not_found:{id}`（没有 `exec.finished`）、`ambiguous_execution:{id}`（多条 `exec.finished`——不猜哪条是真的） |
| `run_id` | `"run-" + sha256(canonical_json({"task_id","execution_id","plan_sha256"}))[:16]` | `derive_run_id()` 复算 | 调用方传了 `run_id` 且与派生值不同 → `run_id_mismatch:given=… derived=…` |
| `evidence_sha256` | 封存记录**本体**的 sha256 | `RawRecord.compute_sha256()` | 盘上字节哈希 ≠ 声明 → `evidence_hash_mismatch`；序列化出第二套口径 → `sealed_hash_mismatch` |

三条不变量：

- `run_id` **确定性派生**，同一 `(task_id, execution_id, plan_sha256)` 永远同一个值；
  调用方不能自选 run 身份，只能拿派生值来对账；
- `execution_id` 是**执行侧**写的那个 `exec_id`，不是交接侧生成的；没有
  `exec.finished` 就没有执行证据（`exec.started` 单独不算）；
- `evidence_sha256` 是**本体**的哈希，本体不含自身哈希字段。

### 1.1 自指哈希：盘上字节哈希 == `evidence_sha256`（与 git commit 同构）

自指哈希写不进自己的内容里。所以：

| 产物 | 含 `evidence_sha256` 字段吗 | 用途 |
|---|---|---|
| `RawRecord.body()` | **不含**（`schema`/`schema_version`/`task_id`/`run_id`/`execution_id`/`plan_sha256`/`kind`/`source_evidence_sha256`/`source_event_seq`/`source_event_type`/`revision_id`/`build_id`/`policy_version`/`recorded_by`/`sealed_at`/`payload`） | 取哈希的输入 |
| `RawRecord.bytes()` | **不含** = `canonical_json(body()).encode("utf-8")` | 落盘字节 |
| `RawRecord.to_dict()` | **含**（补上 `evidence_sha256`） | 记录文档 |

于是「文件哈希」就是 `evidence_sha256`：`sha256(路径.read_bytes()) == evidence_sha256`
（`seal_execution` 落盘后立刻用 `ref.sha256` 复验，不等复核者来发现）。
`RawRecord.from_dict()` 读回时也复算一遍：声明值与复算值不同 →
`raw_record_sha_mismatch`。

---

## 2. 封存与只读读取

### 2.1 `seal_execution()`

```python
seal_execution(store, task_id, *, execution_id, evidence_root=None,
               run_id="", revision_id="", build_id="", policy_version="",
               recorded_by="executor", event_seq=0) -> RawRecord
```

顺序（任一步不成立就报错，**不补一条「看起来跑过了」的记录**）：

| 步 | 动作 | 失败码 |
|---|---|---|
| 1 | 扫事件流，按 `payload.exec_id` 收 `exec.started` / `exec.finished`；`exec.finished` 必须恰好 1 条（给了 `event_seq` 就只认那一条——同一 `exec_id` 有多条 finish 时必须由调用方点名） | `execution_not_found` / `ambiguous_execution` |
| 2 | 取 `exec.finished.payload.evidence_sha256`，必须 64 位 hex | `evidence_missing:{execution_id}` |
| 3 | 到证据台账定位该 sha 的落地路径 | `evidence_not_in_store:{sha[:12]}` |
| 4 | 文件必须存在 | `evidence_file_missing:{sha[:12]}` |
| 5 | 盘上字节 sha256 必须等于声明值 | `evidence_hash_mismatch:{sha[:12]}` |
| 6 | `run_id = derive_run_id(task_id, execution_id, plan_sha256)`；传了 `run_id` 就必须相等 | `run_id_mismatch` |
| 7 | 组装 `RawRecord`（`revision_id` 缺省取 `payload.build.harness`，再缺省取 `exec.started.harness_revision`；`build_id` 取 `payload.build.build_id`；`policy_version` 取 `exec.started.policy_version`；`sealed_at = now()`；`payload = {"start": <start 事件 payload>, "finish": <finish 事件 payload>}`） | `raw record: …`（缺字段/坏 run_id/坏 hex/`source_event_seq<=0`） |
| 8 | `record.validate()` → 算 `evidence_sha256` → 封成不可变记录，并复验哈希稳定 | `sealed record hash is not stable` |
| 9 | `EvidenceStore.put_bytes(task_id, RAW_KIND, sealed.bytes(), source_stage="RUNNING")`，并断言 `ref.sha256 == sealed.evidence_sha256` | `sealed_hash_mismatch:computed=… stored=…` |

`record.validate()` 只校验**身份与形状**（必填字段、`run_id` 形如
`run-<16hex>`、两个哈希是 64 位 hex、`source_event_seq>0`）；原始记录里出现模型加工
字段（`summary`/`claim`/`conclusion` 等）**不在解析期拒收**——那由复核者的
`raw_source_only` 判成 `rejected`（§4.5）。

封存入口自己也产不出这些字段：`payload` 只照抄两条事件的 payload，记录其余字段
全部由事件与入参算出。

### 2.2 `open_pending()`

```python
open_pending(store, task_id, *, execution_id, evidence_root=None,
             revision_id="", build_id="", policy_version="", run_id="",
             event_seq=0) -> dict
```

封存（§2.1）后开一条待复核项：

- 先按 `(run_id, execution_id, evidence_sha256)` 三段查已有项，命中就**原样返回**
  （幂等：同一次执行不会开出第二条项；库上另有唯一索引
  `idx_review_items_triple` 兜底）；
- 否则分配 `item_id = HI1, HI2, …`（`_next_item_id`，取最小可用号），
  `status="pending"`，`source="exec.finished"`，`detail` 记
  `plan_sha256` / `source_evidence_sha256` / `source_event_seq` / `policy_version`。

### 2.3 `RawRecordReader`（只读）

```python
reader = RawRecordReader(store, evidence_root=None, task_id="")
reader.path_of(sha256_value, task_id="") -> Path      # 只定位，不读内容
reader.read(sha256_value, *, task_id="")   -> RawRecord
```

`read()` 的七道校验，全部报错、**不返回半份记录**：

| 校验 | 失败码 |
|---|---|
| sha 形如 64 位 hex | `evidence_sha256 must be 64 hex chars: …` |
| 台账里有这条 sha | `evidence_not_in_store:{sha[:12]}` |
| 盘上有这个文件 | `evidence_file_missing:{sha[:12]}` |
| 盘上字节哈希 == sha | `evidence_hash_mismatch:{sha[:12]}` |
| 能解析成 JSON 对象 | `raw_record_not_json:{sha[:12]} (JSONDecodeError)` |
| 本体复算 == sha | `raw_record_sha_mismatch:{sha[:12]}` |
| 记录属于请求的任务 | `wrong_task:record=… request=…` |

### 2.4 事件绑定（`event_binding`）

源证据必须真的挂在**同一条** `exec.finished` 上，不是记录自己声明的。

事件视图**只**从验证侧的只读钩子取：`agent.platform.verify.raw_execution_refs(store,
task_id, execution_id=…)`；`_event_binding()` 不另写一套事件字段读法。三样都要对上：

| 比对项 | 不一致时 |
|---|---|
| `ref["event_seq"] == record.source_event_seq` | 不匹配 → 该 ref 跳过；全跳过 → `raw_event_missing:{execution_id}#{seq}` |
| `ref["evidence_sha256"] == record.source_evidence_sha256` | 同上 |
| `ref["plan_sha256"] == record.plan_sha256` | 同上 |
| `ref["registered"] and ref["hash_ok"]` | 同上（证据登记在台账、盘上哈希复算通过） |

只读 + 内容寻址：证据按 sha256 存，封存记录本身也是一个 sha256 blob
（`kind="raw_execution"`），复核时不需要、也不允许再跑一次执行器。

### 2.5 自动入口：`run_research()` 跑完就开项

```python
_open_handoff_items(store, task_id, *, evidence_root, after_seq=0,
                    revision_id="", policy_version="") -> dict
```

`adaptive/cli.run_research()` 在控制器跑完后（写报告之前）调一次，把**本次运行**真跑
出来的执行封成待复核项：

| 规则 | 代码事实 |
|---|---|
| 只看本次运行 | 控制器启动前记事件水位 `handoff_watermark = list_events(task_id)[-1]["seq"]`，扫描时 `list_events(task_id, after_seq=handoff_watermark)`——历史执行不会被重开一遍 |
| 只认真执行 | 只扫 `event_type == "exec.finished"` 且 `payload.exec_id` 非空的事件 |
| 同一 `exec_id` 多条 finish | 以**最后一条**为准（append-only 覆盖），并把该条 `event_seq` **显式**传给封存器；`ambiguous_execution` 只在没点名（`event_seq=0`）且不唯一时抛 |
| 封存失败不伪造 | `evidence_not_in_store` / `evidence_file_missing` / `evidence_hash_mismatch` / `execution_not_found` 等 `HandoffError` 记进 `unsealed`，**不补一条"看起来跑过了"的记录**，也不改任何结论 |
| 归因 | `revision_id = result.revisions[-1]`（本轮最后一个 revision，没有就是 `""`），`policy_version="v3-w3"` |

返回块（写进研究报告的 `handoff` 段）：

```python
{"schema": "vulnmap.adaptive.handoff_queue.v1",
 "opened": <成功开项数>, "skipped": <跳过数>,
 "items":  [{"item_id","run_id","execution_id","evidence_sha256","status"}],
 "unsealed": [{"execution_id", "reason"}],   # reason 是原样的 HandoffError 文案
 "note": "封存成功只代表『有一条可复核的原始记录』，不代表已验证；复核结论由独立复核者给出"}
```

联动：

- 研究报告（`vulnmap.research.run.v1`）新增 `handoff` 段 = 上面这块（没有执行时是
  `{"opened":0,"skipped":0,"items":[],"unsealed":[]}`）；
- `research.mapped` 事件 payload 带 `handoff_items`（**项 id 列表**）与
  `handoff_skipped`（**跳过数**，`int`；未封存的 `{execution_id, reason}` 明细在报告
  `handoff.unsealed` 里）——报告与事件说的是同一批记录，事件里不重复整份明细；
- 开项只是「排队」：`status` 一律 `pending`，没有任何裁决字段。

---

## 3. 待复核项：一张队列表 + 一张定性表

### 3.1 `review_items`（`store.SCHEMA_W3`）

| 列 | 类型 | 说明 |
|---|---|---|
| `item_id` | TEXT PRIMARY KEY | `HI1…`；落库时加 `task_id::` 前缀（与候选同一命名空间），读出时还原 |
| `task_id` | TEXT | 所属任务 |
| `run_id` | TEXT | §1 派生身份 |
| `execution_id` | TEXT | 执行侧 `exec_id` |
| `evidence_sha256` | TEXT | 封存记录本体哈希 |
| `kind` | TEXT | 执行类别（`payload.kind`） |
| `status` | TEXT DEFAULT `'pending'` | 见 §3.3 状态机 |
| `revision_id` / `build_id` | TEXT | 该次执行对应的 revision / build |
| `source` | TEXT | 只允许 `exec.finished` |
| `verdict_id` | TEXT | 落定后指向 `handoff_verdicts` |
| `detail_json` | TEXT | `plan_sha256` / `source_evidence_sha256` / `source_event_seq` / `policy_version` |
| `created_at` / `updated_at` | TEXT | 时间戳 |

索引：`idx_review_items_triple`（`task_id`,`run_id`,`execution_id`,`evidence_sha256`
**唯一**）、`idx_review_items_status`（`task_id`,`status`）。

### 3.2 `handoff_verdicts`（只定性，不写 `verified` / `confirmed`）

| 列 | 说明 |
|---|---|
| `verdict_id` | `HV1…`（落库方分配，复核者给的定性本身不带编号） |
| `item_id` / `task_id` / `run_id` / `execution_id` / `evidence_sha256` | 三方身份回填，和项一一对应 |
| `status` | `accepted` / `rejected` / `needs_evidence`（**不含** `pending`） |
| `reason` | `all checks passed` 或 blockers 去重后 `; ` 连接 |
| `verifier` | `independent-verifier.v1` |
| `checks_json` | §4 十项检查的布尔结果 |
| `blockers_json` | 拒绝码列表（§9.5） |
| `detail_json` | 复核者读到的事实（`plan_sha256` / `kind` / `revision_id` / `build_id` / `policy_version` / `source_event_seq` / `source_evidence_sha256` / `expected_revision` / `sealed_at`，以及 `model_summary_accepted: False`） |
| `created_at` | 时间戳 |

`store.HANDOFF_VERDICT_STATUSES = ("accepted","rejected","needs_evidence")`，
`store.REVIEW_ITEM_STATUSES = ("pending","accepted","rejected","needs_evidence")`
（与 `handoff.STATUSES` / `handoff.TERMINAL_STATUSES` 对账，有测试守着）。

### 3.3 状态机

```
              review_item()                review_item()
  ┌────────┐ ─────────────► accepted   ┌──────────────┐ ──────────► accepted
  │pending │                          │needs_evidence│
  └────────┘ ─────────────► rejected   └──────────────┘ ──────────► rejected
        ▲                                         │
        │  open_pending() 是唯一入口               └─ 补材料后重新封存 → 新项 pending
```

| 规则 | 代码 | 报错 |
|---|---|---|
| `pending` 是**唯一入口态** | `open_pending()` 只写 `status="pending"` | — |
| 只有 `pending` / `needs_evidence` 可复核 | `review_item()` 前置检查 | `review_item_closed:{item_id} status=…`（已定性的项不重复复核；补证据请重新封存） |
| 项不存在 | `review_item()` | `review_item_not_found:{task_id}/{item_id}` |
| 复核结论必须是三态之一 | `Verdict.validate()` / `save_handoff_verdict()` | `status must be one of ("accepted","rejected","needs_evidence")` / `verdict_status_invalid:` |
| 项与定性都**不许**带 `confirmed` | `ReviewItem.validate()` / `Verdict.validate()` | `… must not carry 'confirmed'` |

`needs_evidence` 不是终点而是「缺材料」：可以重新封存一次执行再开新项，或补齐证据后
重新复核同一条项；`accepted` / `rejected` 是终态。

### 3.4 两个字段契约

```
vulnmap.adaptive.review_item.v1
  schema / item_id / task_id / run_id / execution_id / evidence_sha256 / kind /
  status / revision_id / build_id / source / verdict_id / detail /
  created_at / updated_at

vulnmap.adaptive.handoff_verdict.v1
  schema / verdict_id / item_id / task_id / run_id / execution_id /
  evidence_sha256 / status / reason / checks / blockers / detail / verifier /
  created_at
```

`ReviewItem` 的 docstring 就是口径：**只有身份与状态，没有结论字段**——结论只来自复核者。

---

## 4. 独立复核者：10 项检查与三条判定规则

```python
CHECKS = ("item_valid", "record_present", "record_hash_match", "task_match",
          "triple_match", "source_evidence_match", "event_binding",
          "revision_current", "version_current", "raw_source_only")
GAP_CHECKS = ("record_present", "record_hash_match", "source_evidence_match")
VERIFIER = "independent-verifier.v1"
```

### 4.1 十项检查

| # | check | 判据 | 不成立时 |
|---|---|---|---|
| 1 | `item_valid` | 项能通过 `ReviewItem.from_dict()`（身份字段齐全、`status`/`source` 合法、不带 `confirmed`） | 直接 `rejected`，blocker `item_invalid:{err}`（连身份都不成立，没有可复核的原始记录） |
| 2 | `record_present` | `evidence_sha256` 在证据台账里 | `evidence_not_in_store:{sha[:12]}`（缺证据档） |
| 3 | `record_hash_match` | `RawRecordReader.read()` 通过（盘上存在 + 字节哈希 == sha + 本体复算 == sha + 能解析） | 读取失败的码进 blockers（`evidence_file_missing` / `evidence_hash_mismatch` / `raw_record_not_json` / `raw_record_sha_mismatch`），本项置 `False` |
| 4 | `task_match` | `record.task_id == item.task_id` | 记录属于别的任务 → 硬拒绝（见 §4.2 `wrong_task`） |
| 5 | `triple_match` | `record.run_id == item.run_id` **且** `record.execution_id == item.execution_id` **且** `record.evidence_sha256 == item.evidence_sha256` | `identity_mismatch:run_id=…/…, execution_id=…/…, evidence=…/…` |
| 6 | `source_evidence_match` | `item.detail.source_evidence_sha256` 也在证据台账里，且 `evidence_sha256` 本身在台账里 | `source_evidence_not_in_store:{…}`（缺证据档） |
| 7 | `event_binding` | §2.4：事件序号 / `plan_sha256` / 源证据哈希三者与同一条 `exec.finished` 对上，且 `registered` + `hash_ok` | `raw_event_missing:{execution_id}#{seq}` |
| 8 | `revision_current` | 记录 `revision_id` 等于当前 head revision（`revisions.current()`；没有 revision 账本、或记录没写 revision → 不参与判定，本项 `True`） | `stale_revision:record=… head=…` |
| 9 | `version_current` | 记录 `policy_version` 等于复核者期望值（`IndependentVerifier(policy_version=…)`；期望值为空 → 不参与判定，本项 `True`） | `stale_version:record=… expected=…` |
| 10 | `raw_source_only` | `record.summary_keys()` 为空（原始记录里没有 `summary/claim/claims/narrative/conclusion/conclusions/rationale/model_summary/analysis/verified/confirmed/verdict/adjudicated/pass`） | `model_summary_in_record:[…]` → `rejected`（硬拒绝，见 §4.5） |

「不参与判定」≠「任意值都行」：`revision_current` / `version_current` 只在**没有可比
对象**时放行（没有 revision 账本 / 没期望版本），一旦有对象就必须相等。

### 4.2 三条判定规则（`derive_verdict`）

```python
if checks["record_hash_match"] and checks["task_match"] is False:  return "rejected"        # 硬拒绝
if any(not checks[n] for n in GAP_CHECKS):                          return "needs_evidence"  # 缺证据
if not all(checks[n] for n in CHECKS):                              return "rejected"        # 其余不成立
return "accepted"
```

顺序不能换：

1. **错任务 = 硬拒绝**：记录完好但属于**另一个任务**（`record_hash_match=True` 且
   `task_match=False`）→ `rejected`。补证据救不了错任务；
2. **缺证据 = `needs_evidence`**：`record_present` / `record_hash_match` /
   `source_evidence_match` 任一不成立（不在库、文件缺失、哈希不符、源证据缺失）→
   可补材料后重进复核；
3. **其余不成立 = `rejected`**：身份不对（`identity_mismatch`）、事件绑不上
   （`raw_event_missing`）、版本旧了（`stale_revision` / `stale_version`）、记录被模型
   加工过（`model_summary_in_record`）都是「这条证据不能当结论」，不是「缺材料」。

### 4.3 三类拒绝用例

| 场景 | 触发条件 | blocker / 码 | 落的状态 | 是否采纳（进 `conclusions`） | 能否补材料重进 |
|---|---|---|---|---|---|
| 错任务 ID | 记录本体属于任务 B，项却挂在任务 A（`RawRecordReader.read()` 报 `wrong_task`） | `wrong_task:record='B' request='A'`（`task_match=False`） | `rejected` | 否 | **不能**（硬拒绝；补证据无用） |
| 旧 revision | 项记录 `revision_id=r1`，`revisions.current()` 已是 `r2` | `stale_revision:record=r1 head=r2` | `rejected` | 否 | 否（要拿当前 revision 的证据重新封存） |
| 旧版本 | 项记录 `policy_version="v3-w2"`，复核者期望 `"v3-w3"` | `stale_version:record=v3-w2 expected=v3-w3` | `rejected` | 否 | 否 |
| 证据不在库 | `evidence_sha256` 没在 `evidence` 台账登记 | `evidence_not_in_store:{sha[:12]}` + `record_unreadable` | `needs_evidence` | 否 | **能**（补登记/重新封存） |
| 证据文件缺失 | 台账有行、盘上 blob 被删 | `evidence_file_missing:{sha[:12]}` + `record_unreadable` | `needs_evidence` | 否 | 能 |
| 证据哈希不符 | 盘上字节被改 | `evidence_hash_mismatch:{sha[:12]}` + `record_unreadable` | `needs_evidence` | 否 | 能（补回原字节） |
| 源证据缺失 | `detail.source_evidence_sha256` 不在台账 | `source_evidence_not_in_store:{…}` | `needs_evidence` | 否 | 能 |
| 记录被加工过 | `payload.finish` 里带 `summary` 等字段（`SUMMARY_KEYS`） | `model_summary_in_record:['payload.finish.summary']`（`raw_source_only=False`） | `rejected`（硬拒绝，见 §4.5） | 否 | **不能**（补证据救不了被加工的记录） |
| 身份不一致 | 项的 `run_id`/`execution_id`/`evidence_sha256` 与记录本体不同 | `identity_mismatch:run_id=…/…, execution_id=…/…, evidence=…/…` | `rejected` | 否 | 否 |
| 事件绑不上 | 事件流里找不到同序号同 `plan_sha256` 同源证据的 `exec.finished` | `raw_event_missing:{execution_id}#{seq}` | `rejected` | 否 | 否 |

无论哪一类，`handoff_view()` 的 `conclusions` 都只收 `accepted`——拒绝项不进报告结论。

### 4.4 给复核者递摘要 = 直接报错

```python
IndependentVerifier.verify(item, *, summary=None) -> dict
```

`summary` 参数**只为拒绝存在**：任何非空值（dict / str / list，`None`、`""`、`{}`、
`[]` 除外）都抛

```
HandoffError: model_summary_not_accepted: verifier only reads raw records (got dict)
```

拒绝发生在**入口**：不落 verdict、不改项状态、不产生结论（回归
`test_verifier_rejects_model_summary_argument` 钉住这三点，并确认「不给摘要时同一份
原始记录照常 `accepted`」——拒的是摘要，不是证据）。

也就是说「模型说这次是可利用的」这条信息**没有入口**——它既不能替代原始记录，也不能
作为旁证。verdict 的 `detail` 里固定写 `model_summary_accepted: False`；
`agent/platform/verify.raw_handoff_view()` 同样恒为 `False`（§7.1）。

### 4.5 被模型加工过的记录 = `rejected`（不是 `needs_evidence`）

分工写死在这里：

| 层 | 做什么 | 不做什么 |
|---|---|---|
| `RawRecord.validate()` | 只校验身份与形状（必填字段、`run-<16hex>`、64 位 hex、`source_event_seq>0`） | **不在解析期**拒收摘要字段 |
| `RawRecord.summary_keys()` | 列出记录里出现的模型加工字段（顶层、`payload.*`、`payload.finish.*` 三层都查） | 不判定、不抛错 |
| 复核者的 `raw_source_only` | `summary_keys()` 非空 → 本项 `False` → blocker `model_summary_in_record:[…]` | — |
| `derive_verdict()` | `raw_source_only` 不在 `GAP_CHECKS` 里 → 落 **`rejected`** | 不落 `needs_evidence` |

**为什么不是 `needs_evidence`**：`needs_evidence` 的含义是「材料还没凑齐，补上就能
重进复核」。而被加工过的记录是材料本身出了问题——补证据救不了它：那条记录已经
不是执行器写的原始事实，再怎么补也改不回「没被模型写过」。错任务（`wrong_task`）
同理，所以两者都是硬拒绝。

这也是为什么解析期**不**抛错：若 `RawRecord.validate()` 在 read 阶段直接抛，分类会
退化成 `record_hash_match=False` → `needs_evidence`，看起来像「文件缺失、补一下就行」，
与事实相反。分类必须由复核者按 `raw_source_only` 给出。

回归 `test_raw_record_carrying_summary_is_not_accepted` 钉住这条：写一个
`payload.finish.summary` 的 blob 并登记 → verdict `rejected`、
`checks["raw_source_only"] is False`、blockers 含 `model_summary_in_record`、
项不进 `conclusions`。

简化成一句：**被加工过的记录不是「缺材料」，是「不能当证据」。**

---

## 5. 报告口径（CasePack）

### 5.1 `handoff_view()`：可追溯结论视图

```python
handoff_view(store, task_id, *, revisions=None) -> dict
```

| 字段 | 含义 |
|---|---|
| `schema` / `schema_version` | `vulnmap.adaptive.handoff.v1` / `1` |
| `counts` | `pending` / `accepted` / `rejected` / `needs_evidence` 逐状态计数，加 `items`（总数）、`conclusions`（可追溯结论数）、`unverified`（`pending + needs_evidence`） |
| `expected_revision` | 当前 head revision（没有账本就是 `""`） |
| `conclusions` | **只**含 `traceable` 的项：`item_id` / `run_id` / `execution_id` / `evidence_sha256` / `verdict_id` / `kind` / `revision_id` |
| `items` | 每项一行：`item_id` / `run_id` / `execution_id` / `evidence_sha256` / `status` / `kind` / `revision_id` / `build_id` / `verdict_id` / `reason` / `blockers` / `traceable` / `revision_current` |
| `note` | 口径原文：只有 `accepted` 且三方身份齐全的项算可追溯结论；`pending`/`needs_evidence` 不算结论、不进包级 `verified` 计数 |

`traceable` 的判据（三件同时成立）：`status == "accepted"`、`verdict_id` 非空、
`evidence_sha256` 是 64 位 hex。

`pending_items(store, task_id)` 是待办队列：`pending` + `needs_evidence`
（缺证据的项也要能被看见，不能藏进「还没开始」里）。

### 5.2 进包（`agent/platform/casepack.py`）

```python
HANDOFF_FILE       = "handoff.json"
HANDOFF_COUNT_KEYS = ("items", "pending", "accepted", "rejected",
                      "needs_evidence", "conclusions", "unverified")
HANDOFF_NOTE       = ("只有 accepted 且 run_id/execution_id/evidence_sha256 齐全的项"
                      "算可追溯结论；pending/needs_evidence 一律不算结论，"
                      "也不进包级 benchmark_verified / accepted_by_review")

_handoff_view(store, task_id, *, revisions=None)     # handoff_view() 的唯一调用点（延迟 import）
_handoff_counts(handoff) -> dict                     # 七个计数键，缺项按 0
_handoff_block(handoff)  -> dict                     # casepack.json 的 handoff 段
_render_handoff_md(handoff) -> list[str]             # report.md 的交接小节
```

| 位置 | 内容 |
|---|---|
| `FILES` | 新增 `"handoff.json"`（排在 `reviews.json` 之后），因此进 `files` 清单并随 `content_sha256` 一起被哈希覆盖；**没有交接时也写**（计数为 0，不省略文件） |
| `handoff.json` | `handoff_view()` 的整份只读快照（§5.1）；包内不重算、不猜 |
| `casepack.json` 的 `handoff` 段 | `{"file": "handoff.json", "counts": {七个计数}, "conclusions": N, "unverified": M, "note": HANDOFF_NOTE}` |
| `casepack.json` 的 `verdict.handoff` 段 | `{"items","pending","needs_evidence","accepted","rejected","conclusions","note"}`——**只数状态** |
| `events` 的 `report.ready` payload | `"handoff": {"file","items","conclusions","unverified"}` |
| `report.md` | `## 证据交接（handoff）` 小节：一行计数 + 口径句 + **逐项明细表** `item_id / status / run_id / execution_id / evidence_sha256 / revision_id`（无项时写一行 `—`） |
| `report.html` | 同名小节（`<h2>证据交接（handoff）</h2>`）：交接项逐状态计数 + 可追溯结论数 + 未核验数 + **逐项明细表** `item_id / status / run_id / execution_id / evidence_sha256`（无项时写 `（无）`），末尾指向 `handoff.json` |

硬规则：

- **`verdict.handoff` 只数状态**；`benchmark_verified` / `accepted_by_review` 的
  语义不变（仍只来自 `verifications` / `reviews`），交接项**不能**冒充 `verified`；
- 视图取不到就**抛**（`_handoff_view` 不吞异常、不编空视图冒充「没有待复核项」）；
- `report.md` / `report.html` 两侧**都逐行列出待复核项**，且说同一句话
  （`HANDOFF_NOTE`）：明细两处都有，口径不许只在一处说；网页只是它所记录快照的
  确定性函数，不另算一套计数。

---

## 6. 隔离/授权验收门（`ProposalGate`）

> 第 3 周的这道闸只有一个问题：**"凭什么放行"**。授权仍然按 `metadata` 严格解析；
> 隔离**改口径**——只认平台侧记录，任务提交者填的字段恒为 advisory。隔离事实
> 本身怎么跑出来、记录长什么样、越界/断网怎么验，唯一出处是
> `docs/V3-ISOLATION-ACCEPTANCE.md`；本节只说闸怎么读它。

### 6.1 授权：`metadata.authorized` 严格解析

```python
AUTHORIZATION_FIELD = "authorized"
ISOLATION_FIELD     = "isolation_accepted"      # 只是**声明**字段，不放行

resolve_acceptance(task, *, record=None, store=None, path=None)
    -> Acceptance(authorization, isolation, ok, acceptance_id,
                  evidence_sha256, declared_isolation, reason)
```

`authorized` 走 `_accept_token()` → `agent.platform.authorization.parse_authorized()`
（唯一授权口径）：

| metadata 写法 | `parse_authorized()` | `Acceptance.authorization` |
|---|---|---|
| `true` / `1` / `yes` / `on`（含 JSON 布尔、整数 `1`） | `True` | `"true"` |
| `false` / `0` / `no` / `off`（含 JSON 布尔、整数 `0`） | `False` | `"false"` |
| 缺失（`metadata` 里没有这个键） | `_accept_token` → `(False, "missing")` | `"false"`（未授权） |
| 其余（`"maybe"`、`""`、`2`、列表、字典） | `AuthorizationError` | `"invalid"`（fail-closed） |

**字符串 `"false"` 仍是未授权**：`bool("false")` 为真是上一代假阳性的根因，
`parse_authorized()` 明确禁用它——空串、拼错的词、非 0/1 的整数一律
`AuthorizationError`（不当成 `True`）。

### 6.2 隔离：只认平台侧记录（`isolation_acceptance`）

`metadata.isolation_accepted` **不再参与判定**：

| 位置 | 作用 |
|---|---|
| `metadata.isolation_accepted` | 只解析成 `Acceptance.declared_isolation`（`declared` / `missing` / `invalid`），进 `to_dict()["declared"]`，`authority="advisory"`；**不改** `isolation`、**不改** `ok` |
| 平台侧记录（`PlatformStore.isolation_acceptance` 表 / `isolation-acceptance.jsonl`） | 唯一的放行依据：由 `record_isolation_acceptance()` 在**真隔离执行之后**写入，带检查项、证据哈希、时间 |

记录本体（`vulnmap.adaptive.isolation_acceptance.v1`）：

```python
ISOLATION_ACCEPTANCE_SCHEMA = "vulnmap.adaptive.isolation_acceptance.v1"
ISOLATION_ACCEPTANCE_STATUSES = ("accepted", "rejected")
ISOLATION_EXECUTORS = ("bwrap", "unshare", "container")
ISOLATION_CHECKS = ("isolation_available", "qualified_executor",
                    "executed_isolated", "network_denied",
                    "capability_dropped", "root_read_only",
                    "probe_write_confined", "probe_network_denied")
ISOLATION_PROBES = ("write_confined", "network_denied")
```

| 字段 | 含义 |
|---|---|
| `acceptance_id` | `"ia-" + sha256(本体)[:16]`（同一组事实恒得同一 id） |
| `status` | `accepted`（八个检查项全真）/ `rejected`（缺一项就不是） |
| `isolation` / `network` / `cap_drop` / `ro_root` / `executed_isolated` | 来自 build/smoke 记录的**实际**隔离事实 |
| `checks` | 八个检查项的布尔表（见上） |
| `evidence` | `[{"kind": "build"|"smoke"|"probe", "id": ..., "sha256": ...}]`（日志哈希 / 探针证据哈希） |
| `evidence_sha256` | 记录**本体**（含 `checks`/`evidence`/事实/时间）规范化 JSON 的 sha256 |
| `reason` / `checked_at` | 判决原因与验收时间 |

`verify_isolation_acceptance(record, *, task_id="")` → `(state, detail)`，state 只有
`accepted` / `rejected` / `missing`：

| 情形 | state | `detail.reason` |
|---|---|---|
| 没有记录（`None`） | `missing` | `no_platform_record` |
| 记录 schema 不对 | `rejected` | `schema_mismatch` |
| 记录的 `task_id` 不是这个任务 | `rejected` | `wrong_task` |
| 记录本身是 `rejected` | `rejected` | `recorded_rejected` |
| `evidence_sha256` 与复算值不等（**改一个字节**） | `rejected` | `evidence_hash_mismatch` |
| `accepted` 但证据列表为空 | `rejected` | `evidence_missing` |
| `accepted` 但有检查项为假 | `rejected` | `checks_failed:<names>` |
| 全真 | `accepted` | `platform_record_accepted` |

`Acceptance.ok = auth_ok and isolation == "accepted"`。`Acceptance.to_dict()` 固定带
`authorization` / `isolation` / `ok` / `acceptance_id` / `evidence_sha256` / `reason` /
`declared`（自填字段的状态与 `authority="advisory"`）/ `fields` / `policy`。

### 6.3 判定与建议清单

```python
ProposalGate(task=task, store=store)              # 从平台库取最近一条记录
ProposalGate.from_task(task, isolation_record=…)  # 显式递记录
ProposalGate.from_task(task, path=…)              # 从追加文件读
ProposalGate(acceptance=Acceptance(...))          # 只做单元判定
gate.admit(scope="engineering", action="propose", params={...}) -> GateDecision
```

| `GateDecision.status` | 条件 | blockers |
|---|---|---|
| `apply` | `authorization == "true"` **且** `isolation == "accepted"` | 空 |
| `advisory` | 任一不成立 | `authorization:<true|false|invalid>`、`isolation:<accepted|rejected|missing>`（缺哪个报哪个） |

`GateDecision.to_dict()` 里 `applied = (status == "apply")`；`ProposalGate.record()`
写建议清单一行，**固定** `status="advisory"`、`applied=False`，带
`round` / `action` / `params_sha256`（params 规范化 JSON 的 sha256）/
`blockers` / `acceptance` / `note` / `created_at`。

`admit()` 的 `scope` / `action` / `params` **只是标签**：判定只读 `Acceptance`，不看
调用方说自己要做什么（控制器传 `action="propose"`、`params={actions, revision}`，
单元测试传 `action="stage"`，判定结果相同）。

### 6.4 控制器行为

`ResearchController(..., proposal_gate: ProposalGate | None = None)`；**默认 `None` =
W1/W2 行为**（不启用闸，既有测试语义不变）。

闸的位置：`PROPOSE` 之后、`AUTHORIZE` 之前，条件是
`plan.actions or plan.revision is not None`：

| 情形 | 相位 | `stop_reason` | `status` | 建议清单 | stage/revision/adoption/verification |
|---|---|---|---|---|---|
| 未验收 | `PROPOSE=advisory`、`STOP=advisory`（消息 `advisory_only: authorization:false,isolation:missing`） | `advisory_only` | `completed` | 写一行，`applied=False` | **一次执行都不会发生**（`exec_runner` 零调用）：不 authorize、不 stage、不建 revision、不写 adoption、不产生 verification |
| 已验收（授权 + 平台记录 accepted） | `AUTHORIZE=accepted`（消息 = `gate.note`） | 继续原流程 | 按原逻辑 | 不写 | 按原逻辑 |
| 不传 `proposal_gate` | 无此相位 | 原逻辑 | 原逻辑 | 无 | 原逻辑 |

`RoundRecord.advisories` 留档（`round` / `action` / `status` / `applied` /
`params_sha256` / `blockers` / `acceptance` / `note` / `created_at`），
`RoundRecord.note = "advisory_only"`。提议本体原样进清单，**不**写进工作副本。

### 6.5 与执行侧的接缝

闸读的记录必须是**同一次任务的隔离执行**产出的：`build_isolation_acceptance()`
只从 `BuildRecord` / `SmokeRecord` 的实际隔离事实与探针证据算检查项，工作副本
（`TaskWorkspace`）负责“没有合格执行器就一个命令都不跑”（见
`docs/V3-ISOLATION-ACCEPTANCE.md`）。计划里的隔离模式（`workspace.json` 的
`isolation` / `require_isolation`）**只描述要求**，它写不出 `executed_isolated`。

---

---

## 7. 与既有模块的边界

### 7.1 `verify.py`：只加只读钩子

```python
RAW_HANDOFF_SCHEMA = "vulnmap.verification.raw_handoff.v1"
RAW_EVENT_TYPES    = ("exec.finished",)

raw_execution_refs(store, task_id, *, execution_id="", evidence_sha256="") -> list[dict]
raw_handoff_view(store, task_id, *, execution_id="", evidence_sha256="") -> dict
```

`raw_execution_refs()` 每条引用都是 `exec.finished` 事件里的真实字段 + 本机存在性：

| 字段 | 来源 |
|---|---|
| `execution_id` / `evidence_sha256` / `plan_sha256` | 事件 payload |
| `kind` | 证据台账 |
| `event_seq` / `event_type` / `recorded_at` | 事件本身 |
| `registered` / `present` / `hash_ok` | 台账是否登记 / 盘上是否存在 / 字节哈希复算 |
| `source` | 固定 `"event_stream+evidence_store"` |

`raw_handoff_view()`：`counts{refs, registered, traceable}`（`traceable = present and
hash_ok`）+ `refs` + `model_summary_accepted=False`（**恒为 False**，不是「当前没读」）
+ `reads=["task_events(exec.finished)","task_evidence","evidence blob"]`。

**不动**：`verification` 的判据、`benchmark_policy`、`verified` 的写法。这两个函数
不写事件、不改状态、不产生证据、不改 verification 记录。

### 7.2 `review.py`：`run_review` 仍是唯一复核入口

交接接入只到「待复核项桥」为止：`run_review()` 依旧是 `verifications`/`reviews`
记录的唯一复核入口，`handoff_verdicts` 不替代它，也不写 `verified`。

```python
HANDOFF_TOUCHES       = ("review_items", "handoff_verdicts", "evidence")
HANDOFF_NEVER_TOUCHES = ("verifications", "reviews", "task_state")

handoff_items(task_id, store, *, status="")            -> list[dict]   # 只读队列
open_handoff_item(task_id, store, *, execution_id, evidence_root=None,
                  revision_id="", build_id="", policy_version="",
                  run_id="")                           -> dict         # 转发 open_pending
review_handoff_item(task_id, store, item_id, *, verifier=None,
                    evidence_root=None, revisions=None,
                    policy_version="")                 -> dict         # 转发 review_item
handoff_report(task_id, store, *, revisions=None)      -> dict         # 转发 handoff_view
```

| 约束 | 说明 |
|---|---|
| 两条链不混 | `Review` 的 `accept/reject/needs_evidence` 只由 `run_review` 产出；交接项的 `accepted/rejected/needs_evidence` 只落在 `handoff_verdicts` |
| 不写 `verifications` / `reviews` / 任务状态 | 桥只写 `review_items` / `handoff_verdicts`（+ 读 `evidence`），状态怎么走仍由调用方按 `task.TRANSITIONS` 决定 |
| `status` 过滤项 | `handoff_items(status=…)` 只认 `handoff.STATUSES`，不认识的值抛 `ReviewError`（不静默返回空列表） |
| 口径同一句话 | `review.HANDOFF_BOUNDARY` 与 `casepack.HANDOFF_NOTE` 说的是同一句：只有 `accepted` 且三方身份齐全的项算可追溯结论 |
| 返回形状 | `review_handoff_item()` 返回 `{"task_id","item_id","status","item","verdict","traceable","note"}`（`traceable = status == "accepted"`） |

两个模块都**延迟 import** `adaptive.handoff`（`review.py` 走 `_handoff_module()`），
导入期不把研究子系统整条依赖链拖进平台包。

### 7.3 `store.py`：只加两张表与方法

- `SCHEMA_VERSION` 5 → **6**；`PRAGMA user_version=6`；
- `SCHEMA_W3` 全部是 `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`，
  老库打开即幂等升级（不删列、不重写既有表）；
- 新增方法：`save_review_item` / `get_review_item` / `list_review_items` /
  `save_handoff_verdict` / `get_handoff_verdict` / `list_handoff_verdicts` /
  `handoff_summary`；`summary()` 新增 `handoff` 段（`items` / `pending` /
  `accepted` / `rejected` / `needs_evidence` / `verdicts` / `last_item` /
  `last_verdict`）；
- 落库时 `item_id` / `verdict_id` 加 `task_id::` 前缀（与候选同一命名空间），
  读出时 `_strip_ns()` 还原；
- store **不** import `adaptive`（`adaptive` 依赖 store，反向 import 成环）：
  状态词表以常量 `REVIEW_ITEM_STATUSES` / `HANDOFF_VERDICT_STATUSES` 与之对账
  （回归 `test_status_vocabularies_match_handoff_module`）。

### 7.4 `handoff.py` 自身的依赖方向

模块顶层只 import `.contracts`；`evidence` / `verify` / `authorization` 全部**延迟
import**（函数内），避免平台包循环。

---

## 8. 回归测试映射（`tests/test_v3_week3_handoff.py`）

六组、十三条用例。夹具自己搭（不 import 其它测试模块）：真 `PlatformStore` +
真 `EvidenceStore`（内容寻址落盘）+ 真 `EventBus`（`exec.started` /
`exec.finished`）+ 真 `RevisionStore`/`HarnessRevision` 账本。凡涉及
`evidence_sha256` 的断言都**回到磁盘复算**，不读内存对象。

| 组 | 用例 | 断言点 |
|---|---|---|
| 1 成功链路 | `test_seal_then_review_keeps_one_identity` | `HI1` / `pending` / `source="exec.finished"` / `verdict_id=""`；`run_id == derive_run_id(TASK, EXEC_ID, PLAN_SHA)`、`execution_id == EXEC_ID`；盘上 blob `sha256 == evidence_sha256` 且 `record_doc` 里**没有** `evidence_sha256`（自指哈希）；`raw_handoff_view()` 的 `model_summary_accepted is False`、`counts == {refs:1, registered:1, traceable:1}`；verdict `HV1` / `accepted` / `blockers == []` / `set(checks) == set(handoff.CHECKS)`；record/item/verdict 三方身份全等；`counts == {1,0,0,0,1,1,0}`；`store.summary()["handoff"] == {items:1, …, last_item:"HI1", last_verdict:"HV1"}`；**幂等**：同三方身份再 `open_pending()` 仍返回 `HI1`、台账仍 1 条；已定性项再复核抛 `review_item_closed` |
| 2a 错任务 | `test_wrong_task_evidence_is_rejected` | 同一条证据登记到 `OTHER` 并伪造 `OTHER` 的项 → `rejected`、blockers 有 `wrong_task` 前缀、`task_match is False`、项的 `status=="rejected"`；`OTHER` 的 `conclusions == []`、`counts.rejected==1`、`counts.conclusions==0`；原任务的项不被牵连 |
| 2b 旧 revision | `test_stale_revision_is_rejected` | 账本 head 推到 `r2` → `rejected`、blockers 含 `stale_revision` 且含 `head=r2`、`revision_current is False`、`conclusions == []` |
| 2b 旧版本 | `test_stale_policy_version_is_rejected` | 记录写 `v3-w2`、复核期望 `v3-w3` → `rejected`、blockers 含 `stale_version`、`version_current is False`、`conclusions == []` |
| 2c 证据文件缺失 | `test_missing_evidence_file_needs_evidence` | 删 blob → `needs_evidence`、blockers 含 `evidence_file_missing`、`record_hash_match is False`；项状态落 `needs_evidence`；`pending_items()` 仍看得见它；`summary()["handoff"]["needs_evidence"] == 1` |
| 2c 证据不在库 | `test_evidence_not_in_store_needs_evidence` | 伪造 `evidence_sha256 = "f"*64` 的项 → `needs_evidence`、blockers 含 `evidence_not_in_store`、`record_present is False`、`conclusions == []`、`counts.needs_evidence == 1` |
| 3 递摘要 | `test_verifier_rejects_model_summary_argument` | `verify(item, summary={"conclusion":"exploitable"})` 抛 `HandoffError`，消息含 `model_summary_not_accepted` 与 `dict`；`"漏洞已确认"` / `["exploitable"]` / `{"claim":"x"}` 同样被拒；**什么都没写进去**（`list_handoff_verdicts()==[]`、项仍 `pending`、`conclusions==[]`）；不给摘要时同一份记录照常 `accepted`；`summary=""` 等同没给 |
| 3 记录带摘要 | `test_raw_record_carrying_summary_is_not_accepted` | 直接写一个 `payload.finish.summary` 的 blob 并登记（绕过 `seal_execution`）→ verdict **`rejected`**、`checks["raw_source_only"] is False`、blockers 含 `model_summary_in_record`（§4.5）、项状态 `!= "accepted"`、`HI9` 不在 `conclusions` |
| 4 CasePack | `test_casepack_carries_handoff_trace` | `handoff.json in casepack.FILES` 且文件存在可 `json.load`；一个 accepted + 一个 pending + 一个 needs_evidence → `conclusions == ["HI1"]`、`items` 状态 `{HI1:accepted, HI2:pending, HI3:needs_evidence}`、`doc["counts"] == view["counts"]`、`unverified == 2`、`note.startswith("只有 accepted")`；`pack["verdict"]["handoff"]` 七键与视图一致且 `note == casepack.HANDOFF_NOTE`；`pack["verdict"]["verified"] == 0`、`benchmark_verified is False`（交接不冒充 verified）；`pack["handoff"]["counts"]` 逐键相同；`report.md` 含 `证据交接（handoff）`、`| HI1 | accepted |`、`| HI3 | needs_evidence |`；`report.html` 含同一小节、`needs_evidence`、`handoff.json` 与 `交接项</dt><dd>3 条` |
| 5 验收门（单元） | `test_proposal_gate_unit_requires_both_acceptances` | 空 `metadata` → `advisory`、`applied is False`、`blockers == {"authorization:false","isolation:missing"}`；只有平台记录没授权 → `advisory` + `authorization:false`；**自填 `isolation_accepted` 只留 `declared`（advisory）不放行**；授权 + 平台记录 accepted → `apply`、`blockers == ()`；`"false"` 仍是 `advisory` + `authorization:false`；`"maybe"` → `authorization == "invalid"`；记录被改一个字段 → `isolation:rejected` |
| 5 验收门（集成·未验收） | `test_controller_stops_at_advisory_only_before_acceptance` | `status=="completed"`、`stop_reason=="advisory_only"`、`error==""`；`runner.calls == []`（一次执行都没发生）；`record.note/stop_reason=="advisory_only"`、`len(advisories)==1`、`status=="advisory"`、`applied is False`、`action=="propose"`、`blockers==["authorization:false","isolation:missing"]`、`params_sha256` 非空；时间线有 `("PROPOSE","advisory")` 与 `("STOP","advisory")`、**没有** `EXECUTE`；`revisions.all()` 长度不变、`adoptions()==()`、无 `adoptions.jsonl`、`pending_invalidations()==[]` |
| 5 验收门（集成·已验收） | `test_controller_proceeds_after_acceptance` | 先用**真隔离** build+smoke 落一条平台记录（`_platform_record_for()`），`gate.acceptance.ok is True`、`acceptance_id`/`evidence_sha256` 与落库行一致、`admit(action="propose").status=="apply"`；控制器 `stop_reason=="max_rounds"`（不再是 `advisory_only`）、`runner.calls==["exec-0001"]`、`record.advisories==[]`；时间线有 `("AUTHORIZE","accepted")`、无 `("PROPOSE","advisory")`、有 `EXECUTE` |
| 6 词表对账 | `test_status_vocabularies_match_handoff_module` | `store.REVIEW_ITEM_STATUSES == handoff.STATUSES`；`store.HANDOFF_VERDICT_STATUSES == handoff.TERMINAL_STATUSES`；入口态只有一个且是 `pending`；终态是待复核状态的真子集且少一个；`verified` / `confirmed` 不在状态词表里 |

跑：

```bash
python3 -m pytest tests/test_v3_week3_handoff.py -q
```

---

## 9. 字段清单

### 9.1 原始记录（`vulnmap.adaptive.raw_execution.v1`）

| 字段 | 类型 | 说明 |
|---|---|---|
| `schema` | str | 固定 `vulnmap.adaptive.raw_execution.v1` |
| `schema_version` | int | `1` |
| `task_id` | str | 所属任务 |
| `run_id` | str | `run-<16 hex>`（§1 派生） |
| `execution_id` | str | 执行侧 `exec_id` |
| `plan_sha256` | str | `exec.finished.payload.plan_sha256` |
| `kind` | str | `exec.finished.payload.kind` |
| `source_evidence_sha256` | str | `exec.finished.payload.evidence_sha256` |
| `source_event_seq` | int | `exec.finished` 的事件序号（>0） |
| `source_event_type` | str | 固定 `exec.finished` |
| `revision_id` / `build_id` / `policy_version` | str | 执行时的 revision / build / 策略版本 |
| `recorded_by` | str | 缺省 `"executor"` |
| `sealed_at` | str | 封存时间 |
| `payload.start` / `payload.finish` | dict | `exec.started` / `exec.finished` 的原始 payload |
| `evidence_sha256` | str | **只在 `to_dict()` 里**：本体哈希，落盘字节不含（§1.1） |

### 9.2 待复核项（`vulnmap.adaptive.review_item.v1`）

`schema` / `item_id` / `task_id` / `run_id` / `execution_id` / `evidence_sha256` /
`kind` / `status` / `revision_id` / `build_id` / `source` / `verdict_id` /
`detail` / `created_at` / `updated_at`。

### 9.3 复核定性（`vulnmap.adaptive.handoff_verdict.v1`）

`schema` / `verdict_id` / `item_id` / `task_id` / `run_id` / `execution_id` /
`evidence_sha256` / `status` / `reason` / `checks` / `blockers` / `detail` /
`verifier` / `created_at`。

### 9.4 状态词表

| 词 | 出现在哪 | 含义 |
|---|---|---|
| `pending` | 项状态 | 唯一入口态，尚未复核 |
| `accepted` | 项状态 / verdict | 十项检查全过 |
| `rejected` | 项状态 / verdict | 错任务、身份/版本/事件绑定不成立、记录被模型加工过（硬拒绝与一般拒绝都落这里） |
| `needs_evidence` | 项状态 / verdict | 缺证据（不在库/文件缺失/哈希不符/源证据缺失），可补材料重进 |
| `apply` / `advisory` | `GateDecision.status` | 验收门放行 / 只给建议 |
| `authorization:<state>` | `GateDecision.blockers` | 只在未验收时出现：`authorization:false`（未声明或声明为假）/ `authorization:invalid`（写法非法） |
| `isolation:<state>` | `GateDecision.blockers` | 同上：`isolation:false` / `isolation:invalid` |
| `true` / `accepted` | `Acceptance.authorization` / `.isolation` | 验收通过的写法（不会进 blockers） |
| `missing` | 裸 `Acceptance()` 默认值 | 只出现在未经过 `resolve_acceptance()` 的构造里 |
| `advisory_only` | 控制器 `stop_reason` / `note` | 本轮只给建议，没有应用 |

> `Acceptance` 的两个状态字段是**字符串**而不是布尔：`"true"` / `"accepted"` 才算
> 验收，`"false"` / `"invalid"` 都是未验收。这样报告里能直接看出「为什么没过」。

### 9.5 拒绝码表

**抛错类**（`HandoffError` / `store.TaskError`，消息形如 `<code>: <detail>`，
调用方用 `startswith` 认码）：

| code | 触发 | 抛出点 |
|---|---|---|
| `execution_not_found:{execution_id}` | 没有 `exec.finished` 事件 | `seal_execution` |
| `ambiguous_execution:{execution_id}` | 多条 `exec.finished` | `seal_execution` |
| `evidence_missing:{execution_id}` | `exec.finished` 没有 `evidence_sha256` | `seal_execution` |
| `evidence_not_in_store:{sha[:12]}` | 证据台账没有这条 sha | `RawRecordReader.path_of` |
| `evidence_file_missing:{sha[:12]}` | 台账有、盘上没有 | `RawRecordReader.read` / `seal_execution` |
| `evidence_hash_mismatch:{sha[:12]}` | 盘上字节哈希 ≠ 声明 | `RawRecordReader.read` / `seal_execution` |
| `raw_record_not_json:{sha[:12]}` | 封存记录不是合法 JSON | `RawRecordReader.read` |
| `raw_record_sha_mismatch:{…}` | 本体复算 ≠ 声明 / 请求值 | `RawRecord.from_dict` / `read` |
| `wrong_task:record=… request=…` | 记录属于别的任务（读取阶段） | `RawRecordReader.read` |
| `run_id_mismatch:given=… derived=…` | 调用方 `run_id` ≠ 派生值 | `seal_execution` |
| `sealed_hash_mismatch:computed=… stored=…` | 落盘字节哈希 ≠ 声明（序列化两套口径） | `seal_execution` |
| `raw record: …` | 记录缺字段 / `run_id` 不合 `run-<16hex>` / 非 64 hex / `source_event_seq<=0` / 含模型摘要字段 | `RawRecord.validate` |
| `model_summary_not_accepted: …` | 给复核者递了摘要 | `IndependentVerifier.verify` |
| `item_invalid:…`（blocker） | 项本身读不出来 | `IndependentVerifier.verify` |
| `review_item_not_found:{task}/{item}` | 项不存在 | `review_item` |
| `review_item_closed:{item} status=…` | 对 `accepted`/`rejected` 项重复复核 | `review_item` |
| `wrong_task_id:verdict=… request=…` | 定性所属任务与请求不符 | `review_item` |
| `verdict_status_invalid:{status}` | 定性状态不在三态内 | `review_item` |
| `unsafe item_id: …` / `unsafe run_id …` / `unsafe verdict_id: …` | 身份含不安全字符 | `ReviewItem.validate` / `Verdict.validate` |
| `item must not carry 'confirmed'` / `verdict must not carry 'confirmed'` | 项/定性里出现 `confirmed` | 同上 |
| `review item status must be one of …` / `handoff verdict status must be one of …` | 落库状态不合法 | `store.save_review_item` / `save_handoff_verdict` |
| `review item requires task_id and item_id` / `handoff verdict requires task_id and verdict_id` | 落库缺身份 | 同上 |

**blocker 类**（进 `verdict.blockers`，同时以 `; ` 连接进 `verdict.reason`）：

| blocker | 落的状态 |
|---|---|
| `item_invalid:…` | `rejected` |
| `evidence_not_in_store:{sha[:12]}` | `needs_evidence` |
| `evidence_file_missing:{sha[:12]}` / `evidence_hash_mismatch:{sha[:12]}` / `raw_record_not_json:` / `raw_record_sha_mismatch:` | `needs_evidence` |
| `source_evidence_not_in_store:{…}` | `needs_evidence` |
| `record_unreadable` | `needs_evidence` |
| `wrong_task:record=… request=…` | `rejected`（硬拒绝） |
| `wrong_task_id:record=… item=…` | `rejected` |
| `identity_mismatch:run_id=…/…, execution_id=…/…, evidence=…/…` | `rejected` |
| `raw_event_missing:{execution_id}#{seq}` | `rejected` |
| `stale_revision:record=… head=…` | `rejected` |
| `stale_version:record=… expected=…` | `rejected` |
| `model_summary_in_record:[…]` | `rejected`（硬拒绝；补证据救不了被加工的记录，见 §4.5） |

---

## 10. 边界（明确不做）

- **不写 `verified` / `confirmed`**：漏洞结论仍只由 `agent.platform.verify` 推导；
  交接只到「这项证据可不可以当结论引用」，不产生漏洞结论；
- **不做模型摘要的「可信化」**：不校验摘要、不给摘要打分、不让摘要参与判定；
  摘要的唯一去处是 `model_summary_not_accepted`；
- **不改执行器执行语义**：`exec.started` / `exec.finished` 的字段与写入时机不变，
  交接侧只读；自动开项只**读**事件流与证据库，封存失败如实记 `unsealed`；
- **开项 ≠ 结论**：`run_research()` 跑完自动开出来的项一律 `pending`，报告里的
  `handoff` 段与 `research.mapped` 事件只带身份与状态，没有裁决字段；
- **审计视图只读**：`raw_execution_refs()` / `raw_handoff_view()` /
  `handoff_view()` / `pending_items()` 都不写库、不写事件、不产生证据；
- **不静默修正**：读取失败不返回半份记录、不猜「更像新的」那条事件、不把缺失的
  证据补成默认值。

---

## 11. 文件清单

| 文件 | 本周改动 |
|---|---|
| `agent/platform/adaptive/handoff.py` | 新增：`RawRecord` / `RawRecordReader` / `seal_execution` / `open_pending` / `ReviewItem` / `Verdict` / `IndependentVerifier` / `review_item` / `handoff_view` / `pending_items` / `raw_evidence_path` / `Acceptance` / `resolve_acceptance` / `GateDecision` / `ProposalGate` / `derive_run_id` / `derive_verdict` |
| `agent/platform/store.py` | `SCHEMA_W3`（`review_items` + `handoff_verdicts` 两表与索引）、`SCHEMA_VERSION` 5→6、七个读写方法、`summary()["handoff"]`、`REVIEW_ITEM_STATUSES` / `HANDOFF_VERDICT_STATUSES` |
| `agent/platform/verify.py` | 只读钩子：`RAW_HANDOFF_SCHEMA` / `RAW_EVENT_TYPES` / `raw_execution_refs()` / `raw_handoff_view()` |
| `agent/platform/adaptive/controller.py` | `proposal_gate` 参数（默认 `None`）、`RoundRecord.advisories`、`PROPOSE` 之后 `AUTHORIZE` 之前的验收闸与 `advisory_only` 出口 |
| `agent/platform/adaptive/cli.py` | `_open_handoff_items()`（事件水位 `after_seq` + 点名 `event_seq`）、研究报告与 `research.mapped` 的 `handoff` / `handoff_items` / `handoff_skipped` 段 |
| `agent/platform/casepack.py` | `handoff.json` 进 `FILES`、`HANDOFF_FILE` / `HANDOFF_NOTE` / `HANDOFF_COUNT_KEYS`、`_handoff_view` / `_handoff_counts` / `_handoff_block` / `_render_handoff_md`、`casepack.json` 的 `handoff` 段、`_pack_verdict(..., handoff=)` 的 `verdict.handoff`、`report.md` / `report.html` 的交接小节、`report.ready` payload 的 `handoff` |
| `agent/platform/review.py` | 只读桥：`HANDOFF_TOUCHES` / `HANDOFF_NEVER_TOUCHES` / `HANDOFF_BOUNDARY` / `_handoff_module` / `handoff_items` / `open_handoff_item` / `review_handoff_item` / `handoff_report`（`run_review` 语义不变） |
| `tests/test_v3_week3_handoff.py` | 本周回归：六组 13 条（§8），`13 passed` |
| `docs/V3-W3-HANDOFF.md` | 本文（口径唯一出处） |
