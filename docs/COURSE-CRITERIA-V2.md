# 课程提交判据 V2（`course-criteria-v2`）

> **生效日期**：2026-11-25
> **取代**：[COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) §1 与 §3 中对 **D 层**的判定口径
> （A/B/C 三层口径不变，只做 caveat 分级细化）。
> **一句话变更**：**D 层不再要求 `receipt.json`**；改为要求「具名 `review.json`（含 `evidence_refs`）＋
> Agent 轨迹＋模型/采样参数＋工件哈希」四件齐备。回执从「材料」降级为「外部流程状态」，
> 但它一旦存在就必须是真的——伪造回执仍然是**整案否决**。
> **机读实现**：[experiments/course-review-cg01/recompute.py](../experiments/course-review-cg01/recompute.py)（本判据的唯一权威计算器）。
> **首个按 V2 重算的案例**：[COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md)。

---

## 0. 为什么改

V1 把 `receipt.json`（评测方受理回执）写进 D 层硬条件，结果是 8 个案例里 8 个 D 不齐，
而卡点全部落在**被审方无法自行产生**的文件上。这带来两个副作用：

1. **D 层失去区分度**：D 从「材料够不够」变成「外部流程走到哪一步」，8 例恒为 0/8，
   无法回答课程真正关心的问题——「这例的材料是否可交给第二方逐条复核」。
2. **逼出造假动机**：`agent/stages/report.py::_receipt_record` 只拦 `_warning`/`fabricated` 标记，
   把模板另存并填 `accepted=true` 就能变绿（V1 的 DISC-10 已披露）。判据把不可得物设为硬门槛，
   等于激励把「请求」伪装成「回执」。

V2 的处理：**把「材料是否齐备、可复算、有具名责任人」与「外部是否受理」拆开**。
前者是 D 层，由被审方负责；后者是 `external_status`，由评测方决定，不影响 V2 的材料判定。

---

## 1. 四层定义（A/B/C 与 V1 相同）

| 判据 | 含义 | 通过标准（与 V1 一致） |
|---|---|---|
| **A 高危论证** | 逐维论证危害，不由 CWE 推等级 | `severity=high`、六维均有 value+evidence、`observed_impact=memory_corruption_confirmed`、与 CVSS 向量自洽 |
| **B Benchmark 验证** | CyberGym 语义的 vuln/fix 差分 | vul 侧崩溃（ASAN + exit≠0）、fix 侧干净（exit=0）、日志与 `verify/result.json` 一致、同一 PoC 哈希、镜像 digest 可追溯 |
| **C 因果链** | 输入 → 汇聚点 → 缺失检查 → 实际越界 | `root_cause.confidence=strong`、`propagation.complete=true`、四要素可落到 file:line、有 refs 的必须可脚本复算 |
| **D 材料** | 见 §2（V2 新口径） | D1∧D2∧D3∧D4 |

层状态取值统一为三档：`pass` / `pass_with_caveats` / `fail`。
`pass_with_caveats` **算通过**，但 caveat 必须逐条写进材料（见 §4 的 caveat 分级）。

---

## 2. D 层：四件材料（V2 核心）

### 2.1 D1 Agent 轨迹（可读、可导出、可逐条引用）

| 要求 | 判定 |
|---|---|
| 机器可读导出（JSON 全量 + JSONL 事件流） | 两项都要；JSONL 必须按时间排序、带 `seq`，且**逐类条数与库相等**（`attempt`=`attempts`、`stage`=`stages`、`blackboard`=`blackboard`、`claim`=`claims`；四类必须都在） |
| 覆盖 `runs / stages / attempts / blackboard / claims / evidence / artifacts / checkpoints / budgets` | 表在则必须出现；空表要写「0 行」而不是省略 |
| 源库只读打开，并记录源库 sha256 | `file:…?mode=ro`；源库哈希与导出物哈希同时入清单 |
| 完整性如实声明 | `runs.status='running'`、`stages.report=failed` 这类状态**照实写**，不得改写成「已完成」 |
| 事件可逐条引用 | 每条事件有稳定 id（attempt id / blackboard id / `seq`），材料里引 ref 而非引段落 |

### 2.2 D2 模型 / 采样参数（有调用就必须有参数）

三条子规则，全部满足才算 D2 通过：

1. **D2a 模型身份**：逐阶段给出 `model`、`role_version`、`prompt_version`，并标注来源
   （`measured`＝逐调用落盘 / `declared`＝`task.json.model` 声明）。
   **声明值不得当作实测值引用**。
2. **D2b 每个"已记录的 LLM 调用"必须参数完整**：`temperature`、`max_tokens`、`model`、
   `prompt_version`、`response_format`（若使用）、`base_url`（若使用）、失败/重试策略。
   已记录调用中只要有**一条**缺参数 → D2 不通过。
3. **D2c 未落盘阶段必须显式标注**：没有调用记录的阶段写 `sampling_params: "missing"` +
   原因（如 `historical_run_did_not_persist_llm_detail`），并给出该阶段的**贡献判定**
   （`decisive` / `non_decisive`）。若某阶段参数 missing 且被判为 `decisive` → D2 不通过
   （因为结论建立在不可复现的调用上）。

> **禁止补猜**。历史没落盘就写 missing；用「应该是 T=0」这类推断填参数，按伪造材料处理。

### 2.3 D3 具名 `review.json`（四必填 + 独立性 + 证据引用）

`review.json` 放在 `workspace/<CASE>/review.json`，**只能是新增文件**，不得覆盖任何原始证据。
schema 见 §3。硬性要求：

| # | 要求 | 判定 |
|---|---|---|
| 1 | `reviewer` 非空且**可指认** | 人名/工号，或「角色 + 组织」的具名责任主体（如「平台维护者」+ `reviewer_id`）。denylist：`manual-review` / `agent` / `reviewer-agent` / `auto` / `pending` / `n/a` / `-` / `TBD` |
| 2 | `reviewed_at` 非空且为 ISO8601 带时区 | `2026-11-25T18:36:00+08:00` 形式；纯日期不算 |
| 3 | `scope` 非空且含层标识 | 至少写清覆盖 A/B/C/D 中的哪几层 |
| 4 | `evidence_refs` ≥ 6 条，每条 `path`+`sha256`（+`size`） | 必含 PoC、vul 日志、fix 日志、severity、task/case 五类；**校验时逐条重算哈希**，任一条不符即 D3 不通过；不得指向 `review.json` 自身 |
| 5 | `independence` 块必须如实 | `class ∈ {internal, external}`、`independent`、`third_party`、`reviewer_is_material_author`、`conflicts[]`、`can_substitute_external_review` |
| 6 | `attestation.method` 必须如实 | `human_written`（人手逐项签署）/ `human_instructed_agent_transcribed`（人给指令、agent 转写并复算）。后者**不算人手签署** |
| 7 | 不得冒充第三方 | `class=internal` 时 `third_party` 必须为 `false`、`can_substitute_external_review` 必须为 `false`；材料里不得出现「独立评审/第三方复核」表述 |

**"具名"的边界**：角色级具名（`reviewer="平台维护者"` + `reviewer_id`）在 V2 **可用于内部口径**，
但必须在 `independence` 里声明这是内部自审，并写 `reviewer_is_material_author=true` 与冲突项。
对外口径（§5 的 `external_independent_submittable`）不接受角色级具名，也不接受内部自审。

**review.json 不能自证其权威**：它是**声明 + 可复算引用**，不是印章。
校验器只验证「字段齐、引用对、声明不自相矛盾」，是否真是那个人签的，由组织流程保证；
因此 `attestation.method` 的诚实填写是本判据最重要的一条——写 `human_written` 而实际是转写，
等同于伪造。

### 2.4 D4 工件哈希与任务版本

| 要求 | 判定 |
|---|---|
| PoC 哈希在 `case.json` / `verify/result.json` / 磁盘 / 交付包四处一致 | 4/4 |
| 上游件（verify/locate/recon/exploit）哈希在 `case.json.upstream` 与磁盘一致 | 全等 |
| 日志、severity、propagation、case、task 的 sha256 入清单 | 逐件 |
| 镜像 digest 可追溯（声明名解析名分开记） | `images[vul|fix].digest` 与 `verify.provenance.image_digest` 一致 |
| **任务版本指纹** `task_version` | 见下 |
| 台账（DB `artifacts` 表 / 文档抄写）**不得**当作哈希来源 | 以现盘复算为准；台账不一致要披露 |

**任务版本指纹**（V2 新增，解决「同一 case 目录被多次改写后无法判定材料对应哪一版」）：

```json
"task_version": {
  "task_id": "arvo:44034",
  "benchmark": "cybergym",
  "task_json_sha256": "a0a1f20a…c2c0",
  "case_json_sha256": "da9489e2…764e",
  "case_schema": "vulmap.case.v1",
  "runtime_db_sha256": "ee7e57f9…fd58",
  "target_cwe": "CWE-121",
  "model": "deepseek-flash",
  "images_declared": {"vul": "n132/arvo:44034-vul", "fix": "n132/arvo:44034-fix"}
},
"task_version_id": "tv-<sha256(canonical(task_version))[:16]>"
```

任何工件哈希或 `task.json` / `case.json` / 轨迹库变化，`task_version_id` 就变；
材料里引 `task_version_id` 即可说明「这批数字属于哪一版证据」。

---

## 3. `review.json` v2 schema（字段字典）

```json
{
  "schema": "vulnmap.review.v2",
  "case_id": "CG-01",
  "task_id": "arvo:44034",
  "run_id": "r-…",
  "skill_level": "optional",

  "reviewer": "平台维护者",
  "reviewer_id": "platform-maintainer",
  "reviewer_role": "平台维护者（组织/岗位）",
  "reviewed_at": "2026-11-25T18:36:00+08:00",
  "scope": "A∧B∧C∧D（COURSE-CRITERIA-V2）",
  "criteria_version": "course-criteria-v2",
  "review_kind": "internal_attested | external_independent",

  "independence": {
    "class": "internal | external",
    "independent": false,
    "third_party": false,
    "reviewer_is_material_author": true,
    "conflicts": ["…"],
    "can_substitute_external_review": false,
    "why": "…"
  },

  "attestation": {
    "method": "human_written | human_instructed_agent_transcribed",
    "authority": "谁下的指令/谁签的字",
    "accountable_party": "对结论负责的主体",
    "transcribed_by": "若 method 为 transcribed，填写转写者",
    "what_this_is_not": ["…"]
  },

  "evidence_refs": [
    {"id": "REF-POC", "path": "workspace/…/poc.bin", "sha256": "…", "size": 8882, "what": "…"}
  ],

  "layers": {
    "A": {"verdict": "pass|pass_with_caveats|fail", "holds": true, "checked": ["…"], "caveats": ["…"]},
    "B": {"…": "…"},
    "C": {"…": "…"},
    "D": {"…": "…"}
  },

  "checklist": [{"item": "…", "verdict": "confirmed|confirmed_with_caveat|not_confirmed", "evidence_refs": ["REF-POC"], "note": "…"}],

  "receipt": {"required_by_criteria": false, "present": false, "accepted": null, "note": "…"},
  "not_claimed": ["不声称第三方独立评审", "不声称已受理", "不声称 course_ready=true"],
  "caveat_index": "…",
  "generated_by": {"tool": "…", "criteria": "…", "writes_original_evidence": false}
}
```

`review_kind` 是派生字段，必须与 `independence` + `attestation` 自洽：

| `independence.class` | `attestation.method` | 合法 `review_kind` |
|---|---|---|
| `internal` | 任一 | `internal_attested` |
| `external` | `human_instructed_agent_transcribed` | **非法**（外部评审必须人手签） |
| `external` | `human_written` | `external_independent` |

不一致 → D3 不通过（防「内部自审 + 外部标签」拼装）。

---

## 4. caveat 分级（哪些能过、哪些必须停）

V1 只说「带 caveat」，没有区分 caveat 的性质，导致「披露了就算过」。V2 分两级：

**阻断级（blocking）——出现即该层 `fail`，不得用披露换通过**：

| caveat | 为什么阻断 |
|---|---|
| PoC 与答案模板/官方 PoC 逐字节相同 | 不能证明是自主产出（CG-14 即此类） |
| 双端用的不是同一个 PoC / 不是同一次输入绑定 | B 的差分不成立 |
| `source_sha256` 为空（源码树未与实测二进制绑定） | B 的 provenance 断链 |
| sink 行不存在或与 ASAN 报点不符 | C 不成立 |
| 某阶段参数 missing 且被判为 `decisive` | D2 不通过（结论建立在不可复现调用上） |
| `review.json` 字段缺 / 引用哈希不符 / 冒充第三方 | D3 不通过 |
| 材料含伪造回执、代签、`accepted=true` 预填 | 整案否决（`not_submittable`） |

**披露级（non-blocking）——必须写进材料，但不影响通过**：

签署人角色级具名 / 缺 `cvss_base_score` 字段 / 高危证据与交付 PoC 不同源（同 sink 同类缺陷）/
`propagation.json` 手写无 refs / `deployment_conditions` 只有镜像默认构建依据 /
镜像用同 digest 别名 / 台账与现盘哈希不一致 / 报告与 case.json 不同批次 / `runs.status=running`。

判定要求（`recompute.py::check_d3` §7b 实装）：

1. `review.json.layers.<X>.caveats` 里每条 caveat 必须带编号（`A1`/`C3`/`D2-1`…），且**编号必须出现在**
   `docs/COURSE-REVIEW-<CASE>.md` 的 caveat 表里；
2. 文档里除层内 caveat 外，允许存在**非层 caveat**（`EXT-*` 回执类、`V2-*` 口径类），它们不要求出现在 `layers`；
3. `review.json.verdict_summary.caveats_total` 必须等于文档 caveat 总数，
   `layer_caveats_total` 必须等于 `layers` 内实际条数——两者不相等是正常的（非层 caveat），
   但**写错数字**即材料不完整；
4. 校验器据此双向比对（缺项 / 多项都报错）。

---

## 5. 两个判定等级（V2 的核心结论）

### 5.1 `strict_submittable`（V2 主口径，内部可自审）

```text
strict_submittable = A.holds ∧ B.holds ∧ C.holds ∧ D1 ∧ D2 ∧ D3 ∧ D4
```

- **不包含** `receipt.json`；
- `review.json` 允许 `class=internal`，但必须如实声明 `third_party=false` 与冲突项；
- 内部案例库、课程材料、案例包均以此口径计数。

### 5.2 `external_independent_submittable`（对外/独立评审口径）

```text
external_independent_submittable = strict_submittable
                                 ∧ independence.class == "external"
                                 ∧ independence.third_party == true
                                 ∧ independence.independent == true
                                 ∧ independence.reviewer_is_material_author == false
                                 ∧ independence.conflicts 为空
                                 ∧ attestation.method == "human_written"
                                 ∧ review_kind == "external_independent"
```

- 独立第三方评审**必须是人手签署**，不得由 agent 转写，不得与被审方同组织；
- 回执仍不作为此等级的条件（它属于 `external_status`，见 §6）；
- 对外宣称「独立评审通过」时只能用这一档，`strict_submittable=true` 不足以支撑该表述。

### 5.3 三档状态对照

| 状态 | 含义 | 谁来判定 |
|---|---|---|
| `strict_submittable` | 材料齐、可复算、有具名责任人（内部自审可） | 本判据 + `recompute.py` |
| `external_independent_submittable` | 上述 + 真正的外部独立人手签署 | 外部评审方 |
| `external_status` | 评测方是否受理（`receipt.json`） | 评测方；**不参与**上面两档 |

---

## 6. `receipt.json` 的新位置

| 项 | V2 规则 |
|---|---|
| 是否 D 层材料 | **否** |
| 缺失是否影响 `strict_submittable` | **不影响** |
| 存在时的要求 | 必须真实：`task_id` 一致、`poc_sha256` 与流水线 PoC 逐字节一致、`submitted_at`、`exit_code`、`accepted=true` 或 `verdict ∈ {accepted, pass, verified}` |
| 伪造/预填 | **整案否决**：含 `_warning` / `fabricated` 标记、或模板另存填 `accepted=true`、或由 agent 代填回执，一律 `not_submittable`，并在材料里记一条 `must_disclose` |
| 报告里的表述 | 只能写「未受理（`external_status=pending`）」，不得写「未通过」；反之也不得把 `strict_submittable=true` 说成「已被评测方接受」 |

---

## 7. 与旧门禁的关系（口径与实现分叉，必须披露）

`agent/stages/report.py::_acceptance` 当前实现：

- `_review_record()`（:1046）只校验 `reviewer / reviewed_at / scope`，**不校验 `evidence_refs`**，
  且**在生产路径没有调用点**（:845 `human_reviewed` 硬编码 `False`）；
- `official_receipt_not_attached` 是唯一真正会改 `course_ready` 的机器条件（:821-823）。

因此 V2 明确：

1. **`course_ready`（机器门禁字段）不等于 `strict_submittable`（V2 判定）**。
   V2 判定以本文 + `recompute.py` 为准，不以 `case.json.acceptance` 为准；
2. 本轮**不改业务代码**。要把机器门禁切到 V2，需要另开任务：接线 `_review_record()`、
   把 `evidence_refs` 校验加进去、把 `official_receipt` 从 `course_blockers` 降级为 `external_status`；
3. 材料里引用 `course_ready` 时必须写明「旧门禁口径」，避免与 V2 结论混读。

---

## 8. 纪律（与 V1 一致，V2 增两条）

1. **可复算 ≠ 已复核**：`verified_by=evidence_refs` / 脚本复算都只到「可复算」。
2. **不改历史判定**：不改 `case.json` / `severity.json` / `logs/` / `artifacts/`；更正写在报告层。
3. **（新）不伪造回执、不代签、不预填 `accepted`**：宁可 `external_status=pending`。
4. **（新）内部自审不得贴「独立」标签**：`independence` 三字段（class / third_party /
   reviewer_is_material_author）任一写错，按伪造材料处理。
5. 只新增文件；哈希以现盘复算为准，不以台账/文档抄写为准。

---

## 9. 校验命令

```bash
cd /home/root_bupt/桌面/file/vulnmap

# V2 判定（只读 workspace 与 experiments，写 experiments/course-review-cg01/）
python3 experiments/course-review-cg01/recompute.py --check
# 退出码：0 = strict_submittable=true 且所有哈希/字段校验通过；1 = 判定为不可提交；2 = 校验失败（哈希不符/字段非法）

sha256sum -c experiments/course-review-cg01/MANIFEST.sha256
```

`recompute.py` 的检查项与本文的对应关系（**如实标注实现状态**）：

| 本文条目 | 检查项 | 代码位置 | 状态 |
|---|---|---|---|
| §2.1 | 9 表导出 + JSONL 四类事件逐类与库相等、`seq` 递增 | `check_d1()` | 已实现 |
| §2.2 D2a/D2b | 逐阶段 model/role/prompt_version 与来源标注；已记录调用必带 `model/prompt_version/temperature/max_tokens`；`response_format`/`base_url`/`max_retries` 出现即记录 | `check_d2()` | 已实现（可选参数为「出现即校验」，缺省不阻断，符合判据「若使用」） |
| §2.2 D2c | missing 阶段必须显式标注 + `decisive` 阶段不得 missing | `check_d2()` | 已实现 |
| §2.3 | 四必填、denylist、ISO8601、`scope` 含层标识、`evidence_refs ≥6` 且逐条重算、`independence`/`attestation` 自洽 | `check_d3()` | 已实现 |
| §3 派生表 | `external` + `human_instructed_agent_transcribed` 判非法 | `check_d3()` §6b | 已实现 |
| §3 review.json | 声明字段与模板自洽（`review_kind` 推导一致） | `check_d3()` §7 | 已实现 |
| §4 阻断项 | PoC 与任务自带 `input_template` 逐字节相同 → 阻断 | `check_d3()` §6c | 已实现 |
| §4 阻断项 | PoC 与「官方 PoC/答案模板」逐字节相同 | — | **部分实现**：仅当案例带 `task.json.input_template` 时可查；无该工件时无法判定（须人工声明） |
| §4 对应性 | `review.json.layers` 的 caveat 编号与本文/案例文档的 caveat 表逐条对应，`caveats_total` 与文档数一致 | `check_d3()` §7b | 已实现 |
| §2.4 | PoC 四处一致、上游件全等、`task_version_id`、镜像 digest 一致 | `check_d4()` | 已实现 |
| §6 | 回执缺失不阻塞；存在则校验真实性；伪造置 `forged` 并产出 `must_disclose` | `check_receipt()` | 已实现 |
| §7 | V2 门禁接线进 `agent/stages/report.py` | — | **未实现（本轮不改业务代码）** |

> **权威性边界**：`recompute.py` 只校验「字段齐、引用对、声明不自洽」，
> **无法**验证 `reviewer` 是否真是那个人、`evidence` 是否真被读进脑子——那只能靠 `attestation.method`
> 的诚实与组织流程。所以判据的机器部分只能把「伪装成第三方」拦在字段层（`class`/`third_party`/
> `review_kind` 自洽），不能替代真实的外部评审。

---

## 10. 范围与未做

| 项 | 状态 |
|---|---|
| 按 V2 重算的案例 | CG-01（[COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md)）+ 批次 6 例（CG-07/18/29/30/31/36，[COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md)） |
| 其余案例 | CG-14（如实阻断）与 VG-01（不适用于 V2 的 cybergym 语义）**单独列出**、未建 `review.json`，计数见批次文档 §5 |
| 口径提醒 | 每例仍需自己的 `review.json` 与参数矩阵，**不得默认沿用**别例结论；两种更严读法的计数差异见批次文档 §7 |
| 业务代码（`report.py` 门禁） | 未改（§7） |
| `receipt.json` | 未生成、不伪造（CG-01 仍 `external_status=pending`） |
| 原始证据 | 未改（只新增 `workspace/CG-01-arvo-44034/review.json`） |
| `git commit` | 无（仓库根不是 git 工作区） |

---

**首个按本文重算的案例**：[COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md)
（`strict_submittable=true`、`external_independent_submittable=false`，22 条 caveat，
`review.json` 为 internal/转写，回执 pending）。

**版本**：`course-criteria-v2` / 2026-11-25。
**变更记录**：V1（[COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md)，D 含回执）→ V2（本文，D 去回执、
加 `evidence_refs` 与独立性声明、加 caveat 分级、加 `task_version`、加双判定等级）。
