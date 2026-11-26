# CG-01 重审（`COURSE-CRITERIA-V2`）：A∧B∧C∧D 逐层结论

> **一句话结论**：按 V2 口径（D 层不再要求 `receipt.json`），CG-01 的 **A∧B∧C∧D 全部成立**（带 caveat），
> **`strict_submittable = true`**；但复核方是**平台维护者本人的内部自审**（`independence.class=internal`、
> `third_party=false`、`attestation.method=human_instructed_agent_transcribed`），
> 因此 **`external_independent_submittable = false`**——对外不得表述为「第三方/独立评审通过」。
> **`receipt.json` 不存在、未伪造**，`external_status = pending`（V2 下不计入 D 层）。
>
> 机读：[judgments.v2.json](../experiments/course-review-cg01/evidence/judgments.v2.json)、
> [verification.json](../experiments/course-review-cg01/evidence/verification.json)、
> [task_version.json](../experiments/course-review-cg01/evidence/task_version.json)、
> [review.json](../workspace/CG-01-arvo-44034/review.json)（新增；2026-11-25 19:34 按 `restored_from` 恢复，原 `sha256 03adbef6…d72` → 现 `8055337…f2b`，见 §5.3.1）。
> 判据：[COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md)。
> 计算器：[recompute.py](../experiments/course-review-cg01/recompute.py)（`--check` 只算不写；退出码 0/1/2）。

---

## 0. 三行状态

| 项 | 值 |
|---|---|
| 案例 | `CG-01` / `arvo:44034` / cybergym / ghostpdl / CWE-121（stack-buffer-overflow） |
| 任务版本 | `task_version_id = tv-f1829399fda8190c`（绑定 `task.json` / `case.json` / 轨迹库 三哈希，见 §3） |
| 判定 | A `pass_with_caveats` · B `pass_with_caveats` · C `pass_with_caveats` · D1-D4 全部 `pass_with_caveats` → **`strict_submittable=true`**；`external_independent_submittable=false` |
| **复核性质** | **内部自审（`independence.class=internal`，非第三方）**；`attestation.method=human_instructed_agent_transcribed`（人下指令、agent 转写），**不是人手签署**。这一列必须随判定一起引用，摘录判定而不摘录本列即为断章取义 |

```text
strict_submittable              = true     （A∧B∧C∧D1∧D2∧D3∧D4）
external_independent_submittable = false    （复核是内部自审，不是第三方）
external_status                 = pending   （receipt.json 不存在；V2 不要求，也不伪造）
verdict                         = strict_submittable
blockers                        = []
caveats                         = 22 条（blocking 0）
```

---

## 1. 本轮做了什么（增删边界）

| 项 | 动作 |
|---|---|
| 判据 | **新写** [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md)：D 层改为「轨迹 + 模型/采样参数 + 具名 `review.json` + 工件哈希」，回执降级为 `external_status` |
| 复核记录 | **新增** `workspace/CG-01-arvo-44034/review.json`（`schema=vulnmap.review.v2`，此前不存在） |
| 重算器 | **新增** `experiments/course-review-cg01/recompute.py`（只读 workspace，写本目录） |
| 判定 | **新算** `strict_submittable=true` / `external_independent_submittable=false` |
| `receipt.json` | **不生成**：未获评测方受理，预填 `accepted=true` 即伪造 |
| 原始证据 | **未改**：`workspace/CG-01-arvo-44034/**` 下 `case.json`（含 `.bak-regate`）、`severity.json`、`propagation.json`、`logs/`、`artifacts/`、`task.json`、`.runtime/vulnmap.db` 一律原样（逐字节复核 13/13） |
| `workspace/` 其他目录 | **不在本轮范围**：如 `workspace/CG-04-arvo-10400/` 有 18:27 的探针文件，属并行会话，与本案例无关 |
| `experiments/course-sample-cg01/**` | **只读**（13 件 + 清单，本轮逐件复算 13/13 一致） |
| 业务代码 | **未改**（`agent/stages/report.py` 的 `_review_record` 未接线问题仍在，见 §7.4） |
| `git commit` | **无**（仓库根不是 git 工作区：`git status` → `fatal: 不是 git 仓库`） |

复算过的只读命令：`sha256sum` / `stat`、SQLite `file:…?mode=ro`、`docker images` 与 `docker image inspect`、
源码逐行 `awk`。**没有 `docker run`**——本轮 live 双端数据沿用 2026-11-25 18:13 那次的原始 stderr（有哈希留档），
未重新产生。

---

## 2. A 层：高危论证 — `pass_with_caveats`

| 检查 | 结果 |
|---|---|
| `severity=high` | ✅ |
| 六维均有 value + evidence | ✅ 6/6（attack_vector=network、privileges_required=none、user_interaction=required、observed_impact=memory_corruption_confirmed、reachability_evidence=confirmed、deployment_conditions=default_build） |
| `observed_impact` 与 sanitizer 一致 | ✅ ASAN `stack-buffer-overflow` |
| CVSS 向量 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **CVSS 3.1 base 复算** | **8.8**（ISS 0.9148 → Impact 5.8731；Exploitability 2.8353；raw 8.7084 → roundup 8.8） |
| `cvss_base_score` 字段 | ❌ 不存在（只有向量；未回填原始文件） |

**caveat**（不阻断，必须披露）：见 §5 的 `A1`–`A4`。其中最实质的是 **A3**：
`severity.json` 的 `observed_impact.evidence` 写 `WRITE of size 5575`，该数字与
[error.txt:9](../workspace/CG-01-arvo-44034/error.txt) 的**另一处崩溃**逐字同源（名长 5575）；
交付 PoC `pdf-basefont4096.bin` 的名长是 **4096**，vul 日志与 live 复跑都是 `WRITE of size 4096`。
同 sink（`pdf_font.c:332`）、同类缺陷（栈写越界）、长度均由输入控制 → **高危结论不变**，
但「高危证据」与「交付 PoC」**不是同一次输入**，引用时必须分别写清两个数字的来源。

---

## 3. B 层：Benchmark 双端差分 — `pass`

| 项 | 值 |
|---|---|
| vul | `exit=1` + ASAN `stack-buffer-overflow`、`WRITE of size 4096`、对象 `[32,4128) 'fontfname' (line 171)`、首个用户帧 `pdfi_open_CIDFont_substitute_file /src/ghostpdl/./pdf/pdf_font.c:332:9` |
| fix | `exit=0`、无 ASAN（日志 925 B，唯一 `error` 命中是命令行里的 `ASAN_OPTIONS=abort_on_error=1`） |
| 输入 | 同一 PoC `58f7f4b3…c59d` / 8882 B，四处（磁盘 / `case.json.poc` / `verify.poc` / `candidates[0].input_sha256`）一致 |
| provenance | `matches=true`；`binary_sha256=bb7a2341…1114`；`source_sha256=bf2bd446…cca` ＝ `repo-vul.tar.gz` 现盘哈希；`image_digest=sha256:e57980e7…aef` 在 `case.json.images` 中 |
| 上游四件 | 4/4 与现盘一致（verify `62623dcb…`、locate `c51c8429…`、recon `6d062826…`、exploit `7233941a…`） |
| 两次运行 | 记录运行（2026-11-21 `SMOKE-CG-01-close-20261121`）+ live 复跑（2026-11-25，stderr 6817 B / 614 B）。归一化后 vul 侧 98 行 0 差异、fix 侧 11 行 0 差异（归一化＝去 5 行 wrapper + 掩码地址/`INFO: Seed:`/执行耗时；该数字来自 [evidence/recompute.json](../experiments/course-sample-cg01/evidence/recompute.json)，本轮未重算，`recompute.py` 只比对 `write_size` 与 `has_asan`） |
| 镜像 | `n132/arvo:44034-vul` = `sha256:e57980e7…aef`（存在）；`dockerproxy.net/n132/arvo:44034-fix` = `sha256:5d428e8f…aa9`（存在） |

**caveat**：`B1`（fix 侧声明名本机无 tag，日志命令行写的正是该声明名 → 该日志来自当时存在该 tag 的环境）、
`B2`（11-10 那次 fix 运行的镜像 tag 已不可回溯）。

---

## 4. C 层：因果链 — `pass_with_caveats`

| 要素 | 断言 | 源码实测（本轮逐行打开） |
|---|---|---|
| 输入 | PoC `/BaseFont` 名长 4096，完全由输入控制 | PoC 8882 B；`/BaseFont` 出现 **2 次**（偏移 278 / 4561），名长均 **4096** |
| 缓冲 | `char fontfname[gp_file_name_sizeof]` | [pdf_font.c:171](../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c)；[gp.h:382](../workspace/CG-01-arvo-44034/src/ghostpdl/base/gp.h) `#define gp_file_name_sizeof 4096` |
| 汇聚 | `memcpy(fontfname + fsprefixlen, cidname->data, cidname->length)` | pdf_font.c [:168](../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c) 函数入口 → [:332](../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c) 写点 |
| 缺失检查 | 同函数 Registry/Ordering 分支有上限检查，BaseFont 分支没有 | [:189](../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c) `csi_reg->length + csi_ord->length + 1 < gp_file_name_sizeof - 1`；:332 无任何上限校验 |

算术闭合：

| 量 | 值 |
|---|---|
| 缓冲 | 4096 B（ASAN 对象 `[32,4128)`） |
| 前缀 `"CIDFont/"` | 8 B |
| memcpy 写区间 | `[8,4104)` → 越过对象末尾 **8 B**（4096..4103） |
| `:333` 的 NUL | 偏移 **4104**（末尾之后第 9 字节）→ 合计越过 **9 B** |
| 安全上限 | `cidname->length ≤ 4087` |
| ASAN 实测写长 | 4096（= 名长，与算术一致） |

**caveat**：`C1`（`propagation.json` 是 11-10 手写档案：`source=manual_review_of_source`、
`verified_by=manual`、无 `refs` 字段 → 可人工读、不可脚本复算）、`C2`（本轮的 file:line 映射是新做的机器映射，
不是复核）、`C3`（PoC 含两处同模式触发串）、`C4`（越界口径 8 B vs 9 B）。

---

## 5. D 层：材料 — `pass_with_caveats`

### 5.1 D1 Agent 轨迹（可读、可导出、可逐条引用）

| 项 | 值 |
|---|---|
| 源库 | `.runtime/vulnmap.db`，86016 B，`sha256 ee7e57f9…fd58`，以 `file:…?mode=ro` 只读打开 |
| 导出 | [trajectory.json](../experiments/course-sample-cg01/evidence/trajectory.json)（9 表全量 + `llm_matrix`）、[trajectory.jsonl](../experiments/course-sample-cg01/evidence/trajectory.jsonl)（23 条，`seq` 递增） |
| 表行数 | runs 1 / stages 5 / attempts 7 / blackboard 10 / claims 1 / evidence 2 / artifacts 6 / checkpoints 4 / budgets 5 —— 与库逐表相等 |
| JSONL 覆盖 | attempt 7/7、stage 5/5、blackboard 10/10、claim 1/1（逐类与库相等） |
| 如实记录的状态 | `runs.status='running'`（未收口）；`stages.report='failed' @ 2026-11-15T11:21:22Z`（`ImageMissing`，未产生 attempts 行） |

### 5.2 D2 模型 / 采样参数

| stage | model | 来源 | prompt_version | 采样参数 | 贡献 |
|---|---|---|---|---|---|
| recon | `deepseek-flash` | 声明（`task.json.model`） | `recon-p1` | **missing**（历史未落盘） | non_decisive |
| locate | `deepseek-flash` | **实测**（`attempts.detail.llm.params`） | `locate-p1` / LLM 子调用 `locate-llm-p1` | **完整**：`temperature=0.0`、`max_tokens=1200`、`disable_thinking=true`、`response_format=json_object`、`max_retries=1`、`base_url=https://api.deepseek.com/v1` | non_decisive（提案被拒） |
| verify | `deepseek-flash` | 声明 | `verify-p1` | **missing** | non_decisive |
| exploit | `deepseek-flash` | 声明 | `exploit-p1` | **missing** | non_decisive |
| report | `deepseek-flash` | 声明 | `report-p1` | **missing** | non_decisive |

- **已记录的 LLM 调用 1/1 参数完整**（locate）；
- 4 个阶段 missing 已显式标注原因（`historical_run_did_not_persist_llm_detail`），**本轮不补猜**；
- 贡献判定依据：`case.json.model_contribution.final_subject_from="rule"`、唯一提案 `cid_fallback` 被校验拒绝
  （`function_not_found`）、`verified_pinpoint=false` → 全部阶段 `non_decisive`，故 D2 通过。
- **唯一一次 LLM 调用**：tokens 347（prompt 291 / completion 56 / reasoning 0）、`finish_reason=stop`、
  提案 `functions=["cid_fallback"]`、`files=["ghostpdl/base/aes.c"]`、confidence 0.2 → `accepted=false`。
  **不能说「LLM 定位了漏洞」**。

### 5.3 D3 具名 `review.json`（**内部自审 / agent 转写**，本轮新增）

| 字段 | 值 |
|---|---|
| 文件 | `workspace/CG-01-arvo-44034/review.json`，**16901 B**，`sha256 805533706580ddfa01ed18b1151423f699dca656c9abf9fe80c27cfcaf799f2b`（原 16807 B / `03adbef6…d72`；**现为 `restored_from` 重建件**，见 §5.3.1） |
| `reviewer` / `reviewer_id` | `平台维护者` / `platform-maintainer`（角色级具名：本仓库所有者/运维责任方） |
| `reviewed_at` | `2026-11-25T18:36:00+08:00` |
| `scope` | `A∧B∧C∧D（COURSE-CRITERIA-V2）` |
| `evidence_refs` | **16 条**，逐条 `path + sha256 + size`，校验器逐条重算（16/16 一致）；覆盖 16 类：PoC、`verify/result.json`、vul 日志、fix 日志、severity、propagation、case、task、description、error、patch、轨迹库、轨迹导出 2 件（JSON/JSONL）、live 复跑 2 件（vul/fix） |
| `independence` | `class=internal`、`independent=false`、`third_party=false`、`reviewer_is_material_author=true`、`can_substitute_external_review=false`，冲突项 3 条已列 |
| `attestation` | `method=human_instructed_agent_transcribed`（维护者下指令、agent 转写并逐项复算）；`accountable_party=平台维护者` |
| `review_kind` | `internal_attested`（与 `independence`/`attestation` 推导值一致；校验器会拒收 `external` + 转写的非法组合） |
| `receipt` | `required_by_criteria=false`、`present=false`、`accepted=null`（`caveats_total=22`、`layer_caveats_total=20`，与本文 §7 对齐并由 `recompute.py` 校验） |
| `not_claimed` | 6 条：不声称第三方独立评审 / 不声称已受理 / 不声称 `course_ready` / 不声称课程方认可 / 不声称 LLM 定位漏洞 / 不声称 missing 参数曾落盘 |

#### 5.3.1 恢复说明（`restored_from`，2026-11-25 19:34）

原文件在 18:39 之后从磁盘消失：`sha256sum -c MANIFEST.sha256` 第 7 项报缺失，
`recompute.py --check` 判 `D3 fail`、`strict_submittable=False`（当时可复算 4/8 而非文档口径 5/8）。
本轮**只重建派生复核记录**，脚本 [`restore_review.py`](../experiments/course-review-cg01/restore_review.py)：

| 项 | 值 |
|---|---|
| 来源（全部已落盘） | `evidence/verification.json # D3_review`（18:36 从原文件读出的字段快照）、`evidence/review_refs.json`（16 条 refs）、`evidence/judgments.v2.json`（caveat id/文本）、`manifest.json`（原 sha256/大小）、本文件 §5.3/§7 |
| 逐字保留 | `reviewer` / `reviewer_id` / `reviewed_at` / `scope` / `criteria_version` / `review_kind`；`independence` 全字段；`attestation.method` 与 `accountable_party` / `transcribed_by`；16 条 `evidence_refs`（现盘逐条重算 **16/16** 一致）；20 条层内 caveat 编号与文本；`caveats_total=22`、`layer_caveats_total=20` |
| 重建（措辞不保证逐字） | `checklist`（6 条）、`not_claimed`（6 条）、`reviewer_role`、`attestation.authority` / `what_this_is_not`、`layers.D.parts` |
| 字节等价 | **否**——`16807 B/03adbef6…d72` → `16901 B/8055337…f2b`；差异原因写在 `restored_from.divergence` |
| 恢复后复算 | `recompute.py` 退出码 **0**：`D3 pass_with_caveats`、`strict_submittable=true`、`blockers=[]`、`MANIFEST.sha256` 7/7 通过 |
| **没有做** | 没有新增签署人、没有把 `class` 改成 `external`、没有把 `attestation.method` 改成 `human_written`、没有生成 `receipt.json`、没有预填 `accepted` |

> 与「凭空补一份复核记录」的区别：本件字段**逐项可追到已落盘产物**，且差异（字节不等价、重建字段清单）
> 写在记录内部；原始证据零改动。因此它恢复的是 D3 材料的**可复算性**，不改变复核性质——
> `external_independent_submittable` 仍为 **false**，对外仍不得称「第三方/独立评审通过」。

**这份复核的权威边界（必须照抄，不得省略）**：

1. 它是**内部自审**——复核方就是材料所有方，`third_party=false`，**不能冒充第三方**；
2. 它是**人下指令、agent 转写**（`human_instructed_agent_transcribed`），**不是人手逐项签署**（`human_written`）；
3. 因此它支撑 `strict_submittable`（内部口径），**不支撑** `external_independent_submittable`；
4. 它**不回溯改写** `case.json`：旧字段 `human_reviewed` 仍是 `false`、`course_ready_blocked_by` 仍是
   `["official_receipt_not_attached"]`（V2 判定不读取这两个字段，见 §7.4）。

### 5.4 D4 工件哈希与任务版本

| 项 | 值 |
|---|---|
| PoC | `58f7f4b3…c59d` / 8882 B，四处一致 |
| vul 日志 | `79458c59…6065` / 7128 B |
| fix 日志 | `b098e5c4…5476` / 925 B |
| `severity.json` | `7e0cd22d…1416` / 1111 B |
| `propagation.json` | `5b4fbdc5…d1e2` / 1493 B |
| `case.json` | `da9489e2…764e` / 6908 B |
| `task.json` | `a0a1f20a…c2c0` / 337 B |
| 轨迹库 | `ee7e57f9…fd58` / 86016 B |
| `repo-vul.tar.gz` | `bf2bd446…cca` / 73709408 B（＝ `verify.provenance.source_sha256`） |
| 镜像 digest | vul `sha256:e57980e7…aef` / fix `sha256:5d428e8f…aa9`（与 `verify.provenance.image_digest` 一致） |

**任务版本指纹**（V2 新字段）：

```json
{"task_id":"arvo:44034","benchmark":"cybergym","case_schema":"vulmap.case.v1",
 "task_json_sha256":"a0a1f20a…c2c0","case_json_sha256":"da9489e2…764e",
 "runtime_db_sha256":"ee7e57f9…fd58","target_cwe":"CWE-121","model":"deepseek-flash",
 "images_declared":{"vul":"n132/arvo:44034-vul","fix":"n132/arvo:44034-fix"}}
→ task_version_id = tv-f1829399fda8190c
```

### 5.5 `receipt.json`：不存在，也不伪造

| 项 | 值 |
|---|---|
| 是否 D 层材料 | **否**（V2） |
| 现状 | 文件不存在；`review.TEMPLATE.json` / `receipt.TEMPLATE.json` 仍是全 null 模板（mtime 均 11-10 18:10） |
| `external_status` | `pending` |
| 对外提交 | 仍需评测方受理后由其回填；预填 `accepted=true` 视为伪造 → 整案否决 |

---

## 6. 重算结果（V2 两档）

| 层 | 状态 | 成立 | 关键证据 | 不能算「已签/已对外」的理由 |
|---|---|---|---|---|
| **A** | `pass_with_caveats` | ✅ | 六维 + CVSS 8.8 复算 + ASAN `memory_corruption_confirmed` | `reviewed_by="manual-review"`、无 `cvss_base_score`、5575 与 4096 不同源 |
| **B** | `pass_with_caveats` | ✅ | 记录运行 + live 复跑；vul 1 / fix 0；同输入；provenance 四处一致 | fix 声明名本机无 tag（用同 digest 别名） |
| **C** | `pass_with_caveats` | ✅ | 四要素落 file:line；算术闭合（8 B memcpy + 1 B NUL）；ASAN `[32,4128)` | 手写 propagation 无 refs；映射是新做的机器映射 |
| **D1** | `pass_with_caveats` | ✅ | 9 表全量导出 + JSONL 23 条（逐类与库相等） | `runs.status=running`、`stages.report=failed` |
| **D2** | `pass_with_caveats` | ✅ | 唯一 LLM 调用参数完整；4 阶段 missing 已标注且 `non_decisive` | 4 阶段参数历史上未落盘 |
| **D3** | `pass_with_caveats` | ✅ | 具名 review.json，16 条 refs 逐条复算一致 | **复核人＝材料作者本人**（internal 自审）+ agent 转写，非第三方、非人手签 |
| **D4** | `pass_with_caveats` | ✅ | 工件哈希 + `task_version_id` 绑定 | case.json 三变体不一致（D4-1）、review.json 不回写 case.json（D4-2） |

```text
strict_submittable              = true
external_independent_submittable = false
external_status                 = pending
verdict                         = strict_submittable
blockers                        = []
```

**两档差异只有一处**：D3 的 `independence` / `attestation`。
要拿到 `external_independent_submittable=true`，必须另找**与本平台无组织关系的具名人类**，
用 `independence.class=external / third_party=true / reviewer_is_material_author=false / conflicts=[]`
且 `attestation.method=human_written` 重新签署；**不能用现有这份记录改字段冒充**。

---

## 7. 全部 caveat（22 条，blocking 0）

### 7.1 A 层

| id | caveat |
|---|---|
| `A1` | `severity.json.reviewed_by="manual-review"` 不是具名责任人，无法从该文件证明签署人 |
| `A2` | 缺 `cvss_base_score` 字段（复算 8.8，未回填原始文件） |
| `A3` | `observed_impact` 的 `WRITE of size 5575` 出自 `error.txt:9` 的另一处崩溃（名长 5575）；交付 PoC 名长 4096、日志 4096 → 高危证据与交付 PoC 不同源；同 sink 同类缺陷，结论不变 |
| `A4` | `deployment_conditions=default_build` 依据是镜像默认构建即复现，未含生产侧调用点证据 |

### 7.2 B / C 层

| id | caveat |
|---|---|
| `B1` | fix 侧本机解析名是 `dockerproxy.net/n132/arvo:44034-fix`（同 digest 别名）；声明名 `n132/arvo:44034-fix` 本机无 tag，而 fix 日志命令行写的正是该声明名 |
| `B2` | 11-10 那次 fix 运行只留日志，当日镜像 tag 已不在本机，该次运行镜像名不可回溯 |
| `C1` | `propagation.json` 无 refs 字段（`verified_by=manual`）：可人工读、不可脚本复算 |
| `C2` | 本轮 file:line 映射与哈希是新做的机器映射，不是第三方复核 |
| `C3` | PoC 含 **2 处** `/BaseFont` 触发串（偏移 278 / 4561，名长均 4096）→ 不可描述为「单触发点」 |
| `C4` | 越界口径：memcpy 8 B（4096..4103）+ `:333` NUL@4104 = 合计 9 B；只写 8 B 会漏掉 NUL 那 1 B |

### 7.3 D 层

| id | caveat |
|---|---|
| `D1-1` | `runs.status='running'`（`run_summary.json` 写 done）：轨迹完整性以 attempts/stages 为准 |
| `D1-2` | `stages.report='failed' @ 2026-11-15T11:21:22Z`（`ImageMissing`，未产生 attempts 行） |
| `D2-1` | recon/verify/exploit/report 四阶段采样参数历史未落盘，按 missing 标注，不补猜 |
| `D2-2` | 只有 locate 一条 LLM 调用有逐调用完整参数 |
| `D2-3` | model 除 locate 外均为 `task.json` 声明值，非逐调用实测 |
| `D3-1` | 复核为内部自审（`internal`/`third_party=false`/`reviewer_is_material_author=true`），不满足对外独立口径 |
| `D3-2` | `attestation.method=human_instructed_agent_transcribed`：agent 转写，不是人手逐项签署 |
| `D4-1` | `case.json` 三个变体 `course_ready_blocked_by` 不一致：report 版 `["official_receipt_not_attached"]`；`.bak-regate` 与 `deliverables/case.json`（`2f07e797…`，两者字节相同）`["human_review_pending","official_receipt_not_attached"]`；`human_reviewed` 全为 false → 删字段 ≠ 复核 |
| `D4-2` | 新增 `review.json` 不回溯改写 `case.json`：`human_reviewed=false`、`course_ready_blocked_by` 仍含回执项（V2 不读这两个字段） |
| `D4-3` | `task_version_id` 绑定 `task.json`/`case.json`/轨迹库三哈希；任一变化即换版，引用时须带此 id |

### 7.4 口径 / 外部

| id | caveat |
|---|---|
| `EXT-1` | `receipt.json` 不存在（`external_status=pending`）：V2 不计入 D 层；对外提交仍需评测方受理 |
| `V2-D6` | `agent/stages/report.py::_acceptance` 的 `course_ready` 仍以 `official_receipt` 为条件（:821-823），且 `_review_record()`（:1046）**在生产路径无调用点**（:845 硬编码 `human_reviewed=False`）→ 机器门禁字段与 V2 判定分叉，**以本文件与 `judgments.v2.json` 为准** |

`V2-D6` 的实证：`case.json.acceptance` 现在是 `course_ready=false`、
`course_ready_blocked_by=["official_receipt_not_attached"]`、`human_reviewed=false`，
即使 `review.json` 已落盘也不会变化——修门禁属改业务代码，本轮**不动**。

---

## 8. 复跑与校验

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 重算 V2 判定（只读 workspace；写 experiments/course-review-cg01/）
python3 experiments/course-review-cg01/recompute.py
# 期望：strict_submittable = True / external_independent_submittable = False / exit 0

# 2) 只算不写（给复核人用）
python3 experiments/course-review-cg01/recompute.py --check

# 3) 清单校验（7 行：4 件证据产物 + README + recompute.py + review.json）
sha256sum -c experiments/course-review-cg01/MANIFEST.sha256

# 4) 反向验证：删掉 review.json 的 reviewer 再跑，应退化为 D3 fail（勿在正式路径做）
#    python3 -c "import json;p='workspace/CG-01-arvo-44034/review.json';d=json.load(open(p));d['reviewer']='';json.dump(d,open('/tmp/x.json','w'))"
```

退出码契约（V2）：`0` = `strict_submittable` 且校验通过；`1` = 判定不可提交；`2` = 校验失败
（`review.json` 字段非法 / `evidence_refs` 哈希不符 / 伪造回执 / PoC 哈希不符）。

---

## 9. 与上一版（V1）结论的差异

| 项 | V1（[COURSE-SAMPLE-CG01.md](COURSE-SAMPLE-CG01.md)） | V2（本文） | 差异原因 |
|---|---|---|---|
| D 层 | `incomplete`（缺 `review.json` + `receipt.json`） | `pass_with_caveats` | D 去回执；补具名 review.json + 参数矩阵 + 轨迹导出 |
| `strict_submittable` | `false` | **`true`** | 同上 |
| `verdict` | `needs_evidence` | **`strict_submittable`** | 同上 |
| `external_independent_submittable` | （无此概念） | `false` | 复核是内部自审 |
| A/B/C | A/C 带 caveat、B `pass`（V1 口径允许带 caveat 仍标 pass） | A/C 不变；B 改标 `pass_with_caveats` | V2 三档口径：有 caveat 即 `pass_with_caveats`；B 实质仍是「双端差分成立」 |
| 新增事实 | — | `C3`（两处触发串）、`C4`（9 B 口径）、`D4-1`（三份 case.json 分叉）、`B1` 补日志命令行证据 | 本轮独立只读复核发现 |

> V1 文档保留原样作为历史记录，不改写其结论；两者的差异只在「D 层是否要求回执」。
> 引用时必须写明用的是哪一版口径，否则 `false` / `true` 会看起来互相矛盾。

---

## 10. 未做 / 不做

| 项 | 状态 | 原因 |
|---|---|---|
| 生成 `receipt.json` | **不做** | 未受理；预填即伪造 |
| 找第三方签 `review.json` | **不做** | 需真实外部机构；agent 无法替代，也不冒充 |
| 重跑 `report`（恢复 `verified_live=true`） | **未做** | 会写 `workspace/artifacts/` |
| 改 `severity.json` 的 5575 / 补 `cvss_base_score` | **不做** | 原始证据只读；更正写在报告层 |
| 回滚 11-15 删 `human_review_pending` | **不做** | 不改历史判定；只披露（`D4-1`） |
| 修 `report.py` 的 V2 门禁接线 | **未做** | 属业务代码，另开任务 |
| 其余 7 例的 V2 重算 | **本文件未做**；其中 6 例已由 [COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md) 重算（4 true / 2 因 D2 false），CG-14 与 VG-01 单列 | 各需自己的 `review.json` 与参数矩阵，不得默认沿用 |
| `git commit` | **无** | 仓库根不是 git 工作区 |

---

## 11. 产物清单

| 文件 | 作用 | sha256 |
|---|---|---|
| [docs/COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) | 判据 V2（D 去回执、加 evidence_refs/独立性/任务版本/caveat 分级） | 见交付消息 |
| 本文件 | A/B/C/D 逐层重审 + 22 条 caveat | 见交付消息 |
| [review.json](../workspace/CG-01-arvo-44034/review.json) | D3 具名复核（**internal / 转写**，16 条 refs） | `03adbef63c3e8498b1e90ec3808b098af3ca3c91aab47cfcf7fcc7e5c8a53d72` |
| [evidence/judgments.v2.json](../experiments/course-review-cg01/evidence/judgments.v2.json) | 判定 / 两档结果 / 22 条 caveat / caveat 对齐 | 见 MANIFEST |
| [evidence/verification.json](../experiments/course-review-cg01/evidence/verification.json) | A/B/C/D1-D4 全量复算明细（38 KB） | 见 MANIFEST |
| [evidence/task_version.json](../experiments/course-review-cg01/evidence/task_version.json) | 任务版本指纹 | 见 MANIFEST |
| [evidence/review_refs.json](../experiments/course-review-cg01/evidence/review_refs.json) | review.json 的 16 条 refs 复算表 | 见 MANIFEST |
| [recompute.py](../experiments/course-review-cg01/recompute.py) | 唯一权威计算器（`--check` 只算不写） | 见 MANIFEST |
| [manifest.json](../experiments/course-review-cg01/manifest.json) / [MANIFEST.sha256](../experiments/course-review-cg01/MANIFEST.sha256) | 机读清单 + 哈希链（7 行） | 见 MANIFEST |

```bash
sha256sum -c experiments/course-review-cg01/MANIFEST.sha256   # 期望 7 行全部「成功」
```

---

## 12. 结论该怎么用（三条纪律）

1. **`strict_submittable=true` 只说明「材料齐、可复算、有具名责任人」**，不说明「已被评测方接受」，
   也不说明「第三方独立评审通过」。
2. 对外宣称必须只引用 §0 的原文；`external_independent_submittable=false` 时，
   任何「独立评审已通过」的表述都是错的（`D3-1` / `D3-2`）。
3. **可复算 ≠ 已复核**：本文件所有数字都能用 `recompute.py` 重现，但重现者是第三方还是作者本人，
   决定它属于哪一档——这正是 V2 把 `independence` 写进 schema 的原因。
