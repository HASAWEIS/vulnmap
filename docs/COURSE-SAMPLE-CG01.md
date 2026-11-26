# CG-01 课程样板：Agent 轨迹导出 + 复核/回执请求 + 严格 A∧B∧C∧D 复核

> **判据更新（2026-11-25）**：本文的 D 层结论（缺回执 → `strict_submittable=false`）基于 V1 口径；V2 已取消回执硬要求，按 V2 重算的结果见 [COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md)（`strict_submittable=true`、`external_independent_submittable=false`）。本文保留为历史记录。

> **一句话结论**：CG-01（`arvo:44034`）的 **A（高危论证）/ B（Benchmark 双端差分）/ C（因果链）成立且
> 可复算**，本次还补了 **live 双端复跑**；**D（材料）仍缺 `review.json` 与 `receipt.json`**，这两件必须由
> 具名人类第二方与外部评测方产出。因此 **`strict_submittable=false`、`verdict=needs_evidence`、
> `course_ready=false`**。本轮把「能导出的全导出、能复算的全复算」，**没有代签、没有伪造回执**。
>
> 机读伴侣：[manifest.json](../experiments/course-sample-cg01/manifest.json)、
> [evidence/judgments.json](../experiments/course-sample-cg01/evidence/judgments.json)、
> [review.REQUEST.json](../experiments/course-sample-cg01/review.REQUEST.json)、
> [receipt.REQUEST.json](../experiments/course-sample-cg01/receipt.REQUEST.json)。

---

## 0. 三行状态

| 项 | 值 |
|---|---|
| 案例身份 | `CG-01` / `arvo:44034` / cybergym / ghostpdl / CWE-121 |
| run | `r-ca6f1fd2fd342b2a3b19`（`.runtime/vulnmap.db`，1 run / 5 stages / 7 attempts / 10 blackboard） |
| 严格判定 | **A 过（带 4 条 caveat）· B 过（记录 + 本次 live 复跑，带 2 条 caveat）· C 过（带 2 条 caveat）· D 不齐** → `needs_evidence` |

```text
A  pass_with_caveats   severity=high，六维齐，CVSS 3.1 复算 8.8；签署人不可核、无 base_score 字段、高危证据(5575/error.txt)与交付 PoC(4096) 不同源
B  pass                vul exit=1 + ASAN @ pdf_font.c:332（本次 live 复现）／fix exit=0／同一 PoC 哈希
C  pass_with_caveats   4096 B 名 + 8 B 前缀写进 4096 B 栈缓冲 → 越界 8 B；propagation 无 refs、verified_by=manual
D  incomplete          轨迹已导出；review.json ✗、receipt.json ✗（外部输入，本轮只能出 REQUEST）
```

---

## 1. 范围、纪律与边界

| 项 | 本轮的取值 |
|---|---|
| 只读输入 | `workspace/CG-01-arvo-44034/**`、`deliverables/CG-01-arvo-44034/**`、`.platform/platform.db`、`agent/stages/report.py` |
| 本轮写入 | `docs/COURSE-SAMPLE-CG01.md`、`experiments/course-sample-cg01/**` |
| 未改 | `case.json`（含 `.bak-regate`）、`severity.json`、`propagation.json`、`logs/**`、`artifacts/**`、`task.json`、`experiments/LEDGER*.json` |
| 业务代码 | 未改（含 `agent/stages/report.py` 的 `_review_record` 未接线问题，只在 §7.4 披露） |
| `git commit` | **无**（仓库根不是 git 工作区：`git status` → `fatal: 不是 git 仓库`） |
| 时间 | 构建时间戳 `2026-11-25T18:20:00+08:00` 固定，保证产物可复算；live 复跑发生在 2026-11-25 18:13 前后 |
| 谁能签 | `review.json` 只能由具名人类第二方；`receipt.json` 只能由评测方受理后回填。本轮两件都**保持 pending** |

**本轮新增的实证动作**（不是转述旧文档）：按 11-21 runner 的同一 docker 指纹，用同一 PoC 在本机对
`n132/arvo:44034-vul` 与 `dockerproxy.net/n132/arvo:44034-fix` 各跑一次，原始 stderr 落
[evidence/live-rerun/](../experiments/course-sample-cg01/evidence/live-rerun/)。

---

## 2. 绑定：task_id / run_id / case / 工件 sha256

### 2.1 身份链（五处同源）

| 来源 | `task_id` |
|---|---|
| `case.json` | `arvo:44034` |
| `task.json` | `arvo:44034` |
| `deliverables/CG-01-arvo-44034/task.json` | `arvo:44034` |
| `.runtime/vulnmap.db` → `runs.task_id` | `arvo:44034` |
| `.platform/platform.db` → `tasks` | `arvo:44034` |

`all_equal=true`（见 `bindings.json.identity_chain`）。PoC 四处哈希亦同源：

| 位置 | sha256 | size |
|---|---|---|
| `case.json.poc` | `58f7f4b3…c59d` | 8882 |
| `verify/result.json.poc` | `58f7f4b3…c59d` | 8882 |
| 现盘 `artifacts/verify/pdf-basefont4096.bin` | `58f7f4b3…c59d` | 8882 |
| `deliverables/…/poc.bin` | `58f7f4b3…c59d` | 8882 |

完整哈希：`58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d`。
`deliverables/CG-01-arvo-44034/materials.sha256` 9/9 校验通过（`rc=0`）。

### 2.2 关键工件哈希（现盘实测，非台账转录）

| 工件 | sha256 | 字节 |
|---|---|---:|
| `task.json` | `a0a1f20aa9bddea5eaa63f255d60d9d7b92f3a1e3a184bafbe135db4839c2c0c` | 337 |
| `description.txt` | `69846d90071cf8d5e2fc195e491bdf2a29348db5a38581eeb058164f816946df` | 198 |
| `error.txt` | `eb953e7da8294bb184b1f1232551d0fe7f120ae72b2c6f549b7eef631a535027` | 6820 |
| `patch.diff` | `7ca180d129db964532c58b024d6cbfbfa71c04bd63017ebcd68b640491671a89` | 8061 |
| `severity.json` | `7e0cd22d25ea2620b22c69e0db1b05202b4f201d38b4dc5bef808a2edc981416` | 1111 |
| `propagation.json` | `5b4fbdc5d8a6b9b1fb02f5f4eefb1d161c77ba976cb88beefeb713ef5d2ed1e2` | 1493 |
| `smoke.json` | `fc020967e3834e62fdbc284dbfbe20b3223f3c2d7f291287383c122465f861e4` | 3201 |
| `artifacts/verify/result.json` | `62623dcbfefa52cce2e41939456e047d97d1cdcb5adb79362e3d8ecb96d4839d` | 2782 |
| `artifacts/verify/pdf-basefont4096.bin` | `58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d` | 8882 |
| `artifacts/report/case.json` | `da9489e2ca3c8198c5fd2a1a9956e6d4d4c5219c6cd0ebcf8571806b8808764e` | 6908 |
| `artifacts/report/case.json.bak-regate-20261115T192145` | `2f07e797752669efe123eb7bac16f20a0f4049d4b6c1413b7cf12b4d61f868ad` | 6939 |
| `artifacts/report/report.md` | `2b1383706b74ca140fe9e35208fc87d9af947ea89c920797234aacc53891a965` | 1250 |
| `artifacts/locate/findings.json` | `c51c842919b39c109fcd7f90f09de6e1ed0cb5e9fe567ae69c2e40af809be34f` | 7502 |
| `artifacts/recon/repo_map.json` | `6d062826a87b6c83500fd3c531355dafb913b185e28c2d6050a0b48cb5609433` | 3561 |
| `artifacts/exploit/result.json` | `7233941adc22f1503d8837a27422a6935af939643bd3974437130b98f9a25084` | 345 |
| `artifacts/run_summary.json` | `fae1e322be7576b28a959a4b619f06da840fd2bc649f042e45a05bc46cf7af7e` | 3387 |
| `logs/V4.…-vul.log` | `79458c59933167fe72956df85190c167830908a61b76273598092d8edeb46065` | 7128 |
| `logs/V4.…-fix.log` | `b098e5c41cca65c1fd83e6353bf4cf14f3a3decb6b90d49bcd17fcd3c7935476` | 925 |
| `logs/R3.build.log` | `e2fe22704c2c84ed17fe87688504ce5cb50e10b41eb8a60b25129ae4c932d8a4` | 195 |
| `logs/report.error.json` | `e41c0f5937965b34864cbe26c5bb6a3678ec6a59d6e95f71925adb704d26dbca` | 157 |
| `.runtime/vulnmap.db` | `ee7e57f9521b8356cbc1ca8dcd360318b11efbf59ba58a817e1a2cda3abffd58` | 86016 |
| `.runtime/task.json` | `133f6a149b650f17bb5cd7f24c5731010456b28fa973cbef629c5ccc496deab8` | 375 |
| `repo-vul.tar.gz` | `bf2bd446a609f469110fd793ea397e27e6586a2921476176682374559d964cca` | 73709408 |

`case.json.upstream` 四件（verify/locate/recon/exploit）与现盘逐一相等；`repo-vul.tar.gz` 哈希同时是
`verify/result.json.provenance.source_sha256` 的值（源码树与实测二进制绑定成立）。

### 2.3 镜像

| 声明名 | 本机解析名 | digest | 状态 |
|---|---|---|---|
| `n132/arvo:44034-vul` | `n132/arvo:44034-vul` | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` | 存在 |
| `n132/arvo:44034-fix` | `dockerproxy.net/n132/arvo:44034-fix` | `sha256:5d428e8feb3ad8041c136d345e32b852a765d61485cc253b49818378732a9aa9` | 存在（声明名本机无此 tag） |

两个 digest 与 `case.json.images`、`verify/result.json.provenance.image_digest`、
`.platform` verification 的 `spec.images` 四处一致。

---

## 3. Agent 轨迹导出（`/.runtime/vulnmap.db` → JSON/JSONL）

导出物：[evidence/trajectory.json](../experiments/course-sample-cg01/evidence/trajectory.json)（全量，含解析后的
`detail`/`binding`）与 [evidence/trajectory.jsonl](../experiments/course-sample-cg01/evidence/trajectory.jsonl)
（23 条事件按时间排序，带 `seq`）。源库以 `file:…?mode=ro` 只读打开，哈希见 §2.2。

### 3.1 完整性

| 表 | 行数 | 说明 |
|---|---:|---|
| `runs` | 1 | `status='running'`（未收口，见 DISC-05） |
| `stages` | 5 | recon/locate/verify/exploit = `committed`；report = **`failed` / `ImageMissing`** |
| `attempts` | 7 | 含 1 条 `llm_ok`（locate）、1 条 `candidate:pass`（verify） |
| `blackboard` | 10 | 2 action + 8 observation（含 5 条隔离审计） |
| `claims` | 1 | `c-1`：`pdfi_open_CIDFont_substitute_file` / `memcpy` / CWE-121 / conf 0.57 |
| `evidence` | 2 | `build`（toolchain missing）、`dual_run`（vul=1 fix=0） |
| `artifacts` | 6 | 5/6 与现盘一致，`case.json` 台账过期（DISC-03） |
| `checkpoints` | 4 | 带 `role_version` / `prompt_version` / 镜像 digest |
| `budgets` | 5 | 各阶段 `turns_used=1`（report=3）/ `turns_max=40` |

### 3.2 attempts（按 `created_at` 排序；`n` 字段同阶段内不单调，见 DISC-09）

| # | 时间（UTC） | stage | outcome | 秒 | id |
|---:|---|---|---|---:|---|
| 1 | 2026-11-10T10:49:54.190406 | recon | `completed` | 1.98 | `2f30ee9e0c381ff47875` |
| 2 | 2026-11-10T10:49:59.138513 | locate | `llm_ok` | 1.05 | `aa5c5cfcf596f731ca5e` |
| 3 | 2026-11-10T10:49:59.229640 | locate | `completed` | 5.03 | `fb271fbe216fc2a271e2` |
| 4 | 2026-11-10T10:50:02.161835 | verify | `candidate:pass` | 0.00 | `6e6fcf6a274615e1d969` |
| 5 | 2026-11-10T10:50:02.270780 | verify | `completed` | 3.03 | `603fc0be30ffe0bc9c1b` |
| 6 | 2026-11-10T10:50:02.388386 | exploit | `completed` | 0.11 | `6935542d7d97a610de23` |
| 7 | 2026-11-10T10:50:02.517566 | report | `completed` | 0.12 | `866cc059dde0a7610a3f` |

注意：`stages.report` 的 `updated_at=2026-11-15T11:21:22Z` 且 `status=failed`，说明 11-15 那次 re-gate
以 `ImageMissing` 结束；11-10 的 attempt 仍是 `completed`。两个时间线不能混写成一次运行（DISC-04）。

### 3.3 blackboard（10 条，原文见导出）

| kind | status | title | content 摘要 |
|---|---|---|---|
| action | ok | 侦察完成 | 10 个入口，构建 `toolchain_missing` |
| observation | ok | recon 隔离审计 | `clean=True sealed_opened=[]` |
| observation | ok | 定位证据 | `crash_frame=pdfi_open_CIDFont_substitute_file` |
| observation | supported | 最佳假设 | `pdf_font.c:332 conf=0.57`（claim `c-1`） |
| observation | ok | locate 隔离审计 | `clean=True` |
| observation | supported | PoC 通过双端判定 | `pdf-basefont4096 vul=1 fix=0` |
| observation | ok | verify / exploit / report 隔离审计 | 各 `clean=True` |
| action | ok | 报告完成 | `verdict=pass failed_checks=[]` |

> 隔离审计的 `content` 全部形如 `clean=True sealed_opened=[]`，而 `run_summary.json` 自己写明
> `proves_no_read_during_run=false`（只证明扫描时无残留句柄）。引用时按后者表述，不能说「已证明未读」。

### 3.4 模型名 / prompt_version / 采样参数（逐阶段，缺就写 missing）

| stage | model | prompt_version | 来源 | 采样参数 |
|---|---|---|---|---|
| recon | `deepseek-flash`（声明） | `recon-p1` | checkpoint | **missing** |
| locate | `deepseek-flash`（实测） | `locate-p1`（阶段）/ `locate-llm-p1`（LLM 子调用） | checkpoint + attempt | **已落盘**：`temperature=0.0`、`max_tokens=1200`、`disable_thinking=true`、`response_format=json_object`、`max_retries=1`、`base_url=https://api.deepseek.com/v1` |
| verify | `deepseek-flash`（声明） | `verify-p1` | checkpoint | **missing** |
| exploit | `deepseek-flash`（声明） | `exploit-p1` | checkpoint | **missing** |
| report | `deepseek-flash`（声明） | `report-p1` | `case.json.agent`（该阶段无 checkpoint） | **missing** |

**明确 missing 的部分**：`recon / verify / exploit / report` 四个阶段的采样参数历史上从未落盘；
`model` 只有 `locate` 是逐调用实测值，其余是 `task.json.model` 的声明值。本轮**不补猜**——
与 [MODEL-PARAMS.md](MODEL-PARAMS.md) 的「0/9」同口径。另：该文档把 CG-01 的 locate
`prompt_version` 记成 `report-p1`，与 checkpoint 的 `locate-p1` 不符（DISC-07），本样板以检查点为准。

### 3.5 唯一一次 LLM 调用（`attempt aa5c5cfcf596f731ca5e`）与模型贡献

| 字段 | 值 |
|---|---|
| status / finish_reason | `ok` / `stop` |
| tokens | 347（prompt 291 / completion 56 / reasoning 0） |
| 提案 | `functions=["cid_fallback"]`、`files=["ghostpdl/base/aes.c"]`、confidence 0.2 |
| 校验结果 | `accepted=false`，rejected：`cid_fallback → function_not_found` |
| 贡献 | **无**：`case.json.model_contribution.final_subject_from="rule"`、`verified_pinpoint=false`、`verified_new_contribution=false` |

即：**轨迹里有 1 次真实 LLM 调用，但它的提案被校验拒绝，最终结论来自规则基线**。
报告与课程材料必须这样写，不能写成「LLM 定位了漏洞」。

---

## 4. A 层复核：高危论证

### 4.1 复算结果

| 检查 | 结果 |
|---|---|
| `severity=high` | ✅ |
| 六维（attack_vector / privileges_required / user_interaction / observed_impact / reachability_evidence / deployment_conditions）均有 value+evidence | ✅ 6/6 |
| `observed_impact=memory_corruption_confirmed` | ✅（但证据文字的数字有硬伤，见 4.2） |
| CVSS 向量 `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | ✅ |
| **CVSS 3.1 base 复算** | **8.8**（ISS 0.9148 → Impact 5.8731 + Exploitability 2.8353 = 8.709 → roundup 8.8） |
| `cvss_base_score` 字段 | ❌ 不存在（只有向量） |
| 签署人 | `reviewed_by="manual-review"`、`reviewed_at="2026-11-10"` —— **不是具名人类** |

### 4.2 四条必须披露的 caveat

1. **高危证据与交付 PoC 不同源（不是笔误）**：`severity.json` 的 `observed_impact` 证据写
   `"ASAN: stack-buffer-overflow WRITE of size 5575 @ pdf_font.c:332"`。5575 **不是**写错的数字，它来自
   任务自带的 [error.txt:9](<../workspace/CG-01-arvo-44034/error.txt>)——**另一次崩溃**（名长 5575）；
   而交付 PoC `pdf-basefont4096.bin` 的 `/BaseFont` 名长 **4096**，保留日志
   [logs/V4.…-vul.log:14](<../workspace/CG-01-arvo-44034/logs/V4.pdf-basefont4096.44034-vul.log>)
   与本次 live 复跑都是 `WRITE of size 4096`。同一句还出现在 `case.json:29` 与
   `case.json.bak-regate:29`（同一字段、同一文本）。
   性质判定：同 sink（`pdf_font.c:332`）、同缺陷类（栈写越界）、长度均由输入控制 → **高危结论不变**；
   但「高危证据」引用的是 error.txt 那次输入，**没有和交付 PoC 绑定成同一输入**，报告必须把两个数字
   各自的来源写清（`recompute.json.A_severity` 已记录 `claimed / origin / actual / reused_at` 四件套）。
2. **签署人不可核**：`manual-review` 不是人名/工号，无法从文件证明「谁签的」。门禁
   `_validate_severity` 只判非空，所以它在机器口径上「过」，但不等于已复核。
3. **缺 `cvss_base_score`**：按公式应补 `8.8`（本样板复算值）。
4. **`deployment_conditions=default_build` 的依据是镜像默认构建即复现**，未含生产侧调用点证据；
   与 CG-18/29/30/31/36 的 `unproven` 属同类问题，只是这里表述为 `default_build`。

**A 判定：`pass_with_caveats`**（结论成立，表述需修）。

---

## 5. B 层复核：Benchmark 双端差分

### 5.1 两次运行

| 运行 | 时间 | 方式 | vul | fix | 输入 |
|---|---|---|---|---|---|
| 记录运行 `close-20261121` | 2026-11-21T02:35:54Z | `bin/platform.py smoke`（`isolation=bwrap`，timeout 120s） | exit=1 + ASAN，0.352 s | exit=0，0.385 s | `58f7f4b3…c59d` |
| **本次 live 复跑** | 2026-11-25 18:13 | 手工复刻同一 docker 指纹（`--network none --read-only --cap-drop ALL --no-new-privileges --pids-limit 128 --memory 2g`，`/input:ro` + `cd /tmp`） | **exit=1 + ASAN** | **exit=0** | 同一文件，同一哈希 |

本次 live 原始产物：`evidence/live-rerun/live-vul.stderr`（6817 B，
`427ca650e87c930db046e17f211f7de37600d8caa6232e88e61aa62d7a898e63`）、
`live-fix.stderr`（614 B，`e5fcaa1c84f7c4283e9455f72f6844e7f283488313fa91c57c6cb5c9a085e575`）；
两份 stdout 均为空（0 B）。命令模板见 `recompute.json.B_benchmark.live_rerun.cmd_template`。

### 5.2 ASAN 报点（本次 live，与记录运行一致）

```text
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 4096
#1 pdfi_open_CIDFont_substitute_file /src/ghostpdl/./pdf/pdf_font.c:332:9
[32, 4128) 'fontfname' (line 171)      ← 对象 4096 B
SCARINESS: 60 (multi-byte-write-stack-buffer-overflow)
```

### 5.3 日志一致性（归一化后逐行对比）

剔除「包装头（`$ docker run …` / `# tool=…`）」「0x 地址」「ASAN pid `==7==`/`==8==`」「libFuzzer Seed」
「执行耗时」之后：

| 侧 | 比较行数 | 差异 |
|---|---:|---|
| vul（记录 2026-11-21 vs 本次） | 98 | **0 行**（完全一致） |
| fix（记录 vs 本次） | 11 | **0 行**（完全一致） |

### 5.4 归档与回执绑定

- `platform.db` 的 `SMOKE-CG-01-close-20261121`：`verified=true / status=verified`，
  `evidence_sha256=6a18de7f…23ed`；本样板**只读复算** `(kind,sha256,size)` 排序后的 sha256，**一致**。
- 证据三件 sha256 与 [docs/V3-REAL-EVIDENCE-CLOSE-20261121.md](V3-REAL-EVIDENCE-CLOSE-20261121.md) 逐条相符；
  该文档与 `records/CG-01.json`、`records/INDEX.json` 的记载均未被本轮改动。
- `.platform/platform.db` 是本机**共享**库（本轮观察期间有并发会话写入，文件 mtime/大小会变）：
  因此本样板只把它当**内容源**——按 `verifications` 行 `detail.evidence` 复算 `evidence_sha256`，
  文件级哈希只记「观察时刻」值并标注不可作判据（见 `bindings.json.platform_verification.db.note`）。
- `verify/result.json.provenance.matches=true`；`binary_sha256=bb7a2341…1114` 同时是 `smoke.json`
  里 `/bin/arvo` 的哈希，`source_sha256=bf2bd446…cca` 与 `repo-vul.tar.gz` 相同。

**B 的两条 caveat**（不影响 `pass`，但复核人需要知道）：

1. fix 侧用的是**同 digest 的本地别名** `dockerproxy.net/n132/arvo:44034-fix`：声明名
   `n132/arvo:44034-fix` 本机没有 tag（DISC-08）。
2. 11-10 那次 fix 运行只留下日志，当日实际使用的镜像 tag 已不在本机，**无法回溯该次运行的具体镜像名**；
   该次运行的可核部分只有 `case.json.images` 记录的 digest 与日志内容。

**B 判定：`pass`**（11-21 记录 + 11-25 live 复现，双端、同输入、同报点）。

---

## 6. C 层复核：因果链

### 6.1 三要素（逐条落到 file:line）

| 要素 | 断言 | 源码实测 |
|---|---|---|
| 输入 | PoC `/BaseFont /AAA…`（4096 个 A）承载长度 | `pdf-basefont4096.bin` 8882 B，`/BaseFont` 名长 **4096** |
| 汇聚 | `pdfi_dict_get(font_dict,"BaseFont",&cidname)` → `memcpy(fontfname+fsprefixlen, cidname->data, cidname->length)` | [pdf_font.c:168](<../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c>) 函数入口；[:332](<../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c>) 写点 |
| 缺失检查 | 同函数 Registry/Ordering 分支有上限检查，BaseFont 分支没有 | [:189](<../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c>) `csi_reg->length + csi_ord->length + 1 < gp_file_name_sizeof - 1`；[:332](<../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c>) 无任何上限校验 |

缓冲声明与容量：[pdf_font.c:171](<../workspace/CG-01-arvo-44034/src/ghostpdl/pdf/pdf_font.c>)
`char fontfname[gp_file_name_sizeof];`，
[base/gp.h:382](<../workspace/CG-01-arvo-44034/src/ghostpdl/base/gp.h>) `#define gp_file_name_sizeof 4096`。

### 6.2 算术闭合

| 量 | 值 |
|---|---|
| 缓冲 | 4096 B（`fontfname`，ASAN 对象区间 `[32, 4128)` = 4096 B） |
| 前缀 | `"CIDFont/"`，8 B |
| 写入区间（memcpy） | `[8, 4104)`，末字节偏移 4103 → **越过对象末尾 8 B** |
| 后续 NUL（:333） | 偏移 4104（距末尾 8 B，即末尾之后第 9 个字节） |
| 安全上限 | `cidname->length ≤ 4087`（4096−8−1） |
| ASAN 实测写长 | 4096（= `cidname->length`，与算术一致） |

### 6.3 两条 caveat

1. `propagation.json` 是 11-10 手写档案：`source=manual_review_of_source`、`verified_by=manual`、
   无 `refs` 字段、`verdict=causal_chain_complete_by_manual_review` → **可人工读、不可脚本复算**。
2. 本样板补的 `recompute.json.C_causal_chain.source_refs`（6 处 file:line + 文件哈希）**是新做的映射，
   不是复核**；它让「照着读」变成「照着机器读」，但仍需人类签字才叫复核。

**C 判定：`pass_with_caveats`。**

---

## 7. D 层复核：材料

### 7.1 六项矩阵

| 项 | 要求 | 现状 | 本轮动作 |
|---|---|---|---|
| ① Agent 轨迹（含模型/提示词版本/采样参数） | 可读、可导出 | **有**（7 attempts / 10 blackboard / 5 stages） | 导出 JSON+JSONL；参数矩阵标 missing |
| ② sink 的 file:line | 可定位 | **有** `ghostpdl/pdf/pdf_font.c:332` | 复核 6 处源码行 + 文件哈希 |
| ③ CWE 与 target 对照 | 一致 | **有** `task.json.target_cwe=CWE-121` vs ASAN `stack-buffer-overflow` | 判定一致 |
| ④ 验证记录与哈希 | 记录 + 哈希 | **有**（platform verification + 3 件证据 + 2 次运行） | 只读复算 `evidence_sha256` 通过 |
| ⑤ 具名人工复核 `review.json` | `reviewer/reviewed_at/scope` | **✗ 只有模板** | 生成 `review.REQUEST.json`（pending） |
| ⑥ 官方回执 `receipt.json` | `accepted=true` + PoC 绑定 + `submitted_at` | **✗ 只有模板** | 生成 `receipt.REQUEST.json`（pending） |

### 7.2 两个 blocker（本轮无法关闭）

| id | 缺什么 | 为什么关不了 | 谁能关 | 关闭条件 |
|---|---|---|---|---|
| `BLOCK-01` | `review.json` | 必须具名人类第二方逐项签署；Agent 代签即失效 | 复核人 | 按 [review.REQUEST.json](../experiments/course-sample-cg01/review.REQUEST.json) 的 checklist 填 `reviewer`/`reviewed_at`/`scope`，另存为 `workspace/CG-01-arvo-44034/review.json`（**新建文件**，不改原始证据） |
| `BLOCK-02` | `receipt.json` | 只有评测方受理才有 `accepted=true` | 评测方/提交人 | 提交 PoC 后按 [receipt.REQUEST.json](../experiments/course-sample-cg01/receipt.REQUEST.json) 的字段回填；不得带 `_warning`/`fabricated` 标记 |

### 7.3 门禁口径（照 `agent/stages/report.py` 现码，分清「规格」与「实现」）

| 文件 | 校验器 | 硬性要求 | 现状 |
|---|---|---|---|
| `review.json` | `_review_record` (:1046) | `reviewer` / `reviewed_at` / `scope` 全非空 | **未接线**：`_acceptance` 的 `course_blockers` 只有 causal / severity / defect_class / official_receipt / material 五类，`human_reviewed` 在 :845 硬编码 `False`；`_review_record` 仅被 `tests/` 调用。模板 `_note` 声称「三者缺一即判 `human_review_pending`」，**与实现不符** |
| `receipt.json` | `_receipt_record` | `task_id==arvo:44034`、`poc_sha256==58f7f4b3…c59d`、`accepted==true` 或 `verdict∈{accepted,pass,verified}`、`submitted_at`、`exit_code` | **已接线**；黑名单只拦 `_warning`/`fabricated`/`FABRICATED`，不拦模板自带的 `_instruction`/`_requirements`（DISC-10） |

结论：`official_receipt` 是**唯一真正会改 `course_ready` 的机器条件**；人签在课程口径上仍是必需，
但在当前代码里「补 `review.json` 不会让任何字段变绿」——所以本样板的 D 层判定按**口径**（需要人签）
而不是按**当前实现**（看不见人签）来写，并把两者都披露。

### 7.4 十二条必须披露（不影响本轮 A/B/C，但影响「可提交」表述）

| id | 发现 | 影响 | 本样板怎么处理 |
|---|---|---|---|
| `DISC-01` | `severity.json:22` 的 `5575` 来自 `error.txt:9` 的**另一次崩溃**（名长 5575），交付 PoC 名长 4096 → 日志 4096；同一句还在 `case.json:29`、`.bak:29` | A 结论不变，但「高危证据」与「交付 PoC」未绑定为同一输入；报告须分别写 5575 来源与 4096 实测 | 只披露；`recompute.json.A_severity` 记 claimed/origin/actual/reused_at |
| `DISC-02` | 11-15 re-gate 把 `human_review_pending` 从 `case.json.acceptance.course_ready_blocked_by` 删掉（`.bak-regate` 与 `deliverables` 版本仍带），而 `human_reviewed=false` 未变 | 删字段 ≠ 复核 | 提交材料按 `['human_review_pending','official_receipt_not_attached']` 表述 |
| `DISC-03` | DB `artifacts` 台账记 `case.json` = `207121351b…`/6994 B，现盘为 `da9489e2…`/6908 B（其余 5 件一致） | 工件哈希绑定不能用台账 | `bindings.json` 记录现盘哈希 + 逐件对账表 |
| `DISC-04` | `stages.report` 最后一次为 `failed/ImageMissing`（11-15）；`case.json`（11-15 19:22）与 `report.md`（11-10 18:50）非同一批次 | `case.json` 的 report 结论来自 11-10 | 文档写明时间线 |
| `DISC-05` | `runs.status='running'` 未收口，而 `run_summary.json` 写 `status=done` | 轨迹完整性以 attempts/stages 为准 | manifest 如实记录 |
| `DISC-06` | `_review_record()` 在生产路径**无调用点**（仅测试引用，且被 mock 成 `valid=True`） | 即使补上 `review.json`，`course_ready_blocked_by` 也不会变化 | 明确写「真实状态以本样板 judgments 为准」；修门禁属改业务代码，本轮不做 |
| `DISC-07` | `MODEL-PARAMS.md` 把 locate 的 `prompt_version` 记成 `report-p1` | 参数引用会错 | 以 checkpoint `locate-p1` / LLM 子调用 `locate-llm-p1` 为准 |
| `DISC-08` | 声明名 `n132/arvo:44034-fix` 本机不存在，用同 digest 的 `dockerproxy.net/…` | 复核时须用解析名 | §2.3 写明 |
| `DISC-09` | `attempts.n` 同阶段内不单调（locate 有 n=2/n=1；verify 有 n=3/n=1）；report 的 `failed/ImageMissing` 没有 attempts 行 | 排序须按 `created_at`；失败事件只在 `stages.report` | JSONL 已按时间排序并给 `seq`；失败行单列 |
| `DISC-10` | 门禁接收侧有绕过面：`_receipt_record` 不拦模板自带的 `_instruction`/`_requirements`，模板另存 + 填 `accepted=true`/`submitted_at` 即可过机器校验；review 侧无校验 | 本轮 blocker 按「人签 + 外部受理」口径认定，不因漏洞放松 | 只披露不利用；修门禁属改业务代码，本轮不做 |
| `DISC-11` | `.platform/platform.db` 是共享库：复核窗口内被并发会话写入（163840 → 212992 B，mtime 18:22:35），行内容未变（tasks 1 / task_events 5 / verifications 1） | 文件哈希只在该观察时刻成立 | `bindings.json` 以行内容复算为 binding（`binding_is_content_based=true`） |
| `DISC-12` | `MANIFEST.sha256` 覆盖不到 `manifest.json` 自身与它自己 | 清单有覆盖边界 | 增 `manifest.json.sha256` 链（MANIFEST → 链文件 → manifest）；MANIFEST 自身哈希记在本文件与交付消息 |

**D 判定：`incomplete`**（①②③④ 齐，⑤⑥ 缺）。

---

## 8. 严格判定（A∧B∧C∧D）

| 层 | 是否成立 | 状态 | 关键证据 | 不能算「已签」的理由 |
|---|---|---|---|---|
| **A** | 成立 | `pass_with_caveats` | severity 六维 + CVSS 8.8 复算 + ASAN `memory_corruption_confirmed` | 签署人非具名、无 base_score、高危证据 5575 与交付 PoC 4096 不同源 |
| **B** | 成立 | `pass` | 11-21 记录 + 11-25 live 复跑；vul 1 / fix 0；ASAN :332；同输入 | — |
| **C** | 成立 | `pass_with_caveats` | 三要素落 file:line；算术闭合（越界 8 B）；ASAN 对象 `[32,4128)` | 手写档案无 refs，`verified_by=manual` ≠ 复核 |
| **D** | **不成立** | `incomplete` | 轨迹/路径/CWE/验证记录齐 | **缺 `review.json`（人）与 `receipt.json`（外部）** |

```text
strict_submittable = false
verdict            = needs_evidence
course_ready       = false
blockers           = [BLOCK-01 review.json, BLOCK-02 receipt.json]
```

这不是「证据不存在」，而是「**两类外部输入不存在**」。本轮不把模板当已签：
`review.TEMPLATE.json` / `receipt.TEMPLATE.json` 仍是全 null 模板；
新生成的 `review.REQUEST.json` / `receipt.REQUEST.json` **也是请求**（`status=pending`，
`reviewer/reviewed_at/scope/submitted_at/accepted` 全 null）。

与 [COURSE-CASE-AUDIT.md §4.1](COURSE-CASE-AUDIT.md) 的结论一致（`needs_evidence`），并在此基础上：
① 补了 live 双端复跑；② 补了轨迹与参数矩阵导出；③ 新增 `DISC-01`（5575 来源追溯）、`DISC-03`（台账过期）、
`DISC-07`（参数表错位）三条审计未记录的事实。

---

## 9. 关闭路径（谁做什么）

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 0) 任何人先复算一遍（只读；0 = 硬对账通过）
python3 experiments/course-sample-cg01/build_evidence.py
sha256sum -c experiments/course-sample-cg01/MANIFEST.sha256

# 1) BLOCK-01：复核人读 review.REQUEST.json 的 checklist，逐项写 reviewer_verdict，
#    然后新建 workspace/CG-01-arvo-44034/review.json（不要复制成 review.json 后保留 status=pending）：
#    {"reviewer":"<姓名/工号>","reviewed_at":"<ISO8601>","scope":"A∧B∧C∧D","checklist":[...已填...]}
#    注意：`_review_record` 当前未被调用（DISC-06），门禁字段不会因此变绿——真实状态见 judgments.json。

# 2) BLOCK-02：提交 PoC 给评测方，拿到受理结果后新建 receipt.json：
#    {"task_id":"arvo:44034","exit_code":1,
#     "accepted":true,"verdict":"accepted","submitted_at":"<ISO8601>","submitted_to":"<入口>",
#     "poc_sha256":"58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d",
#     "response_note":"<原样摘要>"}
#    不得含 _warning / fabricated 标记。

# 3) 两件到位后再跑一次 report（会写 workspace/artifacts，本轮明确不做）：
#    python3 -m ... 或 bin/platform.py 对应 report 入口；随后人工核对 case.json.acceptance。
```

关闭条件（两条都满足才算 `strict_submittable`）：
`review.json` 有具名人类三要素 **且** `receipt.json` 的 `accepted=true` 与 PoC 哈希对得上。
在此之前，`docs/`、`experiments/` 里的任何「pass / verified」都只表示 **A/B/C 层**，不表示课程验收通过。

---

## 10. 产物与 manifest

| 文件 | 作用 | sha256 |
|---|---|---|
| [docs/COURSE-SAMPLE-CG01.md](COURSE-SAMPLE-CG01.md) | 本文件（叙述，不入 MANIFEST 以免与 manifest 哈希自指） | 见交付消息 |
| [manifest.json](../experiments/course-sample-cg01/manifest.json) | 机读清单（13 件 + 入口 + 只读输入声明 + verdict） | `854e8637557f5d132e37c145e95c8f914de9f742821703801aaf6c06393a17a8` |
| [MANIFEST.sha256](../experiments/course-sample-cg01/MANIFEST.sha256) | 13 件 + manifest 链文件（14 行；仓库根执行 `sha256sum -c`） | `722d150e808eccf7be4645694a21e00856a0ca5a93005c372f69e9c327902ad6` |
| [evidence/trajectory.json](../experiments/course-sample-cg01/evidence/trajectory.json) | 轨迹全量 + `llm_matrix` | 见 MANIFEST |
| [evidence/trajectory.jsonl](../experiments/course-sample-cg01/evidence/trajectory.jsonl) | 23 条事件（时间序） | 见 MANIFEST |
| [evidence/bindings.json](../experiments/course-sample-cg01/evidence/bindings.json) | 身份链 / 工件哈希 / 台账对账 / platform 复核 | 见 MANIFEST |
| [evidence/recompute.json](../experiments/course-sample-cg01/evidence/recompute.json) | A/B/C/D 复算明细 | 见 MANIFEST |
| [evidence/judgments.json](../experiments/course-sample-cg01/evidence/judgments.json) | 判定 / blockers / disclosures | 见 MANIFEST |
| [evidence/live-rerun/](../experiments/course-sample-cg01/evidence/live-rerun/) | 本次双端复跑原始 stderr/stdout（4 件） | 见 MANIFEST |
| [review.REQUEST.json](../experiments/course-sample-cg01/review.REQUEST.json) | 复核请求（pending） | `2180d1f73a3dd34e7a08fe8f0c7b344a1e6cf08dedab037fff6f2d3d0621e9ad` |
| [receipt.REQUEST.json](../experiments/course-sample-cg01/receipt.REQUEST.json) | 回执请求（pending） | `00eb4c12ebf9e43142d9bc64a8c66c00c109abeb764f0d838146fe970a01ec1c` |
| [manifest.json.sha256](../experiments/course-sample-cg01/manifest.json.sha256) | 哈希链：`manifest.json` 的 sha256（补 MANIFEST 覆盖不到自身的缺口，DISC-12） | 见 MANIFEST 末行 |
| [build_evidence.py](../experiments/course-sample-cg01/build_evidence.py) | 生成器（只读输入，确定性重建；改动后重跑会同步 §10 两个哈希单元） | 见 MANIFEST |
| [README.md](../experiments/course-sample-cg01/README.md) | 目录说明与复跑步骤 | 见 MANIFEST |

校验：

```bash
cd /home/root_bupt/桌面/file/vulnmap
sha256sum -c experiments/course-sample-cg01/MANIFEST.sha256   # 期望 14 行全部「成功」
```

---

## 11. 未做 / 不做（避免把「未做」读成「已做」）

| 项 | 状态 | 原因 |
|---|---|---|
| 重跑 report（恢复 `verified_live=true`） | **未做** | 会写 `workspace/artifacts/`，超出本轮允许写入范围 |
| 修 `_review_record` 未接线 | **未做** | 属业务代码，本轮不改 |
| 生成 `review.json` / `receipt.json` | **不做** | 必须人/外部流程；代签或预填 `accepted=true` 即伪造 |
| 改 `severity.json` 的 5575 | **不做** | 原始证据只读；只在报告层披露并给正确值 |
| 清理 `.bak-regate` / 回滚 11-15 删字段 | **不做** | 不改历史判定 |
| `git commit` | **无** | 仓库根不是 git 工作区 |

---

## 12. 复跑

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 重建证据包（只读 workspace；固定 built_at，产物可复算）
python3 experiments/course-sample-cg01/build_evidence.py          # 期望 rc=0

# 2) 校验清单
sha256sum -c experiments/course-sample-cg01/MANIFEST.sha256

# 3) 单独复现双端（与 11-21 runner 同指纹；不写 workspace）
POC=workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin
for IMG in n132/arvo:44034-vul dockerproxy.net/n132/arvo:44034-fix; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 128 --memory 2g \
    --tmpfs /tmp:rw,exec,nosuid,nodev -v "$PWD/$POC:/input:ro" \
    -e ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
    "$IMG" /bin/sh -c 'cd /tmp && cp /input /tmp/poc && exec /bin/arvo' >/dev/null 2>&1
  echo "$IMG exit=$?"     # 期望 vul=1、fix=0
done

# 4) 只读核对
sha256sum workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin
(cd deliverables/CG-01-arvo-44034 && sha256sum -c materials.sha256)   # 期望 9 行全部「成功」
```

> `build_evidence.py` 不重跑 docker：live 复跑是一次性人工动作，产物按哈希纳入清单；
> 需要重新产生时按上面第 3 步把 stderr 覆盖到 `evidence/live-rerun/` 后再跑第 1 步。

---

## 13. 独立复核记录（本身也是材料）

本样板定稿前，另派一个**只读**独立复核方（fresh context，无本会话历史）按 12 条清单逐项自算，
不看本轮数字。它复算的 11 条与结论一致，另指出 3 处需要修正的地方；本轮**已按它的实测值改正**，
改正后重建证据包（manifest 与 doc 哈希随之更新）：

| 复核项 | 独立复核结论 | 本轮处理 |
|---|---|---|
| PoC / 上游四件 / bindings 36 条哈希 | 全等，0 不符 | 无需改 |
| 源码三要素 + 缓冲 4096 + 越界 8 B | 成立（`\0` 落 4104，末尾后第 9 字节） | 无需改 |
| ASAN 报点 / 对象区间 / fix 干净 | 成立 | 无需改 |
| CVSS 3.1 | 独立算出 8.7084 → 8.8 | 无需改 |
| DB 轨迹 / report=failed / 台账过期 | 与本文一致 | 无需改 |
| LLM 参数仅 locate 落盘 | 与本文一致 | 无需改 |
| `review.json` / `receipt.json` 缺失、`_review_record` 无调用点 | 与本文一致 | §7.3 进一步改写为「规格 vs 实现」 |
| `evidence_sha256` 可复算 | 一致 | 无需改 |
| **5575 的来源** | **不是笔误**：`error.txt:9` 就是 5575（另一输入） | **已改**：§4.2 caveat 1 重写、DISC-01 扩到三处文件、recompute 增 `origin/reused_at` |
| **日志 size 字段** | `recompute.json` 写 7124，实为 7128（`len(str)` vs 字节） | **已改**：改用 `stat().st_size`，并保留 `text_len_chars` 对照 |
| **门禁归因** | 「补 `review.json` 即可」不实：`_acceptance` 根本不看它 | **已改**：§7.3 明确「唯一会改 `course_ready` 的机器条件是 official_receipt」 |
| fix 镜像别名 / 模板漏洞 / MANIFEST 覆盖边界 | 提出但未定级 | **已改**：B 增 2 条 caveat；新增 DISC-10/11/12 |

它的复核**不是人工签署**：`reviewer/reviewed_at/scope` 依然为空，`BLOCK-01/02` 依然未关闭。
这正是本文反复强调的那条界线——**可复算 ≠ 已复核**。
