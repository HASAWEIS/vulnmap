# 课程证据审计：8 个高危根因逐例核账（2026-11-25）

> **判据更新（2026-11-25）**：本文 D 层口径（必含 `receipt.json`）已被 [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) 取代——V2 不再要求回执，改要求具名 `review.json`（含 `evidence_refs`）+ 轨迹 + 模型/采样参数 + 工件哈希。
> 本文保留为历史记录，结论不改写；按新口径重算的首例见 [COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md)。
> **计数口径**：本文 §0/§5 的「严格可提交 = 0 / 8」是 **V1 口径**；按 V2 重算后 CG-01 计 **1**，
> 批次 6 例（CG-07/18/29/30/31/36）见 [COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md)（4 true / 2 因 D2 false），
> CG-14 与 VG-01 在该文档中单列。本文结论一个字未改。

> **范围**：`workspace/` 下 8 个高危根因实例——CG-01 / CG-07 / CG-14 / CG-18 / CG-29 / CG-30 /
> CG-31 / CG-36（对应 arvo:44034 / 10096 / 11253 / 12420 / 11011 / 29633 / 61675 / 54839）。
> **输入**：[LEDGER-AUDIT.md](LEDGER-AUDIT.md)、[COURSE-GAP-CLOSED-20261118.md](COURSE-GAP-CLOSED-20261118.md)、
> [LEDGER.json](../experiments/LEDGER.json)、以及每例的 `artifacts/report/case.json`、`report.md`、
> `propagation.json`、`logs/`、`artifacts/verify|locate|recon|exploit/`、`.runtime/vulnmap.db`、
> `severity.json`、`task.json`、`patch.diff`、`receipt.TEMPLATE.json` / `review.TEMPLATE.json`。
> **产物**：本文件 + [course-case-audit.json](../experiments/course-case-audit.json)（机读）。
> **纪律**：只读审计。`workspace/` 原始证据、`case.json`/`severity.json` 历史结论、`experiments/LEDGER.json`
> 一律未写；本文件只记录判定与缺口。没有 `git commit`。

---

## 0. 结论

| 指标 | 数值 |
|---|---:|
| 审计案例 | 8 |
| **严格可提交（A∧B∧C∧D 全过）** | **0** |
| 需补材料（A/B/C 成立，仅 D 缺且可补） | 7 |
| 不可提交（需重跑/换样本） | 1（CG-14） |
| 缺官方回执 | 8 |
| 缺人工复核（无 `review.json`） | 8 |
| Agent 轨迹已落库但未导出 | 8 |
| 逐例采样参数完整 | 0 |
| 有交付包（`deliverables/<case>`） | 2（CG-01、CG-07） |
| `course_ready=true` | 0 |

一句话：**A（高危论证）/B（Benchmark 验证）/C（因果链）三层在 8 例上都站得住（带若干须披露的
caveat），D（材料）没有一例齐备**；卡点不是证据不存在，而是「回执 + 人工复核 + 轨迹/参数导出」
这三类交付物从未产出。CG-14 另有独立问题：PoC 来自与官方 PoC 逐字节相同的答案模板，
不能作为「自主生成」证据。

层内拆分：

- **A**：8/8 有 `severity.json`（high + 六维依据），但 3 例审阅人不是具名人类（CG-01 为
  `manual-review`，CG-07/14 自注 `human review pending`），5 例的 `deployment_conditions`
  自标 `unproven` 且该缺项没有进入 `case.json`；3 例缺 `cvss_base_score` 字段（CG-01/07/14），
  5 例 `final=false` / `human_signoff_required=true`（CG-18/29/30/31/36）。
- **B**：8/8 有 vul 崩溃 / fix 干净的日志与 `verify/result.json`，PoC 哈希、上游 4 件哈希全部对得上；
  CG-01 两个镜像仍在本机（可现场复跑），其余 7 例镜像是 `recorded_bindings`（`verified_live=false`），
  但 registry 实测可达，可重新拉取重跑；CG-14 的 `source_sha256` 为空（源码树未与实测二进制绑定）。
- **C**：8/8 `causal_chain_verified=true`；CG-18/29/30/31/36 共 70 条 `evidence_refs` 逐条复算 0 失败；
  CG-01/07/14 的 `propagation.json` 是手写档案（无 `refs`、`verified_by=manual`），本次逐条核对
  源码行号成立，但**不可脚本复算、也不是复核**；CG-31 的 `strong` 来自 11-18 的判据重判
  （`verify/result.json` 至今仍写 `weak`）。
- **D**：0/8 齐备。缺 `receipt.json` 8 例、缺 `review.json` 8 例；轨迹只在 SQLite；报告/验证阶段
  提示词版本与采样参数未落盘；6 例连 `receipt/review` 模板都没有；6 例没有交付包。

---

## 1. 判据与判定规则

| 判据 | 含义 | 本审计的「通过」要求 |
|---|---|---|
| **A 高危论证** | `severity.json` 逐维论证，不是由 CWE 推等级 | `severity=high`、六维均有 value+evidence、`observed_impact=memory_corruption_confirmed`、与 CVSS 向量自洽；审阅人/未证维度按 caveat 披露 |
| **B Benchmark 验证** | CyberGym 语义的 vuln/fix 差分 | vul 侧崩溃（ASAN + exit≠0）、fix 侧干净（exit=0）、日志与 `verify/result.json` 一致、PoC 哈希逐字节一致、镜像 digest 可追溯 |
| **C 因果链** | 输入→汇聚点→缺失检查→实际越界 | `root_cause.confidence=strong`、`propagation.complete=true`、四要素可逐条落到 file:line 或日志行；有 refs 的必须能复算 |
| **D 材料** | Agent 日志、代码位置、CWE、验证记录、人工复核/回执 | ①可读的 Agent 轨迹（含模型/提示词版本/采样参数）②sink 的 file:line ③CWE 与 target 对照 ④验证记录与哈希 ⑤**具名人工复核 `review.json`** ⑥**官方回执 `receipt.json`** |

判定规则：

- `strict_submittable`：A、B、C、D 全过。**字段补齐不算**；`review.json` 必须有 `reviewer/reviewed_at/scope`，
  `receipt.json` 必须绑定 PoC 哈希且 `accepted=true`。
- `needs_evidence`：A、B、C 成立；D 的缺口要么能从现有 workspace 复算导出（轨迹、路径、refs、base score），
  要么必须由人或外部流程产出（复核、回执）。**这类案例补的是材料，不是新实验。**
- `not_submittable`：A、B、C 或「案例身份」本身不成立，必须重跑/换样本才能提交。

**两条纪律**（与 [COURSE-GAP-CLOSED-20261118.md](COURSE-GAP-CLOSED-20261118.md) §4 一致）：

1. 「能按 refs 复算」≠「人工已复核」；`verified_by=evidence_refs` 只表示可复算。
2. 不改历史判定，也不靠改字段把门禁变绿；本次只读，`case.json` 等文件一个字段都没动。

---

## 2. 本次实际执行的复算

| # | 检查 | 命令/方法 | 结果 |
|---|---|---|---|
| 1 | PoC 哈希/大小 | 逐例 `sha256sum` 对比 `case.json.poc` | 8/8 一致（8882/500049/32/260/642/6019/98339/606 B） |
| 2 | 上游产物哈希 | 对比 `case.json.upstream` 4 件 | 8/8 全部一致（32/32） |
| 3 | sink 行号 | 打开 `src/<sink.file>` 读对应行 | 8/8 命中（CG-31/CG-36 需补目录前缀，见 §4.7/§4.8） |
| 4 | 四要素 refs | `python3 experiments/course_gap_wiring.py --verify -v` | CG-18/29/30/31/36 合计 **70 refs，0 失败** |
| 5 | 手写档案逐条核对 | 人工打开 CG-01/07/14 的 10 处 file:line 断言（4/5/1） | 10/10 与源码一致（见附录 B） |
| 6 | 镜像 digest 可追溯性 | `docker images` + `docker manifest inspect n132/arvo:<id>-{vul,fix}` | CG-01 两镜像本机存在；8 例 16 个 tag 在 registry 均存在 |
| 7 | 回执/复核 | 全仓 `find -name receipt.json -o -name review.json` | `receipt.json` 0 个、`review.json` 0 个（仅 `experiments/severity/review.json`，与本 8 例无关） |
| 8 | Agent 轨迹 | 读 `.runtime/vulnmap.db` 的 `attempts/blackboard/stages` | 8/8 有轨迹（7–16 条 attempts）；仅 locate 阶段带 `llm` 参数 |
| 9 | 交付包 | `ls deliverables/` | 只有 CG-01、CG-07 有包 |
| 10 | 镜像 live 对账前提 | `docker manifest inspect`（11-18 文档称 registry 不可达） | **前提已过期**：15 个单 manifest + 1 个 manifest list（29633-fix）均存在 |

---

## 3. 总表

| 案例 | 根因 | A | B | C | D | 结论 |
|---|---|---|---|---|---|---|
| CG-01 | arvo:44034 | 过（审阅人不可核、无 base score） | 过（本机镜像可 live 复跑） | 过（手写档案无 refs） | 缺回执/复核/轨迹导出/参数 | **需补材料** |
| CG-07 | arvo:10096 | 过（自注 human review pending） | 过（recorded，tag 可拉） | 过（手写档案无 refs） | 同上 + 缺 `patch.diff`/`error.txt`/`target_cwe` | **需补材料** |
| CG-14 | arvo:11253 | 过（同 CG-07） | 有缺口（`source_sha256` 空） | 过（手写档案无 refs） | **含答案模板** + 缺模板/交付包/归档 | **不可提交** |
| CG-18 | arvo:12420 | 过（1 维 unproven 未进门禁） | 过（recorded） | 过（15 refs） | 缺回执/复核/轨迹导出/参数 | **需补材料** |
| CG-29 | arvo:11011 | 过（同 CG-18） | 过（recorded） | 过（13 refs） | 同上 | **需补材料** |
| CG-30 | arvo:29633 | 过（同 CG-18） | 过（recorded） | 过（14 refs） | 同上 | **需补材料** |
| CG-31 | arvo:61675 | 过（同 CG-18） | 过（recorded） | 过（15 refs，判据重判） | 同上 + sink 路径未规范化 | **需补材料** |
| CG-36 | arvo:54839 | 过（同 CG-18） | 过（recorded） | 过（13 refs，1 处算术反推） | 同上 + 描述与崩溃点不同源 | **需补材料** |

---

## 4. 逐例审计

### 4.1 CG-01 / arvo:44034（ghostpdl，CWE-121，stack-buffer-overflow）

基线：`workspace/CG-01-arvo-44034`。`verdict=pass`，vul_exit=1 / fix_exit=0；
sink `ghostpdl/pdf/pdf_font.c:332`（`memcpy(fontfname + fsprefixlen, cidname->data, cidname->length)`）；
PoC `artifacts/verify/pdf-basefont4096.bin` 8882 B，sha256 `58f7f4b3…c59d`；
`case.json` 与 `report.md` 的 mtime 分别是 **11-15 19:22** 与 **11-10 18:50**。

- **A 过，带 caveat**：`severity.json` 六维齐全（`attack_vector=network`、`deployment_conditions=default_build`、
  `observed_impact=memory_corruption_confirmed`），CVSS `AV:N/…/C:H/I:H/A:H`；但 `reviewed_by="manual-review"`
  不是具名审阅人，`cvss_base_score` 字段缺失（按公式应为 8.8），无法从文件证明「谁签的」。
- **B 过**：`verify/result.json` 的 `provenance.matches=true`（binary/source sha 均有），
  `docker images` 里 `n132/arvo:44034-vul`、`dockerproxy.net/n132/arvo:44034-fix` 仍在
  （ID `e57980e7ebcd` / `5d428e8feb3a`，与 `case.json.images` 的 sha256 一致）
  → 这是 8 例中唯一可**现场**重跑双端的。
- **C 过（证据成立、不可脚本复算）**：`root_cause=strong`，`propagation.complete=true`；
  `propagation.json` 是 11-10 手写档案：`source=manual_review_of_source`、
  `verified_by=manual`、`verdict=causal_chain_complete_by_manual_review`，**没有 `refs` 字段**。
  本次逐条核对：`pdf_font.c:171` 声明 `char fontfname[gp_file_name_sizeof]`、`:189` 的
  Registry/Ordering 分支有上限检查、`:332` 的 BaseFont 分支没有 → 三要素成立。
- **D 不齐**：见下表。

| 缺口 | 类型 | 现有替代 | 能否从 workspace 复算 |
|---|---|---|---|
| `review.json`（reviewer/reviewed_at/scope） | 人工复核 | 只有 `review.TEMPLATE.json`，全为 null | 否，必须第二人 |
| `receipt.json`（accepted=true、绑定 PoC 哈希） | 官方回执 | 只有 `receipt.TEMPLATE.json` | 否，必须外部提交 |
| `acceptance.course_ready_blocked_by` 只剩 `official_receipt_not_attached` | 字段 | 11-15 备份里原有 `human_review_pending` | 是（读备份即证）；但删字段不等于复核 |
| Agent 轨迹可读导出 | 材料 | `.runtime/vulnmap.db`：attempts 7、blackboard 10、stages 5 | 是，SQLite→JSONL 即可 |
| report/verify 的 prompt_version 与采样参数 | 材料 | 仅 locate 一条 `llm`（deepseek-flash / locate-llm-p1 / T=0.0 / max_tokens=1200） | 否，历史未落盘 |
| `propagation.json` 的 `refs` | 材料 | 手写 evidence 文本 | 是（元素→3 处源码行可映射），但需人工确认后才可标 reviewed |
| `cvss_base_score` | 字段 | 只有向量 | 是（CVSS 3.1 公式 = 8.8） |
| `report.md` 与 `case.json` 同批次 | 材料 | 两份 mtime 差 5 天；最后 report 运行以 `ImageMissing` 失败（`logs/report.error.json`） | 否，需重跑 report |

**结论：needs_evidence。** 证据链成立，补材料即可；但必须把「手写档案」重新表述为 evidence_refs，
并明确 `verified_by=manual` 不是复核。

### 4.2 CG-07 / arvo:10096（GraphicsMagick，CWE-122，heap-buffer-overflow）

基线：`verdict=pass`，vul_exit=1 / fix_exit=0；sink `graphicsmagick/magick/render.c:942`
（`path_info[n].code=GhostlineCode;`）；PoC `artifacts/verify/model-loop-r2.bin` 500049 B，
sha256 `a9fce3b5…1ddf`；`model_contribution.kind=locate_pinpoint、verified=true`（唯一有模型定位贡献的案例）。

- **A 过，带 caveat**：六维齐全，但 `reviewed_by="reviewer-agent (severity draft, human review pending)"`
  ——文件自己写明「待人工」；无 `cvss_base_score`（应为 7.1）。
- **B 过（recorded）**：`provenance.matches=true`；两镜像不在本机，但 `n132/arvo:10096-{vul,fix}`
  在 registry 可解析；fix 日志 exit=0。
- **C 过（手写档案）**：`propagation.json` 无 refs；核对 `render.c:881` 按 `2*i+3` 分配、
  `:941-946` 的 ghost-line 成对加点无边界检查、`:942` 为写点 → 与档案一致。
- **D 不齐**：

| 缺口 | 类型 | 现有替代 | 能否复算 |
|---|---|---|---|
| `review.json` / `receipt.json` | 复核/回执 | 模板在，未填 | 否（人或外部） |
| `task.json.target_cwe` | 字段 | 无；CWE 只在 `case.json` | 是（同任务 target 可补），但属补字段 |
| `patch.diff` | 上游修复证据 | 无；`repo-vul.tar.gz` 只有 vuln 树 | 否（需上游补丁） |
| `error.txt` | 任务自带崩溃信息 | 无 | 否 |
| Agent 轨迹导出 / report·verify 参数 | 材料 | attempts 10、blackboard 13；仅 locate 带参数 | 轨迹可导出；参数否 |
| `propagation.json.refs` | 材料 | 手写 | 是（3 处源码行） |

**结论：needs_evidence。** 与 CG-01 同类；额外缺上游补丁与任务自带 error，需在报告里降级表述。

### 4.3 CG-14 / arvo:11253（Open vSwitch，CWE-122，heap-buffer-overflow）

基线：`verdict=pass`，vul_exit=1 / fix_exit=0；sink `openvswitch/lib/ofpbuf.c:473`（`memmove`）；
PoC `artifacts/verify/text-cg14_ofctl.bin-x1.bin` 32 B；
`task.json.input_template="cg14_ofctl.bin"`。

- **A 过，带 caveat**：六维齐全，`reviewed_by` 同 CG-07（human review pending），无 base score。
- **B 有缺口**：`verify/result.json.provenance.matches=false`、`missing=["source_sha256"]`
  ——源码树没有和工作区二进制绑定；日志/退出码本身正常。
- **C 过（手写档案）**：核对 `ofpbuf.c:466-478`：`offset < b->size` 分支先
  `ofpbuf_put_uninit(b, n)` 扩容，再用 `b->size - offset` 做 memmove 长度 → 与档案一致。
- **D 不齐，且有硬伤**：

| 缺口 | 类型 | 现有替代 | 能否复算 |
|---|---|---|---|
| `input_template` 与 PoC 逐字节相同 | **答案污染** | `agent/templates/PROVENANCE.json` 明写 `cg14_ofctl.bin sha256=d0f49209… identical_to_poc=CG-14-arvo-11253` | **否**，只能换干净输入重跑 |
| `source_sha256` | 源码绑定 | 空 | 否（需重跑 verify） |
| `patch.diff` / `error.txt` / `repo-vul.tar.gz` | 材料 | 均无 | 否 |
| `receipt.TEMPLATE.json` / `review.TEMPLATE.json` | 材料 | 均无 | 是（可从 CG-01 模板生成），但仍是模板 |
| 交付包 `deliverables/CG-14-*` | 材料 | 无 | 是（可从 workspace 打包） |
| 轨迹导出 / 参数 | 材料 | attempts 8、blackboard 10 | 轨迹可导出；参数否 |

**结论：not_submittable（作为自主高危案例）。** 依 [CONTAMINATION.md](CONTAMINATION.md) 硬规则，
该例「只能作为开发样本或复现基线，不得进入正式集」；PoC 与答案模板逐字节相同，不能证明由
Agent 生成，`model_contribution` 也无定位贡献。可保留为「双端可复现」基线，但不能凑课程 10 例。

### 4.4 CG-18 / arvo:12420（libidn2，CWE-122）

基线：`verdict=pass`，vul_exit=1 / fix_exit=0；sink `libidn2/lib/lookup.c:621`（`strcpy`）；
PoC 260 B（32+1+32 个 UCS-4 码点）；`propagation` 4 要素 / 15 refs，全部复算通过；
`image_provenance.mode=recorded_bindings、verified_live=false、matches_prior_case_json=true`。

- **A 过，带 caveat**：`severity=high`、`cvss_base_score=7.1`，但 `reviewed_by="agent"`、
  `final=false`、`human_signoff_required=true`；`dimensions.deployment_conditions.value="unproven"`、
  `missing_dimensions=["deployment_conditions:no_witness_of_production_caller_buffer_size_and_location"]`
  ——**该缺项没有出现在 `case.json.acceptance`**（门禁只判 value/evidence 非空，"unproven" 也算齐）。
  另：`severity.json.limitations` 仍写「causal_chain_verified=false」，与当前 `case.json` 相反（陈旧文本）。
- **B 过（recorded）**：`benchmark_verified=true`、`benchmark_kind=vuln_fix_diff`，日志/退出码齐，
  `provenance.matches=true`；镜像不在本机但 tag 可拉。
- **C 过**：输入（260 B=65 码点）、汇聚（`u32_to_u8:602 → idn2_lookup_u8:611 → strcpy:621`，
  写 `malloc(64)` 的 fuzz:67）、缺失检查（`616-620` 只声明契约）→ 恒等式 66 写 / 64 区。
- **D 不齐**：

| 缺口 | 类型 | 现有替代 | 能否复算 |
|---|---|---|---|
| `review.json` / `receipt.json` | 复核/回执 | 无模板、无文件 | 否（人或外部） |
| `deployment_conditions` 未证 | 证据 | 文件已自标 unproven | 否，需生产侧调用点证据 |
| 轨迹导出 / verify·report 参数 | 材料 | attempts 16、blackboard 24；仅 locate 带参数 | 轨迹可导出；参数否 |
| live 镜像对账 | 证据 | `verified_live=false`，`live_error=No such image` | 是（拉 tag 重跑 report），但会写 `artifacts/` |
| 交付包 | 材料 | 无 | 是 |
| `severity.json` 陈旧的 causal=false 文本 | 材料 | — | 是（重生成 limitation） |

**结论：needs_evidence。**

### 4.5 CG-29 / arvo:11011（libarchive rar5，CWE-122）

基线：sink `libarchive/.../archive_read_support_format_rar5.c:2424`
（`window_buf[write_idx & cmask] = (uint8_t) num`）；PoC 642 B；4 要素 / 13 refs 全过；
`input_bytes` 的 `window_size=0` 由「`calloc(1, window_size)` 得 1 字节区域」反推（`arithmetic_identity`）。

- **A**：同 CG-18 的 caveat（agent 签、`deployment_conditions=unproven`、无 final）。
- **B**：recorded；`provenance.matches=true`；tag 可拉。
- **C 过**：`rar5.c:1363-1365` 的 `window_size = is_dir ? 0 : …`、`:2419-2424` 的
  `write_idx & cmask`（`cmask=-1`）、1 字节区域与 offset 1 写点闭合；上游 `patch.diff:10-13`
  在 `window_size==0` 时置 mask=0，作为旁证。
- **D**：同 CG-18 六项（复核/回执、未证维度、轨迹导出、参数、live、交付包）。

**结论：needs_evidence。**

### 4.6 CG-30 / arvo:29633（fio，CWE-121）

基线：sink `fio/filesetup.c:1656`（`sprintf(file_name + len, "%s", fname)`）；PoC 6019 B；
4 要素 / 14 refs 全过；`6001 = 6000+1` 写进 `char file_name[4096]`；fix 日志第 18 行
`value exceeds max length of 4096` 是「缺长度上限」的正面反证。

- **A/B/C**：同 CG-18 模式（A 带 unproven caveat；B recorded；C 14 refs 全过）。
- **D**：同 CG-18 六项。

**结论：needs_evidence。**

### 4.7 CG-31 / arvo:61675（Exiv2，CWE-122，container-overflow）

基线：sink `bmffimage.cpp:208` / `BmffImage::brotliUncompress`；PoC 98339 B；
4 要素 / 15 refs 全过；`case.json.regate` 记录 `weak→strong`（判据 `diagnostics-frames-v2+container-overflow-v1`，
`log_sha256=863d06c1…`，frames=16 / user=14）。

- **A**：同 CG-18 的 caveat。
- **B**：recorded；`provenance.matches=true`；`verify/result.json` 的 `evidence.root_cause=weak`
  是历史快照（未改），`case.json` 的 `strong` 来自只读重判——两者并存本身要写进报告。
- **C 过（重判）**：日志 `:15` 有 `#3 … brotliUncompress … bmffimage.cpp:208`、`:24` 有
  `196606-byte region`、`:10` 有 `WRITE of size 201672`；`patch.diff` 的
  `+ if (++dos > 1 || total_out > 131072)` 对应缺失检查。C 成立，但**不是一次新 verify**。
- **D**：同 CG-18 六项，另加：

| 缺口 | 类型 | 说明 | 能否复算 |
|---|---|---|---|
| `sink.file="bmffimage.cpp"` | 代码位置 | 非工作区相对路径，实际是 `src/exiv2/src/bmffimage.cpp` | 是（补前缀） |
| `sink.symbol` 来源 | 材料 | 来自 raw trace 文本命中，不是栈帧符号字段 | 只能如实标注 |
| `verify/result.json` 与 `case.json` 判据分叉 | 材料 | weak vs strong | 是（读 `regate` 与日志） |

**结论：needs_evidence。**

### 4.8 CG-36 / arvo:54839（libredwg，CWE-122）

基线：sink `src/decode.c:275`（`tbl->size = bit_read_RS(dat)`，结构体偏移 4）；
PoC 606 B；4 要素 / 13 refs 全过；`256 = 128×2`、写点 `offset 260 = 2×128+4`；
`num_sections=0` 由分配大小**算术反推**（未逐字节 dump，`CAUSAL-CG36` 的 I2）。

- **A**：同 CG-18 的 caveat。
- **B**：recorded；`provenance.matches=true`；tag 可拉。
- **C 过**：`decode.c:729` `calloc(sizeof(Dwg_Section), num_sections+2)`、`:765-769` 固定解 5 张表、
  `:274` 直接取 `section[id]`、`:275` 写 → 边界缺失成立；`num_sections` 的取值是反推，已如实标注。
- **D**：同 CG-18 六项，另加：

| 缺口 | 类型 | 说明 | 能否复算 |
|---|---|---|---|
| `description.txt` 与崩溃点不同源 | 材料 | 描述讲 `decode_r11`，实测栈在 `decode_preR13_section_hdr`（上游 CVE 口径） | 否，只能标 inferred |
| `sink.file="src/decode.c"` | 代码位置 | 实际 `src/libredwg/src/decode.c` | 是（补前缀） |
| `num_sections` 未逐字节 dump | 证据 | 反推 | 是（读 PoC 头字节），但需重做取证 |

**结论：needs_evidence。**

---

## 5. 汇总与 10 例目标差距

### 5.1 计数

| 项 | 值 |
|---|---:|
| 独立高危根因（按 arvo 去重） | 9（8 CG + VG-01） |
| A/B/C 成立 | 8（8 CG；其中 CG-14 的 B 有 source 绑定缺陷；VG-01 因果链 false） |
| 严格可提交 | 0 |
| 补材料后可提交 | 7 |
| 不可提交 | 1（CG-14） |
| 缺回执 | 8 |
| 缺人工复核 | 8 |
| 缺 Agent 轨迹导出 | 8 |
| 缺完整逐例采样参数 | 8 |

### 5.2 与「10 个独立高危」的差距

- **按严格口径**：0 / 10，差 10。
- **补齐材料后**：7 / 10，差 3。三格分别是：
  1. CG-14 换干净输入重跑（不能用答案模板）；
  2. VG-01 补服务端事件/源码树（[COURSE-GAP-20261118.md](COURSE-GAP-20261118.md) §3.6，本审计未重审）；
  3. 新增 1 个独立高危根因（原计划的第 10 例）。
- 若把 CG-14 继续当「复现基线」保留但不计入，则 10 例目标需要 **3 个新增/修复根因**，与
  `LEDGER-AUDIT.md` 的「9 个独立高危、8 个 benchmark+因果链」相比，瓶颈已经从「因果链」转成
  「交付材料 + 3 个根因位（CG-14 重跑、VG-01 闭链、1 个新根因）」。

---

## 6. 系统性发现（比逐例更值得先修）

1. **`course_ready` 实际不复核 `review.json`**。[report.py](../agent/stages/report.py) 的
   `_acceptance` docstring 写着「必须存在人工复核记录（review.json）」，但实现只检查
   回执、材料、严重性、高危、因果链；`_review_record()`（:1046）定义后**没有任何调用点**，
   测试里还被 mock 成 `{"valid": True}`（`tests/test_high_severity_gate.py:33`）。
   结果：8 例的 `course_ready_blocked_by` 都只剩 `official_receipt_not_attached`。
2. **11-15 批次把 `human_review_pending` 从 3 例的 blockers 里删掉了**。
   `case.json.bak-regate-20261115T192145` 里 CG-01/07/14 的
   `course_ready_blocked_by=["human_review_pending","official_receipt_not_attached"]`，
   现文件只剩后者，而 `human_reviewed` 仍是 false。**删字段不是复核**，这一步必须在提交材料里
   如实说明，不能拿来当「复核已完成」。
3. **严重性六维的「unproven」不算缺**。CG-18/29/30/31/36 的
   `severity.json.missing_dimensions` 明确列了 `deployment_conditions:…`，但
   `_validate_severity` 只判 value/evidence 非空，`unproven` 也算「有值」，于是
   `case.json.acceptance` 里看不到这个缺口。
4. **「镜像不可达」的前提已过期**。11-18 文档据此把 5 例降为 `recorded_bindings`；本次实测
   `docker manifest inspect n132/arvo:<id>-{vul,fix}` 16 个 tag 均存在（15 个单 manifest +
   1 个 manifest list；CG-01 两镜像还在本机）。
   要恢复 `verified_live=true`，只需拉镜像重跑 report——但那会写 `workspace/artifacts`，本次未做。
5. **Agent 轨迹只存在 SQLite**（`.runtime/vulnmap.db` 的 `attempts/blackboard`），没有导出；
   且只有 locate 阶段的 `llm` 参数（model/prompt_version/temperature/max_tokens），
   report/verify 的提示词版本与采样参数从未落盘——[MODEL-PARAMS.md](MODEL-PARAMS.md) 的 0/9
   在 8 例上仍然成立。
6. **交付包覆盖不足**：`deliverables/` 只有 CG-01、CG-07；其余 6 例没有 case pack。
   6 例连 `receipt.TEMPLATE.json` / `review.TEMPLATE.json` 都没有。
7. **报告与判定不同批次**：`logs/report.error.json` 8 例里 7 例是 `ImageMissing`、CG-36 是
   `NameError`；CG-01/07/14 的 `case.json`（11-15）比 `report.md`（11-10/11-11）新，
   说明 `case.json` 与 `report.md` 不是同一次运行产出，且最后一轮 report 运行在 `ImageMissing`
   处失败。提交时必须把这条时间线写清楚。
8. **案例身份差异**：CG-14 含答案模板；CG-01/CG-07 属 DEV_SET（无答案污染，但参与过工具开发），
   引用时不能声称「盲测」。这三条不影响 A/B/C，但影响「自主发现」的表述。
9. **8 份 `report.md` 自相矛盾且不含危害论证**：头部写「LLM 参与关键决策」，紧接着写
   「过程来源：rule/hybrid（agent_discovered=False）；尚无模型提出关键结论的证据」——7 例如此
   （除 CG-07 为 `llm/True`）。六节模板里也没有 severity / 缺失检查的内容，危害论证只存在于
   `severity.json`。作为课程报告材料，这会被审阅人直接看出「报告没有说出它想证明的事」。

---

## 7. 可复算 / 不可复算清单

**能从现有 workspace 直接复算**：PoC 哈希、上游 4 件哈希、sink 行号、70 条 refs、
手写档案的 10 处 file:line、轨迹导出（SQLite→JSONL）、CVSS base、交付包打包、路径规范化、
`regate` 重判（读日志）。

**不能从 workspace 复算，必须人或外部**：`review.json`、`receipt.json`、verify/report 的
历史采样参数、CG-14 的干净输入重跑、CG-07/14 的上游 `patch.diff`、CG-18/29/30/31/36 的
`deployment_conditions` 生产侧证据、CG-36 的 `num_sections` 逐字节 dump。

**能重跑但本次未做（会写 workspace）**：8 例的 live 双端对账（拉 registry 镜像）；
CG-14 的干净输入重跑；VG-01 的服务端实验。

---

## 8. 边界声明

- 未改 `workspace/` 任何文件；未改 `experiments/LEDGER.json`、`LEDGER-AUDIT.json`、
  `case.json`、`severity.json`、`logs/`、`artifacts/`。
- 运行过的只读命令：`sha256sum` 对比、`docker images` / `docker manifest inspect`、
  `python3 experiments/course_gap_wiring.py --verify -v`、SQLite 只读查询。
- 没有 `git commit`（本仓不是 git 工作区）。
- 复核：`find workspace -newermt '2026-11-25 17:34:00' -type f` → **0 个文件**；本次只新增
  `docs/COURSE-CASE-AUDIT.md` 与 `experiments/course-case-audit.json`。
- 本审计不替任何案例签「人工复核」；`verified_by=evidence_refs` 与本次的逐条核对都只到
  「可复算」为止。

---

## 附录 A：材料存在矩阵

| 案例 | case.json | report.md | logs | verify | propagation | severity | patch.diff | error.txt | repo-vul | receipt 模板 | review 模板 | review.json | receipt.json | deliverables |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CG-01 | ✓ | ✓ | 4 | ✓ | 手写 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ |
| CG-07 | ✓ | ✓ | 6 | ✓ | 手写 | ✓ | — | — | ✓ | ✓ | ✓ | — | — | ✓ |
| CG-14 | ✓ | ✓ | 4 | ✓ | 手写 | ✓ | — | — | — | — | — | — | — | — |
| CG-18 | ✓ | ✓ | 4 | ✓ | refs 15 | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — |
| CG-29 | ✓ | ✓ | 4 | ✓ | refs 13 | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — |
| CG-30 | ✓ | ✓ | 4 | ✓ | refs 14 | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — |
| CG-31 | ✓ | ✓ | 4 | ✓ | refs 15 | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — |
| CG-36 | ✓ | ✓ | 7 | ✓ | refs 13 | ✓ | ✓ | ✓ | ✓ | — | — | — | — | — |

## 附录 B：源码行号核验（本次逐个打开）

| 案例 | 断言 | 实际行 |
|---|---|---|
| CG-01 | `fontfname` 声明 / 分支检查 / 无检查写点 | `pdf_font.c:171` / `:189` / `:332` |
| CG-07 | 按 `2*i+3` 分配 / ghost-line 无检查 / 写点 | `render.c:881` / `:941-946` / `:942` |
| CG-14 | 扩容后 memmove / 写点 | `ofpbuf.c:471` / `:473` |
| CG-18 | `u32_to_u8` / `idn2_lookup_u8` / `strcpy` / `malloc(64)` | `lookup.c:602` / `:611` / `:621` / `fuzz…8z_fuzzer.c:67` |
| CG-29 | `window_size=0` / 写点 | `rar5.c:1363-1365` / `:2424` |
| CG-30 | `char file_name[PATH_MAX]` / `sprintf` | `filesetup.c:1648` / `:1656` |
| CG-31 | `arr.alloc` / `available_out` / 解码调用 / 调用点 | `bmffimage.cpp:204` / `:205` / `:208` / `:541` |
| CG-36 | `calloc(num_sections+2)` / 5 次调用 / 写点 | `decode.c:729-730` / `:765-769` / `:275` |
