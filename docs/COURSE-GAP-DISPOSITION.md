# 课程 5 份缺口处置表（2026-11-26）

> **这 5 份是什么**：已通过 V2 口径的 5 例（CG-01 / CG-29 / CG-30 / CG-31 / CG-36）之外，
> 挡住「10 例四项全满足」的**全部剩余缺口**——CG-07、CG-18、CG-14、VG-01，加第 10 例候选 `arvo:67968`。
> 每份只给一个决策（`retain` / `replace` / `block`）、**一条**可验收条件、所需证据与外部输入、成本与优先级。
>
> **输入**：[COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md)（逐例审计）、[COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md)（6 例 V2 重审）、
> [COURSE-EVIDENCE-DECISIONS.md](COURSE-EVIDENCE-DECISIONS.md)（D1/D2/D3 决策与候选排序）、
> [TENTH-CANDIDATE-ADMISSION.md](TENTH-CANDIDATE-ADMISSION.md)（`arvo:67968` 三闸与逐项预检），
> 以及 [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md)、[COURSE-SUBMISSION-PACK-20261125.md](COURSE-SUBMISSION-PACK-20261125.md)、
> `workspace/**`、`agent/**`、`scripts/**`（只读核到 file:line）。
> **产物**：本文件 + [experiments/gap-disposition.json](../experiments/gap-disposition.json)（机读）。
> **纪律**：只写 `docs/` 与 `experiments/`；**未改**业务代码（`agent/**`、`scripts/**`、`bin/**`）、
> **未改**任何历史证据（`workspace/**` 的 `case.json` / `severity.json` / `propagation.json` / `logs/` / `artifacts/` / PoC）、
> **未改** `experiments/LEDGER.json`；**未拉任何镜像**（只做 manifest 级只读探测）；**无 `git commit`**（仓库根不是 git 工作区）。

---

## 0. 结论先行

| 项 | 值 |
|---|---:|
| 已通过（`strict_submittable=true`） | **5**（CG-01 / CG-29 / CG-30 / CG-31 / CG-36） |
| 本表缺口份数 | **5**（CG-07 / CG-18 / CG-14 / VG-01 / `arvo:67968`） |
| 独立高危根（按 `root_key` 去重） | **9** |
| 目标 | **10 例**四项全满足 |
| 决策分布（当前 5 份） | `retain` **3**（CG-07 / CG-18 / 67968）· `replace` **1**（CG-14）· `block` **1**（VG-01） |
| 67968 关闭后剩余 4 份 | `retain` **2**（CG-07 / CG-18）· `replace` **1**（CG-14）· `block` **1**（VG-01）；合计 **4** |
| 67968 过线后的可提交数 | **6**，仍差 **4** |

**一句话**：5 份缺口 = **1 个新根 + 4 个既有根**；`arvo:67968` 哪怕全部过线，也只是把可提交从 5 推到 6，
**`10 − 5 − 1 = 4`**，CG-07、CG-18、CG-14（或其替换根）、VG-01 这 4 份仍然必须各自关掉，且**每一份最多只加 1**。

---

## 1. 口径与决策词（先写死，后面不改）

### 1.1 判定公式（沿用 V2，不改判据文本）

```text
strict_submittable = A.holds ∧ B.holds ∧ C.holds ∧ D1 ∧ D2 ∧ D3 ∧ D4
receipt.json 不参与判定（external_status = pending）
pass_with_caveats 算通过，但阻断级 caveat 出现即该层 fail，不得用「已披露」换通过
```

### 1.2 三个决策词

| 决策 | 含义 | 关闭后计数 | 现在计数 | 本表适用 |
|---|---|---:|---:|---|
| **`retain`** | 根保留在目标集、**不换样本**；缺口靠补证/重取证关闭 | +1 | 0 | CG-07、CG-18、`arvo:67968`（立项＝保留候选） |
| **`replace`** | 现有输入/材料不可救，**必须换输入**（必要时连根一起换）；旧根 0 + 新根 1 = 1 | +1 | 0 | CG-14 |
| **`block`** | 今日不能推进，依赖**本仓拿不到**的外部输入；不占本地工时，超时转 `replace` | +1 | 0 | VG-01 |

> `retain` 不是「什么都不做」，是「不换样本、把材料做出来」；`block` 也不是「不做」，是「把外部字段列为唯一阻塞项」。

### 1.3 本轮新增的四条硬约束（按任务要求逐条落到行）

| # | 约束 | 落到哪一行 |
|---|---|---|
| C1 | **CG-07 / CG-18 不补历史参数**（补写＝伪造），只能重跑让参数落盘 | §3.1、§3.2 |
| C2 | **CG-14 必须自主证据**（PoC 不得与答案模板同字节） | §3.3 |
| C3 | **VG-01 走服务端对照**（官方 baseline/patched 两端，本地自建双端不计） | §3.4 |
| C4 | **新根因先立项、不计数** | §3.5 |

---

## 2. 总表（5 行）

| # | 案例 | 根（`root_key`） | 阻断层 | 决策 | 唯一可验收条件（摘要） | 优先级 | 工时 | 计数值 |
|---|---|---|---|---|---|---|---:|---:|
| 1 | **CG-07** | `arvo:10096` / GraphicsMagick / `render.c:942` | **D2** | `retain` | 新 verify 每次已记录调用带齐采样参数，D2 转 pass 并出新 `task_version_id` | **P3** | 2.4 h | 0 → 1 |
| 2 | **CG-18** | `arvo:12420` / libidn2 / `lookup.c:621` | **D2** | `retain` | 交付 run 的逐调用参数齐 + 判定只绑本 run 的日志与 PoC | **P1** | 1.7 h | 0 → 1 |
| 3 | **CG-14** | `arvo:11253` / Open vSwitch / `ofpbuf.c:473` | **D 污染 + B provenance** | `replace` | 非模板输入 3/3 稳定触发 + `source_sha256` 三方一致 | **P4** | 2.8 h | 0 → 1 |
| 4 | **VG-01** | `vulngym/nltk/40d0bc1d` / `wordnet_app.py:87` | **B（官方任务字段）** | `block` | 官方 baseline/patched 两端服务端对照成立 | **P5** | 0（+0.7 h 待字段） | 0 → 1 |
| 5 | **`arvo:67968`** | `arvo:67968` / lcms / `cmscgats.c:1251` | **无证据（planned）** | `retain`（立项） | vul 首帧 `ParseIT8` 的 heap WRITE、fix 干净、行号取镜像内 1251 | **P2** | 2.9 h | 0 → 1 |

合计：本地工时 **9.8 h**（最坏 14.7 h）、拉取 **≈108 min**、峰值磁盘 **≈19.6 GB**（按顺序跑、跑完删镜像）。
**这 5 行全部关闭 = 10 例**；任意一行漏掉，总数就停在 9。

---

## 3. 逐例处置

### 3.1 CG-07 / `arvo:10096`（GraphicsMagick，CWE-122，`render.c:942`）

**现状**：`A/B/C/D1/D3/D4 = pass_with_caveats`，**`D2 = fail`**，`strict_submittable=false`（[COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md) §2/§3.1）。
阻断原因不是材料缺件，而是**记录形态**：verify 阶段 decisive 的模型闭环 2 轮（1931 / 1617 tokens）只落 `round/llm_status/llm_tokens`，
无 `model/temperature/max_tokens/prompt_version`；而 round 2 的 sha 与交付 PoC 完全相同 → 决定性调用不可复现（`D2-A`）。

**本轮亲核的根**（不是「历史忘了存」）：

| 位置 | 事实 |
|---|---|
| `agent/stages/verify.py:216-231` | `_ask()` 的 `info` 只含 `retry_round/status/finish_reason/completion_tokens/prompt_tokens/tokens/prompt_chars/error` |
| `agent/stages/verify.py:134-136` | `_round_record()` 调 `rnd.to_record()`，**未传 `params`** |
| `agent/stages/verify.py:2022-2026` | 闭环记录落在 `detail.model_loop_round`（不是 `detail.llm`） |
| 对照 `agent/stages/locate.py:193/217/239` | locate 走 `params=cfg.public_params()`（`agent/llm.py:44-58`：model/temperature/max_tokens/response_format/max_retries/base_url） |

**决策：`retain`。** 根、PoC、因果链都不动；要换的是「这一次运行怎么记」。

**唯一可验收条件**：一次新 verify 运行的**每一次**已记录 LLM 调用均带齐 `model / prompt_version / temperature / max_tokens`
（及实际使用的 `response_format` / `base_url` / `max_retries`），且无任一 decisive 阶段 `sampling_params=missing`；
据此重算 `D2=pass`、`strict_submittable=true`，并给出新的 `task_version_id`（旧 `tv-53f4d6041fba8fcb` 降为历史）。
校验动作：`python3 experiments/course-review-batch/recompute_batch.py --check` → CG-07 判 `true`。

**所需证据**：① `n132/arvo:10096-vul`+`-fix`（内容 **5906.1 MiB**，本机无，manifest 可达）；② 一次带参数落盘的 verify 运行；
③ 9 表轨迹导出；④ 按新 `task_version` 重签的 `review.json`（现件 `233b3867…` 指向旧版本，须新件或 `supersedes` 声明）；
⑤ D4 哈希清单（PoC 四处一致 + 上游件全等 + 镜像 digest）。
**外部输入**：无（自足）。但**依赖共同前置 P0**（见 §5）：不修 `verify.py` 的记录路径，重跑还是同一种缺参数。

**成本/优先级**：拉 55 min（19.6 GB）+ 重跑 20 min + 材料 65 min ≈ **2.4 h**（2 轮 3.5 h）。**P3**。
拉取最贵（5906 MiB 是 5 行里最大的镜像对），故排在 CG-18 之后。

**与已通过 5 例的边界**：不同 project、不同 `root_key`，**不得**借用 CG-01 的 `review.json` / 镜像 / provenance，
也不得把任何已通过例的 severity 论证当自己的论证（V2 §10：每例须有自己的 `review.json` 与参数矩阵）。
**重跑不产生第二例**（同一 `root_key`，见 §4.3 N1）。

**禁止表述**：`T=0.0`（或任何推断值）回填到 2026-11 的那次调用；「参数已补齐」；`benchmark_passed`。

---

### 3.2 CG-18 / `arvo:12420`（libidn2，CWE-122，`lookup.c:621`）

**现状**：18 条 caveat 中只有 **`D2-B` 是阻断级**：3 条已记录的模型闭环调用（tokens 10890 / 3231 / 3418）无参数；
其余 `A1/A5/A6/C9/D1-*/D4-*` 均为披露级。C 层是 5 行里最干净的（15 条 refs 全过、`66 写 / 64 区` 恒等式闭合）。

**决策：`retain`。** 阻断点与 CG-07 同源（`agent/stages/verify.py` 的记录形态），但本例还多一条必须一起消掉的混用风险：
`artifacts.prior-run/` 与交付 run 并存（`B7`），引用事件必须带 `run_id`。

**唯一可验收条件**：重跑后的**交付 run** 中，每次已记录 LLM 调用在同一记录内带齐 `model / prompt_version / temperature / max_tokens`，
且交付判定（vul `exit≠0` / fix `exit=0`）只与该 run 自己的日志和 PoC（`sha256 d9ba75e1672d…`，260 B）绑定，不再引用 `prior-run` 工件；
据此 `D2=pass`、`strict_submittable=true`。
校验动作：`recompute_batch.py --check` → CG-18 判 `true`，且材料里 `B7` 被显式消解（写明按 `run_id` 取值）。

**所需证据**：① `n132/arvo:12420-vul`+`-fix`（内容 **1785.7 MiB**，manifest 可达，本机无）；② 带参数落盘的重跑；
③ 带 `run_id` 的轨迹导出；④ 重签 `review.json`（17 条 refs 指向新 run 工件，旧件保历史不作 decisive 证据）。
**外部输入**：无。**依赖 P0**。

**成本/优先级**：拉 17 min（5.9 GB）+ 重跑 30 min + 材料 50 min ≈ **1.7 h**（2 轮 2.6 h）。**P1** —— 5 行里单位时间回报最高。

**与已通过 5 例的边界**：不与 CG-29/30/31/36 共用参数矩阵；不把旧 `review.json` 的 refs 当新 decisive 证据；
两个历史 run 不构成两例（N1）。

---

### 3.3 CG-14 / `arvo:11253`（Open vSwitch，CWE-122，`ofpbuf.c:473`）

**现状**：`not_submittable`，两个**阻断级**（不是披露级）问题：

| 阻断 | 事实（本轮实读） |
|---|---|
| 答案污染 | `agent/templates/PROVENANCE.json:12-16` 记 `cg14_ofctl.bin`（32 B，`sha256 d0f49209…`）`identical_to_poc=CG-14-arvo-11253`；`task.json.input_template=cg14_ofctl.bin`；交付 PoC 同哈希 |
| provenance 断链 | `workspace/CG-14-arvo-11253/artifacts/verify/result.json` 的 `root_cause.provenance.source_sha256=""`、`matches=false`、`missing=["source_sha256"]`（`image_digest` 有值 `sha256:ab66893a…`） |

`vul exit=1 / fix exit=0` 本身成立，`propagation.json` 为手写档案；无 `patch.diff` / `error.txt` / `repo-vul.tar.gz` / 模板 / 交付包。

**决策：`replace`。** 输入不可救（它**就是**答案），所以不是「补字段」而是「换输入并重取 provenance」。根可保留，槽位只算 1。

**唯一可验收条件**：用**非答案模板**的自生成输入（`sha256 ≠ d0f49209…`，生成过程不读 `agent/templates/*` 与 `cg14_ofctl.bin`）
在 vul 端同 sink（`openvswitch/lib/ofpbuf.c:473`）**3/3 稳定触发** `heap-buffer-overflow`、fix 端 **3/3 `exit=0`**，
同时 `verify.root_cause.provenance.source_sha256` 非空并与镜像内源码树一致（文件 `sha256` = git blob 复算 = 上游 blob sha 三方相等）。
校验动作：新 `verify/result.json` 的 `provenance.matches=true` 且 `missing=[]`；新 PoC 哈希与 `input_template` 及模板目录全部不同；同输入 3 次复跑结果一致。

**所需证据**：① `n132/arvo:11253-vul`（内容 **998.3 MiB**，本轮实测）+ `-fix`（**两次 manifest 探测均失败**，体积未测，按 ≈1.0 GiB 估）；
② 独立构造器（2 轮内不成立即触发 S4）；③ 干净 verify run（逐轮 `input_sha256/duplicate/distinct` 全留）；
④ 能从镜像内取则补 `patch.diff`/`error.txt`/`repo-vul.tar.gz`，取不到如实登记；⑤ `review.json` 与交付包（形态可借 CG-01，**字段值不可**）。
**外部输入**：无。

**成本/优先级**：拉 ≈19–25 min（≈7 GB）+ 构造 60–90 min + 双端与材料 60 min ≈ **2.5–3 h**（止损 S4 后封顶 4 h）。**P4** —— 唯一带「可能白跑」的替换项。

**兜底**：触发 S4（2 轮不成立，或新输入仍与官方 PoC 同字节）→ 槽位**转换根**（新 arvo 号，走 G1-a…G1-e），
CG-14 计 0、新根计 1，合计仍是 1。**不得两边都计**（§4.3 N2）。

**与已通过 5 例的边界**：不得借 CG-29/30/31/36 的 builder 产出来充「自主输入」；不把 CG-14 的污染结论拖累其它 4 例的独立性表述。

**禁止表述**：把 `cg14_ofctl.bin` 的变体写成「自主生成」；把「双端可复现」写成「可提交」；`model_contribution` 既无定位贡献，不得写「模型自主发现」。

---

### 3.4 VG-01 / `vulngym/nltk/40d0bc1d`（CWE-306，`wordnet_app.py:87 → 92/93`）

**现状**：归属这一最硬的段落**已闭合**（原件字节 = 重建件字节 = `f4fa4adc…a4f23`，34427 B / 1002 行，Contents API + codeload tarball + blob sha 三方互算）；
行为证据在原件上同样成立（stdout 恰 22 B `Server shutting down!\n`、rc=0、端口关闭）。
**卡点是任务身份**：官方 `baseline_url` / `patched_url` **全仓 0 命中**，`vuln_commit` / `fix_commit` / `image_digest` 亦无 →
B 层不成立，且这是**本仓不可自造**的（自建 URL 对＝自己出题）。

**决策：`block`。** 不占本地工时，把外部字段列为唯一阻塞项；超时即转 `replace`（换新根，槽位仍只 +1）。

**唯一可验收条件**：同一未认证请求 `GET /SHUTDOWN%20THE%20SERVER` 在**官方 baseline 与 patched 两端**形成服务端对照——
baseline 侧 stdout 恰为 `Server shutting down!\n`、`rc=0`、端口关闭；patched 侧 `403`、stdout 零字节、进程存活；
两端 URL 由官方任务字段（`baseline_url` / `patched_url` + `vuln_commit` / `fix_commit`）绑定。
**本地自建双端（重建件, 镜像）不计**，它只能写「与官方语义一致的自建双端」。
校验动作：两端 `server.stdout.log` 字节级比对 + `returncode` + `port_listening_after_shutdown` 三项落盘，且 URL/commit 能追到任务注册表原件（不是本仓拼写）。

**所需证据/外部输入**：

| 类别 | 项 | 状态 |
|---|---|---|
| 已有 | 原件字节三方互算、原件上的行为复现、重建链第二跳 `diff` 无输出 | ✅ |
| 待补 | 官方两端服务端日志（`host:port`、时间戳、`rc`、stdout 哈希） | ❌ 依赖任务字段 |
| 待补 | `review.json`（本批未建；单建也仅空壳，须与 B 层同时成立） | ❌ |
| **外部必需** | `baseline_url`、`patched_url`、官方 `vuln_commit`/`fix_commit`、`image_digest`、平台侧服务端事件日志或 runner 版本 | ❌ 全缺 |

**成本/优先级**：本地 **0**；字段到位后起 2 个服务 ≈10 min + 1 轮对照 ≈20 min + 材料 ≈15 min ≈ **0.7 h**，磁盘 0。**P5**（外部先到可插队）。

**顺带登记的工程缺陷**（不阻塞服务端对照，但阻塞「归属写成材料」）：
`scripts/vg01_source_check.sh:29` 把 `RECONSTRUCTED_SHA=f4fa4adc…`（**正是原件哈希**）列入坏件黑名单，`:99` 命中即 `fail 6`
→ 任何真原件永远过不了闸门。修法 M1/M2 见 [COURSE-EVIDENCE-DECISIONS.md](COURSE-EVIDENCE-DECISIONS.md) §2.5，属 `scripts/`，本表只登记。

**与已通过 5 例的边界**：**不得**与 EG-02 / CG-01（`arvo:44034`，`pdf_font.c:332`）合并计根——同根永不新增计数；
也不得把 EG-02 拿来顶这个槽位。VG-01 与 67968 是**两个不同的根**，不互相抵扣。

**禁止表述**：`benchmark_verified`、「官方双端已验」、「VulnGym 必选项已满足」。

---

### 3.5 `arvo:67968`（lcms，`cmscgats.c:1251`）— 第 10 例候选

**现状**：G1 `PASS`（`NEW-ID` + `NEW-ROOT` 实测：45 raw / 44 归一化 id / 51 根）、G2 `PASS`（带两条材料限定）、
G3 `CONDITIONAL-PASS`（可取得、今日 0 证据）。**`case.json` 里没有任何字段可以因为立项变绿**；状态 = `planned`。

**决策：`retain`（立项施工），计数值 0。** 它是**库外唯一可用新根**：id 新、`root_key` 新、无外部判定方依赖（ARVO 通道自足）。

**唯一可验收条件**：vul 端同输入首帧为 `ParseIT8`（内联 `AllocTable`）的 `heap-buffer-overflow WRITE` 且 `exit≠0`；
fix 端同输入 `exit=0` 且无 sanitizer 签名；`sink` 行号取 **vul 镜像内** `src/cmscgats.c:1251`（不得用 fix-parent 的 `1384`，S10）。
校验动作：`experiments/tenth-67968/runs/<UTC>/{vul,fix}` 的 `stdout/stderr/exit_code` 原字节日志；ASAN 首帧函数名+行号对齐 1251；fix 侧 `grep` 无 `AddressSanitizer` 签名。

**所需证据**：镜像对（`vul` 727,038,897 B / `fix` 783,331,727 B = **1.4066 GiB**，manifest 已验；本轮 `-fix` 复测 40 层 / 747.0 MiB 与之一致；
`RepoDigest` 今日未钉 = U8）、U1/U4 实测 N 与 `sizeof(cmsIT8)`、U6 `/out/cmsIT8_load_fuzzer` 的 sha256、U7 seed corpus、
`docs/SEVERITY-67968.md`（六维 + CVSS 预判 7.1）、`review.json`（具名 `reviewer_id` + ≥6 refs 逐条 sha256）、`task_version`。
**外部输入**：无（自足；这是它优于 VG-01 的关键）。

**成本/优先级**：拉 14 min + 探针 10 + 构造 20–45 + 双端 15 + 严重性 40 + 材料 50 ≈ **2.9 h**（最坏 3.9 h），磁盘 4.8 GB。**P2**。

**与已通过 5 例的边界**：不得借 CG-07（GraphicsMagick / mvg 家族）的行号、severity 论证或构造器；
不得借任何已通过例的 `review.json`/`evidence_refs`；同 `fix_commit` 的其它 ARVO 号（U10 未清）不得并计。
**立项 ≠ 过线**：本表不把「有根因」当「有案例」；计数只在 S2/S3/S4 产物到位后才 +1。

**禁止表述**：`benchmark_passed`、`verified`、「第 10 例已达成」、「根因已定位即计数」。

---

## 4. 数量关系（本表的核心）

### 4.1 算术

```text
已通过（strict=true）                     5    CG-01 CG-29 CG-30 CG-31 CG-36
缺口份数（本表行）                        5    CG-07 CG-18 CG-14 VG-01 arvo:67968
  ├─ 其中新根                             1    arvo:67968
  └─ 其中既有根补证/替换                  4    CG-07 CG-18 CG-14|替换根 VG-01

10 - 5        = 5   （缺口份数）
10 - 5 - 1    = 4   （67968 过线后仍需补证/替换的份数）
5 + 1 + 4     = 10  （目标达成式）
```

### 4.2 三个时点的计数

| 口径 | 现在（2026-11-26） | **仅** 67968 过线 | 目标 |
|---|---:|---:|---:|
| 独立高危根（去重 `root_key`） | 9 | **10** | ≥10 |
| `strict_submittable=true` 例数 | 5 | **6** | **10** |
| 缺口份数（本表行） | 5 | **4** | 0 |
| 其中 `retain` | 3 | 3 | 0 |
| 其中 `replace` | 1 | 1 | 0 |
| 其中 `block` | 1 | 1 | 0 |

**读法**：67968 过线只让「根」到 10、「可提交」到 6。**「第 10 个根因过线」不等于「10 例达成」**——
剩余 4 份（CG-07、CG-18、CG-14|替换根、VG-01）必须各自关掉，缺一不可。

### 4.3 不得重复计数（8 条硬规则）

| # | 规则 | 一违反就虚增成 |
|---|---|---|
| **N1** | 同一 `root_key` 的重跑只是补证：CG-07 / CG-18 重跑前后仍是一例 | 把 fail 与 pass 各计一次 → 11 |
| **N2** | CG-14 与其替换根互斥：旧 0 + 新 1 = 1 | 两者都计 → 11 |
| **N3** | `arvo:67968` 只计 1，不得既算「第 10 根」又算「CG-14 的替代」 | 4 份缺口被算成 3 → 停在 9 |
| **N4** | EG-02 与 CG-01 同根（`arvo:44034` / `pdf_font.c:332`），永不新增计数，也不得顶 VG-01 的槽位 | 10 → 11 |
| **N5** | `sink` 路径先归一化（去仓库顶层前缀）：`ghostpdl/pdf/pdf_font.c` 与 `pdf/pdf_font.c` 同一 sink（X4） | 9 → 10 的假第 10 例 |
| **N6** | 同一 `fix_commit` 的多个 ARVO 号只算 1（G1-d，如 `42938/42939/42940/42944` 全为 `afdbc940c601`） | 1 个 bug 变 4 例 |
| **N7** | 一例的 D1/D2/D3/D4 四件材料算 1 例，**不按材料件数或 caveat 条数计数** | 114 条 caveat 被读成 114 例 |
| **N8** | 已通过的 5 例不再进入本表任何一行，也不作为其它案例的替代品 | 同一案例吃掉两个槽位 |

### 4.4 为什么「根数到 10」不等于「10 例可提交」

现有 9 根里只有 5 根的材料齐；`CG-14` 甚至属于「根成立但案例不可提交」。
所以本课程的分母是**可提交案例数**，不是**发现根因数**：
`根数 ≥ 10` 只是必要条件，必须同时满足 `strict_submittable` 逐例为真且 `root_key` 两两不同，
才拿到「10 例四项全满足」。

---

## 5. 执行顺序与共同前置

### 5.1 两个前置（都不在本轮写入范围内）

| # | 前置 | 影响 | 内容 | 成本 |
|---|---|---|---|---:|
| **P0** | `verify` 阶段参数落盘路径 | **CG-07 / CG-18 共同前置**，不修则重跑仍 D2 fail | `agent/stages/verify.py:216-231` 的 `_ask()` 并入 `cfg.public_params()`（`agent/llm.py:44-58`）；`agent/stages/verify.py:134-136` 的 `_round_record()` 透传 `params`；或让闭环记录走 `detail.llm` | 0.8 h |
| **P1** | `scripts/vg01_source_check.sh` 黑名单 | VG-01 的**归属入库**（不阻塞服务端对照验收） | 删 `RECONSTRUCTED_SHA` 项（`:29`/`:99`）或降为「无外部锚点才告警」；新增 `file_sha256 = git blob = API blob sha` 三方判据（M1/M2） | 0.5 h |

> 两条都属**业务代码/脚本**，本表按纪律**只登记不实施**；需要在下一轮单独开任务，否则 CG-07/18 的重跑是重复劳动（各烧 ~1 h + 19.6/5.9 GB）。

### 5.2 推荐顺序（按「单位时间对 10 例的贡献 ÷ 失败风险」）

| 序 | 动作 | 依赖 | 成本 | 收益 |
|---|---|---|---:|---|
| 1 | **P0** 修 verify 参数记录 | — | 0.8 h | 解锁 CG-07/18（否则两份重跑都白跑） |
| 2 | **CG-18** 重跑取证（P1 优先级） | P0 | 1.7 h | +1 → 6 |
| 3 | **`arvo:67968`** 立项 → 双端 → 严重性 → 台账 | 无 | 2.9 h | 第 10 个根（+0 直到 S4） |
| 4 | **CG-07** 重跑取证 | P0 | 2.4 h | +1 → 8（含 67968） |
| 5 | **CG-14** 换输入重跑（S4 兜底转换根） | 无 | 2.8 h | +1 → 9 |
| 6 | **VG-01** 等外部字段 → 两端对照 | 外部 | 0(+0.7) | +1 → 10 |
| 7 | **P1** 修闸门（可与 6 并行） | — | 0.5 h | 让 VG-01 的归属写进材料 |

**合计**：本地 9.8 h（最坏 14.7 h）+ 拉取 ≈108 min + 峰值磁盘 19.6 GB（顺序执行、逐题删镜像；4 例镜像同时留盘需 ≈37 GB）。

---

## 6. 复跑与校验（只读）

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 本表与机读件的算术/结构自检（期望：all assertions OK）
python3 - <<'PY'
import json
d = json.load(open('experiments/gap-disposition.json'))
assert [r['case_id'] for r in d['rows']] == ['CG-07','CG-18','CG-14','VG-01','arvo:67968']
assert not set(d['rows'][i]['case_id'] for i in range(4)) & set(d['counts']['passed_ids'])
now, target, tenth = d['counts']['passed_strict_now'], d['counts']['target_cases'], 1
assert target - now == 5 and target - now - tenth == 4
assert sum(r['decision'] == 'retain' for r in d['rows']) == 3
assert sum(r['decision'] == 'replace' for r in d['rows']) == 1
assert sum(r['decision'] == 'block' for r in d['rows']) == 1
assert all(r['counts_toward_ten'] == {'now': 0, 'when_closed': 1} for r in d['rows'])
print('all assertions OK')
PY

# 2) 缺口案例镜像体量（只读，不拉镜像；失败按 2 次重试，抖动即记 blocked）
for T in 10096-vul 10096-fix 12420-vul 12420-fix 11253-vul 11253-fix 67968-vul 67968-fix; do
  docker manifest inspect n132/arvo:$T 2>/dev/null | python3 -c "
import sys,json;d=json.load(sys.stdin);L=d.get('layers') or d.get('manifests')
print('$T', len(L), sum(l['size'] for l in L))" || echo "$T FAIL"
done

# 3) 两个前置的现场（应为现状，修好后应变化）
grep -n "params" agent/stages/verify.py || echo "0 hits（预期：今日无 params 传入，P0 修好后应出现）"
grep -n "RECONSTRUCTED_SHA" scripts/vg01_source_check.sh  # 期望：:29 定义、:99 命中即 fail 6

# 4) CG-14 的两个阻断项（只读）
grep -n -A4 '"provenance"' workspace/CG-14-arvo-11253/artifacts/verify/result.json
grep -n -A4 '"cg14_ofctl.bin"' agent/templates/PROVENANCE.json

# 5) 批次 6 例的判定（不得因本表变化；CG-01 见 COURSE-REVIEW-CG01 的复算器）
python3 experiments/course-review-batch/recompute_batch.py --check   # CG-29/30/31/36 仍 true，CG-07/18 仍 false
```

---

## 7. 边界声明

- **写入**：`docs/COURSE-GAP-DISPOSITION.md`、`experiments/gap-disposition.json`。仅此两件。
- **未改**：`workspace/**`（历史证据一个字节未动）、`experiments/LEDGER.json`、`experiments/LEDGER-AUDIT.json`、
  `experiments/course-review-batch/**`、`experiments/tenth-admission.json`；**未改**业务代码（`agent/**`、`scripts/**`、`bin/**`）。
- **未做**：拉镜像（只做 manifest/config 级只读探测）、跑容器、跑双端、签 `review.json`、生成 `receipt.json`。
- **命令**：`docker manifest inspect`（只读外部）、`grep`/`sed`/`python3 -c`（只读本仓）。
- **无 `git commit`**（仓库根不是 git 工作区）。
- 本表**不改变任何历史判定**，也**不替任何案例签复核**；每行的「决策」只决定下一步做什么，不构成通过声明。

---

## 附录 A：本轮实测观测（供复核对照）

| 观测 | 值 | 取法 |
|---|---|---|
| `10096-vul` / `-fix` | 42 层 / 3,082,145,729 B（2939.4 MiB）；42 层 / 3,110,809,887 B（2966.7 MiB） | `docker manifest inspect` |
| `12420-vul` / `-fix` | 24 层 / 934,001,048 B（890.7 MiB）；24 层 / 938,520,888 B（895.0 MiB） | 同上 |
| `11253-vul` | 27 层 / 1,046,795,643 B（998.3 MiB） | 同上 |
| `11253-fix` | **2 次探测均失败**（registry 抖动），未测 | 同上 |
| `67968-fix` | 40 层 / 747.0 MiB（= K17 的 783,331,727 B） | 同上（与文档一致） |
| `67968-vul` | 2 次探测失败；727,038,897 B 引自 K17 | 同上 |
| 本机 arvo 镜像 | 仅 `44034-vul`（4.52 GB）/ `44034-fix`（4.71 GB） | `docker images` |
| 磁盘 | 477 GB 可用 | `df` |
| `verify.py` 记录形态 | `_ask()` 无采样参数（`:216-231`）；`_round_record()` 不传 `params`（`:134-136`）；闭环落 `detail.model_loop_round`（`:2022-2026`） | `grep`/`sed` |
| `locate.py` 对照形态 | `params=cfg.public_params()`（`:193/217/239`）；`public_params` 见 `agent/llm.py:44-58` | `grep`/`sed` |
| VG-01 闸门 | `:29` `RECONSTRUCTED_SHA=f4fa4adc…`；`:99` 命中即 `fail 6` | `grep`/`sed` |
| CG-14 provenance | `source_sha256=""`、`matches=false`、`missing=["source_sha256"]` | 读 `artifacts/verify/result.json` |
| CG-14 污染 | `cg14_ofctl.bin` 32 B `d0f49209…` `identical_to_poc=CG-14-arvo-11253` | 读 `agent/templates/PROVENANCE.json:12-16` |

## 附录 B：与既有文档的关系（不推翻，只补齐）

| 文档 | 本表怎么用 |
|---|---|
| [COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) | 沿用其 A/B/C 判定与「0/7/1」分布；**不改写**；D 层口径以 V2 为准（该文档 §1 已自注被取代） |
| [COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md) | 沿用 4 true / 2 false 与 114 条 caveat；本表只把 CG-07/18 的阻断翻译成「一条可验收条件 + 一个共同前置」 |
| [COURSE-EVIDENCE-DECISIONS.md](COURSE-EVIDENCE-DECISIONS.md) | 沿用 D1（归属可闭合、闸门误杀）、D2（EG-02 同根不计数）、D3（只能新开根、A1 首选）；**不改**其 9 / 0 / 7 口径 |
| [TENTH-CANDIDATE-ADMISSION.md](TENTH-CANDIDATE-ADMISSION.md) | 沿用 G1/G2/G3 与 S1–S11 止损；本表为其补一行「过线后仍需 4 份」的计数关系 |
| [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) | 判定公式与 caveat 分级唯一来源；本表不新增判据，也不放宽任何阻断项 |
| [COURSE-SUBMISSION-PACK-20261125.md](COURSE-SUBMISSION-PACK-20261125.md) | 「已通过 5 例」的名单以此为准（CG-01/29/30/31/36，`external=0`） |

**补齐项**（不构成对历史的改写）：

| # | 补齐 | 影响 |
|---|---|---|
| G-1 | CG-07/18 的 D2 阻断被定位到 `agent/stages/verify.py` 的**记录形态**（不是历史漏存） | 把「重跑一次」升级为「先修记录路径再重跑」；否则重复劳动 |
| G-2 | CG-14 两个阻断项的现盘取值（`provenance` 空、模板同哈希）逐项核实 | 决策从「补字段」改为 `replace`（换输入） |
| G-3 | 5 行缺口镜像体量首次实测（10096 / 12420 / 11253-vul / 67968-fix） | 成本表由文档估值改为实测校准；`11253-fix` 明确标「未测」 |
| G-4 | 明确写出 `10 − 5 − 1 = 4` 与 8 条防重复计数规则 | 防止「67968 顶 CG-14」把总数算成 9 |
---

## 7. 进展（2026-11-26）：CG-18 已产出第一条带账本的新记录

| 项 | 结果 |
|---|---|
| run_id | r-cg18-ledger-20261126 |
| 位置 | experiments/cg18-newrun-20261126/（workspace 副本，原件未动） |
| 调用 | 4 次 deepseek-chat，16,707 tokens，全部 call_state=sent |
| 参数证据 | complete（4 行 / 4 个请求哈希 / 0 坏行） |
| verify 判定 | generated_but_unverified（模型闭环 3 轮未通过双端） |
| **D2** | **仍 fail；strict_submittable 仍 false** |

为什么不能因为“有账本”就标通过：CG-18 的 D2 要求**决定性调用**（产出交付 PoC 的那次）
有完整参数。这次模型候选全部未通过，交付 PoC 不是它产出的，所以只是“记录链通了”，
不是“决定性证据齐了”。

下一步（仍未做）：让模型产出一次**通过双端**的候选，且该次调用带完整参数；
或明确接受 CG-18 保持 not_submittable，把名额让给替代案例。

明细：[CG18-NEW-RUN-20261126.md](CG18-NEW-RUN-20261126.md)。
---

## 8. 决定（2026-11-27，项目方）：CG-18 名额转替换，CG-07 降优先

| 案例 | 决策 | 名额处理 | 优先级 |
|---|---|---|---|
| CG-18 | **replace** | replacement_pending：保留材料作参考，不计数 | P1（找替代） |
| CG-07 | retain | low_priority_retain：不阻塞交付 | P5 |
| CG-14 | replace | 替换评估 | P4 |
| VG-01 | block | 等外部对照材料 | P5 |
| arvo:67968 | retain | 立项，未计数 | P2 |

依据：CG-18 的历史 D2 缺参数无法补录；2026-11-26 的新运行已证明入口能按 run_id 留证
（4 次调用、参数证据 complete），但模型 3 轮候选全部未通过双端，决定性调用仍无参数。
继续加轮次的期望收益低，因此**不再投入**，名额交给替代案例。

计数不变：

```text
10 = 5 已通过 + arvo:67968 + 4 个名额（CG-07 / CG-18→替换 / CG-14→替换 / VG-01）
```

即：即使 67968 过线，仍差 4 份；CG-18 与 CG-14 各需一个**新的替代根**，
不能拿同一案例填两个名额。
