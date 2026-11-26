# EG-02 · R2 征询投递记录（`EG02-R2-OUTBOX`）

> **本文只记「寄没寄」，不记「通没通过」。**
> 上游是征询书 [EG02-R2-DETERMINATION-REQUEST.md](EG02-R2-DETERMINATION-REQUEST.md)（`status = pending`）；
> 本文**不改征询结论**、**不预填答复**、**不声称已受理**。
> 本仓无第三方身份，`requested_by.class = internal`；本文不是回执，也不是判定。

| 项 | 值 |
|---|---|
| 案例 | `EG-02` / `task_id = user:cybergym/arvo_44034`（归一化 `arvo:44034`）/ ExploitGym / ghostscript / CWE-121 |
| 待判要求 | **R2**：ExploitGym ≥1 例 `benchmark_passed`（有官方判定） |
| 征询书版本 | `eg02-r2-request-v1`（2026-11-25）｜`request.json` sha256 `d3fb575f1fb7316d4fb6e2e2d110ddbe171bdcfafe004f1a77e37da2344ee4ee` |
| 投递状态 | **`ready_not_sent`**：`attempted = false`、`sent = false` |
| 收件人 | **`missing`**（`recipient_source = None`） |
| 通道 | `none`（无 `SMTP_HOST`；无 `sendmail`/`msmtp`；`smtplib` 可用但无服务端） |
| `message_id` | `null`（未发送 → 无服务端 id；草案标识仅作追踪） |
| 原始回执 | 无（`receipts/` 为空，见 `receipts/README.md`） |
| 证据摘要 | `evidence_hash = c6922ccb5f8211f0aaa18f478189337fa132d5ddda67692b4ad07ec2d15014b4`（19 条证据，算法可复算） |
| 生成器 | `experiments/eg02-r2-outbox/build_outbox.py`（`--build` / `--send` / `--check` / `--status`） |
| 机读件 | `experiments/eg02-r2-outbox/DELIVERY.json`、`evidence.index.json`、`outbox/attachments.index.json` |
| 数字口径 | 本文数字与 `DELIVERY.json`（`generated_at = 2026-11-26T18:54:25+08:00`）同一次构建；若重跑 `--build`，一律以 `DELIVERY.json` 为准 |

> **一句话**：可发件已做好（正文、附件、答复表单、哈希全齐），但**没有收件人**，所以没发，
> `status = ready_not_sent`、`recipient = missing`。这是如实记录，不是失败，也不冒称已寄出。

---

## 0. 为什么不发

投递只看两个前提：**收件人可解析** 与 **有可用通道**。本轮两个前提都不成立：

| 检查项 | 结果 | 说明 |
|---|---|---|
| `COURSE_EMAIL` | 未设置 | 任务约定：只有它（或 `COURSE_CONTACT`）存在才投递 |
| `COURSE_CONTACT` | 未设置 | 同上；二者都缺失 → `recipient = missing` |
| `--to` | 未提供 | 人手显式指定是唯一覆盖途径，本轮没有 |
| `SMTP_HOST` / `SMTP_PORT` | 未设置 | 无 SMTP 服务端可投 |
| `sendmail` / `msmtp` / `ssmtp` | 均不存在 | 无本地 MTA |
| `python3 smtplib` | 可用 | 有客户端、无服务端，仍不能投递 |

后果（按约定，且已被 `--check` 断言）：

- `status = ready_not_sent`，`attempted = false`，`sent = false`；
- `message_id = null`，`at = null`，`receipt = null`；
- `receipts/` 保持为空；
- 邮件 `To:` 写 `undisclosed-recipients:;` + `X-Vulnmap-Recipient: missing (...)`，**不编假收件人**。

`--send` 在本状态下重复执行是**幂等**的：仍然 `ready_not_sent`，退出码 0，不产生任何「已发」痕迹。

---

## 1. 可发件内容

### 1.1 主题

```
【征询·EG-02 R2】R2「有官方判定」的载体请课程/评测方认定（status: pending｜eg02-r2-request-v1｜非判定文件）
```

### 1.2 正文（`outbox/body.txt`，13308 B）

七节，内容与机读件同源：

| 节 | 内容 |
|---|---|
| 一 | **R2 问题**：Q1（含 Q1a 判据面 / Q1b 对象面 / Q1c 时间面）、Q2（A–E 五条路径 + 其他）、Q3（同根计数确认）、Q4（`pending` 期间的表述边界），每题给出**回答形态** |
| 二 | 六条既成事实 F1–F6（官方套件在场 / controller 自建 / 10 份日志 1 个哈希 / flag 10/10 / 历史 mtime 跨度 / 判定方缺失）+ 计数 9 → 9 |
| 三 | 19 条证据的路径 + 字节 + **完整 sha256**；并说明本仓无公网 URL、需要何种交付口径请课程指明 |
| 四 | 附件清单 + `evidence_hash` + 表单用法 |
| 五 | **答复字段**逐项（`respondent` / `respondent_role` / `responded_at` / `attestation_method = human_written` / Q1a·Q1b·Q1c / Q2 / `waiver_text` / `third_party` / Q3 / Q4 / `basis`） |
| 六 | 七条「不主张」（不改写成已通过 / 已受理 / 已认定；10/10 ≠ 10 次独立复现；本地 flag ≠ `expected_flag`；不计入独立高危分子；非第三方评审；仍是 `pending`；不替课程下结论） |
| 七 | 复算命令（`build_request.py --check` / `sha256sum -c` / `build_outbox.py --check`） |

正文**不含时间戳**：同一证据集渲染出的正文恒定，`--check` 可逐字节比对。

### 1.3 附件（`outbox/message.eml`，`multipart/mixed`，63928 B）

| # | 文件名 | 来源 | 字节 | sha256（前 16） |
|---|---|---|---|---|
| 1 | `request.json` | `experiments/eg02-r2-request/request.json` | 13420 | `d3fb575f1fb7316d…` |
| 2 | `facts.json` | `experiments/eg02-r2-request/facts.json` | 5365 | `d29a4719c753b324…` |
| 3 | `options.json` | `experiments/eg02-r2-request/options.json` | 10247 | `3fd6af4402a3ac16…` |
| 4 | `MANIFEST.sha256` | `experiments/eg02-r2-request/MANIFEST.sha256` | 638 | `a3b565752fdba4e8…` |
| 5 | `response-form.txt` | `experiments/eg02-r2-outbox/outbox/response-form.txt` | 2886 | `7a649eead1c6caee…` |

`request.json` 是征询本体（**附件引用**：正文第四节给出其 sha256 `d3fb575f1fb7316d4fb6e2e2d110ddbe171bdcfafe004f1a77e37da2344ee4ee`，
表头 `X-Vulnmap-Evidence-Hash` 与正文同值），收到后可直接核对字节一致。

### 1.4 答复表单（`outbox/response-form.txt`）

纯文本、**未预填任何答案**；`attestation_method` 预填为 `human_written` 并注明
`human_instructed_agent_transcribed` 不算课程答复。`--check`（D19）会拦住任何预填痕迹。

---

## 2. 证据与哈希

| 项 | 值 |
|---|---|
| `evidence_hash` | `c6922ccb5f8211f0aaa18f478189337fa132d5ddda67692b4ad07ec2d15014b4` |
| 算法 | `sha256( canonical_json( sorted([[path, sha256], …]) ) )`，仅取现盘存在的文件 |
| 覆盖 | 19 条（`evidence.index.json` 逐条列出） |
| 采集时间 | `2026-11-26T18:54:25+08:00`（= `evidence.index.json.collected_at` = `DELIVERY.json.generated_at`，同一次构建） |

| id | 角色 | 路径 | 字节 | sha256（前 16） |
|---|---|---|---|---|
| E01 | 征询书本体（机读）：Q1–Q4、候选路径、history_baseline、空 response 块 | `experiments/eg02-r2-request/request.json` | 13420 | `d3fb575f1fb7316d…` |
| E02 | 现盘事实快照（--write 生成，含环境采样时间） | `experiments/eg02-r2-request/facts.json` | 5365 | `d29a4719c753b324…` |
| E03 | A–E 五条候选路径的机读矩阵（判定物 / 产出者 / 所需工件 / 残留风险） | `experiments/eg02-r2-request/options.json` | 10247 | `3fd6af4402a3ac16…` |
| E04 | 征询包哈希链（sha256sum -c 可验；注意正文「漂移」一节） | `experiments/eg02-r2-request/MANIFEST.sha256` | 638 | `a3b565752fdba4e8…` |
| E05 | 征询书（人类可读）：Q1–Q4 全文、三层「官方」、五条路径 A–E | `docs/EG02-R2-DETERMINATION-REQUEST.md` | 31923 | `aea90f41f14ea6ef…` |
| E06 | 内部自审意见（请求方陈述，34 条 caveat，非课程判定） | `docs/COURSE-REVIEW-EG02.md` | 34672 | `18393e7080de459b…` |
| E07 | R2 判据来源：§6.4 第 2 行「有官方判定」+ §6.3 E1–E6 | `docs/STAGED_GOALS.md` | 13111 | `6487b960f9c7d18c…` |
| E08 | R1/R2 定义与「判定方不能是本仓自写脚本」（行 56） | `docs/COURSE-EVIDENCE-DECISIONS.md` | 46749 | `33cc12e95dfc43fa…` |
| E09 | 材料口径与回执位置（§5.2/§5.3/§6） | `docs/COURSE-CRITERIA-V2.md` | 21270 | `463751e9fa5bd532…` |
| E10 | 历史回放汇总（runs=10 success=10；10 份日志 1 个 sha256） | `experiments/eg-44034/official-runs/20261110-094901/SUMMARY.json` | 1321 | `14b281740ed5e08d…` |
| E11 | 10 份 socket 日志之代表（435 B，distinct=1；run-01..10 同哈希） | `experiments/eg-44034/official-runs/20261110-094901/run-01.txt` | 435 | `695ceacd3b5fb700…` |
| E12 | 历史结果文件（phase=OFFICIAL_SOCKET_VERIFIED；措辞过强，见 Q4） | `experiments/eg-44034/RESULT.json` | 4321 | `9d2252988da3483a…` |
| E13 | PoC 样本（9518 B，全文不含 flag{ 字面量） | `experiments/eg-44034/poc.pdf` | 9518 | `9f40093d40b28cca…` |
| E14 | 自写验证脚本（sys.path 导入官方 token；--api 默认 127.0.0.1:8666） | `experiments/eg-44034/verify_official.py` | 3288 | `e2b180c865d5b6b0…` |
| E15 | 本地 controller 会话记录（前置条件 / 仍然阻塞的部分） | `experiments/eg-official-entry/VERIFIED.md` | 1720 | `c2b3776ef36ec1d7…` |
| E16 | 任务口径（task_id / note） | `workspace/EG-02-arvo-44034/task.json` | 509 | `0e99eb61c17a32a6…` |
| E17 | 机读自查结果（track_judgment / stability_claim / independence） | `experiments/course-review-eg02/judgments.v2.json` | 34972 | `abe25c84c018b92f…` |
| E18 | 官方提交通道（路径 A 依据）：submissions/<name>/{metadata.yml,results.json} | `/home/root_bupt/bench/exploitgym/docs/submission.md` | 5991 | `69fac1c56c595dd9…` |
| E19 | 官方判定物路径（Q1a 依据）：Evaluator.evaluate() -> EvalResult | `/home/root_bupt/bench/exploitgym/src/cybergym/evaluation/base.py` | 20981 | `6224aaf6f83b5d6c…` |

验证某一条：

```bash
cd /home/root_bupt/桌面/file/vulnmap && sha256sum <path>
```

---

## 3. 已知漂移（记录，不代改）

征询包自己的 `experiments/eg02-r2-request/MANIFEST.sha256` 与现盘有 **1 处**不符：

| 文件 | MANIFEST 记 | 现盘 |
|---|---|---|
| `docs/EG02-R2-DETERMINATION-REQUEST.md` | `c4cd4290b35b84bbdcaad6eb1767f7eab0680b7a65e15f7c1eb8fda71df02224` | `aea90f41f14ea6efbbed4c538376fb9d3df8dc805f71a5654eccc5b5ecfbb493` |

归因（可核查）：该文件 mtime `2026-11-26 18:39:48`，早于本 outbox 首次构建（18:48），属**征询包封包之后、本轮投递包构建之前**的一次改动；差异内容是头部表格新增一行
「发送记录 = **未发现**（仓库内无发送日志、收件人回执或答复记录）」。该行与本文结论一致（确无发送记录），
但它使 `MANIFEST.sha256` 的该项过期——**本轮未改该文档、未改 `eg02-r2-request/`**（该目录今日零写入）。

处理方式：

1. 本 outbox **以现盘哈希为准**（`evidence.index.json` / 正文 / 附件索引一律用现盘值）；
2. **不改** `experiments/eg02-r2-request/`（不在本轮写入范围），也不代改其 MANIFEST；
3. 邮件正文「漂移」一节把两个哈希都写出来，由收件方自行判断，不隐藏。

修法（由有权限的一轮执行，本轮不做）：以现盘哈希重算 `MANIFEST.sha256`，并重跑
`build_request.py --check`。

---

## 4. 发送（等收件人到位再做）

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 需要真实的 SMTP 通道（发件人地址可选：EG02_MAIL_FROM / MAIL_FROM；缺省为占位 vulnmap.local）
COURSE_EMAIL=xxx@example.edu \
SMTP_HOST=smtp.example.edu SMTP_PORT=587 SMTP_STARTTLS=1 \
SMTP_USER=... SMTP_PASS=... \
EG02_MAIL_FROM=maintainer@example.edu \
  python3 experiments/eg02-r2-outbox/build_outbox.py --send
```

或者只给收件人、让系统 MTA 投递（需要 `sendmail`/`msmtp` 在位）：

```bash
python3 experiments/eg02-r2-outbox/build_outbox.py --send --to xxx@example.edu
```

投递发生后会**自动**生成：

- `receipts/receipt-<时间戳>/sent.eml` —— 实际发出的字节；
- `receipts/receipt-<时间戳>/transport.json` —— 通道、收件人、`smtplib` 协议轨迹（`reply` 行逐字保留，
  `send` 行超长截断，正文全文见 `sent.eml`）；
- `DELIVERY.json` 更新为 `status = sent`、`attempted = true`、`sent = true`、`message_id = <…>`、`at = <ISO8601>`、
  `receipt = receipts/receipt-<时间戳>`；
- `outbox/sha256sums.txt` 与 `MANIFEST.sha256` 重算（`To:` 头变了，`message.eml` 的哈希随之变）。

失败时：`status = failed`（或 `failed_partial_refused`）、`sent = false`、`message_id = null`，
`receipts/failed-<时间戳>/` 下留 `attempted.eml` + `error.txt`，`--send` 退出码 4。不重试掩盖、不改写成成功。

> **传输层接受 ≠ 送达 ≠ 受理。** 即使 `status = sent`，也只说明 SMTP 服务器没拒收；
> 「课程已答复 / 评测方已受理」只能由 `request.json.response` 被具名人类以 `human_written` 填写来证明。

---

## 5. 状态机与断言

| `status` | 含义 | `attempted` | `sent` | `message_id` |
|---|---|---|---|---|
| `ready_not_sent` | 可发件就绪，未投递 | false | false | null |
| `blocked_no_transport` | 有收件人、无通道 | false | false | null |
| `sent` | 服务器未拒收（≠ 受理） | true | true | 有 |
| `failed_partial_refused` | 部分收件人被拒 | true | false | null |
| `failed` | 投递异常 | true | false | null |

`--check` 共 **19 组**断言（标签 `D01`–`D19`；`D12b` 是 `D12` 的子断言，故实际打印 20 个标签），关键几条：

| 断言 | 拦什么 |
|---|---|
| D02 / D03 / D05 | `sent = false` 却给 `message_id`、`sent = true` 却没 `message_id`/回执、`attempted = false` 却有 `at` —— **伪造已发** |
| D07 / D08 / D09 / D10 | `request.json` 哈希变了、`status ≠ pending`、`response.answers` 被预填、丢了 `not_a_conclusion` —— **改征询结论** |
| D11 | `evidence_hash` 与现盘不符 —— **证据漂移/被替换** |
| D12 / D12b | outbox 与 `MANIFEST.sha256`、`sha256sums.txt` 不符 —— **产物被手改** |
| D13 / D14 | 附件没进 `message.eml`、正文没给 `request.json` 的 sha256 —— **答复方无法核对** |
| D15 / D16 | 正文或表单缺 `Q1a…Q4`、`attestation_method`、`waiver_text` 等字段 |
| D17 | 出现「已通过 ExploitGym / 官方 socket 10/10 / 官方判定 10/10 / R2 已达成 / 已受理 / 已认定 / 本邮件已发送」等**结论式措辞**（否定语境中的引用除外） |
| D18 | 仓内出现 `receipt.json` —— **伪造回执** |
| D19 | 答复表单被预填 |

复跑：

```bash
python3 experiments/eg02-r2-outbox/build_outbox.py --check      # 0 = 一致；2 = 断言失败；3 = 缺产物
python3 experiments/eg02-r2-outbox/build_outbox.py --check-doc  # 本文数字 × 机读件一致性（防文档漂移）
python3 experiments/eg02-r2-outbox/build_outbox.py --status     # 只读状态
./scripts/eg02-r2-send.sh --check                               # 同上的薄封装
```

> **本文自己也被校验**：`--check-doc` 会逐项比对本文的 `generated_at` / `collected_at` /
> `evidence_hash` / `body.txt` 与 `message.eml` 字节数 / 19 条证据行 / 5 条附件行 / 漂移两处哈希；
> 任一不符即退出 2。这样「文档抄错数字」不会静默存在。

---

## 6. 本轮改了什么、没改什么

| 类别 | 内容 |
|---|---|
| 新增 | `docs/EG02-R2-OUTBOX.md`（本文）、`experiments/eg02-r2-outbox/**`、`scripts/eg02-r2-send.sh` |
| 未改 | 征询书与机读件（`request.json` 仍 `d3fb575f1fb7316d…`、`status = pending`、`response` 全空）；`workspace/**`；`experiments/eg-44034/**`；业务代码；其它 `docs/` 既有文件 |
| 未做 | 未生成 `receipt.json`；未预填答复；未重放 socket；未 `git commit`（仓库根不是 git 工作区） |
| 不冒充 | 未把 `ready_not_sent` 写成 `sent`；未编造 `message_id`/收件人/回执 |

## 7. 不主张的事

1. 不主张 R2 已满足，也不主张 R2 必然不满足——本文只记投递状态。
2. 不主张「已寄出」：`sent = false`，`message_id = null`，`receipts/` 为空。
3. 不主张课程已读、已答复或已受理；`request.json.response.status` 仍为 `pending`。
4. 不主张 EG-02 计入独立高危分子（与 CG-01 同根，`9 → 9`）。
5. 不主张本文或本 outbox 是第三方材料：`class = internal`、`third_party = false`。

## 8. 下一步（需人手提供一项）

要让邮件真的出去，只需给出**收件人**（以及一条可用通道）二者之一：

- `COURSE_EMAIL=…`（或 `COURSE_CONTACT=…`）→ 重跑 `--send`；或
- `--send --to …` 显式指定；

通道二选一：`SMTP_HOST`/`SMTP_PORT`（+ 可选 `SMTP_STARTTLS`/`SMTP_USER`/`SMTP_PASS`），
或装好 `sendmail`/`msmtp`。两种都缺时会记 `blocked_no_transport`（`attempted = false`），不会假装发出。
---

## 8. 清单不符的处置（2026-11-26）

上一轮复验发现：征询包 MANIFEST.sha256 有 1 份文件与现盘哈希不符。
原因是 2026-11-26 在征询书表头补了一行「发送记录：未发现」，属于事实补充，
不改结论、不改 status。

处理方式（**不静默覆盖历史**）：

| 动作 | 文件 |
|---|---|
| 旧清单原样保留并改名 | experiments/eg02-r2-request/MANIFEST-V1.sha256.legacy |
| 新旧哈希逐项对照 | experiments/eg02-r2-request/MANIFEST-CHANGELOG.json |
| 为待发送版本生成匹配清单 | experiments/eg02-r2-request/MANIFEST.sha256 |
| 投递包重新生成并复查 | experiments/eg02-r2-outbox/（build --check 通过） |

当前校验：`sha256sum -c` 6/6 成功；outbox 的 manifest_drift 为 ok=6 / mismatch=[]。
CHANGELOG 明确记录：conclusion_unchanged=true、status_unchanged=pending。

## 9. 收件人确认（仍未完成）

状态仍是 **ready_not_sent**，因为**没有确认的收件人**：

- 环境无 COURSE_EMAIL / COURSE_CONTACT / SMTP 配置；
- 本机无 sendmail / msmtp / ssmtp / mail / mailx；
- 课程文档与仓库内没有可用邮箱地址。

发出前必须确认的只有一件事：**谁是老师或课程指定的认定人**（邮箱或提交渠道）。
确认后两种发送方式：

```bash
# 方式 A：环境变量 + 发送
export COURSE_EMAIL='<认定人邮箱>'
python3 experiments/eg02-r2-outbox/build_outbox.py --send

# 方式 B：显式 --to
python3 experiments/eg02-r2-outbox/build_outbox.py --send --to '<认定人邮箱>'
```

发送后会写 DELIVERY.json：status / sent / recipient / transport / message_id / at，
并把原始回执存到 receipts/。**只有真实投递记录才标 sent；只有具名答复才能更新 R2。**

征询只问一个核心问题：**现有本地历史记录是否满足 R2？如果不满足，课程认可什么替代证据？**
无论 R2 怎么判，EG-02 都不增加独立根因数（与 CG-01 同根）。
