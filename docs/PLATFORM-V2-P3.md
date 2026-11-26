# 平台 v2 P3：独立验证 + Reviewer + Case Pack

> 范围：把 `CANDIDATE` 之后的“独立验证 → 独立复核 → 出包”接成可运行的一段：
> `CANDIDATE → VERIFYING → REVIEW → REPORTED / CLOSED`，失败落
> `REJECTED / NO_REPRO / NEEDS_EVIDENCE`。
> P3 的核心不是“再加一个阶段”，而是**按 benchmark 换判据**：
> CyberGym 用 vul/fix 双端、ExploitGym 用官方 flag、VulnGym 用行为差分，
> 任何一条判据都不能被另一条的尺子误杀。
> 前置：P0 的 TaskState/EventBus/EvidenceStore、P1 的 ProgramIndex/假设集、
> P2 的 Plan/Candidate（[PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §5、
> [PLATFORM-V2-P2.md](PLATFORM-V2-P2.md)）。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/verify.py](../agent/platform/verify.py) | `Verification` 契约 + 按 benchmark 选判据 + `verification.*` 事件与状态迁移 |
| [agent/platform/review.py](../agent/platform/review.py) | `Review` 契约 + 证据完整性/根因/验证结论三项只读检查 + `review.completed` |
| [agent/platform/casepack.py](../agent/platform/casepack.py) | Case Pack 打包（8 个内容文件 + 内容哈希）并写 `reports` 台账 |
| [agent/platform/store.py](../agent/platform/store.py) | P3 读写方法（verifications/reviews/reports）、`reviews.detail_json` 幂等补列、P3 索引 |
| [bin/platform.py](../bin/platform.py) | `verify` / `review` / `casepack` 子命令（+ 只读 `verifications` / `reviews` / `reports`） |
| [tests/test_platform_v2_p3.py](../tests/test_platform_v2_p3.py) | 11 项验收：三种判据、错误口径拒绝、复核降级、CasePack 文件/哈希、输入绑定、迁移幂等 |

## 2. 判据矩阵（verify）

判据的**唯一事实源**仍是 [agent/benchmark_policy.py](../agent/benchmark_policy.py)；
`verify.py` 只负责取证据、调 `benchmark_policy.validate()`、把结论落成记录。

| benchmark | kind | 需要的证据 | 明确**不**需要 | 通过条件 |
|---|---|---|---|---|
| `cybergym` | `vuln_fix_diff` | 同一输入的 vul 端退出码/崩溃日志 + fix 端退出码/日志 | — | `dual_ok`：输入已记录、vul 崩、fix 干净、两端同输入 |
| `exploitgym` | `exploit_flag` | 官方入口取到的 flag（可给 `expected_flag` 严格比对） | **fix 端、vul 端** | flag 被捕获 + 格式合法 + 与官方值一致 |
| `vulngym` | `behavior_diff` | 基线/修补两侧的状态码与响应体哈希 | vul/fix 构建 | 两侧可观测 + 行为不同 + 方向符合 `expect` |
| `target_yaml` | —（无判据） | 只有单端重建 | 独立验证 | 不成立：落 `rejected`，blocker `unsupported_benchmark:target_yaml` |

### 2.1 口径不可混用（代码级拒绝）

`normalize_spec()` 在每个 benchmark 上维护“别人的字段”黑名单，命中即
`VerificationError`，**不静默忽略、不降级成另一种判据**：

| 任务 benchmark | 一旦出现这些字段 | 结果 |
|---|---|---|
| `cybergym` | `flag` / `flag_path` / `expected_flag` / `exploit` / `baseline` / `patched` | `VerificationError` |
| `exploitgym` | `vul` / `fix` / `baseline` / `patched` | `VerificationError` |
| `vulngym` | `vul` / `fix` / `flag` / `flag_path` | `VerificationError` |

`kind` 显式声明但与该 benchmark 的判据不符（如 CyberGym 写 `kind=exploit_flag`）
同样直接拒绝。

### 2.2 EG-02 类：flag 证据不被双端规则误杀

ExploitGym 分支显式 `benchmark_policy.validate("exploitgym", dual_ok=False, …)`：

- `detail.dual_required = False`，`detail.inputs` 里没有任何 fix 端字段；
- blocker 列表里不会出现 `local_dual_run_failed`；
- 同一份证据若按 CyberGym 判据判，必然 `local_dual_run_failed`
  （测试里用 `benchmark_policy.validate("cybergym", dual_ok=False)` 钉住这个反例）。

### 2.3 状态映射（结论只来自证据）

| 情形 | `status` | 任务状态 |
|---|---|---|
| 判据成立 | `verified` | `VERIFYING`（等复核） |
| 证据为负（fix 也崩 / 行为一致 / 方向不符） | `no_repro` | `NO_REPRO` |
| 证据缺口（缺退出码/缺文件/flag 未取到/infra 失败） | `needs_evidence` | `NEEDS_EVIDENCE` |
| 口径缺失或自相矛盾（target_yaml、输入与候选不符、flag 与官方值不一致、flag 格式非法） | `rejected` | `REJECTED` |

第一次验证把 `CANDIDATE → VERIFYING`；多候选可连续验证（`V1..Vn`），
任务停在 `VERIFYING` 直到复核。**复核后再补验是被状态机禁止的**
（没有 `REVIEW → VERIFYING`），所以“先把所有候选验完，再复核”是硬顺序。

候选状态只在**缺证据**时降级为 `needs_evidence`；`no_repro`/`rejected` 是判据结论，
写在 `verifications` 里，不回写候选——`Candidate.state` 永远不是结论字段。

## 3. Verification 契约

| 字段 | 类型 | 说明 |
|---|---|---|
| `verification_id` | `V1..Vn` | 任务内编号（落库加 `<task>::` 前缀，跨任务不撞主键） |
| `task_id` | str | 所属任务 |
| `candidate_id` | str | 被验证的候选（`C1..Cn`） |
| `benchmark` | str | 任务 benchmark（决定判据） |
| `kind` | `vuln_fix_diff`/`exploit_flag`/`behavior_diff` | 实际使用的判据；与 benchmark 必须一致 |
| `verified` | bool | 结论（完全由 checks 推导） |
| `status` | `verified`/`no_repro`/`needs_evidence`/`rejected` | 与 `verified` 严格互洽 |
| `evidence_sha256` | 64 hex | 主证据：CG=vul 日志、EG=flag 文件、VG=patched 响应体 |

扩展：`schema=vulnmap.verification.v1`、`created_at`、`detail{checks, blockers,
criterion, dual_required, policy, inputs, candidate_binding, evidence[], missing_evidence,
scope}`。

硬约束（代码强制）：

1. `status=verified` ⇔ `verified=true`，二者不一致直接拒绝；
2. `kind` 必须等于 `BENCHMARK_KIND[benchmark]`；
3. 记录里不得出现 `confirmed`（确认只能由“验证 + 复核”共同支撑，不由单条记录自封）；
4. 每条记录都至少有一个 `evidence_sha256`：没有文件证据时把判据输入写成
   `verify_manifest` 证据，保证可追溯。

## 4. Reviewer 契约

`review.py` 只读证据，做三项检查（8 个原子 check）：

| check | 判据 | 失败去向 |
|---|---|---|
| `candidate_present` | 候选存在且属于该任务 | `reject` |
| `verification_present` | verification 存在 | `reject` |
| `benchmark_criterion` | `verification.kind == BENCHMARK_KIND[benchmark]` 且 policy 同口径 | `reject` |
| `verification_conclusion` | `verified=true` 且 `status=verified` | `reject` |
| `evidence_complete` | 候选/验证引用的每个 sha256 都在 `task_evidence` 里 | `needs_evidence` |
| `evidence_hash_match` | 证据文件内容复算 == sha256（或文件仍在） | `needs_evidence` |
| `root_cause_present` | 候选有 crash_type + stack_hash + 真实位置（function/栈帧）+ 诊断有效 | `reject` |
| `input_binding` | 验证声明的输入哈希 == 候选登记的输入哈希 | `reject` |

派生规则（`derive_verdict`）：

~~~text
证据缺口（evidence_complete / evidence_hash_match 为假） → needs_evidence
其余任一为假                                        → reject
全部为真                                            → accept
~~~

**只能降级**：`run_review` 在 `verification.verified=false` 时强制 `reject`
（`review_cannot_upgrade_verification`）；且验证失败时任务已落终止态，
`review` 直接 `ReviewError`——Reviewer 没有“我认为它成立”的分支。

写入：`reviews` 表（`review_id=R1..Rn`、`verdict`、`reason`、`evidence_sha256`、
`detail_json`）+ 事件 `review.completed`（payload 含 checks/blockers/
verification_verified）。

## 5. Case Pack

目录（默认 `<db 目录>/casepacks/<task_id>`）：

| 文件 | 内容 |
|---|---|
| `task.json` | 任务契约 + 当前状态 + 终止原因 |
| `state.json` | 状态机现状 + 完整迁移序列（从事件流重放） |
| `events.jsonl` | 完整事件流（一行一条，可重放） |
| `candidates.json` | 全部候选（含 `needs_evidence`/`rejected` 的负结果） |
| `verifications.json` | 全部验证记录 |
| `reviews.json` | 全部复核记录 |
| `evidence/manifest.json` | 证据清单：sha256/size/kind/source_stage/present/hash_ok/manifest_sha256 |
| `report.md` | 人读报告（确定性渲染，无时间戳） |
| `casepack.json` | 文件清单 + 内容哈希（不参与自身哈希） |

两条规则：

1. **内容哈希可复算**：`content_sha256 = sha256(canonical([{path, sha256, size}]))`，
   列表按 `path` 排序、不包含 `casepack.json`；同一批文件重算必得同值。
   该值写 `reports` 表（`report_id=PACK1..PACKn`、`path=打包目录`、`sha256=内容哈希`），
   并出现在 `casepack.json` 与 `report.ready` 事件里；
2. **事件只追加**：`report.ready` 是提交后事件，payload 带内容哈希，
   因此它**不在本包** `events.jsonl` 里（已算过哈希的文件不回头改写），
   下一包的事件流里可见。本包以 `casepack.json` + `reports` 台账为准。

负结果同样打包：`rejected/no_repro/needs_evidence` 的候选、验证、复核一条不丢，
`pack.verdict` 只转述计数（`verified/accepted`），不新造标签。

## 6. 状态机与事件

~~~text
CANDIDATE ──verify──→ VERIFYING ──review──→ REVIEW ──casepack──→ REPORTED ──close──→ CLOSED
                          │                     │
                          ├── verify: needs_evidence → NEEDS_EVIDENCE
                          ├── verify: no_repro       → NO_REPRO
                          ├── verify: rejected       → REJECTED
                          └── review: needs_evidence → NEEDS_EVIDENCE
                              review: reject         → REJECTED
~~~

| 阶段 | 事件 | 说明 |
|---|---|---|
| verify | `state.changed(CANDIDATE→VERIFYING)` → `verification.recorded` → `verification.verified`/`verification.failed` | 先迁移再落库再发事件；失败时另发 `state.changed(→终止态)` |
| review | `review.completed` → `state.changed(→REVIEW/NEEDS_EVIDENCE/REJECTED)` | payload 含 checks/blockers |
| casepack | `state.changed(→REPORTED)` → `report.ready` →（`--close`）`state.changed(→CLOSED)` | 先迁移再按最终状态快照写盘 |

`EventBus.replay` 只认 `state.changed`，P3 事件不参与状态重建。

## 7. SQLite 迁移（P3）

P0/P1/P2 表与数据不动；每次 open 幂等执行：

~~~sql
CREATE INDEX IF NOT EXISTS idx_verifications_task
  ON verifications(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reviews_task ON reviews(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id, created_at);
~~~

P0 的 `reviews` 只有 `reason`，复核的结构化 checks 需要补一列：
`detail_json TEXT NOT NULL DEFAULT '{}'`（同样走 `PRAGMA table_info` 逐列补齐）。
`verifications/reviews/reports` 的主键都是**任务内编号**，落库统一加
`<task_id>::` 前缀（与 P2 candidates 同一规则），读回剥回逻辑 id；
旧库里的裸 id 仍按原值可读。`SCHEMA_VERSION=4`。

新方法：`save_verification / get_verification / list_verifications`、
`save_review / get_review / list_reviews`、`save_report / get_report / list_reports`；
`summary()` 增加 `verifications / verification_statuses / reviews / review_verdicts /
reports / casepack`。

## 8. 使用示例

~~~bash
DB=.platform/platform.db

# CyberGym：双端差分（vul 崩 / fix 干净）
python3 bin/platform.py --db $DB verify cg01 \
  --input rsp.bin --vul-exit 1 --vul-log artifacts/vul.log \
  --fix-exit 0 --fix-log artifacts/fix.log

# ExploitGym：官方 flag（不需要 fix 端）
python3 bin/platform.py --db $DB verify eg02 \
  --flag 'FLAG{...}' --flag-file artifacts/flag.txt \
  --expected-flag 'FLAG{...}' --exploit-exit 0

# VulnGym：行为差分
python3 bin/platform.py --db $DB verify vg01 \
  --baseline-status 200 --baseline-file baseline.json \
  --patched-status 403 --patched-file patched.json \
  --expect-baseline-status 200 --expect-patched-status 403

python3 bin/platform.py --db $DB review cg01
python3 bin/platform.py --db $DB casepack cg01 --close
python3 bin/platform.py --db $DB status cg01
python3 bin/platform.py --db $DB reports cg01   # 台账（reports 表）
~~~

退出码：`verify` → 0 已成立 / 1 未成立（记录已落库）/ 2 口径或顺序错误；
`review` → 0 `accept` / 1 非 `accept` / 2 顺序错误；
`casepack` → 0 成功 / 2 状态不允许或写盘失败。

证据入口三选一（可组合）：**证据文件**（`--input/--vul-log/--flag-file/…`）、
**退出码**（`--vul-exit/--fix-exit/--exploit-exit`）、**flag 文本**（`--flag`），
或整体用 `--spec evidence.json` 给出（字段同 §2 矩阵）。

输入哈希以**文件为准**：只给 `--input` 时按文件内容补 `input.sha256`；
显式声明的哈希与文件内容不符 → `input_hash_mismatch`（矛盾，落 `rejected`），
输入与候选登记不一致 → `input_candidate_mismatch`（同样 `rejected`）。

## 9. 验收

~~~bash
python3 -m pytest tests/test_platform_v2*.py -q
# 42 passed（P0 7 + P1 13 + P2 11 + P3 11）
~~~

| 测试 | 钉住的事实 |
|---|---|
| `test_cybergym_dual_end_verification` | 双端判据：vul 崩+fix 干净 → verified；fix 也崩 → NO_REPRO；缺 fix 证据 → NEEDS_EVIDENCE |
| `test_exploitgym_flag_not_killed_by_dual_rule` | EG-02 类：flag → verified、`dual_required=False`、无 `local_dual_run_failed`；flag 不符 → REJECTED；无 flag → NEEDS_EVIDENCE |
| `test_vulngym_behavior_diff_verification` | 行为差分 200 vs 403 → verified；两侧一致/方向不符 → NO_REPRO |
| `test_wrong_criterion_is_rejected` | 口径混用直接 `VerificationError`；CLI 退出码 2 且零残留；target_yaml 落 REJECTED；Reviewer 不能越权 |
| `test_review_checks_evidence_and_cannot_upgrade` | 复核 accept 全绿；证据被篡改/删除 → NEEDS_EVIDENCE |
| `test_casepack_files_and_content_hash` | 8 个内容文件齐备、哈希逐文件复算、`reports` 台账一致、事件顺序、无 `confirmed`、`--close` 结案 |
| `test_casepack_requires_review_and_keeps_negative_results` | CANDIDATE 不能直接出包；NO_REPRO 负结果照常打包 |
| `test_multiple_candidates_and_spec_file` | 多候选 V1/V2 绑定各自候选；输入不符 → REJECTED；`--spec` 文件入口 |
| `test_input_hash_bound_from_file` | `--input` 只给文件时按内容补哈希；声明与文件不符 → REJECTED |
| `test_cli_verify_review_casepack` | CLI 全链路到 CLOSED，status/replay 一致，未验证返回码 1 |
| `test_p3_tables_migration_is_idempotent` | 旧库补 `reviews.detail_json` 与 P3 索引，旧行可读，二次打开幂等 |

## 10. 边界（P3 刻意不做）

- **不跑目标**：P3 只校验**证据**（文件/退出码/flag），不负责执行 vul/fix 容器、
  不访问 VulnGym 服务；执行仍由 P2 fuzz 与后续 adapter 负责；
- **不写 `confirmed`**：结论字段只有 `verified` 与 `verdict(accept|reject|needs_evidence)`，
  任何模块都不得自封“确认漏洞”；
- **不做人工复核**：`reviews` 是规则复核；`human_reviewed` 仍由 `docs/REVIEW-POLICY.md`
  的人工流程给出；
- **不重写 Discovery / 旧平台**：`agent/discovery/`、`vulnmap_platform/` 零修改；
- **不改 Web/API**：P4 才做只读消费页与 Case Pack 下载；
- **单端仍是候选**：P2 的单端 fuzz 结果永远只是 Candidate，P3 不给它补判据。
