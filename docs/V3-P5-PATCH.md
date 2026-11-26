# V3 P5：可选补丁工作流（V3-017）

对应《VULNMAP-V3 完整升级方案》§12「独立验证：发现能力增强，判据不放松」、
§13「可选 PatchWorkflow 与经验库」与 §19.6「每项实际代码修改需产出原件哈希、
修改副本、可重建 diff、literal 测试记录与可执行 rollback」，前置 P4b
（[V3-P4-REPORT-COMPARE.md](V3-P4-REPORT-COMPARE.md)）。

P4b 把研究产物与五指标并排记账；P5 只做**主路径之外**的一件事：给「有源码、有授权」的
目标生成一份可复核的补丁工件，并证明它**真的修掉了触发条件且没有改坏正常功能**。
落点是一个新的纯标准库子包 `agent/platform/adaptive/patch/`，加上
`bin/platform.py` 的 `patch` 子命令与本文的验收测试。

一句话边界：**补丁只写实验副本，不自动应用；测试通过只算 `patch_validation` 通过，
漏洞结论仍由既有 `agent.platform.verify` 决定。** 本批改动没有改 `verify.py`、
`adaptive/policy.py`、`benchmark_policy`、执行器、DB schema 与任何写端点，也没有
`git commit`。

---

## 0. 实施清单

| 项 | 状态 | 验收口径 | 落点 | tests |
|---|---|---|---|---|
| P5-1 根因对象（V3-017） | 已实施 | `RootCause` 必须带定位（file/line/end_line）、来源枚举（`observed / upstream_assertion / synthesized_state / model_hypothesis`）、论证、**至少一条现场算哈希的证据**或带证据/验证引用的 finding；snippet 的 sha256 与原文一致；缺一项就 `PatchError` | `patch/contracts.py`（`EvidenceRef` / `FindingRef` / `RootCause`） | `test_proposal_carries_diff_tests_finding_and_rollback`、`test_contracts_refuse_applied_or_verdict_fields` |
| P5-2 提案只落实验副本 | 已实施 | `propose` 前后 origin 整树哈希与逐文件字节都不变；`experiment/` 才含补丁；`status=proposed`、`applied_to_origin=false`；`baseline/` 与原件同哈希；写入后重算 origin，不一致就删目录并报错 | `patch/workflow.py`（`PatchWorkflow.propose`） | `test_propose_writes_only_experiment_and_keeps_origin` |
| P5-3 补丁四件套 | 已实施 | 提案含 `origin.tree_sha256`、`diff`+`diff_sha256`、`files[].before/after_sha256`、`tests.trigger`/`tests.regression`、`rollback.{strategy,files,baseline_tree_sha256,command}`；缺回滚方案或测试命令直接拒绝 | `patch/workflow.py`、`patch/contracts.py`（`PatchProposal`） | 同上 + `test_proposal_carries_diff_tests_finding_and_rollback` |
| P5-4 假修复拒绝 | 已实施 | 改测试文件 / 新增 `pytest.skip`·`xfail` / `except` 块只 `pass`·空 `return` / 只删不补 / 超行数·文件数·hunk 上限 → `PatchError("diff rejected: …")`；显式放宽 `limits` 后才允许大补丁 | `patch/diff.py`（`hygiene_problems`） | `test_propose_refuses_fake_fix_diffs`、`test_large_diff_allowed_only_when_limits_raised` |
| P5-5 独立测试 | 已实施 | 从 `baseline/` 重建 `run/baseline` 与 `run/patched`（不复用 `experiment/`）；原版触发必须非零、补丁触发必须为零、回归必须为零；跑完再校验 origin 未变；结论 `passed / failed / blocked` | `patch/workflow.py`（`test` / `_run_stage`） | `test_independent_test_passes_and_review_accepts`、`test_review_accepts_only_when_test_passed` |
| P5-6 回滚可执行、失败即拒 | 已实施 | 正常：`experiment/` 恢复到基线哈希，`rollback.restored_tree_sha256 == origin.tree_sha256`；失败：基线缺失/被改 → `test` 直接 `blocked`、显式 `rollback` 抛错，不假装回滚过 | `patch/workflow.py`（`_restore_experiment` / `rollback`） | `test_rollback_restores_experiment_hash`、`test_failed_rollback_blocks_test_and_refuses_rollback` |
| P5-7 工程采纳与漏洞分离 | 已实施 | `review.scope == "patch_validation"`；只有「测试 passed + 回滚 ok + 原件未变 + 证据可复算 + finding 在 + 工件自洽 + 无裁决字段」全过才 `accepted`；`vulnerability` 块只读回显既有 verify 编号，状态 `not_evaluated` / `verified_in_platform`；任何工件不得出现 `"confirmed"` 或 `"verified": true` | `patch/workflow.py`（`review` / `_vulnerability_block`）、`patch/contracts.py`（`PatchReview` 构造期硬拒） | `test_review_accepts_only_when_test_passed`、`test_verified_record_is_read_only_and_never_confirmed` |
| P5-8 证据可复算、冲突即拒 | 已实施 | 证据 sha256/size 由本模块现场计算；复核时重算，文件被改/被删 → `evidence_recomputable=false` → `rejected`；候选不存在、根因文件不在补丁内、行号越界、diff 与基线不匹配都拒绝且不半写 | `patch/workflow.py`、`patch/contracts.py`（`EvidenceRef.verify`） | `test_review_rejects_tampered_evidence`、`test_propose_refuses_missing_finding_or_source` |
| P5-9 无源码 = unsupported | 已实施 | `source_root` 不是目录 → `PatchUnsupported`；CLI 输出 `{"status": "unsupported"}`、退出码 2；不会退化成“模拟修复” | `patch/workflow.py`、`bin/platform.py`（`cmd_patch_propose`） | `test_cli_refuses_without_source_tree` |
| P5-10 CLI 与库接口 | 已实施 | `platform patch propose/test/review/rollback`；测试通过退 0、失败/拒绝退 1、非法输入退 2；库接口 `PatchWorkflow` 同名方法可直接调用 | `bin/platform.py`、`patch/__init__.py` | `test_cli_propose_test_review_roundtrip` |

### 0.1 文件清单

| 文件 | 变化 | 行数 |
|---|---|---|
| `agent/platform/adaptive/patch/__init__.py` | 新增。子包门面与用法说明 | 61 |
| `agent/platform/adaptive/patch/contracts.py` | 新增。四个契约对象 + 证据/finding 引用 + 裁决字段硬拒 | 621 |
| `agent/platform/adaptive/patch/diff.py` | 新增。统一 diff 生成/严格解析/应用 + 假修复检查 | 315 |
| `agent/platform/adaptive/patch/workspace.py` | 新增。读树/复制树/整树哈希/干净环境跑命令/日志 | 218 |
| `agent/platform/adaptive/patch/workflow.py` | 新增。propose / test / review / rollback 编排 | 754 |
| `bin/platform.py` | 改动。新增 `patch propose|test|review|rollback` 四个子命令（局部导入，不影响旧命令启动） | — |
| `tests/test_v3_p5_patch.py` | 新增。15 个测试函数 | 483 |
| `docs/V3-P5-PATCH.md` | 本文 | — |

`agent/platform/adaptive/__init__.py`、`verify.py`、`policy.py`、`benchmark_policy`、
`store.py` 的 schema、执行器与写端点**未改**；补丁包通过
`from agent.platform.adaptive.patch import PatchWorkflow` 直接导入。

---

## 1. 为什么补丁不能自己宣布“修好了”

P5 沿用 P4b 的三类事实分离，并把它写进字段：

| 类别 | 唯一事实来源 | P5 里回答的问题 | P5 明确不回答 |
|---|---|---|---|
| 工程采纳（补丁） | `PatchReview.scope="patch_validation"` | diff 能否应用、原版是否触发、补丁是否不触发、回归是否通过、回滚是否回原哈希、证据是否可复算 | 有没有漏洞、根因判断是否正确 |
| 漏洞验证 | 既有 `verifications` / `reviews` 台账 | benchmark 判据是否通过 | 补丁写得好不好 |
| 研究进展 | `research.json` / 事件流（P4a/P4b） | 走过哪些轮次、提了哪些动作 | 补丁与漏洞结论 |

`PatchReview` 的构造期就拒绝 `status != accepted|rejected`、拒绝
`scope != patch_validation`、拒绝文档里出现 `confirmed`：

```python
# patch/contracts.py
text = json.dumps(self.to_dict(), ensure_ascii=False, default=str)
if "confirmed" in text:
    raise PatchError("patch review must not carry 'confirmed'")
```

`propose` 也不接受“已应用”的提案：

```python
# patch/contracts.py  PatchProposal.__post_init__
if self.status not in PROPOSAL_STATUSES:   # 只有 "proposed"
    raise PatchError(...)
if self.applied_to_origin:
    raise PatchError("proposal must not be applied to origin")
```

---

## 2. 四个契约对象

### 2.1 `RootCause`：根因 + 原始 finding/证据引用

```json
{
  "schema": "vulnmap.adaptive.patch.root_cause.v1",
  "root_cause_id": "RC1",
  "task_id": "task-1", "candidate_id": "C1",
  "file": "victim.py", "line": 4, "end_line": 4, "function": "",
  "claim": "observed",
  "argument": "数组下标没有边界检查，越界读触发 IndexError",
  "snippet": "print([0, 1, 2][n])", "snippet_sha256": "…",
  "evidence": [{"path": "/abs/crash.log", "rel": "crash.log",
                "sha256": "…", "size": 37, "kind": "file"}],
  "finding": {"task_id": "task-1", "candidate_id": "C1",
              "input_sha256": "…", "evidence_sha256": "…",
              "crash_type": "IndexError",
              "verification_ids": ["V1"], "verification_status": "verified",
              "source": "platform.store"},
  "created_at": "2026-11-20T10:00:00+00:00"
}
```

硬约束：`claim` 只能取 §12 的四个来源；`argument` 至少 8 字符；`line/end_line`
必须在文件行数内；`evidence[].sha256` 不是调用方声明的，而是 `EvidenceRef.from_path()`
现场读文件算出来的；`snippet` 由 `[line, end_line]` 原文切片生成，复核时从
`baseline/` 重算比对。

### 2.2 `PatchProposal`：diff + 测试命令 + 回滚方案

```json
{
  "schema": "vulnmap.adaptive.patch.proposal.v1",
  "patch_id": "P1", "task_id": "task-1", "candidate_id": "C1",
  "root_cause_id": "RC1",
  "status": "proposed", "applied_to_origin": false,
  "source_root": "/abs/src",
  "origin": {"tree_sha256": "…", "files": 3,
             "touched": [{"path": "victim.py", "sha256": "…"}]},
  "files": [{"path": "victim.py", "before_sha256": "…", "after_sha256": "…",
             "added": 4, "removed": 1, "hunks": 1}],
  "diff": "--- a/victim.py\n+++ b/victim.py\n@@ -1,4 +1,8 @@\n…",
  "diff_sha256": "…",
  "tests": {"trigger": {"name": "trigger", "cmd": "python3 victim.py poc.bin",
                        "expect_exit": "nonzero"},
            "regression": [{"name": "regression-1",
                            "cmd": "python3 victim.py good.bin",
                            "expect_exit": "zero"}],
            "timeout": 60.0},
  "rollback": {"strategy": "restore_baseline_bytes",
               "baseline_tree_sha256": "…", "files": ["victim.py"],
               "command": "platform patch rollback P1 --task-id task-1",
               "integrity_checked": false},
  "created_at": "…"
}
```

`diff` 是工作流自己用 `difflib.unified_diff` 生成的（无时间戳、`a/` `b/` 前缀），
`diff_sha256` 对 diff 文本现算；`rollback.files` 是回滚要恢复的文件集合，
`rollback.command` 是可以照着跑的可执行入口。

### 2.3 `PatchTest`：原版触发 / 补丁不触发 / 回归 / 回滚

`test.json` 的 `gates` 是逐项可复核的结论，`runs` 是每条命令的退出码与日志哈希：

| gate | 含义 | 不通过时 |
|---|---|---|
| `baseline_matches_proposal` | `baseline/` 整树哈希 = 提案记录 | `blocked: baseline_tampered` |
| `origin_unchanged` | 现在 origin 整树哈希 = 提案记录 | `blocked: origin_changed` |
| `independent_copy` | `run/baseline` 从 baseline 重建成功 | `blocked: run_copy_failed` |
| `trigger-baseline:trigger_baseline` | 原版跑触发命令**非零**退出 | `failed`（finding 不可复现） |
| `trigger-patched:trigger_patched` | 补丁跑同一命令**零**退出 | `failed`（补丁没修掉） |
| `regression-N:regression` | 回归命令在补丁上**零**退出 | `failed`（改坏正常功能） |
| `origin_unchanged_after_test` | 跑完命令后 origin 仍同哈希 | `failed`（测试污染原件） |
| `rollback_verified` | `experiment/` 恢复后哈希 = 基线 | `failed`（回滚不可信） |

`blocked` 只用于「前置条件不成立、连跑都没跑」，`failed` 是「跑了但不达标」，
两者都不产生 `accepted`。

### 2.4 `PatchReview`：只判 `patch_validation`

```json
{
  "schema": "vulnmap.adaptive.patch.review.v1",
  "review_id": "R1", "patch_id": "P1", "task_id": "task-1",
  "scope": "patch_validation", "status": "accepted", "accepted": true,
  "engineering": {"accepted": true, "proposal_sha256": "…",
                  "test_sha256": "…", "checks": [{"name": "…", "ok": true}]},
  "reasons": [],
  "vulnerability": {"status": "not_evaluated", "verification_ids": [],
                    "source": "agent.platform.verify",
                    "note": "补丁复核不改写漏洞结论；是否有漏洞由 verify 决定"}
}
```

复核的 gate 全集：`root_cause_valid`、`root_cause_matches_finding`、
`root_cause_in_patch`、`evidence_recomputable`、
`root_cause_snippet_matches_baseline`、`finding_present`、`origin_unchanged`、
`test_present`、`test_matches_proposal`、`test_passed`、`test_gates_all_ok`、
`test_runs_consistent`、`test_baseline_matches_proposal`、
`patched_tree_matches_diff`、`rollback_verified`、`test_artifacts_local`、
`no_verdict_claim`。

`test_runs_consistent` 会重算每条 run 的 `ok` 是否真的等于
`expect_exit` 与 `exit_code` 的关系；`patched_tree_matches_diff` 会从
`baseline/` + `diff` 重算补丁树，要求与测试记下的独立副本同哈希；`test_artifacts_local`
只允许 `run/baseline`、`run/patched` 两个相对根，防止把证据拼到别的目录。

---

## 3. 拒绝规则（假修复）

`patch/diff.py` 的 `hygiene_problems()` 在写盘前给出可解释的拒绝码：

| 拒绝码 | 触发条件 | 为什么 |
|---|---|---|
| `touches_test_file` | 路径命中 `tests/`、`test_*`、`conftest.py`、`pytest.ini` 等 | 改测试预期不是修复（§13） |
| `adds_skip` | 新增行含 `pytest.skip/xfail`、`unittest.skip`、`skipTest` | 跳过不等于修好 |
| `swallows_exception` | 新增的 `except …:` 后紧跟只有 `pass` / 空 `return` | 吞异常不是修复 |
| `deletes_without_replacement` | 某个 hunk 只有删除、没有新增 | 删功能不是修复 |
| `too_many_changed_lines` | 增删行数超 `max_changed_lines`（默认 120） | 最小 diff；要放宽必须显式给 `limits` |
| `too_many_files` / `too_many_hunks` / `diff_too_large` | 文件数 > 3、hunk > 16、diff > 256 KiB | 同上 |
| `file creation/deletion is not supported` | diff 含 `/dev/null`、重命名、非统一 diff | 回滚语义要简单可验证 |

另外：只接受 **UTF-8 文本源码**；二进制/非 UTF-8 文件直接拒绝，不猜编码。

---

## 4. 流水线

```
propose
  ├─ 读 origin（跳过 .git/__pycache__/.platform/venv；数量与体积上限）
  ├─ 解析 diff / 由 --patched-file 生成 diff
  ├─ hygiene_problems（改测试/跳过/吞异常/删功能/规模）
  ├─ apply_unified（上下文逐字匹配，不匹配就拒绝）
  ├─ 根因（file/line/snippet/证据/finding）
  └─ 写 patch_root/<task>/<P1>/{root_cause,proposal}.json
     baseline/ = 原件字节；experiment/ = 已打补丁副本（唯一写入口）

test
  ├─ baseline 哈希 = 提案记录？（否则 blocked）
  ├─ origin 哈希 = 提案记录？（否则 blocked）
  ├─ 从 baseline 重建 run/baseline + run/patched（独立副本）
  ├─ trigger 在 baseline 必须非零；在 patched 必须为零
  ├─ 回归在 patched 必须为零
  ├─ 跑完 origin 仍同哈希
  └─ 回滚 experiment/ → 校验 restored == baseline；写 test.json

review
  ├─ 根因/证据/snippet/finding 重新校验
  ├─ origin 未变；test 属于本提案；gates/runs 自洽；补丁树可复算
  ├─ 无裁决字段（verified/confirmed/verdict/…）
  └─ engineering accepted/rejected；vulnerability 只读回显 → review.json
```

实验目录布局（全部落在 `patch_root` 内，不写目标树）：

```
.platform/patch/<task>/<P1>/
    root_cause.json       proposal.json       baseline_manifest.json
    baseline/             experiment/         run/{baseline,patched}/   (测试时)
    logs/<stage>.log      test.json           review.json
```

---

## 5. CLI

```bash
# 1) 生成提案：只写实验副本；--diff 或 --patched-file 二选一
python3 bin/platform.py patch propose task-1 \
  --candidate C1 --source-root /path/to/src --file victim.py --line 4 \
  --claim observed --argument "数组下标没有边界检查，越界读触发 IndexError" \
  --evidence /path/to/crash.log --verification V1 \
  --diff fix.diff \
  --trigger-cmd "python3 victim.py poc.bin" \
  --regression-cmd "python3 victim.py good.bin" \
  --patch-root .platform/patch

# 2) 独立测试：原版触发 / 补丁不触发 / 回归 / 回滚
python3 bin/platform.py patch test P1 --task-id task-1 --patch-root .platform/patch

# 3) 复核：只判 patch_validation（accepted 也不写漏洞结论）
python3 bin/platform.py patch review P1 --task-id task-1 --patch-root .platform/patch

# 4) 显式回滚实验副本（校验恢复到基线哈希）
python3 bin/platform.py patch rollback P1 --task-id task-1 --patch-root .platform/patch
```

退出码：`propose` 成功 0、拒绝/unsupported 2；`test` passed 0、failed/blocked 1、
非法输入 2；`review` accepted 0、rejected 1；`rollback` 成功 0、拒绝 2。
`--task-id` 可省略：`patch test/review/rollback` 会在 `patch_root` 下按 `patch_id` 查找，
重名时报错而不是猜。

库接口：

```python
from agent.platform.adaptive.patch import PatchWorkflow

wf = PatchWorkflow(".platform/patch", store=store, task_id="task-1")
wf.propose(candidate_id="C1", source_root="/path/to/src", line=4,
           argument="…", diff="fix.diff",
           trigger_cmd="python3 victim.py poc.bin",
           regression_cmds=["python3 victim.py good.bin"])
wf.test("P1")
wf.review("P1")     # {"status": "accepted"|"rejected", ...}
```

---

## 6. 交付边界

| 没做什么 | 说明 |
|---|---|
| 没改 `agent/platform/verify.py` | 漏洞 `verified/confirmed` 仍只由它写；P5 只读 `list_verifications` |
| 没改 `adaptive/policy.py` | 仅复用 `VERDICT_FIELDS` / `prune_verdict_fields` 的判定口径，未改一行 |
| 没改 `benchmark_policy` / 执行器 / DB schema | 补丁工件全部是文件，不新增表、不写事件、不改任务状态 |
| 没自动应用补丁 | `proposal.status` 恒 `proposed`、`applied_to_origin` 恒 `false`；应用只发生在 `experiment/` 与 `run/` 副本 |
| 没把补丁当官方 fix 端 | `scope` 恒 `patch_validation`，不写历史 pass、不增加独立根因数 |
| 没 commit | 按任务要求不 `git commit` |

已知限制（如实记录）：

- 只支持**单文件、已存在、UTF-8 文本**的最小 diff（新建/删除/重命名/二进制会拒绝）；
- `test` 的命令由调用方给出，工作流只提供干净环境（最小 `PATH`、`HOME/TMPDIR` 指到
  副本外、`PYTHONDONTWRITEBYTECODE=1`）与超时，不做额外的沙箱包裹；
- 触发/回归判定用退出码，不解析 sanitizer 输出类型；
- 结构比较用整树 sha256，不做逐行 AST 差异；同哈希即视为未变。

---

## 7. 验收测试

`tests/test_v3_p5_patch.py`（15 个函数，全部用临时目录与临时 `PlatformStore`）：

| 测试 | 断言的事 |
|---|---|
| `test_propose_writes_only_experiment_and_keeps_origin` | 原件逐字节 + 整树哈希不变；补丁只在 `experiment/`；`proposed` / `applied_to_origin=false`；`baseline` 同哈希 |
| `test_proposal_carries_diff_tests_finding_and_rollback` | diff 可复算、测试命令、回滚文件、finding 候选、证据 sha 现场可复算、snippet 有哈希 |
| `test_propose_refuses_missing_finding_or_source` | 候选不存在 / 无源码（unsupported）/ 证据缺失 / 没有触发命令 / 无论证 / 行号越界 → 拒绝且不半写 |
| `test_propose_refuses_fake_fix_diffs` | 改测试、吞异常、只删不补、超行数 → 明确拒绝码 |
| `test_large_diff_allowed_only_when_limits_raised` | 只有显式放宽 `limits` 才接受大补丁 |
| `test_independent_test_passes_and_review_accepts` | 非零/零/零三连 + 回滚哈希 + `accepted` + 无 `confirmed`/`verified: true` |
| `test_review_accepts_only_when_test_passed` | 没测试 → `test_present` 拒绝；补丁不修 → `test_passed` 拒绝 |
| `test_rollback_restores_experiment_hash` | 手改实验副本后回滚，哈希回到基线 |
| `test_failed_rollback_blocks_test_and_refuses_rollback` | 基线被删 → `blocked`；显式回滚抛错 |
| `test_review_rejects_tampered_evidence` | 证据文件被改 → `evidence_recomputable` 拒绝 |
| `test_verified_record_is_read_only_and_never_confirmed` | 有 `V1` 验证记录时 `vulnerability.status=verified_in_platform`，但仍无 `confirmed` |
| `test_contracts_refuse_applied_or_verdict_fields` | 契约拒绝 `status=applied`、`applied_to_origin=true`、无证据根因、未知测试状态、非 `patch_validation` 复核 |
| `test_diff_roundtrip_and_context_strictness` | 生成→解析→应用往返一致；上下文不匹配即拒绝 |
| `test_cli_propose_test_review_roundtrip` | CLI 四连跑通，退出码 0，原件仍原样 |
| `test_cli_refuses_without_source_tree` | 无源码 → `{"status": "unsupported"}`、退出码 2 |

回归口径：本批未改既有模块，跑既有 `tests/test_v3_*` 应保持全绿；新增子包不进入
`agent/platform/adaptive/__init__.py` 的导入链，旧入口启动行为不变。
交付时全仓 `python3 -m pytest tests/ -q` 结果：**1438 passed, 8 skipped**（含本批 15 条）。

### 7.1 与实施清单 acceptance_tests 的对应

| 实施清单验收项 | P5 中的落点 |
|---|---|
| T05 修订构建/冒烟与回滚 | `test` 的 `independent_copy` / `trigger-*` / `regression-*` / `rollback_verified` 四个 gate；`rollback` 子命令 |
| T08 harness/工件自崩不升漏洞 | `PatchReview.scope=patch_validation`；`vulnerability` 只读回显；构造期拒绝 `confirmed` |
| T15 原判据不退化 | 未改 `verify.py` / `benchmark_policy`；全仓回归 1438 passed |
| T16 原件与报告哈希可复算 | `origin.tree_sha256`、`diff_sha256`、`evidence[].sha256`、`runs[].log_sha256`、`proposal_sha256` / `test_sha256` 全部现场计算并在复核时重算 |
