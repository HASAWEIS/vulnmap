"""V3 P5（V3-017）可选补丁工作流：根因 → 提案 → 独立测试 → 复核。

《VULNMAP-V3 完整升级方案》§13 把 Patch 放在主路径之外，并要求它守住三条边界：

1. **只进 `patch_validation`**：`PatchReview.scope` 固定，补丁通过独立测试只说明
   「原版触发、补丁不触发、正常回归通过、回滚回原哈希」，不产生漏洞结论；
2. **不碰原件**：`PatchWorkflow.propose()` 只把补丁写进
   `<patch_root>/<task>/<P1>/experiment/`，`proposal.applied_to_origin` 恒为 `False`，
   `status` 恒为 `proposed`；
3. **无源码就 unsupported**：没有源码树的目标不会被“模拟修复”。

四个对象：`RootCause`（根因 + 原始 finding/证据引用）、`PatchProposal`
（diff + 测试命令 + 回滚方案 + 原件哈希）、`PatchTest`（原版触发 / 补丁不触发 /
回归 / 回滚）、`PatchReview`（工程采纳裁决；漏洞结论只读回显既有 verify 台账）。

用法（库接口）：

```python
from agent.platform.adaptive.patch import PatchWorkflow

wf = PatchWorkflow(".platform/patch", store=store, task_id="task-1")
wf.propose(candidate_id="C1", source_root="/path/to/src", line=42,
           argument="...", diff="fix.diff", trigger_cmd="python3 poc.py",
           regression_cmds=["python3 selftest.py"])
wf.test("P1")
wf.review("P1")          # engineering accepted 才为 accepted；漏洞仍是 verify 的事
```

CLI 见 `bin/platform.py` 的 `patch propose/test/review/rollback`，
验收口径见 `docs/V3-P5-PATCH.md`。
"""
from .contracts import (CLAIM_SOURCES, EXPECT_NONZERO, EXPECT_ZERO,
                        PATCH_VERSION, PROPOSAL_SCHEMA, PROPOSAL_STATUSES,
                        REVIEW_SCHEMA, REVIEW_STATUSES, ROOT_CAUSE_SCHEMA,
                        SCHEMA, SCHEMA_VERSION, TEST_SCHEMA, TEST_STATUSES,
                        EvidenceRef, FindingRef, Gate, PatchError, PatchProposal,
                        PatchReview, PatchTest, PatchUnsupported, RootCause,
                        json_bytes, safe_relpath, sha256_bytes,
                        verdict_fields_in)
from .diff import (DEFAULT_LIMITS, FileDiff, Hunk, apply_to_text,
                   apply_unified, build_unified, changed_stats, diff_paths,
                   hygiene_problems, parse_unified)
from .workspace import (CommandResult, file_sha256, manifest_of_tree,
                        read_json, read_tree, run_command, tree_manifest,
                        tree_sha256, write_json, write_log, write_tree)
from .workflow import PatchWorkflow

__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "PATCH_VERSION", "ROOT_CAUSE_SCHEMA",
    "PROPOSAL_SCHEMA", "TEST_SCHEMA", "REVIEW_SCHEMA", "PROPOSAL_STATUSES",
    "TEST_STATUSES", "REVIEW_STATUSES", "CLAIM_SOURCES",
    "EXPECT_ZERO", "EXPECT_NONZERO", "PatchError", "PatchUnsupported",
    "EvidenceRef", "FindingRef", "RootCause", "PatchProposal", "Gate",
    "PatchTest", "PatchReview", "verdict_fields_in", "safe_relpath",
    "sha256_bytes", "json_bytes",
    "DEFAULT_LIMITS", "Hunk", "FileDiff", "build_unified", "parse_unified",
    "apply_unified", "apply_to_text", "changed_stats", "diff_paths",
    "hygiene_problems", "CommandResult", "read_tree", "write_tree",
    "tree_manifest", "tree_sha256", "manifest_of_tree", "run_command",
    "write_log", "write_json", "read_json", "file_sha256", "PatchWorkflow",
]
