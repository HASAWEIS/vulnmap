# S4-a 阶段验收报告（2026-11-10）

审查对象：S4-a「模型 loop 去重与换假设」——开发样本 arvo:10096
审查方式：代码核对 + 单测 + 独立容器复跑 + 产物哈希链
结论：**S4-a 通过（带 2 项条件）**

---

## 1. 验收标准核对

| # | 标准 | 证据 | 结果 |
|---|---|---|---|
| 1 | 重复输入被识别且不执行 | `run_diverse_loop` 每轮记 `input_sha256`，重复判 `duplicate_input` 并写回“换假设”提示；`tests/test_verify_diversity.py` 6 条 | ✅（单测） |
| 2 | 连续重复可终止 | 连续 2 轮重复写 `terminal_reason` | ✅（单测） |
| 3 | 模型贡献成立 | `verified_new_contribution=true`、`verified_generation/pinpoint=true`、`added_by_llm=["ConvertPrimitiveToPath"]` | ✅ |
| 4 | 结果可独立复现 | 我用同一 PoC 跑：vul=1（ASAN heap-buffer-overflow）、fix=0；PoC 500,049 B，由模型第 2 轮生成 | ✅ |
| 5 | 不越界改动 | `agent/loop.py` 未改；只改 `verify.py` + 新测试 + 新工作区 + `experiments/s4` | ✅ |

---

## 2. 关键结果

```text
verdict      : pass
rounds       : 2
distinct     : 1（第 2 轮即命中）
added_by_llm : ConvertPrimitiveToPath
sink         : magick/render.c:942
vul/fix      : 1 / 0
```

这是项目里**第一个** `verified_new_contribution=true` 的案例：模型不仅提出函数，还生成了真正触发崩溃的输入。

---

## 3. 两项条件（S4 整体通过前必须关）

1. **只在开发样本上成立**：10096 属于开发集，不能作为“泛化能力”证据。必须在正式集干净任务（如 CG-09/53666）上复现一次 `verified_new_contribution=true`，否则 S4 只能算“开发样本上的能力验证”。
2. **去重/终止路径未在真机触发**：本次第 2 轮就 pass，`duplicates_rejected` 实际为 0，重复与终止只由单测覆盖。需要一次故障注入（强制模型两轮同输入）证明真机路径生效。

---

## 4. 顺带修复的仓库级问题

S2/S4 引入了实验工作区（`S2-*`、`S4-*`），导致三处台账测试从 15 变 18 而失败：

- `experiments/check_consistency.py`：`load_cases` 与 `workspace_dirs` 排除实验前缀；
- `tests/test_dashboard.py`、`tests/test_docs_in_sync.py`：同步排除；
- 新增 `experiments/workspaces.py` 统一口径。

修复后：**312 passed / 6 skipped / 0 failed**，审计 0 mismatch。

---

## 5. 结论

- S4-a 达成了阶段性目标：**模型贡献从 0 到 1**；
- 但这条贡献发生在开发样本上，**不能直接写进课程材料当“自主发现”**；
- 下一步 S4-b：把同一套 loop 用在 CG-09（正式集干净任务）上，跑一次冻结后的模型路径，看能否复现。

**一句话：第一个真贡献出现了，但它还必须在一个没调过参的任务上再出现一次。**
