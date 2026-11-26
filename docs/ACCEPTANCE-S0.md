# S0 阶段验收报告（2026-11-10）

审查对象：`vulnmap` 的 S0「状态与来源审计」
审查方式：子智能体实现 → Lead 独立复跑 → 数据比对
结论：**S0 通过（带 2 项条件）**

---

## 1. 派发与完成情况

| 任务 | 子智能体 | 交付 | 状态 |
|---|---|---|---|
| task-1 S0-a 一致性审计 | s0-consistency | `experiments/check_consistency.py`、`CONSISTENCY.json`、14 项测试 | ✅ |
| task-2 S0-b 正式集与泄漏扫描 | s0-evalset | `eval_set.py`、`EVAL_SET.json`、`leak_scan.py`、`CONTAMINATION.md`、15 项测试 | ✅ |
| task-3 S0-c 修复 CG-08 不一致 | s0-remediate | 修 `report._llm_enabled`、重生成 CG-08 产物、7 项测试、before/after 存档 | ✅ |
| task-4 S0-d 补齐正式集归档 | s0-manifest | 下载 CG-09/CG-12 归档、manifest 解析 5/7、7 项测试 | ✅ |

---

## 2. 验收标准逐条核对（Lead 复跑）

| # | 标准 | 结果 |
|---|---|---|
| 1 | case.json `llm_enabled` 与 attempts 中 `llm.status=ok` 100% 一致 | **20/20 ok，0 mismatch**（修复前 1 处：CG-08） |
| 2 | 每案例有 provenance 五元组 | 15/15，`PROVENANCE.json` 与目录集合一致 |
| 3 | 含答案模板不得用于正式集 | 官方 PoC 模板 3 例（CG-13/14/15）全部标污染，未进正式集 |
| 4 | 开发集与正式集交集为空 | **EVAL_SET(7) ∩ DEV_SET(8) = ∅**（脚本断言） |
| 5 | 冻结 manifest 覆盖正式集，sha/digest 可复核 | 5/7 已解析且与 `sha256sum` 逐条相等；EG-01/EG-02 为 ExploitGym 条目不适用（见条件 1） |
| 6 | 泄漏自检 0 命中 | 扫描 155 个文本文件，跨任务泄漏 **0**；同任务自查 7 处不计 |
| 7 | harness_ub 不计入高危分子 | LEDGER `harness_ub_cases=1`，单列 |

**测试**：`pytest tests -q` → **306 passed, 6 skipped, 0 failed**（修复前 263）。

---

## 3. 关键发现与整改

### 3.1 真实缺陷：CG-08 报告说没调模型，日志里有调用

- 现象：`case.json agent.llm_enabled=false`，但 `.runtime/vulnmap.db` 的 `attempts.detail` 有 `llm.status=ok`；
- 根因：`_llm_enabled` 用 `outcome LIKE 'llm%'` 查询，而 `outcome` 实际是 `completed`，永远查不到；
- 整改：改为解析 `attempts.detail` 的 JSON；CG-08 产物通过真实 `ReportStage` 重跑生成（非手改），before/after 存档在 `experiments/remediation-s0/`；
- 复验：`llm_enabled false → true`，审计 0 mismatch。

### 3.2 正式集归档缺口

- CG-09/CG-12 原缺 `repo-vul.tar.gz`，已下载并校验（5.1MB / 3.2MB，sha256 与 manifest 一致）；
- EG-01/EG-02 为 ExploitGym 条目，无 `repo-vul.tar.gz` 概念，manifest 中标 `unresolved`，**不计入可跑正式集**。

---

## 4. 两项通过条件（不影响本轮结论，但 S2/S4 前必须关）

1. **EG 条目隔离**：EG-01/EG-02 的 `repo_sha256/image_digest` 仍为 null，必须在 S3 前改成 ExploitGym 专用字段（镜像 digest + task bundle 哈希），或从正式集移出；
2. **测试副作用**：`tests/test_exploit.py` 会写真实 `workspace/CG-04.../artifacts/verify/p.bin`，`tests/test_dashboard.py` 会重写 `web/data.json`；应改用 `tmp_path`。属 P2，不阻塞 S0，但会污染"最后一次运行"的证据。

---

## 5. 结论

- S0 的七条验收标准 **6 条完全满足、1 条部分满足（manifest 5/7，ExploitGym 条目另行处理）**；
- 数字首次做到"报告 = 日志 = 台账 = 文档"四方一致；
- 正式集与开发集互斥已由脚本断言，不是口头声明；
- 允许进入 S1 复核；S2 启动前需关闭第 4 节两项条件。

**一句话：S0 把"自证"变成了"可审计"，这是后续所有数字可信的前提。**
