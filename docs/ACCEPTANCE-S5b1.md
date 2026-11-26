# S5-b1 阶段验收报告（2026-11-10）

审查对象：S5-b1「harness 契约提取与 CG-09 复跑」
审查方式：代码核对 + 测试 + 运行结果比对
结论：**S5-b1 部分通过**——契约机制成立，但 CG-09 仍未通过；S4 的“干净任务贡献”仍未达成

---

## 1. 交付与验证

| 项 | 结果 |
|---|---|
| `agent/harness.py` | 从 `Fuzz_chpw.c:26` 解析出 `Size < kMinInputLength || Size > kMaxInputLength`，常量解析为 **20 / 100**，`confidence=exact` |
| 注入 loop | `loop_prompt_version=verify-llm-loop-p3`，提示中写明允许区间 |
| 执行前校验 | 越界候选不执行，记 `rejected_by_contract`（本例 0 次，因两轮都在区间内） |
| 测试 | 全库 **336 passed / 6 skipped / 0 failed** |

## 2. 运行对比（同一任务，契约前后）

| 轮次 | S4-b（无契约） | S5-b1（有契约） |
|---|---|---|
| 1 | 未记录 | 100 B（区间内）`not_triggered` |
| 2 | 未记录 | 45 B（区间内）`not_triggered` |
| 3 | **1 B（区间外空转）** | 与第 1 轮重复 → `duplicate_input` 被拒 |

- 尺寸问题已消除：不再出现 1 字节空转；
- **重复检测在真机触发**：第 3 轮被判 `duplicate_input`——S4-a 遗留的“去重只靠单测”条件，本轮由真机路径补上了。

## 3. 仍未通过的原因

`verdict=generated_but_unverified`。契约只解决了“长度合法”，没解决“结构合法”：

- KRB5 `chpw` 需要 ASN.1 编码的改密请求，纯随机字节走不进 `krb5_chpw_message` 的 UTF-8 规范化分支；
- 现有 loop 只有“缺陷函数源码 + 尺寸约束”，没有格式种子/结构样例，因此 3 轮都在语义门外。

## 4. 结论

- **必要不充分**：harness 契约是 S4-b 的 B1 修复，确实生效，但 CG-09 还需要 B2/B3（格式种子 + 更具体的失败反馈）；
- S4 整体仍不通过：干净任务上的 `verified_new_contribution` 依旧是 0；
- S5 计数不变：独立高危仍为 3 例。

**一句话：这轮把“模型猜错长度”变成了“模型长度对了但结构不对”，问题更接近本质了，但还没解决。**
