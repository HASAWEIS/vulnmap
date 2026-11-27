# 严格 V2 复核：AR6 / AR7（2026-11-27）

> 结论先行：**AR6、AR7 是「人工验证包」，包内检查通过，但未通过严格 V2 复核。**
> 本轮据此把严格可提交数从（误报的）7 改回 **5**，并把两份包标为参考件。
> 复核用的是**原 5 份包同一个实现**：`experiments/submission-pack/pack_verify.py::verify`。

## 1. 复核方式

```bash
python3 experiments/case6-42470179/strict_v2_recheck.py
# 读取 课程提交包_20261127/{AR6,AR7}，调用冻结包同一 verify()
```

机读结果：`experiments/strict-v2-recheck-ar6-ar7.json`。

## 2. 结果

| 包 | strict | A | B | C | D1 | D2 | D3 | D4 | verify() 报错 |
|---|---|---|---|---|---|---|---|---|---|
| AR6 | **false** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | `缺 SHA256SUMS / MANIFEST.json` |
| AR7 | **false** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | `缺 SHA256SUMS / MANIFEST.json` |

冻结包校验器在**完整性门**就直接返回：两份包没有 `SHA256SUMS`、`MANIFEST.json`，
也没有 `judgments/`、`source/`、`build/`、`evidence-index.json`。
也就是说：它们根本还不是冻结包那种格式。

## 3. 逐项缺口（即使补上完整性门也过不了的原因）

| 层 | 冻结判据要求 | AR6/AR7 现状 |
|---|---|---|
| A | `severity.json` 需 `declared_base`、`final`、CVSS 向量与 `attack_vector` 一致、reviewer 不在拒绝名单 | 只有六维 + `rationale`，缺 `declared_base`/`final`，未做 CVSS 反算校验 |
| B | 双端日志 + 退出码 + PoC 哈希，且需与 `judgments/` 交叉 | 日志与退出码有；无 `judgments/` 交叉记录 |
| C | 传播链四要素 + 每条 ref 可解析且哈希一致 | 有四要素与 refs，但 refs 类别不满足冻结要求（`poc/`、`-vul.log`、`-fix.log`、`severity.json`、`task.json` 五类虽齐，仍缺 `judgments/` 支撑） |
| **D1** | **Agent 事件流（JSONL，seq 连续）+ 源数据库导出 + 逐类型行数对账** | **完全没有**：`trajectory.json` 是 4 步人工记录，`kind=manual`，无事件流、无 DB |
| D2 | 逐调用采样参数矩阵，决定性阶段完整 | `model_params.state=not_applicable`（0 次调用）——本身不违规，但不能替代 D1 |
| D3 | `review.layers` 含 A/B/C/D 且各 `holds`，`D.parts` 含 D1–D4；refs ≥6 且分类齐全 | `review.json` 无 `layers` 字段 |
| D4 | `MANIFEST.json` + `SHA256SUMS` 全量哈希 | 两者都缺 |

## 4. 两份包现在是什么

| 项 | 结论 |
|---|---|
| 类型 | **人工验证包**（源码分析 → 手工 PoC → docker 双端） |
| 包内检查 | 通过（各自 `verify_case.py` 13/13，退出 0） |
| 严格 V2 | **未通过** |
| 是否计入提交数 | **否**（保留作参考） |
| 是否计入独立根因 | 是（wget2 `42470179`、haproxy `42485152` 确实是新根） |

## 5. 口径修正后的数字

| 指标 | 值 |
|---|---:|
| 台账去重后的独立高危根因 | **11** |
| 通过各自包内复算的材料 | **7**（冻结 5 + AR6 + AR7） |
| **严格 V2 提交包** | **5** |
| 第三方独立复核 | **0** |
| 后端 `course_ready` | **0** |

## 6. 要变成严格 V2，缺什么（未做，只列清单）

1. **Agent 运行事实**：用 `bin/vulnmap.py` 跑出 runs/stages/attempts/blackboard 并导出 JSONL 事件流 + 源库；
   或取得课程对「人工案例可接受哪些替代日志」的**书面认可**；
2. `severity.json` 补 `declared_base` / `final` 并按冻结口径反算 CVSS；
3. `review.json` 补 `layers`（A/B/C/D + `D.parts` D1–D4）；
4. 补 `judgments/`、`source/`、`build/`、`evidence-index.json`；
5. 生成 `MANIFEST.json` + `SHA256SUMS`，再过一遍冻结 `verify()`。

在这些完成前，**不得**把 AR6/AR7 写成「严格可提交」，首页也不改成 7。
