# 贡献拆分与特化性说明（2026-11-12）

## 为什么需要拆分

`discovery_source=llm` 只表示**定位阶段**的 subject 来自模型；不代表候选/构造器由模型生成。S21（CG-39）就是例子：

- locate：`subject=cff_string_index`，来源 `llm`（`locate-llm-p1`）；
- 生成：候选 `pdf-cff-real`，`proposed_by=builder`（`agent/builders/cff_pdf.py`）；
- `model_contribution.verified_new_contribution=false`，台账未把它算作模型新增贡献。

## 四类贡献（台账必须分开）

| 类型 | 定义 | 本项目例子 |
|---|---|---|
| 参考复现 | 使用官方 PoC/模板或任务自带答案 | 早期模板来源记录中的 PoC 同源模板 |
| 规则自动化 | 规则定位 + 内置构造器 | CG-04、CG-08R、CG-10D 等 |
| 模型参与 | 模型给出 subject/候选，但生成由构造器完成 | CG-39（S21） |
| 模型新增贡献 | 模型生成的候选被执行并验证通过，且非任务专用分支 | CG-07（1 例） |

## 当前口径

- 台账 `model_new_contribution` 只统计第 4 类；
- `dev_rerun` 案例标注 `first_run=false`，不计“未知任务首跑”；
- 盲测可用任务为 0，因此“自主泛化”目前**没有正面证据**，只有“协作复现”的证据。

## 盲测协议

见 `experiments/blind/FREEZE.json`：冻结 59 个 agent 文件、提示词版本与预算；首跑期间不改代码、不加任务专用分支、不用官方 PoC；失败保留。