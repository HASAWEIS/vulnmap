# 自主性口径与 builder/model 路径分离（2026-11-12）

## 问题

此前 verify 的顺序是「预置构造器优先，失败才进模型循环」。因此案例通过不能证明模型做了关键决策。

## 已改

1. `task.json` 新增 `verify.allow_builders`（默认 true）；设为 false 时，`_candidates()` 直接返回空，**不运行任何预置构造器**，强制走模型循环；
2. `case.json` 新增 `generation_path`：`builder` / `model` / `none`，按候选 `proposed_by` 与 `model_loop.rounds` 判定；
3. 台账统计时，`model_new_contribution` 仍只认“模型生成 + 执行验证通过”，与 `generation_path=model` 分开看。

## 分类

| generation_path | 含义 | 能否证明自主 |
|---|---|---|
| builder | 预置构造器直接命中 | 否，自动化复现 |
| model | 模型循环产出候选并验证 | 是（需冻结代码与未知任务） |
| none | 两者都没有 | 否 |

## 盲测边界（重要）

`s22-blind-10013` 在本次改动**之前**启动，FREEZE.json 钉的是旧代码哈希；但该任务格式 `tiff` 没有构造器分支，实际执行只走模型循环。
因此它可以作为“模型路径”的观察，但**不能声称是在 allow_builders=false 下跑的**；下一轮会用新 FREEZE-v2 重跑一个带构造器分支的格式，做严格对照。

## 下一步

- 统计 9 个高危的 `generation_path`，把 builder 命中的从“模型自主”叙事中剔除；
- 新任务首跑统一 `allow_builders=false`，规则工具只做基线；
- 失败也进台账，不重跑覆盖。