# 自主闭环验收：运行包 + 独立校验（2026-11-27）

> 主线变更：从「尽快做出案例包」改为「先证明 Agent 独立做了什么」。
> 本文只覆盖**自主能力验收**，不改变课程计数（严格 V2 仍是 5 份）。

## 1. 三类结果分开（定义即判据）

| 类型 | 人做了什么 | 能证明什么 | 系统怎么判 |
|---|---|---|---|
| `manual_baseline` | 准备关键输入，脚本执行留档 | 结果可复核；不证明 Agent 能力 | 有 `provided_input/edit/supplied_answer` 类介入，或工件等于开始时可见材料哈希，或工件早于运行开始，或工件 `producer != agent` |
| `agent_assisted` | 提供输入/提示/中途修正 | 只证明有证据的那几步 | 有介入流水但不构成搬运/旧件 |
| `agent_autonomous` | 只给任务、权限、预算、验收 | 本次任务上独立闭环 | 无介入、工件均为本次产生、预算未超 |

AR6 / AR7 属于第一栏（人工基线），不因已有结果就转成自主案例。

## 2. 运行包里有什么（`agent/autonomy/pack.py`）

| 文件 | 内容 |
|---|---|
| `run.json` | `run_id`、任务、预算、`base_dir`、起止时刻、状态 |
| `frozen_inputs.json` | 开始时**给定/可见**材料的 sha256（冻结，事后可验未篡改） |
| `interventions.jsonl` | 人工介入流水（append-only，发生即降级，不删除） |
| `observations.jsonl` | 每次执行/读取的观测（用于预算核验） |
| `artifacts.jsonl` | 工件流水：包内路径、sha256、产生时刻、`producer` |
| `result.json` | Agent 提交的结果（含 `run_id`，跨运行引用会被拒） |

## 3. 独立校验器（`agent/autonomy/verify.py`）

读运行包 + 冻结任务 + **保留答案**（`experiments/autonomy/holdout/expected.json`，不进 Agent 可读目录），
输出 `pass` / `incomplete` / `fail`，并给出 `class` 与理由：

| 检查 | 不通过的含义 |
|---|---|
| `frozen_inputs_intact` | 冻结材料被改 |
| `budget_observations` / `budget_seconds` | 超预算 |
| `result_belongs_to_run` | 结果来自别的运行 |
| `artifact_provenance` | 工件不存在 / 哈希不符 / 非本次记录 |
| `expected_matched` | 与保留答案不符、缺条目、把不可观测项报成 ok |
| `class_autonomous` | 类别不是自主 |

`incomplete` 是**诚实结果**：观测不足就报 `unknown`，不算通过，也不算造假。

## 4. 第一张工单的结果：正例 / 反例

无害 fixture：`fixtures/autonomy/kvparse/`（键值解析器，无漏洞）。任务：对 7 个输入报告
`entries` 与 `errors`，其中 `missing.kv` 不存在，必须报 `unknown`。

| 运行 | 人工介入 | 分类 | 判定 | 说明 |
|---|---|---|---|---|
| `runs/auto` | 无 | **agent_autonomous** | pass（6 匹配 + 1 如实 unknown） | 冻结 7 份材料未变、7 次观测、6 件工件全为本次产生 |
| `runs/assisted` | 提供 `e.kv` | **agent_assisted** | fail（`class_autonomous=false`） | 系统据此降级，不把结果算作自主 |

```bash
python3 experiments/autonomy/demo_agent.py --pack experiments/autonomy/runs/auto --run-id r-auto-001
python3 experiments/autonomy/demo_agent.py --pack experiments/autonomy/runs/assisted --run-id r-assist-001 \
  --assisted fixtures/autonomy/kvparse/inputs/e.kv
```

## 5. 回归（9 项，`tests/test_autonomy_runpack.py`）

| 场景 | 期望 |
|---|---|
| 自主运行 | `agent_autonomous`，provenance ok |
| 人工提供输入 | `agent_assisted`，verdict fail，理由含「关键输入类人工介入」 |
| 缺条目 | fail，`missing>0` |
| 跨运行引用 | `result_belongs_to_run=false`，fail |
| 工件被篡改 | `artifact_provenance=false`，fail |
| 超预算 | `budget_observations=false`，fail |
| 搬运可见材料当工件 | `manual_baseline` |
| 不可观测项如实报 unknown | `expected_matched=true` |
| 不可观测项猜成 ok | fail |

## 6. 边界（明确不做）

- 不在真实目标上做利用生成；本验收只证明“任务执行 + 反馈调整 + 证据交接”；
- 不把人工轨迹补造成 Agent 运行记录；
- 不因为这套验收通过就改课程计数：严格 V2 仍 5 份，AR6/AR7 仍人工参考件；
- 保留样例的答案不进入任何 Agent 可读路径，也不写进运行包。

## 7. 下一步

1. 在保留样例上跑稳定性（多轮、同任务重复），看类别是否稳定为自主；
2. 把同一套运行包接入课程流程（`bin/platform.py` 的 run_id 与事件流），让“自主运行”可被课程判据直接引用；
3. 人工案例认定征询（`MANUAL-CASE-ACCEPTANCE-REQUEST.md`）仍待外部答复，不影响本验收。
