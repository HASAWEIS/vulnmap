# 平台统计口径（STATS）：四个数不能合成一个

> 一句话：**workspaces / runs 是"跑了多少次"，ledger_cases / independent_high 是"有多少案例"。**
> 两者混用会直接虚增样本量与完成度——旧版界面把 S2-/S4-/S5* 实验复跑目录当案例，
> 于是出现"25 个案例 / 12 个本地通过"，而台账只有 17 / 10。

数据来源：`vulnmap_platform/api/app.py` 的 `/api/overview` 返回的 `stats` 块（活数据，
随时增长）；本文表格只是 2026-11-11 的**快照**，判断进度请以 API 为准。

## 1. 四个口径

| 字段 | 含义 | 来源 | 可否用于"案例数" |
|---|---|---|---|
| `workspaces` | `workspace/` 下**全部目录**数（含无 `task.json` 的实验目录） | 文件系统 | **否**——这是运行载体，同一漏洞可复跑多次 |
| `runs` | 流水线**运行次数** | 各 `workspace/*/.runtime/*.db` 的 `runs` 表行数之和 | **否**——一个目录可能跑过多次 |
| `ledger_cases` | **台账案例条目数** | `experiments/LEDGER.json` 的 `totals.cases` | **是**（唯一正确口径） |
| `independent_high` | **独立高危**数（严重性已论证且不与其它案例同源） | `LEDGER.json` 的 `totals.high_severity_confirmed` | 用于"高危案例数"，不能当总量 |

2026-11-11 快照：`workspaces=25`、`runs=25`、`ledger_cases=17`、`independent_high=5`。

## 2. 为什么不能合并

1. **分母不同**：25 个目录里 8 个是复跑/诊断目录（S2-CG09-llm、S4-CG07-10096、S5E-CG08…），
   同一个漏洞出现两三次；台账按"一个漏洞一条"计；
2. **口径不同**：`runs` 数的是执行次数（重试、换构造器都会 +1），
   把它当进展会把"反复失败"读成"进展"；
3. **高危要看论证**：`independent_high` 要求严重性六维论证 + 非同源，
   不是"CWE 看起来像溢出"就算——EG-02 与 CG-01 同源，就不进这个分子。

## 3. 平台内部还有两处同名不同义的字段（务必区分）

| 平台字段 | 平台取值方式 | 台账字段 | 台账取值方式 | 2026-11-11 |
|---|---|---|---|---|
| `totals.cases` | 有 `task.json` 的目录数 | `ledger_cases` | 台账条目数 | 25 vs **17** |
| `totals.local_dual_run_pass` | `acceptance.local_verified` 为真 | `local_dual_run_pass` | `verdict == "pass"` | 12 vs **10** |
| `totals.causal_chain_verified` | `acceptance.causal_chain_verified` | 同名 | 同名 | 7 vs 6 |
| `totals.high_severity_confirmed` | 同上 | `independent_high` | 同名 | 5 = 5 |

结论：**只有 `ledger_cases` / `independent_high` 与台账同源**；`totals` 全块按工作区统计，
含复跑目录，所以它在数值上偏大，且已经标注 deprecated。

## 4. 兼容性处理

- `totals` 未删除（前端与既有脚本仍在读），但每个响应都带
  `totals._deprecated=true`、`totals._replaced_by="stats"` 和一句 `_note`；
- 顶层同时给 `totals_deprecated: true`；
- 新代码一律读 `stats.ledger_cases`（案例）、`stats.independent_high`（高危）、
  `stats.workspaces` / `stats.runs`（运行量）。

## 5. 界面该怎么用

| 界面位置 | 该显示的字段 | 不该显示的字段 |
|---|---|---|
| 首页"案例数"卡片 | `stats.ledger_cases` | `totals.cases` |
| 首页"高危"卡片 | `stats.independent_high` | 按 CWE 反推的高危 |
| 运行/复跑面板 | `stats.workspaces`、`stats.runs` | 混入案例列表 |
| 案例列表（`/api/cases`） | **当前仍返回全部有 `task.json` 的目录（含 S2-/S4-/S5* 复跑）**；收紧成正式案例需另立任务 | 拿它算"案例数"或完成度 |

## 6. 仍未收口的两处（本次 scope 外，需另立任务）

1. **前端卡片**：`vulnmap_platform/static/index.html` 的内联脚本仍读 `ov.totals`，首屏"案例总数"显示 `totals.cases`（当前 25），而非 `stats.ledger_cases`（17）；
2. **案例列表**：`/api/cases` 仍按"有 task.json 的目录"枚举，复跑目录会出现在列表里；
   收紧会改变既有测试 `tests/test_platform.py::test_every_workspace_case_listed` 的断言，属独立变更。

在此之前：**看数字请用 `/api/overview` 的 `stats` 块，不要看首页卡片。**

## 7. 复核

```
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_platform_stats.py -q     # 锁死四个口径
python3 -c "import json;d=json.load(open('experiments/LEDGER.json'))['totals'];print('ledger', d['cases'], d['high_severity_confirmed'])"
```

测试断言的不变式：
- `stats.ledger_cases == LEDGER.totals.cases`；
- `stats.workspaces > stats.ledger_cases`（多出的必须是复跑目录）；
- `stats.independent_high == LEDGER.totals.high_severity_confirmed`；
- `ledger_cases <= totals.cases <= workspaces`（旧的 totals 仍落在合理区间）。
