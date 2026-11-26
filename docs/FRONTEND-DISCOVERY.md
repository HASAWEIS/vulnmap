# Discovery 前端与只读 API

平台默认入口是 **Discovery 总览**。前端零构建、零外部资源，复用
`vulnmap_platform/static/style.css` 与 `app.js` 的侧栏 / 顶栏 / 面板样式。

启动：

```bash
python3 vulnmap_platform/serve.py --port 8900
# http://127.0.0.1:8900/
```

## 数据源

只有一个数据源：`<DISCOVERY_ROOT>/**/campaign.json` 以及同目录的证据文件。

```text
<evidence>/
  campaign.json      # id / target / risk_stats / coverage / analysis / execution_isolation
  target.json        # D0 静态档案
  callsites.json     # D1 调用点台账
  hypotheses.json    # D1.5 假设
  triage.json        # D3 分诊
  reviews.json       # D3.5 复核
  report.json        # D4 结构化报告
  report.md          # D4 报告正文
  crashes/crash-*.bin + .log
```

- 默认根目录：仓库 `discovery/`。
- 环境变量 `DISCOVERY_ROOT` 可覆盖根目录；每次请求重新读取，便于测试。
- 平台不复制、不缓存、不写回任何 campaign 状态。
- 证据缺失时返回空列表 / `null` / 404，不补写、不推断结论。

### 重复 campaign id

同一 id 可能在多个目录出现（如 `eval-fixture/eval-ranked` 是复跑副本）。
列表保留每份证据的 `key`（相对目录）；详情按 id 查询时取**最浅、路径最短**的
原始目录（`discovery-83fddbcf` → `fixture`，`cJSON-81da812d` → `real-cjson`）。
需要精确目录时传 `?dir=<key>`。

## 页面

| 路径 | 内容 |
|---|---|
| `/`（`index.html`） | Discovery 总览 = Benchmark 通过性：台账案例、双端通过 / 通过率、因果链、高危；附 Discovery 证据摘要与三张架构/路线/流程图 |
| `discovery-campaigns.html` | Campaign 列表：按 confirmed / weakened / 崩溃 / 缺报告筛选，支持搜索与分页 |
| `discovery-campaign.html?id=<id>&dir=<key>` | Campaign 详情：元数据、覆盖率、调用点、假设、分诊、复核、崩溃、target 档案 |
| `discovery-findings.html` | Findings / Crashes：跨 Campaign 汇总崩溃文件，按 triage 结论筛选 |
| `discovery-reports.html` | Reports：按 Benchmark 分组，每个 Benchmark 下按样例分节；与旧 `report.html` 同源（`/api/benchmark-reports/{benchmark}`） |
| `discovery-report.html?id=<id>&dir=<key>` | 单个 Discovery campaign 的 `report.md` 阅读器（只渲染已落盘报告） |

旧页面 `cases.html`、`report.html`、`overview.html`、`packages.html`、`lab.html`
保留可访问；侧栏导航默认第一项为 Discovery。

## API

| 端点 | 返回 |
|---|---|
| `GET /api/discovery/campaigns` | `{root, exists, items[], totals}`；item 含 `id` / `key` / `target` / `risk` / `coverage` / `analysis` / `isolation` / `report{md,json,available}` / 崩溃数 |
| `GET /api/discovery/campaigns/{id}` | `campaign`（campaign.json）、`target`、`callsites`、`triage`、`hypotheses`、`reviews`、`report`（report.json）、`crashes`、`evidence` 存缺标记 |
| `GET /api/discovery/campaigns/{id}/report` | `report.md`，`text/markdown; charset=utf-8` |
| `GET /api/discovery/campaigns/{id}/crashes` | `{id, key, dir, count, crashes[]}`；每项含文件名、大小、日志、triage `stack_hash` / `verdict` / `access` / 根因帧 |

详情 / 报告 / 崩溃端点都接受可选 `?dir=<key>` 用于区分重复 id。
未知 campaign、缺失报告、非法目录均返回 404。

## 测试

```bash
python3 -m pytest tests/test_platform_discovery.py -q
```

测试使用 `fastapi.testclient.TestClient` 直接加载 app，证据来自仓库
`discovery/fixture`、`discovery/real-cjson` 与 `discovery/eval-fixture`，
不依赖 8102/8900 等运行中的服务。

## 约束

1. **只读**：新增 API 不含写文件、创建目录、删除或状态变更操作。
2. **不改验收状态**：前端只展示证据，不提供通过 / 撤回 / 重跑 Discovery 的入口。
3. **不写密钥**：页面与 API 不读取、不展示、不落盘任何 LLM API key。
