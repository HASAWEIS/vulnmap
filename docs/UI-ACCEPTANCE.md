# Discovery 前端浏览器视觉验收

- **验收对象**：`vulnmap_platform/static` 中的 Discovery 前端（只读证据视图）
- **访问入口**：http://127.0.0.1:8102/ （本地 uvicorn，验收后已关闭）
- **启动命令**：`python3 -m uvicorn vulnmap_platform.api.app:app --host 127.0.0.1 --port 8102`
- **验收时间**：2026-11-16 11:41–11:56（Asia/Shanghai）
- **浏览器**：Microsoft Edge 152.0.4191.62（headless，CDP `127.0.0.1:9222`），真实渲染 + 真实截图
- **视口**：桌面 1440×900（布局视口 1425，滚动条 15px）；移动 390×844；极窄 320×720
- **结论**：**通过**。5 个要求的页面 + campaign 报告阅读器全部可达、无 JS 报错、无横向溢出，campaign 详情与列表数据来自 `/api/discovery/*` 且与接口一致；修掉 2 个实际问题（favicon 404、窄屏第 5 张 KPI 卡孤行），遗留 5 项均不影响可用性。

## 一、验收方式与工具说明（重要）

本次使用 DSH 的 `browser_navigate` / `browser_snapshot` / `browser_screenshot` 起手：`/` 首页已成功加载并截图、读到控制台。

随后为把桌面视口从 headless 默认的 772×496 调宽，重启了被 CDP attach 的 Edge 进程；浏览器插件的 CDP 会话缓存了旧页面 target，之后所有 `browser_*` 调用固定返回 `Page.navigate: the DevTools socket closed` / `unknown tab`，无法再自愈。为避免中断验收，改用同一套能力但直连 CDP：

- 同一个 Edge（`--remote-debugging-port=9222 --user-data-dir=/tmp/edgeprofile --headless=new`），
  通过 `Page.navigate` / `Runtime.evaluate` / `Page.captureScreenshot` / `Log.entryAdded` / `Runtime.consoleAPICalled` 驱动；
- 截图是该浏览器真实渲染的 PNG（非拼图、非占位、非伪造），每页同时抓 viewport 图与整页图；
- 溢出检测在页面内用 `getBoundingClientRect()` 遍历所有元素：排除 `.sidebar`（移动端 off-canvas，按设计在视口外）与自身带 `overflow-x: auto/scroll/hidden` 的滚动容器（表格按设计横向滚动），只把**越出视口且没有任何滚动容器可承接**的元素计为缺陷。

因此：**视觉验收已完成**，截图来自真实浏览器；仅“由 DSH 浏览器插件驱动”这一点替换为“直接 CDP 驱动”。

## 二、结果总览（桌面 1440×900）

| # | 页面 | URL | `<h1>` | 表格行 | 横向溢出 | 控制台错误 |
|---|------|-----|--------|--------|----------|-----------|
| 1 | Discovery 总览 | `/` | Benchmark 通过性 | 3 | 0 | 0 |
| 2 | Campaign 列表 | `/discovery-campaigns.html` | Campaign 列表 | 12（分页 14 条 / 12 每页） | 0 | 0 |
| 3 | Campaign 详情 | `/discovery-campaign.html?id=discovery-83fddbcf&dir=fixture` | discovery-83fddbcf | 8 | 0 | 0 |
| 4 | Findings / Crashes | `/discovery-findings.html` | Findings / Crashes | 17 | 0 | 0 |
| 5 | Reports | `/discovery-reports.html` | Reports（正文 CyberGym 报告） | 1333 | 0 | 0 |
| 6 | Campaign 报告阅读器 | `/discovery-report.html?id=discovery-83fddbcf&dir=fixture` | Discovery 报告正文 | 4 | 0 | 0 |

截图（相对仓库根目录）：

- 总览：`discovery/ui-acceptance/00-index.png`、整页 `discovery/ui-acceptance/00-index-full.png`
- Campaign 列表：`discovery/ui-acceptance/01-campaigns.png`、`discovery/ui-acceptance/01-campaigns-full.png`
- Campaign 详情：`discovery/ui-acceptance/02-campaign-detail.png`、`discovery/ui-acceptance/02-campaign-detail-full.png`
- Findings / Crashes：`discovery/ui-acceptance/03-findings.png`、`discovery/ui-acceptance/03-findings-full.png`
- Reports：`discovery/ui-acceptance/04-reports.png`、`discovery/ui-acceptance/04-reports-full.png`
- Campaign 报告：`discovery/ui-acceptance/05-campaign-report.png`、`discovery/ui-acceptance/05-campaign-report-full.png`

![Campaign 列表](../discovery/ui-acceptance/01-campaigns.png)

原始证据（每页 h1 / 行数 / 溢出 / 控制台）落盘在 `discovery/ui-acceptance/evidence.json`，交互脚本输出在 `discovery/ui-acceptance/interactions.json`、`discovery/ui-acceptance/interactions2.json`、`discovery/ui-acceptance/desktop-scan.json`。

## 三、导航可达性

侧栏 9 项与顶部移动端 tab 均指向已存在页面，实测点击：

| 动作 | 结果 |
|------|------|
| 总览 → 侧栏「Campaign 列表」 | 落在 `/discovery-campaigns.html`，h1 = Campaign 列表 ✅ |
| 列表首行「discovery-83fddbcf」 | 落在 `...?id=discovery-83fddbcf&dir=fixture`，h1 = id ✅ |
| 详情「阅读 report.md」 | 落在 `/discovery-report.html?id=...&dir=...`，Markdown 已渲染出 `h2` 分节 ✅ |
| 移动端汉堡按钮 | `.nav-open` 生效、抽屉+遮罩显示；点「Findings / Crashes」落在 `/discovery-findings.html` ✅ |

## 四、数据来自 API（campaign 详情）

详情页 5 张 KPI 卡与 `/api/discovery/campaigns` 中同一条记录逐项对齐：

| 页面显示 | 接口字段 | 值 |
|----------|----------|----|
| 覆盖率 100%（4/4 调用点） | `coverage.covered / coverage.planned` | 4 / 4 |
| Confirmed 1 | `risk.confirmed` | 1 |
| Weakend 0 | `risk.weakened` | 0 |
| 崩溃文件 1 | `crashes` | 1 |
| 假设 3 | `hypotheses` | 3 |
| 元数据区块 | `id / key / target / strategy / format_hint / isolation.mode / analysis.mode / build.sha256 / campaign_path` | 全部命中，长 sha256 与长路径在格内换行不断版 |

另取一条 0 confirmed、超长路径的 campaign 复核长文本：`/discovery-campaign.html?id=libpng-1.6.37-914c87e9&dir=real-libpng-row`（13%、30/225 调用点、sha256 64 字符、target 绝对路径）——溢出检测为 0，截图 `discovery/ui-acceptance/08-campaign-longtext.png`。

## 五、空态与异常态

| 场景 | 表现 | 截图 |
|------|------|------|
| Campaign 搜索 `zzz-no-match` | 表格内「没有匹配的 Campaign」，计数「0 个结果」，不塌版 | `discovery/ui-acceptance/06-campaigns-empty.png` |
| 筛选「缺报告」 | 「0 个结果」+ 空态行（当前 14 个 campaign 都有 report.md，符合数据） | — |
| Findings 筛选「未分诊」 | 17 → 7 行，计数同步「7 个结果」 | — |
| Reports 切 `?benchmark=exploitgym` | 标题/分节整体切换，5 个 report-section，无报错；`?benchmark=nope` 显示「未找到该 Benchmark，请选择已有分类。」 | `discovery/ui-acceptance/07-reports-exploitgym.png` |
| 详情页缺 `id` | 「没有选择 Campaign」+ 回列表引导 | — |
| 详情页 id 不存在 | 「no-such-id 不存在 / HTTP 404」+ 返回列表 | — |
| Reports「导出 PDF」 | 503 → 状态行显示「PDF 依赖未安装，请安装 reportlab 或先导出 Markdown」（不静默失败） | `discovery/ui-acceptance/40-reports-pdf-status.png` |
| Reports「导出 Markdown」 | 状态行「已生成 MD，请查看下载。」 | 同上 |

## 六、移动窄屏（390×844 / 320×720）

- 5 个页面在 390 与 320 下 `documentElement.scrollWidth - clientWidth` 均为 **0**（页面级无横向滚动），越出视口且无滚动容器的元素 **0 个**；
- 侧栏按设计转为 off-canvas，汉堡 + 遮罩可用，`Esc`/点击遮罩可关；
- 表格在 `.tw` 容器内横向滚动（390 下可见宽 356 / 内容 878，`scrollLeft` 可到 400），**页面本身不横滚**；
- 移动截图：`discovery/ui-acceptance/10-mobile-index.png`、`discovery/ui-acceptance/11-mobile-campaigns.png`、`discovery/ui-acceptance/12-mobile-campaign-detail.png`、`discovery/ui-acceptance/13-mobile-findings.png`、`discovery/ui-acceptance/14-mobile-reports.png`、抽屉态 `discovery/ui-acceptance/15-mobile-nav-open.png`、表格横滑态 `discovery/ui-acceptance/16-mobile-table-scrolled.png`、极窄 320 `discovery/ui-acceptance/22-narrow320-detail.png`。

## 七、本次改动（仅 static）

1. **新增 `vulnmap_platform/static/favicon.ico`**（32×32，ICO/PNG 容器，手绘项目蓝 + 白色 v）。
   —— 验收时每个页面唯一的控制台报错就是 `/favicon.ico` 404（`GET /favicon.ico → 404 application/json`）。因为静态目录挂在根路径，补一个图标文件即可全站生效，无需改任何 HTML。修复后首页与所有页面控制台 **0 error**（`discovery/ui-acceptance/33-desktop-index-fixed.png`）。
2. **`vulnmap_platform/static/style.css`**：窄屏（≤650px）2 列 KPI 网格下补 `.metrics-grid>.metric:last-child:nth-child(odd){grid-column:1/-1}`。
   —— 总览 / Findings / 详情页都是 5 张卡，最后一张在 2 列网格里独占半格，右侧留空半屏。修复前 `discovery/ui-acceptance/12-mobile-campaign-detail.png`，修复后 `discovery/ui-acceptance/31-mobile-detail-fixed.png`（第 5 张「假设」卡铺满整行）。
3. **11 个页面 HTML 的 `style.css?v=202611161130` → `?v=202611161150`**：只改缓存串，确保上面那条 CSS 生效而不是吃到浏览器旧缓存。JS 未改，`app.js?v=` 保持原值。

未改动 `agent/`、`discovery/` 下任何 campaign 证据、`README.md`、`vulnmap_platform/api/`。

> 说明：`discovery/ui-acceptance/` 只是本次验收产物目录，没有 `campaign.json`，不会被 `/api/discovery/campaigns` 当成 campaign（验收前后列表均为 14 条）。

## 八、回归测试

```
python3 -m pytest tests/test_platform_discovery.py -q
28 passed, 1 skipped   # 新增 5 条视觉验收回归
```

新增用例（`tests/test_platform_discovery.py` 末尾）：

- `test_favicon_is_served_not_404` —— TestClient 打 `/favicon.ico`，断言 200 且是 ICO 容器；
- `test_every_page_pins_the_same_css_version` —— 11 个页面 style.css 版本号必须一致；
- `test_local_static_assets_referenced_by_pages_exist` —— 页面引用的本地 png/svg/js/css/ico 必须存在；
- `test_odd_metric_card_spans_full_width_on_narrow_screen` —— 守住窄屏第 5 张卡的铺满规则；
- `test_ui_acceptance_screenshots_referenced_in_doc_exist` —— 本文档引用的截图必须真实存在（防止文档引用幻觉路径）。

## 九、遗留问题（均不影响本次可用性结论）

1. **移动端表格靠横滑**：`.tw` 容器可滚动，但没有视觉暗示（右侧无渐隐、无「← 滑动」提示），列表页 390 宽下只露「Campaign / 目录」「Target」两列。建议后续给 `.tw` 加右侧渐隐遮罩或窄屏卡片式布局。
2. **详情页 404 文案夹英文**：错误框标题是中文，正文直接拼了 `e.message`（`HTTP 404`）。建议前端按状态码换中文文案。
3. **Reports 页一次性渲染**：CyberGym 27 个样例 → 1333 行 DOM、正文约 64k 字符，首屏偏重（本地静态服务下 ~1s 内可交互）。后续可按分节懒加载。
4. **PDF 导出依赖缺失**：环境未装 reportlab，`/api/benchmark-reports/{key}/export?format=pdf` 返回 503。UI 已正确显示中文原因、不静默失败；要出 PDF 需补依赖（本次不改 API）。
5. **未覆盖范围**：Safari/WebKit、真实移动设备、深色模式（页面未提供 dark theme）、打印样式；`/cases.html`、`/report.html`、`/overview.html`、`/packages.html`、`/lab.html` 五个旧页只确认可访问与共享骨架，未逐页截图验收。
