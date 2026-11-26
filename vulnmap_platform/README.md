# vulnmap 平台

只读可视化平台：把 `workspace/` 与 `experiments/` 里的验收工件呈现为可浏览的界面。

## 启动

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 vulnmap_platform/serve.py --port 8900
```

打开 <http://127.0.0.1:8900/>

依赖：FastAPI + Uvicorn（已在环境内）。前端零构建、零外部资源。

## 页面

| 路径 | 内容 |
|---|---|
| `/` | 总览：KPI、验收漏斗、案例一览 |
| `/cases.html` | 案例列表，支持筛选；点击展开完整验收链路 |
| `/packages.html` | 交付证据包与材料哈希 |
| `/lab.html` | 实验记录与对照实验 |
| `/api/docs` | 自动生成的 API 文档 |

## API

| 端点 | 说明 |
|---|---|
| `GET /api/overview` | 汇总数字与四层门禁定义 |
| `GET /api/cases` | 全部案例摘要 |
| `GET /api/cases/{dir}` | 单案例详情（验证结果、模型轮次、工件清单） |
| `GET /api/packages` | 交付包与文件哈希 |
| `GET /api/experiments` | 实验记录与 AB 对照 |
| `GET /api/health` | 健康检查 |

## 设计语言

布局参考 BinSight 的 landing 结构，按本平台的信息密度做了调整。

**借来的四个特征**

| 特征 | BinSight | 本平台 |
|---|---|---|
| 大留白 | `padding-block: clamp(80px,7vw,112px)` | `.sec{padding-top:96px}` |
| 大字号 | 正文 16–18px，行高 1.85–1.95 | 正文 15px / 行高 1.85，hero 44px |
| 卡片圆角 | 16px | 16px（表格、面板、步骤卡统一） |
| eyebrow 段落头 | `.section-no` + h2 + 描述 | `01 — 项目指标` 竖排段落头 |

**按本平台改的地方**

1. **信息密度提高**：BinSight 是营销页，本平台是控制台，表格与数据卡片是主体。
2. **步骤卡改为横向流程条**：详情页原用竖排 lane-steps，占高太多；
   改成五阶段横向连接线，省下一整屏。
3. **配色**：主色 `#1b2f6e`（比 BinSight 的 `#192d84` 更沉），
   强调色 `#e07b1f`，页面底 `#f7f8fa`——整体亮色，深色仅 hero。

**排版尺寸**

```css
--page:#f7f8fa  --surface:#fff  --line:#e4e8ee
--brand:#1b2f6e  --accent:#e07b1f
.sec{padding-top:96px}       /* 段落间大留白 */
.hero{padding:88px 80px}     /* hero 内边距 */
.card{border-radius:16px}    /* 统一圆角 */
```

## 设计约束

1. **只读**：后端不含任何写操作，页面点不动任何验收状态。
   （有测试 `test_platform_is_read_only` 守卫）
2. **单一数据源**：一律读 `case.json` / `LEDGER.json`，不另存副本。
3. **不隐藏失败**：unsupported、withdrawn 的案例照样列出。
4. **数据自洽**：`test_funnel_is_monotonic` 保证
   可交付 ⊆ 高危 ⊆ 因果链 ⊆ 双端 ⊆ 已完成。

## 数据更新

案例重跑后无需改前端，刷新即可（API 每次实时读文件）。
若 `LEDGER.json` 有变：

```bash
python3 experiments/ledger.py       # 重算台账
python3 experiments/gen_docs.py     # 同步 STATUS.md 与 CSV
```
