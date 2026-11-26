# 平台 v2 P4：任务 Web/API 与只读消费

> 范围：把 P0–P3 的任务运行时（TaskState / EventBus / EvidenceStore / Candidate /
> Verification / Review / CasePack）接上 Web：一个提交/队列入口、一个状态 + 时间线页、
> 一个事件流页、一个证据浏览器、一个 CasePack/报告页。
> P4 的重点不是“再做一个后台”，而是**页面只读、状态只由运行时写**：
> HTTP 只允许提交任务、跑准入门、显式触发执行，其余全是查询。
> 前置：[PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §5、[PLATFORM-V2-P3.md](PLATFORM-V2-P3.md)。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [vulnmap_platform/api/platform_tasks.py](../vulnmap_platform/api/platform_tasks.py) | `/api/platform/*`：提交、列表、详情、事件、证据（含 blob）、CasePack（含文件下载）、准入、显式执行触发 |
| [vulnmap_platform/api/app.py](../vulnmap_platform/api/app.py) | 注册 P4 路由（在静态挂载之前），与 Discovery API 并列 |
| [vulnmap_platform/static/platform-tasks.html](../vulnmap_platform/static/platform-tasks.html) | 任务列表 + 提交表单 + 队列筛选；提交/准入按钮打 API |
| [vulnmap_platform/static/platform-task.html](../vulnmap_platform/static/platform-task.html) | 任务详情：状态 / 预算 / 时间线 / 候选 / 验证 / 复核 / CasePack 指针 |
| [vulnmap_platform/static/platform-events.html](../vulnmap_platform/static/platform-events.html) | 事件流：seq / 时间 / 事件 / stage / payload，支持 `after=` 增量拉取 |
| [vulnmap_platform/static/platform-evidence.html](../vulnmap_platform/static/platform-evidence.html) | 证据浏览器：kind / sha256 / 大小 / 来源阶段 / 在盘 / 哈希复算 / 下载 |
| [vulnmap_platform/static/platform-casepack.html](../vulnmap_platform/static/platform-casepack.html) | CasePack：台账、路径、content_sha256、文件下载、report.md 预览 |
| [vulnmap_platform/static/app.js](../vulnmap_platform/static/app.js) | `VIEWS` 增加 V2 任务入口；新增 `stateBadge` / `taskNav` / `taskPicker` / `getOr404` |
| [vulnmap_platform/static/style.css](../vulnmap_platform/static/style.css) | `.pf-*` 样式（表单、KPI、子导航、代码块），沿用既有色板与响应式断点 |
| [vulnmap_platform/static/index.html](../vulnmap_platform/static/index.html) | 首屏 workspace-strip 增加“V2 任务队列”入口 |
| [tests/test_platform_v2_p4.py](../tests/test_platform_v2_p4.py) | 19 项验收：提交/准入/查询/事件/证据/CasePack/404/只读/页面 |

## 2. API（`/api/platform`）

数据源只有一处：`<PLATFORM_ROOT>/platform.db`（默认 `<repo>/.platform/platform.db`），
与 P0–P3 的 `bin/platform.py --db` 是**同一个库**；证据在 `<PLATFORM_ROOT>/evidence`，
CasePack 在 `<PLATFORM_ROOT>/casepacks/<task_id>`。
`PLATFORM_ROOT` 每次请求重新读取（测试用临时目录覆盖，不影响仓库 `.platform`）。

| 方法 | 路径 | 读/写 | 行为 |
|---|---|---|---|
| `POST` | `/api/platform/tasks` | 写 | 建任务（RECEIVED）并发 `task.created`；**不执行目标**；重复 `task_id` 409 |
| `GET` | `/api/platform/tasks` | 读 | 列表 + `totals.by_state/by_benchmark`；支持 `state` / `benchmark` / `limit` |
| `GET` | `/api/platform/tasks/{id}` | 读 | 状态 + 预算 + `timeline`（事件重放）+ plan/ProgramIndex/候选/验证/复核/CasePack 指针 |
| `GET` | `/api/platform/tasks/{id}/events` | 读 | append-only 事件流；`after=seq` 增量拉取，返回 `next_after` |
| `GET` | `/api/platform/tasks/{id}/evidence` | 读 | 证据清单：`present`/`hash_ok` 由请求时**现场重算** |
| `GET` | `/api/platform/tasks/{id}/evidence/{sha256}` | 读 | blob 下载；只允许该任务登记过的哈希 |
| `GET` | `/api/platform/tasks/{id}/casepack` | 读 | `reports` 台账最新一条 + 文件清单 + `content_sha256`（现场重算并给出 `hash_ok`） |
| `GET` | `/api/platform/tasks/{id}/casepack/file?name=` | 读 | 下载包内文件；名字必须在包清单里，`..`/绝对路径/未知名字 404 |
| `POST` | `/api/platform/tasks/{id}/preflight` | 写（准入） | 在 `RECEIVED` 与 `BLOCKED`（补齐材料后重试）受理：`→ PREFLIGHT → READY/BLOCKED`，写 `preflight.passed/failed`，响应带 `retry/previous_state` |
| `POST` | `/api/platform/tasks/{id}/run` | 写（显式触发） | 只在 `PLANNED` 受理；把执行交给 `bin/platform.py run` 子进程，HTTP 请求本身不跑目标 |

错误口径：未知任务所有子路由 404；非法 benchmark/state/budget 400；重复提交、
`BLOCKED` 的准入是**重试**：只追加事件、不删旧事件，重跑检查再决定 READY/BLOCKED；
其它状态准入、非 `PLANNED` 执行一律 409；库不可读 503。

### 2.1 只读的三条硬约束

1. **GET 不建库**：库文件不存在时列表返回 `exists=false` + 空数组，详情/事件/证据/
   CasePack 返回 404；不会为了“看一眼”而创建 `platform.db`（测试
   `test_list_does_not_create_database` 钉住）。
2. **GET 不改状态**：读端点只调用 `get_task/list_*/summary/replay`；测试在 GET 前后
   对比 `state/updated_at/事件数/证据数/候选数` 必须完全一致。
3. **页面不碰 DB**：五个页面只通过 `api()` / `postJSON()` 取数与提交，源码里没有
   `sqlite`，也没有 `DELETE/PUT/PATCH`；只有提交页允许 `postJSON`，且只能打到
   `/api/platform/tasks*`。

### 2.2 执行由 CLI 或显式接口触发

提交/准入只推进“任务接入”这一段；真正跑目标仍由 CLI 完成：

```bash
python3 bin/platform.py --db .platform/platform.db submit --benchmark target_yaml \
  --target workspace/VG-01 --task-id v2-demo
python3 bin/platform.py --db .platform/platform.db preflight v2-demo
# ... understand / hypotheses / plan / run / verify / review / casepack（P1–P3）
```

`POST /{id}/run` 只是把这套 CLI 的 `run` 包一层：校验状态必须是 `PLANNED`，
把子进程输出写到 `<PLATFORM_ROOT>/runs/<task_id>.log`，返回 `pid`。
HTTP 层不解析、不伪造执行结论，状态变化仍以事件流为准。

## 3. 页面

五页共用现有外壳（`renderShell` + `app.js` + `style.css`），不引入框架、不引外链：

| 页面 | 入口 | 内容 |
|---|---|---|
| `platform-tasks.html` | 侧栏 / 顶栏「V2 任务」；`index.html` workspace-strip | 指标 + 提交表单（benchmark/target/mode/预算/metadata）+ 队列（状态筛选、搜索、准入按钮） |
| `platform-task.html?task_id=` | 列表行「详情」 | 状态徽章、预算字段、时间线、Plan/ProgramIndex/假说集、候选/验证/复核表、CasePack 指针与子导航 |
| `platform-events.html?task_id=` | 详情子导航 / 列表行「事件」 | 事件表（payload 可展开）、类型/内容过滤、`after=` 增量拉取、重放状态 |
| `platform-evidence.html?task_id=` | 详情子导航 | 证据表 + 完整性 KPI（条数/在盘/哈希可复算）+ 逐条下载 |
| `platform-casepack.html?task_id=` | 详情子导航 | 包路径、`content_sha256` 与现场重算对比、包内文件下载、`report.md` 预览、打包台账 |

导航：`app.js` 的 `VIEWS` 在 Discovery 四页之后插入 `V2 任务`（`platform-tasks.html`），
`index.html` 首屏 workspace-strip 也放了一个显式入口；任务子页用 `taskNav()` 互跳，
`task_id` 只放 query，不写 URL path，刷新/分享都稳定。

空状态与错误：没有任务时给提交提示；任务不存在时给 404 说明 + 返回列表按钮；
CasePack 未出包时明确写“只由运行时产生，本页不提供打包按钮”。

## 4. 测试

`tests/test_platform_v2_p4.py`（19 项，全部走 `TestClient` + 临时 `PLATFORM_ROOT`）：

| 组 | 断言 |
|---|---|
| 提交/准入 | RECEIVED + 唯一 `task.created`；preflight→READY/BLOCKED；缺目标 blocked；BLOCKED 可重试（事件只追加）；其它状态 409；重复 409；非法 benchmark/预算/授权值 400 |
| 查询 | 列表筛选/limit/totals；`by_benchmark` 精确；非法 state/benchmark 400 |
| 事件 | `after=0` 全量 = 4 条（task.created + 两条 state.changed + preflight.passed）；`after=last` 空且 `next_after` 不变 |
| 证据 | 清单 `hash_ok`；blob 内容一致；未登记 sha / 非法 sha 404；篡改 blob → `hash_ok=false` |
| CasePack | 未出包 404（含 file 下载）；出包后 `content_sha256` 可由包内文件复算；`casepack.json` / `report.md` 200；`../platform.db`、绝对路径、未知名字 404 |
| 只读 | GET 前后状态/事件/证据/候选不变；无库时 GET 不建库；未知任务全 404 |
| 页面 | 五个页面 200、含共用外壳；页面无 sqlite/写动词；提交页 `postJSON` 只打 `/api/platform/tasks*`；index/app.js 有 V2 入口；路由清单与页面调用对齐 |

验收命令（仓库根）：

```bash
python3 -m pytest tests/test_platform_v2*.py tests/test_platform_discovery.py -q
# 90 passed（P0 7 + P1 13 + P2 11 + P3 11 + P4 19 = 61；Discovery 29）
```

## 5. 本地起服务

```bash
python3 vulnmap_platform/serve.py --port 8102
# 或
PLATFORM_ROOT=/tmp/vulnmap-platform python3 -m uvicorn \
  vulnmap_platform.api.app:app --host 127.0.0.1 --port 8102
```

`PLATFORM_ROOT` 未设置时用仓库 `.platform/`（P0–P3 CLI 的默认库）；
起服务后先提交一个任务，五个页面才有数据可看。API 文档在 `/api/docs`。

## 6. 边界（P4 不做）

- 不做鉴权/多用户：默认本地单机只读 + 提交/准入；对外暴露前必须加认证与 CSRF 防护；
- 不做 SSE/WebSocket：事件流用 `after=seq` 增量拉取，轮询即可，避免长连接与状态缓存；
- 不做页面内执行：`run` 只在显式接口/CLI，页面不提供“一键跑完”按钮；
- 不重写 Discovery 五页：它们仍是“执行证据视图”，P4 只新增任务视图并复用外壳；
- 不把 CasePack 复制到页面：只给路径 + 哈希 + 下载，blob 留在内容寻址 store；
- 不新增状态：`platform.db` 仍由 `agent/platform/store.py` 一个 schema 管，
  `SCHEMA_VERSION=4` 不变。
