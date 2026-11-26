# 平台 v2 P4.6：CasePack 网页报告 + 写操作默认只开本机

> 范围：P3 的 Case Pack 只有 `report.md`（纯文本表格，给终端和 diff 用），P4.5 的写操作
> 在未设 token 时“全网开放、只是标注 open”。这一轮收两个口子：**报告多一份自包含的
> 确定性 HTML**，**写操作默认只允许本机回环**。前置见
> [PLATFORM-V2-P3.md](PLATFORM-V2-P3.md)、[PLATFORM-V2-P4.md](PLATFORM-V2-P4.md)、
> [PLATFORM-V2-P45.md](PLATFORM-V2-P45.md)、总文档 [PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md)。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/casepack.py](../agent/platform/casepack.py) | `FILES` 增加 `report.html`；新增 `render_report_html()`（确定性、样式内联、零外部资源、全字段转义）；`build_casepack()` 同批渲染 `report.md` + `report.html`，包内 `report{md,html,html_sha256,html_size,html_external_refs}`；`_record_report_html()` 给 `reports` 表幂等补列 `report_html_sha256` |
| [vulnmap_platform/api/platform_auth.py](../vulnmap_platform/api/platform_auth.py) | 写操作守卫改成“有 token 校验 Bearer，无 token 只放行回环”；`is_loopback_host()` / `client_is_loopback()` / `has_forward_headers()` / `trust_proxy()`；`auth_info()` 增加 `write_scope` / `loopback_only` / `remote_writes`；`X-Platform-Write-Scope` 头 |
| [vulnmap_platform/api/platform_tasks.py](../vulnmap_platform/api/platform_tasks.py) | `/casepack` 多 `report_html*` 字段与三个下载链接；`/casepack/file` 认 `text/html`；任务详情的 `casepack` 多 `report_html_sha256` / `download_html`；写端点响应带写口径头 |
| [tests/test_platform_v2_casepack.py](../tests/test_platform_v2_casepack.py) | 9 项验收：HTML 内容/哈希 3、API 下载 1、认证 4、打包门槛 1 |
| [docs/PLATFORM-V2-CASEPACK.md](PLATFORM-V2-CASEPACK.md) | 本文档 |

`store.py` 一行未改：`reports` 的附加列由 casepack 侧 `_ensure_columns()` 按 PRAGMA
幂等补齐，`SCHEMA_VERSION` / `PRAGMA user_version` 仍是 **4**（P4.5 的测试继续钉住）。

## 2. `report.html`

### 2.1 渲染口径

| 约束 | 做法 | 为什么 |
|---|---|---|
| 确定性 | 只用同一批台账快照（task/state/candidates/verifications/reviews/manifest/verdict）渲染，**不留渲染时间戳** | `report.html` 要进 `content_sha256`，同一内容必须得到同一字节，否则哈希不可复算 |
| 自包含 | 样式写在 `<style>` 里；无 `<script>` / `<link>` / `<img>` / `<iframe>` / `@import` / `url()` / `http(s)://` | 包要能离线打开，且不能被指成“偷偷拉外部资源” |
| 可审计 | 所有台账字段经 `html.escape(..., quote=True)`；候选/复核/证据路径一律当不可信输入 | 台账里有 `crash_type`、`reason`、`path` 这类自由文本，直接插值就是 XSS |
| 不新造结论 | 页面只转述 `verifications` / `reviews`，不出现 `confirmed` | 与 P3 的口径一致：确认结论只能由“验证 + 复核”共同支撑 |

页面结构：任务摘要 → 包级摘要（验证/复核计数与 `benchmark_verified`）→ 事件流（事件数、
阶段迁移 chips、重放状态）→ 候选表 → 独立验证表 → 复核表 → 证据清单（含逐条
kind/sha256/size/present/hash_ok/path）→ 口径声明 → footer 注明“确定性渲染、零外部资源”。

### 2.2 文件清单与哈希

```text
FILES = task.json, state.json, events.jsonl, candidates.json, verifications.json,
        reviews.json, evidence/manifest.json, report.md, report.html
content_sha256 = sha256(canonical_json([{path, sha256, size}] 按 path 排序))
```

- `report.html` 与 `report.md` **同时存在**：md 给终端/评审 diff，html 给人看；
- `report.html` 进 `FILES`，因此自动进 `content_sha256`，也自动出现在 `casepack.json`
  的 `files` 与 `report.ready` 事件的 `files` 列表里；
- 包内新增 `report` 段：

```json
"report": {"md": "report.md", "html": "report.html",
           "html_sha256": "<report.html 单文件 sha256>", "html_size": 12345,
           "html_deterministic": true, "html_external_refs": 0}
```

- `report.ready` 事件额外带 `report_html` / `report_html_sha256`，离线追责时不必先解包。

### 2.3 `reports` 台账：多记一列 html 哈希

| 列 | 含义 |
|---|---|
| `sha256` | 整包内容哈希（P3 口径不变：台账 ↔ 磁盘的唯一纽带） |
| `report_html_sha256` | `report.html` 单文件哈希（P4.6 新增，默认 `''`） |

只校验网页文件时不必重算整包：`sha256(report.html) == reports.report_html_sha256`。
列由 `_record_report_html()` 在打包时 `PRAGMA table_info(reports)` 检查后补，旧库打开即
自动升级；`store.py` 与 `SCHEMA_VERSION=4` 不动。

## 3. API（`/api/platform`）

| 端点 | 变化 |
|---|---|
| `GET /tasks/{id}/casepack` | 多 `report_html`、`report_html_sha256`（盘上文件）、`report_html_sha256_recorded`（台账值）、`report_html_ok`；`links` 多 `report_md` / `report_html` 下载地址 |
| `GET /tasks/{id}/casepack/file?name=report.html` | 新允许项，`Content-Type: text/html; charset=utf-8`；名字仍必须在包清单里，`..` 照样 404 |
| `GET /tasks/{id}` | `casepack` 段多 `report_html_sha256` 与 `download_html` |
| 所有写端点 | 响应体 `auth.write_scope` + `X-Platform-Write-Scope: loopback|token`；被拒的远端请求回 `X-Platform-Auth: denied` |

## 4. 写操作默认只开本机

### 4.1 判定矩阵

| 客户端 | `PLATFORM_API_TOKEN` | 结果 |
|---|---|---|
| `127.0.0.1` / `::1` / `localhost` / `*.localhost`（无转发头） | 未设置 | 受理；`auth.mode="open"`、`write_scope="loopback"`、`X-Platform-Auth: open` |
| 同上，但带 `X-Forwarded-For` / `X-Real-IP` / `Forwarded` | 未设置 | **403**（同机反代不等于本机调用）；`PLATFORM_TRUST_PROXY=1` 只覆盖“客户端地址仍是回环、只是带了转发头”的情况（uvicorn 默认 `proxy_headers=True`，会先把客户端改写成转发来源，那时按真实来源判定，远端照样 403） |
| 其它地址（`203.0.113.9` 之类） | 未设置 | **403**，detail 明说“设置 `PLATFORM_API_TOKEN` 并携带 Bearer”，不给“先试试”的空间 |
| `testclient`（Starlette `TestClient` 默认 peer） | 未设置 | 视为本机（不经网络、不可能是生产流量）；需要模拟远端就显式传 `client=(...)` |
| 任意地址 + 正确 Bearer | 已设置 | 受理；`write_scope="token"` |
| 任意地址 + 缺失/错 scheme | 已设置 | 401 + `WWW-Authenticate: Bearer realm="vulnmap-platform"` |
| 任意地址 + 错 token | 已设置 | 403 |
| 任意地址（GET） | 任意 | 200——读端点不改状态，不因鉴权口径关掉 |

要点：**token 是凭据，回环只是默认；一旦设置 token，回环不再免检**。

### 4.2 为什么不信任转发头

uvicorn 直接监听时 `request.client.host` 就是真实对端；但部署在 nginx/caddy 后面时，
后端看到的是 `127.0.0.1`——如果只按 `client.host` 判断，任何互联网客户端都能借反代拿到
“本机”身份。三层口径叠加，哪一层没配好都不会默认放行：

1. uvicorn 默认 `proxy_headers=True`，会先消费 `X-Forwarded-For` 并把 `request.client`
   改写成真实来源（实测：本机起服务、带 `X-Forwarded-For: 198.51.100.7` POST → 403，
   detail 里写的就是 `198.51.100.7`）；
2. 即使 uvicorn 没消费转发头（`--no-proxy-headers`），本模块也默认**见到转发头就当远端**；
3. 只有运维显式设置 `PLATFORM_TRUST_PROXY=1`（且保证前面那层代理**覆盖**而不是追加这些头）
   才按代理声明的来源判定。

这仍然不是鉴权：对外暴露请设 token。

`PLATFORM_TRUST_PROXY` 与 `PLATFORM_API_TOKEN` 都是**每请求重读**环境变量，测试用
`monkeypatch.setenv` 即可切换，无模块级缓存。

## 5. 测试

`tests/test_platform_v2_casepack.py`（9 项）：

| 组 | 项 | 断言 |
|---|---|---|
| HTML 内容/哈希 | 3 | ① `report.html` 在 `FILES` 且落盘，sha/size 与 `casepack.json`、`reports.report_html_sha256`、`content_sha256` 全部对得上；正文含任务/候选/验证/复核/证据/口径声明，`report.ready` 带 html 哈希，`report.md` 仍在；② 同一批输入渲染两次字节相同，台账里的 `<script>` / `<img onerror>` 只以转义文本出现，且无外部资源特征；③ 负结果（`NO_REPRO`）在 HTML 里照样有 `未通过` 行，不出现 `confirmed` |
| API | 1 | `/casepack` 的 `report_html_sha256 == report_html_sha256_recorded == sha256(文件)`、`report_html_ok=true`；下载 `report.html` 200 且 `text/html`；任务详情同步 |
| 认证默认 | 4 | ① 远端无 token → 403（detail 含 `PLATFORM_API_TOKEN`/`Bearer`、头 `denied`），GET 200 且 `auth.write_scope=loopback`，被拒后**不建库**；② `127.0.0.1`/`::1`/`localhost` 三个回环 peer 都 201，`mode=open`/`loopback_only=true`/头 `open`+`loopback`，note 含“未设置”；③ 回环 + `X-Forwarded-For` → 403，`PLATFORM_TRUST_PROXY=1` 后 201；④ 设 token 后本机缺 token 401、远端正确 Bearer 201、错 token 403、`write_scope=token` |
| 打包门槛 | 1 | 未到 REVIEW 不能打包，盘上没有半成品 `report.html` |

验收命令（仓库根）：

```bash
python3 -m pytest tests/test_platform_v2_casepack.py -q
# 9 passed

python3 -m pytest tests/test_platform_v2*.py tests/test_platform_discovery.py -q
# 235 passed（V2 206 = P0 7 + P1 13 + P2 11 + P3 11 + P3.5 26 + P3.6 16 + P3.7 22
# + P3.8/E2E 35 + P3.9/EXEC 16 + P4 19 + P4.5 21 + P4.6 9；Discovery 29）
```

## 6. 本地验证

```bash
# 1) 生成一个带 html 的包（沿用 P4.5 的提交/准入链路）
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark target_yaml --target fixtures/discovery --task-id p46-demo
python3 bin/platform.py --db .platform/platform.db preflight p46-demo
# understand / hypotheses / plan / run / verify / review 之后：
python3 bin/platform.py --db .platform/platform.db casepack p46-demo
ls .platform/casepacks/p46-demo/report.html
sqlite3 .platform/platform.db \
  'select report_id, substr(sha256,1,12), substr(report_html_sha256,1,12) from reports;'

# 2) 写操作默认只开本机
python3 vulnmap_platform/serve.py --port 8102
curl -s -o /dev/null -w '%{http_code}\n' -XPOST localhost:8102/api/platform/tasks \
  -H 'content-type: application/json' -d '{"benchmark":"target_yaml","target":"fixtures/discovery"}'
# 201（本机）。默认只监听 127.0.0.1；用 --host 0.0.0.0 起再从他机打 → 403，
# detail 提示设置 token；同机带 X-Forwarded-For 打也一样 403

# 3) 带 token（写完就按 token 判，与地址无关）
PLATFORM_API_TOKEN=dev-token python3 vulnmap_platform/serve.py --port 8102
curl -s -o /dev/null -w '%{http_code}\n' -XPOST localhost:8102/api/platform/tasks \
  -H 'authorization: Bearer dev-token' -H 'content-type: application/json' \
  -d '{"benchmark":"target_yaml","target":"fixtures/discovery","task_id":"p46-tok"}'
# 201；不带 token → 401
```

> 注意：`vulnmap_platform/serve.py` 默认 `--host 127.0.0.1`（仅本机可连）。显式传
> `--host 0.0.0.0` 时网络层就全网可达了，此时这层限制只作用于**写操作**（GET 仍可读）；
> 对外暴露请设 token，而不是只靠回环判定。

## 7. 边界（P4.6 不做）

- 不做 PDF / 截图：网页版就是最终的“人读版”，需要 PDF 交给浏览器打印；
- 不做前端框架与图表：HTML 内零脚本，样式内联，不引入 CDN（否则哈希与离线打开都不成立）；
- 不做多用户/角色/审计主体：token 仍是单令牌开关，回环限制只是默认值；
- 不做 TLS / 反代配置：`PLATFORM_TRUST_PROXY` 只影响“回环判定”，不解析真实客户端、不做限流；
- 不改 `store.py` 与状态机：`reports` 附加列由 casepack 侧幂等补齐，`SCHEMA_VERSION=4` 不变；
- 不改 Discovery / 旧案例：本轮只动 CasePack、平台 API 与对应文档。
