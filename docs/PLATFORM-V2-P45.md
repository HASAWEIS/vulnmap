# 平台 v2 P4.5：执行作业化 + 事件推送 + 可选 token

> 范围：P4 的 `POST /tasks/{id}/run` 是 **fire-and-forget**——`Popen` 一次就把 pid 扔掉，
> 进程死没死、退出码多少、日志在哪、能不能停都没有台账；页面靠轮询事件流；写接口完全开放。
> P4.5 补三件事：执行落成 **Job**（`jobs` 表 + 进程监视 + 进程组 SIGTERM）、事件流改成
> **SSE**、写操作支持**可选 Bearer token**。边界一句话：**job 状态只是启动器视角，
> 任务状态永远以 `task_events` 事件流重放为准。** 前置见 [PLATFORM-V2-P4.md](PLATFORM-V2-P4.md)、
> [PLATFORM-V2-P36.md](PLATFORM-V2-P36.md)、[PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §3。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [vulnmap_platform/api/platform_jobs.py](../vulnmap_platform/api/platform_jobs.py) | `jobs` 表（API 侧 `CREATE TABLE IF NOT EXISTS`）+ `create_job` / `get_job` / `list_jobs` / `cancel_job`（无 TTL 回收）；`pid_alive`、watcher 线程、`_spawn_process`（可注入）、日志 tail（末 4 KB） |
| [vulnmap_platform/api/platform_auth.py](../vulnmap_platform/api/platform_auth.py) | `PLATFORM_API_TOKEN` 读法、`auth_info()`、`check_write` / `write_guard`（`hmac.compare_digest`）、`X-Platform-Auth` 响应头标注 |
| [vulnmap_platform/api/platform_tasks.py](../vulnmap_platform/api/platform_tasks.py) | `/run` 改成建 Job；新增 `/jobs`、`/jobs/{id}`、`/jobs/{id}/cancel`、`/tasks/{id}/stream`（SSE）；任务详情多 `jobs` 字段；写端点挂 `Depends(write_guard)` |
| [vulnmap_platform/static/platform-task.html](../vulnmap_platform/static/platform-task.html) | 「执行作业（Job）」面板：job_id / pid / 状态 / 退出码 / 日志 tail、触发执行、取消作业、token 输入框、实时事件列（`EventSource`） |
| [vulnmap_platform/static/platform-events.html](../vulnmap_platform/static/platform-events.html) | 事件表默认 `EventSource` 跟随 `/stream?after=`，可断开退回手动增量拉取 |
| [vulnmap_platform/static/app.js](../vulnmap_platform/static/app.js) | `platformToken()` 读 `localStorage.platform_token`；`writeJSON()` 为写请求加 `Authorization: Bearer`（无 token 则不加）；`jobBadge` / `jobLive` 状态映射；`postJSON()` 变成 `writeJSON()` 别名 |
| [vulnmap_platform/static/platform-tasks.html](../vulnmap_platform/static/platform-tasks.html) | 队列页顶部显示鉴权模式（`auth.mode`）+ token 输入框（存 `platform_token`）；提交/准入沿用原按钮 |
| [vulnmap_platform/static/style.css](../vulnmap_platform/static/style.css) | 追加 `.pf-job*`（作业面板、日志块、连接状态、token 行），既有规则不动 |
| [tests/test_platform_v2_p45.py](../tests/test_platform_v2_p45.py) | 21 项验收：作业生命周期 6、取消 3、SSE 5、认证 3、页面/路由 4 |

`agent/platform` 核心一行未改：`jobs` 表由 API 侧自建，`SCHEMA_VERSION`（`PRAGMA user_version`）仍是 4，测试钉住。

## 2. API（`/api/platform`）

数据源不变：`<PLATFORM_ROOT>/platform.db`（默认 `<repo>/.platform/platform.db`），执行日志在
`<PLATFORM_ROOT>/runs/<task_id>.log`；`PLATFORM_ROOT` 与 `PLATFORM_API_TOKEN` 每次请求重新读取。

| 方法 | 路径 | 读/写 | 行为 |
|---|---|---|---|
| `POST` | `/api/platform/tasks` | 写 | 建任务（RECEIVED）+ `task.created`；重复 `task_id` 409（P4 口径不变） |
| `POST` | `/api/platform/tasks/{id}/preflight` | 写 | 只在 `RECEIVED` 受理，→ `READY`/`BLOCKED`；非 `RECEIVED` 409 |
| `POST` | `/api/platform/tasks/{id}/run` | 写 | 只受理 `PLANNED`；建一行 `jobs` + 起子进程（独立进程组），返回 `job`，同时保留 `pid`/`log`/`state` 旧字段；同任务有活作业 409 |
| `GET` | `/api/platform/jobs?task_id=&limit=` | 读 | 作业台账：按 `created_at DESC, job_id DESC`，`limit` 默认 50、上限 200；库不存在返回空数组 |
| `GET` | `/api/platform/jobs/{id}` | 读 | 进程事实（pid/退出码/日志 tail）+ 事件流派生的 `state`，`status_source="event_stream"`；未知 job 404 |
| `POST` | `/api/platform/jobs/{id}/cancel` | 写 | 双动作：`cancel_task()` → 进程组 SIGTERM；重复取消/任务已终态 409，未知 job 404 |
| `GET` | `/api/platform/tasks/{id}/stream` | 读 | SSE（`text/event-stream`）：`after/once/timeout/max_events/poll`；未知任务 404（开流前判定） |
| `GET` | `/api/platform/tasks/{id}` | 读 | P4 全量字段 + `jobs`（最近 10 条）+ `auth` |
| `GET` | `/api/platform/tasks` | 读 | P4 行为不变，多一个 `auth` 字段（页面据此显示"本地开放 / 需要 Bearer"） |
| `GET` | `/{id}/events`、`/{id}/evidence`、`/{id}/casepack` | 读 | P4 行为完全不变（只读端点不加锁、不加鉴权） |

错误口径：未知任务/未知 job 404；`run` 非 `PLANNED`、活作业冲突、取消终态一律 409；
token 缺失 401（带 `WWW-Authenticate: Bearer realm="vulnmap-platform"`）、token 错误 403；
子进程起不来 503（同时留 `FAILED` 作业行）；库不可读 503。

### 2.1 `jobs` 表（启动器视角）

`jobs` 只记**进程事实**，不是第二套任务状态机：

| 列 | 含义 |
|---|---|
| `job_id` | `job-<12 位 hex>`，主键 |
| `task_id` | 所属任务（建索引 `idx_jobs_task(task_id, created_at)`） |
| `pid` | 子进程 pid，即进程组组长（`start_new_session=True`）；启动失败为 NULL |
| `status` | `PENDING / RUNNING / EXITED / FAILED / CANCELLED`（索引 `idx_jobs_status`） |
| `started` / `finished` | 启动 / 结束时间，本地时区 ISO8601（秒精度），未结束为空串 |
| `log` | 日志绝对路径 `<PLATFORM_ROOT>/runs/<task_id>.log` |
| `exit_code` | 退出码；进程消失但没等到退出码时为 NULL |
| `argv_json` | 实际执行的 argv（`job_dict()` 展开成 `argv` 数组） |
| `note` | 人读备注：`executor exited 7` / `cancel requested: <reason> (sent SIGTERM)` / `spawn failed: …` / `run via POST /api/platform/tasks/{id}/run` |
| `created_at` / `updated_at` | 行写入 / 最后更新时间 |

读路径用 `mode=ro` 打开（库不存在 → 404/空列表，绝不建库建表）；只有写路径（建行/取消）
才 `CREATE TABLE IF NOT EXISTS`。`job_dict()` 额外给 `log{path,exists,size,tail}`、
`alive`（`pid_alive`）、`live`（`status in (PENDING,RUNNING)`）。

### 2.2 两套状态：`status` 与 `state` 分工

| 视角 | 字段 | 判定来源 |
|---|---|---|
| 启动器 | `status` | `pid` 活着 = `RUNNING`；进程退出按退出码 `EXITED(0)` / `FAILED(非 0)`；取消 = `CANCELLED` |
| 运行时 | `state` | `EventBus.replay(task_id)`——`task_events` 唯一裁判 |

`GET /jobs/{id}` 同时给两者，并回答两个不同的问题：`finished`（任务到终态，`state in TERMINAL`）
与 `job_finished`（进程侧结束，`status in (EXITED,FAILED,CANCELLED)`）。watcher 线程只在作业仍处于
`LIVE_STATES` 时回写退出码，已 `CANCELLED` 的行不被改写。读端点不写库，因此 GET 依旧不改状态；
作业行不做 TTL 回收（见 §6），历史都在 `jobs` 表里。

### 2.3 取消是双动作

~~~text
cancel_task()                      # agent/platform/lifecycle.py
  task.cancel_requested {from, reason, actor, usage}
  cancel_snapshot  → 证据库（canonical JSON + sha256）
  state.changed → CANCELLED（terminal_reason = "cancelled: <reason>"）
  task.cancelled   {from, reason, actor, evidence_sha256}
        ↓  之后才动进程：os.killpg(pgid, SIGTERM)（pgid 取不到退回 os.kill(pid)）
jobs.status = CANCELLED（note 记 reason 与 signal）
~~~

- 顺序固定：**事件流先落痕，再打进程**；进程收到 SIGTERM 后自行退出，watcher 不回写；
- 进程已结束（`EXITED`/`FAILED`）但任务还在非终态：仍然受理，只取消任务状态，
  `job_cancelled=false`，作业行保留进程事实（不把历史改写成 `CANCELLED`）；
- 重复取消：job 已终态或任务已终态一律 409，`detail` 指出是哪个终态。

### 2.4 SSE 帧序

~~~text
retry: 1000
event: hello        {task_id, state, after, events, timeout, once, auth}
event: task_event   id: <seq>   data: <事件行>
event: state        {state, terminal, terminal_reason, events, jobs[≤5], status}
event: ping         {after, ts}            # 每 50 tick
event: end          {reason: terminal|once|max_events|timeout|db missing}
~~~

参数：`after`（seq 游标，续传）、`once=1`（单趟，便于脚本与测试）、`timeout`（默认 300 s，
上限 3600，`0` = 不设上限）、`max_events`（上限 5000，0 = 不限）、`poll`（0.05–5 s，默认 0.2）。
响应头：`Cache-Control: no-cache, no-transform`、`Connection: keep-alive`、
`X-Accel-Buffering: no`、`X-Platform-Auth`。

### 2.5 可选 token

> **P4.6 已收口默认值**：`PLATFORM_API_TOKEN` 未设置时，写操作只受理本机回环
> （`127.0.0.1` / `::1` / `localhost`），远端一律 403 并提示设置 token；带转发头的
> 回环也按远端处理（除非 `PLATFORM_TRUST_PROXY=1`）。设置 token 后的口径不变。
> 详见 [PLATFORM-V2-CASEPACK.md](PLATFORM-V2-CASEPACK.md) §4。下表“本地开放”指的是
> **本机回环开放**。

| 情形 | 写操作 | 响应标注 |
|---|---|---|
| `PLATFORM_API_TOKEN` 未设置 | 本机回环受理（远端 403，见 P4.6） | `auth.mode="open"`、`token_required=false`、`write_scope="loopback"`、HTTP 头 `X-Platform-Auth: open` |
| 已设置 + `Authorization: Bearer <token>` 正确 | 受理 | `auth.mode="bearer"`、`token_required=true`、`X-Platform-Auth: bearer` |
| 已设置 + 无/错 scheme 头 | 401 + `WWW-Authenticate: Bearer` | — |
| 已设置 + token 不匹配 | 403 | — |

受管写操作：提交任务、preflight、run、cancel；**GET 一律开放**（读端点不改状态）。
token 每请求重读环境变量（无模块级缓存），比较用 `hmac.compare_digest`，任何响应都不回显 token。

## 3. 页面

页面仍是只读消费者，只有按钮打 API；新增的动作都走 `writeJSON()`（带 Bearer）：

| 页面 | 改动 |
|---|---|
| `platform-task.html` | 新增「执行作业（Job）」面板：job_id / pid / `status` / `exit_code` / 日志 tail（末 4 KB）+ 「最近作业」切换（`?job_id=`）+ 触发执行 + 取消作业；右侧实时事件列由 `EventSource('/api/platform/tasks/<id>/stream?after=<seq>')` 填充，切换任务/终态时 `es.close()`；顶部 token 输入框（存 `platform_token`） |
| `platform-events.html` | 默认开 `EventSource` 跟随 `/stream?after=`，可关闭后退回 `GET /events?after=` 手动增量拉取 |
| `platform-tasks.html` | 列表顶部显示鉴权模式（`auth.mode`）+ token 输入框（存 `platform_token`）；写入口仍是提交/准入，`postJSON()` 现在只是 `writeJSON()` 的别名，因此同样带 Bearer |
| `app.js` | `platformToken()` 读 `localStorage.platform_token`；`writeJSON(path, body)` 有 token 就加 `Authorization: Bearer`；`postJSON()` 改为 `writeJSON()` 的别名（旧调用点零改动就带上鉴权） |

页面不碰 SQLite、不出现 `DELETE/PUT/PATCH`，除提交页外不出现 `postJSON(`——P4 的三条只读硬约束继续有效。

## 4. 测试

`tests/test_platform_v2_p45.py`（21 项，`TestClient` + 每个用例独立临时 `PLATFORM_ROOT`）：执行器
命令被换成本机 `python -c` 小脚本（长睡 / 退出 0 / 退出 7），但 spawn、pid、退出码、SIGTERM 都是真的。

| 组 | 项 | 断言 |
|---|---|---|
| 作业生命周期 | 6 | ① `run` 建 `jobs` 行（需求点名的五列 + log 齐全）、pid>0、`status=RUNNING`、日志在 `runs/<task_id>.log`、触发本身不改任务状态（`state=PLANNED`）；② 非 `PLANNED` 409 + 活作业再 run 409（`detail` 指出是哪条活作业）；③ 退出 0 → `EXITED`/`exit_code=0`/`finished`/`alive=false`，退出 7 → `FAILED`/`exit_code=7`/`note` 含 `exited 7`；④ 日志 tail 可见（`exists`/`size`/含输出）；⑤ 进程 `EXITED` 而事件流已推进到 `RUNNING` → `status=EXITED`、`state=RUNNING`、`finished=false`、`job_finished=true`、`status_source=event_stream`；⑥ 读 job 端点不建库、有库时 `PRAGMA user_version` 仍为 4 且 `PlatformStore` 正常打开 |
| 取消 | 3 | ① 活作业取消：任务落 `CANCELLED`、`signal=SIGTERM`、作业 `CANCELLED`、事件序 `task.cancel_requested → state.changed(CANCELLED) → task.cancelled`、pid 真消失、0.3 s 后 status 不被 watcher 改写；② 进程已结束的作业：`job_cancelled=false`、`status=EXITED`、`state=CANCELLED`；③ 未知 job 404、任务终态后再取消 409 |
| SSE | 5 | ① 首帧 `retry: 1000` → `hello` → `task_event`（`id` 与事件 seq 一一对应）→ `state` → `end(reason=once)`，且 `state` 帧带作业摘要；② `after=last` 空且 `emitted=0`，`after=last-1` 只回最后一条；③ 终态任务 `end(reason=terminal, state=CANCELLED)`，`state.terminal=true`；④ `max_events=2` 截断 `reason=max_events`、`timeout=0.3` 到期 `reason=timeout`、未知任务 404；⑤ 响应头 `no-cache` / `X-Accel-Buffering: no` / `X-Platform-Auth: open` |
| 认证 | 3 | ① 无 token：提交/preflight/run/cancel 全 200 且 `auth.mode=open`、头 `X-Platform-Auth: open`；② 设 token 后：缺失 401（`WWW-Authenticate` 以 `bearer` 开头、`detail` 含 `PLATFORM_API_TOKEN`）、错误 403、`Basic` scheme 401、正确 201/200 且 `mode=bearer`，GET 与 `/stream` 仍 200；③ token 每请求重读（设 → 401，删 → 201） |
| 页面/路由 | 4 | ① `platform-task.html` / `platform-events.html` 含 `EventSource(` 与 `/stream`，页面 200 且带 `app.js`/`style.css`，任务页读 `/api/platform/jobs/` 并有 `close()`，事件页保留 `after=`；② 五页仍无 `sqlite`/`DELETE`/`PUT`/`PATCH`，非提交页无 `postJSON(`，`app.js` 有 `writeJSON`/`platform_token`/`Bearer`；③ 四条新路由已注册；④ `/jobs` 空台账返回 `count=0`、`auth.mode=open`、`note` 说明事件流为准 |

验收命令（仓库根）：

```bash
python3 -m pytest tests/test_platform_v2_p45.py -q
# 21 passed

python3 -m pytest tests/test_platform_v2*.py tests/test_platform_discovery.py -q
# 175 passed（V2 146 = P0 7 + P1 13 + P2 11 + P3 11 + P3.5 26 + P3.6 16 + P3.7 22
# + P4 19 + P4.5 21；Discovery 29）
```

## 5. 本地起服务

```bash
# 本地开放（只适合回环）：写操作不鉴权，响应里 auth.mode=open
python3 vulnmap_platform/serve.py --port 8102
# 带 token：写操作必须 Bearer，GET 仍开放
PLATFORM_API_TOKEN=dev-token python3 vulnmap_platform/serve.py --port 8102

# 提交 → 准入 → 推到 PLANNED（CLI 或 API 均可）
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark target_yaml --target fixtures/discovery --task-id p45-demo
python3 bin/platform.py --db .platform/platform.db preflight p45-demo
# understand / hypotheses / plan 之后任务到 PLANNED

# 触发执行（返回 job；设置了 token 就带 Bearer），然后查作业 / 取消 / 看单趟推送
curl -s -XPOST localhost:8102/api/platform/tasks/p45-demo/run -H 'content-type: application/json' -d '{}'
curl -s "localhost:8102/api/platform/jobs?task_id=p45-demo"
curl -s localhost:8102/api/platform/jobs/JOB_ID          # status/exit_code/log.tail/state
curl -s -XPOST localhost:8102/api/platform/jobs/JOB_ID/cancel -d '{"reason":"operator stop"}'
curl -sN "localhost:8102/api/platform/tasks/p45-demo/stream?after=0&once=1"
```

页面入口：`/platform-tasks.html` → 任务详情 → 「执行作业（Job）」面板；`after` 游标与作业
状态都显示在面板顶部。

## 6. 边界（P4.5 不做）

- 不做多用户/角色：token 是单令牌开关，不区分身份与权限，也没有审计主体；
- 不做 WebSocket：推送只有 SSE 单向流，页面不向服务端发消息；
- 不做作业重试与队列调度：一个任务同时只允许一条活作业（再 run 409），没有排队、优先级、重试与超时回收；
- 不把 job 状态当任务状态：`jobs.status` 只描述进程，任务状态仍由 `task_events` 重放，
  两者不一致时以 `state` 为准（响应里 `status_source="event_stream"`）；
- 不改 `agent/platform` 核心：`jobs` 表由 API 侧 `CREATE TABLE IF NOT EXISTS` 自建，
  `SCHEMA_VERSION` / `PRAGMA user_version` 仍是 4；
- 不自动清理 jobs 行：没有 TTL 回收、归档与分页游标，`jobs` 表只按
  `created_at DESC` 取最近 N 条；也没有"pid 已死却仍挂 RUNNING"行的自动对账（状态按
  watcher 与取消动作落定，读端点不改状态）；
- 不做进程强杀升级：取消只发 SIGTERM 给进程组，不追加 SIGKILL 循环；
- 术语分层不可互换：`jobs.status`（进程）与 `state`（`task_events` 重放）是两个层级，
  作业到终态不等于任务到终态，任务到终态也不代表进程一定已经退出。
