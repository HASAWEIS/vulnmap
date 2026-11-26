# DEPLOY-8102：本地平台后端（127.0.0.1:8102）

本文档对应 2026-11-18 的「恢复 8102」任务：用 `setsid`/`nohup` 把平台后端拉起来，
默认数据源仍是 `.platform/platform.db`，并提供可重复执行的启停脚本。

- 入口脚本：[`scripts/serve-platform.sh`](../scripts/serve-platform.sh)
- 只涉及运行方式，**没有改动任何业务代码**（`vulnmap_platform/` 下文件未动）
- 只有 `scripts/serve-platform.sh`（新增）与本文档是本次产物

## 1. 现状（验收记录）

| 项 | 值 |
| --- | --- |
| 监听 | `127.0.0.1:8102`（仅本机回环） |
| 启动方式 | `setsid nohup python3 -m uvicorn vulnmap_platform.api.app:app --host 127.0.0.1 --port 8102` |
| ASGI 应用 | `vulnmap_platform.api.app:app` |
| DB | 默认 `<repo>/.platform/platform.db`（库不存在时列表接口返回 `exists=false`，不建库） |
| PID / 日志 | `.platform/run/serve-8102.pid` / `.platform/run/serve-8102.log` |
| 启动前端口 | 空闲（`ss -ltnp` 无 8102 监听） |

启动后实测三个端点均 200：

```text
/api/health          -> 200  {"ok":true,"workspace":".../workspace","cases":61}
/index.html          -> 200  (13.7 KB, Benchmark 通过率页)
/api/platform/tasks  -> 200  {"root":".../.platform","db":".../.platform/platform.db","exists":false,...}
```

## 2. 依赖

- `python3`（本机 3.12）
- `fastapi`、`uvicorn`（已装在当前 python3 环境中，无需 venv）
- `curl`、`ss`、`setsid`、`nohup`（系统自带）

确认依赖：

```bash
python3 -c "import fastapi, uvicorn; print(fastapi.__version__, uvicorn.__version__)"
```

当前 PATH 上的 `python3` 解析为 `/home/root_bupt/binsight-next/BinSight/.venv/bin/python3`（3.12.14，
fastapi 0.141.1 / uvicorn 0.52.4）。要固定到别的解释器：`PYTHON=/usr/bin/python3 ./scripts/serve-platform.sh start`。
脚本不会自动建 venv，也不会装依赖。

## 3. 用法

```bash
cd /home/root_bupt/桌面/file/vulnmap

./scripts/serve-platform.sh start     # 后台启动，等到 /api/health 200 才返回（默认最多 20s）
./scripts/serve-platform.sh status    # PID / 端口占用 / health / 日志路径
./scripts/serve-platform.sh stop      # 按 PID 文件 SIGTERM，最多等 10s
./scripts/serve-platform.sh restart   # stop + start
```

`start` 成功时会打印就绪日志：

```text
[serve-platform] PLATFORM_ROOT 未设置，使用默认 db=/home/root_bupt/桌面/file/vulnmap/.platform/platform.db
[serve-platform] 已启动：pid=<PID> log=.../.platform/run/serve-8102.log
[serve-platform] 就绪：http://127.0.0.1:8102/api/health 200（2s）
```

### 可配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `8102` | 监听端口；换端口即换 PID/日志文件名 |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PLATFORM_ROOT` | 空（= `<repo>/.platform`） | `platform.db` 所在目录；设置后透传给服务，db 为 `$PLATFORM_ROOT/platform.db` |
| `PYTHON` | `python3` | 解释器 |
| `WAIT` | `20` | `start` 等待 health 就绪的秒数 |
| `SERVE_STATE_DIR` | `<repo>/.platform/run` | PID/日志落盘目录 |
| `LOG_LEVEL` | `info` | uvicorn 日志级别 |
| `FORCE` | `0` | `stop` 时 SIGTERM 超时后是否 SIGKILL |

示例：

```bash
PORT=8103 ./scripts/serve-platform.sh start          # 换端口
PLATFORM_ROOT=/tmp/vm-platform PORT=8103 ./scripts/serve-platform.sh start   # 换库 + 换端口
FORCE=1 ./scripts/serve-platform.sh stop             # 卡死不退时强杀（只杀自己 PID 文件里的进程）
```

## 4. 验证

```bash
for u in /api/health /index.html /api/platform/tasks; do
  printf '%s -> %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8102$u")"
done
```

期望三行都是 `200`。参考响应语义：

- `/api/health`：`{"ok":true,"workspace":"<repo>/workspace","cases":<n>}`
- `/index.html`：静态首页（`vulnmap_platform/static/`，`no-store` 不缓存）
- `/api/platform/tasks`：任务列表；`exists=false` 表示 `.platform/platform.db` 还没建过，
  这是正常状态（只读视图不建库），不是故障

本次测试的完整闭环（脚本启动 → curl → 停止）已执行通过：

```text
start  -> 就绪（health 200）
curl   -> /api/health 200, /index.html 200, /api/platform/tasks 200
stop   -> 已停止，8102 释放
```

## 5. 端口被占时

`start` 会先探测端口；若被别的进程占用，**只报告、不处理、不杀任何无关服务**，退出码 `75`：

```text
[serve-platform] 端口 8113 被占用：pid=207270 cmd=python3
 207270  00:11  .../python3 -m http.server 8113 --bind 127.0.0.1
[serve-platform] 端口 8113 已被占用，未做任何处理（不杀无关服务）。
```

处理顺序：

1. `./scripts/serve-platform.sh status` 看是否是自己脚本的实例（有 PID 文件就是自己的，直接 `stop`）
2. 不是自己的 → 先确认那个进程是什么（`ps -o pid,lstart,cmd -p <PID>`），由人决定是否停
3. 只是要临时起一份 → 换端口：`PORT=8103 ./scripts/serve-platform.sh start`

## 6. 故障排查

| 现象 | 处理 |
| --- | --- |
| `启动失败：进程已退出` | 看 `.platform/run/serve-8102.log` 尾部，多为依赖缺失或端口争用 |
| `启动超时：20s 内 health 未就绪` | 加 `WAIT=40` 重试；同时看日志是否有 traceback |
| `status` 显示 `health=DOWN` 但 PID 在 | 等 1–2s 再查；仍在则 `restart` |
| 陈旧 PID 文件 | `start` 会自动识别已死 PID 并清理；也可手动 `rm .platform/run/serve-8102.pid` |
| `stop` 后端口仍被监听 | 说明监听者不是 PID 文件里的进程，按第 5 节重新确认来源 |
| `/api/platform/tasks` 返回 `exists=false` | 尚未生成 `.platform/platform.db`，属正常；需要真实任务时按平台流程建库 |
| `PLATFORM_ROOT` 目录不存在 | 服务启动时不会建库；目录由平台写库流程创建，必要时 `mkdir -p` |

## 7. 运行时文件与回滚

运行期只产生这些文件，全部在版本库之外的目标位置，删掉即干净：

```text
.platform/run/serve-8102.pid     # 进程号
.platform/run/serve-8102.log     # uvicorn 访问/错误日志（每次 start 清空重写）
```

彻底回到「没起过」的状态：

```bash
./scripts/serve-platform.sh stop
rm -rf .platform/run
```

本次任务**未**执行任何写库动作，也**未**改业务代码，因此不存在需要回滚的代码变更。
