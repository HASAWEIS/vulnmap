# 真实 runner 阻塞盘点（2026-11-18）

> 目标：把"能不能真的跑起来"从推测变成实测——镜像、网络、基础镜像、`smoke` 四件事各给一次真实探测，
> 能拉的拉下来并配好 `smoke`，拉不到的写进缺失清单。**本轮只写 `docs/`**，未改业务代码、未改任何
> `workspace/*/task.json`、未 git commit。
> 结论先行：**docker.io 不可达，但镜像站可拉；CG-01 的 vul 镜像已落地且 digest 与历史证据逐位一致；
> `smoke` 在补上 `cmd`/`input_path` 后能 ready；真跑仍被两条硬阻塞卡住（`--read-only` 与 `/input` 挂载约定）。**

## 0. 结论摘要

| # | 探测项 | 实测结果 | 判定 |
|---|---|---|---|
| 1 | docker daemon | `29.7.2`，overlayfs，kernel `6.8.0-149`，20 CPU / 30.8 GiB | ✅ 可用 |
| 2 | `docker pull arvo/cybergym`（docker.io） | `dial tcp 31.13.73.9:443: i/o timeout`（DNS 解析到非 Docker 网段） | ❌ **blocked** |
| 3 | 控制组 `docker pull hello-world` | `dial tcp [2a03:2880:f130:83:face:b00c:0:25de]:443: i/o timeout` | ❌ 说明**不是** arvo 特例，是 Docker Hub 整体不可达 |
| 4 | 镜像站 `docker.1panel.live` | manifest `200`；blob 拉取 `timeout awaiting response headers`，两次整镜像拉取均在 blob 阶段失败 | ⚠️ 只可读 manifest，整镜像不可用 |
| 5 | 镜像站 `dockerproxy.net` | manifest `200`、blob `200`（44.2 MB / 34.5 MB 完整返回） | ✅ **可用**（本轮即用它） |
| 6 | 镜像站 `docker.m.daocloud.io` | `/v2/` → `401 UNAUTHORIZED`（需认证） | ⚠️ 未使用 |
| 7 | `python:3.12-slim`（`agent/sandbox.py:SANDBOX_IMAGE`） | 本地已存在 `sha256:5e2bdb1b0d54…`，`docker run` 打印 `python 3.12.16 ok` | ✅ 可用 |
| 8 | `bwrap`（discovery isolation） | `/usr/bin/bwrap` 存在 | ✅ 可用 |
| 9 | `n132/arvo:44034-vul` | 经 `dockerproxy.net` 拉到，`sha256:e57980e7ebcd…` = `case.json.images.*` 记录值 | ✅ **traceable** |
| 10 | `n132/arvo:44034-fix` | 35/37 blob 已下载、6/37 层已解压后**停滞**（22:42 后再无输出，重试被中断） | ⚠️ **部分完成**（可续传） |
| 11 | `bin/platform.py smoke`（仓库现状） | 3/3 `needs_evidence`，`persisted=false` | ⚠️ 如实报缺口 |
| 12 | `smoke --execute`（配置后） | 见 §4：**`--read-only` 使 CG-01 不复现**（假阴性） | ❌ **blocked（runner 硬化参数）** |

## 1. 环境探测（原始证据）

### 1.1 docker daemon 与基础镜像

```text
$ docker version
 Client: 29.7.2 (API 1.55)
 Server: 29.7.2, containerd v2.3.3
$ docker info | grep -E "Storage Driver|Kernel|CPUs|Total Memory"
 Storage Driver: overlayfs
 Kernel Version: 6.8.0-149-generic
 CPUs: 20
 Total Memory: 30.8GiB

$ docker image inspect python:3.12-slim --format '{{.Id}} {{.Created}}'
sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b 2026-11-05T08:00:30Z

$ docker run --rm --network none python:3.12-slim python -c "import sys;print('python',sys.version.split()[0],'ok')"
python 3.12.16 ok
exit=0
```

`python:3.12-slim` 是 `agent/sandbox.py` 的 `SANDBOX_IMAGE`（封存隔离容器），**已就位且可执行**，不需要重拉。

### 1.2 Docker Hub 不可达（两条独立证据）

```text
$ docker pull arvo/cybergym
Error response from daemon: failed to resolve reference "docker.io/arvo/cybergym:latest":
  failed to do request: Head "https://registry-1.docker.io/v2/arvo/cybergym/manifests/latest":
  dial tcp 31.13.73.9:443: i/o timeout

$ docker pull hello-world
Error response from daemon: ... Head "https://registry-1.docker.io/v2/library/hello-world/manifests/latest":
  dial tcp [2a03:2880:f130:83:face:b00c:0:25de]:443: i/o timeout
```

两条错误里的 IP（`31.13.73.9`、`2a03:2880:f130:83:…`）都不是 Docker Hub 的地址段，属解析被污染后连到不可达主机。
`getent hosts registry-1.docker.io` 也只返回 `2001::9df0:1032`（IPv6），`curl -4` 无响应 —— **IPv4/IPv6 双路都不通**。

### 1.3 镜像站探测（`/v2/` 与 manifest 级）

```text
registry-1.docker.io     超时（无响应）
docker.1panel.live       200 0.55s      ← /v2/ 通
dockerproxy.net          200 0.97s      ← /v2/ 通
hub.rat.dev              302 0.45s
docker.m.daocloud.io     401 0.14s（需 auth）
docker.xuanyuan.me       401 1.34s（需 auth）

# manifest 级（n132/arvo:44034-vul）
docker.1panel.live   200  （config 20537B / 35 layers）
dockerproxy.net      200  （同上）
docker.m.daocloud.io 401
```

**但 manifest 通 ≠ 镜像能拉**：`docker.1panel.live` 两次整镜像拉取都在 blob 阶段 `timeout awaiting response headers`
（`sha256:034e6697…` 44.2 MB、`sha256:c949c6f1…` 34.5 MB），换 `dockerproxy.net` 后同样的 blob 一次成功。

## 2. 拉取（本轮真正落地的部分）

```bash
# 1panel 失败后改用 dockerproxy.net；拉下来再打回原 tag，避免改 daemon.json / 重启 docker
docker pull dockerproxy.net/n132/arvo:44034-vul
docker tag  dockerproxy.net/n132/arvo:44034-vul n132/arvo:44034-vul
```

```text
$ docker image inspect n132/arvo:44034-vul --format '{{.Id}} {{.Created}} {{.Size}}'
sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef 2024-05-01T01:24:51Z 1338604461

$ python3 -c "import json;print(json.load(open('workspace/CG-01-arvo-44034/artifacts/report/case.json'))['images'])"
{'recon':  ['sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef'], …}
```

**镜像 digest 与历史证据逐位一致**（`e57980e7ebcd…`），说明镜像站分发的是同一份字节，不是重新构建的近似品 ——
这一步同时验证了"历史结论不是靠一个来历不明的镜像跑出来的"。

PoC 也做了同样的核对：

```text
$ sha256sum workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin
58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d
# = case.json.poc.sha256
```

### 2.1 fix 侧镜像：部分完成（停滞证据）

`n132/arvo:44034-fix`（37 层 / 1395.6 MB）没有拉完，状态如实记录：

```text
22:42:30  /tmp/pull-fix.log 最后一次写入（此后 16 分钟无任何输出）
           Download complete: 35/37    Pull complete: 6/37
22:58:29  docker system df → Images 72.07GB（只有 vul 的 4.52GB 增量，fix 未落盘）
23:00     一次重试（timeout 420）在解压阶段被中断
```

判定：**这是"镜像站大 blob 读超时 + 解压慢"的传输问题，不是仓库侧问题**；
已下载的 35 个 blob 留在 docker 缓存里，再次执行同一 `docker pull` 会从断点续传（`Already exists`）。
`smoke` 的 CG-01 因此仍停在 `image_not_found:n132/arvo:44034-fix` —— 这一条**不掩盖**。

## 3. 镜像清单：42 个 CyberGym 案例要 84 个 tag，当前只到位 1 个（vul 侧）

`workspace/*/task.json` 共 61 个，其中 CyberGym 42 个案例各需 `-vul` / `-fix` 两个镜像，ExploitGym 1 个只需 vul 侧，
VulnGym 不用镜像（HTTP 服务）。去重后 **85 个镜像引用**：

| 类别 | 数量 | 当前状态 |
|---|---|---|
| `n132/arvo:<id>-vul` | 42 | 1 个就位（`44034-vul`） |
| `n132/arvo:<id>-fix` | 42 | 0 个完整就位（`44034-fix` 部分下载，见 §2.1） |
| `cybergym/arvo:44034-vul.exp.none-nogit`（EG-02） | 1 | 缺（EG 侧还需官方 socat socket） |
| VulnGym（`vulngym/nltk/40d0bc1d`） | 0 | 不用镜像，需要 `baseline_url`/`patched_url` |

按案例列出（`task.json` 里声明的镜像名，全部缺失，除 `44034-vul`）：

| 案例 | task_id | image_vul | image_fix |
|---|---|---|---|
| CG-01 | `arvo:44034` | `n132/arvo:44034-vul` ✅ 已就位 | `n132/arvo:44034-fix` |
| CG-02 | `arvo:47101` | `n132/arvo:47101-vul` | `n132/arvo:47101-fix` |
| CG-04 | `arvo:10400` | `n132/arvo:10400-vul` | `n132/arvo:10400-fix` |
| CG-06 | `arvo:3938` | `n132/arvo:3938-vul` | `n132/arvo:3938-fix` |
| CG-07 | `arvo:10096` | `n132/arvo:10096-vul` | `n132/arvo:10096-fix` |
| CG-08 | `arvo:10147` | `n132/arvo:10147-vul` | `n132/arvo:10147-fix` |
| CG-09 | `arvo:53666` | `n132/arvo:53666-vul` | `n132/arvo:53666-fix` |
| CG-10 | `arvo:54625` | `n132/arvo:54625-vul` | `n132/arvo:54625-fix` |
| CG-11 | `arvo:12466` | `n132/arvo:12466-vul` | `n132/arvo:12466-fix` |
| CG-12 | `arvo:11081` | `n132/arvo:11081-vul` | `n132/arvo:11081-fix` |
| CG-13 | `arvo:47947` | `n132/arvo:47947-vul` | `n132/arvo:47947-fix` |
| CG-14 | `arvo:11253` | `n132/arvo:11253-vul` | `n132/arvo:11253-fix` |
| CG-15 | `arvo:3940` | `n132/arvo:3940-vul` | `n132/arvo:3940-fix` |
| EG-02 | `user:cybergym/arvo_44034` | `cybergym/arvo:44034-vul.exp.none-nogit` | —（EG 无 fix 侧） |
| VG-01 | `vulngym/nltk/40d0bc1d` | — | — |
| S7-CG16 | `arvo:368` | `n132/arvo:368-vul` | `n132/arvo:368-fix` |
| S7-CG17 | `arvo:1065` | `n132/arvo:1065-vul` | `n132/arvo:1065-fix` |
| S7-CG18 | `arvo:12420` | `n132/arvo:12420-vul` | `n132/arvo:12420-fix` |
| S8-CG19 | `arvo:10055` | `n132/arvo:10055-vul` | `n132/arvo:10055-fix` |
| S8-CG20 | `arvo:10306` | `n132/arvo:10306-vul` | `n132/arvo:10306-fix` |
| S9-CG21 | `arvo:10710` | `n132/arvo:10710-vul` | `n132/arvo:10710-fix` |
| S10-CG22 | `arvo:10486` | `n132/arvo:10486-vul` | `n132/arvo:10486-fix` |
| S10-CG23 | `arvo:10653` | `n132/arvo:10653-vul` | `n132/arvo:10653-fix` |
| S11-CG24 | `arvo:10252` | `n132/arvo:10252-vul` | `n132/arvo:10252-fix` |
| S12-CG25 | `arvo:14821` | `n132/arvo:14821-vul` | `n132/arvo:14821-fix` |
| S12-CG26 | `arvo:19414` | `n132/arvo:19414-vul` | `n132/arvo:19414-fix` |
| S13-CG27 | `arvo:12818` | `n132/arvo:12818-vul` | `n132/arvo:12818-fix` |
| S13-CG28 | `arvo:16445` | `n132/arvo:16445-vul` | `n132/arvo:16445-fix` |
| S14-CG29 | `arvo:11011` | `n132/arvo:11011-vul` | `n132/arvo:11011-fix` |
| S15-CG30 | `arvo:29633` | `n132/arvo:29633-vul` | `n132/arvo:29633-fix` |
| S16-CG31 | `arvo:61675` | `n132/arvo:61675-vul` | `n132/arvo:61675-fix` |
| S16-CG32 | `arvo:58262` | `n132/arvo:58262-vul` | `n132/arvo:58262-fix` |
| S17-CG33 | `arvo:60983` | `n132/arvo:60983-vul` | `n132/arvo:60983-fix` |
| S18-CG34 | `arvo:49259` | `n132/arvo:49259-vul` | `n132/arvo:49259-fix` |
| S19-CG35 | `arvo:49613` | `n132/arvo:49613-vul` | `n132/arvo:49613-fix` |
| S19-CG36 | `arvo:54839` | `n132/arvo:54839-vul` | `n132/arvo:54839-fix` |
| S20-CG37 | `arvo:59500` | `n132/arvo:59500-vul` | `n132/arvo:59500-fix` |
| S20-CG38 | `arvo:52465` | `n132/arvo:52465-vul` | `n132/arvo:52465-fix` |
| S21-CG39 | `arvo:58405` | `n132/arvo:58405-vul` | `n132/arvo:58405-fix` |
| S22-BLIND | `arvo:10013` | `n132/arvo:10013-vul` | `n132/arvo:10013-fix` |
| S24-*（2 个目录） | `arvo:59884` | `n132/arvo:59884-vul` | `n132/arvo:59884-fix` |
| S25-BLIND | `arvo:10341` | `n132/arvo:10341-vul` | `n132/arvo:10341-fix` |
| S26/S27-BLIND | `arvo:10841` | `n132/arvo:10841-vul` | `n132/arvo:10841-fix` |
| S28–S32-BLIND（5 个目录） | `arvo:10628` | `n132/arvo:10628-vul` | `n132/arvo:10628-fix` |

> 单个镜像约 **1.34 GB**（`docker images` 显示磁盘 4.52 GB / 内容 1.34 GB），42 组 ≈ **112 GB**。
> 本机 `/` 可用 489 GB（拉完 vul+fix 后），**磁盘够，瓶颈只在带宽**：`dockerproxy.net` 实测约 20 分钟/镜像（USD 千兆级线路，抖动大）。
> 因此本轮只拉了 `44034` 这一组做端到端验证，其余 41 组未拉 —— 这是**带宽预算决定，不是不可拉**。

## 4. `smoke`：仓库现状 vs 配置后

### 4.1 仓库现状（未改任何文件）

```bash
python3 bin/platform.py smoke
```

```json
{"summary": {"needs_evidence": 3}, "persisted": false}
CG-01 cybergym   needs_evidence | missing: ["cmd"]                  | blockers: ["runner_not_configured:cmd","image_not_found:n132/arvo:44034-vul","image_not_found:n132/arvo:44034-fix"]
EG-02 exploitgym needs_evidence | missing: ["mode","exploit_target"]| blockers: ["runner_not_configured:mode","runner_not_configured:exploit_target"]
VG-01 vulngym    needs_evidence | missing: ["baseline_url","patched_url"] | blockers: ["runner_not_configured:baseline_url,patched_url"]
```

三项都如实报缺口（`persisted=false`，没有把缺口写成负结果）——这一行为符合 `agent/platform/runners/spec.py` 的设计。

### 4.2 配置后的 smoke（不改仓库业务文件的做法）

`smoke` 只从 `<workspace>/task.json` 读 spec，而仓库里的 `task.json` 缺 `harness_cmd` / `input_path`。
为把"能跑"验证到底又不改业务数据，本轮在 `/tmp` 造了一份**同构工作区**（`/tmp/smoke-ws`），只补两个字段：

```json
{"case_id":"CG-01","task_id":"arvo:44034","benchmark":"cybergym",
 "image_vul":"n132/arvo:44034-vul","image_fix":"n132/arvo:44034-fix",
 "harness_cmd":["/out/gstoraster_fuzzer","/input"],
 "input_path":"/home/root_bupt/桌面/file/vulnmap/workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin"}
```

```bash
python3 bin/platform.py smoke CG-01 --workspace-root /tmp/smoke-ws --workdir /tmp/smoke-run
# → spec 完整：{"image_vul":…,"image_fix":…,"cmd":["/out/gstoraster_fuzzer","/input"],"input_path":…}
# → 唯一的 blocker 变成镜像缺失（vul 到位后只剩 fix 侧）
```

`harness_cmd` 为什么是 `/out/gstoraster_fuzzer /input` 而不是镜像自带的 `/bin/arvo`：

```text
$ docker run --rm --entrypoint cat n132/arvo:44034-vul /bin/arvo | sed -n '15,30p'
if [ "$#" -ge 1 ]; then
    first_param="$1"
    if [ "$first_param" = "compile" ]; then compile
    elif [ "$first_param" = "run" ]; then /out/gstoraster_fuzzer /tmp/poc
    else echo "Unknown command: $first_param"
else
    /out/gstoraster_fuzzer /tmp/poc
fi
```

`/bin/arvo` 把输入路径写死成 `/tmp/poc`，而 `CyberGymRunner` 的挂载约定是 `-v <input>:/input:ro`（见
`agent/platform/runners/cybergym.py` 的 `argv += ["-v", f"{input_path}:/input:ro"]`）。**两者不兼容**，
所以 runner 侧正确的 `cmd` 必须直接调 fuzzer 并指向 `/input`。

## 5. 真跑结果与**两条硬阻塞**

### 5.1 阻塞 A：`--read-only` 让 CG-01 不复现（假阴性）

`CyberGymRunner.DOCKER_FLAGS` 硬编码了 `--read-only`。用同一镜像、同一 PoC、按 runner 的硬化参数跑：

```bash
POC=$PWD/workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin

# ① 历史命令（无硬化）
docker run --rm -v $POC:/tmp/poc:ro -e ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
  n132/arvo:44034-vul /bin/arvo
#   → AddressSanitizer: stack-buffer-overflow WRITE of size 4096 @ pdf_font.c:332 … ==7==ABORTING
#   → exit 1  ✅ 与 logs/V4.pdf-basefont4096.44034-vul.log 一致

# ② 只加 --read-only
docker run --rm --read-only -v $POC:/tmp/poc:ro n132/arvo:44034-vul /bin/arvo
#   → gsapi_init_with_args: error -9
#   → exit 0  ❌ 崩溃消失
```

逐参数二分（同一 PoC、同一镜像，只看是否出现 `AddressSanitizer`）：

| 附加参数 | 结果 |
|---|---|
| （无） | ✅ CRASH exit=1 |
| `--read-only` | ❌ no-crash exit=0（`gsapi_init_with_args: error -9`） |
| `--network none` | ✅ CRASH exit=1 |
| `--tmpfs /tmp:rw,exec,nosuid,nodev` | ✅ CRASH exit=1 |
| `--memory 2g` | ✅ CRASH exit=1 |
| `--cap-drop ALL` | ✅ CRASH exit=1 |
| `--security-opt no-new-privileges` | ✅ CRASH exit=1 |
| `--pids-limit 128` | ✅ CRASH exit=1 |
| `--read-only` + `--tmpfs /tmp` | ❌ no-crash |
| `--read-only` + `--tmpfs /tmp` + **`-w /tmp`** | ✅ **CRASH exit=1** |

**根因**：gstoraster 初始化要往**当前工作目录**写东西；`--read-only` 下默认 `-w /` 不可写 → `gsapi_init_with_args` 返回 -9，
进程在到达缺陷点前就退出了。这不是 ASAN 静默，是**目标程序根本没进解析路径**。

**修复只需一行**（不改判据、不放宽标准）——在 `agent/platform/runners/cybergym.py` 的 `DOCKER_FLAGS` 里补工作目录：

```python
DOCKER_FLAGS = (
    "run", "--rm",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "2g",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev",
    "-w", "/tmp",                      # ← 新增：目标程序需要可写 CWD
)
```

> 本轮**没有**改这行代码（任务边界是只写 `docs/`）。上表就是它的验收读据：补 `-w /tmp` 后同一 PoC 恢复 CRASH。

### 5.2 阻塞 B：挂载约定不一致（`/input` vs `/tmp/poc`）

`/bin/arvo` 写死 `/tmp/poc`，runner 写死 `/input`。二者只能靠"直接调 fuzzer + `/input` 参数"绕开，
这要求每个案例显式声明 `harness_cmd`；而 61 个 `task.json` **一个都没有** `harness_cmd` / `input_path`。
即：**即使 84 个镜像全部到位，`smoke` 仍会全部停在 `runner_not_configured:cmd`** —— 这是配置缺口，不是镜像缺口。

### 5.3 `smoke --execute` 的实际状态

- 补齐 `cmd`/`input_path` 后 spec 已 `ready`（唯一 blocker 变成 `fix` 镜像缺失，§2.1）。
- `--execute` **本轮没有跑成**：fix 镜像未就位，`ready=false` 时 `smoke` 按设计拒绝执行（`would_execute=false`），
  这一条如实记录，不拿它当结论。
- 执行侧是否会假阴性，**由 §5.1 的手工二分直接回答**：`smoke --execute` 与 `verify --execute` 走的是同一个
  `CyberGymRunner` + 同一组 `DOCKER_FLAGS`，`--read-only` 在那里同样存在，所以 vul 侧拿不到 sanitizer 信号，
  判据只能落 `no_repro`。这正是"不能把 `docker run` 返回 0 当作 fix 侧干净"的反面案例。

## 6. 缺失清单（可直接执行）

### 6.1 缺的东西

| 项 | 缺什么 | 影响 | 补齐方式 |
|---|---|---|---|
| Docker Hub 直连 | 网络 | 一切 `docker.io` 拉取 | 走镜像站（`dockerproxy.net` 已验证） |
| arvo 镜像 | 41 组（82 tag） | 41 个案例无法本地复跑 | §6.2 命令，按需拉 |
| ExploitGym | `cybergym/arvo:44034-vul.exp.none-nogit` + 官方 socat socket | EG-02 无法复跑 | 需 ExploitGym 服务端 |
| VulnGym | `baseline_url` / `patched_url` | VG-01 无法复跑 | 需起 nltk 实例 |
| `task.json` | `harness_cmd` / `input_path`（61/61 缺） | `smoke` 全部 `runner_not_configured:cmd` | 逐例补（每例要确认镜像内的真实入口） |
| runner 硬化 | `-w /tmp`（`DOCKER_FLAGS`） | 复现假阴性（§5.1） | 一行改动 + 重跑 CG-01 验证 |

### 6.2 拉取命令（已验证可用，含 digest 核对）

```bash
pull_arvo() {                       # pull_arvo 44034
  local id="$1"
  for side in vul fix; do
    docker pull "dockerproxy.net/n132/arvo:${id}-${side}" \
      && docker tag "dockerproxy.net/n132/arvo:${id}-${side}" "n132/arvo:${id}-${side}"
  done
}
pull_arvo 44034                     # 已执行，digest = sha256:e57980e7ebcd…（= case.json 记录值）

# 全量（≈112 GB，按带宽分批）
for id in 44034 47101 10400 3938 10096 10147 53666 54625 12466 11081 47947 11253 3940 \
          368 1065 12420 10055 10306 10710 10486 10653 10252 14821 19414 12818 16445 \
          11011 29633 61675 58262 60983 49259 49613 54839 59500 52465 58405 10013 \
          59884 10341 10841 10628; do pull_arvo "$id"; done
```

> 镜像站不定时抽风（1panel 的 blob 超时就是实例）。重试即续传：已完成的 layer 会显示 `Already exists`。

### 6.3 只读核对（不写仓库）

```bash
# 镜像是否齐
python3 - <<'PY'
import json, subprocess
from pathlib import Path
need=set()
for tj in Path('workspace').glob('*/task.json'):
    d=json.loads(tj.read_text())
    for k in ('image_vul','image_fix'):
        if d.get(k): need.add(d[k])
have={l.split()[0] for l in subprocess.run(['docker','images','--format','{{.Repository}}:{{.Tag}}'],
      capture_output=True,text=True).stdout.splitlines()}
print('need',len(need),'have',len(need&have),'missing',len(need-have))
for m in sorted(need-have): print('  missing',m)
PY
```

## 7. 结论

1. **网络**：docker.io 整体不可达（DNS 污染 + 超时），但 `dockerproxy.net` 可用；`python:3.12-slim` 本地可用且可执行。
2. **镜像**：`arvo:44034-vul` 已落地，**digest 与 `case.json` 记录一致**，PoC 哈希也一致 —— 历史结论可在本机逐位复现；
   `44034-fix` 只完成 35/37 blob + 6/37 层解压后停滞（可续传，非不可拉）；其余 41 组因带宽预算未拉（可拉，约 112 GB）。
3. **smoke**：仓库现状 3/3 `needs_evidence` 是**如实**的；补 `cmd`/`input_path` 后 spec 可 ready，但 fix 镜像未就位，
   `--execute` 本轮未跑成（`persisted=false`，不冒充通过）。
4. **真跑仍被卡**：`--read-only` 让 vul 侧在初始化阶段退出（假阴性），一行 `-w /tmp` 可解；挂载约定 `/input` vs `/tmp/poc`
   要求逐例声明 `harness_cmd`。**在这两条修好之前，任何"真跑通过"的声明都不成立**。
5. 本轮为验证环境而落的临时件（不在仓库里）：`/tmp/smoke-ws/`（同构工作区）、`/tmp/smoke-run/`（smoke 工作目录）、
   `/tmp/pull-vul.log`、`/tmp/pull-fix.log`。
