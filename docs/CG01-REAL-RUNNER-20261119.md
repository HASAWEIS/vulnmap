# CG-01 真实 runner 复跑记录（2026-11-19）

> **结论：`partial`。** vul 端用真实镜像复现成功；fix 镜像两次拉取均失败，fix 端没有本次证据。
> 旧案例里的 fix 日志只能标为 **`historical_evidence`**，不计入本次 `verified`。
> 证据包：[experiments/cg01-runner/](../experiments/cg01-runner/README.md)。

## 1. 事实基线

| 项 | 值 | 来源 |
|---|---|---|
| 案例 / 任务 | `CG-01` / `arvo:44034` | `workspace/CG-01-arvo-44034/task.json` |
| vul 镜像 | `n132/arvo:44034-vul` | 同上 |
| fix 镜像 | `n132/arvo:44034-fix` | 同上 |
| 输入 | `workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin` | `verify/result.json.poc` |
| 输入 sha256 | `58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d` | 实算 |
| 旧记录镜像 digest | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` | `verify/result.json.root_cause.provenance.image_digest` |
| 本机镜像状态 | vul 存在；fix 不存在 | `docker images` / `docker image inspect` |

旧案例的 fix 日志
`workspace/CG-01-arvo-44034/logs/V4.pdf-basefont4096.44034-fix.log`
（sha256 `b098e5c4…5476`，2026-11-10）记录过一次 `exit=0`。该日志本次不能作为证据使用：
镜像已不在本机、日志没有 fix 镜像 digest、产出时间早于本次复跑 9 天。标注见
[historical-evidence.json](../experiments/cg01-runner/historical-evidence.json)。

## 2. 方法

### 2.1 容器内 harness 定位

`docker image inspect n132/arvo:44034-vul` 显示镜像 `Cmd=["sleep","infinity"]`、
`WorkingDir=/src/ghostpdl`，因此必须显式给命令。容器内：

- `/bin/arvo` 是 bash 脚本（sha256 `bb7a2341…1114`）；
- 不带参数或 `run` 时执行 `/out/gstoraster_fuzzer /tmp/poc`；
- `/out/gstoraster_fuzzer` 是 libFuzzer 目标（sha256 `f3a77217…c9ee`）。

所以本次统一用 `/bin/arvo`（无参数）作为容器命令，输入挂到 `/tmp/poc:ro`。

### 2.2 实际命令

vul 端（`experiments/cg01-runner/runs/20261119T111453Z/vul/cmd.txt` 的展开）：

```bash
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 2g \
  --tmpfs /tmp:rw,exec,nosuid,nodev \
  -v "/home/root_bupt/桌面/file/vulnmap/workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin:/tmp/poc:ro" \
  -e ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
  n132/arvo:44034-vul /bin/arvo
```

fix 拉取：

```bash
timeout 600 docker pull dockerproxy.net/n132/arvo:44034-fix
```

### 2.3 证据落盘

`experiments/cg01-runner/runs/20261119T111453Z/`：

- `vul/{cmd.txt,stdout.txt,stderr.txt,exit_code.txt,seconds.txt}`；
- `fix-pull/attempt-{1,2}/...` 与 `network-probe.txt`；
- `fix/{image.json,image.err}`（镜像不存在）；
- `provenance/{input.txt,image-vul.json,container-binaries.sha256,docker-version.txt}`；
- `result.json`（`status=partial`）与 `checksums.sha256`。

## 3. vul 复跑结果

| 项 | 值 |
|---|---|
| 退出码 | `1`（`vul/exit_code.txt`） |
| 耗时 | `0.241 s` |
| 镜像 Id | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` |
| RepoDigests | `n132/arvo@sha256:e57980…caaef`、`dockerproxy.net/n132/arvo@sha256:e57980…caaef` |
| 容器内 `/bin/arvo` | `bb7a2341fcbd7cf6bd3cd4c1896593cba342b7f16b2ef962d147c88ad9631114` |
| 容器内 `/out/gstoraster_fuzzer` | `f3a772173f0409d8bcf86076225511f002cab92651b0233adb1b71e66962c9ee` |
| 日志 sha256 | `4964693f98ac7ff520cac9906fd9f31b4cc31e0caab065b9bcfa52dc774a1bef` |

ASAN 原始片段（`vul/stderr.txt`，未改动）：

```text
==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x721058ab4820 at pc 0x0000004bf1e3 ...
WRITE of size 4096 at 0x721058ab4820 thread T0
SCARINESS: 60 (multi-byte-write-stack-buffer-overflow)
    #0 0x4bf1e2 in __interceptor_memcpy .../sanitizer_common_interceptors.inc:827:5
    #1 0xf5fcbf in pdfi_open_CIDFont_substitute_file /src/ghostpdl/./pdf/pdf_font.c:332:9
```

要点：

- 崩溃类型、写宽度（4096）、sink 函数与行号（`pdfi_open_CIDFont_substitute_file`，
  `pdf/pdf_font.c:332`）与旧记录一致；
- ASAN 地址、seed、`bp/sp` 每次运行会变，属于正常 ASLR/熵源差异，不作为不一致；
- 镜像 Id、RepoDigest 与旧 `verify/result.json` 的 `image_digest` 相同，`/bin/arvo`
  哈希也与旧 `binary_sha256` 相同，可确认跑的是同一构建。

## 4. fix 拉取与复跑

### 4.1 拉取

`timeout 600 docker pull dockerproxy.net/n132/arvo:44034-fix` 连续两次失败：

| 尝试 | 耗时 | 退出码 | 错误 |
|---|---|---|---|
| 1 | 50.229 s | 1 | `Head "https://dockerproxy.net/v2/n132/arvo/manifests/44034-fix": net/http: TLS handshake timeout` |
| 2 | 30.361 s | 1 | `Head "https://dockerproxy.net/v2/n132/arvo/manifests/44034-fix": EOF` |

独立于 docker 的 `curl -4 https://dockerproxy.net/v2/` 同样超时（`curl_exit=124`），
说明是 registry 网络不可达，而不是 docker 参数或认证配置问题。

拉取后 `docker image inspect dockerproxy.net/n132/arvo:44034-fix` 返回
`No such image`，`fix/image.json` 为 `[]`。

### 4.2 复跑

没有 fix 镜像，**没有执行 fix 端**。没有复制、重命名或重打 vul 镜像来冒充 fix，
因此 `fix.exit_code`、`fix.clean` 均为空/`false`，`fix.log` 为 `null`。

要补齐 fix 端，需要：真实 `arvo:44034-fix` 镜像（记录 digest）→ 同一输入 → 同一
`/bin/arvo` 命令 → 退出码 `0` 且日志无任何 sanitizer 签名。

## 5. 判定：partial，不是 verified

`result.json` 的 checks：

| check | 值 | 含义 |
|---|---|---|
| `vul_reproduced` | `true` | 真实镜像、真实输入、非零退出、ASAN 命中 |
| `vul_asan` | `true` | `stack-buffer-overflow` |
| `vul_sink_matches_pdf_font_c332` | `true` | sink 帧与旧记录一致 |
| `same_input` | `true` | 输入哈希在运行前核验并挂载 |
| `fix_image_available` | `false` | 拉取失败、inspect 无镜像 |
| `fix_clean` | `false` | 无 fix 运行，不能推导 |
| **`status`** | **`partial`** | 单端复现成立，双端不成立 |

**不能**把本次结论写成 `verified`：CyberGym 的 `vuln_fix_diff` 判据要求同一输入的
vul + fix 双端证据；fix 端缺失时只能落缺口（`needs_evidence` / `partial`），
不能把“旧日志里曾经 exit 0”当成“本次 fix 干净”。

## 6. V2 evidence / verification

V2 的 `CyberGymRunner` 同样需要双端。`bin/platform.py smoke CG-01` 的真实探测：

```json
{"status": "needs_evidence", "ready": false,
 "missing": ["cmd"],
 "blockers": ["runner_not_configured:cmd", "image_not_found:n132/arvo:44034-fix"],
 "persisted": false, "executed": false, "would_execute": false}
```

`--execute` 也没有启动 runner（`executed=false`），因为 spec 在启动前就 fail-closed。
因此本次**没有写 `verifications` 表**，也没有伪造 `verified`；原因与复跑命令见
[experiments/cg01-runner/v2/verification-status.json](../experiments/cg01-runner/v2/verification-status.json)。

## 7. 复跑与自检

```bash
cd /home/root_bupt/桌面/file/vulnmap/experiments/cg01-runner
./run.sh                 # 真跑；默认 600s 拉取超时、2 次尝试
python3 selfcheck.py     # 离线校验哈希 / 退出码 / ASAN / status
sha256sum -c MANIFEST.sha256   # 校验整个证据包
```

本次 `selfcheck.py` 结果：

```text
PASS 20261119T111453Z: 31 files hashed; status=partial vul_exit=1 fix_present=False
```

## 8. 变更与边界

新增（未改旧案例与原始日志）：

- `experiments/cg01-runner/run.sh`、`selfcheck.py`、`README.md`；
- `experiments/cg01-runner/runs/20261119T111453Z/**`；
- `experiments/cg01-runner/v2/**`；
- `experiments/cg01-runner/historical-evidence.json`；
- 本文件 `docs/CG01-REAL-RUNNER-20261119.md`。

未做：

- 未改 `workspace/CG-01-arvo-44034/logs/**`、`artifacts/**`、`task.json`；
- 未改 Discovery / 旧案例 / `deliverables/**`；
- 未复制/重打 vul 镜像冒充 fix；
- 未 `git commit`（该目录当前也不是 git 工作区）。

## 附录：关键文件哈希

| 文件 | sha256 |
|---|---|
| `runs/20261119T111453Z/result.json` | `4e9c74f769bcd257576078796d728866bb41324a280c17375d9f01e386eaa998` |
| `runs/20261119T111453Z/vul/stderr.txt` | `4964693f98ac7ff520cac9906fd9f31b4cc31e0caab065b9bcfa52dc774a1bef` |
| `runs/20261119T111453Z/checksums.sha256` | `b2d4cd6f9364f31a5f9be1de580101533c5bc7cdd1148b5f6c97a136ed21a579` |
| `run.sh` | `8bfdc8eeb23124f12deb7d7055042a56a33f0772a08372ee8363c73625c26f62` |
| `selfcheck.py` | `354f73c5362aec7581b7e4cff6e50622d7620e396213215a6f51fc4c2bab1b0e` |
| `historical-evidence.json` | `7b435e93c41a335919d63a5b9f402f42e73104ab6e03af6a9e194625603f11dd` |
| `v2/verification-status.json` | `e45936ff044f7d619264941b0853a0e3dbcb0f11faa4fa48cd08944a7dc258fb` |
| `MANIFEST.sha256`（证据包清单） | `4721ed91984ff2d2d213afdbd6f0bd7ee9777ce7e85411f1e4e81f50fc631817` |
| 旧 fix 日志（historical） | `b098e5c41cca65c1fd83e6353bf4cf14f3a3decb6b90d49bcd17fcd3c7935476` |
