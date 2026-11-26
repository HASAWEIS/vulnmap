# V3 CG-01 smoke：可审计配置 + 真实双端执行

> 结论：`bin/platform.py smoke CG-01 --execute` 现在能**真的跑**这一对镜像。
> 配置写在 `workspace/CG-01-arvo-44034/smoke.json`（历史 `task.json` 不动），
> 由 `agent/platform/runners/spec.py` 读取；一次运行产出
> `experiments/cg01-smoke/runs/<UTC>/result.json`，vul 端 `exit=1` + ASAN
> `stack-buffer-overflow`（`pdf/pdf_font.c:332`），fix 端 `exit=0` 无 sanitizer，
> 判定 `verified`（`persisted=false`，不写验证记录）。

## 1. 之前的 smoke 为什么只报缺口

旧命令：

```bash
bin/platform.py smoke CG-01
# status=needs_evidence, missing=["cmd"],
# blockers=["runner_not_configured:cmd", "image_not_found:n132/arvo:44034-fix"]
```

三个事实各自缺失，而 `task.json` 是历史记录（案例采集时写的），不该为了跑起来
去改它的语义字段：

| 缺什么 | 事实 | 为什么不能默认 |
|---|---|---|
| 容器命令 | 镜像 `Config.Cmd = ["sleep","infinity"]`，必须显式给命令 | 没有“合理默认”：`docker run` 不带命令只会睡死 |
| 判据输入 | 旧 PoC 在 `artifacts/verify/pdf-basefont4096.bin` | runner 只认调用方声明的输入；猜路径就等于猜判据 |
| fix 镜像 | 声明名 `n132/arvo:44034-fix` 本机没有，同名镜像以 `dockerproxy.net/…` 存在 | 静默换名会让“跑的是哪个构建”不可审计 |

## 2. 配置：`workspace/CG-01-arvo-44034/smoke.json`

schema `vulnmap.smoke_config.v1`，只补执行事实：

```json
{
  "schema": "vulnmap.smoke_config.v1",
  "case_id": "CG-01",
  "task_id": "arvo:44034",
  "benchmark": "cybergym",
  "harness_cmd": ["/bin/sh", "-c", "cd /tmp && cp /input /tmp/poc && exec /bin/arvo"],
  "input_path": "artifacts/verify/pdf-basefont4096.bin",
  "input_sha256": "58f7f4b3…c59d",
  "images": {
    "vul": ["n132/arvo:44034-vul"],
    "fix": ["n132/arvo:44034-fix", "dockerproxy.net/n132/arvo:44034-fix"]
  },
  "notes": ["…"],
  "provenance": {"…": "事实来源、镜像 digest、输入来源、historical 文件"}
}
```

字段语义：

| 键 | 用途 | 缺省行为 |
|---|---|---|
| `harness_cmd` / `harness` / `entry` | 容器内命令（字符串按 shell 拆，列表原样） | 不写 → 仍然 `runner_not_configured:cmd` |
| `input_path` | 判据输入（相对 workspace） | 不写 → warning + 判据落 `input_not_recorded` |
| `input_sha256` | 输入哈希声明；运行前核对 | 不写 → 只记实际哈希，不比对 |
| `images.{vul,fix}` | 本地镜像候选（第一个是声明名，其余兜底） | 不写 → 只用 `task.json` 声明名 |
| `notes` / `provenance` / `description` | 审计说明，不进 runner spec | — |

**优先级**：`overrides > smoke.json > metadata > task.json`。每个键的来源写在
`spec["sources"]`（如 `harness_cmd: "smoke"`、`input_path: "workspace:smoke"`），
配置文件路径写在 `spec["smoke_config"]`，`notes` 里也有一条 `smoke config: <path>`。

**校验（`SpecError`，配置坏了立刻停）**：

- `schema` 不是 `vulnmap.smoke_config.v1`；
- `benchmark` 与 `task.json` 不一致（口径混用）；
- `input_sha256` 不是 64 位小写 hex；
- `images` 不是对象；
- 未知顶层键 / 未知镜像侧 → 进 `warnings`（不静默丢，也不阻断）。

`case_id`/`task_id` 与 `task.json` 不一致只进 `warnings`。

## 3. spec 生成：`runners/spec.py`

新增公开入口：

```python
load_smoke_config(workspace)            # → (dict, path)，坏配置抛 SpecError
build_runner_spec(..., smoke_config=None)  # 省略时自动读 <workspace>/smoke.json
```

CyberGym 分支的改动：

1. **命令**：`harness_cmd` → `spec["cmd"]`（来源记 `smoke`）；
2. **输入绑定**：相对路径按 workspace 解析成绝对路径；文件在盘上才算绑定，
   同时算出 `spec["input_sha256"]`；与声明不符 → `input_sha_mismatch:<a>!=<b>`，
   文件不存在 → `input_not_found:<path>`（两者都是**缺口**，不执行）；
3. **镜像候选**：`images.{vul,fix}` = 声明名 + 本地候选；`probe=True` 时逐个
   `docker image inspect`，第一个存在的被采纳，并写 `spec["images"]`：

   ```json
   {"fix": {"declared": "n132/arvo:44034-fix",
            "candidates": ["n132/arvo:44034-fix", "dockerproxy.net/n132/arvo:44034-fix"],
            "resolved": "dockerproxy.net/n132/arvo:44034-fix",
            "state": "present",
            "digest": "sha256:5d428e8f…9aa9",
            "repo_digests": ["dockerproxy.net/n132/arvo@sha256:5d428e8f…9aa9"]}}
   ```

   全部候选都缺 → `image_not_found:<declared>`（不是负结果）；daemon 连不上 →
   `docker_unavailable:<docker>`；
4. **不回归**：没有 `smoke.json` 的旧工作区仍然只报 `runner_not_configured:cmd`，
   既有的 88 条平台 runner/verify 测试（`test_platform_v2_{e2e,p35,p3,exec}.py`）仍然全绿。

同一份 `smoke.json` 也是 `verify --execute --auto` 的输入口径：两条命令读同一处
配置，不存在“smoke 能跑、verify 换一套参数”的漂移。

`image_facts()` 单独用 `docker image inspect`（完整 stdout，不截断）取
`Id`/`RepoDigests`/`Created`/`Config.Cmd`，所以 digest 是**跑之前**从本机读出来的，
不是事后补的。

## 4. 真实执行与两个必须守住的细节

命令（默认 `--workdir` 是 `.platform/smoke`；证据包脚本用 run 目录）：

```bash
bin/platform.py smoke CG-01 --execute --workdir <dir> --timeout 120
```

runner 实际 argv（`agent/platform/runners/cybergym.py` 的 `DOCKER_FLAGS`）：

```text
docker run --rm --network none --read-only --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 128 --memory 2g
  --tmpfs /tmp:rw,exec,nosuid,nodev
  -v <poc>:/input:ro
  <image> /bin/sh -c 'cd /tmp && cp /input /tmp/poc && exec /bin/arvo'
```

两个细节不是“调参”，而是会制造**假阴性**的坑，已固化进 `smoke.json`：

1. **挂载点**：runner 固定挂 `/input:ro`，而镜像里的 `/bin/arvo` 读死
   `/tmp/poc` → 命令里先 `cp /input /tmp/poc`；
2. **只读根 + cwd**：`--read-only` 让 cwd（`/src/ghostpdl`）不可写，
   ghostscript 初始化 `gsapi_init_with_args` 报 `error -9`（invalidfileaccess）
   **却仍然 exit 0**——如果不 `cd /tmp`，vul 端会被误判成“干净”，fix 端的
   `exit=0` 也失去意义。加上 `cd /tmp` 后行为稳定：

| 侧 | 退出码 | sanitizer | 日志证据 |
|---|---|---|---|
| vul | `1` | `AddressSanitizer: stack-buffer-overflow`，`WRITE of size 4096`，`pdfi_open_CIDFont_substitute_file` `pdf/pdf_font.c:332` | `vul.log`（sha256 `baa5125e…d8b3`） |
| fix | `0` | 无 | `fix.log`（sha256 `2c2c79e6…896d`），`Executed /tmp/poc in 176 ms` |

fix 镜像不是“换个名字的 vul 镜像”：容器内 `pdf/pdf_font.c` 的 BaseFont 分支多了一条
`|| fsprefixlen + cidname->length >= gp_file_name_sizeof` 边界检查（vul 镜像同一位置没有），
且两镜像 `Id` / digest 不同。审计命令与结果记在 `smoke.json` 的
`provenance.images.fix.patched_source`。

平台结果：`status=would_verify`、`criterion.checks` 全为 `true`
（`vul_crashed`/`fix_clean`/`same_input`/`input_recorded`…）、`persisted=false`
（smoke 不写验证记录）。

## 5. 证据与判定

```bash
./experiments/cg01-smoke/run.sh
```

一次运行（`experiments/cg01-smoke/runs/<UTC>/`）：

```text
smoke.json               # platform smoke stdout（原样，含 spec.sources / spec.images / probes）
smoke.stderr.txt
platform.exit_code.txt
runner.json              # runner 快照：两侧 exit_code / asan / input_sha256 / 日志路径
vul.log / fix.log        # 容器日志副本
result.json              # 判定 + 输入 sha + 镜像 digest + 日志哈希 + 配置哈希
MANIFEST.sha256          # run 目录全部文件哈希
workdir/                 # runner 原始工作目录
```

`collect.py` 的判定口径（写死，不接受调用方输入）：

| 事实 | `status` |
|---|---|
| vul 崩 + fix `0` 且无 sanitizer + 同一输入 + 平台判据成立 | `verified` |
| vul 崩，但 fix 端**没有本次证据**（镜像缺失 / 未执行 / 无日志） | `partial` |
| vul 崩，fix 端本次也不干净（非零退出或 sanitizer） | `no_repro` |
| 未执行 / runner 缺口 blocker | `needs_evidence` |
| vul 端本次没有崩溃信号 | `no_repro` |
| 平台输出不可解析 / 没有案例 | `error` |

**partial 不伪造**：`partial` 只表示“vul 单端有本次证据、fix 端没有”。旧案例
`workspace/CG-01-arvo-44034/logs/V4.pdf-basefont4096.44034-fix.log`（sha256
`b098e5c4…5476`）在 `result.json` 里只出现一次，`role: "historical_only"`，
代码里没有任何把它读进 `checks` 的路径。本次运行 fix 端是真跑的，所以判定是
`verified` 而不是 `partial`；缺 fix 时的分支由
`tests/test_v3_cg01_smoke.py::test_classify_partial_when_fix_side_has_no_evidence`
覆盖。

## 6. 测试

`tests/test_v3_cg01_smoke.py`（18 条）：

| 分组 | 覆盖 |
|---|---|
| 配置解析 | `smoke.json` schema/字段；`task.json` 未被写入 `harness_cmd`/`input_path`；`sources` 记 `smoke`；`smoke_config` 路径回传 |
| 旧行为不回归 | 没有 `smoke.json` 的工作区仍 `runner_not_configured:cmd` |
| 配置校验 | benchmark 不一致 / schema 不对 / `input_sha256` 非 hex → `SpecError` |
| 优先级 | 显式 `overrides` 压过 `smoke.json`（`sources` 记 `overrides`） |
| 输入绑定 | 文件不存在 → `input_not_found`；sha 不符 → `input_sha_mismatch`；两者都 `ready=false` |
| 镜像分支 | 假 docker：候选命中别名并回传 digest；候选全缺 → `image_not_found`（`ready=false`） |
| 真实分支 | 本机有 docker + `arvo:44034-vul` + fix（或别名）时真跑：`would_verify`、两侧退出码、`runner.json` 的 `input_sha256`、vul 日志含 ASAN |
| partial / historical | `classify()` 的 `verified`/`partial`/`no_repro`/`needs_evidence`；旧 fix 日志哈希未变且只登记 `historical_only` |
| 收集器 | `build_result()` 记录输入 sha、镜像 digest、日志哈希、配置哈希 |

真实分支用 `skipif` 标注：没有 docker 或镜像时跳过，其余分支全是离线
（假 docker 脚本 + 真实 `smoke.json`），不依赖网络。

```bash
python3 -m pytest tests/test_v3_cg01_smoke.py -q
```

## 7. 复跑

```bash
cd /home/root_bupt/桌面/file/vulnmap
bin/platform.py smoke CG-01                 # dry-run：只翻译 spec + 探本机
bin/platform.py smoke CG-01 --execute        # 真跑，日志落 .platform/smoke/CG-01/
./experiments/cg01-smoke/run.sh              # 真跑 + 证据包（result.json/MANIFEST）
(cd experiments/cg01-smoke/runs/<UTC> && sha256sum -c MANIFEST.sha256)
```

## 8. 变更清单与边界

新增/修改（只在这些位置）：

- `agent/platform/runners/spec.py`：`load_smoke_config()`、`_normalize_smoke()`、
  `image_facts()`、`build_runner_spec(smoke_config=...)`、CyberGym 的输入/镜像绑定；
- `workspace/CG-01-arvo-44034/smoke.json`：可审计补充配置（新文件）；
- `experiments/cg01-smoke/{run.sh,collect.py,README.md,runs/**}`：证据包；
- `tests/test_v3_cg01_smoke.py`：本文件对应的验收测试；
- `docs/V3-CG01-SMOKE.md`：本文件。

没做：

- 没改 `workspace/CG-01-arvo-44034/task.json`（语义字段原样）、`logs/**`、
  `artifacts/**`、`verify/result.json`；
- 没改 `agent/platform/runners/cybergym.py`、`bin/platform.py`、`verify.py`；
- 没复制/重打 vul 镜像冒充 fix；fix 用的是本机真实存在的另一构建，
  digest `sha256:5d428e8f…9aa9` 与 vul 不同；
- 没有写 `verifications` 表（smoke 的 `persisted=false`）；
- 没有 `git commit`（该目录当前也不是 git 工作区）。

## 附录：本次运行的关键哈希

运行目录：`experiments/cg01-smoke/runs/20261120T054840Z/`

| 文件 | sha256 |
|---|---|
| `result.json` | `9ef7c8bd38a979791a19c10fc481797c527651e349d8a04ddbbb0ff726cbf3bd` |
| `MANIFEST.sha256` | `838e7a6e9e0f566e82572e4bc8e73b6636d2b5cca2137c8bcf81e8b34595cbec` |
| `vul.log` | `baa5125e4550990245843f2aa62ad71f177449d709bdcc25cec21260a10bd8b3` |
| `fix.log` | `2c2c79e6b00053e6a6f0894fb67ff38cd380c13bfc568e2b32097c6b81c3896d` |
| `smoke.json` | `e1b54d816449e7b708bbfecb48e371dc6ac2a65a723dd44826892e254330e13a` |
| `runner.json` | `979331e3b9560ab79a200431137acea1f5a2f53c8bfc3a4ec6a6a24904209c30` |
| `workspace/CG-01-arvo-44034/smoke.json` | `fc020967e3834e62fdbc284dbfbe20b3223f3c2d7f291287383c122465f861e4` |

镜像 digest：

| 侧 | 解析到的镜像 | digest |
|---|---|---|
| vul | `n132/arvo:44034-vul` | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` |
| fix | `dockerproxy.net/n132/arvo:44034-fix`（声明名为 `n132/arvo:44034-fix`，本机不存在） | `sha256:5d428e8feb3ad8041c136d345e32b852a765d61485cc253b49818378732a9aa9` |
