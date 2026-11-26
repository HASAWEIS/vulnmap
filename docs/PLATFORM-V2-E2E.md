# 平台 v2 P3.8：端到端 runner spec 自动生成 + `smoke`

> 范围：P3.5 让 `verify --execute` 能现场取证据，但**执行输入还得人手抄**：
> 镜像名、镜像内命令、socket 地址、基线/修补 URL 散落在 `workspace/<case>/task.json`
> 和任务 metadata 里，抄错一个字就是一次口径事故。
> P3.8 补两件事：
> **① `runners/spec.py` 把 task.json / metadata 翻译成 runner spec，并把缺的东西列成 blockers；
> ② `verify --execute --auto` 与 `bin/platform.py smoke` 用这份 spec 跑一次（或只 dry-run），
> 本机没镜像/没服务就如实 `needs_evidence`。**
> 一句话：**spec 自动生成，缺口如实上报，`verified` 仍然只能由判据推导。**
> 前置：[PLATFORM-V2-P35.md](PLATFORM-V2-P35.md) 的 runner 契约与
> `runner_*` blocker 词表、[PLATFORM-V2-P3.md](PLATFORM-V2-P3.md) 的
> `Verification` 契约、[benchmark_policy.py](../agent/benchmark_policy.py) 判据事实源。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/runners/spec.py](../agent/platform/runners/spec.py) | `build_runner_spec()`：task.json/metadata/显式覆盖 → runner spec；`load_task_json()` / `summarize()`；本机探测 `docker_path()` / `image_probe()` / `tcp_probe()` / `http_probe()`；`SpecError` |
| [agent/platform/verify.py](../agent/platform/verify.py) | `run_verification(..., auto=True)`：先翻译 spec，有缺口就**不启动 runner**（`_spec_gap_execution`），`detail.auto_spec` + `execution{auto,executed,auto_blockers}` 留痕；`_execution_snapshot()` 统一快照形状 |
| [bin/platform.py](../bin/platform.py) | `verify --auto/--workspace/--no-probe`；新增 `smoke`（默认 CG-01 / EG-02 / VG-01，dry-run + 可选 `--execute`，`--strict`） |
| [tests/test_platform_v2_e2e.py](../tests/test_platform_v2_e2e.py) | 35 项验收：字段映射/缺字段/优先级/无 docker/镜像缺失/daemon 掉线/假 socket/本地 HTTP/auto 成功与缺口/CLI `--auto`/`smoke` 三态 |
| [docs/PLATFORM-V2-E2E.md](PLATFORM-V2-E2E.md) | 本文 |

## 2. 为什么需要“自动 spec”

P3.5 的 runner 只认一份**显式** spec，这在单测里很干净，在真实案例里很脆：

| 真实事实在哪 | P3.5 的做法 | 后果 |
|---|---|---|
| `workspace/CG-01-arvo-44034/task.json` 的 `image_vul`/`image_fix` | 手抄到 `--image-vul/--image-fix` | 抄错镜像名 → 跑的是别的案例 |
| `--meta harness_cmd="/workspace/reproduce /input"` | 手抄到 `--cmd` 三次 | argv 拆错 → 镜像里跑了个不存在的路径 |
| ExploitGym 的 `task_info`（host/port / exploit_cmd） | 手抄 `--host/--port` | 端口漏了 → `runner_not_configured`，看起来像“跑不动” |
| VulnGym 的基线/修补 URL | 手抄 `--baseline-url/--patched-url` | 两个 URL 写成同一个 → 两侧一致 → 假 `no_repro` |

P3.8 的做法是把这些事实**翻译**过来，而不是让调用方再复述一遍。翻译不猜：

- 没有 `image` 就是 `runner_not_configured:image`，不编一个 `latest`；
- 没有 `task_info` 里的 host/port 也没有 `exploit_cmd` 就是
  `runner_not_configured:exploit_target`，不退化成“随便连一个”；
- 没有 `service_url` 也没有 `baseline_url`+`patched_url` 就是
  `runner_not_configured:baseline_url,patched_url`，不把同一个 URL 当两侧。

## 3. 字段映射

### 3.1 CyberGym

| runner spec 字段 | 来源（`task.json` / metadata / `--meta`） | 备注 |
|---|---|---|
| `image_vul` | `image_vul`，别名 `vul_image` | 必填 |
| `image_fix` | `image_fix`，别名 `fix_image` | 必填 |
| `cmd` | `harness_cmd` / `entry` / `entry_point` / `harness{cmd}` | 字符串按 shell 规则拆，list 原样；**必填**（P3.5：没有默认命令） |
| `input_path` | `input_path` / `input_file` / `input`（可 `{path}`）；相对路径按 workspace 解析 | 可选；缺了只 warning（判据会落 `input_not_recorded`） |
| `docker` | `docker`（metadata/`--docker`） | 默认 `docker` |

### 3.2 ExploitGym

| runner spec 字段 | 来源 | 备注 |
|---|---|---|
| `image` | `image`，别名 `image_vul`（EG-02 的写法） | 必填（审计环境） |
| `image_mode` | `mode` / `image_mode`（如 `exp.none`） | **必填**；任务级 mode 不能冒充 transport |
| `mode`（transport） | `task_info.transport`，或由 `host`+`port` / `exploit_cmd` 推导 | `socket` / `exploit_cmd` |
| `host` / `port` | `task_info{host,port}`、`task_info="127.0.0.1:9009"`、`task_info` 文件路径、metadata | socket 必填 |
| `exploit_cmd` | `task_info{exploit_cmd,cmd,exploit}` 或 metadata `exploit_cmd` | 命令模式必填 |
| `expected_flag` | `task_info{expected_flag,flag}` 或 metadata | 可选；缺了只 warning（不严格比对） |

`task_info` 支持四种形态：dict、JSON 文本、JSON 文件路径、`host:port`。

### 3.3 VulnGym

| runner spec 字段 | 来源 | 备注 |
|---|---|---|
| `baseline_url` / `patched_url` | 显式两个；或 `service_url` / `base_url` 同时用于两侧（`notes` 里写明） | 必填 |
| `method` | `method`（默认 `GET`） | — |
| `expect` | `expect{baseline_status,patched_status_in}`，或扁平 `expect_baseline_status` / `expect_patched_status` | 可选；缺了只 warning |

### 3.4 优先级与来源记账

`task.json` < `metadata`（`--meta`） < 显式覆盖（`--image-vul`、`--spec` 里的 runner 键）。
覆盖只透传该 benchmark 的 runner 键白名单，**判据键（`flag`/`vul`/`fix`/`baseline`…）不会钻进 spec**。
`doc["sources"]` 逐键记录来源（`task_json` / `metadata` / `overrides` / `workspace:…`），
出错时能直接回答“这个镜像是从哪抄来的”。

## 4. 缺口 vs 警告 vs 本机探测

产物字段（`schema=vulnmap.runner_spec.v1`）：

| 字段 | 含义 |
|---|---|
| `spec` | 直接喂 runner 的字典 |
| `blockers` | 缺口（`runner_not_configured:*` / `docker_unavailable:*` / `image_not_found:*` / `connection_failed:*` / `runner_timeout:*`），**有 blocker 就不执行** |
| `missing` | 缺的字段名（`image_vul` / `mode` / `exploit_target` …），给人看 |
| `required` | 该 benchmark 的必填字段清单（`REQUIRED`），空 `missing` 时用来对照“还差什么” |
| `warnings` | “能跑但证据会不完整”（缺 `input_path` / `expected_flag` / `expect`） |
| `probes` | 本机探测事实：`{name,target,ok,detail}` |
| `ready` / `status` | `not blockers` / `ready` 或 `needs_evidence` |

代码强制的不变量：`blockers` 的每一前缀都必须落在缺口词表
（`GAP_BLOCKERS = docker_unavailable / image_not_found / connection_failed / http_error /
runner_not_configured / runner_unavailable / runner_timeout`）里，否则直接 `SpecError`——
spec 层**没有能力**产出“判据被推翻”类 blocker（`runner_spec_invalid`、`flag_mismatch`…）。

本机探测（`probe=True`，可用 `--no-probe` 关掉）：

| 探什么 | 怎么探 | 结果 |
|---|---|---|
| docker 客户端 | `shutil.which(docker)` 或路径存在 | 缺 → `docker_unavailable:docker` |
| 镜像 | `docker image inspect <image>` | 非零且 stderr 含 daemon 特征 → `docker_unavailable`；否则 → `image_not_found:<image>` |
| ExploitGym socket | `socket.create_connection(host,port)` | 拒连 → `connection_failed:host:port` |
| ExploitGym 命令 | 可执行文件能否解析 | 缺 → `runner_unavailable:<cmd>` |
| VulnGym URL | 一次 GET（禁代理、不跟跳转、读 4 KiB） | 连不上 → `connection_failed:<url>`；超时 → `runner_timeout:<side>` |
| ExploitGym 镜像 | `exploit_cmd` 模式下才查（命令跑在本地镜像里）；socket 模式只审计 | 缺 → `image_not_found:<image>` |

**为什么要先探再跑**：`docker run` 对不存在的镜像返回 **125**。如果直接交给 runner，
vul 端会拿到 `exit_code=125`，`evaluate_cybergym` 会把它读成“vul 端崩了”——
一个纯纯的**假阴性/假阳性风险**。P3.8 在启动前停下：缺镜像就是 `needs_evidence`。

## 5. `verify --execute --auto` 编排

~~~text
run_verification(auto=True)
  ├─ build_runner_spec(benchmark, metadata, workspace/task.json, overrides, probe)
  │    ├─ blockers 非空 → _spec_gap_execution()：**不启动 runner**
  │    │     └─ 写 <workdir>/runner-spec.json（verify_runner_spec 证据）
  │    └─ blockers 为空 → _execute_runner(spec)（P3.5 原路径，一字未改）
  ├─ normalize_spec → EVALUATORS[benchmark]            # 判据仍是唯一事实源
  ├─ _merge_execution(...)                             # 只做与运算
  └─ verification.executed{auto,executed,auto_blockers} → recorded → verified|failed
~~~

- 缺口路径：`verified=False`、`status=needs_evidence`、任务落 `NEEDS_EVIDENCE`；
  记录照常落库（含 `detail.auto_spec` 与 `detail.execution.executed=false`），**不写 `verified`**；
  注意这条路径的 `blockers` 会叠加判据自身的缺口项（`input_not_recorded` /
  `flag_not_captured` …）与 `benchmark_policy` 的“判据不成立”标记（如
  `local_dual_run_failed`）——`status` 由**缺口优先**规则判定为 `needs_evidence`，
  这些条目只是“判据此刻缺什么”，不是负结论；
- 就绪路径：与 P3.5 完全同一条链路，只是 spec 由本模块生成；
- 判据为负（fix 也崩、两侧一致）：仍然是 `no_repro`——auto 不会把负结果“洗成”缺口；
- 没有 runner 的 benchmark（`target_yaml`）：`runner_unavailable:target_yaml` +
  `unsupported_benchmark:target_yaml` → `rejected`，不假装跑过。

## 6. `bin/platform.py smoke`

~~~bash
# dry-run：只看 spec 与本机缺口（默认 CG-01 EG-02 VG-01）
python3 bin/platform.py smoke

# 指定案例 / 只看字段不探本机
python3 bin/platform.py smoke CG-01 VG-01 --no-probe

# 真的跑一次（仍然不落验证记录；判据成立也只说 would_verify）
python3 bin/platform.py smoke VG-01 --execute --isolation none --timeout 30

# 严格模式：不是每个案例都 would_verify 就退出 1
python3 bin/platform.py smoke --strict
~~~

输出（`schema=vulnmap.smoke.v1`）逐案例给 `status` / `missing` / `blockers` / `probes` / `spec`，
顶层 `persisted=false`。状态只有四种：

| `status` | 含义 |
|---|---|
| `ready` | dry-run：字段齐全且本机可用，可以跑 |
| `needs_evidence` | 缺字段 / 缺镜像 / 缺服务——**如实报缺口，不是负结果** |
| `would_verify` | `--execute` 跑完且判据成立；**没有**写任何验证记录 |
| `no_repro` | `--execute` 跑完且判据为负（两侧一致、fix 也崩…） |

退出码：`0` 诚实完成（含 `needs_evidence`）/ `1` `--strict` 下没全绿 / `2` 案例编号或
`task.json` 读不了（操作错误）。

### 6.1 本机实测（无 arvo 镜像、无 ExploitGym/VulnGym 实例）

~~~text
$ python3 bin/platform.py smoke | jq -r '.cases[] | "\(.case) \(.benchmark) \(.status) \(.blockers)"'
CG-01 cybergym    needs_evidence  ["runner_not_configured:cmd",
                                   "image_not_found:n132/arvo:44034-vul",
                                   "image_not_found:n132/arvo:44034-fix"]
EG-02 exploitgym  needs_evidence  ["runner_not_configured:mode",
                                   "runner_not_configured:exploit_target"]
VG-01 vulngym     needs_evidence  ["runner_not_configured:baseline_url,patched_url"]
summary {"needs_evidence": 3}   exit=0
~~~

三条都**没有**被写成 `no_repro`：CG-01 缺的是本机镜像与镜像内命令，
EG-02 缺的是 `mode` 与 `task_info` 里的 socket/命令，VG-01 缺的是服务地址。
这正是需求要的口径——**本机跑不了 ≠ 案例不成立**。

## 7. 验收

~~~bash
python3 -m pytest tests/test_platform_v2*.py -q
# 181 passed（P0 7 + P1 13 + P2 11 + P3 11 + P4 19 + P3.5 26 + P3.6 16 + P3.7 22
#            + P4.5 21 + P3.8 35）
~~~

| 测试 | 钉住的事实 |
|---|---|
| `test_spec_cybergym_reads_task_json_and_metadata` | 镜像来自 task.json、命令来自 metadata、`sources` 逐键记账 |
| `test_spec_cybergym_entry_alias_and_argv` | `entry` list / `harness{cmd}` 都能变成 argv；字符串按 shell 拆 |
| `test_spec_cybergym_missing_fields_are_blockers` | 缺 `image_vul,image_fix,cmd` → `runner_not_configured:*`，输入缺失只是 warning |
| `test_spec_exploitgym_task_info_socket` | `image`/`mode`/`task_info{host,port}` → `mode=socket`，任务级 mode 落 `image_mode` |
| `test_spec_exploitgym_task_info_address_string` | `task_info="127.0.0.1:9009"` 也能解析成 socket |
| `test_spec_exploitgym_task_info_file` | `task_info` 指向 JSON 文件 → `exploit_cmd` |
| `test_spec_exploitgym_missing_transport_and_mode` | 缺 `mode`/`exploit_target` 各一条 blocker |
| `test_spec_vulngym_service_url_shared` / `_missing_urls` | `service_url` 两侧共用并写 note；全缺则两条 blocker |
| `test_spec_precedence_task_json_metadata_overrides` | task.json < metadata < 覆盖；判据键不泄漏进 spec |
| `test_spec_probe_*`（5 项） | 缺 docker / 缺镜像 / daemon 掉线 / socket 通·拒 / HTTP 通 |
| `test_verify_auto_cybergym_success` | fake docker 双端 → `verified`；`execution.auto=True`、`auto_spec` 入库、无 `confirmed` |
| `test_verify_auto_missing_image_is_needs_evidence` | 缺镜像 → `needs_evidence`、`executed=false`、`verify_runner_spec` 证据、事件带 `auto` |
| `test_verify_auto_missing_docker_is_needs_evidence` | 无 docker → `docker_unavailable:*`，runner 没起 |
| `test_verify_auto_exploitgym_socket_success` | 本地 TCP 服务 → `verified`、`dual_required=False` |
| `test_verify_auto_exploitgym_unreachable_is_needs_evidence` | 拒连 → `connection_failed:*` + `needs_evidence` |
| `test_verify_auto_vulngym_local_server` | 200 vs 403 → `verified`，主证据 = patched 响应体 |
| `test_verify_auto_vulngym_unreachable_is_needs_evidence` | 服务不可达 → `needs_evidence` |
| `test_verify_auto_reads_workspace_task_json` | metadata 为空时镜像只能来自 `<workspace>/task.json` |
| `test_verify_auto_real_negative_is_not_downgraded` | 双端干净 → `no_repro`（auto 不是“一切皆缺口”） |
| `test_verify_auto_target_yaml_degrades_without_runner` | 无 runner 的 benchmark → `rejected`，不假装跑过 |
| `test_verify_without_auto_is_unchanged` | 不传 `auto` 时 P3.5 行为逐字保留 |
| `test_cli_smoke_reports_gaps_honestly` | 三案例全 `needs_evidence`、`persisted=false`、输出无 `"verified": true` |
| `test_cli_smoke_execute_vulngym_would_verify` | `--execute` 成功 → `would_verify`，仍不落验证记录 |
| `test_cli_smoke_missing_service_stays_needs_evidence` | 服务不可达 → `needs_evidence` 且 `executed=false` |
| `test_cli_smoke_unknown_case_exit_2` / `_strict_exit_1` | 操作错误 2 / 未全绿 1 |
| `test_cli_verify_auto_end_to_end` | CLI `verify --auto` 全链路：fake docker → 退出码 0 → 记录可重开 |

全部本地 fake：docker 用 `#!/usr/bin/env python3` 脚本（`image inspect` 报存在性、`run` 回放行为），
ExploitGym 用本地 TCP 服务，VulnGym 用本地 `ThreadingHTTPServer`；不碰真实 benchmark 网络。

## 8. 边界（P3.8 刻意不做）

- **不猜**：没有镜像/命令/服务地址就不执行，绝不编默认值；
- **不把缺口当负结果**：所有 blocker 都落在 `runner_*`/`docker_unavailable`/`image_not_found`/
  `connection_failed`/`http_error`/`runner_timeout` 词表里 → `needs_evidence`；
- **不写 `verified`**：`spec.py` 只产 spec 与探测事实，`smoke` 只报 `would_verify`，
  结论仍只由 `benchmark_policy` 推导；
- **不构建镜像**：本机没有就报缺口，`smoke --execute` 也不会去 `docker build`；
- **不落 smoke 记录**：`smoke` 不建库、不写 `verifications`，只写 `<workdir>/<case>/` 下的
  runner 产物（供人工查看）；
- **不改 Discovery / API / 旧案例**：只新增 `runners/spec.py` 与
  `verify.py`/`bin/platform.py` 的 auto/smoke 分支；
- **不做并发**：`smoke` 串行跑案例，一条案例一个 runner 工作目录。
