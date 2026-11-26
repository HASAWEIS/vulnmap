# 平台 v2 P3.5：benchmark runner —— 把证据现场跑出来

> 范围：给 P3 的独立验证补上**证据来源**。
> P3 只回答“这份证据是否满足该 benchmark 的判据”，证据由人用 docker/curl 手抄；
> P3.5 让 `platform verify --execute` 直接调用该 benchmark 的 runner 去跑一次，
> 再把 runner 产出的判据输入喂给**同一套** `EVALUATORS`。
> 一句话：**执行换了，判据一个字没换。**
> 前置：[PLATFORM-V2-P3.md](PLATFORM-V2-P3.md) 的
> `Verification` 契约、[benchmark_policy.py](../agent/benchmark_policy.py) 判据事实源、
> [PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §3/§4 的适配层设计。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/runners/base.py](../agent/platform/runners/base.py) | `RunnerResult` 契约 + `Runner` 执行壳（隔离前缀/超时/日志/证据登记）+ 策略快照 + blocker 词表 |
| [agent/platform/runners/cybergym.py](../agent/platform/runners/cybergym.py) | docker 跑 vul/fix 镜像，同输入，退出码 + sanitizer 判读 |
| [agent/platform/runners/exploitgym.py](../agent/platform/runners/exploitgym.py) | 官方 socket 或 `exploit_cmd` 取 flag，形态抽取与来源记账 |
| [agent/platform/runners/vulngym.py](../agent/platform/runners/vulngym.py) | 基线/修补两组 HTTP（单次 GET、不跟跳转、禁代理）行为差分 |
| [agent/platform/runners/__init__.py](../agent/platform/runners/__init__.py) | `RUNNERS` + `select_runner()`（口径校验的唯一入口） |
| [agent/platform/verify.py](../agent/platform/verify.py) | `--execute` 分支：选 runner → 取证据 → 同一判据 → 落 `verification.*` 事件 |
| [bin/platform.py](../bin/platform.py) | `verify --execute` 与 runner 参数（`--runner/--timeout/--isolation/--image-*/--exploit-cmd/--baseline-url`…） |
| [tests/test_platform_v2_p35.py](../tests/test_platform_v2_p35.py) | 26 项验收：三类 runner 的成功/失败/超时/证据哈希/口径越界，全部本地 fake |

## 2. 为什么要单独一层 runner

P3 的三条硬约束没有变，只是现在要能被**执行**触发，于是多出三个新问题：

| 问题 | P3 的做法 | P3.5 的答案 |
|---|---|---|
| 证据从哪来 | 调用方给文件/退出码/flag | runner 现场产出，字段口径与 P3 完全一致 |
| runner 说“通过”怎么办 | — | 不许：runner 只能写 `spec/checks/blockers`，`verified` 只由 `benchmark_policy` 推导 |
| 跑不动（超时/缺镜像/连不上） | 不知道 | `completed=False` + `runner_*` blocker + `runner.json` 证据，落 `needs_evidence` |

所以新增的包只有“执行”，没有“判定”：`grep -rn "verified" agent/platform/runners/`
只会命中两句解释性文档和一条“runner 与 benchmark 不符”的拒绝消息，
**没有任何一处给 `verified` 赋值**——这个字段在 `verify.py` 里由
`benchmark_policy` 唯一推导。

## 3. RunnerResult 契约

| 字段 | 类型 | 说明 |
|---|---|---|
| `runner` / `benchmark` / `kind` | str | 必须三者一致（`cybergym`↔`vuln_fix_diff` 等），否则 `RunnerError` |
| `completed` | bool | runner 是否跑到终点；**与判据成立与否无关** |
| `timed_out` | bool | 是否因超时收尾；`completed=True` 时不得为真 |
| `spec` | dict | 喂给 `verify.evaluate` 的判据输入（只含该 benchmark 自己的字段） |
| `checks` | dict | runner 观测到的事实（退出码、sanitizer 命中、状态码…） |
| `blockers` | list | 缺口/口径问题；**`completed=False` 时至少一条**（否则直接违约） |
| `evidence` | list | `{kind, path, sha256, size}`；verify 会重新哈希后入 `EvidenceStore` |
| `policy` | dict | 隔离模式、网络、超时、cap-drop/ro-root/pidns 快照 |
| `elapsed` / `detail` | float / dict | 耗时（秒）、每侧过程（argv 摘要、退出码、错误） |

落盘：每次执行（含失败）都写 `<workdir>/runner.json`（`schema=vulnmap.runner.v1`，
`outcome=completed|incomplete`），并作为 `verify_runner` 证据入库——
**没有任何一次执行是“查无实据”的**。

四条不变量（`RunnerResult.validate()` 代码强制）：

1. `runner == benchmark`，且都在 `RUNNER_NAMES` 里；
2. `completed and timed_out` 不能同时为真；
3. `not completed` 必须带 blocker（空 blocker 的失败会让结论无法解释）；
4. 结果序列化后不得出现确认类标签（与 `Verification` 同一条红线）。

## 4. 三类 runner

| benchmark | 准入输入 | 执行动作 | 产出判据输入 | 明确**不**做 |
|---|---|---|---|---|
| `cybergym` | `image_vul`、`image_fix`、`cmd`、`input_path`（可选 `docker`） | `docker run` 两侧各一次，同一个输入文件挂 `/input:ro` | `input{path,sha256}` + `vul{exit_code,log_path,asan}` + `fix{…}` | 不猜镜像命令、不跑 fix 端以外的第三端 |
| `exploitgym` | `host`+`port`（官方 socket）或 `exploit_cmd` | 连一次读干 / 跑一条本地命令 | `flag`、`flag_path`、`exploit{exit_code,log_path,source}` | 不要求 fix 端（EG-02 类）、不把超时当“没拿到 flag” |
| `vulngym` | `baseline_url`、`patched_url`（可选 `expect`） | 两侧各一次 HTTP（默认 GET） | `baseline{status,body_path,body_sha256}` + `patched{…}` + `expect` | 不跟跳转、不复用会话、不打第三个主机 |

### 4.1 CyberGym：同输入 + sanitizer

~~~text
docker run --rm --network none --read-only --cap-drop ALL
           --security-opt no-new-privileges --pids-limit 128 --memory 2g
           --tmpfs /tmp:rw,exec,nosuid,nodev
           -v <input>:/input:ro  <image>  <cmd...>
~~~

- **同输入不是口头的**：`input.sha256` 只算一次，两端 `input_sha256` 都取它，
  `checks.same_input` 直接反映这一点；
- **判据**：vul 端“非零退出 **或** 日志出现 sanitizer 签名（ASAN/LSAN/MSAN/TSAN/UBSAN/HWASAN、
  `runtime error:`、`SUMMARY: *Sanitizer`）”即崩溃信号；fix 端必须 0 退出且日志无 sanitizer；
- **ASAN 命中但退出码 0** 也算崩——这正是“只有退出码”会漏掉的一类；
- 镜像命令必须显式给：缺 `cmd` 时 runner 直接返回
  `runner_not_configured:cmd`（needs_evidence），不跑一个“什么都不做”的默认命令。

### 4.2 ExploitGym：flag 只按 `exploit_flag` 判

- 两条入口共用一份判据 spec；`exploit.source` 记 `socket` 或 `exploit_cmd`；
- flag 抽取只在**形态**层面匹配（`[A-Za-z]{2,12}{…}`），最终形态校验仍是
  `verify.FLAG_RE`，两者分开，避免 runner 自己“发明”合法 flag；
- 命令非零退出即使拿到 flag 也 `rejected`（`exploit_exit_nonzero`）：
  `flag_ok` 现在显式要求 `exploit_exit_ok is not False`，
  不再出现“blocker 里写着退出码非零、结论却 verified”的自相矛盾；
- 不产生任何 `vul`/`fix` 字段，EG-02 类不可能被双端规则误杀。

### 4.3 VulnGym：行为差分的三个坑

| 坑 | 处理 |
|---|---|
| 跳转被当成 200 | `HTTPRedirectHandler` 子类直接 `return None`，3xx 走 `HTTPError` 原样记状态码 |
| 宿主 `HTTP_PROXY` 把请求带出本机 | 显式 `ProxyHandler({})`，禁代理 |
| 连接被重置（“修补后直接断开”） | 记 `connection_closed=True`，这是**有效差分信号**，不是缺口 |

响应体截断到 1 MiB，`baseline.body` / `patched.body` 落盘，`body_sha256` 现场算。

## 5. 隔离 / 超时 / 网络策略

宿主侧包裹层复用 [agent/discovery/isolation.py](../agent/discovery/isolation.py)，
runner 只做“选模式 + 记录策略”：

| 模式 | 网络 | 硬化项 | 说明 |
|---|---|---|---|
| `auto`（默认） | `none` | bwrap：`--unshare-net/--unshare-pid/--die-with-parent/--cap-drop ALL/--ro-bind / /` | 有 bwrap 就 bwrap |
| | `none` | unshare：`--unshare-net` + `PR_SET_NO_NEW_PRIVS` | bwrap 不可用时 |
| `bwrap` / `unshare` | `none` | 同上，不可用直接报错 | 显式选择，不静默降级 |
| `none` | `host` | 无 | 显式选择；策略里写明 `network=host`，证据里可查 |
| `container` | — | — | **不在 runner 包裹层里**：CyberGym 跑的就是镜像，再套一层是 docker-in-docker |

- **fail-closed**：`require_isolation=True` 且只剩 `none` 时直接失败
  （`runner_unavailable:isolation`），不退回宿主执行；
- **超时**：默认 60 s/步，上限 3600 s；超时按**进程组**收（`setsid` + `killpg`），
  避免 docker 客户端被杀、容器还在跑；
- **网络**：CyberGym 容器 `--network none`；VulnGym 只连 spec 里声明的两个 URL、
  不跟跳转、禁代理；ExploitGym 只连声明的 `host:port`（或跑一条本地命令）；
- **资源**：`--pids-limit 128`、`--memory 2g`、`--read-only`、`--tmpfs /tmp`，
  宿主侧 `RLIMIT_CORE=0`（ASAN 需要大地址空间，因此**不设** `RLIMIT_AS`）。

策略快照进 `detail.execution.policy` 与 `runner.json`，
每一份“通过”的证据都能回答“它在什么隔离/网络/超时下跑出来的”。

## 6. `verify --execute` 编排

~~~text
verify(execute=True)
  ├─ select_runner(benchmark, name)          # 名字≠benchmark → RunnerMismatch（契约错误，不落记录）
  ├─ runner.safe_run(spec)                   # 任何异常 → failure()（带 blocker），不抛
  │    └─ record(runner.json)                # 失败也落证据
  ├─ normalize_spec(runner.spec)             # 与 P3 同一个口径门
  ├─ EVALUATORS[benchmark](bound_spec)       # 与 P3 同一套判据
  ├─ _merge_execution(...)                   # 只做与运算（见下）
  └─ verification.executed → verification.recorded → verification.verified|failed
~~~

合并规则（`_merge_execution`，只削弱不增强）：

~~~text
verified = 判据成立
       and runner.completed
       and not runner.timed_out
       and runner.blockers 为空
       and 判据自己的 blockers 里没有口径类（reject）项
status   = verified ? verified : _status(blockers)
~~~

- runner 失败（超时/缺 docker/连不上）→ 追加 `runner_*` blocker + `runner_incomplete`
  → `needs_evidence`，任务落 `NEEDS_EVIDENCE`；
- runner 跑完但证据为负（fix 也崩、两侧行为一致）→ 判据自己给 `no_repro`；
- 口径不符（runner 名与 benchmark 不符、证据字段混用）→ **不落记录**，CLI 退出码 2。

`target_yaml` 没有 runner：`--execute` 会落一条 `rejected`（
`runner_unavailable:target_yaml` + `unsupported_benchmark:target_yaml`），
不假装跑过。

## 7. 事件与状态

| 阶段 | 事件 | payload 要点 |
|---|---|---|
| 执行 | `verification.executed` | `runner/completed/timed_out/isolation/network/blockers/evidence[]` |
| 落库 | `verification.recorded` | 与 P3 相同（`verification_id/status/verified/blockers/evidence_sha256`） |
| 结论 | `verification.verified` / `verification.failed` | 与 P3 相同 |

状态机**没有新增状态**：`CANDIDATE → VERIFYING`，失败仍落
`NO_REPRO / NEEDS_EVIDENCE / REJECTED`。`verification.executed` 不参与
`EventBus.replay` 的状态重建（replay 只认 `state.changed`）。

主证据口径不变：CG = vul 日志、EG = flag 文件、VG = patched 响应体；
`verify_runner` 只是“这次是怎么跑出来的”的补充证据。

## 8. 使用示例

~~~bash
DB=.platform/platform.db

# CyberGym：docker 跑双端（同输入），现场判定
python3 bin/platform.py --db $DB verify cg01 --execute \
  --image-vul arvo:44034-vul --image-fix arvo:44034-fix \
  --input rsp.bin --cmd=/bin/sh --cmd=-c --cmd="/workspace/reproduce /input" \
  --timeout 120 --isolation auto

# ExploitGym：官方 socket
python3 bin/platform.py --db $DB verify eg02 --execute \
  --host 127.0.0.1 --port 9009 --expected-flag 'FLAG{...}'

# ExploitGym：本地利用命令（shell 规则拆分 argv）
python3 bin/platform.py --db $DB verify eg02 --execute \
  --exploit-cmd 'python3 exploit.py --target 127.0.0.1:9009' \
  --expected-flag 'FLAG{...}'

# VulnGym：基线 / 修补行为差分
python3 bin/platform.py --db $DB verify vg01 --execute \
  --baseline-url http://127.0.0.1:8080/api/items \
  --patched-url  http://127.0.0.1:8080/api/items \
  --expect-baseline-status 200 --expect-patched-status 403

# 不看现场、只校验既有证据（P3 行为，逐字兼容）
python3 bin/platform.py --db $DB verify cg01 \
  --input rsp.bin --vul-exit 1 --vul-log vul.log --fix-exit 0 --fix-log fix.log
~~~

退出码：`--execute` 下仍是 **0 已成立 / 1 未成立（记录已落库）/ 2 口径或顺序错误**。

## 9. 验收

~~~bash
python3 -m pytest tests/test_platform_v2*.py -q
# 87 passed（P0 7 + P1 13 + P2 11 + P3 11 + P4 19 + P3.5 26）
~~~

全部测试使用**本地 fake**：docker 用 `#!/usr/bin/env python3` 的假可执行文件
（按镜像名回放退出码/输出/延时），ExploitGym 用本地 TCP 服务与本地脚本，
VulnGym 用本地 `ThreadingHTTPServer`；不访问任何真实 benchmark 网络。

| 测试 | 钉住的事实 |
|---|---|
| `test_cybergym_execute_success` | 双端同输入 → verified；`verify_vul_log/fix_log/runner.json` 入库且哈希可复算；主证据 = vul 日志；`verification.executed` 只发一次 |
| `test_cybergym_execute_fix_crashes_is_negative` | fix 也崩 → `no_repro`（`local_dual_run_failed` + `fix_sanitizer_reported`），runner 本身 `completed=True` |
| `test_cybergym_execute_timeout_is_gap_not_negative` | 超时 0.4 s 收尾（<4.5 s）、`needs_evidence`、`runner_timeout:vul`、证据仍可查 |
| `test_cybergym_execute_missing_docker_records_blocker` | docker 不存在 → `runner_unavailable:*` + `needs_evidence`，不抛异常、不丢记录 |
| `test_cybergym_execute_missing_image_command_is_gap` | 缺 `cmd` → `runner_not_configured:cmd`，不跑假默认命令 |
| `test_cybergym_execute_input_binding_still_enforced` | 执行模式不绕过输入绑定：输入与候选不符 → `rejected` |
| `test_exploitgym_socket_mode` | socket 取到 flag → verified、`dual_required=False`、无 `local_dual_run_failed`、主证据 = flag |
| `test_exploitgym_socket_flag_mismatch_is_rejected` | flag 与官方值不符 → `rejected` |
| `test_exploitgym_socket_timeout_is_gap` | 对端不说话 → `runner_timeout:socket` + `needs_evidence` |
| `test_exploitgym_connection_refused_is_gap` | 拒连 → `connection_failed:*`，仍写记录与 `runner.json` |
| `test_exploitgym_exploit_cmd_mode` | 本地命令取 flag → verified |
| `test_exploitgym_cmd_nonzero_exit_is_rejected` | 拿到 flag 但退出码非零 → `rejected`（不再出现“blocker 非零、结论成立”） |
| `test_vulngym_behavior_diff` | 200 vs 403 → verified；主证据 = patched 响应体 |
| `test_vulngym_same_behavior_is_negative` | 两侧一致 → `no_repro` |
| `test_vulngym_direction_mismatch_is_negative` | 状态码变了但方向不符 `expect` → `no_repro` |
| `test_vulngym_timeout_is_gap` | 修补端超时 → `runner_timeout:patched` + `needs_evidence` |
| `test_vulngym_invalid_url_is_rejected` | `file://` 之类非 http(s) → `runner_spec_invalid` + `rejected` |
| `test_runner_selection_and_contract` | 跨 benchmark / 未知名 → `RunnerMismatch`/`RunnerError`；空 blocker 的失败违约 |
| `test_cross_benchmark_runner_is_contract_error` | CLI/API 混用 runner 不落半成品记录，任务停在 CANDIDATE |
| `test_execute_mode_without_runner_support_degrades` | `target_yaml` 无 runner → rejected，不假装跑过 |
| `test_evidence_mode_unchanged_without_execute` | 不传 `--execute` 时无 `verification.executed`、`mode=evidence` |
| `test_cli_verify_execute` | CLI 全链路：fake docker → 退出码 0 → 记录落库可重开 |
| `test_cli_verify_execute_contract_error_exit_2` | 口径错误 → 退出码 2 且零残留 |
| `test_sanitizer_signature_detection` | ASAN/UBSAN/`runtime error:` 都能识别，干净日志不误报 |
| `test_runner_spec_outside_criterion_is_rejected` | runner 递别的 benchmark 字段 → 口径门拒绝（`runner_spec_invalid` + `rejected`），执行快照照样入库 |
| `test_runner_json_never_carries_verdict_labels` | `runner.json` 只有执行快照，没有 `verified`/`verdict`/确认类字段 |

## 10. 边界（P3.5 刻意不做）

- **不接真实 benchmark 网络**：默认整套都是本地可复现的 runner；真镜像/真 socket
  由使用者在自己的环境里给参数，不在 CI 里跑；
- **不做 build**：CyberGym runner 假设镜像已就绪（build 仍属 P2/后续 adapter），
  缺镜像就是缺口，不当负结果；
- **不判“漏洞是否存在”**：runner 无 `verified` 字段可写，判据永远只有
  `benchmark_policy` 一个事实源；
- **不写 `confirmed`**：与 P3 同一条红线，`RunnerResult.validate()` 与
  `Verification.validate()` 各挡一次；
- **不改 Discovery / vulnmap_platform / 旧案例**：仅新增 `runners/` 与
  `verify.py`/`bin/platform.py` 的 execute 分支；
- **不做并发编排**：一次 `verify --execute` 跑一个 runner、一条验证记录；
  批量/队列留给后续 runtime。
