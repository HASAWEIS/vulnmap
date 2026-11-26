# 平台 v2 P3.7：源码包自动解包 + 旧 PoC 重放 —— 让“仓里已有答案”真的能跑一遍

> 范围：P1 的 ProgramIndex 在 CG/EG 上留了一个空档——ARVO workspace 常常只带
> `repo-vul.tar.gz`，`src/` 是空的，于是 `source_count=0`、D0/D1 什么都看不到；
> P2 的 planner 在这种情况下会选 `kind=replay`（“先恢复工作区再重放”），
> 但 replay **没有执行器**，只能停在 PLANNED 或 FAILED。
> P3.7 把两头补上：
> **① understand 自动解包并把解包树接进 D0/D1；② replay 执行器把旧案例的 PoC + 日志重跑一遍，
> 产出 Candidate 与可直接喂 `verify --spec` 的判据输入。**
> 一句话：**不重新造输入，也不假装已经验证。**
> 前置：[PLATFORM-V2-P1.md](PLATFORM-V2-P1.md) 的 ProgramIndex、
> [PLATFORM-V2-P2.md](PLATFORM-V2-P2.md) 的 Plan/执行编排、
> [PLATFORM-V2-P35.md](PLATFORM-V2-P35.md) 的判据口径、
> [PLATFORM-V2-P36.md](PLATFORM-V2-P36.md) 的预算/取消、
> [PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §3 状态机。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/program.py](../agent/platform/program.py) | `unpack_archive()` / `ensure_sources()` / `discover_archives()` / `find_src_root()`：内容寻址缓存 + 成员白名单 + 原子换入；`image_state()`：镜像 digest 只做审计；ProgramIndex 新增 `images` / `unpack` / `warnings` 三个字段 |
| [agent/platform/executors/replay.py](../agent/platform/executors/replay.py) | `discover_pocs()`（只读发现旧 PoC + 绑定旧日志）、`execute()`（命令/docker 二选一，超时按进程组收，产出崩溃记录 + 判据 `spec`）、`ReplayError` |
| [agent/platform/executors/__init__.py](../agent/platform/executors/__init__.py) | `kind_override` / `replay_cmd` 两个新参数；按 kind 分派（fuzz 原路径逐字保留，static/dynamic 仍 fail-closed）；replay 证据 kind `replay_input` / `replay_log` / `replay_spec`，`exec_stats` 增 `replay` 段 |
| [agent/platform/planner.py](../agent/platform/planner.py) | CG/EG 分支先探测旧 PoC → **优先 `kind=replay`**；`inputs.replay` 记 PoC 台账（含旧日志 + 哈希） |
| [agent/platform/hypotheses.py](../agent/platform/hypotheses.py) | `run_understand(..., unpack_root=)` 透传解包缓存根 |
| [bin/platform.py](../bin/platform.py) | `understand --unpack-cache`；`run --kind {static,dynamic,fuzz,replay}` + `--replay-cmd` |
| [tests/test_platform_v2_p37.py](../tests/test_platform_v2_p37.py) | 22 项验收：临时 tar.gz 解包/缓存/路径穿越/源文件计数/digest warning/replay 三态/CLI 端到端 |

## 2. 为什么“解包”属于程序理解，而不是构建

P1 在 `src/` 为空时的行为是**诚实的空结果**：`source_count=0`、`coverage.status=partial`、
notes 里写“repo-vul.tar.gz 未解包”。这留下三个洞：

| 洞 | 后果 | P3.7 的答案 |
|---|---|---|
| 程序理解看不见源码 | `functions/call_sites/entry_points` 全空，假设集没有落点 | 解包树直接喂 D0/D1，`source_count/entry_points/call_sites` 来自真实源码 |
| planner 的 replay 无法执行 | 选了 replay 也跑不动，只能 FAILED | replay 执行器接上（见 §5） |
| “解包过没有”不可复算 | 换台机器重跑结果可能不同 | 缓存键是**包内容哈希**，`unpack` 元数据进 ProgramIndex（含 sha256/files/bytes/cached） |

关键取舍：**不改案例目录**。解包只写 `<workspace>/.unpacked/<sha256[:16]>/`，
workspace 自带的 `src/` 不被覆盖、不被当成“构建产物”；缓存目录在扫描时被跳过，
不会反过来被当成“工作区源码”（否则第二次 understand 会索引缓存树，得到另一套路径）。

## 3. 解包规则

### 3.1 缓存与原子性

~~~text
<workspace>/repo-vul.tar.gz          # 案例原始包，只读
        ↓ sha256(包内容)
<workspace>/.unpacked/<sha[:16]>/
    ├── demo/src/a.c …               # 解包树
    └── manifest.json                # {schema, archive, sha256, files, bytes, src_rel}
~~~

- **缓存键 = 包内容 sha256**：同包第二次 understand 直接命中（`unpack.cached=true`，不重写树）；
- **两次落盘**：先解到 `.unpacked/.tmp-<rand>/`，校验通过后 `os.replace` 原子换入；
  中途失败只删临时目录，不会留下“半个可用缓存”；
- **manifest 只记相对路径**（`src_rel`），换机器/换挂载点也能命中；
- **src_root 探测**：`<root>/src` → `<child>/src` → 含源文件的最浅目录；
  找不到源文件就退回解包根，由 `_source_files` 全量兜底（仍受 `max_sources` 限制）。

### 3.2 成员校验（先全量校验，再写盘）

| 成员形态 | 处理 | 理由 |
|---|---|---|
| 绝对路径 `/etc/passwd`、`//host/share` | `UnpackError` | 写入点跑出根 |
| `..` 段（`../x`、`a/../../x`） | `UnpackError` | 路径穿越 |
| Windows 盘符 `C:/…`、路径反斜杠归一后含 `..` | `UnpackError` | 跨平台绕过 |
| 含 NUL、空名 | `UnpackError` | 解析歧义 |
| 符号链接 / 硬链接 / 设备 / FIFO | `UnpackError` | 链接是“把写入点/读取点挪到根外”的第二种写法 |
| 成员数 > 200 000、解包总字节 > 2 GiB | `UnpackError` | gzip 炸弹/整卷包 |
| 不是 tar / gzip 截断 | `UnpackError` | 包损坏 |

> 不做“就地修正”（把 `..` 抹掉再解）：那会把攻击包静默变成另一棵树，
> 审计时看不出来。宁可让 understand 失败。

写盘后还有一道 realpath 复核：所有文件解析后的真实路径必须在解包根内，
树里出现符号链接也直接报错（防御性检查）。

### 3.3 失败语义

`UnpackError` 是**硬错误**：`run_understand` 落 `FAILED`（reason 带异常类型），
不会静默退回 `source_count=0`。理由与 P2/P3.6 一致：
“包解不开”和“包里没源码”是两件事，不能都写成“没有程序可理解”。

## 4. 镜像 digest：审计字段，不是闸门

P1 的 ProgramIndex 只描述源码；镜像属于“这套源码会在哪个环境里跑”，
是 Case Pack 复盘时必需、但**不该阻断静态索引**的事实。

- 来源：`casekit.image_for(ws, side)`（CG：`n132/arvo:<n>-vul|fix`；EG：`cybergym/arvo:<n>-vul.<mode>-nogit`，只有 vul 侧）
  → `checkpoint.image_digest()`（`docker image inspect`）；
- 落点：`ProgramIndex.images = {"vul": {name, digest, present}, "fix": {...}}`；
- 失败路径：缺 docker / 镜像不在本地 / inspect 超时 → `digest=""`、`present=false`、
  `warnings` 记一条 `docker inspect <image> 未取到 digest：…`，`notes` 同步提示；
  **索引照常生成、照常 validate**；
- 进程内按 `(workspace, benchmark)` 缓存，同一任务多次构建只 inspect 一次。

这条边界很重要：P3.5 的 runner 才是“镜像必须存在”的地方（缺镜像 → `runner_unavailable`
blocker）。ProgramIndex 只记账，不替 runner 做准入判断。

## 5. replay 执行器

### 5.1 发现旧 PoC（只读）

`discover_pocs(workspace)` 扫这些目录的**直接子文件**（不递归）：

~~~text
artifacts/verify  artifacts/poc  artifacts/crash  artifacts/crashes
artifacts/exploit poc  pocs  crash  crashes  candidates
~~~

- 认领条件：普通文件、`0 < size ≤ 4 MiB`、后缀 ∈ `.bin/.pdf/.pdfi/.ps/.poc/.input/.dat/.crash`，
  或文件名以 `poc` / `crash` / `case` 开头；`.json/.log/.md/.txt` 一律排除；
- **旧日志绑定**（三级回退，都算 sha256）：
  `logs/<stem>.log` → `logs/*<stem>*vul*.log` → 同目录 `<stem>.log`；
- `artifacts/verify/result.json` 里声明的 `poc.path` 排**最前**（唯一带旧 `vul.exit_code` 的条目，
  记为 `known_exit`）；
- 按 `sha256` 去重（后出现条目的 `log`/`known_exit` 补空字段），最终排序
  `(source, path)` 确定性——同一工作区多次调用结果完全一致。

CG-01 实测：`artifacts/verify/pdf-basefont4096.bin`（8882 B，
sha256 `58f7f4b3d8ca…`）+ `logs/V4.pdf-basefont4096.44034-vul.log`（sha256 `79458c59…`），
`known_exit=1`。

### 5.2 选择与执行

| 步骤 | 规则 |
|---|---|
| 选 PoC | 显式 `poc` 参数 → `plan.inputs.replay.poc_path` → `discover_pocs()` 第一条 |
| 命令来源（按序） | `--replay-cmd` → `plan.inputs.replay.cmd` → 环境变量 `VULNMAP_REPLAY_CMD` → docker |
| 命令模板 | 含 `{poc}` 的 token 替换成**宿主** PoC 绝对路径；不含则原样执行（不偷偷追加参数） |
| docker 模式 | `docker run --rm --network none -v <poc>:/tmp/poc:ro <image> /bin/arvo`（`argv` 可覆盖） |
| 超时 | `--timeout` → `plan.inputs.replay.timeout` → `plan.budget.timeout`，上限 3600 s |
| 进程管理 | `start_new_session=True`，超时按**进程组** SIGKILL，绝不留下跑飞的容器/子进程 |
| 日志 | 合并 stdout/stderr，只留尾部 2 MiB；落 `workdir/replay/<poc_sha[:12]>.log` |

### 5.3 崩溃判定与栈签名

- `crashed = exit_code != 0 or 命中 sanitizer 文本`（ASAN/MSAN/UBSAN/TSAN 签名表与 P3.5 同口径）；
- `crash_type`：`ERROR: AddressSanitizer: <type>` → `SUMMARY: …Sanitizer: <type>` →
  UBSAN `runtime error:` → 兜底 `replay_nonzero_exit`；
- `stack_hash = sha256("replay:" + crash_type + ":" + 归一化前三个栈帧)`，
  帧文本是 `function@basename:line`（抹掉地址/绝对路径）。
  **这是 replay 自己的签名，不冒充 D3 的 sha1 口径**——两套执行环境的栈不能假装同源，
  去重只在 replay 内部生效。

### 5.4 判据输入（喂 `verify --spec`）

| benchmark | `spec` 形状 |
|---|---|
| cybergym | `{benchmark, input:{path,sha256}, vul:{exit_code,log_path,crashed,asan}, fix:{}, replay:{poc_source,source_log}}` |
| exploitgym | `{benchmark, input:{…}, exploit:{exit_code,log_path}, flag:<形态抽取>, replay:{…}}` |
| target_yaml / vulngym | `{benchmark, input:{…}, replay:{…}}`（本仓没有对应判据，不伪造字段） |

两个易错点：

1. **`vul.asan` 必须给**：`evaluate_cybergym` 的 `vul_crashed = exit != 0 or vul.asan`。
   只写退出码会让“sanitizer 命中但退出码 0”出现 replay 说崩、verify 说没崩的分裂；
2. **`fix` 留空**：单侧重放不伪造修补端，`verify` 会落 `needs_evidence`
   （`fix_exit_not_recorded`）——这是正确结论，不是缺陷。

### 5.5 fail-closed 一览

| 情况 | 异常 | 状态 |
|---|---|---|
| 没有旧 PoC | `ReplayError("replay_no_poc: …")` | `FAILED`（不落 NO_REPRO） |
| 无 docker 且无命令 | `ReplayError("replay_no_executor: …")` | `FAILED` |
| 命令/可执行文件不存在 | `ReplayError("replay_no_executor: cannot spawn …")` | `FAILED` |
| 超时 | `ReplayError("replay_timeout: …")` | `FAILED` |
| `require_isolation=True` 且 `isolation="none"` | `ReplayError("replay_isolation: …")` | `FAILED` |
| PoC 空文件 / > 4 MiB | `ReplayError("replay_no_poc: …")` | `FAILED` |

“跑不动”永远不是“不可复现”：`NO_REPRO` 只出现在**重放跑完但没崩**的情况。

## 6. 编排与状态机

`run_execution()` 新增两个参数，其余口径不动：

- `kind_override`：本次执行换一种方式（`static/dynamic/fuzz/replay`）；
- `replay_cmd`：只给 replay 分支的命令模板。

事件与证据：

~~~text
exec.started   payload.kind = effective_kind
               payload.kind_override / replay_cmd（空串也记，便于审计）
               payload.caps（P3.6 的秒数夹紧/额度上限，原样保留）
exec.finished  payload.kind / outcome / replay{poc_sha256,exit_code,method,
               source_log,crashed,poc_source,spec_evidence_sha256}
evidence       replay_input（PoC 原始字节）
               replay_log（本次重放输出）
               replay_spec（判据输入 JSON，可直接 verify --spec）
               exec_stats（含 replay 段）
               exec_error（失败时）
~~~

候选：沿用 `build_candidates()` 的去重/编号，额外写
`detail.source="replay"`（不再冒充 `fuzz:d2`）与
`detail.replay{poc_source,poc_sha256,source_log,source_log_sha256,method,exit_code,log_path}`。

状态迁移：

~~~text
PLANNED → RUNNING → CANDIDATE   （重放崩了，产 1 条候选）
                  → NO_REPRO    （重放跑完没崩）
                  → FAILED      （ReplayError：没跑起来）
                  → CANCELLED / TERMINATED   （P3.6 原有路径，逻辑未改）
~~~

replay 分支同样走 `guard.absorb(execs=1)` 结算；`stopped="completed"` 所以
`_STOP_BUDGET_KEY` 天然不触发，但取消/超限语义与 fuzz 完全一致。

## 7. planner 与 CLI

### planner

CG/EG 分支的分层判定（确定性，不看网络）：

1. 工作区有旧 PoC → `kind=replay`，reason 写明「旧 PoC 重放优先」+ 首选条目的
   source/sha256/字节数（绑定了旧日志时额外说明）；
2. 没有源码树 → `kind=replay`（保持 P2 原判据）；
3. 有源码 + 入口/调用点 → `kind=fuzz`；有源码但没识别到入口 → `kind=replay`。

`Plan.inputs.replay`：

~~~json
{"pocs": [{"path": "...", "source": "artifacts/verify/result.json",
           "sha256": "...", "size": 8882,
           "log": "logs/V4.pdf-basefont4096.44034-vul.log",
           "log_sha256": "..."}],
 "poc_path": "...", "cmd": "", "argv": []}
~~~

> 注意第 1 条优先于第 3 条：**有旧 PoC 就不再重新 fuzz**。
> 重放是“同一输入重跑”，比从零 fuzz 更确定，也不会引入新变量。

### CLI

~~~bash
# 只有源码包的工作区：understand 自动解包（可选 --unpack-cache 指定缓存根）
python3 bin/platform.py understand cg01 --unpack-cache /tmp/unpack

# 有旧 PoC：plan 选 replay，run 用本地驱动或 docker 重放
python3 bin/platform.py plan cg01
python3 bin/platform.py run cg01 --kind replay \
    --replay-cmd 'python3 local_arvo.py {poc}' \
    --workdir .platform/work/cg01 --evidence-root .platform/evidence

# 判据输入直接喂 verify（仍只是 candidate，verified 由 benchmark_policy 推导）
python3 bin/platform.py verify cg01 --spec <replay_spec 证据路径>
~~~

## 8. 验收

`tests/test_platform_v2_p37.py`（22 项）：

| 组 | 覆盖 |
|---|---|
| 自动解包 | 临时 tar.gz → 缓存目录/`unpack` 元数据/D0-D1 真的吃到（`source_count`/`entry_points`/`call_sites`/`sources`） |
| 缓存 | 第二次构建 `cached=true`、manifest 未被重写 |
| 优先级 | workspace 自带 `src/` 时不解包（避免双份索引） |
| 路径穿越 | `../x`、`a/../../x`、绝对路径、盘符、反斜杠变体、符号链接全部 `UnpackError`；workspace 外零写入、无“可用缓存”残留 |
| 坏包 | 非 tar 字节 → `UnpackError`；ProgramIndex 构建失败且不留缓存 |
| 镜像 digest | 成功写 `images.vul/fix`；`docker inspect` 失败只 `warnings`，索引仍 validate；EG 只声明 vul 侧 |
| planner | 有旧 PoC → `kind=replay`，reason 含「旧 PoC」「优先」，`inputs.replay.pocs` 带 sha256+log |
| replay 成功 | 候选 1 条、`input_sha256` 与 PoC 一致、`crash_type=stack-buffer-overflow`、`detail.source=replay`、证据 kind 齐、`replay_spec` 可被 `normalize_spec("cybergym", …)` 接受 |
| replay 失败 | 无执行手段 / 无 PoC → `ReplayError` + `FAILED` + `exec_error` 证据 + 无候选；`--kind static` fail-closed |
| replay 干净 | 退出码 0 且无 sanitizer → `NO_REPRO` |
| CLI | `understand` 解包（`source_count`/notes）→ `plan` 选 replay → `run --kind replay --replay-cmd` → CANDIDATE |

口径：`python3 -m pytest tests/test_platform_v2*.py -q` → **125 passed**
（P0 7 + P1 13 + P2 11 + P3 11 + P3.5 26 + P3.6 16 + P3.7 22 + P4 19）。

真实样本复核（不联网、不跑容器）：

~~~bash
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from pathlib import Path
from agent.platform.executors.replay import discover_pocs
for p in discover_pocs(Path('workspace/CG-01-arvo-44034')):
    print(p['source'], p['sha256'][:12], p['size'], p['known_exit'], p['log'])
PY
# artifacts/verify/result.json 58f7f4b3d8ca 8882 1 logs/V4.pdf-basefont4096.44034-vul.log
~~~

## 9. 边界（没做什么）

- **不碰 Discovery 核心**：D0/D1 只被复用，解包只是把“根目录”换成一个可读的源码树；
- **不改 API/UI**：P3.7 只动 `agent/platform/` 与 `bin/platform.py`；
- **不做构建**：解包不跑 `build.sh`，也不解压 fix 侧源码包（P3.7 只需要“能静态理解 + 能重放”）；
- **不伪造验证**：replay 只产 Candidate + 判据输入，`verified` 仍由
  [benchmark_policy.py](../agent/benchmark_policy.py) 唯一推导；`fix` 端留空 → `needs_evidence`；
- **不联网**：docker 模式显式 `--network none`；命令模式网络=host 的事实写进 `policy.network`；
- **不自动清理缓存**：`.unpacked/` 由内容哈希寻址，重跑可复用；清理交给运维
  （删目录即可，下次 understand 重新解包）。
