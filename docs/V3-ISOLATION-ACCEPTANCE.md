# V3 隔离验收：隔离是跑出来的事实，不是计划里的一行字

> 适用范围：`agent/platform/adaptive/workspace.py`（构建/冒烟的隔离执行与记录）、
> `agent/platform/adaptive/handoff.py`（平台侧隔离验收记录 + `ProposalGate`）、
> `agent/platform/store.py`（`isolation_acceptance` 台账）、
> `tests/test_v3_isolation_acceptance.py`、`docs/V3-W3-HANDOFF.md` §6、本文。
> 本文是「隔离怎么跑、怎么记、凭什么放行」的**唯一出处**；第 2 周配置口径见
> `docs/V3-W2-CONFIG.md`，第 3 周交接口径见 `docs/V3-W3-HANDOFF.md`，三套字段
> 互不冒充。
> **不动**：`agent/platform/verify.py` 的判据、`benchmark_policy`、执行器
> （fuzz/replay/dynamic）的执行语义。

---

## 0. 这一版解决什么

先有执行、再有结论。但“在隔离里跑的”这句话以前可以是三层假象：

| 假象 | 后果 |
|---|---|
| 构建/冒烟在宿主 `subprocess` 里跑，报告里写“隔离执行” | 目标代码能写工作区外、能连网络、能靠 setuid 提权；报告里却是一条“隔离内事实” |
| 隔离写在**计划**里（配置项/命令行参数），记录里没有“实际用了什么” | 计划 `bwrap`、实际 `none`，两者在账本上长得一样 |
| 放行只读任务提交者填的 `metadata.isolation_accepted` | 提交者自己写 `"yes"` 就把自己放行了 |

这一版把三件事拆开并可复算：

1. **执行 fail-closed**：`TaskWorkspace` 构建/冒烟前先 `isolation.resolve()`，
   解析结果必须是**强隔离**（`bwrap` / `container`）；`auto` 降级到 `unshare`、
   显式 `unshare`、`none` 一律 `WorkspaceError(strong_isolation_required)`，
   **一个命令都不跑**，绝不回退弱隔离或宿主 `subprocess`；
2. **实际隔离进记录**：`IsolatedBuildRecord` / `IsolatedSmokeRecord` 带
   `isolation` / `network` / `cap_drop` / `ro_root` / `executed_isolated`，
   并逐次追加 `isolation-executions.jsonl` 台账；计划只留在 `workspace.json`
   的 policy 里，**写不出 `executed_isolated`**；
3. **放行只认平台侧记录**：`ProposalGate` 只读
   `PlatformStore.isolation_acceptance`（或 `isolation-acceptance.jsonl`）里的
   `accepted` 记录——带检查项、证据哈希、时间，改一个字节就复算不上；
   提交者自填字段只留 `declared`（advisory）。

一句话：**没跑过的隔离不算隔离，自己说的验收不算验收。**

---

## 1. 隔离执行器阶梯（模式探测在 `agent/discovery/isolation.py`，强隔离判据在 `workspace.py`）

| 模式 | 断网 | cap-drop | 只读根 | PID ns | no_new_privs | 强隔离（能承载 build/smoke） |
|---|---|---|---|---|---|---|
| `bwrap`（`auto` 首选） | `--unshare-net` | `--cap-drop ALL` | `--ro-bind / /` | `--unshare-pid` | bwrap 自带 | ✅ 是 |
| `unshare`（显式低保证） | `--unshare-net` | ❌ | ❌ | ❌ | preexec `prctl` | ❌ 不是（见 §8） |
| `container`（显式） | `--network none` | `--cap-drop ALL` | `--read-only` | `--pids-limit` | `no-new-privileges` | ✅ 是（要引擎+镜像） |
| `none` | host | ❌ | ❌ | ❌ | ❌ | ❌ 永远不是 |

```python
STRONG_ISOLATION_MODES       = ("bwrap", "container")
QUALIFIED_ISOLATION_MODES    = STRONG_ISOLATION_MODES   # 旧名保留，语义收窄为“强隔离”
LOW_ASSURANCE_ISOLATION_MODES = ("unshare",)
```

**这是“能不能跑”的判据，不是推荐列表**：

- `auto` 只在 `bwrap` 可用时通过；**只剩 `unshare` 时不再“降级但继续”**，而是
  `WorkspaceError(strong_isolation_required)`——命令不执行、工作区外不写标记、
  `builds/` 不复制、build/smoke 记录与 `isolation-executions.jsonl` 都不落行；
- `unshare` 只能作为**显式低保证模式**用于 discovery 执行器（`--isolation unshare`
  的知情降级，见 `docs/DISCOVERY-V1.md`），**不能承载 workspace 的自动应用**
  （`build()` / `smoke()`），也不因为“显式指定”就变成强隔离；
- `none` 永远不合格：宿主执行的产物不能进隔离结论。

### 1.1 `TaskWorkspace` 的参数

```python
TaskWorkspace(root, *, task_id, build_command=(), smoke_command=(),
              isolation="auto", require_isolation=True)          # 默认 fail-closed
TaskWorkspace.create(root, origin, *, ..., isolation="auto", require_isolation=True)
TaskWorkspace.open(root)      # policy 从 workspace.json 读回（重启后同口径）
```

| 情形 | 结果 |
|---|---|
| `isolation` 不在 `MODES` 里 | 构造即 `WorkspaceError: unknown isolation mode` |
| `isolation="none"` 且 `require_isolation=True` | 构造即 `WorkspaceError: strong_isolation_required`（拒绝建立会假装隔离的工作区） |
| `isolation="none"` 且 `require_isolation=False` | 允许建工作区（policy 可留痕），但 `build()` / `smoke()` 仍在 spawn 前 `strong_isolation_required`——`none` 永远不承载自动应用 |
| `isolation="auto"` 解析到 `unshare` | `build()` / `smoke()` 抛 `WorkspaceError: strong_isolation_required`，命令未执行、无记录、无台账 |
| `isolation="unshare"`（显式） | 同上：不管 `require_isolation` 真假，build/smoke 都在 spawn 前拒绝 |
| `resolve()` 抛 `RuntimeError`（bwrap 缺失 / 引擎不可用） | `WorkspaceError: isolation_unavailable`（错误里带原因），命令未执行 |
| `require_isolation=True` 但解析出的 `network != "none"` | `WorkspaceError: strong_isolation_required`（“有网络 = 不算强隔离”） |

`require_isolation=False` 只影响 `resolve()` 是否因 `none` 抛错，**不放松强隔离判据**：
workspace 的 build/smoke 是自动应用路径，弱隔离没有入口。

### 1.2 一次隔离执行的顺序（硬约束）

```
_write_guard(grant)
  → isolation.resolve(mode, require=True)          # 解析结果必须是强隔离
  → 强隔离判据（bwrap/container）                    # 不合格就地抛错，磁盘/进程都不碰
  → 解析 revision → 命令存在？
  → 复制 revision 快照到 builds/<rev>-<n>/
  → _clean_env({}, home=root/"home")               # 只给 PATH/LANG/TZ/HOME/TMPDIR
  → prefix_for(info, workdir, home) + preexec(info, budget)
  → subprocess.run(argv, cwd=workdir, shell=False)
```

- **前缀**：`prefix_for()` 产出的隔离器参数 + 目标命令；`bwrap`（以及 discovery
  执行器里的 `unshare`）用 `--` 分隔，`container` 用 `docker run … IMAGE cmd`；
- **可写绑定只覆盖真正要落盘的目录**：本次构建目录 `builds/<rev>-<n>/` 与工作区
  `home/`（`HOME`/`TMPDIR` 都在里面）；其余（含 `/tmp`）在只读根下；
- **preexec**：`setsid` + `RLIMIT_CORE=0` + `RLIMIT_CPU/FSIZE/NOFILE`；
  discovery 执行器的 `unshare` 额外 `prctl(PR_SET_NO_NEW_PRIVS,1)`；容器模式不设
  CPU/NOFILE（那会杀 docker 客户端），资源上限交给 `--pids-limit/--memory`；
- **顺序不可换**：强隔离判据是**第一道闸**，在解析 revision、复制快照之前——
  判据失败时工作区里连 `builds/<rev>-<n>/` 都不会出现，测试据此断言“命令一次都
  没跑、标记没写、台账没有行”。`smoke()` 同样把强隔离判据放在最前面：弱隔离下
  连构建记录都不读，哪怕手里已经有一条“自报隔离”的记录也不允许启动。

---

## 2. 记录：实际隔离在哪一行

### 2.1 `IsolatedBuildRecord` / `IsolatedSmokeRecord`

`revision.py` 的 `BuildRecord` / `SmokeRecord` 只描述结果；`workspace.py` 用**子类**
追加隔离事实（不改基类、不改账本格式）：

| 字段 | 来源 | 语义 |
|---|---|---|
| `isolation` | 本次 `resolve()` 的 `mode` | 实际用的执行器（`bwrap`/`container`；旧记录里可能有 `unshare`/`none`） |
| `network` | `info["network"]` | `none` / `host` |
| `cap_drop` / `ro_root` / `pidns` / `no_new_privs` | 同上 | 硬化项是否真的在 |
| `qualified` / `strong` | `mode in STRONG_ISOLATION_MODES`（复算） | `bwrap`/`container` 为真；`unshare`/`none` 恒为假 |
| `executed_isolated` | `spawned and mode in STRONG_ISOLATION_MODES` | **唯一**的“这次真在强隔离里跑过” |
| `prefix_sha256` | 完整 argv 的 sha256 | 复核“到底带的是什么前缀” |

`qualified` 是历史字段名，语义已收窄为“这次算不算强隔离”，与 `strong` 同源同值。
读回时（`from_dict` / `isolation_ledger()`）**按当前口径复算**这两个字段与
`executed_isolated`：旧台账里 `unshare` 行哪怕写着 `executed_isolated=True`，
读回来也只能是 `qualified=False` / `strong=False` / `executed_isolated=False`
（文件不改，台账只增不改；结论不能靠旧字段洗白）。

`to_dict()` 把上面这些**并进**基类字段（`controller`/报告/`round.build` 直接可见）；
`from_dict()` 认回来。

### 2.2 `isolation-executions.jsonl`（逐次台账）

每次构建/冒烟追加一行（只增不改，`fsync`）：

```json
{"schema": "vulnmap.adaptive.isolation_execution.v1", "stage": "build",
 "record_id": "bd-…", "revision_id": "hr-…", "task_id": "…",
 "argv": ["bwrap", "--unshare-net", "…", "--", "python3", "-m", "py_compile", "parser.py"],
 "isolation": "bwrap", "network": "none", "cap_drop": true, "ro_root": true,
 "pidns": true, "no_new_privs": true, "qualified": true, "strong": true,
 "executed_isolated": true, "prefix_sha256": "…",
 "evidence_sha256": "<日志 sha256>", "at": "…"}
```

`TaskWorkspace.isolation_ledger()` 读回（坏行跳过，不伪造）；
`isolation_facts_for(record_id)` 按记录 id 取**实际**事实——冒烟校验构建产物时
用的是台账，不是内存里那个对象（跨进程/重启后仍然有效）。

### 2.3 计划 vs 实际（两处，互不冒充）

| 位置 | 内容 | 谁能写 |
|---|---|---|
| `workspace.json` 的 `isolation` / `require_isolation`；`state()["isolation"]` | **要求**什么（mode / require / strong/qualified 模式表 / low-assurance 表 / 已记录执行数） | `create()`/policy |
| `BuildRecord`/`SmokeRecord` 的隔离字段 + `isolation-executions.jsonl` | **实际**用了什么、有没有真跑 | 只有执行路径 |

`state()["isolation"]` 与 `workspace.json` 里**没有** `executed_isolated`
（测试断言 `"executed_isolated" not in state` / `not in meta`）：计划写不出执行事实。

### 2.4 冒烟的前置校验

`smoke()` 在解析自身的隔离（必须是强隔离）之后，还要求**构建产物来自强隔离执行**：

```python
build_facts = isolation_facts_for(record.build_id) or getattr(record, "isolation_facts", dict)()
if require_isolation and not build_facts.get("executed_isolated"):
    raise WorkspaceError("isolation_violation: …")
```

宿主时代留下的 `BuildRecord`（没有隔离事实）→ `isolation_violation`，不冒烟。

---

## 3. 平台侧隔离验收记录

### 3.1 schema 与检查项

```python
ISOLATION_ACCEPTANCE_SCHEMA   = "vulnmap.adaptive.isolation_acceptance.v1"
ISOLATION_ACCEPTANCE_STATUSES = ("accepted", "rejected")
ISOLATION_EXECUTORS           = ("bwrap", "unshare", "container")
ISOLATION_CHECKS = ("isolation_available", "qualified_executor",
                    "executed_isolated", "network_denied",
                    "capability_dropped", "root_read_only",
                    "probe_write_confined", "probe_network_denied")
ISOLATION_PROBES = ("write_confined", "network_denied")   # 必须有探针证据
ISOLATION_ACCEPTANCE_FILE = "isolation-acceptance.jsonl"
```

`ISOLATION_EXECUTORS` 是**验收记录能读取**的执行器词表（`handoff.py`，本版未改）；
workspace 的强隔离闸更窄：build/smoke 只跑 `bwrap`/`container`，所以执行事实里不会
出现 `unshare`。旧台账里的 `unshare` 行读回即 `strong=False`、`executed_isolated=False`，
验收自然拿不到 `qualified_executor/executed_isolated` 两项。

| 检查项 | 判定 |
|---|---|
| `isolation_available` | 实际模式非空且不是 `none` |
| `qualified_executor` | 实际模式 ∈ `ISOLATION_EXECUTORS` |
| `executed_isolated` | build **且** smoke 记录的 `executed_isolated` 都为真 |
| `network_denied` | 两份记录的 `network` 都是 `none` |
| `capability_dropped` | 两份记录的 `cap_drop` 都为真 |
| `root_read_only` | 两份记录的 `ro_root` 都为真 |
| `probe_write_confined` | `write_confined` 探针 `ok`（工作区外写被拒） |
| `probe_network_denied` | `network_denied` 探针 `ok`（连不上宿主端口） |

`status == "accepted"` 当且仅当**八项全真**；任何一项为假或探针缺失 → `rejected`，
`reason` 逐项列出（`check_failed:<name>;probe_missing:<name>`）。

### 3.2 证据与哈希

```python
evidence = [{"kind": "build", "id": "bd-…",  "sha256": "<日志 sha256>"},
            {"kind": "smoke", "id": "sm-…",  "sha256": "<日志 sha256>"},
            {"kind": "probe", "id": "write_confined",
             "sha256": isolation_probe(...)["evidence_sha256"]},
            {"kind": "probe", "id": "network_denied", "sha256": "…"}]
evidence_sha256 = sha256(canonical_json(记录本体))
```

`isolation_probe(name, ok=..., evidence={...})` 强制要一份**证据体**：没有证据就
不算一次检查。`evidence_sha256` 覆盖事实 + 检查项 + 证据列表 + `checked_at`，
**改任何一个字节都对不上**。

### 3.3 API

```python
build_isolation_acceptance(*, task_id, build=None, smoke=None,
                           probes=(), checked_at="") -> IsolationAcceptance
record_isolation_acceptance(store=None, *, acceptance=None, path=None, **fields) -> dict
verify_isolation_acceptance(record, *, task_id="") -> (state, detail)
load_isolation_acceptance(path) -> list[dict]
latest_isolation_acceptance(*, store=None, path=None, task_id="") -> dict | None
```

- `build_isolation_acceptance()` **只**从 build/smoke 记录与探针算检查项；没有执行
  事实的输入（例如只有一份“计划”）只能得到 `rejected`；
- `record_isolation_acceptance()` 写入前先 `validate()`（状态词、task、证据、
  哈希复算），库写 `PlatformStore.save_isolation_acceptance()`，文件写
  `canonical_json` 一行；
- 台账只增不改：同 `acceptance_id` 同内容幂等返回，**同 id 不同内容 → `TaskError`**
  （改写验收记录等于伪造放行依据）；
- `verify_isolation_acceptance()` 是闸的唯一入口，状态只有
  `accepted` / `rejected` / `missing`。

### 3.4 存储（`store.SCHEMA_W5`，`SCHEMA_VERSION = 7`）

```sql
CREATE TABLE IF NOT EXISTS isolation_acceptance(
  acceptance_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, status TEXT NOT NULL,
  isolation TEXT, network TEXT, cap_drop INTEGER, ro_root INTEGER,
  executed_isolated INTEGER, checks_json TEXT, evidence_json TEXT,
  evidence_sha256 TEXT, reason TEXT, checked_at TEXT, created_at TEXT NOT NULL);
```

方法：`save_isolation_acceptance()` / `get_isolation_acceptance()` /
`list_isolation_acceptances()` / `latest_isolation_acceptance()`；
`store.ISOLATION_ACCEPTANCE_STATUSES` 与 `handoff.ISOLATION_ACCEPTANCE_STATUSES`
是同一套词（有测试对账）。

---

## 4. 放行：`ProposalGate` 读什么、不读什么

| 输入 | 读？ | 作用 |
|---|---|---|
| `metadata.authorized` | ✅ 严格解析 | `Acceptance.authorization = true/false/invalid` |
| `metadata.isolation_accepted` | ⚠️ 只解析成 `declared_isolation` | 进 `to_dict()["declared"]`（`authority="advisory"`），**不参与** `ok` |
| 平台侧记录（`store` / `path` / 显式 `isolation_record`） | ✅ | `Acceptance.isolation = accepted/rejected/missing` |

```python
ProposalGate(task=task, store=store)              # 库取该任务最近一条
ProposalGate.from_task(task, isolation_record=…)   # 显式递记录
ProposalGate.from_task(task, path=…)               # 从追加文件读
ProposalGate(acceptance=Acceptance(...))           # 只做单元判定（不读任何外部）
```

| 条件 | `GateDecision.status` | blockers |
|---|---|---|
| `authorization == "true"` 且 `isolation == "accepted"` | `apply` | 空 |
| 其余 | `advisory` | `authorization:<…>`、`isolation:<accepted|rejected|missing>` |

`Acceptance.to_dict()` 固定带 `authorization` / `isolation` / `ok` / `acceptance_id` /
`evidence_sha256` / `reason` / `declared` / `fields` / `policy`。控制器行为不变：
`advisory` → `PROPOSE=advisory` + `STOP=advisory`，`stop_reason="advisory_only"`，
一次执行都不发生（详见 `docs/V3-W3-HANDOFF.md` §6.4）。

### 4.1 篡改/冒充矩阵

| 冒充方式 | `verify_isolation_acceptance` | 闸 |
|---|---|---|
| 只填 `metadata.isolation_accepted="yes"` | 没有记录 → `missing` | `advisory` |
| 写一个空文件 / 坏 JSON 行 | 坏行不是记录 → `missing` | `advisory` |
| 记录 `status="accepted"` 但把 `ro_root` 改成 `false` | `evidence_hash_mismatch` | `advisory`（`isolation:rejected`） |
| 记录 `accepted` 但抹掉一个检查项（哈希也重算得很自洽） | `checks_failed:<name>` | `advisory` |
| 记录 `accepted` 但没有证据列表 | `evidence_missing` | `advisory` |
| 拿别的任务的记录 | `wrong_task` | `advisory` |
| 计划里写 `bwrap`、`executed_isolated=false` | `recorded_rejected`（且 `checks.executed_isolated=false`） | `advisory` |

---

## 5. 越界证据（这四条是**测试断言**，不是承诺）

| 场景 | 做法 | 断言 |
|---|---|---|
| 越界写 | 冒烟脚本往工作区外（`/tmp` 下的标记）写；脚本自己判 `OSError` 退出 3 | `exit_code==3`、宿主上标记**不存在**、日志无 `WROTE_OUTSIDE`、该次 `executed_isolated=True` |
| 断网 | 宿主先在同一端口 `connect` 成功（证明监听可用），再让隔离内连同一端口 | `exit_code==3`、日志无 `CONNECTED`、有 `net_denied` |
| 缺隔离 | `monkeypatch` `isolation.resolve` 返回 `mode=none`（以及直接抛错） | `WorkspaceError` 含 `strong_isolation_required` / `isolation_unavailable`；痕迹文件不存在、`revisions.builds()==()`、台账为空 |
| 弱隔离降级 | `monkeypatch` `isolation.resolve` 返回 `mode=unshare`（auto 与显式两种 policy） | `WorkspaceError` 含 `strong_isolation_required`；build 与 smoke **都未启动**、工作区外 marker 不存在、无 build/smoke 记录、台账为空 |
| 自报放行 | `metadata.isolation_accepted="yes"` + 平台记录被改一个字节 | `advisory`；`declared.state=="declared"`；`isolation=="rejected"` + `evidence_hash_mismatch` |

“越界写 / 断网”两组在当前机器缺少只读根或断网能力时 `pytest.skip`（
`DETECTED["mode"] in ("bwrap","container") and network=="none"`）——**跳过比假绿好**。

---

## 6. 正常回归：隔离内仍然是「未命中 → 命中 → 未命中」

一个不碰网络、不写目录外的解析器（`parser.py` 只读 `config.json`，`token=="MAGIC"`
才算命中）：

| 步骤 | 构建 | 冒烟 | 断言 |
|---|---|---|---|
| baseline（`token=raw`） | ok / 隔离内 | `failed` + `kind=target` + `exit=1` | 未命中 |
| `stage({"config.json": token=MAGIC})` + `commit` | ok / 隔离内 | `passed` + `exit=0` | 命中 |
| `revert(to=baseline)` | ok / 隔离内 | `failed` + `exit=1` | 未命中，且 `reverted.manifest_sha256 == baseline.manifest_sha256`、`working_manifest()` 与原件哈希都回来 |
| 台账 | 6 条（3 build + 3 smoke） | — | 每条 `executed_isolated=True`、`network=none` |

---

## 7. 测试映射（`tests/test_v3_isolation_acceptance.py`）

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 正常回归 | `test_normal_regression_miss_hit_miss_inside_isolation` | 见 §6；另断言 `state()["isolation"]["executions"]==6`、`workspace.json` 只有 policy |
| 2 越界写 | `test_write_outside_workspace_is_denied` | 见 §5 |
| 3 断网 | `test_network_connect_is_denied` | 见 §5 |
| 4 缺隔离 | `test_missing_isolation_refuses_and_runs_nothing` | 见 §5；另断言 `isolation="none"+require=True` 与未知模式在构造时就拒绝 |
| 5 自报放行 | `test_self_reported_isolation_is_advisory_only` | 见 §5；另断言空文件/不存在文件都不是记录 |
| 6 平台记录放行 | `test_platform_record_grants_apply` | 真 build+smoke+真探针 → `accepted` → 落库+落文件 → 三条读法都 `apply`；`checks` 全真、`evidence` 里有两条 probe；记录里没有提交者自填字段；别的任务借不走（`missing`）；同 id 改内容 `TaskError` |
| 7 计划 ≠ 实际 | `test_planned_isolation_never_masquerades_as_executed` | 只有计划 → `rejected` + `check_failed:executed_isolated`；空证据 → `rejected`；`None` → `missing`；宿主 `BuildRecord` 拿去冒烟 → `isolation_violation` |
| 8 弱隔离降级 | `test_auto_unshare_downgrade_refuses_before_spawn` | monkeypatch `resolve → unshare`：auto 与显式 `unshare` 的 build/smoke 都在 spawn 前 `strong_isolation_required`；工作区外 marker 不存在、`builds/` 未复制、`revisions.builds()/smokes()==()`、台账为空 |
| 8 弱隔离降级 | `test_unshare_never_recorded_as_isolated_execution` | `STRONG_ISOLATION_MODES==("bwrap","container")`；unshare facts 为 `qualified/strong/executed_isolated=False`；旧台账里的 unshare 行读回复算为 False，摘要 `strong_executions==0` |
| 8 弱隔离降级 | `test_bwrap_strong_isolation_still_executes` | bwrap 正常路径仍真跑：build/smoke `executed_isolated/qualified/strong=True`，台账两行都是强隔离 |

`tests/test_v3_week3_handoff.py` 的验收门三行按新口径更新（自填字段不再放行；
“已验收”一列先用真隔离 build+smoke 落一条平台记录）。

---

## 8. 已知边界（写清楚，不装没这回事）

1. **`unshare` 是显式低保证模式，不再是 workspace 执行器**：它只有断网 +
   `no_new_privs`，没有 cap-drop 与只读根。因此 `TaskWorkspace.build()/smoke()`
   在 spawn 前就拒绝（`strong_isolation_required`），不会产生任何 build/smoke
   记录；它只能由 discovery 执行器在**显式** `--isolation unshare` 时知情使用，
   不能承载自动应用，也不能作为验收证据。要跑自动应用、要 `apply`，必须有
   `bwrap` 或 `container`。
2. **`container` 要引擎 + 本地镜像**：`DISCOVERY_ISOLATION_IMAGE` 指定镜像，缺失
   时 `container_problem()` 直接报原因，不静默退化。
3. **`bwrap` 的 `/tmp`**：只读根下 `/tmp` 不可写，需要临时文件的目标要写
   `HOME`/`TMPDIR`（工作区 `home/` 已可写绑定）或目标目录。
4. **不设 `RLIMIT_AS`**：ASAN 需要大地址空间；资源上限靠 CPU/FSIZE/NOFILE 与
   容器的 `--pids-limit/--memory`。
5. **验收记录是“平台侧”而非“密码学签名”**：同一进程内谁都能调
   `record_isolation_acceptance()`。防的是“提交者自报”和“记录被改写”，
   不是“平台自身被攻破”；要更强可以把 `evidence_sha256` 追加到
   `task_events`（本版未做，不假装做了）。

---

## 9. 边界（明确不做）

- 不改 `agent/platform/verify.py` 的判据、`benchmark_policy`、执行器语义；
- 不改 `revision.py` 的 `BuildRecord`/`SmokeRecord` 基类（用子类追加隔离事实）；
- 不把隔离事实写进 `revision_id` 身份（`environment` 不含隔离字段：换隔离器
  不产生新 revision，但会产生新的 build/smoke 记录与验收记录）；
- 不从 `metadata` 里“推测”隔离验收（自填永远是 advisory）。

---

## 10. 文件清单

| 文件 | 变更 |
|---|---|
| `agent/platform/adaptive/workspace.py` | `isolation`/`require_isolation`；`STRONG_ISOLATION_MODES`（bwrap/container）、`QUALIFIED_ISOLATION_MODES`（同义）、`LOW_ASSURANCE_ISOLATION_MODES`（unshare）；`_resolve_isolation()` 的强隔离闸（`strong_isolation_required`）；`_observed_isolation_facts()` 的 `qualified`/`strong`；台账读回复算；build/smoke 带前缀 + preexec 真跑并落台账 |
| `agent/platform/adaptive/handoff.py` | `IsolationAcceptance`、`build_isolation_acceptance()`、`isolation_probe()`、`record_isolation_acceptance()`、`verify_isolation_acceptance()`、`load_isolation_acceptance()`、`latest_isolation_acceptance()`；`Acceptance` 增加 `acceptance_id`/`evidence_sha256`/`declared_isolation`/`reason`；`resolve_acceptance(task, record=…, store=…, path=…)`；`ProposalGate` 只认平台记录 |
| `agent/platform/store.py` | `SCHEMA_W5`（`isolation_acceptance`）、`SCHEMA_VERSION=7`、四条读写方法、状态词表 |
| `tests/test_v3_isolation_acceptance.py` | 新增（八组用例，见 §7；含 unshare 降级拒绝与 bwrap 正常路径回归） |
| `tests/test_v3_week3_handoff.py` | 验收门三行按新口径更新 |
| `docs/V3-W3-HANDOFF.md` | §6 重写为“授权读 metadata、隔离只认平台记录”；测试映射同步 |
| `docs/V3-ISOLATION-ACCEPTANCE.md` | 本文 |
