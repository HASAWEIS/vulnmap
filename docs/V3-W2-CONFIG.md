# V3 第 2 周：配置白名单变更 + 实际加载版本（loaded_config_sha256）

> 适用范围：`agent/platform/adaptive/workspace.py`、`adaptive/revision.py`、
> `adaptive/controller.py`、`adaptive/session.py`、`adaptive/snapshot.py`（仅新增
> config 组四个字段）、`agent/platform/executors/__init__.py`（只读钩子）、
> `tests/test_v3_week2_config.py`、`tests/fixtures_config/`、本文。
> 另有两处**跟随性一行改动**（不是新口径，只是把已有的相位表/导出表补齐）：
> `vulnmap_platform/api/platform_research.py` 的 `PHASES` 加 `CONFIG`
> （`tests/test_v3_p4_api.py::test_phase_order_matches_controller` 要求与控制器同序）、
> `adaptive/__init__.py` re-export `ConfigSurface` / `ConfigError` / `ConfigEffectRecord`。
> 本文是这套口径的**唯一出处**；第 1 周的目标三态口径见
> `docs/V3-TARGET-SEMANTICS.md`，两套字段互不冒充。
> **不动**：`agent/platform/verify.py`、`benchmark_policy`、执行器执行语义、
> 对外 API 形态。

---

## 0. 这一周解决什么

第 1 周把「跑过 / 输入被处理 / 检查点命中」拆成三段三值事实，解决了
**观测**上的假阳性。但「改了什么」这件事本身仍然没有边界：

| 现象 | 后果 |
|---|---|
| 模型可以往工作副本里写任意脚本/源码 | 一次「实验」可能直接改掉目标的行为判据，事后无法归因 |
| revision 只记文件哈希，不记「配置是哪一版」 | 「配置改了」与「配置生效了」被当成同一件事 |
| 汇报里写的是**计划**版本 | 配置已写盘、执行器却加载了旧副本时，报告仍然显示「已生效」 |

本周加两条硬约束：

1. **变更白名单**：工作区在配置模式下只接受 `config/active.json` 的
   *两种* 变更——切换**已有**样例、启用**已有**观测点；原始配置（目录清单、
   样例文件、目标源码）一律不可变，任何源码/脚本改动在 `stage()` 与
   `commit()` 两处都被拒绝。
2. **实际加载版本**：执行器必须回报它**真的加载**的配置哈希
   （`loaded_config_sha256`）；计划版本（`planned_config_sha256`）只来自
   revision，二者不一致就是 `not_effective`——不写 `verified`、不写采纳。

一句话：**计划版本不能冒充实际加载版本；「配置改了」不等于「配置生效了」。**

---

## 1. 配置面（ConfigSurface）与白名单

### 1.1 三个文件，两个可读一个可写

判定规则：**两份目录清单**（`config/samples.json` + `config/observation_points.json`）
都在原件里时，工作区进入**配置模式**（`ConfigSurface.detect`）。只看
`config/active.json` 不算——没有目录清单，"这个 id 存在不存在"无从判断，
那种情况宁可退回 generator 模式（保守方向：不误锁源码），也不假装能校验白名单。

| 路径 | 角色 | 谁能改 |
|---|---|---|
| `config/samples.json` | 样例目录（样例 id + 文件路径） | **没有人**（原件，0444） |
| `config/observation_points.json` | 观测点目录（观测点 id + 探针名） | **没有人**（原件，0444） |
| `config/active.json` | 当前选择（哪一个样例、启用哪些观测点） | 只允许 `stage_config()` / 配置模式下的 `stage()`（没有这份文件时按"全部未选"处理，第一次 `stage_config()` 会创建它） |

```json
// config/samples.json
{"schema": "vulnmap.sample_catalog.v1",
 "samples": [{"id": "alpha", "path": "samples/alpha.txt"},
             {"id": "beta",  "path": "samples/beta.txt"}]}

// config/observation_points.json
{"schema": "vulnmap.observation_point_catalog.v1",
 "points": [{"id": "input_processed", "probe": "input_processed"},
            {"id": "guard", "probe": "checkpoint:guard"}]}

// config/active.json  （唯一可写文件）
{"schema": "vulnmap.active_config.v1",
 "sample": "alpha",
 "observation_points": ["input_processed"]}
```

### 1.2 白名单：只允许两种变更

| 变更 | 允许的值 | 拒绝的情形 |
|---|---|---|
| `sample` | 目录里**已经存在**的样例 id | 目录里没有的 id（不能凭空造样例） |
| `observation_points` | 目录里**已经存在**的观测点 id 的子集 | 目录里没有的 id；重复 id；非字符串 |

- `schema` 必须等于 `vulnmap.active_config.v1`，且**不可改**；
- `active.json` 里出现 `schema`/`sample`/`observation_points` 之外的键 →
  拒绝（白名单是白名单，不是"只校验这两个字段"）；
- 样例目录里登记的 `path` 必须在工作副本里真实存在（否则 `unknown_sample`）；
- 判断以**当前工作副本**为基线（`before`），不是以原件为基线——回退本身就是
  一次合法的白名单变更（回到旧选择）。

### 1.3 错误码（唯一词形，测试与文档共用）

| code | 触发 | 由谁抛 |
|---|---|---|
| `config_path_not_whitelisted` | 配置模式下 `stage()` 写了 `config/active.json` 之外的路径 | `workspace.stage` |
| `config_source_edit_forbidden` | `commit()` 相对父 revision 改了配置面之外的文件 | `workspace.commit` |
| `config_field_not_whitelisted` | `active.json` 出现白名单外的键，或改了 `schema` | `ConfigSurface.validate` |
| `config_invalid` | 不是 JSON 对象 / 类型不对 / 缺必需键 / 观测点重复 | `ConfigSurface.validate` |
| `unknown_sample` | `sample` 不在样例目录里（或登记的文件不存在） | `ConfigSurface.validate` |
| `unknown_observation_point` | 观测点 id 不在目录里 | `ConfigSurface.validate` |
| `no_change` | 新配置与当前配置完全相同 | `workspace.stage_config` |

全部 `WorkspaceError`（`ConfigError` 是它的子类），消息形如
`"<code>: <detail>"`——控制器/测试用 `startswith` 认码，不解析自然语言。

### 1.4 配置模式下 `stage()` 就是 `stage_config()`

```python
ws = TaskWorkspace.create(root, origin, task_id=...)   # origin 有配置面 → 模式=config
ws.config_mode              # "config" | "generator"
ws.stage({"target.py": "..."})                          # → WorkspaceError(config_path_not_whitelisted)
ws.stage({"config/active.json": doc})                   # → 走白名单校验
ws.stage_config(doc)                                    # 显式入口（两种模式都可调，必须存在配置面）
```

- `origin` 没有配置面 → `config_mode="generator"`，`stage()` 行为与第 1 周完全一致
  （既有 1483 条测试不受影响）；此时调 `stage_config()` → `config_invalid`
  （没有目录就没法校验）。
- `commit()` 在配置模式下额外做一次**差异守卫**：
  `revision.changed_against(parent) ⊆ {CONFIG_RELPATH}`，否则
  `config_source_edit_forbidden`——即使有人绕过 `stage()` 直接改了 `current/`，
  也进不了 revision。

---

## 2. 配置身份：一个哈希，三种用法

```python
config_doc_sha256(doc) -> str            # 规范化 JSON（sort_keys + 紧凑分隔符）的 sha256
config_raw_sha256(raw: bytes | str) -> str  # 字节 → 解析 → 上面那个哈希；坏 JSON → ""
config_file_sha256(path) -> str          # 读文件 → 上面那个哈希；缺失/坏 JSON → ""
```

工作区侧只暴露三个**只读**入口（`TaskWorkspace`）：
`active_config_doc()`（每次读盘，commit/revert 后立刻可见）、
`active_config_sha256()`（= 计划版本的唯一来源）、
`config_integrity()`（目录清单/样例文件/`active.json` 对基线的复核：ok + problems）。

规范化后的哈希就是**配置版本**：

| 用法 | 取法 |
|---|---|
| revision 身份 | `commit()`/`revert()` 把 `active_config_sha256`、`baseline_config_sha256` 写进 `revision.environment`（于是换配置必然换 revision id） |
| 计划版本 `planned_config_sha256` | **只**来自工作区当前 revision 的配置（`workspace.active_config_sha256()` / `exec.started.payload.config_planned_sha256`） |
| 实际加载版本 `loaded_config_sha256` | **只**来自执行器的回报（`exec.finished.payload.config_loaded_sha256` / `fuzz.loaded_config_sha256`） |

**硬规则：`loaded` 缺省一律 `unknown`，绝不回填 `planned`。**
"执行器没报" 与 "执行器报了同一版" 是两件事，混起来就是本周要禁掉的假阳性。

---

## 3. 执行器只读钩子（`agent/platform/executors/__init__.py`）

只新增纯函数与字段，不改执行语义：

```python
CONFIG_RELPATH = "config/active.json"
CONFIG_ACTIVE_SCHEMA = "vulnmap.active_config.v1"
CONFIG_FACT_FIELDS = ("config_planned_sha256", "config_loaded_sha256",
                      "config_source", "config_effective")

def config_facts(*, planned_sha256="", loaded_sha256="",
                 loaded_source="") -> dict
def config_effect_view(start: dict | None = None,
                       finish: dict | None = None) -> dict
```

`config_facts()` 的三值表（`config_effective` 只可能是 `True` / `False` / `None`）：

| planned | loaded | `config_effective` | `config_source` | `config_status` |
|---|---|---|---|---|
| 有 | 有，且相等 | `True` | `reported` / `reported_fuzz_stats` / `reported_executor_stats` | `effective` |
| 有 | 有，不相等 | `False` | 同上（只标"从哪一段读到的"） | `not_effective` |
| 有 | 缺失 | `None` | `loaded_unreported` | `unknown` |
| 缺失 | 任意 | `None` | `planned_missing` | `unknown` |

`config_source` 只说明「actual 这个值是从执行器的哪一段读到的」（顶层 /
`fuzz` 段 / `stats` 段），**不**影响三值判定；三段都没有就是
`loaded_unreported`。

`config_effect_view()` 逐字段返回 `config_planned_sha256` /
`config_loaded_sha256` / `config_effective` / `config_status` /
`config_source` / `config_present{planned,loaded}`：`planned` 先读
`exec.started` 再读 `exec.finished`，`loaded` **只读**
`exec.finished.config_loaded_sha256`（或 `exec.finished.fuzz.loaded_config_sha256`）。

`run_execution()` 新增两个**可选**关键字参数：

```python
run_execution(..., config_path=None, config_planned_sha256="")
```

- `config_path` 缺省 `workdir / "config/active.json"`；
- 计划版本：显式参数优先，否则在执行前读一次该文件（执行器"将要交给进程的那份"）；
- 实际版本：只取执行器返回值/统计里的 `loaded_config_sha256`；
- `exec.started` / `exec.finished` 都带 `**config_facts(...)` 的四个字段。

`EXEC_FACT_FIELDS["start"] += ("config_planned_sha256", "config_load_path")`；
`EXEC_FACT_FIELDS["finish"] += CONFIG_FACT_FIELDS + ("config_load_path",)`；
`_FUZZ_STATS_KEYS += ("loaded_config_sha256",)`（这样 fuzz 执行器能在统计里直接回报它
加载的那一版）。

`config_load_path` 记录**执行器实际打开的那个配置文件路径**（默认
`<workdir>/config/active.json`）：`loaded` 哈希必须能对应到一个真实路径，
否则"我加载了另一版"连落在哪儿都说不清。

---

## 4. revision 账本：`ConfigEffectRecord`

```python
CONFIG_EFFECT_SCHEMA = "vulnmap.adaptive.config_effect.v1"
CONFIG_STATUSES = ("effective", "not_effective", "unknown")

@dataclass(frozen=True)
class ConfigEffectRecord:
    effect_id: str            # "ce-" + digest 前 16 位
    revision_id: str
    planned_sha256: str
    loaded_sha256: str
    status: str               # CONFIG_STATUSES
    source: str = ""
    execution_id: str = ""
    round_no: int = 0
    reason: str = ""
    created_at: str = ""
    # adoptable == (status == "effective")
```

不变量（构造时校验，写不进去的假话就不该存在于账本里）：

| status | 要求 |
|---|---|
| `effective` | planned 与 loaded 都是 64 位 hex **且相等** |
| `not_effective` | planned 与 loaded 都是 64 位 hex **且不相等** |
| `unknown` | loaded 允许为空；但要更严：planned 与 loaded **都是**合法 64hex 时不许写 `unknown`（能判定却写"不知道"就是把可算的降级成不可算） |

`RevisionStore` 新增：`CONFIG_EFFECTS = "config_effects.jsonl"`、
`record_config_effect()`、`config_effects(revision_id="")`、
`latest_config_effect(revision_id)`、`config_effect_for_execution(execution_id)`、
`config_adoptable(revision_id) -> bool`，并纳入 `to_dict()`。
`HarnessRevision` 新增只读属性 `active_config_sha256` / `baseline_config_sha256`
（读 `environment`，没有就是 `""`）。

---

## 5. 快照 / 会话 / 控制器

### 5.1 快照（`adaptive/snapshot.py`，仅新增）

`config` 组新增四个字段（`_GROUP_PATHS["config"]` + `_fill_config`）：

`planned_config_sha256`、`loaded_config_sha256`、`config_effective`（三值
`"true"/"false"/"unknown"`）、`config_source`。取值全部来自 §3 的钩子视图，
没有就 `unknown`，不做推断。

### 5.2 会话（`adaptive/session.py`）

- `Observation` 新增 `config: Mapping`（`planned/loaded/effective/status/source`），
  `facts_hash` 里带上 `config_status` 与 `planned_config_sha256`：
  **换配置就是新事实**，但也仅仅是新事实，不是"有进展"。
- `DIAGNOSIS_CODES` 新增两码：

| code | 条件 | severity | 含义 |
|---|---|---|---|
| `config_not_effective` | `config.status == "not_effective"` | `blocked` | 执行器实际加载的配置 ≠ 计划配置（已观测的"没生效"） |
| `config_unverified` | `config.status == "unknown"` 且有 planned | `warn` | 改了配置，但没有任何"实际加载"的回报（只能 unknown） |

  诊断优先级插在"执行报错/超时"之后、候选之前：
  `execution_error → config_not_effective → candidate_observed → program_not_started
  → input_not_processed → target_unreached → progress/low_coverage →
  config_unverified → no_execution → coverage_unknown`。
  `config_unverified` 放在目标三态之后：**"没生效"能不能推翻别的结论，取决于
  它自己的证据等级**——`not_effective` 已经观测到了，可以推翻；`unknown` 只是
  没观测，不能顶替"目标没命中"这种真观测。
- 新增 `ConfigRole`：配置模式下的**确定性**变更（不读盘、不执行）——

```python
ConfigRole(*, samples, observation_points, current_provider, max_attempts=3)
ConfigRole.revision_plan(observation, diagnosis, *, attempt) -> RevisionPlan | None
```

  attempt 0 不改（先按原配置跑出反馈）；attempt 1 启用目录里下一个未启用的观测点；
  attempt 2 = 启用剩余观测点 + 切到目录里下一个样例。产物永远是
  `RevisionPlan(files={"config/active.json": <规范化 JSON>}, tool="config_editor")`。
  `ResearchSession(..., config_role=None)`：为 `None` 时行为与第 1 周完全一致。

### 5.3 控制器（`adaptive/controller.py`）

- `PHASES` 新增 `"CONFIG"`（紧跟 `COLLECT`，在 `COMPARE` 之前）。
- 每轮 COLLECT 之后算一次配置效果并落账：
  `planned = workspace.active_config_sha256()`（revision 侧，权威），
  `loaded = observation.config["loaded"]`（**只**来自执行器回报），
  `status = effective/not_effective/unknown`；
  `revisions.record_config_effect(...)`，`RoundRecord.config_effect` 留档，
  时间线写一行 `CONFIG`。
- **门**（`config_not_effective` / `config_unverified`）：

| 状态 | 相位 | 停止原因 | status | 采纳 | verification |
|---|---|---|---|---|---|
| `not_effective` | `CONFIG=not_effective` | `config_not_effective` | `blocked` | **不写**（`adoptions.jsonl` 不加行） | **不产生** |
| `unknown` | `CONFIG=unknown` | `config_unverified` | `blocked` | **不写** | **不产生** |
| `effective` | `CONFIG=effective` | 继续原流程 | — | 按 policy | 按 policy |

- 配置模式下 ADOPT **延后**：`policy.engineering()` 说 adopt 时先挂起
  （相位 `ADOPT=deferred`），等本轮 `CONFIG` 门判定 `effective` 才真正
  `record_adoption()`；判 `not_effective` 时改为回退到父 revision
  （`revert(reason="config_not_effective:...")`）并停。
- 配置模式下 `STAGE` 仍走 `workspace.stage()`（第 1.4 节：它就是白名单入口），
  非白名单路径在这里以 `stage_failed: config_path_not_whitelisted` 停住。
- 任何配置门拦截都不会调用 `verify`、不会写 `verified/confirmed`
  （与第 1 周 T15 一致：裁决只认 verify，而 verify 这一步根本没被走到）。

---

## 6. 四组回归（`tests/test_v3_week2_config.py`）

夹具 `tests/fixtures_config/` 是**真跑**的：真 `subprocess.run` 的
`target.py`（按配置选样例、按启用的观测点写探针）+ `runner.py`
（读 `config/active.json` → 算 `loaded_config_sha256` → 跑目标 → 输出事实
JSON）。两个真实反例开关：`--stale-config PATH` 让执行器**仍加载旧副本**（配置已写盘、
加载的是别的版本）；`--no-report-config` 让执行器**什么都不报**（有加载、没回报 →
只能是 `unknown`，不许回填 planned）。

`tests/test_v3_week2_config.py` 共 **11 条**（全绿）：

| 组 | 用例 | 断言要点 |
|---|---|---|
| 夹具自证 | `runner_runs_standalone_and_reports_loaded_version` | `python3 runner.py` 单独就能给出合法事实 JSON（不依赖 pytest 内部） |
| ① 白名单拒绝 | `whitelist_rejects_source_edits` | 改 `target.py`/`runner.py`/`config/samples.json`/观测点目录 → `config_path_not_whitelisted`（整次拒绝、一个字节不写）；绕过 `stage()` 直接改 `current/` 再 `commit()` → `config_source_edit_forbidden`；`origin_integrity` / `config_integrity` ok |
| ① 白名单拒绝 | `whitelist_rejects_unknown_ids` | 凭空造样例/观测点 → `unknown_sample` / `unknown_observation_point`；改 `schema`、加白名单外的键 → `config_field_not_whitelisted`；重复观测点/缺键/非对象/坏 JSON → `config_invalid`；同内容 → `no_change`；失败不留痕 |
| ① 边界 | `generator_mode_keeps_week1_behaviour` | origin 没有配置面 → `config_mode=="generator"`、两个哈希都是 `""`、`stage()` 照旧、`stage_config()` → `config_invalid` |
| ② 实际加载版本 | `loaded_version_is_reported_not_planned` | 真跑 loaded==planned → `effective`；`ConfigEffectRecord.adoptable is True`；§4 的三条不变量反例（伪造 effective / 两版都在却写 unknown / effect_id 被改写）逐条被拒 |
| ② 实际加载版本 | `unreported_load_is_unknown_not_planned` | `--no-report-config`（执行器真的不报）→ `config_effective is None`（**不是 False**）、`status=="unknown"`、`source=="loaded_unreported"`、`loaded` 不回填 planned；诊断 `config_unverified`（warn） |
| ③ 未生效反例 | `stale_load_is_not_effective` | `--stale-config` 真跑（executor 加载旧副本）→ `not_effective`；控制器 `stop_reason=="config_not_effective"`、`status=="blocked"`、`CONFIG=not_effective`、`REVERT ok`；`adoptions.jsonl` 不存在、`list_verifications()==[]`、`result.verification is None`；工作树与配置哈希都回父 revision |
| ④ 回退哈希/行为 | `baseline_modify_revert_restores_hash_and_behavior` | baseline（alpha，检查点 unknown）→ modify（gamma + guard，检查点 true）→ revert：`active_config_sha256` 回到 baseline、`working_manifest()` 等于 baseline、真跑事实与 `probe_hits` 逐字段回到 baseline；revision 恰 3 条、`reverted_to` 指回被回退的那条、旧 revision 未被改写 |
| ④ 目标侧失败 vs 装置 | `bad_magic_sample_fails_smoke_on_target_side` | 换到 beta（坏 magic）→ build ok 但 smoke `failed`/`kind=="target"`：这是目标行为不符，不是 harness 崩了 |
| ⑤ 配置变更闭环 | `controller_proposes_and_lands_whitelisted_config_change` | 控制器自带的 `ConfigRole` 第 2 轮提出「启用 `guard`」→ 经 `workspace.stage()` 落地：新 revision `tool=="config_editor"`、`changed_against==("config/active.json",)`、`environment["active_config_sha256"]` 随配置变；`CONFIG` 全是 `effective`、采纳 1 条、无 verification；真跑证据：同一份 alpha 从 `checkpoint_reached=unknown` 变 `false`（观测点真的生效了）；反向（执行器改回不报）→ `config_unverified`/blocked/不回退/不采纳 |
| ⑤ 配置变更闭环 | `config_mode_rejects_plan_that_edits_source` | 注入一个提出 `RevisionPlan(files={"target.py": ...})` 的角色（先断言它真被调用过）→ STAGE `failed` 且 detail 含 `config_path_not_whitelisted`、`stop_reason=="stage_failed"`、一条 revision 都没新增、工作副本与原件字节未变、无采纳/无 verify、连执行都没走到 |

夹具八件（`tests/fixtures_config/`，全部真文件、无替身）：

| 文件 | 作用 |
|---|---|
| `config/samples.json` | 样例目录原件（alpha → `samples/alpha.txt`、beta、gamma），不可写面 |
| `config/observation_points.json` | 观测点目录原件（`input_processed`、`guard` → 探针 `checkpoint:guard`） |
| `config/active.json` | 唯一可写文件；baseline = `alpha + [input_processed]` |
| `samples/alpha.txt` | 合法头 `VMAP1`、无 `GUARD` → 处理过、检查点 false |
| `samples/beta.txt` | 坏 magic `VMAP0` → 目标侧 exit 1（冒烟真失败、`kind=target`） |
| `samples/gamma.txt` | 合法头 + `GUARD token=deadbeef` → 检查点 true |
| `target.py` | 无害解析器：只按**启用**的观测点写 JSONL 探针（启用+无行=false、未启用=unknown）；它本身就是"禁止改"的对照物 |
| `runner.py` | 执行器：读它真加载的那份配置 → `config_file_sha256` → 子进程跑 `target.py` → 输出事实 JSON；`--stale-config` / `--no-report-config` 造两个真实反例 |

跑：

```bash
python3 -m pytest tests/test_v3_week2_config.py -q
python3 -m pytest tests/ -q
```

---

## 7. 边界（明确不动）

- `verify` / `benchmark_policy` / 执行器执行语义 / 对外 API 形态：不动；
- 第 1 周三态口径：不动（`program_started` / `input_processed` /
  `checkpoint_reached` 仍然是唯一的目标语义出口，配置效果**不**参与它们的推断）；
- 配置效果 **不** 升格成漏洞证据：`effective` 只说明"跑的是这一版配置"，
  既不是覆盖增益，也不是候选；
- `generator` 模式（origin 没有配置面）行为不变，既有测试全绿是硬要求。

---

## 8. 改动面速查（复核用）

| 文件 | 这一周加了什么 | 没动什么 |
|---|---|---|
| `executors/__init__.py` | `config_doc_sha256` / `config_raw_sha256` / `config_file_sha256` / `config_facts` / `config_effect_view`、`CONFIG_FACT_FIELDS`、`run_execution(config_path=, config_planned_sha256=)` 与 9 个 `exec.finished` 写入点的配置字段 | 分派表、状态机、证据/候选写法 |
| `adaptive/workspace.py` | `ConfigSurface` / `ConfigError` / `config_mode` / `stage_config` / `active_config_doc` / `active_config_sha256` / `baseline_config_sha256` / `config_integrity` / `stage()` 配置路由 / `commit()` 差异守卫 | generator 模式的 `stage/commit/revert` 行为 |
| `adaptive/revision.py` | `ConfigEffectRecord` / `CONFIG_STATUSES` / `config_effects.jsonl` 读写 / revision 的配置身份属性 | `HarnessRevision` 身份算法、既有 build/smoke 记录 |
| `adaptive/snapshot.py` | config 组四个字段 + `_config_view` | 七个事实组的结构、`OBSERVED_FIELDS`、`status()` |
| `adaptive/session.py` | `Observation.config`、facts_hash 两键、两个诊断码、`ConfigRole` | 三段目标语义、既有诊断优先级前三条 |
| `adaptive/controller.py` | `CONFIG` 相位、`RoundRecord.config_effect`、配置门、ADOPT 延后 | 预算/取消/失效消费/比较口径 |
| `tests/` | `test_v3_week2_config.py` + `fixtures_config/`（真跑夹具） | 既有 1491 条用例 |
