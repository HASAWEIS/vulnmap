# Harness MVP 最终验收（2026-11-24）

> 范围：`vulnmap` 仓库 V3 Harness（W1 目标三态、W2 配置效果、W3 证据交接、W4 A/B 门禁）。
> 纪律：只写 `docs/` 与 `experiments/harness-acceptance/`；**不改业务代码、不改历史证据、
> 不 `git commit`**。本文所有数字都来自本机重跑留下的日志 / JSON，不引用未复算的口头结论。
>
> 结论先行：
> - **V3 测试全绿**：`tests/test_v3_*.py` 15 个文件 **253 passed / 0 failed**（关键 smoke 81/81）。
> - **无害 demo 全绿**：基线未命中 → 建议切换样例 → 落盘 → 执行器**实际加载**新版本 →
>   命中 → 回退未命中；无探针组 `unknown`；4 条执行记录被独立复核判 `accepted`。
> - **不构成漏洞发现**：本次 demo 新增独立根因数 **0**、`vulnerability_findings` **0**、
>   `verified/confirmed` **0**；一次分支命中只被写成“执行事实”。
> - **可提交案例数（严格 A∧B∧C∧D）为 0**：8 例候选已过高危 + 因果链，但人工复核记录与
>   官方回执仍未取得（外部输入，不由代码置真）。

---

## 1. 测试：全量与关键 smoke

### 1.1 命令与结果

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_v3_*.py -q
# 253 passed in 27.57s   (第二次带 junit 复跑：31.40s)
```

| # | 测试文件 | 通过 | 失败 |
|---|---|---|---|
| 1 | `tests/test_v3_backend_http.py` | 14 | 0 |
| 2 | `tests/test_v3_cg01_smoke.py` | 18 | 0 |
| 3 | `tests/test_v3_p1_seed.py` | 8 | 0 |
| 4 | `tests/test_v3_p2_contracts.py` | 57 | 0 |
| 5 | `tests/test_v3_p2c_research_cli.py` | 9 | 0 |
| 6 | `tests/test_v3_p2_session.py` | 14 | 0 |
| 7 | `tests/test_v3_p3.py` | 30 | 0 |
| 8 | `tests/test_v3_p4_api.py` | 14 | 0 |
| 9 | `tests/test_v3_p4_report.py` | 11 | 0 |
| 10 | `tests/test_v3_p5_patch.py` | 15 | 0 |
| 11 | `tests/test_v3_smoke_record.py` | 15 | 0 |
| 12 | `tests/test_v3_target_semantics.py` | 16 | 0 |
| 13 | `tests/test_v3_week2_config.py` | 11 | 0 |
| 14 | `tests/test_v3_week3_handoff.py` | 13 | 0 |
| 15 | `tests/test_v3_week4_ab.py` | 8 | 0 |
| | **合计** | **253** | **0** |

关键 smoke（目标语义 + 配置 + 交接 + A/B + 两条 smoke 记录）：

```bash
python3 -m pytest tests/test_v3_cg01_smoke.py tests/test_v3_smoke_record.py \
  tests/test_v3_target_semantics.py tests/test_v3_week2_config.py \
  tests/test_v3_week3_handoff.py tests/test_v3_week4_ab.py -q
# 81 passed, 1 warning in 13.61s
```

### 1.2 证据

- 全量日志：[pytest-v3-full.log](../experiments/harness-acceptance/logs/pytest-v3-full.log)
- 全量 JUnit：[v3-junit.xml](../experiments/harness-acceptance/logs/v3-junit.xml)（`tests=253 errors=0 failures=0 skipped=0`）
- 逐文件复跑：[pytest-per-file.log](../experiments/harness-acceptance/logs/pytest-per-file.log)
- 关键 smoke：[pytest-key-smoke.log](../experiments/harness-acceptance/logs/pytest-key-smoke.log)
- 最终复跑：[pytest-v3-final.log](../experiments/harness-acceptance/logs/pytest-v3-final.log)
  （`253 passed in 26.93s`，退出码 0）
- demo 运行日志：[acceptance-demo.log](../experiments/harness-acceptance/logs/acceptance-demo.log)

---

## 2. 无害 demo：一次“分支命中”如何被写成执行事实

### 2.1 夹具与边界

demo 只用仓库内已有的**无害替身**，复制到 `experiments/harness-acceptance/demo/origin/` 后
由 `TaskWorkspace` 建实验副本；`tests/fixtures_config/` 与 `fixtures/target_semantics/`
原件只读、没有被写过一个字节（mtime 早于本次会话）：

| 件 | 来源 | 作用 |
|---|---|---|
| `target.py` | `tests/fixtures_config/target.py` 复制 | 纯文本解析器；按启用的观测点写 JSONL 探针；**不是漏洞程序** |
| `runner.py` | `tests/fixtures_config/runner.py` 复制 | 执行器替身：读它**真的**交给进程的配置 → 算 `loaded_config_sha256` → 真子进程跑目标 |
| `config/samples.json` | 复制后把目录顺序写成 alpha → gamma → beta | 让 `ConfigRole` 的“下一个样例”落在带 `GUARD` 的 gamma；仍是目录里**已有**的样例 |
| `config/active.json` | 基线 = `alpha + [input_processed, guard]` | 两个观测点都启用，基线检查点是**观测到的 false**（不是 unknown） |
| `fixtures/target_semantics/probe.py` | 只读调用 | `no_probe` 组提供“跑得起来但没有观测手段 → unknown”的真实子进程 |

复跑入口：`python3 experiments/harness-acceptance/run_acceptance.py`（退出码 0 = 全部断言通过）。

### 2.2 主链路（真跑、真加载、真回退）

基线配置哈希 `c8e76d9ca69e0067f138518b07bc2f85d7d2d730beaa907e82b8f5c193d91576`，
建议后的配置哈希 `1f01c916fc7ad456d89d86c94a9706fc99845944e2f15daea37b6f2eafea6aeb`。

| 阶段 | revision | planned | loaded（执行器回报） | 配置判定 | 三段事实（started / processed / checkpoint） | 结论 |
|---|---|---|---|---|---|---|
| baseline | `hr-37408a71717733c3` | `c8e76d9c…` | `c8e76d9c…` | `effective` | `true / true / false` | **观测到的未命中** |
| suggested | —（只提案） | — | — | — | — | `target_unreached` → 切 gamma + 全开观测点 |
| modified | `hr-dd011c12ed445f0f` | `1f01c916…` | `1f01c916…` | `effective`（`ce-8a52a689820500a6`，可采纳） | `true / true / true` | **实际加载新版本后命中** |
| control: stale | `hr-dd011c12ed445f0f` | `1f01c916…` | `c8e76d9c…` | `not_effective`（`ce-503217782adfdc2c`，不可采纳） | `true / true / false` | 反例：配置写盘了，执行器仍加载旧副本 |
| control: no-report | `hr-dd011c12ed445f0f` | `1f01c916…` | （空） | `unknown`（`ce-ce96d174b778699f`，不可采纳） | `true / true / true` | 反例：没回报 ≠ 回填 planned |
| reverted | `hr-485d6665fbff4763` | `c8e76d9c…` | `c8e76d9c…` | `effective`（`ce-0a3368916db1b5cf`） | `true / true / false` | **回退后行为与基线逐字段相同** |
| no-probe 组 | —（W1 夹具） | — | — | — | `true / unknown / unknown` | 跑得起来，但没有观测手段 |

建议本身是**确定性**的，理由与事实指纹一起留档：

```json
{
  "diagnosis": {"code": "target_unreached", "severity": "warn",
                 "reasons": ["target_not_reached"],
                 "facts_hash": "b97c0d806c655ad7d7f8dce14aa2460633f102189ff4c564e801136961b3f125"},
  "attempt_1": null,
  "attempt_2": {"tool": "config_editor",
                 "reason": "target_unreached: config attempt 2 (sample=gamma points=['guard', 'input_processed'])",
                 "files": {"config/active.json": "{\"sample\":\"gamma\",\"observation_points\":[\"guard\",\"input_processed\"],...}"}}
}
```

- `attempt 1` 返回 `None`：两个观测点已经在基线启用，没有“下一个观测点”可开——**不假装有变更**；
- `attempt 2` 只做白名单内的两件事：切到目录里已有的 `gamma`、启用目录里已有的观测点；
- 落盘后 `modified.changed_against(baseline) == ("config/active.json",)`，源码/目录/样例一个字节没动。

回退保真（三条同时成立）：

| 检查 | 结果 |
|---|---|
| `active_config_sha256` 回到基线 | `c8e76d9c…` |
| `working_manifest()` 等于基线 | 是（整树逐文件哈希一致） |
| 真跑行为回到基线 | `checkpoint_reached=false`，`sample=alpha`，`probe_hits=["input_processed"]` |
| 旧 revision 未被改写 | `hr-dd011c…` 的 `manifest_sha256` 不变 |
| 原件完整性 | `origin_integrity.ok == true`，`config_integrity.ok == true` |

### 2.3 无探针组：unknown 不是 false

`fixtures/target_semantics/probe.py` 的 `no_probe` 用例走真实子进程：

| 事实 | 值 | 原因 |
|---|---|---|
| `program_started` | `true` | 子进程真的起来了、有退出码 |
| `input_processed` | `null` → snapshot `unknown` | `--no-probe`，目标没写探针；**没有观测手段** |
| `checkpoint_reached` | `null` → snapshot `unknown` | 同上；不能因为“没看到”就写 false |

该执行同样被封存为待复核项 `HI4`，独立复核判 `accepted`——**接受的只是“这条执行记录可复核”，
`unknown` 仍是 `unknown`**，不产生命中/未命中结论。

### 2.4 谁确认：复核链只看原始记录

| 项 | baseline | modified | reverted | no-probe |
|---|---|---|---|---|
| 待复核项 | `HI1` | `HI2` | `HI3` | `HI4` |
| 独立复核裁决 | `accepted` | `accepted` | `accepted` | `accepted` |
| 模型摘要 | 被拒 | 被拒 | 被拒 | 未尝试（同一 verifier 口径） |
| 复核证据 | 执行记录本体 + 盘上哈希 | 同左 | 同左 | 同左 |

模型摘要拒绝的实际报错（三次主链路各试过一次）：

```text
model_summary_not_accepted: verifier only reads raw records (got dict)
```

`accepted` 的边界：它只说明 `run_id / execution_id / evidence_sha256` 三方身份一致、
盘上字节可复算、源事件能对上；**不写 `verified` / `confirmed`**，也不代表漏洞成立。
本次 demo 没有调用 `verify`，因此没有任何漏洞裁决产生。

### 2.5 证据清单

- 汇总：[acceptance.json](../experiments/harness-acceptance/evidence/acceptance.json)
  （每次重跑覆盖；哈希以 [INDEX.json](../experiments/harness-acceptance/evidence/INDEX.json) 为准）
- 每次执行：`evidence/runs/<stage>.json`、`evidence/snapshots/<stage>.json`、
  `evidence/stages/<stage>.json`、`evidence/runner/<stage>.stdout.json`
- 建议：[suggestions/baseline.json](../experiments/harness-acceptance/evidence/suggestions/baseline.json)
- 账本副本：[revisions.jsonl](../experiments/harness-acceptance/evidence/ledger/revisions.jsonl)、
  [config_effects.jsonl](../experiments/harness-acceptance/evidence/ledger/config_effects.jsonl)
- 全部产物哈希索引：[INDEX.json](../experiments/harness-acceptance/evidence/INDEX.json)

---

## 3. 四问

### 3.1 知道什么（What do we know）

**答：只知道被观测到的三段事实，缺失一律 `unknown`，不用统计量顶替探针。**

| 事实 | 谁能给 `true`/`false` | 本 demo 的观测 |
|---|---|---|
| `program_started` | 子进程真起来（执行计数 / 显式字段） | baseline/modified/reverted/no-probe 都是 `true` |
| `input_processed` | **只能**显式探针/显式字段 | baseline/modified/reverted `true`；no-probe `unknown` |
| `checkpoint_reached` | **只能**显式探针/显式 `checkpoint_reached` | baseline `false`、modified `true`、reverted `false`、no-probe `unknown` |

禁止推断（代码与测试都守着）：`execs>0` 只证明程序跑过；`new_coverage_bits>0`、崩溃数、
`covered==planned` 都不能推出“检查点命中”。快照层把 `None` 落成 `unknown`，不填 `false`。
证据：`docs/V3-TARGET-SEMANTICS.md`、`tests/test_v3_target_semantics.py`（16 passed）、
本次 `evidence/snapshots/*.json`。

### 3.2 为什么建议（Why this suggestion）

**答：因为诊断码 + 事实指纹指向“目标分支没走到”，而可做的变更只有白名单两种；
建议是确定性的，且只提案、不自动应用。**

链路（全部可在证据里复算）：

1. baseline 快照：`checkpoint_reached=false`，配置 `effective`，无候选 → `DiagnoseRole`
   给 `target_unreached`（`reasons=["target_not_reached"]`，`facts_hash=b97c0d80…`）；
2. `ConfigRole` 的 attempt 序列：attempt 1 无可启用观测点 → `None`（不假装改）；
   attempt 2 → 切目录里下一个样例 `gamma` + 全开目录里已有观测点；
3. 产物固定为 `RevisionPlan(files={"config/active.json": …}, tool="config_editor",
   evidence_refs=[facts_hash])`，理由写进 `reason`；
4. 变更只经 `workspace.stage()`（配置模式白名单入口）落盘；源码/目录/样例写入会被
   `config_path_not_whitelisted` 拒绝，绕过 `stage()` 直接改 `current/` 会被 `commit()`
   的差异守卫拒绝（`config_source_edit_forbidden`）；
5. 没有“模型建议自动应用”：W4 的 `auto_apply` 恒为 `False`，本 demo 的改动由验收脚本
   以操作者身份显式 `stage + commit`（`model_auto_applied_changes=0`）。

证据：`evidence/suggestions/baseline.json`、`evidence/ledger/revisions.jsonl`
（`tool="config_editor"`、`reason` 完整）、`tests/test_v3_week4_ab.py`（8 passed）。

### 3.3 改动是否生效（Did the change take effect）

**答：只认“执行器实际加载的版本”，计划版本不能冒充；三种状态各自留档。**

| planned vs loaded | `config_effective` | 状态 | 本 demo |
|---|---|---|---|
| 都有且相等 | `true` | `effective` | baseline / modified / reverted 三次都是 |
| 都有但不相等 | `false` | `not_effective` | `--stale-config` 对照：`loaded=旧哈希` |
| loaded 缺失 | `None` | `unknown` | `--no-report-config` 对照：不回填 planned |

配置身份同时写进 revision 环境（换配置必换 revision id），配置效果只增不改地落
`config_effects.jsonl`；只有 `effective` 可采纳（`adoptable=true`），
`not_effective` / `unknown` 一律不可采纳。回退后 `active_config_sha256`、工作树 manifest、
真跑三段事实三者同时回到基线（§2.2）。

证据：`evidence/ledger/config_effects.jsonl`（5 条：主链路 3 + 对照 2）、
`tests/test_v3_week2_config.py`（11 passed）。

### 3.4 谁确认（Who confirms）

**答：独立复核者只读原始记录；模型摘要不进入复核；机器只能确认“执行记录可复核”，
漏洞结论仍必须由既有 `verify` 与外部人工/官方回执确认。**

| 角色 | 能做什么 | 不能做什么 | 本 demo |
|---|---|---|---|
| 执行器 | 回报事实、`loaded_config_sha256` | 不能声明计划版本、不能写裁决 | 真跑 `runner.py` |
| 控制器/建议 | 诊断、提案、配置门 | 不能自动采纳、不能写 `verified` | 只提案 + 操作者落盘 |
| 独立复核者 `IndependentVerifier` | 读封存记录、复算 `run_id/execution_id/evidence_sha256` | 不接受 `summary/claim/conclusion` | 4 条 `accepted`；3 次摘要尝试被拒 |
| `verify` / benchmark | 写 `verified/confirmed` | —— | **未调用** |
| 人工 / 官方回执 | 最终可提交性 | 代码不能代替 | **未取得** |

机器 `accepted` 与“漏洞成立”之间隔着一整条验证链：本次 `vulnerability_findings=0`、
`verified/confirmed` 未写、没有 candidate 记录。证据：`evidence/stages/*.json` 的
`handoff` 段、`tests/test_v3_week3_handoff.py`（13 passed）。

---

## 4. 三张表

### 4.1 表一：独立根因数（本次验收不增加任何一个）

口径：`root_key = (归一化 task_id, sink.file, sink.line)`；同一 task 的不同 sink 需人工裁定，
同一 `arvo` 的两种写法（`arvo:44034` / `user:cybergym/arvo_44034`）归一。只读扫描
`workspace/*/task.json` 与 `**/case.json` 复算，未改任何台账。

| 项 | 数值 | 口径 / 来源 |
|---|---|---|
| 原始 `task_id` | 45 | `workspace/*/task.json` |
| 归一化 `task_id` | 44 | arvo 两种写法归一后 |
| 全部根（task, sink.file, sink.line） | **51** | 所有 `case.json` |
| 高危根（`high_severity_confirmed=true`） | **9** | `LEDGER.json` 行 + case sink 去重 |
| 高危 ∧ 因果链 ∧ `target_defect` 根 | **8** | 与 `COURSE-GAP-CLOSED` 的 8 一致 |
| 本次 Harness demo 新增独立根 | **0** | 一次分支命中不是漏洞根因 |

> 反过度声明：demo 的 `checkpoint_reached=true` 是**无害解析器**里一个受控分支，
> 没有输入→汇聚点→缺失检查的传播证据，也没有双端/benchmark 判定，因此：
> **不计根、不计高危、不计可提交案例**。

### 4.2 表二：可提交案例数（严格口径 = 0）

交付标准是四项 AND（A 独立、B 高危且有人工复核、C 双端/官方验证、D 材料齐全），
不是分开凑数；失败案例保留在分母。

| 指标 | 数值 | 说明 |
|---|---|---|
| 台账案例行 | 30 | `LEDGER.json:rows` |
| 本地双端通过 | 21 | `local_dual_run=true` |
| benchmark_verified | 23 | 含 ExploitGym 官方 socket 记录 |
| 因果链闭合 | 10 | 9 `target_defect` + 1 `harness_ub`（CG-06，不计高危） |
| 高危已确认 | 9 | `high_severity_confirmed=true` |
| 独立高危 ×（benchmark + 因果链） | **8** | 8 个不同根 |
| `human_reviewed=true` | **0** | 人工复核记录仍是外部输入 |
| `official_receipt` 已附 | **0** | 官方回执仍是外部输入 |
| `course_ready=true` | **0** | 代码不自动置真 |
| **严格可提交（A∧B∧C∧D）** | **0** | 8 例候选只差 B 的人工记录 + D 的回执 |

8 例候选（`course_ready_blocked_by` 均为 `official_receipt_not_attached`，且
`acceptance.human_reviewed=false`）：

`CG-01`、`CG-07`、`CG-14`、`CG-18`、`CG-29`、`CG-30`、`CG-31`、`CG-36`

> 因此本验收的写法是“8 例候选 / 0 例可提交”，而不是“8 例已交付”。
> 若把 demo 的分支命中算进来，会同时破坏 A（不是独立缺陷根）与 C（无双端/官方判定）。

### 4.3 表三：Harness 实验指标（本次 demo 真跑）

| 指标 | 值 | 证据 |
|---|---|---|
| 执行次数 | 6 | 3 主链路 + 2 配置反例 + 1 无探针组 |
| 基线未命中（观测到的 `false`） | 1 | `stages/baseline.json` |
| 建议提案数 | 1（attempt 2；attempt 1 明确 `None`） | `suggestions/baseline.json` |
| 实际应用的配置变更 | 1 | `revisions.jsonl`（`tool=config_editor`） |
| 计划版本 == 实际加载版本 | 3/3 主链路 | baseline / modified / reverted |
| `not_effective` 反例 | 1 | `control_stale`（`ce-503217…`） |
| `unknown` 配置反例 | 1 | `control_no_report`（`ce-ce96d1…`） |
| 修改后检查点命中 | 1 | `modified`：`checkpoint_reached=true` |
| 回退保真（哈希 + manifest + 行为） | 3/3 同时恢复 | `stages/reverted.json` |
| 无探针组 `unknown` 字段 | 2（`input_processed`、`checkpoint_reached`） | `stages/no_probe.json` |
| 待复核项 / `accepted` / `rejected` | 4 / 4 / 0 | `HI1–HI4` |
| 模型摘要被接受 | 0（每次尝试都被拒） | `model_summary_not_accepted` |
| 模型建议自动应用 | 0 | `counts.model_auto_applied_changes=0` |
| 写 `verified` / `confirmed` | 0 | 未调用 `verify` |
| 新增独立根因数 / 漏洞发现 | 0 / 0 | `counts.independent_root_factors_added` |
| 可复跑性 | 6 个 stage 记录逐字段相同；revision/effect id 相同 | 两次重跑对比：仅账本 `created_at` 不同 |

---

## 5. 反过度声明与边界

| 没做什么 | 说明 |
|---|---|
| 没把分支命中写成漏洞发现 | demo 目标是无害解析器；`vulnerability_findings=0`，`outcome=no_repro` |
| 没把 `accepted` 写成 `verified/confirmed` | 交接裁决只覆盖执行记录；漏洞裁决只由 `verify` 写，本次未调用 |
| 没改历史证据 | 本验收**自己**只写 `docs/HARNESS-MVP-ACCEPTANCE.md` 与 `experiments/harness-acceptance/**`；`workspace/**`、`experiments/LEDGER.json`、历史 `case.json`、`tests/fixtures_config/**`、`fixtures/target_semantics/**` 均由本验收只读引用。验收期间仓库存在**并发会话**写入（见 §5.1），不在本验收动作内 |
| 没改业务代码 | 只新增 `docs/HARNESS-MVP-ACCEPTANCE.md` 与 `experiments/harness-acceptance/**` |
| 没 git commit | 按要求不提交 |
| 没把 demo 计入可提交案例 | 严格 A∧B∧C∧D 仍为 0 |

### 5.1 并发变更披露（验收环境事实）

本次验收期间（20:23–20:30）观察到仓库其他路径被并发会话改动。为免把别人的写入算成
本验收的动作，逐条披露；本验收没有执行任何写入这些路径的命令：

| 观察到的最近修改 | 路径 | 与本验收的关系 |
|---|---|---|
| 20:28:52 | `agent/platform/adaptive/compare.py` | 最后一次代码变更；**晚于**它的全量复跑在 20:29:03 启动，`253 passed` 对应当前代码 |
| 20:29:02 | `docs/V3-W4-AB.md` | 文档，不参与测试 |
| 20:28:38 / 20:29:24 | `workspace/CG-04-arvo-10400/artifacts/verify/p.bin`、`experiments/severity/review.json` | 非本验收写入；本验收的独立根/可提交计数在 20:29 复算后未变（51 根 / 9 高危根 / 8 候选 / 0 可提交） |
| 20:26:29 | `tests/test_v3_week4_ab.py` | 全量复跑已覆盖；计数仍为 253 |

结论：最终 253 passed 的复跑发生在最后一次代码修改之后；上表其他写入没有改变本文任何
计数或结论，但也说明**验收环境不是独占的**，正式交付前应在独占环境再复跑一次。

已知外部缺口（不是代码可修项）：

1. 8 例候选缺真实人工复核记录（`human_reviewed=true` 全为 0）；
2. 全部案例缺官方回执（`official_receipt` 全为 0）；
3. 盲测可用任务仍为 0（冻结后开发使用记录取走盲测资格）。

---

## 6. 复跑

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) V3 全量 + 关键 smoke
python3 -m pytest tests/test_v3_*.py -q
python3 -m pytest tests/test_v3_cg01_smoke.py tests/test_v3_smoke_record.py \
  tests/test_v3_target_semantics.py tests/test_v3_week2_config.py \
  tests/test_v3_week3_handoff.py tests/test_v3_week4_ab.py -q

# 2) 无害 demo（会重建 experiments/harness-acceptance/demo 与 evidence/）
python3 experiments/harness-acceptance/run_acceptance.py
# 期望末行：All acceptance checks passed.
```

demo 的 `demo/`、`evidence/` 是本轮生成的派生物；重跑会覆盖它们（历史台账不在其中，
不会被改）。若要保留某次结果，先把 `evidence/` 复制到别处再重跑。
