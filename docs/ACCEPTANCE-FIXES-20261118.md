# 平台验收整改记录：F1–F4（2026-11-18）

> 依据：[../验收_20261118/平台验收报告.md](../../验收_20261118/平台验收报告.md) 第二节 F1–F4。
> 范围：只改平台侧（授权口径、V2 假设集 LLM 默认、主页 benchmark 口径、准入恢复入口）与其文档/测试。
> **未改** Discovery 核心（`agent/discovery/**`、`bin/discover.py`）、未改历史案例数据
> （`workspace/*/artifacts/**`、`experiments/LEDGER.json`），未调用真实 LLM，未 `git commit`。

| 项 | 结论 | 关键证据 |
|---|---|---|
| F1 授权字符串 `false` 被当成 true | 已修（严格解析 + 缺失默认阻断） | `agent/platform/authorization.py`；CLI/API 回归 |
| F2 V2 假设集未继承“默认使用 LLM” | 已修（默认 auto，`--no-llm` 显式关闭） | `resolve_llm_mode`；mock 三态回归 |
| F3 主页按 `local_verified` 算所有赛道 | 已修（按 `benchmark_verified` + 分赛道列） | `/api/cases` 新字段；`index.html` |
| F4 BLOCKED 后不能重新准入 | 已修（BLOCKED 可重试，事件只追加） | `preflight.py`；失败→补齐→重试→重放用例 |
| F5 正式入口/三类真实 runner 未就绪 | **未处理**（环境问题，非代码问题） | 见 §7 |

测试命令与结果：

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_platform_v2_*.py tests/test_platform_v2.py \
                 tests/test_platform_discovery.py \
                 tests/test_platform_acceptance_fixes.py -q
# 301 passed in 34.26s
```

（`tests/test_platform_acceptance_fixes.py` 新增 66 项；既有 V2/discovery 用例全部保持通过。
另：`tests/test_platform.py`、`test_platform_stats.py`、`test_platform_ui_stats.py` 也一并跑过，
合计 341 passed。）

---

## 1. F1 · 授权声明严格解析

### 1.1 根因

CLI `--meta authorized=false` 把值当字符串存进 `metadata`，准入直接
`bool(authorized)`。非空字符串恒为真，于是“未授权”被判成“已授权”：

```python
bool("false") is True    # F1 的根因
bool("0") is True
bool("no") is True
```

### 1.2 修复（三层，同一口径）

| 层 | 文件 | 行为 |
|---|---|---|
| 解析 | `agent/platform/authorization.py`（新增） | `parse_authorized()` 只认 `true/1/yes/on` 与 `false/0/no/off`（JSON 布尔与整数 `1/0` 同义）；其余值 / 类型抛 `AuthorizationError` |
| 入口归一化 | `agent/platform/task.py` `TaskSpec.__post_init__` | CLI `--meta`、API `metadata`（dict 或 `k=v` 列表）都走 `normalize_metadata()`：提交时就变成布尔落库，非法值直接拒（CLI 退出 2 / API 400），不落库 |
| 准入判定 | `agent/platform/preflight.py` | `authorization.resolve()` 严格解析；历史脏数据（库里仍是字符串 `"false"`）同样按 `false` 阻断，非法值 fail-closed 阻断 |

`authorized` 检查项现在带 `declared` / `reason` / `policy` 三个字段，
事件与 API 响应里能直接看出“为什么阻断”，不再是裸布尔。

### 1.3 缺失授权策略（显式决定）

**产品口径：默认阻断（`MISSING_POLICY = "block"`）。**

- 未声明 `metadata.authorized` → 准入判 `BLOCKED`，`reason=missing`，`policy=block`；
- 理由：授权声明是门禁而不是默认值。旧行为“缺字段即 READY”与 F1 的字符串 bug 属于同一类失效
  ——判定失效时放行；改成默认阻断后，判定失效一律停在 BLOCKED；
- 该常量是显式常量而不是散落的隐式默认值：改口径必须改这个常量，并同步本文档与回归用例
  （`tests/test_platform_acceptance_fixes.py::test_f1_missing_policy_is_explicit_block`）。

复现验收报告里的原始命令，现在的结果：

```console
$ python3 bin/platform.py --db /tmp/f1-repro/p.db submit --benchmark target_yaml \
    --target /tmp/f1-repro/target --task-id cli-auth-false --meta authorized=false
metadata= {'authorized': False}          # 落库即布尔，不是字符串
$ python3 bin/platform.py --db /tmp/f1-repro/p.db preflight cli-auth-false
{ "state": "BLOCKED",
  "checks": [ {"name": "target_path", "ok": true, ...},
              {"name": "authorized", "ok": false, "detail": "authorized=false",
               "declared": false, "reason": "false", "policy": "block"} ],
  "blockers": ["authorized"], "retry": false, "previous_state": "RECEIVED" }
$ echo $?
1
```

### 1.4 覆盖的入口

| 入口 | 处理 |
|---|---|
| CLI `submit --meta authorized=false` | 归一化为 `False`，preflight → BLOCKED |
| CLI `submit --meta authorized=maybe` | 提交即失败（退出 2，任务不落库） |
| API `POST /api/platform/tasks`（`metadata` 为对象） | 同上；非法值 400 |
| API `POST /api/platform/tasks`（`metadata` 为 `["authorized=false"]`） | 走同一条归一化路径 |
| 库里的历史字符串（`metadata_json` 仍是 `"false"`） | 准入时严格解析后阻断 |

### 1.5 回归

`tests/test_platform_acceptance_fixes.py` F1 段：真值/假值/非法值/非法类型的参数化、
`bool("false")` 根因断言、缺失策略断言、`TaskSpec` 归一化、库内脏数据阻断、
CLI 四个方向（false 阻断 / true 放行 / 非法值拒绝 / 缺失阻断）、API 四个方向。

---

## 2. F2 · V2 假设集默认优先 LLM

### 2.1 改动

| 位置 | 之前 | 之后 |
|---|---|---|
| `agent/platform/hypotheses.py` | `propose(use_llm=False)` / `run_hypotheses(use_llm=False)` | 三态 `use_llm: bool \| None = None`：`None`=auto、`True`=on、`False`=off（`resolve_llm_mode`） |
| `bin/platform.py hypotheses` | `--llm`（store_true），默认只走规则 | `--llm` / `--no-llm` 互斥组，默认 auto |
| 事件/返回值 | 只有 `llm: bool` | 增加 `llm_mode: auto\|on\|off`，`llm_status` 如实写 `no_key` / `disabled` / `ok` |

auto 的语义与 D1.5/Discovery 一致：`not llm_disabled()` 就**尝试** LLM；
`DISCOVERY_LLM_DISABLED=1` / `VULNMAP_DISABLE_LLM=1` 是环境级显式关闭。
没有 key 时 `agents.llm_analyze()` 内部 `_llm_config()` 为空直接返回 `None`，
**不发网络请求**，假设集回退规则并记 `llm_status=no_key`。

`--no-llm`（`use_llm=False`）时一条记录都不会走 `llm_analyze`，`llm_status` 记 `disabled`。

### 2.2 回归（全部 mock，不花 token）

| 用例 | 断言 |
|---|---|
| `test_f2_default_is_auto_and_matches_discovery` | `resolve_llm_mode(None) == (True, "auto")`；Discovery `analyze_site` 默认 `use_llm=True` |
| `test_f2_configured_default_calls_llm` | 有 key + mock：默认路径真的调用了 mock，`source=llm:mock-model`、`llm=True` |
| `test_f2_no_config_falls_back_to_rule` | 无 key：连 `socket.connect` 都被替换成抛错，全程零网络；`source=rule:*`、`llm_status=no_key` |
| `test_f2_explicit_off_never_calls` | 配置齐全但 `use_llm=False`：mock 调用次数 0 |
| `test_f2_run_hypotheses_records_mode` | 事件 `hypothesis.proposed.payload.llm_mode == "auto"`、`llm == True` |
| `test_f2_cli_default_auto_and_no_llm_flag` | CLI 默认 `llm_mode=auto`（无 key → 规则 + `no_key`）；`--no-llm` → `llm_mode=off`、`llm_status=disabled`；`--llm --no-llm` 参数层拒绝 |

---

## 3. F3 · 主页 benchmark 统计口径

### 3.1 问题

`benchStats()` 用 `c.local_verified` 当所有 benchmark 的“通过”，于是：

- ExploitGym 显示 `0/2、0%`，而 EG-02 早已 `benchmark_verified=true`、`exploit_flag_issued=true`；
- VulnGym 也被套上“双端通过”，与它自己的行为/定位判据无关；
- 合计“双端通过 22/30”，而按 `benchmark_verified` 逐例核账是 23。

### 3.2 修复

**后端（只读字段，不改任何验收状态）**：`vulnmap_platform/api/app.py`

- `/api/cases` 的每条 item 增加 `benchmark_verified`、`benchmark_criterion`
  （`cybergym→vuln_fix_diff`、`exploitgym→exploit_flag`、`vulngym→behavior_diff`）、
  `exploit_flag_issued`、`counts_in_denominator`；
- 取值顺序：**台账行（`experiments/LEDGER.json`，逐例核账）→ case.json `acceptance`**。
  历史 case.json 多数没有 `benchmark_verified`，只看 case.json 会漏算，所以以台账行优先；
  台账索引按 `LEDGER.json` 的 mtime 缓存，仍然只读。

**前端**：`vulnmap_platform/static/index.html`（软链，实际文件
`前端改版_20261115/MODIFIED_FILE/index.html`，同一 inode）

- `benchStats()` 的通过数改为 `benchmark_verified === true`；
- 表格按赛道分列：`CG 双端`（`local_verified`，仅 CyberGym 有值）、
  `EG flag`（`exploit_flag_issued`，仅 ExploitGym）、`VG 行为`（`benchmark_verified`，仅 VulnGym），
  不适用的单元格显示 `—`，不同赛道不混算；
- “CG 双端”作为**单列指标**保留（指标卡 + 独立表列），不再当所有赛道的成功率；
- 分母明示：`分母 = 台账案例（含撤回 N 例，明示不剔除）`，表尾写明
  “撤回 X 例已计入分母”，页脚写明“CG 双端仅为 CyberGym 专用指标”；
- 首屏 `stat-keys` 把“本地双端通过”换成 `ledger_totals.benchmark_verified`，
  并新增 `CG 双端通过` = `ledger_totals.local_dual_run_pass`。

### 3.3 现场数字（本机 8123 临时服务，真实台账）

用页面里同一段 `benchStats()` 在 node 里跑 `/api/cases` 的实时数据：

| benchmark | 案例 | 验证通过 | 通过率 | CG 双端 | EG flag | VG 行为 | 撤回 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CyberGym | 27 | 21 | 78% | 21 | — | — | 0 |
| ExploitGym | 2 | 1 | 50% | — | 1 | — | 1 |
| VulnGym | 1 | 1 | 100% | — | — | 1 | 0 |
| 合计 | 30 | **23** | 77% | 21 | 1 | 1 | 1 |

改前合计是“双端通过 22/30”，改后是“验证通过 23/30”，并明确 23 = CG 双端 21 + EG flag 1 + VG 行为 1。
EG-02 的 `local_verified=false` 但 `benchmark_verified=true` 现在会被正确计入，这正是 F3 要修的错账。

### 3.4 回归

- `test_f3_cases_api_exposes_per_benchmark_verdict`：字段齐全，`benchmark_verified` 合计与台账逐例一致；
- `test_f3_criteria_are_per_benchmark`：三个赛道的判据互不相同，EG 有“通过但不双端”的行；
- `test_f3_page_uses_benchmark_verified` / `test_f3_stat_keys_use_benchmark_verified`：页面口径 + 首屏键；
- `test_f3_benchstats_behaviour_in_node`：把页面里的 `benchStats()` 抽出来在 node 里跑，
  断言 CG/EG/VG 各自的 `verified/dual/flag/behavior/withdrawn` 与“非本赛道留空”。

---

## 4. F4 · BLOCKED 补齐材料后重新准入

### 4.1 改动

- `agent/platform/preflight.py`：入口状态从 `RECEIVED` 放宽到 `RECEIVED`/`BLOCKED`
  （`ENTRY_STATES`）；`BLOCKED → PREFLIGHT` 本来就在状态机 `task.py:48` 里，现在真正被入口使用；
- 每次准入只**追加**事件：`state.changed(BLOCKED→PREFLIGHT)`、
  `state.changed(PREFLIGHT→READY/BLOCKED)`、`preflight.passed/failed`
  带 `retry` 与 `previous_state`；旧事件一条都不删、不改；
- 返回值增加 `retry` / `previous_state`，`EventBus.replay()` 因此得到
  `PREFLIGHT → BLOCKED → PREFLIGHT → READY` 的完整轨迹；
- `vulnmap_platform/api/platform_tasks.py`：`POST /{id}/preflight` 同样受理 `BLOCKED`，
  其它状态仍 409（错误信息写明 `RECEIVED or BLOCKED (retry)`）。

### 4.2 回归（失败 → 补齐 → 重试 → 事件重放一致）

| 用例 | 断言 |
|---|---|
| `test_f4_preflight_retry_after_material_provided` | 首次 BLOCKED；建目录后重试 READY；旧事件 seq 前缀不变；事件类型同时含 `preflight.failed` 与 `preflight.passed`；`replay.state=READY`、transitions=`PREFLIGHT,BLOCKED,PREFLIGHT,READY`；两次重放结果相同 |
| `test_f4_retry_while_still_blocked_keeps_appending` | 材料没补时重试仍 BLOCKED，transitions 变成 4 段（只追加） |
| `test_f4_retry_rejects_ready_state` | READY 状态重试仍报错（不绕过检查直接跳 READY） |
| `test_f4_cli_retry_end_to_end` | CLI：`preflight` 退出 1 → 建目录 → `preflight` 退出 0 → `status` 里 transitions 与事件数正确 |
| `test_f4_api_retry_end_to_end` | API：两次 200，`retry=true`，`timeline` 四段，`preflight.failed`/`preflight.passed` 各一条 |

---

## 5. 受影响的既有测试（为什么改）

F1 的“缺失授权默认阻断”是有意改变的产品口径，所以既有用例里那些**隐式依赖
“没声明授权 = 放行”**的夹具必须显式声明授权，否则它们测的就不是真实流程：

| 文件 | 改动 |
|---|---|
| `tests/test_platform_v2.py` | `_spec()` 默认 `metadata={"authorized": True}`；vulngym 用例、CLI 用例补 `--meta authorized=true` |
| `tests/test_platform_v2_p1.py` / `_p2.py` / `_exec.py` / `_p36.py` / `_p37.py` | 夹具 `metadata` 合并 `authorized: True`；CLI 提交补 `--meta authorized=true` |
| `tests/test_platform_v2_p4.py` / `_p45.py` | API `_submit()` 补 `metadata={"authorized": True}` |

没有放宽任何断言：`test_preflight_blocks_missing_target`、`test_unauthorized_blocks`、
`test_preflight_rejects_wrong_state` 等负向用例原样保留并继续通过。

另外发现一处**既有**文档漂移（与本次代码无关）：`docs/STATUS.md` 里
“本地双端通过 22”和 EG-02 的旧 `verdict/阶段` 与台账不符，导致
`tests/test_docs_in_sync.py::test_status_md_matches_ledger` 在改动前就是红的。
按台账重新生成 `docs/STATUS.md`（只差 2 行：双端通过 22→21、EG-02 阶段改为
`benchmark_verified_pending_evidence`），未改 `LEDGER.json` 与任何案例数据。

---

## 6. 变更清单

新增：

- `agent/platform/authorization.py`：授权解析 + 缺失策略（`MISSING_POLICY`）。
- `tests/test_platform_acceptance_fixes.py`：F1–F4 共 66 项回归。
- 本文档。

修改：

- `agent/platform/task.py`：`TaskSpec` 归一化 `metadata.authorized`。
- `agent/platform/preflight.py`：严格授权判定 + `BLOCKED` 重试入口 + `retry/previous_state`。
- `agent/platform/hypotheses.py`：`resolve_llm_mode`、三态 `use_llm`、事件记 `llm_mode`。
- `bin/platform.py`：`hypotheses --llm/--no-llm`。
- `vulnmap_platform/api/platform_tasks.py`：准入受理 `BLOCKED`，响应带 `retry/previous_state`。
- `vulnmap_platform/api/app.py`：`/api/cases` 增加 benchmark 判据字段（只读）。
- `vulnmap_platform/static/index.html`（= `前端改版_20261115/MODIFIED_FILE/index.html`，
  sha256 `c346b1f8…d9c`，改动后）：`benchStats`/`benchTable`/指标卡/表头/页脚口径。
- `tests/test_platform_v2*.py`（7 个文件）：夹具显式声明授权。
- `docs/STATUS.md`：按台账重新生成（既有漂移）。
- `README.md`、`docs/PLATFORM-V2-P1.md`、`docs/PLATFORM-V2-P4.md`：同步口径。

> 前端历史清单 `前端改版_20261115/final-manifest.json` 记录的是 11-15 那次改版的
> 基线/修改后哈希，本次 F3 改了 `index.html`，该清单里的 `index.html` 哈希因此不再匹配。
> 那份清单是历史事务证据，**没有回写**；当前文件的真实哈希以上面这行为准。

---

## 7. 未处理与边界

- **F5 仍是环境阻塞**：8102 未运行、CG-01 缺镜像、EG-02 缺 mode/expected_flag、
  VG-01 缺 baseline/patched。本次只做代码与口径整改，不把这些包装成“已验收”。
- 未调用真实 LLM。F2 的所有调用/回退断言都在 mock 下完成，`llm_analyze` 被替换，
  无 key 场景还额外把 `socket.connect` 换成抛错以证明零网络。
- 未改 Discovery 核心与历史案例；`experiments/LEDGER.json`、`workspace/*/artifacts/**` 未改。
- 未 `git commit`（仓库当前不是 git 工作区）。
- 重试入口只重跑检查，不提供“改元数据”的命令：`TaskSpec` 的 `target/metadata` 建任务后不可变，
  补材料指建目标目录/服务/镜像；要改授权声明需新建任务（这条限制写在这里，避免被当成已支持）。

## 8. 复验命令

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 四类修复的定向回归
python3 -m pytest tests/test_platform_acceptance_fixes.py -q

# 2) 既定验收集
python3 -m pytest tests/test_platform_v2_*.py tests/test_platform_v2.py \
                 tests/test_platform_discovery.py -q

# 3) F1 原始复现（应 BLOCKED、退出 1）
mkdir -p /tmp/f1-repro/target
python3 bin/platform.py --db /tmp/f1-repro/p.db submit --benchmark target_yaml \
  --target /tmp/f1-repro/target --task-id cli-auth-false --meta authorized=false
python3 bin/platform.py --db /tmp/f1-repro/p.db preflight cli-auth-false

# 4) F2 三态（无 key 时默认仍应回退规则并记 no_key）
python3 bin/platform.py --db /tmp/f1-repro/p.db understand cli-auth-false   # 需先 READY
python3 bin/platform.py --db /tmp/f1-repro/p.db hypotheses cli-auth-false --no-llm

# 5) F4 重试
mkdir -p /tmp/f4/target
python3 bin/platform.py --db /tmp/f4/p.db submit --benchmark target_yaml \
  --target /tmp/f4/target --task-id f4 --meta authorized=true
rmdir /tmp/f4/target
python3 bin/platform.py --db /tmp/f4/p.db preflight f4     # BLOCKED，退出 1
mkdir -p /tmp/f4/target
python3 bin/platform.py --db /tmp/f4/p.db preflight f4     # READY，退出 0
python3 bin/platform.py --db /tmp/f4/p.db status f4        # transitions 四段
```
