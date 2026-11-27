# vulnmap

面向 **CyberGym / ExploitGym / VulnGym** 的漏洞挖掘运行时：从**源码或二进制 + 构建方式**出发，做危险调用点排序、可证伪假设、覆盖率引导 fuzz、分诊、独立验证与证据打包。

设计原则一句话：**Agent 只指路，Fuzz 证明，Triage/Review 判定，报告只写可追溯的事实。**

> 本项目用于授权范围内的本地靶场、CTF 与课程实验。请勿用于未授权目标。

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [三条主线](#三条主线)
  - [1. Discovery：无已知崩溃的源码优先发现](#1-discovery无已知崩溃的源码优先发现)
  - [2. V2 任务运行时：状态机 + 事件 + 证据](#2-v2-任务运行时状态机--事件--证据)
  - [3. V3 自适应 Harness：执行感知与受限自修改](#3-v3-自适应-harness执行感知与受限自修改)
- [快速开始](#快速开始)
- [CLI 速查](#cli-速查)
- [隔离与安全边界](#隔离与安全边界)
- [诚实状态](#诚实状态)
- [仓库结构](#仓库结构)
- [文档索引](#文档索引)
- [测试](#测试)
- [许可与引用](#许可与引用)

---

## 它解决什么问题

传统复现流程依赖"已知崩溃信息"（error.txt / patch.diff / 官方 PoC），本质是**答案已知后的重放**。vulnmap 的 Discovery 主线反过来：

- **输入只有**：源码或 ELF、构建方式（`target.yaml` 或自动探测）；
- **不读取**：`error.txt`、`patch.diff`、官方 PoC；
- **不假设**：不知道崩溃在哪一行，先按危险调用点与可达性排序；
- **可证伪**：每条假设必须写清"怎么证明它是错的"；
- **可审计**：结论必须能追到输入哈希、构建哈希、日志与证据文件。

它不承诺发现 0day。它承诺的是：**每条结论都有证据链，没有证据就写 `needs_evidence`。**

---

## 三条主线

### 1. Discovery：无已知崩溃的源码优先发现

```text
D0 静态档案     后缀 / ELF magic / main / 函数 / 格式
D1 调用点排序   memcpy/strcpy/sprintf/malloc/read… · 权重 3/2/1 · 近似可达 · 参数可控
D1.5 只读分析   默认 LLM（无 key 回退规则）· ≤8 条可证伪假设 · 定向种子 + 字典
D2 覆盖率 Fuzz  ASAN + trace-pc/trace-cmp · 64K bitmap · cmp 操作数入字典
D3 分诊门禁     有效诊断 + 独立目录干净重建 3/3
D3.5 复核       规则复核，或显式开启单次 LLM 复核
D4 报告 + 台账  report.json / report.md / SQLite campaign.db
D5 对照实验     ranked vs random · Agent 种子 vs 纯 fuzz · 负结果保留
```

关键设计：

| 设计 | 原因 |
|---|---|
| 假设 ≤ 8 条、必须可证伪 | 防止"什么都可能是漏洞"的伪分析 |
| Fuzz 才是证明手段 | 模型不产 verdict；崩溃也不等于高危 |
| 干净重建 3/3 才算复现 | 复用旧构建的"能跑"不算证据 |
| WRITE → `confirmed`；READ/UB → `weakened` | 不把越界读夸大成可写漏洞 |
| 负结果保留 | 0 崩溃、0 覆盖、构建失败都记录，不删不改写 |

实现：`agent/discovery/`（`profile / callsites / agents / covfuzz / coverage_map / triage / report / campaign`），入口 `bin/discover.py`、`bin/covfuzz.py`。

### 2. V2 任务运行时：状态机 + 事件 + 证据

把"跑一个任务"变成**可恢复、可审计、可重放**的过程：

```text
RECEIVED → PREFLIGHT → READY → UNDERSTANDING → HYPOTHESES
        → PLANNED → RUNNING → CANDIDATE → VERIFYING → REVIEW
        → REPORTED → CLOSED
异常分支：BLOCKED / FAILED / NO_REPRO / NEEDS_EVIDENCE / REJECTED / CANCELLED / TERMINATED
```

- **TaskState**：主状态机，非法迁移直接拒绝；
- **EventBus**：append-only 事件流，可重放校验每一步 `state.changed`；
- **EvidenceStore**：内容寻址（`evidence/<sha256>`），报告只引用哈希；
- **Candidate / Verification / Review / Report**：候选、按赛道判定、复核、Case Pack 分离；
- **Budget**：`max_seconds / max_execs / max_tokens / max_turns` 强制，超限终止；
- **Job**：launcher 进程事实与实验语义分开，支持取消与 UNKNOWN 对账。

按赛道判定，不硬套同一把尺子：

| 赛道 | 判据 |
|---|---|
| CyberGym | 同输入 vuln 崩溃 / fix 干净 |
| ExploitGym | 官方入口取到 flag（不要求 fix 端） |
| VulnGym | 服务端行为差分或定位证据 |
| 通用 `target.yaml` | 单端 fuzz 只到 `candidate`，不冒充独立验证 |

实现：`agent/platform/`（`task / store / events / evidence / preflight / program / hypotheses / planner / executors / candidates / verify / review / casepack / runners / benchmark_policy`），入口 `bin/platform.py`。

### 3. V3 自适应 Harness：执行感知与受限自修改

在 `RUNNING` 内部加一层**慢循环**，让下一步由真实执行反馈决定，而不是固定脚本：

```text
OBSERVE → DIAGNOSE → PROPOSE → AUTHORIZE → STAGE → BUILD/SMOKE
        → EXECUTE → COLLECT → COMPARE → ADOPT / REVERT / STOP
```

边界写死：

- **模型只读事实、只提建议**，不写状态、不写证据、不改判据；
- **自修改仅限实验副本**（白名单配置、seed、字典、观测点），原件只读；
- **执行器必须回报实际加载的版本**，计划版本不算证据；
- **隔离 fail-closed**：构建/冒烟只认 `bwrap` / `container` 强隔离，只剩 `unshare` 时在启动子进程前拒绝；
- **工程采纳 ≠ 漏洞验证**：模型/规则都不能写 `verified` / `confirmed`。

三条硬语义修正（都有回归）：

1. `program_started` / `input_processed` / `checkpoint_reached` 三段分开，没探针记 `unknown`，不填 `false`；
2. `target_reached` 只由 `checkpoint_reached` 派生，不再用 `coverage_bits>0` 或 `execs>0` 冒充；
3. 逐调用参数账本区分 `sent` / `not_sent` / `missing`，不用默认值回填历史。

实现：`agent/platform/adaptive/`（`controller / session / workspace / revision / snapshot / contracts / tools / policy / handoff / budget / jobs / recovery / call_ledger / llm_provider / real_ab / compare / patch / backends`）。

---

## 快速开始

要求：Python ≥ 3.11；运行时**零第三方依赖**（标准库）。Fuzz 需要 `gcc` 与 ASAN；隔离建议安装 `bubblewrap`。

```bash
git clone https://github.com/HASAWEIS/vulnmap.git
cd vulnmap

# 1) Discovery：受控 fixture，3 秒
python3 bin/discover.py fixtures/discovery --out /tmp/out --seconds 3 --max-sites 3

# 2) Discovery：真实目标（需本地源码树）
python3 bin/discover.py /path/to/cJSON --target-yaml examples/targets/cjson.yaml \
  --out discovery/real-cjson --seconds 60 --max-sites 8

# 3) 生成 target.yaml 草稿
python3 bin/discover.py /path/to/target --init-target
```

V2 任务运行时（任务接入 → 准入 → 理解 → 假设 → 规划 → 执行）：

```bash
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark cybergym --target workspace/CG-01-arvo-44034 \
  --task-id cg01 --meta task_id=arvo:44034 --meta authorized=true
python3 bin/platform.py --db .platform/platform.db preflight cg01
python3 bin/platform.py --db .platform/platform.db understand cg01
python3 bin/platform.py --db .platform/platform.db hypotheses cg01
python3 bin/platform.py --db .platform/platform.db plan cg01
python3 bin/platform.py --db .platform/platform.db run cg01 --seconds 5
python3 bin/platform.py --db .platform/platform.db candidates cg01
```

研究模式（慢循环）：

```bash
python3 bin/platform.py --db .platform/platform.db run cg01 --research --max-rounds 2
python3 bin/platform.py --db .platform/platform.db research-status cg01
```

只读平台视图：

```bash
python3 vulnmap_platform/serve.py --port 8900
# 打开 http://127.0.0.1:8900/
```

---

## CLI 速查

### `bin/discover.py`

| 参数 | 说明 |
|---|---|
| `--out` | 证据输出目录 |
| `--seconds` | fuzz 预算（每 worker） |
| `--max-sites` | 分析的调用点上限 |
| `--workers` | 并行 worker 数 |
| `--format` | 结构化变异格式（png / tiff / json…） |
| `--analysis llm\|heuristic` | 假设来源；`--no-llm` 显式关闭 LLM |
| `--isolation` | `auto\|bwrap\|unshare\|container\|none` |
| `--require-isolation` | 隔离不可用直接失败 |
| `--target-yaml` / `--init-target` | 构建与 harness 描述 |
| `--eval` / `--ab` | ranked vs random / 种子 A/B |
| `--db` | SQLite 台账 |

### `bin/platform.py`

```text
submit preflight status events evidence replay understand hypotheses program
plan run cancel budget candidates verify smoke verifications reviews reports
research-status research-events review casepack attach transition patch
```

常用组合：

| 目的 | 命令 |
|---|---|
| 看任务状态与事件重放 | `status <task>` |
| 只重放状态机 | `replay <task>` |
| 端到端准入探测 | `smoke CG-01 --execute` |
| 落验证台账 | `smoke CG-01 --execute --record` |
| 生成 Case Pack | `casepack <task> --close` |

---

## 隔离与安全边界

| 层级 | 机制 |
|---|---|
| 网络 | bwrap `--unshare-net`；container `--network none` |
| 文件系统 | 只读根 + 必要目录可写绑定；工作区外写入拒绝 |
| 权限 | `--cap-drop ALL`、`no-new-privileges`、PID 命名空间 |
| 资源 | 超时、`--pids-limit`、`--memory`、进程组清理 |
| 宿主 | 隔离不可用即拒绝，不回退宿主执行 |

其他约束：

- 目标 worker **不继承模型 API key**；环境变量按名称黑名单过滤；
- 密钥只从环境变量读取，不写入仓库、日志、账本或报告（账本只记 `key_ref`）；
- 模型输入（源码、日志、RAG、工具返回）一律视为**不可信数据**，不得改变工具表、预算或判据。

---

## 诚实状态

以下数字来自仓库内可复算台账（`experiments/audit_ledger.py`），**不是完成度百分比**：

| 指标 | 当前值 |
|---|---:|
| 台账案例行 | 31 |
| 独立高危根因（按根因键去重） | **10** |
| 其中"Benchmark 验证 + 因果链"同时成立 | **9** |
| 严格 V2 提交包 | **5**（材料齐备 7，其中 2 份为人工验证包） |
| 第三方独立复核 | **0** |
| 后端 `course_ready` | **0** |
| 测试 | 1572 passed · 8 skipped · 17 xfailed（旧前端断言待迁移） |

需要如实说明的边界：

- **独立根因 11 个，严格可提交仍是 5 份。** 另有 2 份人工验证包（AR6/AR7）包内复算通过但未过严格 V2，不计入；复核方是平台维护者本人（内部自审），不是第三方；
- **ExploitGym 必选项未认定。** 历史 10/10 flag 只证明链路可达，缺官方/第三方判定，且与 CG-01 同根，不增加独立计数；
- **CG-07 / CG-18** 的历史采样参数无法补录，D2 保持 `false`；新账本只记录后续调用；
- **CG-14** 缺自主生成证据（PoC 与答案模板同字节），不可提交；
- **VG-01** 缺官方 baseline/patched 服务端对照；
- **模型默认仍是规则。** 只读 A/B 中规则与模型同为 7/10，模型更慢更贵，错误采纳未减少，因此不开放自动应用；
- **受控 fixture 的 `confirmed` 不等于真实目标战果。** 真实目标上目前只有 cJSON 的 `weakened` 越界读。

---

## 仓库结构

```text
agent/
  discovery/          Discovery D0–D5
  platform/           V2 任务运行时
    adaptive/         V3 慢循环、隔离副本、账本、A/B、补丁
    executors/        static / dynamic / fuzz / replay
    runners/          cybergym / exploitgym / vulngym
  stages/             旧五阶段（归档，仅历史案例）
  runtime/            旧编排器（归档）
bin/
  discover.py         Discovery 入口
  covfuzz.py          独立 fuzz 入口
  platform.py         V2/V3 入口
  vulnmap.py          旧复现入口（归档）
fixtures/             受控靶子（含 Discovery PNG/TIFF/JSON 样例）
examples/targets/     target.yaml 示例（cjson / libpng / libtiff…）
docs/                 设计、验收、课程证据与状态文档
tests/                pytest（1592 项）
vulnmap_platform/     只读 Web 视图 + API
```

> 仓库刻意不包含 `workspace/`、`experiments/`、`discovery/` 下的原始靶场与实验产物（本地约 9.6 GB）。
> 这些是本地证据库，按需生成；仓库只保留代码、文档、测试与前端。

---

## 文档索引

| 主题 | 文档 |
|---|---|
| Discovery 设计与结果 | [DISCOVERY-V1.md](docs/DISCOVERY-V1.md) · [DISCOVERY-V1-RESULTS.md](docs/DISCOVERY-V1-RESULTS.md) |
| V2 升级方案 | [PLATFORM-V2-UPGRADE.md](docs/PLATFORM-V2-UPGRADE.md) |
| V3 目标语义 | [V3-TARGET-SEMANTICS.md](docs/V3-TARGET-SEMANTICS.md) |
| V3 隔离验收 | [V3-ISOLATION-ACCEPTANCE.md](docs/V3-ISOLATION-ACCEPTANCE.md) |
| V3 受控配置与回退 | [V3-W2-CONFIG.md](docs/V3-W2-CONFIG.md) |
| V3 证据交接与独立复核 | [V3-W3-HANDOFF.md](docs/V3-W3-HANDOFF.md) |
| 逐调用参数账本 | [CALL-LEDGER.md](docs/CALL-LEDGER.md) · [ACTUAL-AB-LEDGER.md](docs/ACTUAL-AB-LEDGER.md) · [VERIFY-CALL-LEDGER.md](docs/VERIFY-CALL-LEDGER.md) |
| 模型只读 A/B | [V3-REAL-AB.md](docs/V3-REAL-AB.md) · [AB-ERROR-REVIEW.md](docs/AB-ERROR-REVIEW.md) |
| 规则诊断优先级 | [RULE-DIAGNOSIS-PRIORITY.md](docs/RULE-DIAGNOSIS-PRIORITY.md) |
| 课程判据与复核 | [COURSE-CRITERIA-V2.md](docs/COURSE-CRITERIA-V2.md) · [COURSE-CASE-AUDIT.md](docs/COURSE-CASE-AUDIT.md) |
| 第 6 份案例（AR6） | [CASE6-AR6-20261127.md](docs/CASE6-AR6-20261127.md) · [CASE6-CHECKLIST.md](docs/CASE6-CHECKLIST.md) |
| 提交包与缺口 | [COURSE-SUBMISSION-PACK-20261125.md](docs/COURSE-SUBMISSION-PACK-20261125.md) · [COURSE-GAP-DISPOSITION.md](docs/COURSE-GAP-DISPOSITION.md) |
| 当前状态与统计 | [STATUS.md](docs/STATUS.md) · [STATS.md](docs/STATS.md) |

---

## 测试

```bash
python3 -m pytest tests -q

# 分组
python3 -m pytest tests/test_discovery.py -q            # Discovery
python3 -m pytest tests/test_platform_v2*.py -q         # V2 运行时
python3 -m pytest tests/test_v3*.py -q                  # V3 Harness
```

当前基线：

```text
1572 passed, 8 skipped, 17 xfailed
```

测试约定：

- 验证器/账本/隔离类测试**不联网**，除本地 `127.0.0.1` fixture；
- 真实模型调用默认关闭，需显式环境变量；
- 测试通过不代表真实靶场通过；真实结论只认 `verifications` 台账与原始证据。

### 关于 17 项 xfailed

`vulnmap_platform/static` 已从旧 Discovery 页面替换为新版仪表盘（`dashboard.js` + 5 项导航 + 课程三指标卡片）。
下列测试仍按**旧前端 DOM** 写死（`<script id="stat-keys">`、10 项导航、首屏 17/3、CSS 版本串），
描述的是已被替换的实现：

- **没有删除**这些测试（避免"删测试让 CI 变绿"）；
- 在 `tests/conftest.py` 的 `LEGACY_FRONTEND_TESTS` 中集中登记为 `xfail(strict=False)`；
- 迁移到新版口径后从该表移除，自动恢复为普通测试。

具体清单与迁移说明见 [docs/FRONTEND-COURSE-METRICS.md](docs/FRONTEND-COURSE-METRICS.md) 的"遗留测试"一节。

---

## 许可与引用

- 本仓库尚未声明开源许可证。用于课程作业与授权研究；对外分发前请先补充许可证。
- 第三方靶场与数据（CyberGym / ExploitGym / VulnGym、ARVO 元数据、各开源项目源码）版权归各自权利人，本仓库不重新分发其源码树。
- 引用本项目请注明仓库地址与提交哈希。
