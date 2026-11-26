# 平台 v2 P1：ProgramIndex + 可证伪假设集

> 范围：P1 把“程序理解”和“假设集”固化成运行时产物：`ProgramIndex`（入口/函数/调用点/覆盖率/格式/源码量）与 ≤8 条可证伪假设。
> 本阶段仍然**只读**目标：不 build、不 fuzz、不联网、不产出 verdict。
> 前置：P0 的 TaskState / EventBus / EvidenceStore（[PLATFORM-V2-UPGRADE.md](PLATFORM-V2-UPGRADE.md) §5）。

## 1. 交付物

| 文件 | 内容 |
|---|---|
| [agent/platform/program.py](../agent/platform/program.py) | `ProgramIndex` 契约 + 三类 benchmark 的构建路径 + 有界扫描 + 静态锚点 |
| [agent/platform/hypotheses.py](../agent/platform/hypotheses.py) | ≤8 条假设生成（默认优先 D1.5 LLM、无 key 回退规则）、字段校验、无 verdict 硬约束、CLI 编排 |
| [agent/platform/store.py](../agent/platform/store.py) | `program_indexes` / `hypotheses` 表 + 幂等迁移 + 保存/读取方法 |
| [bin/platform.py](../bin/platform.py) | `understand` / `hypotheses` / `program` 子命令 |
| [tests/test_platform_v2_p1.py](../tests/test_platform_v2_p1.py) | 13 项验收：契约、CG/VG/fixture、字段、迁移、CLI、事件回放、无 LLM 伪造 |

## 2. ProgramIndex 契约

必选字段（任务口径）：

| 字段 | 含义 |
|---|---|
| `benchmark` | `cybergym` / `exploitgym` / `vulngym` / `target_yaml` |
| `root` | 静态分析根目录（绝对路径） |
| `entry_points` | `[{kind, name, file, line}]`，kind ∈ `main` / `fuzzer` / `fuzzer_init` / `harness` |
| `functions` | `[{name, file, line}]`（有界，上限 800） |
| `call_sites` | D1 调用点：`id/function/file/line/callee/category/args/controlled/reachable/score/status`（上限 240） |
| `coverage` | `planned/covered/uncovered/status` + 扫描透明度字段（见下） |
| `formats` | magic/扩展名识别结果，空则 `["unknown"]` |
| `source_count` | 源文件总数（不是被扫描数） |

扩展字段：`task_id / anchors / sources / notes / meta / counts / sha256`。
`sha256` 是内容哈希（忽略自身字段、排序序列化），可复算、可直接用于 `evidence` 引用。

### 2.1 三类 benchmark 的构建路径

| benchmark | 输入 | 做法 |
|---|---|---|
| `target_yaml` | 目标目录（含 `target.yaml`） | **直接复用 Discovery D0 `profile.scan` + D1 `callsites.scan` 全量扫描**；`target.yaml` 只读声明字段（name/format/build/fuzz） |
| `cybergym` / `exploitgym` | `workspace/task.json` + `src/` | 读 `task.json` 身份/镜像/component 元数据；复用 D0/D1 的解析函数做**有界扫描** |
| `vulngym` | `task.json` + `SOURCE.md`（workspace 常无源码树） | 从 `SOURCE.md` 表格与 `task.json` 提取静态定位锚点；workspace 若恰有 `src/` 才做有界扫描 |

### 2.2 有界扫描（CG/EG）

ARVO 源码树规模远超一次索引的预算（CG-01 全量 D0 就要 ~12s，D1 更慢）。因此：

- 源文件上限 `max_sources`（默认 240，CLI `--max-sources` 可调）；
- 排序优先级：`task.json component` 指向的文件 → 文件名含 `fuzz`/`harness` → 路径深度；
- 截断必须记账：`coverage.scanned_sources / total_sources / truncated_sources / truncated_sites / truncated_functions`；
- `source_count` 始终是**总数**，不是扫描数。

CG-01 实测：`source_count=2895`；`--max-sources 60` 约 0.9s、默认 240 约 2.3s；
识别到 `LLVMFuzzerTestOneInput`（`gstoraster_fuzzer.cc:113`）与 component 锚点
`pdf/pdf_font.c` → `ghostpdl/pdf/pdf_font.c:168 pdfi_open_CIDFont_substitute_file`。

函数归属：Discovery D1 的 `iter_functions` 对 K&R 风格（返回类型单独一行）会漏检。
ProgramIndex 只在归属为 `?` 时用严格兜底：函数名顶格 + 上一行是顶格纯类型前缀；
不满足就保留 `?`，不把调用语句误标成定义。CG-01 因此能把 `pdf_font.c:332` 归到
`pdfi_open_CIDFont_substitute_file`（与案例记录一致）。

### 2.3 VulnGym 静态锚点

`anchors` 元素：`{kind, file, resolved_file, line, symbol, repo, commit, verified, note}`。

- VG-01 实测锚点：`nltk/app/wordnet_app.py:87`、`MyServerHandler.do_GET`、`repo=https://github.com/nltk/nltk`、`commit=40d0bc1d`、`verified=false`；
- `verified=false` 是关键事实：workspace 没有源码树，行号只能在 `repo@commit` 上复算；
- 解析结果不完整时宁可不给锚点，也不猜：component 里只把“含下划线 / 小写开头驼峰”的 token 当符号（`pdfi_open_CIDFont_substitute_file` 收，`WordNet`/`browser` 不收）。

## 3. 假设集契约

字段（缺一即校验失败）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | `H1..H8` | 稳定编号，单任务内唯一 |
| `statement` | str | 可证伪命题：给条件与可观测后果，不用“可能存在漏洞”式表述 |
| `falsifiable_by` | str | 具体检验：输入形态 + 观测口径 + 否定条件 |
| `evidence_gap` | list[str] | 缺失证据（可达性、数据流、覆盖率、fix 端） |
| `cost` | `{level, execs, seconds}` | level ∈ low/medium/high |
| `confidence` | 0..1 | 静态先验，不是 verdict |
| `source` | str | `rule:call_site` / `rule:anchor` / `rule:entry_point` / `llm:<model>` |

附加：`site_id / function / file / line / category / callee / reachable / controlled / citations / window / llm / llm_status`。

硬约束（代码强制）：

1. **≤8 条**：`validate` 超上限直接拒绝；
2. **不得夹带 verdict**：任何层级出现 `verdict/confirmed/exploitable/severity/...` 键、或 statement 命中“已确认/确认漏洞/可利用/verdict”等 token，直接拒绝；
3. **不允许凭空来源**：`source` 必须是 `rule:*` 或 `llm:<model>`；无 key/超时/非法 citations 时严格回退规则，不编造 LLM 结论；
4. **citations 必须可解析**：规则路径只给 `file:line`（ProgramIndex 里的真实位置）；VulnGym 锚点行来自 SOURCE.md，**不给 citations**。

### 3.1 生成策略

1. 取 `call_sites`：**锚点文件（component/SOURCE.md）优先**，同组内按 score 降序；
   同一 `(file, line, callee)` 视为同一调用点，不同行是不同的命题（不按函数折叠，避免大函数吞预算），最多 8 条；
2. 规则文本按 category（copy/format/input/alloc）生成 statement + 检验口径；
3. `evidence_gap` 固定给出可达性/数据流/覆盖率/fix 端缺口；
4. 无调用点但有锚点 → 锚点假设（source=`rule:anchor`）；
5. 无调用点也无锚点 → 入口假设（source=`rule:entry_point`，confidence 0.10），不静默返回空集；
6. **默认（`use_llm=None` / CLI 不带参数）= auto**：与 Discovery/D1.5 一致，未显式禁用就尝试 D1.5 `llm_analyze`（前 4 个调用点）；
   无 key 时 `llm_analyze` 直接返回 `None`、不联网，假设集严格回退规则并记 `llm_status=no_key`；
   `--no-llm`（`use_llm=False`）是显式离线模式，一次都不调用并记 `llm_status=disabled`；
   `--llm` 强制尝试。事件 `hypothesis.proposed` 与返回体都带 `llm_mode ∈ auto/on/off`。
   （验收整改 F2，见 [ACCEPTANCE-FIXES-20261118.md](ACCEPTANCE-FIXES-20261118.md)。）
   citations 必须可解析、statement 不得含 verdict token，否则逐条回退规则；
7. 一条都生成不出来（无调用点/锚点/入口）时**拒绝进入 HYPOTHESES**：停在 UNDERSTANDING 并报错，不装空假设集。

## 4. SQLite 迁移

P0 的 `SCHEMA` 原样保留；P1 只新增 `SCHEMA_P1`，每次打开库都执行 `CREATE TABLE/INDEX IF NOT EXISTS` 并设 `PRAGMA user_version=2`：

~~~sql
program_indexes(task_id PK, benchmark, root, sha256, source_count,
                call_site_count, entry_count, doc_json, created_at, updated_at)
hypotheses(task_id, hypothesis_id, statement, falsifiable_by, evidence_gap_json,
           cost_json, confidence, source, doc_json, created_at,
           PRIMARY KEY(task_id, hypothesis_id))
~~~

- 幂等：同一库反复打开不改变 P0 数据；测试用“只有 P0 表的旧库”验证迁移后 P0 行仍可读；
- `program_indexes` 每任务一行（UPDATE→INSERT，保留 created_at）；
- `hypotheses` 为集合语义：整批替换（先 DELETE 再插入），不做增量合并。

store 新方法：`save_program_index / get_program_index / save_hypotheses / list_hypotheses / get_hypothesis`；`summary()` 增加 `program_index` 摘要与 `hypotheses` 计数。

## 5. 状态机与事件

~~~text
READY ──understand──→ UNDERSTANDING ──hypotheses──→ HYPOTHESES
~~~

- `understand`：要求 `READY`；`READY→UNDERSTANDING`，构建并保存 ProgramIndex，发 `program.indexed`（payload 含 sha256/counts/coverage/formats/anchors）；构建失败 → `FAILED`（事件流保留，可回放）；
- `hypotheses`：要求 `UNDERSTANDING`（或 `HYPOTHESES` 重跑）；生成→校验→`→HYPOTHESES`→保存→发 `hypothesis.proposed`（payload 含 count/max/llm_status/逐条 id+statement 摘要）；
- 其他状态调用直接报错、退出码 2，状态不变（`test_cli_hypotheses_requires_understand` / `test_cli_understand_hypotheses_end_to_end` 钉住）；
- 静态证据为 0（无调用点/锚点/入口）时，`hypotheses` 报错且停在 UNDERSTANDING（`test_hypotheses_requires_static_evidence`）；
- `EventBus.replay` 只认 `state.changed`，P1 事件不参与状态重建，重放两次结果一致。

## 6. 使用示例

~~~bash
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark target_yaml --target fixtures/discovery --task-id fx1
python3 bin/platform.py --db .platform/platform.db preflight fx1
python3 bin/platform.py --db .platform/platform.db understand fx1
python3 bin/platform.py --db .platform/platform.db hypotheses fx1
python3 bin/platform.py --db .platform/platform.db status fx1
python3 bin/platform.py --db .platform/platform.db program fx1     # 完整 ProgramIndex

# CyberGym：缩小扫描上限做快速索引
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark cybergym --target workspace/CG-01-arvo-44034 --task-id cg01-v2
python3 bin/platform.py --db .platform/platform.db preflight cg01-v2
python3 bin/platform.py --db .platform/platform.db understand cg01-v2 --max-sources 120

# VulnGym：target 是 URL，workspace 通过 metadata 传入
python3 bin/platform.py --db .platform/platform.db submit \
  --benchmark vulngym --target http://127.0.0.1:8000 --task-id vg01-v2 \
  --meta workspace=$PWD/workspace/VG-01-nltk-wordnet
~~~

## 7. 验收

~~~bash
python3 -m pytest tests/test_platform_v2.py tests/test_platform_v2_p1.py -q
# 20 passed
~~~

| 测试 | 钉住的事实 |
|---|---|
| `test_fixture_program_index_contract` | fixture（target_yaml）产出 1 入口 / 3 函数 / 4 调用点，哈希可复算 |
| `test_cg01_workspace_program_index` | CG-01 真实 workspace：有界扫描记账、fuzzer 入口、component 锚点行 168，且假设集优先落在 `pdf_font.c`（含 332 行） |
| `test_vulngym_source_md_anchors` | VG-01：无源码树 → `anchors_only` + repo/commit/file/line 锚点 |
| `test_hypotheses_fields_and_budget` | 字段完整、≤8、citations 与证据缺口 |
| `test_hypotheses_budget_and_verdict_are_rejected` | 9 条 / verdict 字段 / verdict 文本 / 空证据缺口全部拒绝 |
| `test_vulngym_hypothesis_from_anchor` | 锚点假设不伪造 citations |
| `test_no_llm_fabrication_without_key` | 无 key 时只有 `rule:*`，输出不含 key/Authorization |
| `test_p1_migration_is_idempotent_and_keeps_p0` | 旧库迁移幂等、P0 数据保留、覆盖写不重复 |
| `test_cli_understand_hypotheses_end_to_end` | CLI 全链路 + 事件类型/顺序 + 非法迁移拒绝 |
| `test_cli_hypotheses_requires_understand` | 跳步拒绝、状态不变 |
| `test_hypotheses_requires_static_evidence` | 无静态证据时不进 HYPOTHESES，状态不前进 |
| `test_p1_event_replay_is_stable` | 事件回放得到 HYPOTHESES 且两次一致 |
| `test_understand_failure_marks_failed_and_keeps_replay` | 构建失败 → FAILED，事件仍可回放 |

## 8. 边界（本阶段刻意不做）

- **不产 verdict**：P1 没有执行/验证证据；`confirmed` 只能在 P3 由 vuln/fix 或行为差分给出；
- **不做深度准入**：preflight 仍是 P0 的 target/authorized/image_declared 检查；镜像 digest、socket 探测、服务授权细节留 P2；
- **不执行目标**：不 build、不 fuzz、不访问网络；有界扫描只读源文件与 magic；
- **VulnGym 行号不可本仓复算**：`verified=false` 时必须带 repo+commit，禁止只写行号；
- **有界扫描会漏**：`truncated_sources > 0` 时 call_sites 只覆盖子集，这一点写进 `coverage` 与 `notes`，不假装全量。
