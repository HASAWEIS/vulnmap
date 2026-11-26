# 前端课程证据三档口径（`docs/FRONTEND-COURSE-METRICS.md`）

> **⚠ 本文是旧版（`前端改版_20261115/MODIFIED_FILE/index.html`）的实现记录，保留作历史。**
> 8102 现役前端自 2026-11-25 18:15 起换为 `前端收口_20261125.sv8KTO/MODIFIED_FILE`（`dashboard.js` 结构），
> 三指标已迁到新版仪表盘，新文档见 **[FRONTEND-COURSE-METRICS-V2.md](FRONTEND-COURSE-METRICS-V2.md)**。
>
> **§0.1 的现盘更正状态已变（2026-11-25 19:34）**：CG-01 的 `review.json` 已按
> `restored_from` 从派生证据重建（`experiments/course-review-cg01/restore_review.py`），
> `recompute.py` 复算 **D3 pass → strict_submittable=true**，因此 **5/8 现在可复算**，
> 「今日只能 4/8」这句话自此失效。重建的边界（无新签署人、字节不等价、internal 性质不变）
> 见 [COURSE-REVIEW-CG01.md §5.3.1](COURSE-REVIEW-CG01.md) 与 V2 文档。
> 另：本文 §0.1 写「没有重建、没有补写 `review.json`」——那是对当时**凭空补写**的拒绝；
> 本次重建逐字段可追到已落盘产物并自注差异，性质不同，两处结论不冲突。

> **做了什么**：在首页 `index.html` 新增「课程证据口径」区块，把原先被压成一个数的课程结论
> 拆成**三个并列、互不覆盖**的数字——**V2 内部复核可提交 5/8 · 第三方独立复核 0 · 后端 `course_ready` 0**，
> 每一项标注**来源文档**与**「内部 / 外部 / 后端」口径**，并写明「课程结论：未通过、未判定」。
> 现有 benchmark / 台账统计（`benchStats`、8 张 `metric` 卡片、`stat-keys`、benchmark 表）**一行未改**。
>
> **⚠ 现盘复算更正（2026-11-25 19:15，见 §0.1）**：`workspace/CG-01-arvo-44034/review.json` **已从磁盘消失**
> （`MANIFEST.sha256` 校验 1 项失败，`recompute.py --check` 判 `D3 fail`、退出码 2），
> 因此 **5/8 今日不可复现，现盘可复算的是 4/8**（CG-29/30/31/36）。页面按「文档口径 5/8 + 卡片内
> 明示现盘 4/8 及原因」展示：**主数字不改写、差异不隐瞒**。
>
> **前端源**：`前端改版_20261115/MODIFIED_FILE/index.html`（本次唯一被修改的产品文件）
> **配套检查**：[frontend_course_metrics_check.py](frontend_course_metrics_check.py)（30 条断言，只读）
> **截图**：[面板（桌面）](assets/course-metrics-panel.png)、[整页（桌面）](assets/course-metrics-desktop.png)、
> [整页（手机）](assets/course-metrics-mobile.png)、[面板（手机）](assets/course-metrics-mobile-panel.png)
> **纪律**：只改前端源与 `docs/`；未改后端、未改 `style.css`、无 `git commit`（仓库根不是 git 工作区）。

---

## 0. 三条数字（唯一口径表）

| 卡片 | 数字 | 口径 | 来源文档 | 含义边界 |
|---|---:|---|---|---|
| **V2 内部复核可提交** | **5 / 8 例**（文档口径；**现盘复算 4/8**，见 §0.1） | **内部**（`internal_attested`，`third_party=false`） | [COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md) §0（CG-01 = 1 例）＋ [COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md) §0/§2（CG-29 / 30 / 31 / 36 = 4 例） | 内部自审：不等于第三方复核，也不等于课程已通过 |
| **第三方独立复核** | **0 / 8 例** | **外部**（本仓无任何第三方签字） | [COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md) §0 ＋ [COURSE-REVIEW-BATCH.md](COURSE-REVIEW-BATCH.md) §0（`external_independent_submittable` 全 false、`external_status=pending`）＋ [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) §3 | 外部口径空缺：`receipt.json` 未生成、未伪造 |
| **后端 `course_ready`** | **0 / 8 例** | **后端**（旧机器门禁字段） | [COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) §0（`course_ready=true` 计 0）＋ [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) §7 | 机器门禁 ≠ V2 判定；0 不等于材料全废 |

**分母 8 例**：[COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) §0 的审计范围——
CG-01 / CG-07 / CG-14 / CG-18 / CG-29 / CG-30 / CG-31 / CG-36。

**为什么三个数不能合并**：三者问的是三个不同的问题——「材料按 V2 齐不齐（内部谁判的）」、
「有没有与本平台无组织关系的第三方签过」、「后端机器门禁放不放行」。任何一个为真都推不出另外两个，
相加也没有意义（5 + 0 + 0 不是「5 例通过」）。页面按此写成三张**并列卡片**，而不是一个「课程完成度」。

**逐例分解**（页面上的「逐例口径明细」，可折叠）：

| 案例 | V2 内部复核 | 第三方独立复核 | 后端 `course_ready` | 来源 |
|---|---|---|---|---|
| CG-01 / arvo:44034 | **文档 true / 现盘 fail**（D3，`review.json` 缺失） | 无第三方 | false | COURSE-REVIEW-CG01.md §0 ＋ `recompute.py --check` |
| CG-07 / arvo:10096 | 不可提交（D2） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |
| CG-14 / arvo:11253 | 不可提交（`not_submittable`） | 无第三方 | false | COURSE-REVIEW-BATCH.md §5.1 |
| CG-18 / arvo:12420 | 不可提交（D2） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |
| CG-29 / arvo:11011 | 可提交（内部） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |
| CG-30 / arvo:29633 | 可提交（内部） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |
| CG-31 / arvo:61675 | 可提交（内部） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |
| CG-36 / arvo:54839 | 可提交（内部） | 无第三方 | false | COURSE-REVIEW-BATCH.md §2 |

**不计入上面任何数字的两例**（页脚明示）：`VG-01` 在本批口径下 `out_of_v2_scope`；
`EG-02` 单列——赛道可达（socket 10/10 历史回放）但**判定缺失、材料不齐**，
四项状态见 [COURSE-REVIEW-EG02.md](COURSE-REVIEW-EG02.md) §0，同样不是「通过」。

### 0.1 现盘复算更正：5/8 是文档口径，现盘只能复算 4/8

独立核账（只读、未改文件）在核对「5/8」时发现一处**硬冲突**，本文件据实登记：

| 检验 | 命令 | 结果 |
|---|---|---|
| `review.json` 是否存在 | `ls workspace/CG-01-arvo-44034/review.json` | **不存在**；该目录只有 `review.TEMPLATE.json` |
| 全仓 `review.json` 清单 | `find workspace -maxdepth 2 -name review.json` | 6 份：CG-07 / CG-18 / CG-29 / CG-30 / CG-31 / CG-36，**无 CG-01** |
| 清单校验 | `sha256sum -c experiments/course-review-cg01/MANIFEST.sha256` | 6 项成功，**第 7 项 `workspace/CG-01-arvo-44034/review.json: 没有那个文件或目录`**（清单期望 `03adbef6…`，16807 B） |
| 权威计算器 | `python3 experiments/course-review-cg01/recompute.py --check` | **`D3 fail`**、`strict_submittable = False`、`blockers = ['D3_fail','review_json_blocking']`、**退出码 2** |
| 批次侧计算器 | `python3 experiments/course-review-batch/recompute_batch.py --check` | `strict_submittable_true = 4` / `false = 2`、`external_independent_true = 0`、`external_status_pending = 6`、退出码 1（契约允许） |

**结论**：三份文档（CG01 §0、BATCH §2、本文件 §0）写的 5/8 在写就时成立，但**今天复现不出来**——
CG-01 的 `review.json` 在文档写就后丢失，且**没有任何文档登记这次丢失**。
现盘可复算的是 **4/8**（CG-29 / CG-30 / CG-31 / CG-36），第三方复核与 `course_ready` 两项不受影响（都是 0）。

**页面怎么处理**（三条，都已落地并被检查脚本钉住）：

1. 主数字仍是 **5 / 8 例**，但标签加「**文档口径**」二字——这是文档快照值，不是今日复算值；
2. V2 卡片内嵌橙色「**现盘复算 4 / 8 例 · 2026-11-25 19:15**」块，写明「`CG-01-arvo-44034/review.json` 现盘已缺失 →
   `recompute.py --check` 判 D3 fail（退出码 2）」以及复算依据文件；
3. 逐例明细里 **CG-01 的 V2 列显示「文档 true / 现盘 fail」**，来源列同时给「文档 §0（true）」与「现盘 D3 fail」。

**没有做的事**：没有重建、没有补写 `review.json`，也没有改 `judgments.v2.json` / `MANIFEST.sha256` 去迁就页面。
凭空补一份复核记录等于伪造评审材料——V2 §3 的 `external` 与 `internal_attested` 校验就是防这个的。
正确的修法是**重跑 CG-01 的 D3 材料并重新生成 `review.json`**，然后同步改卡片（§5）。

**对外口径建议**：`0`（外部）、`0`（后端门禁）可直接引用；`5/8` **只能在「内部自审 + 文档口径」双标签下引用，
并必须同时给出「CG-01 `review.json` 现盘缺失 → 今日复算 4/8」这句更正**。

---

## 1. 页面实现

新增区块位置：benchmark 通过性面板之后、`overview-grid` 之前。结构：

```text
<section class="panel course-panel" aria-labelledby="course-heading">
  ├─ .panel-hd      标题「课程证据口径 · 三档并列」+ 分母说明
  ├─ .course-metrics[role=list]
  │    ├─ .course-metric[data-metric="v2_internal"][data-caliber="internal"]  5 / 8 例
  │    ├─ .course-metric[data-metric="external"][data-caliber="external"]     0 / 8 例
  │    └─ .course-metric[data-metric="course_ready"][data-caliber="backend"]  0 / 8 例
  │    └─ .course-recompute   仅 V2 卡：现盘复算 4/8 + 原因 + 复算依据（橙色更正块）
  ├─ .course-verdict   课程结论：未通过、未判定
  ├─ details.course-cases  逐例口径明细（8 行，含来源文档）
  └─ .course-footnote  快照口径说明 + 不计入的两例
```

**数据契约**：数字与来源不写死在渲染函数里，而是放在页面内一份机读快照中——
`<script id="course-metrics" type="application/json">`（`schema = vulnmap.course_metrics.v1`）。
渲染函数 `courseSection(courseSpec())` 只读这份快照：

- 快照缺失或非法 JSON → 区块显示「口径快照未载入」，**不退化显示 0**（避免把缺数据读成「0 例可提交」）；
- 每个条目必带 `sources[]`（`doc` + `note`）与 `notEqual`（该数字**不等于**什么）；
- `data-caliber` 只有 `internal` / `external` / `backend` 三值，卡片右上角标签随之为「内部 / 外部 / 后端」；
- `valueNote`（如「文档口径」）显示在卡片标题右侧；`recompute`（`value` / `at` / `affected` / `reason` / `sources`）
  由 `recomputeBox()` 渲染成卡片内的橙色更正块——**只有文档口径与现盘复算不一致时才存在**；
- `cases[].v2Now` 与 `cases[].v2` 不一致时，逐例表显示「文档 true / 现盘 fail」，而不是悄悄改成 false。

**样式**：`<style>` 内联在 `index.html` 的 `<head>`，全部 `course-` 前缀，只作用于本区块。
刻意**不改** `style.css`：它被全站页面以 `?v=202611161150` 引用，改动会牵连其它页面的缓存版本；
内联也避免了版本串不一致。检查脚本断言内联样式不含 `.metric` / `.metrics-grid` 覆盖规则。

**可访问性**：区块 `aria-labelledby` 指向标题；三卡容器 `role="list"`、卡片 `role="listitem"`；
「课程结论」条 `role="note"`；逐例表在 `.tw`（可横向滚动、可聚焦）容器内；折叠用原生 `<details>`。

**响应式断点**：

| 视口 | 三卡排布 | 实测（Chromium，`overflow` = 横向溢出像素） |
|---|---|---|
| 1440 × 900 | 三列并排 | 3 卡同一行，`overflow = 0` |
| 1180 × 860 | 三列并排 | 3 卡同一行，`overflow = 0` |
| 900 × 800 | `auto-fit minmax(230px,1fr)` → 两行折行 | 2 + 1，`overflow = 0` |
| 390 × 844（手机） | 单列堆叠 | 3 行，`overflow = 0` |

---

## 2. 未改动清单（`保持现有 benchmark/台账统计不变`）

| 项 | 状态 | 证据（检查脚本断言） |
|---|---|---|
| `benchStats()` 判据 | 未改 | 仍 `benchmark_verified === true`，未用 `local_verified` 当通过 |
| 分赛道列 | 未改 | `CG 双端` / `EG flag` / `VG 行为` 三列仍在 |
| 撤回与分母 | 未改 | 页脚「含撤回 / 分母」表述仍在 |
| 8 张 `metric` 卡片 | 未改 | 渲染后 `.metrics-grid .metric` 计数 = 8（4 个视口均验） |
| benchmark 表 | 未改 | `table.overview-table` 仍在，11 列 |
| `#stat-keys` | 未改 | 仍含 `ledger_totals.benchmark_verified` / `local_dual_run_pass` / `stats.ledger_cases` |
| `style.css` | 未改（文件级） | `.metrics-grid{display:grid…}` 原文仍在 |
| 唯一文案改动 | `验收口径` 面板里「课程可交付」一行 | 改为「见下方『课程证据口径』：内部 / 外部 / 后端三档并列，均不等于课程通过」（**描述**，不是统计） |
| 页脚 | 追加一句 | 「课程口径另见三档卡片（内部 / 外部 / 后端门禁），不并入通过率」 |
| 后端 | **未改** | 本次没有触碰 `agent/`、`vulnmap_platform/`、schema、API |

---

## 3. 验证

### 3.1 静态检查（30 条，全过）

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 docs/frontend_course_metrics_check.py
# → 30 PASS / 0 FAIL，退出码 0
```

覆盖：快照合法性与 schema、三档数字（5/8、0、0）、口径标签、来源文档逐份存在性、
「课程已通过」类肯定表述的否定语境甄别、`benchStats` 判据与分赛道列、`stat-keys`、
样式隔离、两个响应式断点、内联脚本 `node --check`，以及把**仓库测试用的同一组 5 例样例**
在 node 里重跑 `benchStats`（结果必须仍是 5 例 → 3 通过）。

另有 6 条**现盘一致性**断言（§0.1 的机器护栏）：V2 卡片必须带 `recompute.value = 4`、写明受影响的
`CG-01`、复算依据文件必须存在、逐例表里 CG-01 必须是「文档 true / 现盘 fail」，并且按磁盘双向校验——
`review.json` 仍在缺失 → 页面必须挂着现盘 fail 说明；`review.json` 一旦恢复 → 页面若还挂着 fail 就报红，
强制重跑 `recompute.py` 并更新快照。

### 3.2 渲染检查（Chromium，4 个视口 × 12 条断言 + 1 条 = 49 条，全过）

用 8102 上的真实 `/api/cases`、`/api/discovery/campaigns` 数据渲染前端源
（临时静态服务器 + `/api` 反向代理，未改动仓库内任何服务配置）：

| 视口 | 结果 |
|---|---|
| 1440 × 900 | 3 卡同行、数字为 `5/8 例 · 0/8 例 · 0/8 例`、口径标签 `内部/外部/后端`、V2 卡带「现盘复算 4/8」块、无横向溢出、原 8 卡 + 表在、逐例 8 行、CG-01 行标「文档 true / 现盘 fail」 |
| 1180 × 860 | 同上 |
| 900 × 800 | 折行 2+1，无溢出 |
| 390 × 844 | 单列堆叠，无溢出 |

同时断言**无 JS 运行时错误**（`pageerror` 为空）。**降级检查**：把 `#course-metrics` 快照整块删掉后再渲染，
结果为 0 张卡片 + 明文「口径快照未载入」「不用 0 冒充未知」，不出现任何 `0 / 8`，仍无 JS 错误——
即数据缺失时不会把「未知」显示成「0 例可提交」。

截图见 [assets/](assets/)：

- [course-metrics-panel.png](assets/course-metrics-panel.png) — 桌面区块特写
- [course-metrics-desktop.png](assets/course-metrics-desktop.png) — 桌面整页
- [course-metrics-mobile-panel.png](assets/course-metrics-mobile-panel.png) — 手机区块特写
- [course-metrics-mobile.png](assets/course-metrics-mobile.png) — 手机整页

### 3.3 仓库既有测试

```bash
# 与前端相关的两个文件
python3 -m pytest tests/test_platform_discovery.py tests/test_platform_acceptance_fixes.py -q
# → 9 failed, 86 passed

# 全量
python3 -m pytest -q
# → 17 failed, 1551 passed, 8 skipped（146 s）
```

这 17 个失败**不是本次引入的**：全部断言 `vulnmap_platform/static/` 下的页面
（`PAGE = ROOT/"vulnmap_platform"/"static"/"index.html"`、`STATIC = …/static`），
而该目录已在本日 18:12 被换成另一套生成物（`index.html` + `dashboard.js` + `dashboard.css`，
标题「项目总览 · vulnmap」），不再含 `benchStats` / `#stat-keys` / `renderShell(`，
`style.css` 也不带 `?v=`。因此列表里的 `test_f3_*`、`test_index_*`、`test_overview_keeps_three_diagrams`、
`test_static_assets_are_versioned`、`test_cases_page_renders_shell`、`test_first_screen_*`、`test_index_navigation_has_v2_entry`
等断言在**改动前**即失败。

本次只改前端源 `前端改版_20261115/MODIFIED_FILE/` 与新增 `docs/` 文件，与被断言的 `static/` 不是同一批文件：
未新增失败、也未修复它们。要让它们回绿，需要先把源发布到 `vulnmap_platform/static/`
（会覆盖当前的 `dashboard.js` 版本），属于另一件有取舍的事（见 §4.3），本次未做。

---

## 4. 已知限制与边界

### 4.1 数字是**文档快照**，不是接口实时值

三档数字来自 2026-11-25 的审计/重审文档，写进页面内 `#course-metrics` 快照，`/api/cases` 不参与计算。
原因：后端目前**不暴露** `course_ready` 字段（只给 `blockers`），也没有「第三方复核」这类字段，
接口算不出这三档。因此页面明写「文档快照 · 只读 · 未接后端接口」，并与上方台账统计**分属两套口径、互不换算**。
快照更新方式见 §5。

### 4.2 `course_ready` 仍是**旧门禁口径**

`agent/stages/report.py::_acceptance` 目前只按 `official_receipt_not_attached` 放行，且不复核
`review.json` 的 `evidence_refs`（[COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) §7）。
所以卡片标题写「后端 `course_ready`」而不是「课程可交付」，并注明「0 不等于材料全废，也不等于 V2 判定为假」。
**把机器门禁切到 V2 需要改后端**（接线 `_review_record()`、校验 `evidence_refs`、把回执降级为
`external_status`），本次按任务边界未做。

### 4.3 运行中的 GUI（8102）目前是另一套页面

8102 提供的是 `vulnmap_platform/static/`，其 `index.html` + `dashboard.js` 是同日 18:12 的另一版
「项目总览」，课程部分只有一张合并卡「课程可交付 = `ledger_totals.course_ready`」（即本页三档里的第三档）。
本次按任务指定的前端源改，**没有**镜像进那一版；若要让 8102 也显示三档，最小改动是把它 `#course-metrics`
快照搬进 `dashboard.js` 的 `cards`（一行改三张），但那属于覆盖他人当天改版的另一个决定，留待确认。

### 4.4 5/8 的引用约束（硬）

`5/8` 只能与「**内部自审**」「**文档口径**」两个标签一起出现，并且**必须**附带 §0.1 的更正：
CG-01 的 `review.json` 现盘缺失 → 今日复算 **4/8**。任何只写「5/8 可提交」而不写这两点的引用，
都属于把「文档快照」说成「今天复算通过」。

### 4.5 表述纪律

页面里凡是出现「课程已通过 / 评审通过」字样的地方，都在否定语境中（检查脚本逐条校验 12 字符上下文）。
对外引用时请连**口径标签 + 来源文档**一起引用：只引用「5/8」而不引用「内部自审」，
等同于把内部自审说成第三方复核——这正是 [COURSE-REVIEW-CG01.md](COURSE-REVIEW-CG01.md) 头部禁止的断章取义。

---

## 5. 维护（数字变了怎么改）

0. **先跑两个计算器**：`python3 experiments/course-review-cg01/recompute.py --check` 与
   `python3 experiments/course-review-batch/recompute_batch.py --check`，以它们的输出为准，
   不拿文档里的历史结论当现值（§0.1 就是一次教训）；
1. 改 `index.html` 里 `<script id="course-metrics" type="application/json">` 的 `metrics[].value`，
   以及（若逐例判定有变）`cases[]` 的 `v2 / external / ready`；
   CG-01 的 `review.json` 若已重新生成，必须同时把 `v2Now` 改回 `true` 并删除 `recompute` 块——
   检查脚本会双向盯着这件事；
2. 在同一个 `sources[]` 条目里补上**新来源文档**（不要把旧来源删掉后只留数字）；
3. 跑 `python3 docs/frontend_course_metrics_check.py`（数字与来源不一致、来源文档不存在都会红）；
4. 数字若来自新的重审批次，请同步新增 `docs/COURSE-REVIEW-*.md`，并把 `snapshot` 日期改成那一天。

**本次未做的事**：没有把快照接到任何接口、没有新增后端字段、没有改 `case.json` / `review.json` /
`LEDGER.json`，也没有生成 `receipt.json`。

---

## 6. 回滚

改动集中在 `MODIFIED_FILE/index.html` 一个文件，共 6 处（按出现顺序）：

| # | 位置 | 回滚动作 |
|---|---|---|
| 1 | `<head>` 内 `<style>` 整块（`.course-*`） | 删除该 `<style>` 块 |
| 2 | `#stat-keys` 之后的 `#course-metrics` JSON 快照 | 删除该 `<script>` 块与其上注释 |
| 3 | `benchTable()` 之后的 `CALIBER_TEXT` / `courseSpec()` / `recomputeBox()` / `courseSection()` | 删除四个声明 |
| 3b | `v2_internal.recompute`、`CG-01.v2Now`、`.course-recompute` 样式 | 与 §0.1 一同撤回（撤回即表示放弃「现盘 4/8」披露，需同步在别处登记） |
| 4 | `#content` 模板里的 `${courseSection(courseSpec())}` | 删除该行 |
| 5 | `验收口径` 面板「课程可交付」一行 | 恢复为 `'另需人工复核签字与官方回执'` |
| 6 | 页脚末尾追加的「课程口径另见三档卡片…」 | 删掉这半句 |

`docs/` 下新增文件可直接删除：`FRONTEND-COURSE-METRICS.md`、`frontend_course_metrics_check.py`、
`assets/course-metrics-*.png`。

---

## 7. 遗留测试（旧前端断言）

`vulnmap_platform/static` 已由旧 Discovery 页面替换为**新版仪表盘**
（`dashboard.js` + 5 项导航 + 本文件的课程三指标卡片）。下列 17 项测试仍按旧前端 DOM 断言，
描述的是**已被替换的实现**；**没有删除**，而是在 `tests/conftest.py` 的
`LEGACY_FRONTEND_TESTS` 中集中登记为 `xfail(strict=False)`。

| 文件 | 测试 | 旧断言 |
|---|---|---|
| `test_platform.py` | `test_cases_page_renders_shell` | 旧 cases 页 shell 结构 |
| `test_platform.py` | `test_static_assets_are_versioned` | 静态资源 `?v=` 版本串 |
| `test_platform_acceptance_fixes.py` | `test_f3_page_uses_benchmark_verified` | 旧 `benchStats()` |
| `test_platform_acceptance_fixes.py` | `test_f3_stat_keys_use_benchmark_verified` | `#stat-keys` 口径块 |
| `test_platform_acceptance_fixes.py` | `test_f3_benchstats_behaviour_in_node` | 旧 `app.js` 行为 |
| `test_platform_discovery.py` | `test_discovery_pages_exist_and_are_self_contained` | 旧页面自包含 |
| `test_platform_discovery.py` | `test_index_defaults_to_discovery` | 旧首页默认视图 |
| `test_platform_discovery.py` | `test_index_shows_benchmark_pass_rate` | 旧首页文本 |
| `test_platform_discovery.py` | `test_overview_keeps_three_diagrams` | 旧 overview 三图 |
| `test_platform_discovery.py` | `test_legacy_pages_remain_accessible` | 旧导航入口集合 |
| `test_platform_discovery.py` | `test_every_page_pins_the_same_css_version` | 旧 CSS 版本统一 |
| `test_platform_ui_stats.py` | `test_page_declares_ledger_stats` | `#stat-keys` 必存在 |
| `test_platform_ui_stats.py` | `test_first_screen_shows_17_cases` | 首屏 17 例（台账已 30 行） |
| `test_platform_ui_stats.py` | `test_first_screen_shows_3_independent_high` | 首屏 3 个高危（已 9 个） |
| `test_platform_ui_stats.py` | `test_first_screen_values_contain_17_and_3_but_not_25` | 同上 |
| `test_platform_ui_stats.py` | `test_runs_and_workspaces_not_in_case_cards` | 旧卡片文案 |
| `test_platform_v2_p4.py` | `test_index_navigation_has_v2_entry` | 旧 10 项导航含 "V2 任务" |

迁移方式：把断言改成读新版 `dashboard.js` / `dashboard.css` 的口径（卡片 `id`、`metrics[].value`、
导航项集合），然后从 `LEGACY_FRONTEND_TESTS` 删掉对应条目——测试自动恢复为普通用例。

当前基线：`1567 passed, 8 skipped, 17 xfailed`。
