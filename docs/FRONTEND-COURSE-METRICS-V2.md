# 新版仪表盘的课程三指标（`docs/FRONTEND-COURSE-METRICS-V2.md`）

> **做了什么**：① 先核对 CG-01 —— `review.json` 现盘确实缺失，`recompute.py --check` 判 `D3 fail`（当时可复算
> **4/8**）；随后按「只重建派生复核记录」的口径，用已落盘证据（`verification.json # D3_review`、`review_refs.json`、
> `judgments.v2.json`、`manifest.json`、`COURSE-REVIEW-CG01.md`）重建 `review.json`（自注 `restored_from`，
> **不新增签署人**），复算 **D3 pass → `strict_submittable=true`**，于是 **5/8 重新可复算**。
> ② 把三个课程指标做进**新版**仪表盘 `dashboard.js`：`V2 内部复核可提交 5/8` · `第三方独立复核 0` · `后端 course_ready 0`，
> 每项标口径（内部/外部/后端）、来源与「不等于什么」。③ 8102 实测：预览**就是**新版（`vulnmap_platform/static`
> 是指向 `MODIFIED_FILE` 的软链），`curl` 与真数据渲染均看到三标签、数字为 5/8 · 0/8 · 0/8。
>
> **没做什么**：没切回旧目录（本轮未动、未引用 `前端改版_20261115`；**注**：该目录的 `MODIFIED_FILE/index.html`
> 在今日 19:21 被上一版 v1 交付改过，至今仍内嵌 `course_metrics.v1` 快照 `v2_internal=5`，本轮没有回滚它）；
> 没改后端代码（`vulnmap_platform/api/app.py` 无改动、
> 无课程指标逻辑）；没改导航与赛道图表（`app.js` / `index.html` / `style.css` 哈希不变）；没改任何原始证据
> （`severity.json` / `propagation.json` / `logs/` / `artifacts/` / 轨迹库逐字节未动）；`receipt.json` 没造；
> `accepted` 没预填；没有 `git commit`（仓库根不是 git 工作区）。
>
> **前端源**：`/home/root_bupt/桌面/file/前端收口_20261125.sv8KTO/MODIFIED_FILE/{dashboard.js, dashboard.css}`
> （本次只改这两个文件；`index.html` 未改）
> **配套**：生成器 [`course_metrics_snapshot.py`](../experiments/course-review-cg01/course_metrics_snapshot.py)、
> 恢复脚本 [`restore_review.py`](../experiments/course-review-cg01/restore_review.py)、
> 检查器 [`frontend_course_metrics_v2_check.py`](frontend_course_metrics_v2_check.py)（56 条断言，只读）
> **旧版留档**：[FRONTEND-COURSE-METRICS.md](FRONTEND-COURSE-METRICS.md)（`前端改版_20261115` 那代页面的实现记录）

---

## 0. 三条数字（唯一口径表）

| 卡片 | 页面值 | 口径 | 来源（机读） | 不等于什么 |
|---|---:|---|---|---|
| **V2 内部复核可提交** | **5 / 8 例** | **内部**（`review_kind=internal_attested`、`third_party=false`、`human_instructed_agent_transcribed`） | `experiments/course-review-cg01/evidence/judgments.v2.json`（CG-01 `strict_submittable=true`）＋ `experiments/course-review-batch/summary.json`（CG-29/30/31/36 四例 true） | 不等于第三方复核；不等于课程通过；不等于评测方受理 |
| **第三方独立复核** | **0 / 8 例** | **外部**（要求 `class=external` + `third_party=true` + `attestation.method=human_written`） | 同上两件的 `external_independent_submittable` / `counts.external_independent_true`（全 false、`external_status=pending`）＋ [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md) §5.2 | 不等于内部自审；不等于 `receipt.json`；不等于课程通过 |
| **后端 `course_ready`** | **0 / 8 例** | **后端**（旧机器门禁字段，仍要 `official_receipt`） | 逐例 `workspace/<dir>/artifacts/report/case.json → acceptance.course_ready`（8/8 false，`blocked_by=official_receipt_not_attached`）＋ `/api/overview` 的 `ledger_totals`（**现盘无 `course_ready` 键**） | 不等于 V2 判定；不等于课程通过；0 不等于材料全废 |

**分母 8 例**（固定，来自 [COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) §0）：
`CG-01 / CG-07 / CG-14 / CG-18 / CG-29 / CG-30 / CG-31 / CG-36`。
**不计入分母**：`VG-01`（`out_of_v2_scope`：无源码树、无 provenance 链）、`EG-02`（单列：赛道可达但判定缺失、材料不齐）。

**为什么三行不能合并**：三行问的是三个不同问题——「材料按 V2 齐不齐、谁判的」「有没有无组织关系的第三方签过」
「后端机器门禁放不放行」。任一为真都推不出另外两项，`5 + 0 + 0` 不是「5 例通过」。
首页原「课程可交付」KPI 卡片仍在（读 `ledger_totals.course_ready`，现盘该键不存在 → 显示 `—`），
新面板**不改它**，只把三个口径并列摊开。

### 0.1 逐例口径（页面「逐例口径明细」同源）

| 案例 | 任务 | V2 内部 | 第三方 | `course_ready` | 判定依据 |
|---|---|:--:|:--:|:--:|---|
| CG-01 | arvo:44034 | **是** | 否 | 否 | A∧B∧C∧D 全成立（带 caveat）；D3 记录 `restored_from` 重建后复算通过 |
| CG-07 | arvo:10096 | 否 | 否 | 否 | `D2` 阻断：`verify` 阶段模型闭环 **2** 轮调用无采样参数（`missing: base_url / max_retries / max_tokens`，共 7 项） |
| CG-14 | arvo:11253 | 否 | 否 | 否 | `not_submittable`：PoC 与答案模板逐字节相同、`source_sha256` 空 |
| CG-18 | arvo:12420 | 否 | 否 | 否 | `D2` 阻断：`verify` 阶段模型闭环 **3** 轮调用只落 `llm_status`/`llm_tokens`、无采样参数（`missing` 同上 7 项；locate 那条参数是完整的） |
| CG-29 | arvo:11011 | **是** | 否 | 否 | A∧B∧C∧D 全成立（带 caveat） |
| CG-30 | arvo:29633 | **是** | 否 | 否 | A∧B∧C∧D 全成立（带 caveat） |
| CG-31 | arvo:61675 | **是** | 否 | 否 | A∧B∧C∧D 全成立（带 caveat） |
| CG-36 | arvo:54839 | **是** | 否 | 否 | A∧B∧C∧D 全成立（带 caveat） |

合计：V2 内部 **5/8**、第三方 **0/8**、后端 `course_ready` **0/8**。

---

## 1. CG-01 核对与恢复（D3）

### 1.1 恢复前：现盘复算 = 4/8（**历史态**：恢复后已无法复现，保留作对照）

```text
$ python3 experiments/course-review-cg01/recompute.py --check
  D3  fail                 holds=False
  strict_submittable            = False
  verdict                       = needs_evidence
  blockers                      = ['D3_fail', 'review_json_blocking']
```

原因链：`workspace/CG-01-arvo-44034/review.json` 在 2026-11-25 18:39 之后从磁盘消失
（`sha256sum -c MANIFEST.sha256` 第 7 项报缺失），`check_d3` 第一步就判「review.json 不存在（D3 必需）」。
因此当时 8 例里只有 CG-29/30/31/36 四例可提交 —— **4/8**，与用户口径 5/8 的差额正是 CG-01 这一例。

### 1.2 能不能恢复：能，且逐字段可追

先做的三件事（都只读）：

| 检验 | 结果 |
|---|---|
| 全盘找 `review.json` 副本（按文件名、按 `sha256 03adbef6…`、按 `scope` 原文串） | **无副本**：只有 6 份别的案例（CG-07/18/29/30/31/36），CG-01 一份不留 |
| `review_refs.json` 的 16 条 refs 现盘重算 | **16/16 一致**（PoC 8882 B、vul 日志 7128 B、fix 日志 925 B、轨迹库 86016 B、live 复跑两件…） |
| `verification.json # D3_review` | **是原文件字段快照**：`reviewer=平台维护者`、`reviewer_id=platform-maintainer`、`reviewed_at=2026-11-25T18:34:00+08:00`、`scope`、`independence` 全字段、`attestation`（method/accountable_party/transcribed_by）、16 条 refs、`layer_verdicts`、`checklist_items=6`、`not_claimed_count=6`、caveat 对齐 |

结论：记录的内容**完全由已落盘产物决定**，可以重建；能重建的是「派生复核记录」，不是「补一个新签字」。

### 1.3 恢复后：D3 pass、5/8 可复算（restored_at = 2026-11-25T19:34:51+08:00）

```text
$ python3 experiments/course-review-cg01/restore_review.py
[restore] 来源校验通过：16 条 refs 现盘哈希一致；原文件 16807 B / 03adbef63c3e…
[restore] 已写 workspace/CG-01-arvo-44034/review.json：16901 B / sha256 805533706580ddfa01ed18b1151423f699dca656c9abf9fe80c27cfcaf799f2b
[restore] 字节等价：否（见 restored_from.divergence）

$ python3 experiments/course-review-cg01/recompute.py      # 退出码 0
  D3  pass_with_caveats    holds=True
  strict_submittable            = True
  external_independent_submittable = False
  verdict                       = strict_submittable
  blockers                      = []

$ sha256sum -c experiments/course-review-cg01/MANIFEST.sha256    # 7 行全成功
```

| 项 | 原文件 | 恢复件 |
|---|---|---|
| 大小 | 16807 B | 16901 B |
| sha256 | `03adbef6…d72` | `805533706580ddfa01ed18b1151423f699dca656c9abf9fe80c27cfcaf799f2b` |
| 字节等价 | — | **否**（JSON 键序/缩进 + 下面几项重建） |

`review.json` 里自带的 `restored_from` 块（摘录）：

```json
"restored_from": {
  "restored": true,
  "restored_at": "2026-11-25T19:34:51+08:00",
  "restored_by": "agent（dsh）— experiments/course-review-cg01/restore_review.py",
  "reason": "原文件在 2026-11-25 18:39 之后从磁盘消失：MANIFEST.sha256 第 7 项报缺失 … 本件依据同目录已落盘派生证据重建",
  "original_sha256": "03adbef63c3e8498b1e90ec3808b098af3ca3c91aab47cfcf7fcc7e5c8a53d72",
  "original_size": 16807,
  "byte_identical": false,
  "divergence": ["JSON 键序/缩进为本次序列化结果 ……", "checklist（6 条）与 not_claimed（6 条）文本按文档 §5.3 语义重建 ……", "reviewer_role ……", "attestation.authority / what_this_is_not ……", "layers.D.parts ……"],
  "preserved_verbatim": ["reviewer / reviewer_id / reviewed_at / scope / review_kind", "independence 全字段", "attestation.method=human_instructed_agent_transcribed …", "16 条 evidence_refs（现盘 16/16 一致）", "20 条层内 caveat 编号与文本", "caveats_total=22、layer_caveats_total=20"],
  "sources": ["…/evidence/verification.json # D3_review", "…/evidence/review_refs.json", "…/evidence/judgments.v2.json", "…/manifest.json", "docs/COURSE-REVIEW-CG01.md §5.3 / §7"],
  "not_a_new_signature": true,
  "note": "重建件不新增任何签署人 …… 不提升为外部独立评审，不替代 receipt.json"
}
```

**边界（必须随数字一起引用）**

1. 复核性质不变：仍是 `class=internal`、`third_party=false`、`reviewer_is_material_author=true`，
   `attestation.method=human_instructed_agent_transcribed`（人下指令、agent 转写）——**不是第三方，也不是人手逐项签署**；
2. 恢复件**没有**改成 `external` / `human_written`，**没有**新增签署人，**没有**生成 `receipt.json`、**没有**预填 `accepted`；
3. 因此 `external_independent_submittable` 仍为 **false**，第三方那格仍是 **0**；
4. 引用时须同时给出 `restored_from` 与「原 sha256 ≠ 现 sha256」这一差异，不得表述为「原文件仍在」或「字节一致」；
5. 恢复只重建**派生复核记录**：`workspace/CG-01-arvo-44034/` 下其它文件（`case.json`、`severity.json`、
   `propagation.json`、`logs/`、`artifacts/`、`.runtime/vulnmap.db`）一个字节未动，`review.TEMPLATE.json` 仍是原样模板。

`experiments/course-review-cg01/manifest.json` 的 `role` 字段已按现盘如实派生：
`D3 具名复核（internal / restored_from 重建件；原 sha256 03adbef63c3e…、原 16807 B）`。

> 为此对 `recompute.py` 做了一处 5 行改动：`role` 与 `written` 由「新增」改为按 `review.json.restored_from`
> 派生（无 `restored_from` 时仍写「新增文件」，语义不变）。改后 `MANIFEST.sha256` 由脚本自身重算，7/7 通过。

---

## 2. 新版仪表盘的实现

### 2.1 数据流：产物 → 生成器 → 标记区（页面不手填数）

```text
experiments/course-review-cg01/evidence/judgments.v2.json ┐
experiments/course-review-batch/summary.json             ├─→ course_metrics_snapshot.py ─→ dashboard.js 的
workspace/<case>/artifacts/report/case.json (×8)         ┘        （重算分母/逐例/来源）      /* COURSE-METRICS:BEGIN … END */
                                                                                          └─ courseMetricsSection() 渲染
```

- 页面里的 `COURSE_METRICS` 是一份**快照 JSON**（`schema=vulnmap.course_metrics.v2`），带 `generated_at` / `generator` /
  `denominator` / `metrics[3]` / `cases[8]` / `excluded` / `notes`；
- 值 5 是脚本从 `judgments.v2.json`（CG-01）和 `summary.json`（批次 `strict_true_cases` 长度）**算**出来的，
  不是写死的字面量；改页面数字而不改产物，`--check` 会报不一致；
- 三项都带 `caliber`（`internal` / `external` / `backend`）、`caliberLabel`（内部/外部/后端）、`question`（问的是什么）、
  `notEqual[]`（不等于什么）、`sources[]`（`doc` + `note`，≥2 条）；
- 快照缺失/非法时面板显示「口径快照未载入：横线表示未知，不是零」并给出重新生成的命令，**不退化显示 0**。

### 2.2 页面结构（只新增一个区块，不动既有区块）

```text
.dash
 ├─ .dash-hero        （未改）Benchmark 验证通过率 / 大分数
 ├─ .dash-kpis        （未改）4 张台账 KPI 卡片
 ├─ .cm-panel         ← 新增：课程三指标
 │    ├─ .panel-hd（标题 + 分母说明 + 右上「快照 2026-11-25 19:37」）
 │    ├─ .cm-cards[role=list] → 3 × .cm-card[data-metric][data-caliber]
 │    ├─ .cm-verdict  「课程结论：未通过、未判定 —— 三个数问的是三个不同问题，相加无意义」
 │    ├─ details.cm-cases → 逐例 8 行表（案例｜任务｜V2 内部｜第三方｜course_ready｜判定依据+来源）
 │    └─ .cm-foot      口径备注 + 不计入分母的两例 + 生成器路径
 ├─ .dash-body        （未改）按评测轨道查看（3 条赛道条）+ 发现记录
 └─ details.dash-diagrams（未改）架构和流程图
```

- **可访问性**：三卡容器 `role="list"`、卡片 `role="listitem"`、结论条 `role="note"`、表头 `scope="col"`、
  首列 `scope="row"`；表格在 `.tw`（可滚动）容器内；折叠用原生 `<details>`；沿用既有 `:focus-visible` 规则。
- **响应式**：`≥1101px` 三列并排；`≤1100px` 两列（2+1）；`≤690px` 单列堆叠、表格 `min-width:640px` 横向滚动。
- **样式**：只往 `dashboard.css` 尾部追加一段 `.cm-*` 规则（4550 B → 7789 B；含 `1100px` / `690px` 两条断点），
  **未改** `style.css`、未覆盖 `.metric` / `.metrics-grid` 等旧选择器。

### 2.3 文件与哈希

| 文件 | 大小 | sha256 | 状态 |
|---|---:|---|---|
| `MODIFIED_FILE/dashboard.js` | 18411 B | `8e310cbc874cdbe873a9e3626daa7e641500d3880ff5050d99796992f8f238d3` | **改**（+ 标记区 + `courseMetricsSection()` + 一处调用） |
| `MODIFIED_FILE/dashboard.css` | 7789 B | `c008fb89338072838a68040c3102b7bd8d44755b4d1deee32074d56ef7c5a12b` | **改**（追加 `.cm-*` 段与断点） |
| `MODIFIED_FILE/index.html` | 1278 B | 与闭包基线一致 | 未改 |
| `MODIFIED_FILE/app.js` / `style.css` / `cases.html` / `overview.html` / `packages.html` | — | 与闭包基线一致 | 未改 |

> 判定依据：`前端收口_20261125.sv8KTO/modified.sha256`（63 件，闭包完成时的哈希）。
> 现盘与之不同的**只有** `dashboard.js`、`dashboard.css` 两件 —— 检查器对此有硬断言。

---

## 3. 没改的东西（逐项可验）

| 项 | 状态 | 证据 |
|---|---|---|
| 新版结构（`renderShell` + `dashboard()` + `.dash` 网格） | 保留 | 只在 `.dash-kpis` 之后插入 `${courseMetricsSection()}` |
| 主导航（`VIEWS` / `SECONDARY_VIEWS` / 侧栏） | 未动 | 导航在 `app.js`，哈希未变 |
| 赛道图表（3 条 `.dash-bench` + 图例） | 未动 | 渲染快照 `tracks=3`；模板 `按评测轨道查看` 仍在 |
| KPI 四卡（案例条目 / 独立高危 / 因果链闭合 / 课程可交付） | 未动 | `dash-kpis` 计数 = 1；「课程可交付」仍读 `ledger_totals.course_ready`（缺键 → `—`） |
| 发现记录 / 架构图示 | 未动 | 渲染快照 `discovery=true`、`diagrams=true` |
| 旧前端目录 `前端改版_20261115/` | **本轮**未切回、未改动 | 本文与检查器只引用 `MODIFIED_FILE`；该目录 `index.html` 19:21 由 v1 交付改过（28912 B，内嵌 `vulnmap.course_metrics.v1` 快照 `v2_internal=5`），本轮未回滚 |
| 后端 | 未改 | `vulnmap_platform/api/app.py` 无 `course_metrics` / `courseMetrics` 字样；`/api/overview` 响应未变 |
| 原始证据 | 未改 | 16 条 refs 现盘重算 16/16 一致（恢复前后同一组哈希） |
| `receipt.json` / `accepted` | 未生成、未预填 | `review.json.receipt.present=false`、`accepted=null`；`check_d3` 会拒 `accepted=true` |
| `git commit` | 未做 | `git rev-parse --show-toplevel` 失败（仓库根不是 git 工作区） |

---

## 4. 验证记录（8102 实测）

### 4.1 预览是否指向新版：是（软链，非拷贝）

```text
$ readlink -f vulnmap_platform/static
/home/root_bupt/桌面/file/前端收口_20261125.sv8KTO/MODIFIED_FILE
$ ss -ltnp | grep 8102
LISTEN 0 2048 127.0.0.1:8102 users:(("python3",pid=1045024,fd=13))   # uvicorn frontend_preview:app（只读前置，写方法 405）
```

进程 cwd = `/home/root_bupt/桌面/file/vulnmap`，`PYTHONPATH=…/上线_8102:…/vulnmap`，
`StaticFiles(directory=vulnmap_platform/static)` 即 `MODIFIED_FILE`。**改 `MODIFIED_FILE` 即生效，无需重启**。

### 4.2 `curl` 能看到三标签

```text
$ curl -s --noproxy '*' -o /dev/null -w 'status=%{http_code} bytes=%{size_download}\n' http://127.0.0.1:8102/
status=200 bytes=1278
$ curl -s --noproxy '*' http://127.0.0.1:8102/dashboard.js -o /tmp/dash.js -w 'status=%{http_code} bytes=%{size_download}\n'
status=200 bytes=18411
$ grep -o "V2 内部复核可提交\|第三方独立复核\|后端 course_ready" /tmp/dash.js | sort | uniq -c
      1 第三方独立复核
      1 后端 course_ready
      2 V2 内部复核可提交            # 一次是卡片 label，一次在面板脚注「内部自审」说明句里
$ grep -o '"value": [0-9]*' /tmp/dash.js | head -3
"value": 8      # denominator
"value": 5      # v2_internal
"value": 0      # external_independent
$ curl -s --noproxy '*' -o /dev/null -w 'status=%{http_code} bytes=%{size_download}\n' http://127.0.0.1:8102/dashboard.css
status=200 bytes=7789
```

### 4.3 真渲染（无浏览器环境下的 DOM 冒烟，取 8102 真实接口数据）

以 `node` + 最小 DOM 桩加载真实 `app.js`/`dashboard.js`，`fetch` 指向 `127.0.0.1:8102`：

```text
{"cards":3, "calibers":["internal","external","backend"],
 "values":["5/8","0/8","0/8"],
 "labels":true, "rows":8,
 "tracks":3, "hero":true, "kpis":1, "discovery":true, "diagrams":true, "unclosed":0,
 "verdict":"课程结论：未通过、未判定 —— 三个数问的是三个不同问题，相加无意义"}
```

### 4.4 计算器与检查器

```text
$ python3 experiments/course-review-cg01/recompute.py                 # 退出码 0
  strict_submittable = True；blockers = []；caveats = 22（blocking 0）

$ python3 experiments/course-review-batch/recompute_batch.py --check   # 退出码 1（契约允许；不校验清单，见 §5.1）
  strict_submittable_true = 4 / false = 2；external_independent_true = 0；external_status_pending = 6

$ python3 experiments/course-review-cg01/course_metrics_snapshot.py --check
[metrics] 一致：V2 内部 5/8、第三方 0、course_ready 0

$ python3 docs/frontend_course_metrics_v2_check.py
[check] 断言 56 条：通过 56，失败 0｜页面快照 V2 内部 5/8、第三方 0、course_ready 0
```

**第二条独立路径**（不经过 `summary.json`，直接读逐案例产物）：

```text
$ python3 -c "读 experiments/course-review-batch/evidence/<CASE>/judgments.v2.json 的 strict_submittable              + experiments/course-review-cg01/evidence/judgments.v2.json"
CG-07 strict=False（layers.D=fail）   CG-29 strict=True   CG-01 strict=True
CG-18 strict=False（layers.D=fail）   CG-30/31/36 strict=True（各层 pass）
→ strict_true = 5 / 8（CG-14 无 review.json，按 not_submittable 记 false）
```

检查器覆盖四类断言（A 快照=产物、B 结构与口径、C 不覆盖旧内容、D 无后端改动/未 commit），
其中 A 类会**独立重算** `expect_v2 = (CG-01 strict) + len(batch.strict_true_cases)` 再与页面值比对 ——
页面上写死一个更好看的数会被判失败。

---

## 5. 维护：数字变了怎么改

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 任何证据/判定变化后，先重算判定产物
python3 experiments/course-review-cg01/recompute.py
python3 experiments/course-review-batch/recompute_batch.py --check

# 2) 把产物重算成页面快照（只改 dashboard.js 的标记区
#    /* COURSE-METRICS:BEGIN … */ … /* COURSE-METRICS:END */）
python3 experiments/course-review-cg01/course_metrics_snapshot.py

# 3) 校验：快照=产物、结构完整、旧区块未动、无后端改动
python3 docs/frontend_course_metrics_v2_check.py
```

纪律三条：
1. **不手改页面数字**——改了也过不了 `--check`；
2. `--check` 与人工核对都在跑之前先看退出码（`recompute.py`：0 可提交 / 1 不可提交 / 2 校验失败；
   `recompute_batch.py`：**1 是本批正常值**）；
3. 新增/删除分母案例要同时改 `course_metrics_snapshot.py` 的 `CASES`（分母 8 的来源是 `COURSE-CASE-AUDIT.md` §0）。

---

## 5.1 批次产物的一处已知过期（不在本轮写范围，已登记）

`experiments/course-review-batch/**` **不在本任务的允许写范围**（只允许 `experiments/course-review-cg01/` 派生件），
但核对时发现它的清单已过期，如实登记如下：

```text
$ sha256sum -c experiments/course-review-batch/MANIFEST.sha256
experiments/course-review-batch/evidence/CG-07/model_params.json: 失败
experiments/course-review-batch/evidence/CG-18/model_params.json: 失败
workspace/CG-07-arvo-10096/review.json: 失败
workspace/S7-CG18-arvo-12420/review.json: 失败
sha256sum: 警告：4 个校验和不匹配          # 清单共 52 行
```

| 项 | 事实 |
|---|---|
| 原因 | 清单 `manifest.json` / `MANIFEST.sha256` 生成于 **18:41:45**，上述 4 件在 **18:58:22** 被重写（模型参数取证补栏 + 两例 review.json 重写），未刷新清单 |
| 连带 | `summary.json` 里 CG-07 / CG-18 的 `review_sha256` 已 STALE（记录 `233b3867…` / `6a3a717a…`，现盘 `b81c1009…` / `a75ec350…`） |
| 为什么不修 | 写批次日录超出本轮授权范围；**重跑 `recompute_batch.py`（不带 `--check`）即可刷新清单与 summary**，属批次维护动作，留给批次任务 |
| 对本页数字的影响 | **无**。页面只用逐例 `strict_submittable` 真假（CG-07/18 为 false），已用第二条独立路径复核：`evidence/<CASE>/judgments.v2.json` 的 `layers.D=fail`、CG-14 无 `review.json` → 仍是 4+1=**5/8** |
| 陷阱 | `recompute_batch.py --check` **不校验清单哈希**，退出码 1 只表示「有案例不可提交」，会掩盖这 4 项过期 |

检查器已把这条写成断言：批次清单的过期项**必须**恰好是上面这 4 件（多出未登记项即失败），并在输出里把原因打出来。

---

## 6. 边界与已知限制

1. **5/8 是内部口径**，且其中 CG-01 这一例的复核记录是 `restored_from` 重建件。对外引用必须三件一起给：
   `5/8` + 「内部自审 + agent 转写」+ 「CG-01 review.json 为重建件（原 sha256 ≠ 现 sha256）」。
2. **第三方 0 与 `course_ready` 0 不受本次恢复影响**：恢复件没有、也不可能把内部自审变成外部签署。
3. 页面读的是**静态快照**（无后端接口），所以「页面值 = 最后一次生成时的产物」；
   快照与现盘产物不一致时，`course_metrics_snapshot.py --check` 与检查器都会报。
4. 后端 `/api/overview` 的 `ledger_totals` **没有 `course_ready` 键**，所以首页原「课程可交付」卡片显示 `—`；
   新面板的第三个数字改为逐例读 `case.json` 复算，并在卡片来源里写明这一差异。若要后端直接给该字段，
   属于改后端，本轮不做。
5. `dashboard.css` 新增段落在 `≤690px` 让表格横向滚动（`min-width:640px`），未做卡片内部滚动。
6. 本轮未做真实浏览器截图（本会话无可用 Chromium/CDP，见 §4.3 的 DOM 冒烟替代；数字与结构均由该冒烟 + `curl` 双证）。
7. 批次目录的清单过期（4 件）是本轮**未修**的已知问题，见 §5.1：它不影响 5/8 这个数字，
   但对外直接引用批次产物哈希前必须先重跑 `recompute_batch.py` 刷新清单。

---

## 7. 回滚

改动是**纯追加**：把追加段去掉即可逐字节还原，已用哈希验证（还原件 sha256 与 `modified.sha256`
闭包基线完全一致），原件落在 `前端收口_20261125.sv8KTO/pre-course-metrics/`。

```bash
cd /home/root_bupt/桌面/file/vulnmap
C=/home/root_bupt/桌面/file/前端收口_20261125.sv8KTO

# 1) 前端：还原到加指标之前（两个文件，哈希可验）
cp "$C/pre-course-metrics/dashboard.js"  "$C/MODIFIED_FILE/dashboard.js"
cp "$C/pre-course-metrics/dashboard.css" "$C/MODIFIED_FILE/dashboard.css"
sha256sum "$C/MODIFIED_FILE/dashboard.js"  "$C/MODIFIED_FILE/dashboard.css"
#   a25a2e1977973f9433df74719bcba4ce9f43317a5a6aa85091208300a3f6a9d4  dashboard.js
#   09dc2776daafac02f6edfbecfa91f9b963affa6d5119633b371957021a1a5a34  dashboard.css
# 8102 的 static 是指向 MODIFIED_FILE 的软链，刷新首页即生效，无需重启

# 2) 判定：删掉重建的 review.json，即回到「D3 fail / 现盘 4 可复算」的原始状态
rm workspace/CG-01-arvo-44034/review.json
python3 experiments/course-review-cg01/recompute.py --check   # 会重新报 D3 fail（符合预期）
# 想再恢复：python3 experiments/course-review-cg01/restore_review.py --force   # 幂等，除 restored_at 时间戳

# 3) 若只想撤页面、保留恢复后的 CG-01：只做第 1 步即可
```

回滚后三指标面板消失，首页回到「hero + 4 KPI + 赛道条 + 发现记录 + 图示」的原结构；
CG-01 的判定则取决于是否保留 `review.json`（保留 = 5/8，删除 = 4/8）。
