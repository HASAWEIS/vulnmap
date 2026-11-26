# 课程三指标前端数字一致性检查（`docs/COURSE-METRICS-CONSISTENCY.md`）

> **任务**：新增 `scripts/check_course_metrics.py`，只读校验新版 `dashboard.js` 的 **5 / 0 / 0**
> 与 `experiments/course-review-*/` 的 judgments/summary、`workspace/<case>/artifacts/report/case.json`
> 的 `acceptance.course_ready` 是否一致；不一致退出非 0 并逐条列出。
>
> **结论**：现盘一致。`5/8 · 0/8 · 0/8`（V2 内部 / 第三方 / 后端 course_ready）在
> 页面快照、逐例产物、批次 summary、8 份 `case.json` 之间**完全对得上**：
> **81 条断言全通过，退出码 0**。没有改前端数字、没有改后端、没有 `git commit`。
>
> **产物**：[`scripts/check_course_metrics.py`](../scripts/check_course_metrics.py)（只读，无写文件调用）
> · 本文档。

---

## 0. 一句话结果

```text
复算：5/8 · 0/8 · 0/8（V2 内部 / 第三方 / 后端 course_ready）
页面：5/8 · 0/8 · 0/8
断言 81 条：通过 81，失败 0｜PASS
```

| 项 | 值 |
|---|---|
| 页面快照文件 | `前端收口_20261125.sv8KTO/MODIFIED_FILE/dashboard.js`（= `vulnmap_platform/static` 软链目标） |
| 页面快照 sha256 | `8e310cbc874cdbe873a9e3626daa7e641500d3880ff5050d99796992f8f238d3` |
| 检查脚本 sha256 | `d3570e98e52d6826b8ae5420f14fb5ad442eb81368d7077639818b91360b2f2c` |
| 断言 | 81 条（A 结构 4 · B 页面↔产物 52 · D summary 自洽 21 · E 分母/排除 4） |
| 退出码 | `0` |

---

## 1. 为什么单独做这个检查

`dashboard.js` 里的三张卡片是**快照**，由一个生成器写进 `/* COURSE-METRICS:BEGIN … END */`
标记区；生成器（`experiments/course-review-cg01/course_metrics_snapshot.py`）本身能 `--check`，
但它把「页面 = 现算」当成整体比较，报错只说「哪几个 key 不一致」。本任务要的是**独立、只读、
可逐条定位**的校验：

- 页面上的 **5 / 0 / 0** 是否等于从证据现算的结果；
- 逐例 8 行是否等于逐例产物（不是只看合计）；
- `course_ready` 是否逐例等于 `case.json.acceptance.course_ready`（含 `blocked_by`）；
- 批次 `summary.json` 的 `counts` 是否等于 `evidence/<CASE>/judgments.v2.json` 的逐例标记
  （防「summary 写 4、judgments 其实 3」这类内部漂移）；
- 页面内部「逐例计数 = 卡片值」是否成立（防「卡片写 5、表格只勾 4」）。

任一不成立 → 打印 `FAIL [CODE] 详情`，退出码 `2`。

---

## 2. 检查来源（全部只读）

| 数字 | 来源 | 取用字段 |
|---|---|---|
| V2 内部复核可提交（CG-01） | `experiments/course-review-cg01/evidence/judgments.v2.json` | `strict_submittable` |
| V2 内部复核可提交（批次） | `experiments/course-review-batch/summary.json` ＋ `experiments/course-review-batch/evidence/<CASE>/judgments.v2.json` | `strict_submittable`（两边必须一致） |
| 第三方独立复核 | 同上两处 | `external_independent_submittable` |
| CG-14（不计入批次） | `summary.json → separate` | `bucket=not_submittable`、`in_batch_count=false` |
| 后端 `course_ready` | `workspace/<dir>/artifacts/report/case.json` | `acceptance.course_ready`、`acceptance.blocked_by` |
| EG-02（排除项） | `experiments/course-review-eg02/judgments.v2.json` | `strict_submittable` 必须非 true，且不在分母 |
| 分母 8 例 | 脚本内固定清单（= `docs/COURSE-CASE-AUDIT.md` §0） | `CG-01/07/14/18/29/30/31/36` |

`dashboard.js` 定位顺序：`--dashboard` → `COURSE_METRICS_DASHBOARD` → 仓库内
`vulnmap_platform/static/dashboard.js`（软链）→ `web/dashboard.js` → 同级
`前端收口_*/MODIFIED_FILE/dashboard.js`。显式传入的路径不存在时直接退出 `3`，不静默回退。

---

## 3. 现盘复算结果

| 案例 | 目录 | V2 内部 | 第三方 | `course_ready` | 依据 |
|---|---|:--:|:--:|:--:|---|
| CG-01 | `CG-01-arvo-44034` | **true** | false | false | `course-review-cg01/evidence/judgments.v2.json` |
| CG-07 | `CG-07-arvo-10096` | false | false | false | batch summary ＋ `evidence/CG-07/judgments.v2.json` |
| CG-14 | `CG-14-arvo-11253` | false | false | false | `summary.json → separate`（`not_submittable`） |
| CG-18 | `S7-CG18-arvo-12420` | false | false | false | batch summary ＋ `evidence/CG-18/judgments.v2.json` |
| CG-29 | `S14-CG29-arvo-11011` | **true** | false | false | batch summary ＋ `evidence/CG-29/judgments.v2.json` |
| CG-30 | `S15-CG30-arvo-29633` | **true** | false | false | batch summary ＋ `evidence/CG-30/judgments.v2.json` |
| CG-31 | `S16-CG31-arvo-61675` | **true** | false | false | batch summary ＋ `evidence/CG-31/judgments.v2.json` |
| CG-36 | `S19-CG36-arvo-54839` | **true** | false | false | batch summary ＋ `evidence/CG-36/judgments.v2.json` |
| **合计** | 8 例 | **5** | **0** | **0** | — |

8 份 `case.json` 的 `acceptance.course_ready` 全为 `false`，`blocked_by` 全为
`["official_receipt_not_attached"]`；页面逐例行与之逐例相等。

---

## 4. 用法与输出

```bash
cd vulnmap
python3 scripts/check_course_metrics.py            # 全量：页面路径 + 81 条断言
python3 scripts/check_course_metrics.py --quiet    # 只打印结论与失败项
python3 scripts/check_course_metrics.py --json     # 机读（ok/computed/page/cases/checks）
python3 scripts/check_course_metrics.py --dashboard /path/to/dashboard.js
```

现盘 `--quiet` 实跑输出：

```text
复算：5/8 · 0/8 · 0/8（V2 内部 / 第三方 / 后端 course_ready）
页面：5/8 · 0/8 · 0/8
断言 81 条：通过 81，失败 0｜PASS
```

全量输出（节选，共 81 条 `ok`）：

```text
课程三指标前端数字一致性检查（只读）
  页面：/home/root_bupt/桌面/file/前端收口_20261125.sv8KTO/MODIFIED_FILE/dashboard.js
  仓库：/home/root_bupt/桌面/file/vulnmap
  ok   [D-STRICT] CG-29 strict_submittable：summary=True / judgments=True
  ok   [D-TRUE] summary.counts.strict_true_cases=['CG-29', 'CG-30', 'CG-31', 'CG-36'] / 复算 ['CG-29', 'CG-30', 'CG-31', 'CG-36']
  ok   [A-SCHEMA] schema='vulnmap.course_metrics.v2'（期望 vulnmap.course_metrics.v2）
  ok   [A-DEN] 分母=8（期望 8）
  ok   [B-VALUE] 页面「V2 内部复核可提交」=5 / 复算 5
  ok   [B-VALUE] 页面「第三方独立复核」=0 / 复算 0
  ok   [B-VALUE] 页面「后端 course_ready」=0 / 复算 0
  ok   [B-ROW-CR] CG-01 course_ready：页面=False / case.json=False
  …（中间 71 条 ok 省略）…
  ok   [B-SUM] 页面卡片「后端 course_ready」=0 / 逐例行合计 0
  ok   [E-EXCLUDED] excluded 含 VG-01 与 EG-02（实际 ['EG-02', 'VG-01']）
```

---

## 5. 断言分组

| 组 | 条数 | 内容 |
|---|---:|---|
| **A 结构** | 4 | 快照合法且 `schema=vulnmap.course_metrics.v2`；分母 8；`scope` = 8 例审计范围；指标 id/顺序固定 |
| **B 页面↔产物** | 52 | 三个值 = 复算；三卡分母 8；逐例 8 行且案例集合一致；逐例 `task_id` / `v2_internal` / `external_independent` / `course_ready` / `blocked_by` 全部相等；卡片值 = 逐例行合计 |
| **D summary 自洽** | 21 | 六例 `summary.strict/external` = `evidence/<CASE>/judgments.v2.json`；`counts` 的 true/false 名单与数量 = 复算；`batch_size`、`separate_listed` 一致；CG-14 `bucket`/`in_batch_count` 正确 |
| **E 分母与排除** | 4 | EG-02 非 `strict_submittable`、不在分母；`excluded` 含 `VG-01`/`EG-02` 且不与分母重叠 |

> 说明：`counts.strict_true_cases` 只统计**批次六例**（4 例），CG-01 来自单独的
> `course-review-cg01` 产物——脚本按这个口径比较，避免把「批次 4」错当「全量 5」。

---

## 6. 负向验证（证明它真的会拦）

把 `dashboard.js` 复制到 `/tmp`，**只**把 `v2_internal` 的 `"value": 5` 改成 `4`，其余不动：

```text
$ COURSE_METRICS_DASHBOARD=/tmp/dash_bad.js python3 scripts/check_course_metrics.py --quiet
  FAIL [B-VALUE] 页面「V2 内部复核可提交」=4 / 复算 5
  FAIL [B-SUM] 页面卡片「V2 内部复核可提交」=4 / 逐例行合计 5

复算：5/8 · 0/8 · 0/8（V2 内部 / 第三方 / 后端 course_ready）
页面：4/8 · 0/8 · 0/8
断言 81 条：通过 79，失败 2｜FAIL
EXIT=2
```

另外验证：`--dashboard /tmp/nope.js`（显式路径不存在）→ `EXIT=3`，不静默改查默认路径。

---

## 7. 退出码

| 码 | 含义 |
|---:|---|
| `0` | 一致（页面 = 产物 = `case.json`） |
| `2` | 数字或结构不一致，已在 stderr 逐条列出 `FAIL [CODE]` |
| `3` | 检查无法完成：找不到 `dashboard.js`，或快照标记区/JSON 不可解析 |

---

## 8. 边界（做了什么 / 没做什么）

**做了**：新增只读检查脚本；跑通 81 条断言；写本文档；负向验证一次；确认脚本无写文件调用
（`grep` 无 `write_text` / `open(...,'w')`）；前后两次读取 `dashboard.js` 的 sha256 不变。

**没做**：
- 没改前端任何数字/模板（`dashboard.js` / `dashboard.css` / `app.js` / `index.html` 均未动，
  sha256 = `8e310cbc…`）；
- 没改后端（`vulnmap_platform/` 未动，未跑服务、未访问 `/api/overview`）；
- 没改证据（judgments / summary / `case.json` / 轨迹 / 日志逐字节未动）；
- 没 `git commit`（仓库根不是 git 工作区，`git status` 报 `not a git repository`）。

**它不回答什么**：本脚本只校验「页面数字与已落盘产物一致」，**不重新判定证据本身**。
5/0/0 是否该是 5/0/0，取决于 `recompute.py` / `recompute_batch.py` 与人工复核记录；
若证据合法变化，应先用 `course_metrics_snapshot.py` 重生成快照，再跑本脚本——直接手改页面
数字会被 `B-VALUE` 逐条拦下。

---

## 9. 文件清单

| 文件 | 状态 |
|---|---|
| [`scripts/check_course_metrics.py`](../scripts/check_course_metrics.py) | 新增（只读校验器，81 条断言） |
| [`docs/COURSE-METRICS-CONSISTENCY.md`](COURSE-METRICS-CONSISTENCY.md) | 新增（本文档） |
| `前端收口_20261125.sv8KTO/MODIFIED_FILE/dashboard.js` | **未改**（`8e310cbc…`） |
| `experiments/**`、`workspace/**`、`vulnmap_platform/**` | **未改** |
