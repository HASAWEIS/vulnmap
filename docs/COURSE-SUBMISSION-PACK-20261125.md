# 课程提交包（2026-11-25）：CG-01 / CG-29 / CG-30 / CG-31 / CG-36

> 机读产物：[`experiments/submission-pack/summary.json`](../experiments/submission-pack/summary.json)；
> 包源：[`experiments/submission-pack/packs/`](../experiments/submission-pack/packs/)；
> 干净副本：`/home/root_bupt/桌面/file/课程提交包_20261125/`。
> 判据：[`COURSE-CRITERIA-V2.md`](COURSE-CRITERIA-V2.md)；构建时间：`2026-11-25T20:40:00+08:00`。

## 0. 三行结论

| 项 | 值 |
|---|---|
| `strict_submittable = true` | **5/5**（CG-01 / CG-29 / CG-30 / CG-31 / CG-36） |
| `external_independent_submittable = true` | **0/5 → external = 0** |
| 第三方签署 / `receipt.json` | **0 份 / 0 份**（复核全部为平台维护者内部自审；`external_status=pending`） |

五个包各自带齐 `case.json`、`severity.json`、`propagation.json`、`task.json`、`review.json`、
`verify/result.json`、PoC、vul/fix 日志、轨迹导出与模型/采样参数、判定记录、证据索引、
哈希清单，以及只读复算器 `verify/verify_pack.py`。

## 1. 逐例判定

| 案例 | task_id | 项目 / CWE | task_version_id | strict | external | 文件数 | review sha256（前 16） |
|---|---|---|---|---|---|---|---|
| CG-01 | `arvo:44034` | ghostpdl / CWE-121 | `tv-f1829399fda8190c` | `true` | `false` | 39 | `805533706580ddfa…` |
| CG-29 | `arvo:11011` | libarchive (rar5) / CWE-122 | `tv-b4d8430a537ea7b0` | `true` | `false` | 35 | `552ce182830a9b2f…` |
| CG-30 | `arvo:29633` | fio / CWE-121 | `tv-d99200f334adbb83` | `true` | `false` | 36 | `a4eb8ceceddb826f…` |
| CG-31 | `arvo:61675` | exiv2 / CWE-122 | `tv-716cc93f62533aa7` | `true` | `false` | 35 | `8a0b7f748030e938…` |
| CG-36 | `arvo:54839` | libredwg / CWE-122 | `tv-3ac46c581326c1ea` | `true` | `false` | 40 | `186fda7d621d3f1f…` |

blockers 全为空；caveat 均为披露级（B1 记录型绑定、A1/A4/A5/A6 等级来源、C1/C5 推导口径、
D2-D/D2-E 历史参数未落盘、D3-A/D3-B 内部自审等），逐条见各包 `judgments/judgments.v2.json`。

## 2. 每包内容与独立性

```text
<CASE>/
  README.md                  包内说明（判定、内部复核、CG-01 restored_from、依赖、边界）
  MANIFEST.json              机读清单（role / source_path / sha256 / size）
  SHA256SUMS                 sha256sum -c 可用
  path-map.json              原仓库相对路径 → 包内路径（复算唯一路径入口）
  evidence-index.json        要求项 → 文件 → 哈希；复核引用逐条对账
  case.json / severity.json / propagation.json / task.json / review.json
  verify/result.json         双端判定原始结果
  verify/verify_pack.py      自包含只读复算器（A/B/C/D1–D4 + 判定对账）
  poc/<poc>                  交付 PoC（与原盘逐字节一致）
  logs/                      vul / fix 原始日志及同批日志
  trajectory/                trajectory.json / .jsonl / model_params.json / task_version.json
  judgments/                 judgments.v2.json / verification.json / review_refs.json / verdict.json
  artifacts/                 locate / recon / exploit 上游工件
  source/                    vulnmap.db、repo-vul.tar.gz（CG-01 另有 runtime-task.json）
  src/                       被 propagation / 复核引用的源码文件（逐行断言可复算）
  build/build.sh             构建脚本（如原目录存在）
```

**独立性**：原始记录（`case.json`、`severity.json`、`propagation.json`、`task.json`、
`review.json`、`verify/result.json`、日志、PoC、DB、源码包）一律按原字节复制，
不因打包改写路径；记录里出现的 `workspace/…`、`experiments/…` 路径由 `path-map.json`
解析到包内副本。复算器拒绝绝对路径与 `..`，因此包外文件不可达。
复算器从包内原始记录重新计算 A / B / C / D1–D4，再与 `judgments/judgments.v2.json` 对账，
不是直接读取 `strict_submittable` 字段。CG-29 / CG-30 / CG-31 / CG-36 的
`case.json.case_id` 是 workspace 目录名，`review.json` / `judgments` 用课程编号（如 `CG-29`），
`task_id` 一致，按别名处理，原始记录不改写。

## 3. 干净目录只读复算

构建后整包复制到 `/home/root_bupt/桌面/file/课程提交包_20261125/`，
在包外工作目录（`/`）下逐个运行包内复算器；复算器不写文件。

| 案例 | 完整性 | strict | external | judgments 对账 | pack_ok |
|---|---|---|---|---|---|
| CG-01 | `true` | `true` | `false` | `true` | `true` |
| CG-29 | `true` | `true` | `false` | `true` | `true` |
| CG-30 | `true` | `true` | `false` | `true` | `true` |
| CG-31 | `true` | `true` | `false` | `true` | `true` |
| CG-36 | `true` | `true` | `false` | `true` | `true` |

汇总：5/5 例 `pack_ok=true`、
`strict_submittable=true`、`external=false`；复算输出见 [`clean-verify/`](../experiments/submission-pack/clean-verify/)。

隔离审计（`sys.addaudithook` 记录 `open`/`os.open`）：**5/5 例复算过程 0 次打开仓库路径**；明细见 [`ISOLATION-AUDIT.json`](../experiments/submission-pack/clean-verify/ISOLATION-AUDIT.json)。

复算命令（干净副本内）：

```bash
cd /home/root_bupt/桌面/file/课程提交包_20261125
python3 verify_all.py
# 或逐例：cd CG-29 && python3 verify/verify_pack.py
sha256sum -c SHA256SUMS
```

## 4. CG-01 `restored_from`

`CG-01/review.json` 是恢复件：原文件在 2026-11-25 18:39 之后从磁盘丢失，
按已落盘派生证据重建（`docs/COURSE-REVIEW-CG01.md` §5.3.1）。
包内 `review.json` 与 `restored_from` 一并保留，关键字段：

| 项 | 值 |
|---|---|
| restored | `true` |
| original_sha256 | `03adbef63c3e8498b1e90ec3808b098af3ca3c91aab47cfcf7fcc7e5c8a53d72` |
| 现件 sha256 | 见 `CG-01/MANIFEST.json` 与 `CG-01/review.json` 复算（`byte_identical=false`） |
| not_a_new_signature | `true` |

恢复件没有新增签署人，仍是 `internal` / `third_party=false` /
`human_instructed_agent_transcribed`。

## 5. 依赖清单（缺什么，写清楚）

| 依赖 | 状态 | 影响 |
|---|---|---|
| `case/severity/propagation/task/review/verify/日志/PoC/轨迹/判定` | **随包** | 只读复算全部可用 |
| `repo-vul.tar.gz` 源码包 | **随包** | B 的 `source_sha256` 可复算 |
| 被引用源码文件 | **随包**（只展开被引用文件） | C 的 file:line 断言可复算 |
| 运行时 `vulnmap.db` | **随包** | D1 导出与 D4 版本指纹可复算 |
| Docker 镜像 `n132/arvo:<task>-vul/fix` | **未随包**（仅登记 digest） | **不能由本包单独 live 复跑**；B 层为记录型绑定（caveat B1） |
| DeepSeek API / 新 LLM 调用 | 不需要 | 历史未落盘参数一律 `missing`，不补猜（D2-D） |
| `case.json` 的历史 `.bak-regate-*` 变体 | 未随包 | D4-B caveat；不影响 strict 判定 |
| `receipt.json` / 第三方签署 | **不存在** | `external_status=pending`，不得补写 |

因此：**五例按 `course-criteria-v2` 的材料口径 `strict_submittable=true`、`external=0`**；
但本包**不宣布 live 复现**，也**不宣布评测方受理或第三方评审通过**；
`strict_submittable=true` 只表示材料齐备、可复算，不等于「可直接复现提交」。

## 6. 构建与边界

| 项 | 动作 |
|---|---|
| 构建器 | `experiments/submission-pack/build_pack.py`（只读 workspace / review 证据，写包与本文档） |
| 原始证据 | **未改**：workspace 下 case/severity/propagation/logs/artifacts/task/DB 原样 |
| 包内记录 | 按原字节复制；路径映射为旁路文件，不改记录内容 |
| 新增派生 | CG-01 `trajectory/model_params.json`（从 `llm_matrix` 抽取，标注 derived_from）、`judgments/verdict.json`、`evidence-index.json`、`path-map.json` |
| 干净副本 | 复制后逐包复算；未引用 workspace |
| `git commit` | 无 |

## 7. 复核口径提醒

- `strict_submittable` 是**材料判定**，允许内部自审；`external_independent_submittable`
  要求真正的外部独立人手签署，五例均为 `false`（external=0）。
- `external_status=pending` 只表示未受理，不是「未通过」。
- 引用判定时必须连同「内部自审」一列一起引用；只摘 `strict_submittable=true`
  而不写复核性质，属于断章取义。
