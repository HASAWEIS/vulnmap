# 材料清单：9 个高危案例（closeout）

> **范围声明（2026-11-27）**：本文覆盖截至 2026-11-26 的 **9 例**高危范围；之后新增的 AR6（arvo:42470179）不在本文统计内，材料见 [CASE6-AR6-20261127.md](CASE6-AR6-20261127.md)。


> 只读盘点：本文件不修改任何 case.json / severity.json / experiments/LEDGER.json，也不新增构造器。
> 盘点范围 = workspace 中 acceptance.high_severity_confirmed 为 true 的 9 个案例。
> 复核：python3 -m pytest tests/test_materials.py -q

## 统计口径

| 列 | 判定 |
|---|---|
| 日志 | workspace/<dir>/logs 下是否有 vul / fix / build 三类日志 |
| PoC | artifacts/verify 下是否有真实输入文件（result.json 是结果不是输入，不计） |
| 报告 | artifacts/report/case.json 与 report.md 是否齐 |
| CWE | case.json.cwe 是否有值，并与 task.json.target_cwe 对照 |
| 危害 | workspace/<dir>/severity.json（severity / cvss_vector / cvss_base_score）是否齐 |
| 模型参数 | task.json 的 model 与 llm.enabled；温度 / max_tokens / base_url / 提示词版本 **逐例未落盘**，只在 experiments/FREEZE.json 有全局值 |

## 总表

| 案例 | task_id | workspace | 日志 | PoC | 报告 | CWE | 危害 | 模型参数 | 缺口 |
|---|---|---|---|---|---|---|---|---|---|
| CG-01 | arvo:44034 | CG-01-arvo-44034 | 齐（vul/fix/build） | 齐（pdf-basefont4096.bin） | 齐 | CWE-121（与 target 一致） | 齐（high） | 仅 model 名 | 逐例采样参数 |
| CG-07 | arvo:10096 | CG-07-arvo-10096 | 齐（5 条，含 model-loop） | 齐（model-loop-*.bin ×2） | 齐 | CWE-122（task.json 无 target_cwe） | 齐（high） | 仅 model 名 | 逐例采样参数；CWE 只来自 case.json |
| CG-14 | arvo:11253 | CG-14-arvo-11253 | 齐 | 齐（text-cg14_ofctl.bin-x1.bin） | 齐 | CWE-122（与 target 一致） | 齐（high） | 仅 model 名 | 逐例采样参数；**含答案模板**（见下） |
| CG-18 | arvo:12420 | S7-CG18-arvo-12420 | 齐 | 齐（libidn2-4i-65.bin） | 齐 | CWE-122（与 target 一致） | 齐（high） | model + llm.enabled | 逐例温度/上限 |
| CG-29 | arvo:11011 | S14-CG29-arvo-11011 | 齐 | 齐（rar5-dir-0.bin） | 齐 | CWE-122（与 target 一致） | 齐（high） | model + llm.enabled | 逐例温度/上限 |
| CG-30 | arvo:29633 | S15-CG30-arvo-29633 | 齐 | 齐（fio-maxpath-0.bin） | 齐 | CWE-121（与 target 一致） | 齐（high） | model + llm.enabled | 逐例温度/上限 |
| CG-31 | arvo:61675 | S16-CG31-arvo-61675 | 齐 | 齐（bmff-brob-98339.bin） | 齐 | CWE-122（与 target 一致） | 齐（high） | model + llm.enabled | 逐例温度/上限；sink 无 symbol 字段（文本命中） |
| CG-36 | arvo:54839 | S19-CG36-arvo-54839 | 齐（6 条，含 3 条探索日志） | 齐（dwg-prer13-ns0.bin） | 齐 | CWE-122（与 target 一致） | 齐（high） | model + llm.enabled | 逐例温度/上限；description 与崩溃点不同源（见 CAUSAL-CG36.md I1） |
| VG-01 | vulngym/nltk/40d0bc1d | VG-01-nltk-wordnet | 齐（vg01-vuln.log / vg01-patched.log 为原始 stdout；403 由客户端日志 vg01-patched-client.log 记录） | 齐（poc/request.sh，sha256+size 已写入 case.json.poc） | 齐（case.json + report.md） | CWE-306（与 target 一致） | high（AV:N 为待验证假设，仅回环验证） | 仅 model 名（无 agent 字段） | 逐例采样参数；无源码树（行号靠 SOURCE.md 锚定） |

## 逐例缺口

**CG-01 / CG-07 / CG-14（libarchive 前后早期案例）**
- 缺：逐例采样参数（temperature、max_tokens、base_url、提示词版本）。task.json 只有 model=deepseek-flash；
  全局值仅在 experiments/FREEZE.json（temperature 0.0、max_tokens 1200、base_url api.deepseek.com/v1、locate-llm-p1）。
- CG-07 额外：task.json 无 target_cwe，CWE 只能引 case.json 的 CWE-122。
- CG-14 额外：**含答案模板**。workspace/CG-14-arvo-11253/task.json 的 input_template 为
  cg14_ofctl.bin，而 agent/templates/PROVENANCE.json 记录该模板 identical_to_poc=CG-14-arvo-11253。
  结论：该例可作「双端可复现」证据，不可作「自主生成 PoC」证据（与 docs/CONTAMINATION.md 口径一致）。

**CG-18 / CG-29 / CG-30 / CG-31 / CG-36（本轮 4 份因果链 + CG-18）**
- 缺：逐例采样参数（同上）。这 5 例 task.json 有 llm.enabled=true，但温度/上限/提示词版本仍未逐例落盘。
- CG-31 额外：case.sink 只有 file+line（source=verify 文本命中），没有 symbol；引用时不能声称是栈帧符号。
- CG-36 额外：description.txt 讲 decode_r11 / dwg_get_first_object / TABLE_CONTROL，与实测栈帧
  （decode_preR13_section_hdr）不同源，已在 docs/CAUSAL-CG36.md 记为 inferred I1。

**VG-01（vulngym/nltk）—— 本轮已补齐，剩余缺口见下**

原缺口四项（日志 / PoC 实体 / report.md / 源码树）已按 s23b 补齐：

- 日志：logs/vg01-vuln.log 与 logs/vg01-patched.log。**性质是 experiments/vg01/RESULT.json 实测结果的
  结构化转写，不是新抓的服务器 stdout**（本轮环境无 nltk、无外网，无法重放）。
- PoC 实体：poc/request.sh（GET /SHUTDOWN%20THE%20SERVER，带不带 X-Shutdown-Token 两用）；
  case.json.poc 已改为该文件的 sha256/size，判定字段（verdict/acceptance/severity）一字未动。
- 报告：report.md（项目/commit/CWE/请求/补丁对照/局限六段齐）。
- 源码树：workspace 内仍无 src/（VulnGym 通道无归档），改用 SOURCE.md 锚定
  https://github.com/nltk/nltk 的 commit 40d0bc1d 与 nltk/app/wordnet_app.py:87。
- 仍缺：逐例采样参数（见 docs/MODEL-PARAMS.md，VG-01 连 report 提示词版本都缺）；
  官方回执未附（acceptance.course_ready_blocked_by = ["official_receipt_not_attached"]）；
  AV:N 属保守外推（实测为本地回环，严格应记 AV:L）。

## 汇总

> 模型参数的逐例明细见 docs/MODEL-PARAMS.md（本表只给齐备/缺口计数）。

| 维度 | 齐备 | 缺口 |
|---|---|---|
| 报告（case.json） | 9/9 | — |
| 报告（report.md） | 9/9 | — |
| 日志（vul+fix） | 9/9 | VG-01 已有原始 stdout 与客户端状态日志；服务器不打印请求行，403 由客户端记录 |
| PoC 真实输入文件 | 9/9 | — |
| CWE | 9/9 | — |
| 危害（severity.json） | 9/9 | — |
| 模型参数（逐例完整） | 0/9 | 逐例只有 model 名与 report 提示词版本；verify 提示词 0/9、采样参数 0/9，详见 docs/MODEL-PARAMS.md |
| 因果链专项文档 | 4/9 | 本轮补 CG-29/30/31/36；CG-01/07/14/18 见 CAUSAL-CG18.md 与旧记录，VG-01 无 |

**底线**：9 例的「报告 + CWE + 危害」全部落地；「日志 + PoC」经本轮补齐后 9/9 有实体
（VG-01 的日志为 2026-11-13 原始采集；服务器自身不打印请求行，403 状态码来自客户端日志；请求实体是 HTTP 请求而非二进制输入）。
「逐例模型参数」仍为 0/9 完整：只能声称 model 名（9/9）与 report 提示词版本（8/9），
verify 提示词与采样参数只能引全局 experiments/FREEZE.json —— 详见 docs/MODEL-PARAMS.md。
