# 真挖掘模式（Discovery）方案 v0.1

## 0. 定位

现有 vulnmap 是 reproduction：输入含 error/patch/description，输出是复现与验证。
Discovery 模式只给源码/二进制与构建方式，不读 error.txt、patch.diff、官方 PoC，输出是**新崩溃 → 去重 → 根因 → 可利用性**。

## 1. 与 BinSight 五阶段的映射

| BinSight | Discovery | 产物 |
|---|---|---|
| 样本准备 | 目标准备：源码/构建/插桩 | build.json、instrumented binary |
| 危险调用 | 攻击面与危险点 | surfaces.json、suspects.json |
| 漏洞分析 | 输入生成与 fuzz | corpus、crashes |
| 结论复核 | 去重、根因、可利用性 | triage.json |
| 报告生成 | 发现报告 | finding.json / report.md |

## 2. 架构

```text
target(source/binary)
  -> Prepare: build + ASAN/UBSAN + coverage + harness
  -> Surface: entries/parsers/protocols (static + LLM rank)
  -> Suspect: taint/dangerous APIs/bounds checks -> ranked functions
  -> Generate: seeds + dictionary + AFL++/libFuzzer + (optional) LLM seeds
  -> Execute: sandbox, timeout, corpus, coverage
  -> Triage: dedup(stack hash), root cause, reproducibility
  -> Assess: reachability, write/read, controllability, CVSS
  -> Report + evidence
```

## 3. 各阶段做法

### 3.1 Prepare
- 识别构建系统（Make/CMake/autotools/Meson）；优先 OSS-Fuzz 风格 build.sh；
- 编译两套：ASAN+UBSAN（发现）与干净版（复现确认）；
- 补 harness：优先项目自带 fuzz target；没有则按入口写 `LLVMFuzzerTestOneInput`；
- 记录 compiler flags、commit、依赖、binary sha256。

### 3.2 Attack surface
- 静态：ctags/tree-sitter/clang AST 抽入口（main、HTTP route、文件解析、IPC）；
- 格式识别：magic、扩展名、解析函数命名；
- LLM 只做排序：给入口列表与源码摘要，输出优先目标与理由；不产生结论。

### 3.3 Suspect
- 危险 API：memcpy/strcpy/sprintf/整数运算/数组索引；
- 轻量污点：从 read/recv/fread 到危险 API 的赋值链（clang AST 或 CodeQL/Semgrep）；
- 边界检查缺失：长度字段与缓冲区大小比较；
- 输出 suspects.json：file:line、函数、原因、可达入口、置信度。

### 3.4 Input generation
- 种子：仓库 tests/、样例文件、协议常量；
- 字典：magic、关键字、长度字段；
- 引擎：AFL++（persistent/QEMU 模式）或 libFuzzer；
- LLM 仅生成结构化种子（如 PNG chunk、PDF 对象），不参与判定；
- 预算：每目标 1–4 小时，覆盖率与 crash 数停止条件。

### 3.5 Triage
- 去重：栈哈希 + crash type + top frame；
- 根因：崩溃帧 → 源码行 → 变量来源；
- 复现：干净构建重跑 3 次；不稳定则标 flaky；
- 排除：OOM、超时、断言、harness 自身 UB。

### 3.6 Assess
- 写/读/控制流；写入字节是否受输入控制；
- 可达性：入口到 sink 的调用链；
- 影响：内存破坏/信息泄漏/DoS；
- 输出 severity draft，人工复核后定级。

## 4. 数据模型

```text
campaign(id, target, commit, flags, budget)
surface(id, campaign, entry, kind, file, line)
suspect(id, campaign, function, file, line, reason, score)
corpus(id, campaign, sha256, seed_source)
crash(id, campaign, sha256, stack_hash, type, stdout_path)
triage(id, crash, root_cause, reproducible, exploitability)
finding(id, triage, severity, cwe, report_path)
```

所有表带 provenance（工具、版本、参数、时间）。

## 5. 与现有代码复用

- 复用：sandbox、store、checkpoint、policy、FastAPI、台账；
- 新增：`agent/discovery/`：prepare、surface、suspect、fuzz、triage、assess；
- CLI：`vulnmap discover --target DIR --budget 2h`；
- 现有 reproduction 流程不改，两条模式共享证据层。

## 6. 评估方案

- 目标集：选 3–5 个开源解析器（libpng、libtiff、jq、nltk 等），**隐藏** error/patch/官方 PoC；
- 真值：维护者已知 CVE 或修复 commit，仅评测方持有；
- 指标：
  - 唯一有效崩溃数；
  - 与隐藏真值的交集（recall）；
  - 误报率（不可复现/非目标）；
  - 首次崩溃时间、覆盖率；
  - 高危占比。
- 对照：纯 fuzz vs fuzz+静态排序 vs +LLM 种子；
- 污染控制：代码冻结、断网、禁用 patch/error 文件、评测脚本不暴露答案。

## 7. 里程碑

| 阶段 | 内容 | 验收 |
|---|---|---|
| M1 | 构建+插桩+harness | 3 个目标能跑起来 |
| M2 | fuzz 闭环+去重 | 每目标产出可复现 crash |
| M3 | 静态 suspect 排序 | 命中率优于随机入口 |
| M4 | LLM 种子辅助 | 对 magic/结构格式提升覆盖率 |
| M5 | 评估报告 | recall/precision/时间对比 |

## 8. 风险与边界

- 构建失败率高：先选 OSS-Fuzz 项目；
- 无 harness：需要手写，工作量常大于 fuzz 本身；
- 时间预算：1–4 小时只能挖浅层；
- 误报：必须干净构建复现；
- 不覆盖：内核、固件、网络服务（后续扩展）。

## 9. 一句话

Discovery 的核心不是 LLM，而是 **插桩 + 覆盖率 + 去重 + 可复现**；LLM 只做排序和种子，不参与判定。