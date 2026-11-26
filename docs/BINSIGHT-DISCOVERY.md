# 深度参考 BinSight 的漏洞挖掘设计

> 参考对象：BinSight 的系统总体架构、核心技术（固件漏洞挖掘）、漏洞挖掘流程三张图。
> 目标：把它的工程结构迁移到 vulnmap 的 Discovery 模式，但保留“源码/二进制、无 error/patch”的前提。

## 1. BinSight 到底怎么挖

它的五段不是“扫一遍出报告”，而是**按调用点做任务分解，再逐点复核**：

1. **样本准备**：文件识别、二进制索引；建立哈希/格式/架构/位数/端序/字符串静态档案；
2. **危险调用**：危险函数库 + 调用点清单；种子输入 + 增量补充候选点；输出“危险函数调用点与覆盖率”；
3. **漏洞分析**：按调用点并发开智能体沙箱；每个沙箱做调用点分析 + 数据流追踪；
4. **结论复核**：复核智能体独立复查，结论分 confirmed / weakened / excluded / 需人工；
5. **报告生成**：文件信息、分析完整性、风险统计、漏洞总览、逐条详情；完整性表统计“计划/已覆盖/未覆盖”。

工程上分五层：用户接入、编排调度、Agent、沙箱、数据持久化；工具链含 IDA、Binwalk、QEMU/Qiling、Docker、LLM、PostgreSQL。

## 2. 迁移到 vulnmap 的关键改造

| BinSight | vulnmap Discovery | 改造原因 |
|---|---|---|
| 固件解包 | 源码构建 / 二进制加载 | 我们不做固件，先做用户态 |
| IDA Pro 反编译 | clang AST / tree-sitter / objdump；IDA/Ghidra 可选适配 | 环境无 IDA，不能假装有 |
| Binwalk | file/readelf/strings/格式识别 | 无固件镜像 |
| QEMU/Qiling | 原生执行 + Docker 沙箱 | 同架构，无需仿真 |
| PostgreSQL | SQLite（现有）/ 可换 PG | 单机够用，接口按仓储抽象 |
| 调用点并发智能体 | 按 suspect/call-site 分片的任务队列 | 复用现有 TeamQueue |

## 3. 五段式 Discovery 设计

### 3.1 样本准备：静态档案 + 索引

对每个目标建立 `target.json`：

```json
{
  "target": "libtiff",
  "commit": "...",
  "build": {"system": "cmake", "sanitizer": "asan+ubsan", "flags": "..."},
  "binaries": [{"path": "tools/tiffcrop", "sha256": "...", "arch": "x86_64", "bits": 64, "endian": "little"}],
  "formats": ["tiff", "raw"],
  "entries": [{"kind": "cli", "file": "tools/tiffcrop.c", "line": 120}],
  "harness": {"path": "fuzz/tiff_read.c", "status": "present"}
}
```

索引内容：文件哈希、格式 magic、架构、字符串、导入函数、编译单元、入口。

### 3.2 危险调用：函数库 + 调用点清单 + 覆盖率

危险函数分四类：

| 类别 | 例子 | 关注点 |
|---|---|---|
| 内存拷贝 | memcpy/memmove/strcpy/strcat | 长度来源、目标大小 |
| 格式化 | sprintf/snprintf/vsnprintf | 格式串可控性 |
| 整数 | 乘法/加法/移位 | 溢出后进入长度 |
| 索引/分配 | 数组下标、malloc/realloc | 上界检查 |

每个调用点一条记录：

```text
call_site(id, function, file, line, callee, arg_sources[], reachable_from[], score)
coverage(planned=N, analyzed=M, unanalyzed=K, status)
```

**覆盖率是硬指标**：BinSight 报告里“发现 184 / 覆盖 184 / 未覆盖 0”就是这一层；我们不能只报“分析了几个”，要报“计划多少个调用点、实际多少个”。

### 3.3 漏洞分析：按调用点开沙箱

每个 call site 一个任务：

1. 静态切片：从入口到调用点的赋值/长度/索引链；
2. 数据流：输入字段 → 长度/偏移 → 调用参数；
3. 输入构造：构造器 / 字典 / fuzz 种子；
4. 执行：Docker sandbox，ASAN/UBSAN，超时；
5. 产出：候选 crash + 触发链 + 证据。

并发模型：任务队列 + 每任务独立工作目录 + 只读源码挂载；结果写回 `candidate` 表。

### 3.4 结论复核：独立复核智能体

复核不重新挖，只做四件事：

1. 复现：干净构建重跑 3 次；
2. 根因：崩溃帧与声明 sink 是否一致；
3. 独立性：与已有 finding 是否同源（栈哈希/根因/补丁点）；
4. 可利用性：读/写、可控字节、可达性。

结论只允许四种：

```text
confirmed    复现稳定、根因一致、影响成立
weakened     能触发但影响弱（如只读/仅 DoS）
excluded     不可复现、harness UB、环境错误
needs_human  证据不足，交人工
```

这与 BinSight 的“确认成立/弱化/排除/需人工复核”一一对应。

### 3.5 报告：完整性 + 风险统计 + 逐条证据

报告固定结构：

1. 文件信息：目标、commit、构建、哈希；
2. 分析完整性：调用点计划/覆盖/未覆盖、阶段状态；
3. 风险统计：严重性分布、结论分布、CWE 分布；
4. 漏洞总览：ID、位置、类型、结论、severity；
5. 逐条详情：基本信息、漏洞概述、触发链与证据、影响、修复建议。

完整性表必须能回答“有没有漏”，而不是只列“发现了什么”。

## 4. 数据模型

```text
campaign(id, target, commit, build_flags, budget, status)
binary(id, campaign, path, sha256, arch, bits, endian)
entry(id, campaign, kind, file, line)
call_site(id, campaign, function, file, line, callee, score, status)
candidate(id, call_site, input_sha256, crash_type, stack_hash, log_path)
review(id, candidate, verdict, root_cause, reproducibility, independence, notes)
finding(id, review, severity, cwe, report_path)
coverage(id, campaign, stage, planned, covered, uncovered)
```

## 5. 优先级与调度

调用点不可能全跑，按分数排序：

```text
score = 入口可达性 × 输入可控性 × 危险度 × (1/分析成本)
```

- 入口可达性：从 main/route/parser 到调用点的最短路径；
- 输入可控性：参数是否来自 read/fread/recv；
- 危险度：写 > 读 > DoS；
- 成本：函数大小、依赖深度。

预算内先跑高分点，未跑的点在报告里标 `unanalyzed`，不静默。

## 6. 工具适配层

BinSight 绑 IDA/Binwalk/QEMU；我们做抽象接口：

```text
Disassembler: clang/objdump（默认）| IDA（可选）| Ghidra（可选）
Unpacker:     无（源码/ELF）| binwalk（可选）
Emulator:     native（默认）| qemu（可选）
```

工具缺失时显式 `tool_unavailable`，回退默认实现，不伪造结果。

## 7. 与现有 vulnmap 的集成

- 新增 `agent/discovery/`，不改 reproduction；
- 复用：sandbox、store（SQLite）、checkpoint、policy、TeamQueue、FastAPI；
- 新命令：`vulnmap discover --target DIR --budget 2h --jobs 4`；
- 新页面：Discovery 报告（完整性表 + 风险统计 + 逐条），风格对齐现有报告页。

## 8. 里程碑

| 阶段 | 交付 | 验收 |
|---|---|---|
| D0 | 静态档案 + 入口识别 | 3 个目标生成 target.json |
| D1 | 危险调用点清单 + 覆盖率 | call_site 表可统计 planned/covered |
| D2 | 单点切片 + 输入构造 + fuzz | 至少 1 个可复现 crash |
| D3 | 复核智能体 + 去重 | confirmed/excluded 分类可用 |
| D4 | 报告页 + 完整性 | 报告能说明“漏没漏” |
| D5 | 对照评估 | 纯 fuzz vs 调用点优先的 recall/时间 |

## 9. 不照搬的部分

- 不做固件解包和跨架构仿真（当前无镜像/工具）；
- 不画 IDA/Binwalk/QEMU 为“已接入”；
- 不用“820 行报告/放大”这类展示功能充当分析能力；
- 不把“调用点覆盖”说成“漏洞发现”，二者分开统计。

## 10. 一句话

BinSight 值得学的不是界面，而是三件事：**静态档案、调用点全覆盖台账、独立复核结论**。
把这三件事做成 Discovery 的骨架，LLM 只是加速器，不是判定器。