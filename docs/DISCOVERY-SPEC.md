# vulnmap Discovery 技术方案（落地版）

> 版本：v1.0 · 2026-11-15  
> 定位：**Discovery 是唯一平台**，旧复现平台归档，不做双轨、不做备选。

## 1. 目标与非目标

### 目标

输入只有源码/二进制与构建方式，不读取 `error.txt`、`patch.diff`、官方 PoC，完成：

1. 静态档案与入口识别（D0）；
2. 危险调用点台账与覆盖率（D1）；
3. 调用点 Agent 沙箱并发分析（D1.5）；
4. Harness + ASAN + 覆盖率引导的并行 fuzz（D2）；
5. 崩溃复核、去重、根因分类（D3）；
6. 完整性报告（D4）；
7. 对照评估（D5）。

### 非目标

- 不做固件解包、跨架构仿真；
- 不接 IDA/Ghidra 作为必需依赖；
- 不把“崩溃数”直接当“高危数”；
- 不用旧平台的 30/23/9 作为课程成果。

## 2. 总体架构

```text
target(source / binary)
  │
  ├─ D0  profile.py        静态档案：源文件、ELF、入口、格式、哈希
  ├─ D1  callsites.py      危险调用点 + 调用图 + 评分 + 覆盖率台账
  ├─ D1.5 agents.py        调用点 Agent 沙箱并发；可选 LLM；只产假设
  ├─ D2  covfuzz.py        Harness + ASAN + trace-pc 覆盖率 + 并行变异
  ├─ D3  triage.py         复现 3 次、栈哈希去重、根因、四类结论
  ├─ D3.5 agents.py        简化复核 Agent：单次独立复核
  ├─ D4  report.py         完整性表 + 风险统计 + 逐条发现
  └─ D5  campaign.py       对照评估：ranked vs random、Agent 种子 A/B
```

原则：**Agent 只指路，Fuzz 证明，Triage/Review 判定，报告只写证据。**

## 3. 目录结构

```text
agent/discovery/
  profile.py        D0
  callsites.py      D1
  agents.py         D1.5 / D3.5（任务池、假设、种子、复核）
  covfuzz.py        D2（覆盖率引导 + 并行）
  coverage_map.py   PC → file:line → 调用点
  triage.py         D3
  report.py         D4
  campaign.py       D5 / 编排
bin/
  discover.py       CLI：vulnmap discover
  covfuzz.py        CLI：并行 fuzz
fixtures/discovery/ 受控 C fixture
discovery/real-cjson/ 真实目标证据
docs/               本方案与结果
```

## 4. D0：静态档案

### 输入

目标目录：源码 + 已编译 ELF（或可构建的源码树）。

### 输出 `target.json`

```json
{
  "target": "cJSON",
  "root": "/tmp/cJSON",
  "sources": ["cJSON.c", "harness.c"],
  "binaries": [{"path": "cjson_fuzz", "sha256": "...", "size": 151432}],
  "entries": [{"kind": "main", "file": "harness.c", "line": 6}],
  "functions": [{"name": "cJSON_Minify", "file": "cJSON.c", "line": 2600}],
  "formats": ["json"],
  "source_count": 2
}
```

### 规则

- 源文件后缀：`.c/.cc/.cpp/.h/.hpp`；
- ELF 识别：magic `\x7fELF`，记录 sha256；
- 入口：`main(` 正则；
- 格式：magic/扩展名；无法识别记 `unknown`。

## 5. D1：危险调用点台账

### 危险函数表

| 类别 | 函数 | 权重 |
|---|---|---|
| copy | memcpy/memmove/strcpy/strcat | 3 |
| format | sprintf/vsprintf/snprintf | 3/2 |
| alloc | malloc/realloc | 1 |
| input | read/fread/recv | 2 |

### 台账字段

```json
{
  "function": "cJSON_Minify",
  "file": "cJSON.c",
  "line": 2642,
  "callee": "memcpy",
  "category": "copy",
  "args": "dst, src, len",
  "controlled": true,
  "reachable": true,
  "score": 12.0,
  "status": "unanalyzed"
}
```

### 评分

```text
score = 危险权重 × (可达 ? 2 : 1) × (参数可控 ? 2 : 1)
```

- 可达：从 `main` 出发的近似调用图 BFS；
- 可控：实参包含 `data/buf/input/len/size/n/p/src`。

### 覆盖率

```text
planned = 调用点总数
covered = 被 PC 映射命中的调用点
uncovered = planned - covered
status = complete | partial
```

**覆盖率是硬指标**：报告必须同时写 planned/covered/uncovered。

## 6. D1.5：调用点 Agent 沙箱并发

### 任务模型

```python
@dataclass
class Task:
    task_id: str
    kind: str
    payload: dict

@dataclass
class Result:
    task_id: str
    ok: bool
    data: dict
    error: str
    seconds: float
```

### 执行

- `run_pool(tasks, handler, workers=4, timeout=60)`；
- 每任务一个 `tempfile.mkdtemp` 工作目录；
- `ThreadPoolExecutor` 并发；单任务失败不影响整批。

### 分析 Agent 的边界

- 只读源码；**不执行目标**；
- 输出 `hypothesis.json`：

```json
{
  "site_id": "cJSON.c:2642:memcpy",
  "function": "cJSON_Minify",
  "file": "cJSON.c",
  "line": 2642,
  "hypothesis": "length/offset from input reaches dangerous call",
  "confidence": 0.7,
  "citations": ["cJSON.c:2642"],
  "window": "...源码窗口..."
}
```

### LLM 接入（可选）

- prompt 只给：site 元数据 + 30 行源码窗口 + 可达性；
- 要求 JSON；`citations` 必须能在源码解析，否则丢弃；
- 超时/无 key → 回退 `heuristic_analyze`；
- LLM **不产出 verdict**。

### 结构化种子

`propose_seeds(site)`：

- JSON：长字符串、`\u0000`、未闭合注释、长数字、反斜杠、数组骨架；
- PNG：IHDR/IDAT/IEND 合法 chunk；
- 其他：通用 magic + 长度字段。

种子只写入 fuzz corpus，不直接判漏洞。

## 7. D2：Harness / ASAN / 覆盖率 / 并行 fuzz

### Harness

每个目标一个最小入口，读文件后调用目标 API：

```c
int main(int argc, char **argv) {
    read_file(argv[1]);
    target_api(buf, len);
}
```

### 构建

```bash
gcc -g -O1 -no-pie \
    -fsanitize=address \
    -fsanitize-coverage=trace-pc \
    -I. target.c harness.c cov_rt.o -o fuzz_target
```

### 覆盖率运行时 `cov_rt.c`

```c
__attribute__((no_sanitize_address))
void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    map[(pc >> 4) & 0xffff] = 1;
    pcs[npcs++] = pc;
}
```

- 64K bitmap 用于语料反馈；
- PC 数组写 `COV_PCS`，用于 `addr2line` 映射；
- `cov_rt.c` 必须**单独编译**，否则回调自递归。

### fuzz 循环

```text
corpus 种子 → 变异 → 执行 → ASAN 判定
   ├─ 新 bitmap 位 → 加入 corpus（上限 300）
   └─ 崩溃 → 保存 input + log → 停止该 worker
```

### 并行

- `multiprocessing`，每 worker 独立工作目录；
- 输入上限 64KB；单次超时 2s；
- `Popen.wait(timeout)` + kill，避免管道卡死；
- 4 workers 实测约 1.5–2k exec/s（cJSON）。

### 覆盖率归属

```text
COV_PCS → addr2line -f -C → file:line / function
→ 命中调用点 function/file:line → covered_by_pc
```

## 8. D3：复核与去重

### 解析

- `ERROR: AddressSanitizer: <type>`；
- `READ/WRITE of size N`；
- 第一帧非 interceptor 的 `file:line`。

### 去重

```text
stack_hash = sha1(type | function | file:line)[:16]
```

### 复现

干净构建重跑 3 次；

### 结论

| 条件 | verdict |
|---|---|
| 写 + 3/3 | confirmed |
| 读/UB + 3/3 | weakened |
| 0/3 | excluded |
| 不稳定 | needs_human |

### 简化复核 Agent

- 输入：triage 结果 + 栈哈希；
- 单次判断，不做多轮辩论；
- 不做二次利用/堆布局；
- 输出四类结论 + reason。

## 9. D4：报告

固定结构：

1. 分析完整性：静态档案、调用点、输入构造/执行；
2. 风险统计：planned/covered/confirmed/weakened/excluded；
3. 发现条目：函数、file:line、类型、读写、栈哈希、复现次数。

输出：`report.json` + `report.md`。

## 10. D5：评估

- ranked vs random 调用点顺序；
- Agent 种子 vs 纯 fuzz：执行数、首次崩溃耗时；
- 指标：覆盖率、confirmed、time-to-first-crash；
- 负结果保留。

## 11. 数据模型（当前实现）

当前落盘为 JSON：

```text
target.json / callsites.json / hypotheses.json / reviews.json
crashes/crash-*.bin + .log
triage.json / report.json / report.md
```

计划中的 SQLite 表：

```sql
campaign(id, target, commit, build_flags, budget, status)
binary(id, campaign, path, sha256, arch, bits, endian)
call_site(id, campaign, function, file, line, callee, score, status)
candidate(id, call_site, input_sha256, crash_type, stack_hash, log_path)
review(id, candidate, verdict, root_cause, reproducible, notes)
finding(id, review, severity, cwe, report_path)
coverage(id, campaign, stage, planned, covered, uncovered)
```

## 12. CLI

```bash
# 单目标 discovery（fixture）
python3 bin/discover.py fixtures/discovery --out /tmp/out --seconds 3 --max-sites 3

# 覆盖率引导并行 fuzz
python3 bin/covfuzz.py /tmp/cJSON/cjson_fuzz \
  --corpus /tmp/cjson-corpus2 --crashes /tmp/cjson-crashes2 \
  --stats /tmp/cjson-stats2 --seconds 60 --workers 4

# A/B
python3 experiments/agent_seed_ab.py
```

## 13. 真实结果

### cJSON 1.7.10

```text
heap-buffer-overflow READ of size 1
cJSON_Minify cJSON.c:2642
3/3 复现，0.17s 首次崩溃
verdict: weakened（读越界）
coverage: 14/80 调用点
```

证据：`discovery/real-cjson/`。

### libpng 1.6.37

```text
4 workers × 60s ≈ 62,400 execs
crashes = 0（负结果）
```

### Agent 种子 A/B（cJSON）

| 策略 | 种子 | 执行数 | 首次崩溃 |
|---|---:|---:|---:|
| 纯 fuzz | 4 | 10 | 0.19s |
| Agent 种子 | 10 | 8 | 0.17s |

结论：在该目标上无显著优势，如实保留。

## 14. 限制

1. Agent 目前是启发式，LLM 未接生产 key；
2. 覆盖率只做了函数/行级归属，未做边覆盖；
3. 没有写/UAF 发现，只有读越界；
4. harness 手写，构建未自动化；
5. 沙箱是进程隔离，不是容器/VM；
6. 未做多轮复核与辩论。

## 15. 路线图

| 阶段 | 内容 | 验收 |
|---|---|---|
| P1 | Agent 种子接入 + A/B | 已完成，cJSON 无优势 |
| P2 | PNG/TIFF 结构化变异 | 至少一个 WRITE/UAF confirmed |
| P3 | 旧平台下线，Discovery 唯一入口 | 新前端五页 + 单 CLI |
| P4 | 构建/harness 自动化 | target.yaml → campaign |

## 16. 安全边界

- 目标必须是本地、授权、隔离环境；
- 默认无网络；不对外提交；
- 失败不删除、不伪造结论；
- 读越界不写成高危。