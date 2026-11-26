# 严重性裁决建议（3 个待裁决点）

> **状态**：reviewer-1 的**建议**，`final=false`，等人工签字。机器可读版本见 `experiments/severity/review.json`。
> 只裁决三个维度（I/C/A 各一），**不改**草案其他维度、**不改** `workspace/*/artifacts/report/case.json`、LEDGER。
> 校验：`python3 experiments/check_severity_review.py` → `OK: 3/3 decisions present`。

## 0. 裁决方法

1. 每个建议值必须能落到 `file:line` 或日志行；证据不足处直接写"未实测"并给出翻案条件。
2. CVSS 3.1 base 按官方公式复算（`roundup(min(Impact+Exploitability,10))`），**只改一个维度**，其余沿用草案。
3. 同时列被排除取值的反方意见（每条都要给"为什么被排除"），避免单向论证。
4. `final` 一律 `false`：维度取值属危害判断，Agent 只给建议，签字权在人工。

## 1. 汇总表

| 案例 | 维度 | 草案值 | **建议值** | CVSS（前 → 后） | is_high_severity | 置信度 |
| --- | --- | --- | --- | --- | --- | --- |
| CG-02 | integrity_impact | I:N | **I:L** | 5.5 → 6.1 | false → false（不变） | medium |
| CG-04 | confidentiality_impact | C:N | **C:L** | 0.0 → 3.3 | false → false（不变） | low |
| CG-15 | availability_impact | A:L | **A:N** | 4.4 → 3.3 | false → false（不变） | medium |

**一句话**：三项建议都**不改变** `is_high_severity`（三例仍全为 false），只是把 CVSS 分值挪到与证据相符的位置；
真正会翻盘的是 CG-02 的 `I:H`（→ 7.1，变高危）——那需要"写入可停留在有意义的数据结构上且进程不崩"的证据，目前没有。

## 2. CG-02 · integrity_impact：**I:L**（草案 I:N）

**结论**：越界写已实测跨出 800 字节数组，因此不是 `I:N`；但写入内容恒为 0、攻击者只控起点与长度、
首触未映射页即 abort，达不到 `I:H` 的"完全/任意数据控制"，故取 **I:L**。

**证据**：

| # | 证据 | 说明 |
| --- | --- | --- |
| 1 | `workspace/CG-02-arvo-47101/logs/V4.gas-file4294967289.47101-vul.log:32` | `0 bytes to the right of 800-byte region` —— 越界第一字节即在数组外，**跨对象修改是实测事实** |
| 2 | `workspace/CG-02-arvo-47101/logs/V4.gas-file4294967289.47101-vul.log:14` | `WRITE of size 137438954272`；`:82` 立刻 `ABORTING`，真实存活期只到第一个未映射页 |
| 3 | `workspace/CG-02-arvo-47101/src/binutils-gdb/gas/dwarf2dbg.c:690` | `memset(files + old, 0, (i + 32 - old) * sizeof(struct file_entry))` —— 写入值固定为 0 |
| 4 | `workspace/CG-02-arvo-47101/src/binutils-gdb/gas/dwarf2dbg.c:681-689` | `files_allocated = i + 32` 在 unsigned 下回绕成 25（800 字节），长度却按 unsigned long 算 |
| 5 | `workspace/CG-02-arvo-47101/logs/V4.gas-file4294967289.47101-fix.log:13` | fix 侧报 `file number 4294967289 is too big`，确认命中的正是该缺陷路径 |

**反方意见**：

- **I:H**：主张"137GB 零写等于任意堆内存被清零"。**排除理由**：值恒 0、落点/范围不受控，且实测随即 abort（vul.log:82），
  没有持久化写、没有跨信任边界篡改；若采纳 I:H，CVSS 变 **7.1**、本例直接升为"高危"，与"无代码执行、无信息泄露"的实测不匹配。
- **I:N**：主张"只是把进程自己的堆写坏、随即崩溃，算纯可用性缺陷"。**排除理由**：ASAN 明确显示第 1 字节已在 800 字节区外（vul.log:32），
  `I:N` 与"已跨对象写"这一实测冲突。

**翻案条件**：能构造使 memset 在映射页内结束、且写坏的是仍有意义的数据结构 → 上调 `I:H`；
若评审坚持"必须造成可观测数据篡改才计 I" → 退回 `I:N`。

## 3. CG-04 · confidentiality_impact：**C:L**（草案 C:N）

**结论**：越界读到的 1 字节没有回显/落盘通道（草案据此标 `unproven`），但它作为 `loop_iters` 的**最低字节**进入控制流，
决定 LOOP 的重复次数，而重复次数会改变解码帧数/输出体积/时序 —— 这是一条窄但真实的信道；内容不可控、量只有 1 字节，故 **C:L** 而非 `C:H`。

**证据**：

| # | 证据 | 说明 |
| --- | --- | --- |
| 1 | `workspace/CG-04-arvo-10400/logs/V4.mng-loop4.10400-vul.log:13` | `READ of size 1` —— 越界只读 1 字节 |
| 2 | `workspace/CG-04-arvo-10400/logs/V4.mng-loop4.10400-vul.log:29` | `0 bytes to the right of 4-byte region` —— 读的是 4 字节分配外的相邻堆字节 |
| 3 | `workspace/CG-04-arvo-10400/src/graphicsmagick/coders/png.c:1021` | `mng_get_long` 里 `p[3]` 左移 0 位 → `chunk[4]`（越界字节）成为 `loop_iters` 最低字节 |
| 4 | `workspace/CG-04-arvo-10400/src/graphicsmagick/coders/png.c:4920-4921` | `loop_iters=mng_get_long(&chunk[1])` 后立刻 `if (loop_iters <= 0)`，越界值直接进控制流 |
| 5 | `workspace/CG-04-arvo-10400/src/graphicsmagick/coders/png.c:4926,4943-4945` | `loop_iters_max` 默认 512；裁剪后写入 `loop_count[loop_level]`，重复次数因此可观测 |
| 6 | `workspace/CG-04-arvo-10400/src/graphicsmagick/coders/png.c:4912` | 只校验 `length > 0` 就进入该路径（缺 `length >= 5`） |

**反方意见**：

- **C:N**（草案口径）："没有任何实测外泄路径，按'不实测不写泄露'应保持 C:N，base 0.0"。
  **回应**：C 维度衡量"信息可被访问"，不是"攻击者已拿到明文"；越界字节进入控制流且改变可观测输出这一源码事实，与 C:N 不符。
  但该保留意见成立：**若评审要求实测外泄，退回 C:N（base 0.0）**。
- **C:H**：主张"连续 chunk 处理可放大为多字节/可控地址读"。**排除理由**：本例只读 1 字节、读点固定在 `chunk[1..4]`，
  长度由 chunk 头决定且受 `PNG_MAX_UINT` 限制，没有任意地址/任意长度读原语。

**翻案条件（建议尽快做）**：差分实验——把相邻堆字节置 `0x00` 与 `0xFF`，比较输出帧数/文件大小/耗时是否稳定可区分；
可区分则 C:L 升级为"已实测信道"，不可区分则退回 C:N。

## 4. CG-15 · availability_impact：**A:N**（草案 A:L）

**结论**：越界量恒为 **1 字节 NUL**（分配 `strlen+1`、写入 `strlen+2`，源码直接可算）；
glibc `malloc(6)` 的最小 chunk 可用 24 字节，偏移 6 的 NUL 仍在本 chunk 的 padding 内，不触碰下一块 header；
日志里的 abort 来自 ASAN 拦截而不是目标自身崩溃。按现有证据，真实部署下的可用性影响应记 **A:N**。

**证据**：

| # | 证据 | 说明 |
| --- | --- | --- |
| 1 | `workspace/CG-15-arvo-3940/logs/V4.text-cg15_proj.bin-x1.3940-vul.log:19` | `WRITE of size 7` —— 只多写 1 字节 |
| 2 | `workspace/CG-15-arvo-3940/logs/V4.text-cg15_proj.bin-x1.3940-vul.log:34` | `0 bytes to the right of 6-byte region` —— 目标区 6 字节 = `strlen(grids)+1`，grids 长 5 |
| 3 | `workspace/CG-15-arvo-3940/src/proj.4/src/pj_apply_gridshift.c:276` | `pj_malloc((strlen(grids)+1)*sizeof(char))` |
| 4 | `workspace/CG-15-arvo-3940/src/proj.4/src/pj_apply_gridshift.c:277` | `sprintf(sgrids, "%s%s", "s", grids)` 需要 `strlen+2` 字节 → 恒多写 1 个 NUL |
| 5 | `workspace/CG-15-arvo-3940/logs/V4.text-cg15_proj.bin-x1.3940-vul.log:80` | `==7==ABORTING` —— 终止由 ASAN 触发，不是目标自身崩溃路径 |
| 6 | `workspace/CG-15-arvo-3940/logs/V4.text-cg15_proj.bin-x1.3940-fix.log:5` | fix 侧同输入 `Execution successfull`，exit=0 |

**反方意见**：

- **A:L**（草案口径）："ASAN 下确实 abort；换 libc/分配器或该串之后又被 realloc 时，第 7 字节可能落到真实边界外"。
  **回应**：A:L 目前只有"可能性"没有观测——全部现有日志都是 ASAN 构建内的 abort，缺非 ASAN 复跑。
  该保留意见成立：**拿到一次非 ASAN 崩溃即改 A:L**。
- **A:H**：主张"堆越界写可破坏分配器元数据 → 拒绝服务"。**排除理由**：越界仅 1 字节且落在同 chunk 的 padding 内，
  不触及下一 chunk 的 size 字段，无崩溃/挂起实测。

**翻案条件**：在非 ASAN 构建（同一 arvo 镜像去掉 ASAN，或 glibc 2.31 直接跑 `standard_fuzzer`）复跑该 43 字节 PoC；
出现 SIGSEGV/heap corruption 改 `A:L`，连续 N 次干净退出则 `A:N` 定案。

## 5. 三项都不改 is_high_severity 的原因

| 案例 | 裁决后 CVSS | 高危门槛 | 结论 |
| --- | --- | --- | --- |
| CG-02 | 6.1 | ≥ 7.0 | false（若改判 I:H → 7.1，才变 true） |
| CG-04 | 3.3 | ≥ 7.0 | false |
| CG-15 | 3.3 | ≥ 7.0 | false |

## 6. 校验与边界

```
python3 experiments/check_severity_review.py
# OK: 3/3 decisions present

python3 -m pytest tests -q
# 391 passed, 1 failed
```

pytest 的唯一失败是 `tests/test_platform.py::test_overview_totals_match_ledger`（`assert 23 == 15`）：
platform 的 `_case_dirs()` 把 workspace 下所有含 `task.json` 的目录都算交付案例（现有 23 个），
而 `experiments/LEDGER.json` 的 `totals.cases=15`；差额来自 S2/S4/S4B/S5B 等实验工作区。
该漂移在本次裁决之前就存在（与 `review.json`、本文档无关），且 `vulnmap_platform/` 与 `LEDGER.json` 都不在本任务可改范围。

未改动清单（本轮只写两个文件）：

- 未改 `experiments/severity/CG-*.json`（草案原样保留，包括 CG-04 的 `affected_confidentiality: unproven`）；
- 未改 `workspace/*/artifacts/report/case.json`、`experiments/LEDGER.json`；
- 未改任何 `agent/`、其他 workspace、既有 experiments；无 git commit；
- `final=false`：三维取值的最终签字权在人工，Agent 只提供证据化的建议值与反方意见。