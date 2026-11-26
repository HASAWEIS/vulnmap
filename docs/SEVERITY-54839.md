# CG-36 / arvo:54839（libredwg AC1009，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S19-CG36-arvo-54839/severity.json`；结构校验：`tests/test_severity_54839.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H = 7.1  (high)
```

**I:H 的依据不是「4 字节」，而是「这 4 字节写到哪里、值由谁定」**：值来自文件（`bit_read_RS/RL`），落点正好是**下一个 chunk 的 size 字段**。
固定的只是**下标**（五个调用点用枚举 BLOCK=1…VIEW=6），不是写入内容——这两件事必须分开看。

## 1. 三个可复核的事实

| # | 事实 | 证据 |
| --- | --- | --- |
| 1 | 数组大小由文件决定：`calloc(sizeof(Dwg_Section), num_sections + 2)`，PoC 把 `num_sections` 设 0 → 只有 **2 个槽位 = 256 字节** | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729`；`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:28`（256-byte region） |
| 2 | 写入内容由文件决定：`tbl->size/number/flags = bit_read_RS(dat)`、`tbl->address = bit_read_RL(dat)` | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:275-278` |
| 3 | 下标是固定的枚举：BLOCK=1、LAYER=2、STYLE=3、LTYPE=5、VIEW=6，五个 `decode_preR13_section_hdr` 调用依次写 section[1..6] | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:765-769`；`workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8579-8584` |

因此：id=1（BLOCK）还落在第 2 个槽位里（偏移 128），**id=2（LAYER）就写到偏移 256 —— 正好越过 256 字节数组**，日志的首个越界写就是它（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:16` 指向 `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:275`）。

## 2. 落点算术：4 字节写进了下一块的 size 字段

| 量 | 值 | 依据 |
| --- | --- | --- |
| `sizeof(Dwg_Section)` | 128 字节 | `workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8591-8610` 字段：number(0)、size(4)、address(8)、name(40,64B)、flags(124) |
| 数组（num_sections=0） | 2×128 = **256 字节** | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729`；`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:28` |
| glibc 下该请求的 chunk | 272 字节，可用 264 | 256+8 向上对齐 16 |
| 用户指针 U 之后 | U+0..263 是本块可用区；**U+256..263 = 下一块 prev_size**；**U+264..271 = 下一块 size**；U+272 起是下一块用户数据 | 标准 chunk 布局 |
| `tbl->address` 写到哪 | section[2]+8 = **U+264**，8 字节 store（uint64_t 字段） | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:274`、`:278`；`workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8595` |
| `tbl->name` 写到哪 | section[2]+40 = U+296，64 字节 | `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:279`；`workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8602` |

**结论**：文件里的 32 位 `address` 值（零扩展成 64 位）会被写进**下一块的 size 字段**；`number/size/flags` 覆盖它的 prev_size 低半部；`name`（常量表名）再往下一块用户数据里写 64 字节。这不是「随便越界 4 字节」，是**用文件值改写分配器元数据**。

## 3. 为什么不是「只是 4 字节」，也不是「固定 id 所以不可控」

| 说法 | 判定 |
| --- | --- |
| 只越界 4 字节 → I:L | 不成立：ASAN 只报第一个越界访问（size 字段，U+260），同一次调用还会继续写 number(U+256)、address(U+264)、name(U+296)、flags(U+380) |
| id 固定 → 内容不可控 | 不成立：固定的是**下标**，写入值来自 `bit_read_RS/RL`（文件字节）；而且 `num_sections` 也由文件控制，决定数组有多小 |
| 无界写 → I:H 太夸张 | 也不需要：越界上限有界（num_sections+2 ≥ 2、最大 id=6 → 约到 U+896），但**元数据字段被文件值覆盖**这一点已足够 I:H |

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | DWG 解析入口（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:1`、`:10-11`、`:16-17`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 606 字节固定 PoC 一次命中，vul exit=1 / fix exit=0（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:2`、`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-fix.log:2`） |
| PR | **N** | 解析 DWG 不需要额外权限（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把文件交给解码器（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:10-11`）；自动处理无证据 → 保守 R |
| S | **U** | 影响在解码进程的堆内 |
| C | **N** | 只写不读 |
| I | **H** | §2：文件值写进下一块 size 字段 + 覆盖其 prev_size/用户数据 |
| A | **H** | 元数据被改写后，后续 free/malloc 必然异常；ASAN 下已 exit=1（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:2`） |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:1`、`:10-11`、`:16-17` |
| privileges_required | none | `workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:1-2` |
| user_interaction | required | `workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:10-11`、`:16-17` |
| observed_impact | heap_buffer_overwrite_controlled_metadata | `workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:13-16`、`:28`、`:30-31`；源码 `workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729`、`:765-769`、`:275-279`；结构 `workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8591-8610` |
| reachability_evidence | confirmed | `workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:16-17`；`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-fix.log:2,12` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log:2`、`workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-fix.log:2`）；生产消费方与分配器加固无证据 |

## 6. 缺证据清单

1. **非 ASAN 崩溃实测**：预期后续 free 报 `invalid size` 或踩坏相邻块，但未跑。
2. **生产消费者与分配器**：谁解析不可信 DWG、glibc 版本/加固（tcache、safe-linking 会影响后续后果）。
3. **address 值落地后的实际效果**：需要构造 `address` 为特定值观察 free/malloc 行为（利用实验）。
4. **num_sections 的其它取值**：本例是 0；其它值下越界起点/范围会变，未系统测。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `I:L`（要求实测改写元数据有效） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `A:L`（ASAN abort 不外推） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| 只算 DoS | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | 5.5 |
| `UI:N`（自动批量转换） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | 7.7 |
| `AC:H`（依赖 num_sections=0 等组合） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H` | 6.3 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 8.1 |

## 8. 反方意见

- **「只有 4 字节，glibc 前 8 字节还在 slack 里（256 请求 → 可用 264）」**：回应：slack 只吃掉 U+256..263（prev_size 低半部）；`address` 的 8 字节 store 落在 **U+264**，正好是下一块的 size 字段，值是文件给的。补一个非 ASAN 复跑（看 `free(): invalid size`）即可定案；在那之前若坚持实测优先，可给 I:L = 6.1。
- **「id 是固定的，不算可控」**：回应：固定的是下标；`number/size/flags/address` 全部来自 `bit_read_RS/RL`（`workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:275-278`），`num_sections` 也由文件决定（`workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729`）。

## 9. 校验

```
python3 -m pytest tests/test_severity_54839.py -q
```

测试会直接读**日志/源码/结构体**验证：日志必须是 `WRITE of size 4` + `4 bytes to the right of 256-byte region`；
`workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729` 必须是 `calloc(..., num_sections + 2)`，`:765-769` 必须是五个 `decode_preR13_section_hdr` 调用，`:275-278` 必须是 `bit_read_RS/RL`；
`workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h` 里必须有 `char name[64]` 与 `SECTION_LAYER = 2`；并断言 2×128 = 256、下一块 size 字段在 U+264、`address` 的 8 字节 store 覆盖它。
## 10. 系统性问题（本轮实测发现，与本例定级无关但必须记）

本草案写完后，S19 的 report 阶段（他方 run，19:15）把 `severity.json` 合并进了 `case.json`：
`severity.state=assessed`、`acceptance.high_severity_confirmed=true`，而 `causal_chain_verified` 仍是 false。
原因在 `agent/stages/report.py::_validate_severity`：它只要求 `reviewed_by`/`reviewed_at` **非空**，
`reviewed_by="agent"` 也算签名 → 于是 agent 草案被当作已评估，`high` 计数超过了 `chain` 计数。

后果：`tests/test_platform.py::test_funnel_is_monotonic` 现在失败（`assert 8 <= 7`），
差的那 1 例就是本用例（S14/S15/S16/S7 已在此前处于同样状态，共 5 例 high-without-chain）。

建议（不在本任务可改范围）：把 `reviewed_by` 里的 `agent`/`agent-draft` 视为**未签**，或要求 `high_severity_confirmed` 以 `causal_chain_verified` 为前置。
