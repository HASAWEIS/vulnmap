# CG-29 / arvo:11011（libarchive rar5，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S14-CG29-arvo-11011/severity.json`；结构校验：`tests/test_severity_11011.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H = 7.1  (high)
```

**I:H 成立，但不是因为"内容可控"四个字**：本例同时具备 (a) 内容可控（Huffman literal，0x00–0xff）与 (b) 位置无界（mask 在目录场景下退化成 -1，循环内没有上界检查）。
实测只到首字节，是 ASAN 停下的位置，不是溢出的边界。

## 1. 实测到什么（不要夸大）

| 事实 | 证据 |
| --- | --- |
| 目标缓冲只有 **1 字节**（目录 window_size=0 → `calloc(1,0)`） | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:34`（`0 bytes to the right of 1-byte region`）、`:36-37`（`calloc ← init_unpack`） |
| 越界写 **1 字节**，ASAN 立即 abort | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:19`（`WRITE of size 1`）、`:20`（SCARINESS 31）、`:2`（exit=1） |
| fix 侧同输入干净退出 | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-fix.log:2`（exit=0）、`:5`（Execution successful） |

单看这三条，只能说"1 字节越界"。要判 I:H，必须再证明"后面还能写、且内容可控"——见下一节。

## 2. 为什么 1 字节实测仍然支撑 I:H（结构性证据）

写入语句（`do_uncompress_block`）：

```c
// workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:2421-2424
int64_t write_idx = rar->cstate.solid_offset + rar->cstate.write_ptr++;
rar->cstate.window_buf[write_idx & cmask] = (uint8_t) num;   // num = Huffman literal
```

三步推出"位置无界"：

1. `cmask` 来自 `window_mask`（`workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:2374`：`const int cmask = rar->cstate.window_mask;`）；
2. `window_mask = window_size - 1`（`workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1826`），而**目录项的 `window_size` 就是 0**（`workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1363-1365`：`is_dir ? 0 : g_unpack_window_size << ...`）→ `window_mask = SIZE_MAX`；
3. `SIZE_MAX` 存进 `int cmask` 变成 **-1**，`write_idx & -1 == write_idx` → **掩码完全失效**，索引随每个 literal 线性递增（0,1,2,3,…），而缓冲只有 1 字节。

再加上内容：`(uint8_t) num` 是解压流里的 literal，攻击者编码什么就写什么（0x00–0xff）。
→ 这不是"某一次越界 1 字节"，而是"**从第 2 个 literal 起，每写一次就往堆上多写 1 字节受控数据，且没有终点**"。
ASAN 在 `write_idx=1` 处就停（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:19`），所以日志里只有 1 字节；换成非 ASAN 构建就会继续往后覆盖相邻堆对象。

**上游补丁正好印证根因**：`workspace/S14-CG29-arvo-11011/patch.diff:9-13` 把 `window_size==0` 时的 `window_mask` 显式置 0 —— 也就是承认"目录场景下 mask 没被置 0"是缺陷本身。

## 3. 与其它"1 字节"案例的区别（为什么它们不能给 H）

| 案例 | 越界量 | 是否可控 | 结论 |
| --- | --- | --- | --- |
| CG-25（OpenThread lexer） | 结构性 ≤2 字节（`VerifyOrExit(dst+2<=endp)` 卡死） | 内容部分可控 | `I:L` |
| CG-27（TGA） | 实测 1 字节（4.29e9 中 4294836225 在区内） | 内容恒 0 | `I:L` |
| **CG-29（本例）** | **无界（mask 失效 + 无上界检查）** | **Huffman literal 全可控** | **`I:H`** |

判断标准不是"写了几字节"，而是"**能不能继续写、写什么由谁定**"。

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | rar5 档案解析入口（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:1`、`:4`、`:21-27`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 642 字节固定档案一次命中，vul exit=1 / fix exit=0（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:2`、`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-fix.log:2`） |
| PR | **N** | 解压不需要额外权限（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把档案交给解压器（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:4`）；自动批处理无证据 → 保守 R |
| S | **U** | 影响在解压进程内 |
| C | **N** | 只写不读，无回显 |
| I | **H** | 受控内容 + 无界位置（§2）；可覆盖相邻堆对象的任意字节 |
| A | **H** | 无界写最终会触及不可写页或破坏堆元数据；ASAN 下已 exit=1（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:2`） |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:1`、`:4`、`:21-27` |
| privileges_required | none | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:1-2` |
| user_interaction | required | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:4`、`:21-27` |
| observed_impact | heap_buffer_overwrite_controlled | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:19-21`、`:34`、`:36-37`；源码 `workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1363-1365`、`:1826`、`:2374`、`:2421-2424`；补丁 `workspace/S14-CG29-arvo-11011/patch.diff:9-13` |
| reachability_evidence | confirmed | `workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:21-27`（`do_uncompress_block ← process_block ← do_uncompress_file ← uncompress_file ← rar5_read_data ← archive_read_data ← LLVMFuzzerTestOneInput`）、`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-fix.log:2,5` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log:2`、`workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-fix.log:2`）；生产消费者与进程形态无证据 |

## 6. 缺证据清单

1. **放大实测**：同一档案里放更多 literal/压缩块，把越界距离从 1 字节推到几十字节——这一步能把 I:H 从"源码可证"变成"实测可证"；本轮没做（ASAN 在首字节停）。
2. **非 ASAN 崩溃点**：普通构建下越界写到哪一页崩、破坏哪些堆对象，未实测。
3. **利用可行性**：没有做堆布局/后续读写配合的利用实验（`artifacts/exploit` 为 skipped）。
4. **生产消费者**：谁解不可信 rar5（文件管理器/归档工具/服务端），决定 UI 与 A 的现实含义。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `I:L`（要求实测到多字节越界才给 H） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `A:L`（ASAN abort 不外推） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| `I:N`（只算可用性） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | 5.5 |
| `UI:N`（自动批量解包） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | 7.7 |
| `AC:H`（依赖窗口布局） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H` | 6.3 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 8.1 |

## 8. 反方意见

- **「只有 1 字节实测，凭什么 H（应 6.1）」**：合理保留意见。回应见 §2：内容是 literal、位置由失效的 mask 决定、循环无上界——三项都是可在源码里复核的事实；1 字节只是 ASAN 的停车点。若评审坚持"实测优先"，接受 6.1 并把它记作待补放大 PoC 的缺口。
- **「只会崩，不谈完整性（5.5）」**：回应：崩溃前每个字节都落在相邻堆对象上且内容可控，"崩不崩"取决于布局，不能反推"没有完整性影响"。

## 9. 校验

```
python3 -m pytest tests/test_severity_11011.py -q
```

除常规（引用行存在、分数复算、禁 AV:N）外，本题的测试还会**直接读源码与补丁**验证 I:H 的结构性依据：
`workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1826` 必须是 `window_mask = window_size - 1`，`workspace/S14-CG29-arvo-11011/patch.diff:13` 必须是 `window_mask = 0`——任何人想在没有这些证据时抬到 H 都会失败。
