# 因果链证据：CG-10D（libredwg）/ CG-12D（harfbuzz）

> 用途：为 CG-10D 与 CG-12D 补「输入字段 → 长度 → 写偏移 → sink」的数据流证据。
> 本文件**只补证据，不改成绩**：workspace/S5G-CG10、workspace/S5H-CG12 的 case.json
> 与 experiments/LEDGER.json 一律不动（sink 仍按原记录，见每节「与 case.json 的关系」）。
>
> 路径约定：所有 **workspace/…:行号** 都相对于仓库根；行号取自下列两份源码树的实际内容，
> 可用 tests/test_causal_evidence.py 复算（文件存在 + 行号不越界 + 该行非空）。

## 判定口径

| 标记 | 含义 |
|---|---|
| confirmed | 源码行 + ASAN 帧／分配大小双向对上，可直接复算 |
| inferred | 机制上唯一合理，但**没有**直接观测（ASAN 只到函数级，或需 gdb/dump 才能定死） |

**硬规则：inferred 不得写成 confirmed。** 每节末尾列 inferred 清单与翻案条件。

---

## 案例 A：CG-10D（libredwg，arvo:54625，CWE-122）

**产物事实**：PoC = workspace/S5G-CG10/artifacts/verify/dwg-ver5.bin（3806 字节）；
vul 侧 docker run exit=1、fix 侧 exit=0（workspace/S5G-CG10/logs/V4.dwg-ver5.54625-fix.log）。
description.txt：「A vulnerability exists in the decode_r11 function where entities_end can overflow.」

**ASAN 关键帧**（workspace/S5G-CG10/logs/V4.dwg-ver5.54625-vul.log）：

| 行 | 内容 |
|---|---|
| :13 | ERROR: AddressSanitizer: heap-buffer-overflow … WRITE of size 1 |
| :14 | WRITE of size 1 at 0x6120000014d5 |
| :16 | #0 json_cquote /src/libredwg/src/out_json.c |
| :17 | #1 json_preR13_header_write_private … header_variables_r11.spec:145:3 |
| :29 | 0x6120000014d5 is located 0 bytes to the right of 277-byte region |
| :32 | 分配点同为 header_variables_r11.spec:145:3 |

277 = 6×46+1 → 缓冲区大小由**规格里的字段长度 46** 决定，不是由运行时 strlen 决定。

### 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 DWG 头 → 进入 preR13 header 私有段（前提 numheader_vars > 74） | workspace/S5G-CG10/src/libredwg/src/header_variables_r11.spec:137 | confirmed | 该行 if (dwg->header.numheader_vars <= 74) return 0; 是进入后续字段的唯一门槛；崩溃发生在该函数内即说明门槛已过 |
| 2 | 定长文本字段读入 struct：FIELD_TFF(unknown_46, 46, 0) 读侧调 bit_read_fixed，**只 memcpy 46 字节、不补 NUL** | workspace/S5G-CG10/src/libredwg/src/header_variables_r11.spec:145 | confirmed | 宏定义 workspace/S5G-CG10/src/libredwg/src/dec_macros.h:508；拷贝点 workspace/S5G-CG10/src/libredwg/src/bits.c:1459（memcpy (dest, &dat->chain[dat->byte], length)）；函数入口 workspace/S5G-CG10/src/libredwg/src/bits.c:1446 |
| 3 | struct 字段 → 长度：写 JSON 时 FIELD_TFv 用**规格长度**算缓冲 _l1 = 6*len+1（len=46 → 277）并 malloc(277) | workspace/S5G-CG10/src/libredwg/src/out_json.c:284 | confirmed | 宏体 workspace/S5G-CG10/src/libredwg/src/out_json.c:282；malloc 在 workspace/S5G-CG10/src/libredwg/src/out_json.c:301；与 ASAN 报告的 277 字节区域（log:29）逐字对上 |
| 4 | 长度 → 写偏移：以 277 为上界调用 json_cquote，endp = dest + len，逐字节写 | workspace/S5G-CG10/src/libredwg/src/out_json.c:1327 | confirmed | 调用点 workspace/S5G-CG10/src/libredwg/src/out_json.c:302；函数入口 workspace/S5G-CG10/src/libredwg/src/out_json.c:1323 |
| 5 | sink：终止符写到 endp 上 → 1 字节越界（堆右红区） | workspace/S5G-CG10/src/libredwg/src/out_json.c:1380 | inferred | ASAN 只到函数级（log:16 无行号）；两个同构候选点是 workspace/S5G-CG10/src/libredwg/src/out_json.c:1335（循环内 dest >= endp 分支）与 :1380（循环后收尾），二者都缺 dest < endp 检查 |

### 为什么「字段」能撑爆 277 字节（仍属 inferred）

FIELD_TFF 读 46 字节且不写 NUL，因此 unknown_46 作为 C 字符串会一路读到相邻 struct 字节里的第一个 0；
转义展开（控制字符 6 字节/个）把 dest 推到 endp，再写终止符即越界 1 字节。
**inferred**：PoC 中该字段的实际取值与 strlen 真值（是否恰为 46 或更长）需要在
workspace/S5G-CG10/src/libredwg/src/out_json.c:302 下断点 dump _buf 与 strlen 才能定死。
翻案条件：若 dump 显示 strlen 恰为 46 且转义输出 ≤ 276 字节，则越界来自别的分支，本步须改写。

### 与 case.json 的关系

sink 仍取 verify 记录的 workspace/S5G-CG10/artifacts/report/case.json 中
src/header_variables_r11.spec:145（symbol json_cquote）。本条链不替换它，只说明**为什么**这个行号是 sink：
它是宏展开点 + malloc 点，真正的写指针在 out_json.c 内。

---

## 案例 B：CG-12D（harfbuzz，arvo:11081，CWE-122）

**产物事实**：PoC = workspace/S5H-CG12/artifacts/verify/harfbuzz-gsub-script.bin（868 字节）；
vul 侧 exit=1、fix 侧 exit=0（workspace/S5H-CG12/logs/V4.harfbuzz-gsub-script.11081-fix.log）。
description.txt：「A vulnerability exists in the size calculation within the DEFINE_SIZE_ARRAY_SIZED macro.」

**ASAN 关键帧**（workspace/S5H-CG12/logs/V4.harfbuzz-gsub-script.11081-vul.log）：

| 行 | 内容 |
|---|---|
| :18 | ERROR: AddressSanitizer: heap-buffer-overflow |
| :19 | WRITE of size 1 at 0x61a0000005c9 |
| :21 | #0 BEInt<unsigned short, 2>::set … hb-machinery.hh:650:10 |
| :22 | #1 OT::Script::subset … hb-ot-layout-common.hh:289:37 |
| :27 | #6 _subset2<OT::GSUB const> … hb-subset.cc:82:21 |
| :38 | 0x61a0000005c9 is located 0 bytes to the right of 1353-byte region |
| :42 | 分配点 hb-subset.cc:74:9（hb_vector_t<char,8>::alloc） |

### 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 868 字节字体 → 取 GSUB 表 → 估算并分配 1353 字节输出缓冲 → 进入表级 subset | workspace/S5H-CG12/src/harfbuzz/src/hb-subset.cc:74 | confirmed | ASAN 分配帧 log:42 指向该行；调用点 workspace/S5H-CG12/src/harfbuzz/src/hb-subset.cc:82（log:27） |
| 2 | 表级分发：scriptList 偏移交给 OffsetTo<RecordListOf<Script>>::serialize_subset | workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-gsubgpos.hh:2597 | confirmed | ASAN 帧 #5 指向该行 |
| 3 | 结构字段 → 计数：按输入 ScriptList 的条数逐条处理，取第 i 条的 offset | workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:147 | confirmed | ASAN 帧 #3；遍历体 out->get_offset (i).serialize_subset (c, (*this)[i], out); |
| 4 | 计数 → 长度：Script::subset 先 embed（表长按 get_size 预留），再按 langSys.len 循环写每条 offset | workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:289 | confirmed | ASAN 帧 #1（:289:37）；embed 在 workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:284，计数取值在 :287 |
| 5 | 写偏移 → sink：OffsetTo::serialize 落到 BEInt<u16,2>::set，先写 v[0]（最后 1 个合法字节）再写 v[1] —— v[1] 即越界的那 1 字节 | workspace/S5H-CG12/src/harfbuzz/src/hb-machinery.hh:650 | confirmed | ASAN 帧 #0 精确到 :650:10（写的是 v[1]）；同行 v[0] 在 workspace/S5H-CG12/src/harfbuzz/src/hb-machinery.hh:649；serialize_subset 定义在 workspace/S5H-CG12/src/harfbuzz/src/hb-open-type.hh:251，:259 是它内部的 src.subset(c) 调用点（ASAN 帧 #2 即此处）；地址 0x…5c9 = 1353 区域右端（log:38） |

### 长度为什么被低估（description 指的 DEFINE_SIZE_ARRAY_SIZED）

- 宏定义：workspace/S5H-CG12/src/harfbuzz/src/hb-machinery.hh:119（= DEFINE_SIZE_ARRAY + get_size() = size - array[0].min_size + array.get_size()，见 :121）
- Script 用它声明：workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:308（DEFINE_SIZE_ARRAY_SIZED (4, langSys)）
- 数组元素 Record<LangSys> 的 min_size = 6（tag 4 + offset 2）：workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:96
- 于是 get_size() = 4 - 6 + (2 + 6·L) = 6·L，而 Script 表真实占 4 + 6·L → **每个 Script 少预留 4 字节**；
  多个 Script 累计后，:289 的 offset 写便落到 1353 字节缓冲之外。该算式三项均可复算，记 confirmed。

**inferred**：越界的**具体是第几个 Script / 第几条 langSys 记录**，以及该表的 L 值。
ASAN 只报最终写地址，不含表索引。翻案条件：在 workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh:289
断点打印 i、langSys.len、serializer 的 head/tail，或解析 PoC 的 GSUB 表逐表核对。

### 与 case.json 的关系

sink 仍取 verify 文本命中的 workspace/S5H-CG12/artifacts/report/case.json 中
hb-ot-layout-common.hh:289（source = verify.root_cause.evidence.text_hit）。
该 case 同时保留 overrode_claim_sink = harfbuzz/src/dump-emoji.cc:210（模型指认、非崩溃点）；
本条链证明 :289 才是写点，**不回写、不覆盖** case.json 字段。

---

## 汇总

| 案例 | 步骤数 | confirmed | inferred | 主要缺口 |
|---|---|---|---|---|
| CG-10D | 5 | 4 | 1（第 5 步的终止符行号）+ 字段取值待 dump | 终止符写到 :1335 还是 :1380；字段 strlen |
| CG-12D | 5 | 5 | 0（链本身）+ 1 条定位信息待补 | 越界的 Script/langSys 索引与 L 值 |

两例的「输入 → 长度 → 写偏移」骨架都由 **源码行 + ASAN 帧 + 缓冲区长度算术** 双向对上；
剩余 inferred 只涉及「具体是哪一个数据下标」，不影响根因判定，也不影响 sink 位置。

## 复核方式

    python3 -m pytest tests/test_causal_evidence.py -q

测试解析本文件的 workspace/…:行号 引用，逐个校验文件存在、行号不越界、该行非空，
并检查两案例各 3-5 步、状态只取 confirmed / inferred。
