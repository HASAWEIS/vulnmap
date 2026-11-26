# 因果链证据：CG-36（libredwg，arvo:54839，CWE-122）

> 只补证据、不改成绩：workspace/S19-CG36-arvo-54839/artifacts/report/case.json 与 experiments/LEDGER.json 一律不动；
> 本节不新增构造器、不改 agent 代码。行号引用可用 tests/test_materials.py 复算
> （文件存在 + 行号不越界 + 该行非空）。
>
> confirmed = 源码行 + ASAN 帧／分配大小双向对上，可复算；inferred = 无直接观测。
> **inferred 不得写成 confirmed。**

## 产物事实

- PoC：workspace/S19-CG36-arvo-54839/artifacts/verify/dwg-prer13-ns0.bin（606 字节）。
- ASAN（workspace/S19-CG36-arvo-54839/logs/V4.dwg-prer13-ns0.54839-vul.log）：
  :13 ERROR heap-buffer-overflow；:14 WRITE of size 4；:16 #0 decode_preR13_section_hdr decode.c:275:13；
  :17 #1 decode_preR13 decode.c:766:12；:28 4 bytes to the right of 256-byte region；
  :31 分配帧 #1 decode_preR13 decode.c:729:40。
- fix 侧同一 PoC exit=0（V4.dwg-prer13-ns0.54839-fix.log）；同工作区另有 dwg-tfv-{0,1,2} 三条探索日志。
- description.txt：「A security vulnerability exists in the decode_r11 function where dwg_get_first_object fails when handling TABLE_CONTROL.」（描述指向另一路径，本链按崩溃点画像，见 inferred I1）

## 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 DWG 头 → 读 num_sections（RS 读入、按 RL 存） | workspace/S19-CG36-arvo-54839/src/libredwg/src/header.spec:47 | confirmed | 该行 FIELD_CAST (num_sections, RS, RL, 0); // 5；header.spec 由 decode.c:724 的 #include 展开进 decode_preR13 |
| 2 | 按 num_sections 分配 section 数组：calloc(sizeof(Dwg_Section), num_sections + 2) | workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:729 | confirmed | ASAN 分配帧 #1 :729:40；num_sections=0 时 2 项；区域 256 字节 = sizeof(Dwg_Section) 128 × 2（log:28） |
| 3 | 无条件解析 5 张表：id 用固定枚举（BLOCK=1、LAYER=2、STYLE=3、LTYPE=5、VIEW=6），与 num_sections 无关 | workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:765 | confirmed | 调用块 :765-769；枚举 workspace/S19-CG36-arvo-54839/src/libredwg/include/dwg.h:8578 |
| 4 | tbl = &dwg->header.section[id]：LAYER 的 id=2 已越过只有 2 项（下标 0..1）的数组 | workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:274 | confirmed | ASAN #1 调用点 :766 = LAYER 那一行（log:17）；枚举 LAYER=2（dwg.h:8580） |
| 5 | sink：第一个字段写 tbl->size（4 字节）落在 section[2]+4 = 偏移 260，越界 4 字节 | workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c:275 | confirmed | ASAN #0 :275:13、WRITE of size 4（log:14）、地址 = 区域右端 +4（log:28）；四个字段里 size 在结构体偏移 4，故首个越界写正是它 |

## inferred

| # | 待证事项 | 说明 |
|---|---|---|
| I1 | description 与崩溃点的关系（描述提到 decode_r11 / dwg_get_first_object / TABLE_CONTROL，本链是 preR13 section header 路径） | 二者都位于 preR13 解码，但描述措辞与实测栈帧不同源。翻案方式：以 fix 侧 patch.diff 命中的函数为准对齐描述，或向上游确认该 CVE 报告口径 |
| I2 | num_sections 在 PoC 中的确切字节值（本链按 256=128×2 反推为 0） | 未 dump DWG 头；分配大小与计算式一致即为强证据。翻案方式：读 PoC 头偏移处 num_sections 字节 |

## 与 case.json 的关系

sink 仍取 workspace/S19-CG36-arvo-54839/artifacts/report/case.json 中 src/decode.c:275（symbol bit_read_RL）。
注意：以本仓源码核对，:275 是 tbl->size 赋值语句（表达式内含 bit_read_RS 读值），
ASAN 的 size=4 来自「RL 字段存 4 字节」；不修改 case.json 的 symbol 字段，只在此处说明口径。

## 复核方式

    python3 -m pytest tests/test_materials.py -q
