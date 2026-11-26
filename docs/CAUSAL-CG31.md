# 因果链证据：CG-31（exiv2，arvo:61675，CWE-122）

> 只补证据、不改成绩：workspace/S16-CG31-arvo-61675/artifacts/report/case.json 与 experiments/LEDGER.json 一律不动；
> 本节不新增构造器、不改 agent 代码。行号引用可用 tests/test_materials.py 复算
> （文件存在 + 行号不越界 + 该行非空）。
>
> confirmed = 源码行 + ASAN 帧／分配大小双向对上，可复算；inferred = 无直接观测。
> **inferred 不得写成 confirmed。**

## 产物事实

- PoC：workspace/S16-CG31-arvo-61675/artifacts/verify/bmff-brob-98339.bin（98339 字节）。
- ASAN（workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log）：
  :9 ERROR container-overflow；:10 WRITE of size 201672；:15 #3 brotliUncompress bmffimage.cpp:208:9；
  :16 #4 boxHandler :541:7；:24 区域 196606 字节；:29 分配帧 #7 brotliUncompress :204:9。
- fix 侧同一 PoC exit=0、无 ASAN（V4.bmff-brob-98339.61675-fix.log）。
- description.txt：「An integer overflow occurs in the calculation of available_out.」

## 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 BMFF box（TAG_brob）→ boxHandler 取 box 数据调 brotliUncompress | workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:541 | confirmed | ASAN #4 :541:7；TAG_brob 分支 :533 起，:534 enforce 数据 ≥4 字节，:541 把 data.c_data(4)、data.size()-4 传下去 |
| 2 | 初始输出容量 = 压缩长度 × 2 = 98303 × 2 = 196606，按此 alloc | workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:194 | confirmed | :194 uncompressedLen = compressedBufSize * 2；:204 arr.alloc(uncompressedLen) 即 ASAN 分配帧（log:29，196606 字节区域 log:24） |
| 3 | 首轮输出填满 → NEEDS_MORE_OUTPUT → 容量翻倍，但 DoS 上限把它压回 131072 | workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:212 | confirmed | :212 uncompressedLen *= 2；:214 上限判定；:215-216 dos 计数只允许一次；:217 uncompressedLen = 131072（此时 131072 < 已产出 196606） |
| 4 | 长度计算下溢：available_out = uncompressedLen - total_out = 131072 - 196606 → SIZE_MAX 级巨大值 | workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:205 | confirmed | :205 为无符号减法且不校验 total_out < uncompressedLen；下溢即 description 所称 integer overflow |
| 5 | sink：以该 available_out 调 BrotliDecoderDecompressStream，libbrotlidec 内 memcpy 写 201672 字节进 196606 容量 | workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:208 | confirmed | ASAN #3 :208:9、WRITE of size 201672（log:10）、区域 196606（log:24）；写量与 available_out 下溢后的「可用空间」一致 |

## inferred

| # | 待证事项 | 说明 |
|---|---|---|
| I1 | 第二轮调用时 total_out 的确切值（本链按 196606 反推） | ASAN 未打印 total_out；196606 由区域大小 + 首轮填满推得。翻案方式：在 bmffimage.cpp:205 加打印或 gdb 断点观察 total_out |
| I2 | 为什么 arr.alloc(131072) 之后仍是 196606 字节区域 | DataBuf::alloc 走 vector resize，缩容通常保留容量（workspace/S16-CG31-arvo-61675/src/exiv2/src/types.cpp:96）；这一点未单独验证，但它不影响第 4-5 步的下溢与越界 |

## 与 case.json 的关系

sink 仍取 workspace/S16-CG31-arvo-61675/artifacts/report/case.json 中 bmffimage.cpp:208
（source = verify 崩溃日志文本命中；该 case 无 symbol 字段，属文本命中，非栈帧符号）。

## 复核方式

    python3 -m pytest tests/test_materials.py -q
