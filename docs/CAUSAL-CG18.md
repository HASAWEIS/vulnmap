# 因果链证据：CG-18（libidn2，arvo:12420，CWE-122）

> 用途：为 CG-18 补「输入 UCS-4 文本 → 逐 label 校验 → 输出长度 → 写偏移」的数据流证据。
> 本文件**只补证据，不改成绩**：workspace/S7-CG18-arvo-12420 与 experiments/s7c/case.json
> 的判定字段、以及 experiments/LEDGER.json 一律不动。
>
> 路径约定：workspace/…:行号 相对仓库根，行号取自本仓源码树实际内容，
> 由 tests/test_causal_cg18.py 复算（文件存在 + 行号不越界 + 该行非空）。

## 判定口径

| 标记 | 含义 |
|---|---|
| confirmed | 源码行 + ASAN 帧 + 实测数据（PoC 解析／分配大小）三方对上，可复算 |
| inferred | 机制上唯一合理但无直接观测（典型：真实 deployment 调用点） |

**硬规则：inferred 不得写成 confirmed。**

## 产物事实

- PoC：workspace/S7-CG18-arvo-12420/artifacts/verify/libidn2-4i-65.bin，260 字节。
  按 fuzzer 的读法解释为 UCS-4（小端 uint32）：**65 个码点 = 32×U+0061('a') + U+002E('.') + 32×U+0062('b')**，
  即两个各 32 字符的纯 ASCII label（本次实测解析，非推断）。
- description.txt：「A vulnerability exists in the idn2_to_ascii_4i() function where the output length
  is not restricted to 63 characters.」
- ASAN（workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log）：

| 行 | 内容 |
|---|---|
| :12 | ERROR: AddressSanitizer: heap-buffer-overflow |
| :13 | WRITE of size 66 at 0x606000000060 |
| :15 | #0 __interceptor_strcpy … asan_interceptors.cc:433 |
| :16 | #1 idn2_to_ascii_4i … lib/lookup.c:621:2 |
| :17 | #2 LLVMFuzzerTestOneInput … fuzz/libidn2_to_ascii_8z_fuzzer.c:73:4 |
| :26 | 0x…060 is located 0 bytes to the right of 64-byte region |
| :29 | 分配点 LLVMFuzzerTestOneInput … fuzz/libidn2_to_ascii_8z_fuzzer.c:67:25 |

## 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入字节 → UCS-4 实参：fuzzer 把 PoC 当 uint32 数组传，inlen = 260/4 = 65；同时按「够 63+1」的契约只分配 64 字节输出缓冲 | workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c:67 | confirmed | 该行 char *out2 = (char *) malloc(64)；调用点在 workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c:73（实参 size / 4）；ASAN 分配帧 log:29 与调用帧 log:17 分别指向这两行 |
| 2 | UCS-4 → UTF-8：u32_to_u8 把 65 个码点转成 65 字节 UTF-8（全 ASCII，1:1），得到 input_u8 | workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:602 | confirmed | 函数体自 workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:581 起；转换调用 :602，长度变量 length 在 :585 声明 |
| 3 | 逐 label 转 ASCII：idn2_lookup_u8 对每个 label 校验「单 label ≤ 63」与「累计域名 ≤ 255」——32/32/65 全部通过，于是输出 65 字符（纯 ASCII 输入按 ToASCII 保持不变） | workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:452 | confirmed | 单 label 校验 workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:83（srclen > IDN2_LABEL_MAX_LENGTH）；总长校验 :452-454；常量 workspace/S7-CG18-arvo-12420/src/libidn2/lib/idn2.h.in:137（63）与 :148（255）；调用点 :611 |
| 4 | 长度契约缺失：函数按注释假定「caller 只需 63+NUL = 64 字节」，对多 label 结果没有任何 strlen(output_u8) < 64 之类的检查 | workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:616 | confirmed | 注释原文 :616-618（room for at least 63 characters plus the terminating zero）；:614 判 rc == IDN2_OK 后直接进入拷贝，:620 只判 output 非空，中段无任何长度上限 |
| 5 | 写偏移越界：strcpy 把 66 字节（65 字符 + NUL）写进 64 字节缓冲，越界 2 字节，首个越界字节落在区域右端 | workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:621 | confirmed | ASAN 帧 #1 :621:2（log:16）、WRITE of size 66（log:13）、64 字节区域（log:26）；65+1 = 66 > 64 的算术与 PoC 的 65 码点一致（log:17 调用点与 fuzzer.c:73 对上） |

## inferred（明确标出，不当结论用）

| # | 待证事项 | 为什么是 inferred | 翻案条件 |
|---|---|---|---|
| I1 | **真实 deployment 调用点**：哪些实际程序以 64 字节缓冲调用 idn2_to_ascii_4i，并按注释理解成「63+NUL 够用」 | 本仓只观测到 fuzzer harness 一处调用；系统内其他调用者（命令行工具、下游库使用者）未审计 | 扫目标发行版对 idn2_to_ascii_4i 的调用点，确认其缓冲分配方式，可转 confirmed 或证伪 |
| I2 | 触发阈值是否恰为 65 字符（65 = 32+1+32；64 字符域名同样越界 1 字节） | 本次只用 260 字节 PoC 实测，未穷举变体 | 用 64 字符输入复跑 docker，观察是否同样 ASAN abort，即可确认阈值 |

I1 是唯一影响「可利用性叙事」的缺口：**API 契约被违反本身是 confirmed，缺的是谁在真实环境按这份契约分配缓冲。**

## 与 case.json 的关系

sink 仍取 verify 记录的 experiments/s7c/case.json 中 libidn2/lib/lookup.c:621（symbol strcpy）。
本条链不替换该行号，只说明它为什么是写点：越界由 64 字节调用方缓冲 + 65 字符输出共同决定，
而 lookup.c 在 :620-621 未做任何长度校验。

## 复核方式

    python3 -m pytest tests/test_causal_cg18.py -q

测试解析本文件的 workspace/…:行号 引用，逐个校验文件存在、行号不越界、该行非空，
并检查至少 3 步、状态只取 confirmed / inferred。
