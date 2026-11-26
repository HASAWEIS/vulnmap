# 因果链证据：CG-29（libarchive rar5，arvo:11011，CWE-122）

> 只补证据、不改成绩：workspace/S14-CG29-arvo-11011/artifacts/report/case.json 与 experiments/LEDGER.json 一律不动；
> 本节不新增构造器、不改 agent 代码。行号引用可用 tests/test_materials.py 复算
> （文件存在 + 行号不越界 + 该行非空）。
>
> confirmed = 源码行 + ASAN 帧／分配大小双向对上，可复算；inferred = 无直接观测。
> **inferred 不得写成 confirmed。**

## 产物事实

- PoC：workspace/S14-CG29-arvo-11011/artifacts/verify/rar5-dir-0.bin（642 字节）。
- ASAN（workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-vul.log）：
  :18 ERROR heap-buffer-overflow；:19 WRITE of size 1；:21 #0 do_uncompress_block archive_read_support_format_rar5.c:2424:55；
  :34 0 bytes to the right of 1-byte region；:37 分配帧 #1 init_unpack :1834:30。
- fix 侧同一 PoC exit=0、无 ASAN（workspace/S14-CG29-arvo-11011/logs/V4.rar5-dir-0.11011-fix.log）。
- description.txt：「mask is not set to 0 for directories, which can lead to buffer overflows due to incorrect truncation of the window.」

## 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 RAR5 文件头 → is_dir 标志 → 窗口大小置 0 | workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1363 | confirmed | 该行 window_size = is_dir ? 0 : g_unpack_window_size << …（语句跨 :1363-1365），is_dir 来自同一文件头解析 |
| 2 | 窗口大小 0 → mask = window_size - 1 变成 SIZE_MAX（转 int 为 -1，等于不做掩码） | workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1826 | confirmed | 该行 window_mask = window_size - 1；同一函数 init_unpack 里没有任何 window_size == 0 的特判 |
| 3 | mask 与缓冲：window_buf = calloc(1, window_size) → calloc(1, 0) 返回 1 字节区域 | workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:1834 | confirmed | ASAN 分配帧 #1 指到 :1834:30（log:37），区域大小 1 字节与 calloc(1,0) 一致 |
| 4 | 解压字面量：write_idx = solid_offset + write_ptr++，索引按 cmask 截断 | workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:2422 | confirmed | 自增语句 :2422；cmask 取自 :2374（const int cmask = window_mask）；截断写法在 :2424 |
| 5 | sink：window_buf[write_idx & cmask] = (uint8_t) num → 第二个字面量写下标 1，越界 1 字节 | workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c:2424 | confirmed | ASAN #0 :2424:55、WRITE of size 1（log:19）、地址 0x…051 即 1 字节区域右端（log:34） |

## inferred

| # | 待证事项 | 说明 |
|---|---|---|
| I1 | 「持续越界写直到不可写页」的完整可利用量级 | ASAN 在首字节即 abort，实际能写多远需要有界运行（非 ASAN 构建）；根因（mask 未置 0）与首字节越界本身是 confirmed |

## 与 case.json 的关系

sink 仍取 workspace/S14-CG29-arvo-11011/artifacts/report/case.json 中
libarchive/libarchive/archive_read_support_format_rar5.c:2424（symbol do_uncompress_block）。本条链只解释该行为什么是写点。

## 复核方式

    python3 -m pytest tests/test_materials.py -q
