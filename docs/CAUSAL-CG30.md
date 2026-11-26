# 因果链证据：CG-30（fio，arvo:29633，CWE-121）

> 只补证据、不改成绩：workspace/S15-CG30-arvo-29633/artifacts/report/case.json 与 experiments/LEDGER.json 一律不动；
> 本节不新增构造器、不改 agent 代码。行号引用可用 tests/test_materials.py 复算
> （文件存在 + 行号不越界 + 该行非空）。
>
> confirmed = 源码行 + ASAN 帧／分配大小双向对上，可复算；inferred = 无直接观测。
> **inferred 不得写成 confirmed。**

## 产物事实

- PoC：workspace/S15-CG30-arvo-29633/artifacts/verify/fio-maxpath-0.bin（6019 字节）。
- ASAN（workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log）：
  :18 ERROR stack-buffer-overflow；:19 WRITE of size 6001；:23 #2 add_file filesetup.c:1656:2；
  :24 #3 str_filename_cb options.c:1320:3；:38 栈帧说明；:39 帧 #0 add_file filesetup.c:1644。
- fix 侧同一 PoC exit=0、无 ASAN（V4.fio-maxpath-0.29633-fix.log）。
- description.txt：「A buffer overrun occurs in the handling of the filename option due to exceeding the size of a MAX_PATH buffer … stack-buffer-overflow in the add_file function in filesetup.c at line 1656, which is called from str_filename_cb in options.c at line 1320.」

## 传播链（5 步）

| # | 环节 | 代码位置 | 状态 | 依据 |
|---|---|---|---|---|
| 1 | 输入 ini 文本 → 解析入口 | workspace/S15-CG30-arvo-29633/src/fio/init.c:2076 | confirmed | ASAN #8 :2076:9（__parse_jobs_ini）；上层 parse_jobs_ini :2127（#9） |
| 2 | option 键值 → 分派到 handler → 具体回调 | workspace/S15-CG30-arvo-29633/src/fio/options.c:5199 | confirmed | ASAN #7 :5199:16（fio_options_parse）→ #6 parse.c:1184 → #5 parse.c:1014 → #4 parse.c:792 |
| 3 | filename= 的值整段取出、不截断 | workspace/S15-CG30-arvo-29633/src/fio/options.c:1306 | confirmed | 回调定义 :1301；:1306 p = str = strdup(input) 拷贝整段 option 值（长度由输入决定） |
| 4 | 目标缓冲：add_file 栈上 char file_name[PATH_MAX] | workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1646 | confirmed | 函数入口 :1643；ASAN 栈帧 #0 :1644（log:39）说明缓冲在 add_file 栈帧内；PATH_MAX 取自系统 limits.h（Linux 4096） |
| 5 | sink：sprintf(file_name + len, "%s", fname) 无长度校验 → 写 6001 字节 | workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1656 | confirmed | ASAN #2 :1656:2、WRITE of size 6001（log:19）：6019 字节 ini 里 filename 值约 6000 字符，加 NUL 即 6001，远超 4096 |

## inferred

| # | 待证事项 | 说明 |
|---|---|---|
| I1 | description 的 MAX_PATH 与代码的 PATH_MAX 是同一个契约 | 代码用 PATH_MAX（Linux 4096）；若产品侧按 Windows MAX_PATH=260 声明，实际可利用边界更小。两者都远小于 6001，不影响结论 |
| I2 | filename 值的确切字符数（6000） | 由 WRITE of size 6001 反推（含 NUL），未逐字节 dump ini；翻案方式：解析 PoC 文本取 filename= 行长度 |

## 与 case.json 的关系

sink 仍取 workspace/S15-CG30-arvo-29633/artifacts/report/case.json 中 fio/filesetup.c:1656（symbol sprintf）。

## 复核方式

    python3 -m pytest tests/test_materials.py -q
