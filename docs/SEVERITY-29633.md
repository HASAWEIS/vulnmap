# CG-30 / arvo:29633（fio job ini，CWE-121）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S15-CG30-arvo-29633/severity.json`；结构校验：`tests/test_severity_29633.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H = 7.1  (high)
```

**I:H 成立，但理由不是「6001 很大」**，而是三条都能复核的事实叠加：内容 = 攻击者给的 filename、越界量 = 1905 字节（6001−4096，日志可算）、该栈帧里**只有 `file_name` 一个对象**。
缺的那一步（返回地址覆盖/执行流改变）属**利用成熟度**，不在 CVSS base 的 I 维度里；若评审要求先看到控制流证据，就退到 I:L = 6.1。

## 1. 实测到什么

| 事实 | 证据 |
| --- | --- |
| 目标缓冲 `char file_name[PATH_MAX]` = 4096 字节 | `workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1646`；`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:43`（`[32, 4128) 'file_name'`） |
| 写入 6001 字节（`sprintf(file_name + len, "%s", fname)`，无边界检查） | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:19`（`WRITE of size 6001`）、`:20`（SCARINESS 60）；源码 `workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1656` |
| 越界 **1905 字节**（6001 − 4096），ASAN 在 offset 4128 处报 | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:38`、`:43` |
| 该帧只有 1 个对象 → 4128 之后就是保存的帧数据 | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:42-43`（`This frame has 1 object(s)`） |
| 内容就是攻击者写的字符串（本次 5991 个 'A'） | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:4`；PoC `workspace/S15-CG30-arvo-29633/artifacts/verify/fio-maxpath-0.bin` |
| ASAN 下 exit=1；fix 侧同输入 exit=0 | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:2`、`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-fix.log:2`、`:5` |

## 2. 为什么这足以支撑 I:H（而不是靠“大”）

1. **内容受控**：写出去的每个字节来自 job ini 的 `filename=` 值，攻击者想写什么就写什么（本次全是 `A`，也可以放任意字节）。
2. **长度由攻击者决定**：`sprintf(file_name + len, "%s", fname)` 没有任何上限，越界量随 filename 长度增长（本次 1905 字节，还可以更长）。
3. **落点可判定**：ASAN 说这一帧只有 `file_name` 一个对象（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:42-43`）。既然对象到 4128 结束，向上（更高地址）就是保存的 rbp/返回地址所在的帧数据区；1905 字节远超任何正常帧在局部变量与 saved rip 之间的间隙，**写出范围必然覆盖这些控制数据**。

合起来：攻击者可以用自选字节改写控制数据 → CVSS 的 I:H（『可修改数据并改变安全态势』）。
注意这不等同于『已经拿到代码执行』：那需要覆盖 RIP 并安排跳转目标（属 E/利用成熟度），本轮没有做。

## 3. 缺的那一步（明确写出来，避免含糊抬分）

| 已有 | 还没有 |
| --- | --- |
| 内容可控、越界 1905 字节、帧内对象布局清楚 | 返回地址被覆盖的**实测**（例如非 ASAN 构建下的 SIGSEGV/`core` 里 rip 指向 `0x41414141...`） |
| ASAN abort（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:2`） | 非 ASAN 构建的崩溃点、canary/FORTIFY 是否拦截 |
| 上游补丁（给 `filename` 加 `.maxlen = PATH_MAX`，`workspace/S15-CG30-arvo-29633/patch.diff:42`） | 利用实验（`artifacts/exploit` 为 skipped） |

补齐「返回地址被覆盖」的实测后，本例仍应保持 I:H/A:H（7.1）；若评审要求在补齐前保持保守，则取 I:L（6.1）。

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | job ini 解析入口（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:1`、`:4`、`:23-25`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 6019 字节固定输入一次命中，vul exit=1 / fix exit=0（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:2`、`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-fix.log:2`） |
| PR | **N** | 解析 job 文件不需要额外权限（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:1-2`） |
| UI | **R** | 需要有人/服务把 job 文件交给 fio（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:4`）；自动处理无证据 → 保守 R |
| S | **U** | 影响在 fio 进程内 |
| C | **N** | 只写不读 |
| I | **H** | §2：受控内容 + 1905 字节越界 + 帧内只有该对象 → 必然改写保存的帧数据 |
| A | **H** | 1905 字节栈破坏：开 canary 则返回时 abort，不开则控制流/崩溃；ASAN 下已 exit=1（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:2`） |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:1`、`:4`、`:23-25` |
| privileges_required | none | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:1-2` |
| user_interaction | required | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:4`、`:23-25` |
| observed_impact | stack_buffer_overwrite_controlled | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:19-23`、`:38`、`:42-43`；源码 `workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1646`、`:1656` |
| reachability_evidence | confirmed | `workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:23-30`（`add_file ← str_filename_cb ← __handle_option ← handle_option ← parse_option ← fio_options_parse ← __parse_jobs_ini ← parse_jobs_ini ← LLVMFuzzerTestOneInput`）、`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-fix.log:2,5`、补丁 `workspace/S15-CG30-arvo-29633/patch.diff:42` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:2`、`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-fix.log:2`）；生产 job 来源与构建加固无证据 |

## 6. 缺证据清单

1. **控制流实测**：非 ASAN 构建下越界到 saved rip 的崩溃/`rip` 值（这是把 I:H 从『布局必然』变成『实测已证』的关键）。
2. **构建加固状态**：canary / `-D_FORTIFY_SOURCE` 的生产取值（本镜像里 sprintf 走 `__sprintf_chk`，但因目标地址动态而没拦住，`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:21-22`）。
3. **生产 job 来源**：谁提供 job 文件、fio 是否被服务端调度。
4. **利用可行性**：无布局/地址信息，未做利用实验。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `I:L`（要求控制流实测才给 H） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `A:L`（ASAN abort 不外推） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| `A:N` | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 5.5 |
| `UI:N`（自动解析 job） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | 7.7 |
| `AC:H`（依赖帧布局） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H` | 6.3 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 8.1 |

## 8. 反方意见

- **「没有控制流证据，只能 I:L（6.1）」**：这是最有力的保留意见。回应：CVSS base 的 I 维度问的是『能不能改写数据/改变安全态势』，控制流劫持属 E 维度；本例的『必然覆盖保存帧』来自日志里的帧对象清单（`workspace/S15-CG30-arvo-29633/logs/V4.fio-maxpath-0.29633-vul.log:42-43`）与可复算的 1905 字节，不是猜测。若团队口径是「I 必须由控制流实测支撑」，就按 6.1 记，并把控制流 PoC 列为升级条件。
- **「栈写就是崩，谈不上完整性（5.5）」**：回应：崩溃发生在写入之后，写入内容由攻击者决定并落在返回地址区域，『崩在哪』正取决于这些字节。

## 9. 校验

```
python3 -m pytest tests/test_severity_29633.py -q
```

除常规（引用行存在、分数复算、禁 AV:N）外，测试还会**直接读源码/日志/补丁**验证 I:H 的依据：
`workspace/S15-CG30-arvo-29633/src/fio/filesetup.c:1646` 必须是 `char file_name[PATH_MAX];`，`:1656` 必须是 `sprintf(file_name + len, "%s", fname);`，
日志必须是 `WRITE of size 6001` + `offset 4128` + 单对象帧，补丁必须给 `filename` 加 `.maxlen = PATH_MAX`。
