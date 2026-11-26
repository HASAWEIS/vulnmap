# CG-18 / arvo:12420（libidn2，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-11`；无 `_status` 草稿标记。
> 机器可读版本：`workspace/S7-CG18-arvo-12420/severity.json`；结构校验：`tests/test_severity_12420.py`。
> 未改 `case.json`、`LEDGER.json`、其他 workspace。

## 0. 结论

`idn2_to_ascii_4i()` 只保证**每个 label ≤ 63**，没有保证**整串输出 ≤ 63**；调用方按文档契约分配 64 字节（63 + 终止符），
而 32+32 双 label 的输入会产出 65 字符、`strcpy` 写 **66 字节** → ASAN 实测堆越界写。
**向量**：`AV:L`（本地文本文件）`AC:L` `PR:N` `UI:R` `S:U` `C:N` **`I:H`** **`A:H`** → **7.1（high）**。

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H = 7.1  (high)
```

## 1. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | 输入是 `docker -v ...:/tmp/poc:ro` 挂载的本地文件（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:1`、`:9-10`）；**没有任何网络入口证据**，因此不写 `AV:N`（若照抄会得 8.1，见敏感性表） |
| AC | **L** | 260 字节固定输入一次触发，vul exit=1 / fix exit=0（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:2`、`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-fix.log:2`） |
| PR | **N** | 容器内未加特权、未 `-u`（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:1`） |
| UI | **R** | 每次只跑一个输入（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:9-10`），需一次投递；产品侧自动处理无证据（保守取 0.62） |
| S | **U** | 影响局限在调用本 API 的进程内 |
| C | **N** | 只有写、没有读；未观测到越界字节被回显 |
| I | **H** | 越界写的内容是输入的决定性转换结果（65 个可控字符），且**越界量随 label 数线性增长**：每个 label 合法（32≤63）但整串无 63 上限 |
| A | **H** | ASAN 下进程 `exit=1` 终止（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:2`）；同一路径放大 label 数即可越过任何 allocator 的 padding → 崩溃 |

## 2. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:1`（`-v ...:/tmp/poc:ro`）、`:9-10`（`Running: /tmp/poc`） |
| privileges_required | none | `workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:1`（无 `--privileged`/`-u`）、`:2`（exit=1） |
| user_interaction | required | `workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:9-10`（单输入逐次执行） |
| observed_impact | memory_corruption_confirmed | `workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:13`（WRITE of size 66）、`:14`（SCARINESS 45）、`:26`（0 bytes right of 64-byte region）、`:16`（写点 `idn2_to_ascii_4i` @ `workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:621`）、`:29`（64 字节缓冲由 `workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c:67` 的 `malloc(64)` 分配） |
| reachability_evidence | confirmed | `workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:16-17`（`idn2_to_ascii_4i ← LLVMFuzzerTestOneInput`）、`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-fix.log:2,11`（fix 干净：exit=0、Executed 1 ms）；PoC `workspace/S7-CG18-arvo-12420/artifacts/verify/libidn2-4i-65.bin`（260 字节） |
| deployment_conditions | unproven | 只见 vul/fix 两镜像的 exit（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:2`、`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-fix.log:2`）；生产调用点与缓冲区位置（堆 64 vs 栈 64）无证据 |

## 3. 因果链（为什么是『整串无 63 上限』）

```c
// workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c:616-621
/* wow, this is ugly, but libidn manpage states:
 * char * out  output zero terminated string that must have room for at
 * least 63 characters plus the terminating zero. */
if (output)
  strcpy (output, (const char *) output_u8);   // 没有检查 strlen(output_u8) <= 63
```

```c
// workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c:67,73 —— 合法调用方：按契约分配 64 字节
char *out2 = (char *) malloc(64);
...
idn2_to_ascii_4i((uint32_t *) data, size / 4, out2, flags[it]);
```

PoC 实测：260 字节 = 65 个 UCS-4 码点，内容为 `32×'a' + '.' + 32×'b'`（两个合法 label），ASCII 输出 `32 + 1 + 32 = 65` 字符，
`strcpy` 连同 NUL 写 **66** 字节 → 越过 64 字节缓冲 2 字节（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:13`、`:26`）。

## 4. 为什么 I:H / A:H（而不是 I:L）

- **内容可控**：写入的是输入 label 的 ASCII 形式，攻击者决定字节。
- **规模可控**：限制是逐 label 的（每个 ≤63），不是整串；把 label 数从 2 提到 N，输出长度≈`33N-1`，越界量线性增长。
- **已有崩溃证据**：ASAN 下 `exit=1`（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-vul.log:2`）；fix 侧同输入 exit=0（`workspace/S7-CG18-arvo-12420/logs/V4.libidn2-4i-65.12420-fix.log:2`、`:11`）。
- **反面**：本 PoC 只越界 2 字节，glibc 的 `malloc(64)` usable 通常是 72，单看这次可能落在 padding 内 → 所以把"放大 PoC 未实测"写进了缺证据清单。

## 5. 缺证据清单

1. **放大 PoC**：label 数 N>2（例如 8×32 字符 → 输出 263 字符）尚未实测；这是把 I:H/A:H 从"可预期"坐实为"必然"的关键一步。
2. **生产调用点**：谁调用 `idn2_to_ascii_4i`、缓冲是堆 `malloc(64)` 还是栈 `char[64]`（栈上后果更严重，可能直接打 canary/返回地址）。
3. **非 ASAN 构建的行为**：普通构建下 2 字节越界是否被 padding 吸收、是否崩溃，未测。
4. **利用实验**：`workspace/S7-CG18-arvo-12420/artifacts/exploit/result.json` 为 `skipped`，没有代码执行证据。

## 6. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:L`（认为 2 字节落 padding 不足以崩） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| `I:L`（要求放大 PoC 实测才给 H） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `A:N` | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 5.5 |
| `AC:H` | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H` | 6.3 |
| `UI:N`（产品侧自动处理） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | 7.7 |
| `C:L`（若找到越界字节回显路径） | `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:H` | 7.3 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **8.1** |

最后一行是提醒：本例**没有任何网络入口证据**，`AV:N` 会把 7.1 抬到 8.1；`tests/test_severity_12420.py` 会把 `AV:N` 直接判失败。

## 7. 校验

```
python3 -m pytest tests/test_severity_12420.py -q
```

测试内容：向量复算（含敏感性表）、六维 evidence 的 `文件:行` 逐条解析并检查行存在、禁止 `AV:N`、`final=false`/`human_signoff_required=true`/无 `_status`、`case.json` 未被回写。
