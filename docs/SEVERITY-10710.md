# CG-21 / arvo:10710（OVN lexer，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S9-CG21-arvo-10710/severity.json`；结构校验：`tests/test_severity_10710.py`。未改 `case.json` / `LEDGER.json`。

## 0. 先纠正一个前提：实测是「读下溢」，不是「栈写破坏」

任务描述写的是「栈写破坏 @ lex.c:341，I:H 可成立」。日志不支持这个说法：

- `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:19` —— **`READ of size 1`**
- `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:20` —— `SCARINESS: 27 (1-byte-read-stack-buffer-underflow)`
- `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:39-44` —— 访问在 offset 31，下溢 `workspace/S9-CG21-arvo-10710/src/openvswitch/ovn/lib/expr.c:1284` 帧里的 `lexer` 对象 `[32,336)`

为什么写入半边是空操作：`workspace/S9-CG21-arvo-10710/src/openvswitch/ovn/lib/lex.c:336` 的守卫是

```c
if (hexit && i / 2 >= sizeof token->value.u8) {   // 只有 hexit 非 0 才查边界
    lex_error(...); return;
}
out[-(i / 2)] |= i % 2 ? hexit << 4 : hexit;        // :341 越界时 hexit 必为 0
```

越过边界的那些迭代里 `hexit` 恒为 0，于是 `|= 0` —— 把读到的字节原值写回，**不改变内容**。
所以：越界访问成立（读 + 同值回写），但没有可观测的数据篡改、没有泄露通道、没有真实崩溃证据。

## 1. 向量与分数

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.3  (low)
```

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | 输入是 `docker -v ...:/tmp/poc:ro` 的本地文本文件（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:1`、`:4`、`:9-10`）；**无网络入口证据，禁 AV:N** |
| AC | **L** | 608 字节固定输入一次触发，vul exit=1 / fix exit=0（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:2`、`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-fix.log:2`） |
| PR | **N** | 容器内无 `--privileged`/`-u`（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:1`） |
| UI | **R** | 每次只解析一个输入文件（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:4`、`:9-10`），需一次投递 |
| S | **U** | 影响局限在解析进程的栈帧 |
| C | **N** | 越界读出的字节经 `|= 0` 又写回同一地址，没有进入 token 值/错误信息/输出 |
| I | **L** | 越界访问真实存在，但写入恒为 `|= 0`（不改字节）；按『证据不足取 I:L』保守记 L，不因"是栈"就给 H |
| A | **N** | `exit=1` 来自 ASAN 的 abort（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:45` 是 ASAN 提示、`:2` 是它的退出码），真实构建里是"读+原值回写"，没有崩溃实测 |

## 2. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:1`、`:4`、`:9-10` |
| privileges_required | none | `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:1`、`:2` |
| user_interaction | required | `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:4`、`:9-10` |
| observed_impact | stack_buffer_underflow_read | `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:19`（READ of size 1）、`:20`（SCARINESS 27）、`:21`（`workspace/S9-CG21-arvo-10710/src/openvswitch/ovn/lib/lex.c:341`）、`:39-44`（expr_parse_string 帧 `workspace/S9-CG21-arvo-10710/src/openvswitch/ovn/lib/expr.c:1284`）；源码 `workspace/S9-CG21-arvo-10710/src/openvswitch/ovn/lib/lex.c:336`、`:341` |
| reachability_evidence | confirmed | `workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:21-32`（`lex_parse_hex_integer ← lex_parse_integer__ ← lex_parse_integer ← lexer_get ← parse_relop ← … ← LLVMFuzzerTestOneInput`）、`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-fix.log:2,11`（fix 正常报语法错、exit=0） |
| deployment_conditions | unproven | 只有两镜像的 exit 对比（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:2`、`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-fix.log:2`）；生产消费者与进程生命周期无证据 |

## 3. 触发机制（608 字节怎么走到的）

- PoC：`1 == 0x` + 600 个 `0` + NUL = 608 字节（`workspace/S9-CG21-arvo-10710/artifacts/verify/ovn-lex-hex600.bin`）。
- 解析 `0x000…0` 时 `len=600`，`in = start + 599`，`out = value.u8 + 15`；
- `i` 从 0 涨到 599：`i/2 ≥ 16` 之后本该报 "requires more than 128 bits"，但因为 `hexit==0` 守卫被跳过，`out[-(i/2)]` 一路下探到 `lexer` 对象之前（offset 31）。
- ASAN 在第一次越界时停住（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-vul.log:18` 报 ERROR、`:45` HINT、`:2` exit=1）；fix 版则正常返回语法错误（`workspace/S9-CG21-arvo-10710/logs/V4.ovn-lex-hex600.10710-fix.log:11`）。

## 4. 为什么不给 I:H / A:H（以及什么条件下改）

| 想要 | 需要补的证据 | 若成立的分数 |
| --- | --- | --- |
| `I:H` | 证明越界那几次迭代能**改写**栈字节（即 `|=` 的右值非 0），或 proof 该 RMW 在目标编译器下不是空操作 | `AV:L/…/I:H/A:H = 7.1` |
| `A:H` | 非 ASAN 构建下的崩溃实测（SIGSEGV/stack-smashing） | 同上 7.1 |
| `I:N` | 若能证明所有构建下 `|=0` 都被优化掉、且不产生任何副作用 | `0.0` |

## 5. 缺证据清单

1. **非 ASAN 构建的行为**：这次越界访问是否真的无害（读+原值回写），未实测。
2. **字节被改写的可能**：需要一个"越界迭代里 hexit 非 0"的构造——但源码守卫（`:336`）看起来堵住了；若能绕开守卫即可翻成 I:H。
3. **生产消费者**：谁把表达式文本交给 OVN lexer（控制器/CLI/长驻守护），决定 UI 与 A 的现实含义。
4. **泄露通道**：越界读出的字节目前只回写同一地址，没有进入任何输出。

## 6. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `I:H` + `A:H`（按任务原本的"栈写破坏"假设） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 7.1 |
| `A:L`（认为 ASAN abort 可外推） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.4 |
| `C:L`（若越界值能进入输出/日志） | `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | 4.4 |
| `UI:N`（产品侧自动解析） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 4.0 |
| `AC:H`（认为依赖具体 token 形态） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` | 2.5 |
| `I:N`（|=0 完全无影响） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N` | 0.0 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 |

## 7. 反方意见

- **「就是栈写，给 I:H/A:H（7.1）」**：`out[-(i/2)] |= …` 语法上确是写；且 ASAN 在镜像里 exit=1。**回应**：日志的访问类型是 READ（`:19`），写半边由 `hexit==0` 限定为 `|= 0`；把"语法上是写"当"数据被改"属推断。补非 ASAN 崩溃或字节改写证据即可翻案。
- **「|=0 无影响，给 I:N（0.0）」**：**回应**：越界访问本身真实存在，且"写回原值"依赖实现与优化，不宜当作零影响；按任务口径取 I:L 更稳。

## 8. 校验

```
python3 -m pytest tests/test_severity_10710.py -q
```

测试会：复算向量与敏感性表分数、把六维 evidence 的 `文件:行` 逐条解析并检查行存在、**禁止 AV:N**、
并要求"评分方向与日志一致"——日志写 `READ of size 1` 时，draft 的 `observed_impact` 必须是读类取值且向量为 `I:L/A:N`。
