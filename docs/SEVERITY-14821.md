# CG-25 / arvo:14821（OpenThread FromString，CWE-121）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S12-CG25-arvo-14821/severity.json`；结构校验：`tests/test_severity_14821.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论（只按证据打分）

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L = 5.1  (medium)
```

- 实测是真的栈越界**写**，但只有 **1 字节**，且**规模结构性受限（上限约 1–2 字节）**，不随输入放大；
- 因此 `I:H`/`A:H` 缺证据，按任务口径记 `I:L` / `A:L`；
- 入口只有 CLI/UART（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:19-21`），**不主张 `AV:N`**；
- 攻击者自己投递命令行，无需第三方动作 → `UI:N`；`PR` 记为 **unproven**（CLI 是否要登录没有证据）。

## 1. 为什么越界量不可能大（这段决定定级）

`Address::FromString` 在 `.` 分支把写入终点往前挪 4 字节，然后做一次压缩拷贝：

```c
// workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:313-318
else if (ch == '.') {
    hasIp4 = true;
    endp -= kIp4AddressSize;   // endp: m8+15 -> m8+11
    break;
}
```

```c
// workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:331-334
while (colonp && dst > colonp) {
    *endp-- = *dst--;          // :333 崩溃点，ASAN WRITE of size 1
}
```

边界推导：

| 量 | 取值 | 依据 |
| --- | --- | --- |
| `dst` 上限 | `m8 + 13` | 分组写入前的 `VerifyOrExit(dst + 2 <= endp)`（`workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:293`），`endp` 初值 `m8+15` |
| `colonp` 下限 | `m8 - 1` | `dst` 从 `m8-1` 起步（`:276` 的 `dst--`） |
| 拷贝字节数 `n` | ≤ 14 | `n = dst - colonp` |
| 写入最低地址 | `m8 + 12 - n` | 从 `m8+11` 往下写 |
| **下溢量** | **n − 12 ≤ 2 字节** | 本 PoC 实测 1 字节（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:30` offset 175 vs 对象起点 176） |

结论：这是**有界**的单/双字节写，不是可放大的溢出。这一点直接把 `I:H`（可改写任意数据）与 `A:H`（必然崩溃）排除在'证据之外'。

## 2. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | 入口是 CLI/UART 收字节（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:1`、`:19-21`）；日志无网络标记，**禁 AV:N**。若 UART 需物理接触，可降 `AV:P`（敏感性表 3.5） |
| AC | **L** | 36 字节固定输入一次触发，vul exit=1 / fix exit=0（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:2`、`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-fix.log:2`） |
| PR | **unproven（暂按 N）** | harness 内无特权（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:1`），但产品 CLI 是否要登录未知 → 列入 missing_dimensions；若需登录改 `PR:L`（4.4） |
| UI | **N** | 攻击者自己把命令送进 UART（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:9-10`、`:21`），不需要第二个用户操作 |
| S | **U** | 影响在 CLI 进程栈内 |
| C | **N** | 只有写，没有读出/回显 |
| I | **L** | 越界写真实存在，但只有 1 字节且落在两个局部之间的空隙（ASAN 帧 `[144,176)`），没有改写有意义变量的证据 |
| A | **L** | ASAN 下 abort（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:2`），普通构建后果未测：'可能崩'而非'已崩' |

## 3. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:1`（`-v ...:/tmp/poc:ro`）、`:9-10`（逐输入执行）、`:19-21`（`Uart::ProcessCommand → Uart::ReceiveTask → LLVMFuzzerTestOneInput`） |
| privileges_required | unproven | `workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:1-2`（harness 无特权、exit=1）；`workspace/S12-CG25-arvo-14821/src/openthread/src/cli/cli_coap.cpp:141-151` 未见鉴权代码 |
| user_interaction | none | `workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:9-10`、`:21` |
| observed_impact | stack_buffer_overwrite_1byte | `workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:13`（WRITE of size 1）、`:14`（SCARINESS 46）、`:15`（写点 `workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:333`）、`:30`（offset 175）、`:36-37`（`coapDestinationIp [176,192)` 被下溢）；源码 `workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:313-318` |
| reachability_evidence | confirmed | `workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:15-21`（七帧完整链）、`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-fix.log:2,11`（fix：exit=0、Executed 0 ms）；PoC `workspace/S12-CG25-arvo-14821/artifacts/verify/ot-ip6-0.bin` |
| deployment_conditions | unproven | 仅两镜像的 exit 对比（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:2`、`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-fix.log:2`）；UART 暴露方式与进程形态无证据 |

## 4. 机制（36 字节怎么走到的）

1. CLI 收到 `coap get ::1:2:3:4:5:6:7:1.2.3.4 /a`（`workspace/S12-CG25-arvo-14821/artifacts/verify/ot-ip6-0.bin`，36 字节）；
2. `Coap::ProcessRequest` 把第 2 个参数交给 `otIp6AddressFromString(argv[1], &coapDestinationIp)`（`workspace/S12-CG25-arvo-14821/src/openthread/src/cli/cli_coap.cpp:151`、`:180`）；
3. 解析到 `.` 时 `hasIp4=true` 且 `endp -= 4`（`workspace/S12-CG25-arvo-14821/src/openthread/src/core/net/ip6_address.cpp:313-318`），但 `dst` 已经推进到 `m8+13`；
4. 压缩循环 `*endp-- = *dst--`（`:333`）写 `n=14` 字节，从 `m8+11` 往下 → 第 14 个字节落在 `m8-1`，即 `coapDestinationIp` 之前 1 字节（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:30`、`:37`）；
5. ASAN 立即 abort（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-vul.log:2`）；fix 版正常返回（`workspace/S12-CG25-arvo-14821/logs/V4.ot-ip6-0.14821-fix.log:11`）。

## 5. 缺证据清单

1. **非 ASAN 构建的现象**：1 字节写进栈空隙是否真的无影响，未实测。
2. **CLI 鉴权**：设备上 CLI 是否要求登录/口令（决定 `PR`）。
3. **UART 暴露方式**：物理引脚 / 板载串口桥 / 串口服务器（决定 `AV:P`、`AV:L`，甚至是否可能 `AV:N`）。
4. **写入值的安全性影响**：写出的字节来自被解析分组（可控 0x00–0xff），但没有证据显示它能落进有意义的相邻变量（本帧内 `[144,176)` 是空白）。

## 6. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `UI:R`（需操作员粘贴命令） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.4 |
| `PR:L`（CLI 需登录） | `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` | 4.4 |
| `A:N`（1 字节写不崩） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 4.0 |
| `I:N`（写进空隙等于无影响） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | 4.0 |
| `AV:P`（UART 需物理接触） | `AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` | 3.5 |
| `I:H/A:H`（需改写有意义数据/崩溃的证据） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | **7.7** |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` | 6.5 |

## 7. 反方意见

- **「栈写就该进高危（7.7）」**：1 字节也能改到相邻的长度/布尔量，字节值还可控。**回应**：规模有结构性上限（≈1–2 字节，见 §1），落点在两局部之间的空隙；没有'改写有意义变量'或'非 ASAN 崩溃'的实测。补证据即可翻到 7.7。
- **「写进空隙等于无影响（4.0）」**：**回应**：越界写是真实的（ASAN 已证），'空隙'是当前编译器布局的结果，不保证其他构建；保守取 `I:L/A:L`。

## 8. 校验

```
python3 -m pytest tests/test_severity_14821.py -q
```

测试会：复算向量与敏感性表分数、把六维 evidence 的 `文件:行` 逐条解析并检查行存在、**禁止 AV:N**、
并要求'不抬分'：向量里不得出现 `I:H`/`A:H`，且 `observed_impact` 必须写成 1 字节写类取值。
