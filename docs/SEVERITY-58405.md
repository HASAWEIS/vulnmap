# CG-39 / arvo:58405（GhostPDF CFF，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S21-CG39-arvo-58405/severity.json`；结构校验：`tests/test_severity_58405.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.3  (low)
```

**越界的不是 'E-'，而是 NUL**：`'E'`/`'E-'` 都写在 `buf[61..64]` 之内，唯一越界的是循环结束后的 `*txt = 0`（workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:744）——1 字节、固定值。
因此 I 不能给 H；也不宜给 N（越界写真实存在）→ I:L、A:N。

## 1. 机制（守卫差 1 字节）

```c
// workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:691-696
char buf[65];
char *txt = buf;
while (txt < buf + (sizeof buf) - 3 && p < e) {   // 只留 3 字节
```

```c
// workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:711-713（高半字节）/ :732-734（低半字节）
else if (n == 0xC) {
    *txt++ = 'E';
    *txt++ = '-';        // 0xCC 的两个半字节各写 2 字符 → 单次迭代最多 4 字符
}
```

| 量 | 值 |
| --- | --- |
| 守卫允许进入的最大 `txt` | `buf + 61`（`65 - 3 = 62`，条件 `< 62`） |
| 单次迭代最多推进 | **4** 字符（0xCC 高、低半字节各 2） |
| 迭代后 `txt` | `buf + 65` |
| `*txt = 0`（workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:744） | 写到 `buf[65]` → **越界 1 字节** |
| 越界内容 | **NUL（固定 0）** |

ASAN 佐证：`WRITE of size 1`（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:14`）、对象 `buf.i` 是 `[32,97)`（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:61`）、访问在帧 offset 97（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:56`）。

## 2. 为什么 I 只能 L

| 要素 | 本例 | 结论 |
| --- | --- | --- |
| 内容可控？ | **否**：越界字节是 NUL；'E-' 全在缓冲区内，nibble 只影响区内内容 | 不满足 I:H |
| 量可控？ | **否**：固定 1 字节，下一轮条件立即为假，无放大路径 | 不满足 I:H |
| 落点 | `buf` 结束于 97，下一个对象 `args` 从 144 开始 → 中间 **47 字节**空隙（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:60-62`） | 真实构建多半落在栈填充 |

## 3. 为什么 A 取 N（而不是 H）

- 没有任何非 ASAN 崩溃实测；`fix` 侧同输入 exit=0（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-fix.log:2`）。
- 唯一越界的那 1 字节落在 47 字节空隙里，按当前布局连 `args` 都碰不到。
- 若换编译器布局让 `args` 紧贴 `buf`，这 1 字节会改写 `args[0]`（数据，不是控制流）→ 也只到 A:L（见敏感性表）。

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | PDF 字体解析入口（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:1`、`:11`、`:16-18`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 1157 字节固定 PoC 一次命中，vul exit=1 / fix exit=0（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:2`、`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-fix.log:2`） |
| PR | **N** | 解析 PDF 不需要额外权限（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把 PDF 交给渲染器（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:11`）；自动处理无证据 → 保守 R |
| S | **U** | 影响在渲染进程栈内 |
| C | **N** | 只写不读 |
| I | **L** | 1 字节固定 NUL；越界真实但内容/量都不可控 |
| A | **N** | 无非 ASAN 崩溃；落点在 47 字节空隙 |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:1`、`:11`、`:16-18` |
| privileges_required | none | `workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:1-2` |
| user_interaction | required | `workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:11`、`:16-18` |
| observed_impact | stack_buffer_overwrite_1byte_nul | `workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:13-16`、`:56`、`:60-62`；源码 `workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:691`、`:696`、`:712-713`、`:733-734`、`:744` |
| reachability_evidence | confirmed | `workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:16-18`；`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-fix.log:2` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-vul.log:2`、`workspace/S21-CG39-arvo-58405/logs/V4.pdf-cff-real.58405-fix.log:2`）；生产消费方与栈布局无证据 |

## 6. 缺证据清单

1. **内容可控性**：越界字节恒为 NUL，没有任何路径让它变成攻击者数据。
2. **放大路径**：守卫与写出的差恒为 1；未见多字节溢出形态。
3. **不同布局下的后果**：若 `args` 紧贴 `buf`，这 1 字节会改写 `args[0]`——未在其它编译器/优化级别下实测。
4. **生产消费者与栈加固**：谁渲染不可信 PDF、是否开 canary。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:L`（换布局可能踩到 args） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.4 |
| `I:H`（需内容可控或可放大） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 5.5 |
| `I:H`+`A:H` | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 7.1 |
| `UI:N`（自动批量转换） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 4.0 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 |

## 8. 反方意见

- **「0xCC 会写 'E-'，说明内容来自输入，应该 I:H」**：回应：'E-' 写在缓冲区**内**（61..64），越界的是随后的 NUL；nibble 影响不了越界那一字节的值。
- **「1 字节 NUL 落空隙＝无影响，应 I:N」**：回应：越界写真实存在（ASAN 已证），'落空隙'是当前布局的巧合；按『证据不足取 I:L』记 L。

## 9. 校验

```
python3 -m pytest tests/test_severity_58405.py -q
```

测试会直接读日志/源码验证：日志必须是 `WRITE of size 1` + 帧 offset 97 + `buf.i` `[32,97)` + `args` `[144,528)`；
源码 `workspace/S21-CG39-arvo-58405/src/ghostpdl/pdf/pdf_font1C.c:691` 必须是 `char buf[65];`、`:696` 守卫必须是 `sizeof buf) - 3`、`:744` 必须是 `*txt = 0;`；
并断言算术：`65-3=62`、单次最多 +4 → `65` → 越界 1 字节；`144-97=47` 字节空隙。
