# CG-37 / arvo:59500（MuPDF BMP 调色板，CWE-124）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S20-CG37-arvo-59500/severity.json`；结构校验：`tests/test_severity_59500.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L = 4.4  (medium)
```

**I 只能到 L**：负下标确实由头部控制（能决定偏移与长度），但**写进去的字节不受控**——memcpy 的源是静态表 `vga_palette` 往前偏移的 rodata。
而且越界量已量化：本例只有 **30 字节**落在 `info` 结构体之外。

## 1. 机制：present 变负 → memcpy 目标落到结构体之前

```c
// workspace/S20-CG37-arvo-59500/src/mupdf/source/fitz/load-bmp.c:940-951
expected = fz_mini(info->colors, 1 << info->bitcount);      // 本例 colors=0x20202020 → expected=16
present  = fz_mini(expected, (bitmap - p) / entry_size);      // bitmap=begin+bitmapoffset；bitmapoffset=0、p=begin+120、entry=4
                                                              // → (0-120)/4 = -30  ← 负数
if (present < expected)
    bmp_load_default_palette(ctx, info, present);             // :954 把 -30 传下去
```

```c
// workspace/S20-CG37-arvo-59500/src/mupdf/source/fitz/load-bmp.c:915-916（bitcount==4 且非灰度分支）
memcpy(&info->palette[readcolors * 3],          // 目标 = palette - 90 = 结构体前 30 字节
       &vga_palette[readcolors * 3],            // 源  = 静态表的 readcolors*3 偏移（rodata！）
       sizeof(vga_palette) - readcolors * 3);   // 长度 = 768 + 90 = 858（反向变长）
```

## 2. 范围量化（为什么不是「一大片」）

| 量 | 值 | 依据 |
| --- | --- | --- |
| `struct info` 在帧内 | `[32, 976)` | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:40-41` |
| `palette[768]` 在结构体内偏移 | 60 | `workspace/S20-CG37-arvo-59500/src/mupdf/source/fitz/load-bmp.c:105-117` 的字段顺序（type/version/bitmapoffset/width/height/bitcount/…/palette） |
| 本例 present | **−30** | ASAN 访问在帧 offset 2 = 32−30（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:36`） |
| memcpy 目标起点 | 结构体 −30 | palette(60) + (−30×3) = −30 |
| memcpy 长度 | 858 | `768 − (−90)`；恰好结束在 palette+768 |
| **结构体外的越界字节** | **30** | [帧 2, 帧 32) |

注意：858 字节里 **828 字节落在 `info` 自身范围内**（把 version/bitmapoffset/width/height/bitcount/masks 覆盖成 rodata 常量），只有 30 字节真正越界。
这也解释了为什么 ASAN 报的是 `WRITE of size 1`（首个越界字节即停，`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:16`），而 `present` 的负值不是无界的：它受 `bitmapoffset` 必须小于当前解析位置约束，最大约 `(p-begin)/entry_size`。

## 3. 为什么 I 只能 L（而不是 H）

| 要素 | 本例 | 结论 |
| --- | --- | --- |
| 内容可控？ | **否**：源是 `vga_palette[readcolors*3]`，即静态表之前的 rodata 常量 | 不满足 I:H 的「任意数据改写」 |
| 位置可控？ | 部分：`bitmapoffset` 决定 `present`，但只能为 ≤0 且量级受 p 限制 | 有限可控 |
| 长度可控？ | 与偏移联动（`768 + |present|*3`），但同受上界约束 | 有界 |
| 越界落点 | 帧内 `info` 之前 30 字节 + 结构体自身头部字段 | 破坏真实存在，但内容固定 |

对比：CG-29/30/36 给 I:H 的共同点是**写的内容来自输入**；本例内容来自 rodata，只能算「数据被破坏、后果不受控」→ **I:L**。

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | BMP 解析入口（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:1`、`:11`、`:18-19`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 186 字节固定 PoC 一次命中，vul exit=1 / fix exit=0（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:2`、`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-fix.log:2`） |
| PR | **N** | 解析图片不需要额外权限（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把图片交给渲染器（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:11`）；自动处理无证据 → 保守 R |
| S | **U** | 影响在渲染进程的栈内 |
| C | **N** | 只写不读 |
| I | **L** | §3：越界真实存在，但内容固定、越界仅 30 字节 |
| A | **L** | 被改写的 `info` 头部字段后续会被用到，存在级联风险；但没有崩/二次越界的实测（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:2` 只是 sanitizer abort） |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:1`、`:11`、`:18-19` |
| privileges_required | none | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:1-2` |
| user_interaction | required | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:11`、`:18-19` |
| observed_impact | stack_underflow_write_uncontrolled | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:15-18`、`:36`、`:40-41`；源码 `workspace/S20-CG37-arvo-59500/src/mupdf/source/fitz/load-bmp.c:915-916`、`:940-951`、`:954` |
| reachability_evidence | confirmed | `workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:18-24`；`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-fix.log:2` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-vul.log:2`、`workspace/S20-CG37-arvo-59500/logs/V4.bmp-pal-hdr108.59500-fix.log:2`）；生产消费方与栈加固无证据 |

## 6. 缺证据清单

1. **内容可控性**：需要某条路径让写入字节来自文件（本例源是 rodata，不成立）。
2. **越界放大**：`bitmapoffset` 只能让 `present` ≤ 0 且量级受 `(p-begin)/entry_size` 限制；未见更大的形态。
3. **级联后果实测**：`info.width/height/bitcount/masks` 被改成 rodata 常量后，后续解码是否越界/崩溃——未测。
4. **生产消费者与栈加固**：谁渲染不可信 BMP/PDF、是否开 canary。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:N`（30 字节落帧空隙、无可用性影响） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 3.3 |
| `A:H`（字段被改后实测崩溃） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `I:H`（认为改自身 info 字段算改变安全态势） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| `I:H`+`A:H`（需内容可控/可放大的实测） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 7.1 |
| `UI:N`（自动批量渲染） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` | 4.9 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.9 |

## 8. 反方意见

- **「偏移由头部控制，等于任意位置写（6.1~7.1）」**：回应：位置只能在 `present ≤ 0` 的一侧、量级受 p 约束；更关键的是**写什么不受控**（rodata 常量）。要 I:H 得先解决内容可控。
- **「30 字节写进帧空隙，等于没影响（3.3）」**：回应：这次 memcpy 同时把 `info` 的头部字段改写成了 rodata 值，不只是空隙；但确实没有崩的实测，故 A 取 L 而非 H，I 取 L 而非 N。

## 9. 校验

```
python3 -m pytest tests/test_severity_59500.py -q
```

测试会直接读日志/源码验证：日志必须是 `stack-buffer-underflow` + `WRITE of size 1` + 帧 offset 2 + 对象 `[32, 976)`；
源码 `workspace/S20-CG37-arvo-59500/src/mupdf/source/fitz/load-bmp.c:943` 必须是 `present = fz_mini(expected, (bitmap - p) / entry_size)`，`:915` 必须是 `memcpy(&info->palette[readcolors * 3], &vga_palette[readcolors * 3],`；
并断言布局算术：palette 在结构体偏移 60、`present=-30` → 目标 = 结构体 −30、长度 858、结构体外仅 30 字节。
