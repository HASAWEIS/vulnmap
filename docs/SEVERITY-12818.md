# CG-27 / arvo:12818（kimageformats TGA，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S13-CG27-arvo-12818/severity.json`；结构校验：`tests/test_severity_12818.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L = 4.4  (medium)
```

一句话：**4.29e9 字节的 memset 里，4294836225 字节是分配区内的清零（本来就要做），真正越界的只有 1 字节**；
内容是 0、长度可控，属『可修改但后果不受控』→ `I:L`；ASAN 下 abort，但零填充导致的 OOM/元数据崩溃未实测 → `A:L`；图片解析入口、无网络证据 → `AV:L`。

## 1. 先把"4.29e9"拆开（这段决定定级）

| 量 | 数值 | 证据 |
| --- | --- | --- |
| 图像缓冲分配 `size` | 65535 × 65535 × 1 = **4294836225** | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:33` 的 region 大小；PoC 头 width/height=0xFFFF、bpp=8（`workspace/S13-CG27-arvo-12818/artifacts/verify/tga-big-0.bin`，22 字节） |
| `readRawData(char*, int)` 实参 | 被截断成 int（-65535）→ 返回 **-1** | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:18` `QIODevice::read (QBuffer): Called with maxSize < 0`；源码 `workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:262` |
| memset 起点 | `&image[-1]` | 源码 `workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:264`；`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:33` `1 bytes to the left of ...` |
| memset 长度 | `size - (-1)` = **4294836226** | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:21` |
| **越界字节数** | **1** | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:33`（`1 bytes to the left of 4294836225-byte region`） |

也就是说：写长只比分配多 1，起点往前 1 —— 剩下 4294836225 字节全在分配区内，是『把整幅图清零』这一设计行为。
所以**不能因为写长 4.29e9 就判 I:H/A:H**：那是把 in-bounds 初始化算成破坏；同样**也不能因为值恒 0 就判 I:N**：那 1 字节落在分配区之外。

## 2. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | 入口是 TGA 图片解析（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:1`、`:4`、`:25-26`），日志无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 22 字节固定输入一次命中，vul exit=1 / fix exit=0（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:2`、`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-fix.log:2`） |
| PR | **N** | 解析图片无需额外权限（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把 TGA 交给解码器（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:4`）；产品侧自动批处理无证据 → 保守取 R |
| S | **U** | 影响在解码进程内 |
| C | **N** | 只写不读，无回显 |
| I | **L** | 越界 1 字节、值恒 0；落点按布局是 mmap chunk 的 size 字段最高字节 → 元数据可被破坏但后果不可控；且失败读被当成功继续解码（`workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:262-264` 无错误分支）→ 静默错误数据 |
| A | **L** | ASAN 在第一个越界字节即 abort（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:2`）；4GB 零填充的 OOM/超时**未实测**，fix 版同样 malloc 4GB 却 exit=0（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-fix.log:2`）说明差异在"零填充"不在"分配" |

## 3. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:1`、`:4`、`:25-26` |
| privileges_required | none | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:1-2` |
| user_interaction | required | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:4`、`:25-26` |
| observed_impact | heap_underflow_write_1byte_zero_fill | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:21`（WRITE of size 4294836226）、`:23-24`（`__asan_memset ← LoadTGA @ workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:264`）、`:33`（1 bytes to the left）、`:36`（malloc @ `workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:215`）、`:18`（int 截断告警） |
| reachability_evidence | confirmed | `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:24-26`（`LoadTGA ← TGAHandler::read ← LLVMFuzzerTestOneInput`）、`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-fix.log:2,5`（fix：exit=0、Execution successful） |
| deployment_conditions | unproven | 仅两镜像（`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:2`、`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-fix.log:2`）；生产消费者与内存预算无证据 |

## 4. 机制（22 字节怎么走到 4.29e9）

```c
// workspace/S13-CG27-arvo-12818/src/kimageformats/src/imageformats/tga.cpp:215, 262-264（vul）
uchar *const image = reinterpret_cast<uchar*>(malloc(size));   // size = qint64 4294836225
const int dataRead = s.readRawData((char *)image, size);         // int 形参被截断 → 返回 -1
if (dataRead < size) {                                          // -1 < 4294836225 恒真
    memset(&image[dataRead], 0, size - dataRead);               // &image[-1], 4294836226
}
```

- fix（`patch.diff`）在 `readRawData` 之后补了 `if (dataRead < 0) return false;`，于是不再进入 memset → `workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-fix.log:5` 直接成功返回。
- 失败读没有被当成错误：`valid` 仍为 true，函数继续按成功路径出图（全 0 像素），这也是 I 不给 N 的原因。

## 5. 缺证据清单

1. **非 ASAN 构建的后果**：1 字节写进 chunk 元数据后 `free()` 是否 abort、4GB 零填充在受限内存下是否 OOM —— 都没有实测。
2. **落点确认**：`image-1` 是否确实是 mmap chunk 的 size 字段最高字节（取决于分配器实现与 Qt 的分配路径），需在目标构建上验证。
3. **生产消费者与内存预算**：谁调用 Qt 图像插件、是否对 4GB 图像设上限。
4. **静默错误解码的下游影响**：全 0 图像被当成合法结果返回，是否影响依赖图像内容的后续逻辑。

## 6. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:H`（把 4GB 零填充 OOM 或元数据崩溃算已证） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `I:H`+`A:H`（需『越界能改写有意义数据』证据） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | **7.1** |
| `I:N`（写 0 到元数据视为无完整性影响） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L` | 3.3 |
| `UI:N`（产品侧自动批量解析） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L` | 5.1 |
| `AC:H`（依赖 4GB 级内存余量） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:L` | 3.6 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 5.4 |

## 7. 反方意见

- **「写 4.29e9 就该 7.1」**：memset 4GB 还会越过分配区 1 字节，抹平内存、破坏元数据，ASAN 已 abort。**回应**：`workspace/S13-CG27-arvo-12818/logs/V4.tga-big-0.12818-vul.log:33` 写明只有 1 字节在分配区左侧，其余 4294836225 字节在区内（是图像清零本身）；内容恒 0、后果不可控，按 I:L/A:L 记。要 7.1 需补『改写有意义数据』与『非 ASAN 崩溃/OOM』实测。
- **「都是 0，等于无影响，给 3.3」**：**回应**：那 1 字节确实越界、且按 glibc 大块布局正落在 size 字段最高字节；再加上失败读被当成功解码，不能直接判 I:N。

## 8. 校验

```
python3 -m pytest tests/test_severity_12818.py -q
```

测试会：复算向量与敏感性表分数、把六维 evidence 的 `文件:行` 逐条解析并检查行存在、**禁止 AV:N**，
并要求『不因写大抬分、不因是 0 判无影响』：向量必须是 `I:L`/`A:L`，且 `observed_impact` 必须点明只有 1 字节越界。
