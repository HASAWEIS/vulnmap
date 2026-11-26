# CG-31 / arvo:61675（Exiv2 brotliUncompress，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S16-CG31-arvo-61675/severity.json`；结构校验：`tests/test_severity_61675.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H = 7.1  (high)
```

**不是只算 DoS**：越界写的内容是 brotli 解压流（攻击者编码什么就写什么），长度由 `size_t` 下溢决定（≈1.8e19，实际写到流结束），落点是堆上紧邻的分配。三要素齐了才给 I:H，不是因为"20 万字节很大"。

## 1. 下溢怎么发生（两步，数字可复算）

```c
// workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:192-215
size_t uncompressedLen = compressedBufSize * 2;   // 98303*2 = 196606
size_t total_out = 0;
do {
  arr.alloc(uncompressedLen);                      // :204  DataBuf::alloc = vector::resize（workspace/S16-CG31-arvo-61675/src/exiv2/src/types.cpp:96-98）
  available_out = uncompressedLen - total_out;     // :205  ← 下溢点
  next_out = arr.data() + total_out;               // :206  ← 已经越过缓冲
  result = BrotliDecoderDecompressStream(..., &available_out, &next_out, &total_out);  // :208
  if (result == NEEDS_MORE_OUTPUT) {
    uncompressedLen *= 2;                          // 393212
    if (uncompressedLen > 131072) {                // :214
      if (++dos > 1) break;                        // :215
      uncompressedLen = 131072;                    // ← 第 2 轮把窗口收紧到 131072
    }
  }
} while (...);
```

| 轮次 | uncompressedLen | total_out | available_out | next_out |
| --- | --- | --- | --- | --- |
| 1 | 196606 | 0 → 196606（填满，NEEDS_MORE_OUTPUT） | 196606 | data()+0 |
| 2 | **131072**（被 DoS 上限收紧） | 196606 | **131072 − 196606 → 下溢 ≈1.8e19** | **data()+196606（已越过 196606 字节缓冲）** |

关键点：`DataBuf::alloc` 只是 `vector::resize`（`workspace/S16-CG31-arvo-61675/src/exiv2/src/types.cpp:96-98`），把 size 改小到 131072 并不会把容量/分配缩回去；于是第 2 轮 `next_out` 直接落在 196606 字节分配的**右边界**，而 `available_out` 因为下溢变成一个天文数字，brotli 会一直写下去。

## 2. 写穿了多远

| 事实 | 证据 |
| --- | --- |
| ASAN 报 `WRITE of size 201672` | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:10` |
| 起点在 196606 字节 region 的右边界（0 字节偏移） | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:24` |
| 分类是 container-overflow：边界后先 `fc`（同一分配的 slack）再 `fa`（红区） | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:9`、`:42-46` |
| 另一跑法测到 65534（数值随解压流变化） | 任务记录；本草案按本跑 201672 记 |

也就是说：memcpy 共 201672 字节，其中约 16 字节还在同一分配的 slack 里（所以 ASAN 归为 container-overflow），**其余约 201656 字节落在分配之外**，踩进红区与相邻对象。

## 3. 为什么不是"只算 DoS"

| 要素 | 本例 |
| --- | --- |
| 内容 | brotli 解压流 = 攻击者编码的任意字节（不是 0、不是常量） |
| 长度 | `available_out` 下溢到 ~1.8e19，实际写到解压流结束；本跑 201672，换流可更长 |
| 落点 | 196606 字节堆分配的右边界之后，直接覆盖相邻堆对象 |

三条同时成立 → 这是"可控内容 + 可控长度 + 堆上越界"的内存破坏，而不是单纯的资源耗尽。
反过来，如果只有"解压出很多数据把内存吃光"，那才是 DoS；本例的关键差别是**写在了自己的缓冲之外**。

## 4. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | BMFF 图片解析入口（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:1`、`:6`、`:15-17`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 98339 字节固定 PoC 一次命中，vul exit=1 / fix exit=0（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:2`、`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-fix.log:2`） |
| PR | **N** | 读图片元数据不需要额外权限（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把图片交给 Exiv2（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:6`）；自动批量处理无证据 → 保守 R |
| S | **U** | 影响在 Exiv2 宿主进程内 |
| C | **N** | 只写不读 |
| I | **H** | §3：内容与长度都可控、写越出 196606 字节分配 |
| A | **H** | 20 万字节踩过相邻 chunk：ASAN 下 exit=1（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:2`），真实构建随后 free/分配时崩 |

## 5. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:1`、`:6`、`:15-17` |
| privileges_required | none | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:1-2` |
| user_interaction | required | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:6`、`:15-17` |
| observed_impact | heap_buffer_overwrite_controlled | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:9-11`、`:15`、`:24`、`:42-46`；源码 `workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:194`、`:204-208`、`:214-215`；`workspace/S16-CG31-arvo-61675/src/exiv2/src/types.cpp:96-98` |
| reachability_evidence | confirmed | `workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:15-17`、`:30-39`；`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-fix.log:2,6`；补丁 `workspace/S16-CG31-arvo-61675/patch.diff:30` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:2`、`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-fix.log:2`）；生产消费方与进程形态无证据 |

## 6. 缺证据清单

1. **非 ASAN 构建的后果**：20 万字节堆越界在真实构建里崩在哪、是否被 malloc 检测拦下，未实测。
2. **利用实验**：没有堆布局/后续分配配合的利用尝试（`artifacts/exploit` skipped）；I:H 指"能写坏相邻堆数据"，不等于已取得代码执行。
3. **生产消费者**：谁用 Exiv2 读不可信 BMFF（桌面看图/缩略图服务/批量 extract）。
4. **越界量与流的关系**：本跑 201672、另一跑 65534；没有系统测"解压流越大越界越远"的上界。

## 7. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `I:L`（要求证明改写有意义结构） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` | 6.1 |
| `A:L`（ASAN abort 不外推） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:L` | 6.1 |
| **只算 DoS**（不采纳内容可控） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | 5.5 |
| `UI:N`（自动批量解析） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` | 7.7 |
| `AC:H`（依赖解压流规模） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H` | 6.3 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 8.1 |

## 8. 反方意见

- **「只算 DoS（5.5）」**：越界写完就 abort，看不出能改成什么有意义的东西。**回应**：写的内容是解压流、长度由攻击者控制、落点紧跟缓冲——这三项都可在日志与源码里复核；"能否变成利用"取决于布局，不等于"没有完整性影响"。若团队要求非 ASAN 崩溃实测，退 6.1。
- **「container-overflow 说明还在 capacity 里，不算越界（I:L）」**：**回应**：边界后只有约 16 字节 slack（shadow `fc`），而 memcpy 是 201672 字节，`workspace/S16-CG31-arvo-61675/logs/V4.bmff-brob-98339.61675-vul.log:42-46` 的 shadow 行显示其后就是 `fa` 红区；绝大部分写在分配之外。

## 9. 校验

```
python3 -m pytest tests/test_severity_61675.py -q
```

测试会直接读**日志/源码/补丁**验证 I:H 的依据：日志必须出现 `WRITE of size 201672` 与 `196606-byte region`；
`workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp:194` 必须是 `compressedBufSize * 2`、`:205` 必须是 `available_out = uncompressedLen - total_out`、`:214-215` 必须是 DoS 上限；
`workspace/S16-CG31-arvo-61675/patch.diff:30` 必须包含 `total_out > 131072`（上游正是这样封掉下溢）。
