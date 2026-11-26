# CG-32 / arvo:58262（matio / HDF5，CWE-122）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`、`reviewed_at=2026-11-12`；无 `_status` 草稿标记。
> 机器可读：`workspace/S16-CG32-arvo-58262/severity.json`；结构校验：`tests/test_severity_58262.py`。未改 `case.json` / `LEDGER.json`。

## 0. 结论

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.3  (low)
```

**I:H 无据，但也不是「只能 DoS」**：这是一次**固定 16 字节**的越界写（写的是 HDF5 的 `hvl_t` 描述符，不是文件原始字节），而且在 glibc 下这 16 字节落在**本 chunk 的可用区**里。

## 1. 机制：缓冲被分配成 0 长度

```c
// workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:739  —— 调用方
hsize_t  nfields=0, nelems;

// workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:615-626
attr_id  = H5Aopen_by_name(dset_id, ".", "MATLAB_fields", ...);
space_id = H5Aget_space(attr_id);
(void)H5Sget_simple_extent_dims(space_id, nfields, NULL);   // :623 标量 dataspace → rank 0，不写 nfields
fieldnames_vl = (hvl_t*)malloc((size_t)(*nfields) * sizeof(*fieldnames_vl));   // :625 nfields=0 → malloc(0)
H5Aread(attr_id, field_id, fieldnames_vl);                  // :626 写入 1 个 hvl_t = 16 字节
```

| 事实 | 证据 |
| --- | --- |
| ASAN：`WRITE of size 16` | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:14` |
| 目标区只有 **1 字节**（malloc(0) 的 ASAN 记账） | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:51` |
| 分配点在 `Mat_H5ReadFieldNames` | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:54`（`workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:625`） |
| 写点在 `H5Aread` → `H5MM_memcpy` | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:16-18`、`:23`（`workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:626`） |
| 上游补丁：rank==0 时把 `*nfields` 置 1，malloc 改 calloc | `workspace/S16-CG32-arvo-58262/patch.diff:22-27` |

## 2. 为什么只有 16 字节（不可放大）

- 标量（scalar）dataspace 只有 **1 个元素**，`H5Aread` 只搬一个 `hvl_t`（`len` + 指针 = 16 字节），这就是日志里的 16。
- 后面的 `for (i = 0; i < *nfields; i++)`（`workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:631`）因为 `*nfields == 0` **一次都不执行**，不存在「按字段数放大」的路径。
- 补丁也印证这一点：修的是「缓冲被分小」（`*nfields = 1`），不是「写入太大」。

## 3. 为什么说它很可能落在 slack 里（A:N 的依据）

| 量 | 值 | 说明 |
| --- | --- | --- |
| 请求大小 | 0 字节 | `malloc(0*16)`（`workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:625`） |
| glibc 最小 chunk | 32 字节 | `malloc(0)` 返回最小 chunk |
| 可用字节 | 24 字节 | `32 − 8`（prev_size 可复用） |
| 越界写范围 | 偏移 1..16 | 起点是 ASAN 的 1 字节边界，长度 16 |
| 是否超出可用区 | **否**（16 ≤ 24） | 因此不触碰下一 chunk 的 header |

ASAN 之所以报错，是因为它按**请求大小**（0/1 字节）划边界；真实 glibc 分配器给了 24 字节可用空间。
注意：换 jemalloc/tcmalloc/硬化 allocator 时可用区可能小于 16，那时才会真的踩到下一块——本轮没有这种构建的实测。

## 4. 为什么不是 I:H，也不是「只算 DoS」

| 主张 | 判定 |
| --- | --- |
| 内容可控 → I:H | 不成立：写的是 `{len, ptr}` 描述符；`len` 来自文件（可控），`ptr` 是 HDF5 内部堆地址（非攻击者选择），不是任意字节 |
| 量大 → I:H | 不成立：固定 16 字节，标量元素只有 1 个，循环不执行 |
| 只算 DoS | 也不成立：没有任何非 ASAN 崩溃实测；`fix` 侧同输入 exit=0（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-fix.log:2`） |
| 取 I:L | 成立：越界写在 ASAN/其它分配器语义下真实存在，内容是含指针的描述符，后果不受控 → 按「证据不足取 I:L」记 |

## 5. 逐维理由

| 维度 | 取值 | 理由 |
| --- | --- | --- |
| AV | **L** | MAT 文件解析入口（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:1`、`:10-11`、`:23-26`），无网络标记 → `AV:L`，**禁 AV:N** |
| AC | **L** | 37240 字节固定 PoC 一次命中，vul exit=1 / fix exit=0（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:2`、`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-fix.log:2`） |
| PR | **N** | 读 MAT 文件不需要额外权限（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:1-2`） |
| UI | **R** | 需要有人/程序把文件交给 matio（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:10-11`）；自动处理无证据 → 保守 R |
| S | **U** | 影响在 matio 宿主进程内 |
| C | **N** | 只写不读 |
| I | **L** | §4：真实越界写，但固定 16 字节、内容为描述符、很可能落在 slack |
| A | **N** | §3：无非 ASAN 崩溃实测；fix 侧 exit=0 |

## 6. 六维证据（逐条可核）

| 维度 | 值 | 证据 |
| --- | --- | --- |
| attack_vector | local | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:1`、`:10-11`、`:23-26` |
| privileges_required | none | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:1-2` |
| user_interaction | required | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:10-11`、`:23-26` |
| observed_impact | heap_buffer_overwrite_16byte_descriptor | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:13-15`、`:23`、`:51`、`:54`；源码 `workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:623`、`:625-626`、`:631` |
| reachability_evidence | confirmed | `workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:18-26`；`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-fix.log:2,12`；补丁 `workspace/S16-CG32-arvo-58262/patch.diff:22-27` |
| deployment_conditions | unproven | 仅两镜像（`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-vul.log:2`、`workspace/S16-CG32-arvo-58262/logs/V4.hdf5-fields-scalar.58262-fix.log:2`）；生产消费方与分配器无证据 |

## 7. 缺证据清单

1. **非 glibc / 小可用区分配的实测**：只有在可用区 < 16 字节时才会踩到下一块；本轮没有这种构建。
2. **非 ASAN 崩溃实测**：A:N 是 slack 推断，不是「跑很多次都不崩」的统计。
3. **生产消费者**：谁用 matio 读不可信 .mat（MATLAB 前端/服务端转换/桌面工具）。
4. **越界量的其它路径**：是否存在非标量 dataspace 走同一段代码、把 16 字节放大（本轮 PoC 是标量）。

## 8. 敏感性（人工裁决备选）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:L`（换分配器可能崩） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.4 |
| `I:N`（slack 吸收＝无完整性影响） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N` | 0.0 |
| `I:H`（描述符越界算改写有意义结构） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 5.5 |
| `I:H`+`A:H`（需放大/踩坏 chunk 的实测） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 7.1 |
| `UI:N`（自动批量转换） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 4.0 |
| **`AV:N`（禁止）** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 5.4 |

## 9. 反方意见

- **「vlen 来自文件、len 可控，应该 I:H（5.5~7.1）」**：回应见 §2/§4：写的是 `{len, ptr}` 描述符、长度固定 16、循环不执行；glibc 下还在本 chunk 可用区内。要 7.1，必须先证明越界可放大或确实踩坏下一块 header。
- **「slack 吸收＝没影响，应 I:N（0.0）」**：回应：越界写在 ASAN 语义和其它分配器下都真实存在，写进去的是含指针的描述符；按「证据不足取 I:L」记 L。若人工接受 slack 结论，I:N = 0.0 也成立。

## 10. 校验

```
python3 -m pytest tests/test_severity_58262.py -q
```

测试会直接读**日志/源码/补丁**验证结论：日志必须是 `WRITE of size 16` + `1-byte region`；
`workspace/S16-CG32-arvo-58262/src/matio/src/mat73.c:739` 必须是 `hsize_t  nfields=0`，`:623` 必须是 `H5Sget_simple_extent_dims`，`:625` 必须是 `malloc(nfields*16)`，`:626` 必须是 `H5Aread`；
补丁必须含 `*nfields = 1;`；并断言 16 ≤ 24（slack 算术）与 `WRITE of size 16`（固定不可放大）。
