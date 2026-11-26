# 自主性实验结果（2026-11-13）

## 未知任务盲测汇总（4 个任务）

| 任务 | 模型是否用 hex | 是否命中 |
|---|---|---|
| arvo:10013 TIFF | 否（旧代码） | 否 |
| arvo:59884 PDF | 否（recipe 失败） | 否 |
| arvo:10341 harfbuzz | 否（text） | 否 |
| arvo:10628 botan | **是**（hex 2/3） | 否（1B/4B/6B，非 3B） |

**未知任务模型成功率：0/4。**

## v9/v10 更正：raw_reply 为准

`rounds[].encoding` 曾被 data 可解码性覆盖，把 hex 标成 text/base64；`transcript[].raw_reply` 才是原文。

| 轮次 | 原始回复 | 实际字节 |
|---|---|---|
| v10-r1 | encoding=hex, content=00 | 1 字节 0x00 |
| v10-r2 | encoding=hex, content=3082010a... | 147 字节 DER 猜测 |
| v10-r3 | encoding=hex, content=308200010200 | 6 字节 ASN.1 长度探测 |

模型确实在使用 hex（v9/v10），失败在内容推理：官方 PoC 只需 3 个零字节，模型从未给出。

## 已修（通用，不含任务专用分支）

- `allow_builders=false` 强制模型路径；
- binary 格式在解析层拒收 text/base64，反馈带中性 hex 示例 414243；
- 无 claim 时 fallback 假设；
- `rounds.encoding` 不再覆盖真实值；`transcript.raw_reply` 保留原文。

## 结论

接口与编码层已打通，模型能自主选择 hex；但二进制内容推理仍失败。当前不能宣称自主挖掘能力，只能算“模型辅助 + 通用接口”的复现平台。