# vulnmap 最终状态（2026-11-13，口径修订）

## 结论

平台是**规则/构造器驱动的漏洞复现流水线 + 模型辅助循环**；自主挖掘未被证明。

台账为 **9 个高危标记**，其中包含参考复现与待复核项，不是“9 个已验收高危”。

## 台账

```text
cases=30  local_dual_run_pass=23  high=9  causal=6  model_contribution=1  course_ready=0
```

## 9 个高危标记

| 案例 | 路径/性质 | 说明 |
|---|---|---|
| CG-01 | 规则 | 既有 |
| CG-07 | model | 唯一模型路径 |
| CG-14 | builder / **参考复现** | 模板与官方 PoC 同字节；保留高危属性，不计自主生成；是否计入课程 10 例需教师认可 |
| CG-18 | 规则 | 既有 |
| CG-29 | 规则 | 既有 |
| CG-30 | 规则 | 既有 |
| CG-31 | builder | avail.py |
| CG-36 | builder | dwg_table.py |
| VG-01 | 规则 / **待复核** | 仅回环验证；`AV:N` 是待验证假设 |

## 自主性

- 未知任务盲测 4 个，成功 **0**；
- 模型会用 hex，但内容推理错误；
- 见 AUTONOMY-RESULTS / GENERATION-PATH。

## ExploitGym

历史记录声称官方 socket **10/10 PASS**、flag 匹配、`on_target=true`；当前缺少 controller/seed，**未完成原始证据复核与重新验证，官方接受状态待核**。EG-02 与 CG-01 同源，不重复计独立漏洞。

## VG-01 证据边界

- 回环实验可证明该配置下的未授权关机行为；
- 服务器自身不打印请求行；403 状态码由**客户端日志**记录；
- `AV:N` 标为待验证假设，不作为已确认结论。

## 验证

```text
pytest tests -q        842 passed / 4 skipped
check_consistency.py   0 mismatch
```

（842 项为本会话最后一次复跑结果；教师侧未重跑确认。）