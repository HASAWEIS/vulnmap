# 调用点 Agent 沙箱并发 + 简化复核

## 1. 对应 BinSight 的位置

| BinSight | 本实现 | 简化点 |
|---|---|---|
| 危险调用阶段 agent + MCP/IDA | 规则 callsites + 可选 LLM 假设 | 不接 IDA/MCP，只读源码 |
| 每个调用点一个智能体沙箱并发 | `agents.run_analysis` 按 site 分片并发 | 线程池 + 临时工作目录，不是完整 VM |
| 漏洞复核智能体 | `agents.run_reviews` 单次复核 | 不做多轮辩论/多 agent 投票 |
| 四类结论 | confirmed / weakened / excluded / needs_human | 规则优先，LLM 可选 |

## 2. 数据流

```text
D1 call_site 台账
  → 任务切分：每个 site 一个 Task
  → N 个 worker（默认 4）
     每个 worker：临时目录 + 只读源码 + 预算
     输出 hypothesis.json（function/file/line/citations/confidence）
  → 合并排序，交给 D2 fuzz 分配预算

D3 triage 结果
  → 复核任务（默认 2 worker）
  → 单次复核：复现次数 + 读/写 + 根因
  → confirmed / weakened / excluded / needs_human
```

## 3. 隔离与预算

- 每个任务一个 `tempfile.mkdtemp` 工作目录；
- 分析 Agent **不执行目标**，只读源码，避免“分析阶段就把环境跑脏”；
- 复核 Agent 只读 triage 结果，不重新 fuzz；
- 任务级超时 60s，失败不影响整批；
- 并发数可配（2/4/8），按 CPU 与 API 限额。

## 4. LLM 的接入方式（可选）

```python
hypothesis = analyze_site(site, source_root, llm=llm_fn)
```

- prompt 只给：site 元数据、30 行源码窗口、入口可达性；
- 要求输出 JSON：`hypothesis / confidence / citations`；
- `citations` 必须能在源码中解析，否则丢弃该条；
- LLM 不可用或超时，回退 `heuristic_analyze`；
- LLM **不产出 verdict**，verdict 只在复核阶段。

## 5. 复核的简化边界

简化版只做三件事：

1. 复现次数（triage 已给）；
2. 读/写类型（ASAN 已给）；
3. 根因栈哈希是否与候选一致。

不做：二次利用、堆布局、绕过缓解、影响面推断。
因此输出 `weakened` 时明确写“未做二次利用分析”，不冒充高危。

## 6. 数据模型

```text
agent_task(id, campaign, kind, site_id, status, started, finished)
hypothesis(id, task, site_id, function, file, line, confidence, citations)
review(id, crash_id, verdict, access, reproduced, reason)
```

## 7. 指标

- 任务吞吐：sites/min；
- 有效率：hypothesis 中 citations 可解析比例；
- 排序收益：被 Agent 排到前 N 的 site，fuzz 命中率 vs 随机；
- 复核一致性：复核 verdict 与 triage 的一致/推翻比例；
- 成本：每 site 的 token/时间。

## 8. 与现有代码

```text
agent/discovery/agents.py     任务池、分析、复核
tests/test_agents.py          并发与分类测试
```

## 9. 一句话

Agent 只负责“把调用点讲清楚、排好序”，复核只负责“独立判断成不成立”；
执行与验收仍由 fuzz、ASAN、人工门禁完成。