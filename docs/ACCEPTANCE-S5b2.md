# S5-b2 阶段验收报告（2026-11-11）

审查对象：S5-b2「种子语料与失败反馈」——CG-09 / arvo:53666
审查方式：代码 + 测试 + 运行记录逐轮核对
结论：**S5-b2 未通过**——种子机制成立，但 loop 退化为 3 轮 `llm_incomplete`，比上一轮更差

---

## 1. 做对的部分

- `agent/harness.py` 新增种子提取，从 `krb5/src/tests/misc/test_chpw_message.c` 还原出 8 条：
  - `result_utf8` 23B（可打印 ASCII）
  - `result_invalid_utf8` 19B（含 NUL）
  - `result_ad_complex/length/history/all` 30B（结构化 AD 字段）
- 长度过滤生效：19B 低于 `min_size=20` 被丢弃，其余在 [20,100] 内；
- 3 条种子被注入 loop（`seeds_used` 有名字、sha256、结构注释）；
- 测试：**349 passed / 6 skipped / 0 failed**。

## 2. 失败的部分（回归）

| 轮次 | 尺寸 | sha | verdict |
|---|---|---|---|
| 1 | 0 | — | `llm_incomplete` |
| 2 | 0 | — | `llm_incomplete` |
| 3 | 0 | — | `llm_incomplete` |

- 没有任何候选被执行（size=0，无输入 sha）；
- 对比 S5-b1：那轮至少执行了 100B/45B 两个候选；本轮**一步都没走**；
- `attempts.detail.llm` 的 verify 记录里 `status/finish_reason/tokens` 全为空，说明失败发生在“解析模型输出”之前，且没有被记录。

## 3. 根因假设（按可能性排序）

1. **提示过长导致输出截断**：种子的 hex + 结构注释把 prompt 撑大，`max_tokens=1200` 下模型输出不完整，JSON 解析失败 → 记 `llm_incomplete`；
2. **种子块格式没被模型理解**：hex 与结构注释混排，模型改写成自然语言，缺少可执行字段；
3. **失败未落 finish_reason**：即使截断，也应把 `finish_reason=length` 写进 detail。

> 复核结果：子智能体后续确认 3 轮均为 `llm_incomplete`、`finish_reason=length`、completion 打满 8000 token（prompt≈2033）。B5 = **种子块导致输出啰嗦化并触顶**，已坐实；修法是输出纪律 + 降载重试，不是再加种子。

## 4. 结论

- 种子提取是有效资产（8 条、来源可追、长度过滤正确），可以保留；
- 但“把种子塞进 prompt”这一步没有收敛，反而让 loop 退化；
- 下一步必须先修可观测性（记录 finish_reason 与原始输出），再把种子块压到 1 条、提高 max_tokens，否则重跑只是重复失败。

**一句话：种子找对了，但喂法把模型噎住了；先让失败可诊断，再谈触发。**