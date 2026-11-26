# LLM vs 规则：调用点分析 A/B 与成本核算

目标：在**同一个调用点**上，把 `--analysis llm` 和 `--analysis heuristic` 摆在一起比，
看两件事——**假设质量**与**要花多少钱**。不跑 fuzz、不看崩溃，避免把 fuzz 噪声
混进分析阶段的结论。

- 脚本：`experiments/analysis_ab.py`
- 输出：`discovery/analysis-ab/results.json` + `discovery/analysis-ab/analysis-ab.md`
- 测试：`tests/test_analysis_ab.py`
- 用量台账：`agent/discovery/agents.py`（`usage_totals()` / `usage_log()` / `usage_delta()`）

## 1. 怎么选点

与 `campaign.run` 同一口径：`callsites.scan` 后按 `score` 降序，每个目标取前
`--max-sites`（默认 5）个。默认排除打包进来的测试树（`tests/`、`fuzzing/`、`test.c`），
否则 cJSON 的 unity 测试源码会抢走名额，比较就没有意义了。

本轮目标：

| 目标 | 调用点 | 说明 |
|---|---:|---|
| `fixtures/discovery`（受控 fixture） | 4 | 长度字段驱动 `memcpy` 写越界 + `fread` 短读 |
| `/tmp/cJSON`（cJSON 1.7.10） | 5 | 80 个候选，排除测试目录后 27 个，取前 5 |

## 2. 指标口径

| 指标 | 定义 | 诚实性约束 |
|---|---|---|
| 耗时 | 分析阶段 wall time（总 / 单点） | `--engine cli` 时是整轮 campaign 时间，侧里标 `engine` |
| hypothesis 有效性 | `citations` 必须解析到源码内真实 `file:line`（`agents.validate_citations`） | 解析不了就不算有效，不看“说得好不好” |
| `seed_count` | 用同一份假设文本跑 `agents.propose_seeds` 得到的结构化种子数 | 两侧同一函数、同一 hint，口径一致 |
| token usage | 只读 API 返回的 `usage`（prompt/completion/total） | 拿不到就是 `-`；全 0 也记 `null`，不补零 |
| 成本 | `tokens × 单价 / 1e6`，单价可配 | 默认单价 0 = **不估算**，`cost` 为 `null`，不写假金额 |

**LLM 产出单独计数**：只有 `llm=true` 的假设进 `llm_hypotheses` / `llm_valid_hypotheses`。
LLM 调用失败（超时/非 JSON/citations 非法）会回退规则分析，这些回退结果记在
`fallback_hypotheses`，**不算 LLM 产出**，也不进 LLM 侧对照——避免把规则输出算成 LLM 的功劳。

## 3. 无 key 的行为

- 环境里没有 key（或 `DISCOVERY_LLM_DISABLED=1`）时，LLM 侧**不发起任何请求**，
  直接记 `skipped: true` / `skip_reason: "no_key"`；
- 该侧 `hypotheses=0`、`tokens=null`、`cost=null`，不拿 heuristic 结果冒充 LLM 结果；
- 规则侧照常跑完，结果完整输出；
- `--engine cli` 时也不会启动子进程（不产生空的 llm 运行目录）；
- 整份 JSON 带 `fingerprint`（剔除耗时/时间戳后 sha256），同样输入跑两次指纹相同，
  可直接拿来验证“可重复”。

## 4. 有 key 的行为

key **只从环境变量读取**，不写入任何输出文件；脚本只记录 key 来自哪个**变量名**
（`environment.key_source_env`），不记录取值：

```
DISCOVERY_LLM_API_KEY / BDVE_LLM_API_KEY / DEEPSEEK_API_KEY / LLM_API_KEY / OPENAI_API_KEY
```

成本估算按每 1M token 单价：

```bash
DISCOVERY_LLM_API_KEY=... python3 experiments/analysis_ab.py \
    --price-input 0.27 --price-output 1.10 --currency USD
```

`cost = prompt_tokens/1e6*price_input + completion_tokens/1e6*price_output`，
另外给出 `cost_per_valid_hypothesis`（每一条有效假设多少钱），
没有 token 或没有单价时该字段为 `null`。

用量台账（`agents.py`）只存白名单字段：`kind`（analysis/review）、`ok`、`attempts`、
`seconds`、`usage`（token 计数）、`error`（固定类别字符串）。**不存 key、不存 header、
不存 prompt/源码原文**；异常文本也不进台账（异常里可能带请求上下文）。

## 5. 本轮实测（无 key）

| 目标 | 侧 | 调用点 | 假设 | 有效假设 | 有效率 | 种子(总/均值) | 耗时(s) | tokens | 成本 |
|---|---|---:|---:|---:|---:|---:|---:|---|---|
| fixture | heuristic | 4 | 4 | 4 | 1.000 | 46/11.5 | ~0.00 | - | 未估算 |
| fixture | llm | 4 | - | - | - | - | - | skipped(no_key) | 未估算 |
| cjson | heuristic | 5 | 5 | 5 | 1.000 | 60/12.0 | ~0.00 | - | 未估算 |
| cjson | llm | 5 | - | - | - | - | - | skipped(no_key) | 未估算 |

结论（`comparison.overall.verdict = llm_not_run`）：

> LLM 侧未运行（无 key）：本轮**只有规则侧基线**，不写任何 LLM 优劣结论。
> 补上 key 后重跑同一条命令即可得到对照数据，脚本会自动按差值门槛给判定。

## 6. 判定规则：不预设 LLM 更好

`_target_verdict` 只看数据：

| 条件 | verdict | 文案口径 |
|---|---|---|
| LLM 侧 skipped | `llm_not_run` | 没有 LLM 数据，不构成对照 |
| LLM 有效假设 0 条 | `llm_no_output` | 按负结果保留 |
| LLM 有效假设 − 规则 ≥ 2 | `llm_advantage` | 只算“初步信号”，明写样本量小、需复核 |
| 规则有效假设 − LLM ≥ 2 | `rule_advantage` | LLM 未体现优势 |
| 其余 | `no_significant_difference` | 差异在噪声内，不主张任何一侧有优势 |

门槛默认 2 条（可在 `_target_verdict(margin=...)` 调整），目的就是防止“5 个调用点上
多一条假设”被写成结论。

## 7. 已知限制

- **样本量小**：每目标 5 个调用点、2 个目标，只能看方向，不能当统计结论；
- **有效性 ≠ 正确性**：`citations` 可解析只说明引用真实存在，不说明假设成立；
  假设是否成立仍由 fuzz + triage 决定（本脚本刻意不碰）；
- **token 依赖供应商**：部分兼容端点不回 `usage`，此时 `tokens=null`、`cost=null`，
  脚本不会用文本长度估算；
- **耗时不可跨机器比**：只有同机、同 worker 数的两次运行才可比。

## 8. 复现

```bash
# 无 key：LLM 侧 skipped，规则侧基线可重复（指纹相同）
python3 experiments/analysis_ab.py

# 只跑一侧
python3 experiments/analysis_ab.py --analysis heuristic --max-sites 3

# 有 key：真实 token + 成本
DISCOVERY_LLM_API_KEY=... python3 experiments/analysis_ab.py --price-input 0.27 --price-output 1.10

# 走真实 CLI 的 --analysis 路径（bin/discover.py）
python3 experiments/analysis_ab.py --engine cli --max-sites 3

# 测试
python3 -m pytest tests/test_analysis_ab.py -q
```

## 9. 改动清单

| 文件 | 改动 |
|---|---|
| `agent/discovery/agents.py` | 新增用量台账 `record_usage/usage_log/usage_totals/usage_delta`、`llm_model()`、`validate_citations()`；`_llm_json` 每次调用记台账（不记 key/prompt）；token 白名单扩展到缓存/推理字段 |
| `agent/discovery/campaign.py` | `campaign.json` 的 `analysis` 增加 `llm_usage`（本次分析阶段净用量） |
| `experiments/analysis_ab.py` | 新增 A/B 脚本：选点、双模式分析、指标、成本、JSON/Markdown |
| `tests/test_analysis_ab.py` | 新增 12 个测试：无 key 跳过、可重复、成本算术、token 真实记录、失败不冒充 LLM、citations 校验、结论不夸大 |
