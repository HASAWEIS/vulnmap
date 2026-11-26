# V3 真实模型只读 A/B（V3-REAL-AB）

> 范围：`agent/platform/adaptive/llm_provider.py`、`agent/platform/adaptive/real_ab.py`、
> `agent/platform/adaptive/compare.py`（只加 `provider_kind="real"` / `"simulated"` 分支）、
> `tests/test_v3_real_ab.py`、本文。
> 纪律：不改 `verify/`、`benchmark_policy`、执行器、DB schema、写端点；不 `git commit`。
> 所有数字都来自本机重跑；没有真实模型结果时**不填数**。

## 0. 结论先行

| 问题 | 答案 | 依据 |
|---|---|---|
| 本轮是否跑了真实模型？ | **否** | 运行环境有 endpoint/model，但**没有任何 API key 环境变量**；`real_model_status="blocked"`、`missing_env=["VULNMAP_LLM_API_KEY"]`、`summary=None` |
| 是否可开放自动应用？ | **否** | `auto_apply` 恒 `False`；错误采纳 > 0 一票否决；应用仍走 `handoff.ProposalGate`（未验收恒 `advisory`） |
| 真实通路是否可用？ | **是，但只在有 key 时** | 默认 `urllib` 通路已用本地 HTTP fixture 实测 `POST /v1/chat/completions`；本地 fixture 的 `endpoint_source="simulated"`（本地 HTTP 只证明通路，不证明真实模型） |
| mock 结果是否与真实混算？ | **否** | mock 文档 `mocked=true` + `real_model_status="mocked"`；`mocked` / `simulated` / `ran` 三态互斥 |
| 显式 `max_usd` 但无单价，会不会照跑？ | **不会** | `max_usd` 一律下发到 `ProviderConfig`；provider 在传输前拒绝（`environment_error/price_unknown`），传输 **0 次**、`calls_invoked=0`，状态是 `blocked` 不是 `ran` |
| 注入内存 transport（测试替身）会被记成真实模型吗？ | **不会** | provider 记 `transport="injected"` / `result_source="simulated"` / `real_model=False`；runner 走 `simulated` 分支，即使 `calls_ok>0` 也不进真实统计 |
| 默认 urllib 打本地 HTTP fixture 会被记成真实模型吗？ | **不会（本轮修复）** | `transport="urllib"` 只说明怎么发；`classify_endpoint("http://127.0.0.1:…")` → `endpoint_source="simulated"`、`simulated_reason="local_endpoint"`、`result_source="simulated"`。A/B 端到端是 `real_model_status="simulated"`、`summary_scope="simulated"`，不是 `ran/real` |
| `real_model_status="ran"` 能证明真实模型被调用吗？ | **只在 `result_source="real"` 时能** | `result_source="real"` 的必要条件：没注入 transport + 默认 `urllib` + **public HTTPS** endpoint；`transport` / `endpoint_source` / `result_source` 三者一起读（见 §2.6、§3.5） |

一句话：**框架和门禁已就绪，真实模型这一轮被环境挡住**。挡住就报 blocked，
不编 0 调用、不编 tokens、不编费用，也不把 mock 结果写成“真实模型有收益”；
钱的上限只要给了，就一定会生效——无单价时连一次传输都不发生。

---

## 1. 改动边界

| 文件 | 变化 | 行数 |
|---|---|---|
| `agent/platform/adaptive/llm_provider.py` | 真实 OpenAI-compatible 只读 provider（env key、超时/预算/结构化错误、密钥卫生）；**来源口径**：新增 `classify_endpoint()`，`transport`（怎么发）/ `endpoint_source`（发给谁）/ `simulated_reason`（机读理由）/ `result_source`（能否进真实统计）；本地 HTTP 仍发请求但 `real_model=False`、`simulated=True`；`status()`/`snapshot()`/调用摘要都带这些字段；预算门禁：`blocked_reason/blocked_reasons/price_unknown` | 984 |
| `agent/platform/adaptive/real_ab.py` | A/B runner（blocked/mocked/simulated/ran/failed 五态）；**来源路由**：`provider=None` + 默认 `urllib` + **public HTTPS** 才进真实分支；本地/私网/非 HTTPS 与注入 transport 一律 `simulated` 分支（`summary_scope="simulated"`、`real_model=false`、`result_source="simulated"`），mock 仍走 `mocked`；blocked 文档带 `blocked_reason` 与 0 次传输记账；互斥自检扩到 `result_source` / `endpoint_source` | 620 |
| `agent/platform/adaptive/compare.py` | 追加 `AB_PROVIDER_KINDS` / `AB_REAL_PROVIDER_NOTE` / `_ab_is_simulated_provider`，`run_ab` / `_ab_gate` 增加 `provider_kind` 参数（`offline` / `real` / `simulated`），`arms.model` 增 `transport` / `result_source` / `simulated`；默认仍是 `offline` 硬门 | 2320 |
| `tests/test_v3_real_ab.py` | 19 个用例，全部不联网（本地 HTTP fixture 除外，绑定 127.0.0.1）；新增 endpoint 来源矩阵、本地 HTTP status、本地 HTTP 端到端 `simulated`、public HTTPS status 四个用例 | 900 |
| `docs/V3-REAL-AB.md` | 本文 | — |

**未改**：`agent/platform/verify.py`、`benchmark_policy`、`adaptive/session.py`、
`adaptive/policy.py`、`adaptive/handoff.py`、`adaptive/controller.py`、工具表、
执行器、DB schema、任何写端点。`adaptive/compare.py` 的 P4b 段与 W4 默认口径
（`offline=True` 硬门、`auto_apply=False`、`verdict="not_evaluated"`）未改。

---

## 2. provider：真实、只读、可审计

### 2.1 环境变量（key 只从这里来）

| 用途 | 变量（按优先级） | 必要性 |
|---|---|---|
| key | `VULNMAP_LLM_API_KEY` → `DISCOVERY_LLM_API_KEY` → `BDVE_LLM_API_KEY` → `DEEPSEEK_API_KEY` → `LLM_API_KEY` → `OPENAI_API_KEY` | **必要** |
| base URL | `VULNMAP_LLM_BASE_URL` → `DISCOVERY_LLM_BASE_URL` → `LLM_BASE_URL` → `BDVE_LLM_ENDPOINT` → `OPENAI_BASE_URL` | **必要** |
| model | `VULNMAP_LLM_MODEL` → `DISCOVERY_LLM_MODEL` → `BDVE_LLM_MODEL` → `LLM_MODEL` → `OPENAI_MODEL` | **必要** |
| 超时 / 预算 | `VULNMAP_LLM_TIMEOUT`、`VULNMAP_LLM_MAX_CALLS`、`VULNMAP_LLM_MAX_TOKENS`、`VULNMAP_LLM_MAX_USD` | 可选 |
| 价格表 | `VULNMAP_LLM_PRICE_IN_PER_1K`、`VULNMAP_LLM_PRICE_OUT_PER_1K` | 可选；没有就记“金额未知” |

- base URL 里的 `/chat/completions` 会被归一，再拼回一次；不重复拼。
- **无 key / 无 base / 无 model** → `status()["real_model_status"]="blocked"`，
  `missing_env` 用统一逻辑名逐项列出；`__call__` 不发请求，只回结构化错误。
- `ProviderConfig(api_key=...)` 是测试 seam；产品路径 `run_real_ab()` 只经
  `provider_from_env()` 读环境，不读文件、不读 CLI 参数、不落盘 key。

### 2.2 status 形状（可安全进报告）

```json
{
  "provider": "RealChatProvider",
  "kind": "openai_compatible_chat",
  "real_model": true,
  "read_only": true,
  "mocked": false,
  "simulated": false,
  "transport": "urllib",
  "result_source": "real",
  "endpoint_source": "real",
  "endpoint_scheme": "https",
  "endpoint_host_kind": "public",
  "simulated_reason": "",
  "simulated_reasons": [],
  "real_model_status": "ready",
  "blocked_reason": "",
  "blocked_reasons": [],
  "price_unknown": false,
  "max_usd_requires_price": false,
  "missing_env": [],
  "key_present": true,
  "key_ref": "env:VULNMAP_LLM_API_KEY",
  "base_url_host": "api.deepseek.com",
  "model": "deepseek-v4-pro",
  "budget": {"max_calls": 12, "max_tokens": 16000, "max_usd": null,
             "price_known": false},
  "writes": []
}
```

`key_ref` 只是“哪来的引用”；`base_url_host` 只到 host，不带 path/query。
`writes` 恒为空：provider 没有写状态/证据/判据的路径。

`ready` 之外一律 `blocked`，且 blocker 是机读的：

| `blocked_reason` | 条件 | `missing_env` | 能否发请求 |
|---|---|---|---|
| `""` | 三件齐 + （没有 `max_usd` 或单价已知） | `[]` | 能（`ready`） |
| `missing_env` | 缺 key/base/model | 缺哪项列哪项 | 不能 |
| `price_unknown` | 设了 `max_usd` 但没有 `PRICE_IN/PRICE_OUT` | 追加 `VULNMAP_LLM_PRICE_IN_PER_1K`、`VULNMAP_LLM_PRICE_OUT_PER_1K` | **不能（传输前拒绝）** |

两者同时命中时 `blocked_reasons` 两条都列，`blocked_reason` 取
`price_unknown`（钱的门禁是可验证的硬约束，先报它），`missing_env` 仍逐项列全。

### 2.3 返回值与错误码

成功：

```json
{
  "status": "ok",
  "diagnosis": {"code": "execution_error"},
  "actions": [{"action": "get_execution_facts", "params": {}}],
  "reason": "...",
  "usage": {"tokens_in": 120, "tokens_out": 40,
            "prompt_tokens": 120, "completion_tokens": 40,
            "total_tokens": 160, "usage_known": true},
  "usd": null,
  "meta": {"model": "...", "read_only": true, "call_id": "call-0001"}
}
```

失败/拒绝（稳定机读码，另带 `error_detail`）：

| `error` | 触发 | 备注 |
|---|---|---|
| `missing_env` | 缺 key/base/model | 不发请求 |
| `timeout` | 传输超时 | `retryable=true`；是否重试由上层决定 |
| `network_error` / `http_401` / `http_403` / `http_429` / `http_error` | 网络/HTTP | 429/5xx 标 `retryable` |
| `invalid_json` / `empty_response` / `protocol_error` | 回包不是合法 JSON 对象 / content 为空 | 不猜内容 |
| `secret_in_output` | 回包出现 key 原文 | 整条丢弃并脱敏，不缓存 |
| `price_unknown` | 设了 `max_usd` 但无单价 | **传输前拒绝**：`calls_invoked=0`、transport 0 次、`invoked=false`，不谎称成本受控 |
| `budget_exhausted` | `max_calls` 触顶（调用前）或 tokens/usd 触顶（调用后） | 该次及后续返回结构化预算错误 |

### 2.4 预算与“金额未知不是 0”

- 调用**前**先判钱（`max_usd` + 单价），再判 `max_calls`（可数）；
- 调用**后**按 provider 的 usage 累计 tokens；超了只影响下一次（与
  `llm_gateway` 的 reserve→settle 同构）；
- 没有价格表 → `usd=null`、`usd_known=false`；A/B 的 `model_usd` 指标是
  `known=false` / `reason="model_unknown"`，**不是 0 元**；
- 设了 `max_usd` 却没有单价 → `status()` 直接 `blocked/price_unknown`，
  `__call__` 在拼请求之前返回 `environment_error/price_unknown`，传输 0 次；
- **`max_usd` 不在 runner 里做过滤**：`real_ab._provider_with_budget()` 把
  `budget.max_usd` 原样写进 `ProviderConfig`（`price_known` 只决定能不能跑，
  不决定要不要守上限）。早先的实现只在单价已知时才传 `max_usd`，结果是
  “设了 0.01 美元的上限却没生效、调用照跑还记 `ran`”——这条已作为回归
  用例锁死（§4 用例 9/10）。

### 2.5 密钥卫生

- key 只在构造请求头时作为局部变量出现一次；provider **不保存** `Authorization`；
- `status()` / `snapshot()` / `log` 里没有 key，也没有 header；
- 回包若回显 key → `secret_in_output`，整条结果丢弃；
- `real_ab.assert_no_secret_material()` 在落盘前再扫一遍（`Bearer `、
  `"authorization":`、`api_key=`），命中即拒绝写盘；
- `ProviderConfig` 的 `repr` 与 `to_dict()` 都不含 key。

### 2.6 来源口径：`transport`（怎么发）vs `endpoint_source`（发给谁）

早先的口径只有一个判据：`real_model=True`（写在类上）+ `calls_ok>0`。
于是 `RealChatProvider(transport=内存替身)` 这种**一次外网都不发**的实例，
照样被 runner 记成 `real_model_status="ran"`、`summary_scope="real"`。
上一轮把“注入 transport”分流到 `simulated`，但还漏了一件事：

> `transport="urllib"` 只说明请求**怎么发**，不证明响应**从哪来**。
> 默认 urllib 打到 `http://127.0.0.1:PORT/v1` 的本地 fixture，请求确实发出去了，
> 响应却来自本地假模型——它必须算 `simulated`。

本轮把来源拆成两个正交字段，并新增 `endpoint_source` / `simulated_reason`：

| 字段 | 回答的问题 | 取值 |
|---|---|---|
| `transport` | 请求是怎么发的？ | `"urllib"`（默认网络传输）/ `"injected"`（构造时注入的测试替身） |
| `endpoint_source` | endpoint 本身允许算真实来源吗？ | `"real"`（仅 public HTTPS）/ `"simulated"`（本机、私网、link-local、非 HTTPS） |
| `simulated_reason` | 为什么不是真实来源？ | `local_endpoint` / `private_endpoint` / `non_https_endpoint` / `injected_transport`（机读码） |
| `result_source` | 这次结果能不能进真实统计？ | `"real"` 当且仅当未注入 transport **且** `endpoint_source="real"`；否则 `"simulated"` |

`classify_endpoint(base_url)` 的判定（不查 DNS，只按字面；`*.localhost` 也算本机）：

| endpoint | `endpoint_source` | `simulated_reason` |
|---|---|---|
| `https://api.example.test/v1` | `real` | `""` |
| `http://api.example.test/v1` | `simulated` | `non_https_endpoint` |
| `http://127.0.0.1:PORT/v1`、`https://localhost/v1`、`https://[::1]/v1`、`http://0.0.0.0:PORT/v1` | `simulated` | `local_endpoint` |
| `https://10.x` / `192.168.x` / `172.16–31.x`、link-local（`169.254.x`、`fe80::/10`）、CGNAT/保留段 | `simulated` | `private_endpoint` |
| `https://8.8.8.8/v1` 等 public IP | `real` | `""` |

优先级：`local` > `private`/`link-local` > `non-HTTPS`。所以
`http://127.0.0.1` 报更具体的 `local_endpoint`，`http://10.0.0.5` 报
`private_endpoint`，`http://api.example.test` 才报 `non_https_endpoint`。

组合后的来源矩阵：

| 构造方式 | `transport` | `endpoint_source` | `result_source` | `real_model` | `simulated` | 能进真实统计吗 |
|---|---|---|---|---|---|---|
| `RealChatProvider(cfg)` + public HTTPS | `"urllib"` | `"real"` | `"real"` | `true` | `false` | **能**（仍受 §3.5 其余口径约束） |
| `RealChatProvider(cfg)` + 本地/私网/非 HTTPS | `"urllib"` | `"simulated"` | `"simulated"` | `false` | `true` | **不能**：HTTP 真发了，只证明通路可用 |
| `RealChatProvider(cfg, transport=...)`（任意 endpoint） | `"injected"` | 按 endpoint | `"simulated"` | `false` | `true` | **不能**，一律记 `simulated` |

- **本地 HTTP 不被禁止发请求**：provider 照样 POST（用于验证通路、header、
  usage 解析），只是 `result_source="simulated"`，结果不进真实统计；
- `status()["real_model_status"]` 仍只表达**能不能跑**（`ready` / `blocked`），
  来源看 `transport` / `endpoint_source` / `result_source`，三者不混用同一字段；
- `status()`、`snapshot()`、`snapshot()["log"]` 每条、A/B 文档、artifact 都带
  `endpoint_source` 与 `simulated_reason`，所以报告里不会只剩一个“ran”；
- 类级别的 `real_model` 常量（`llm_provider.REAL_MODEL`）仍然存在，但**不再**
  作为实例判据：实例属性覆盖它，本地 HTTP 或注入 transport 的实例读出来就是
  `false`。

> 注意：`tests/` 里替换模块级 `llm_provider._urllib_transport` 是“换默认传输槽位”
> 的测试 seam；若 endpoint 仍是 public HTTPS，来源仍记为 `urllib`/`real`
> （§4 用例 14 用它验证真实分支没被误伤）。要标成模拟，要么注入 `transport=`，
> 要么把 endpoint 换成本地/私网/非 HTTPS。
>
> 第三方真实 provider 若没声明 `transport` / `endpoint_source`（鸭子类型，本仓库
> 不用），文档里记 `transport="declared"` / `endpoint_source="declared"`：只表示
> 它自称真实来源，无法核对传输层与 endpoint，不作为真实证据。

---

## 3. A/B runner：同一份输入，两条决策路径，五种来源状态

### 3.1 状态机

```text
blocked   ── 无 key/base/model（blocked_reason=missing_env），或 max_usd 无单价
             （blocked_reason=price_unknown）：不跑、summary=None、
             provider_trace=[]、provider_budget 全 0/None（0 次传输的记账）
mocked    ── 显式注入 mock provider：mocked=true，real_model_status="mocked"，
             cost_is_fake=true，与 ran/real 互斥
simulated ── 模拟来源，两种入口：
             (a) 显式注入 transport 的 RealChatProvider（测试/本地替身）：
                 transport="injected"、simulated_reason 含 injected_transport；
             (b) 默认 urllib 打到本机/私网/非 HTTPS endpoint（本地 HTTP fixture）：
                 transport="urllib"、endpoint_source="simulated"、
                 simulated_reason=local_endpoint / private_endpoint /
                 non_https_endpoint——请求真的发了，但响应不算真实模型。
             两者都是 result_source="simulated"、real_model=false、simulated=true、
             summary_scope="simulated"；**即使 calls_ok>0 也绝不记 ran/real**
ran       ── 真实来源（transport="urllib" + endpoint_source="real" +
             result_source="real"）至少一次成功调用（calls_ok>0），
             **仅此而已**（见 §3.5）
failed    ── 真实来源但有调用都失败（calls_ok==0）
```

- 五态互斥，写在同一字段 `real_model_status`；`mocked` / `simulated` 另有顶层
  布尔，`summary_scope` 取 `null / "mock" / "simulated" / "real"` 标明指标归属；
  顶层 `result_source` 取 `real / simulated / mock / none`，`transport` 取
  `urllib / injected / offline_fake`（provider 没声明时为空串），
  `endpoint_source` 取 `real / simulated / declared`（provider 没声明时为空串，
  文档里记 `declared`）；
- **只有 `provider=None`（或 provider 未声明注入来源）+ 默认 `urllib` +
  public HTTPS endpoint** 才可能进 `ran`/`failed`；
- 显式传入的 `RealChatProvider` 若带注入 transport，一律走 `simulated` 分支，
  哪怕它 `read_only=True`、key 齐全、`calls_ok=10`；
- 默认 `urllib` 但 endpoint 是 `127.0.0.1`/localhost/私网/非 HTTPS 时，同样走
  `simulated` 分支：`transport="urllib"`、`endpoint_source="simulated"`、
  `summary_scope="simulated"`——**transport 不证明来源**；
- `compare.run_ab` 为此新增 `provider_kind="simulated"`：门禁检查
  `read_only_simulated_provider`（`read_only=True` + `offline=False` +
  `result_source="simulated"`），与 `read_only_real_provider` 互不替代；
- 互斥不是口头约定：`run_real_ab()` 返回前跑 `_check_status_exclusive()`，
  出现 `mocked=true` + `ran`、`simulated=true` + `ran/real`、
  `result_source="real"` 却不是 `ran/failed`、`result_source="real"` 却声明
  `endpoint_source="simulated"`/`transport="injected"`、`result_source="simulated"`
  却带 `real_model=true` 等组合直接抛 `RealABError`（不落盘、不返回）；
- mock 走原 W4 的 `offline=True` 硬门；三种口径都不会让 `auto_apply` 变成 True。

### 3.2 回归集与预算

- 默认回归集仍是 `compare.ab_regression_tasks()` 的 10 条无害任务
  （10 个诊断码 + 2 个已知规则盲区）；
- 真实小预算跑用 `small_ab_tasks()`：8 条任务
  （`w4-t01/t02/t03/t05/t07/t08/t09/t10`），保持原顺序；
- `SMALL_BUDGET = {max_rounds: 2, max_calls: 12, max_tokens: 16000, max_usd: null}`；
- 两臂仍吃**同一份** `controls`：回归集 / 初始配置 / 预算 / 人工规则只定义一次，
  `arms_share_controls=true`；A 臂仍是延迟导入的 `DiagnoseRole` +
  `ResearchSession.propose`，没有第二份规则表。

### 3.3 指标与门禁（继承 W4，不放松）

七项指标不变：正确诊断数 / 无效重试 / 耗时 / 模型调用 / tokens / 费用 / 错误采纳；
四条保留类不变：环境错误 / 无建议 / 建议被拒 / 预算耗尽（`correct=None`，不进分母）。

真实 provider 的门禁检查把 `offline_provider` 换成 `read_only_real_provider`：

| 检查 | 通过条件 |
|---|---|
| `no_model_wrong_adoption` | `wrong_adoptions.model == 0`（一票否决） |
| `answered_coverage` | 作答比例 ≥ `min_answered_ratio`（默认 0.8） |
| `no_task_regression` | 不存在“规则答对而模型答错”的任务 |
| `stable_gain` | 每个分层（奇/偶位）的增益都 > 0 |
| `read_only_real_provider` | `real_model=True` + `read_only=True` + `offline=False` |
| `engine_available` | 规则引擎可导入 |

`auto_apply` 恒 `False`；`gate.auto_apply_blockers` 至少含
`proposal_gate:advisory`。门禁通过只说明“下一轮默认建议源可换成模型”，
不授予任何写权限。

### 3.4 不伪造

- `blocked` 文档里没有 `summary`、没有 `model_calls`、没有 `model_tokens`、
  没有 `model_usd`；`provider_trace=[]`；
- `blocked` 文档里的 `provider_budget` 是**“没有发生传输”的记账**
  （`calls_seen/calls_invoked/calls_ok/tokens_in/tokens_out = 0`、
  `usd=null`、`usd_known=false`、`exhausted=""`），可核对但不进指标；
  它不是“跑过且免费”；
- mock 文档的 `note` 与 `provider_status` 明确写 `mocked=true`、
  `cost_is_fake=true`；其费用是 `FakeProvider` 的**构造参数单价**，不是账单；
- `simulated` 文档有 `summary`（指标可算、可对比），但 `summary_scope="simulated"`、
  `real_model=false`、`result_source="simulated"`；`note` 按来源分两种写法：
  注入替身写“不产生外网调用”，本地 endpoint 写“HTTP 确实发出但响应不证明真实
  模型”——两者都明写“不计入真实统计”，**不能**被引用成模型收益；
- `ran`/`failed` 的 `provider_trace` 只有请求摘要（model/host/observation 哈希）、
  响应摘要（诊断/动作名/哈希）、usage、秒数与错误码，没有 prompt 原文与 header。

### 3.5 `ran` 的口径：来源先过关，`calls_ok` 只是第二道

`ran` 现在有三道判据，缺一不可：

1. **传输来源**：没注入 transport、走默认 `urllib`（`transport="urllib"`）；
2. **endpoint 来源**：`endpoint_source="real"`，即 public HTTPS——本地/私网/
   非 HTTPS 在这一步被分流到 `simulated`；
3. **发生过成功调用**：`provider.snapshot()["calls_ok"] > 0`（失败则是 `failed`）。

所以两个旧口子都已关掉：内存假传输、以及“默认 urllib 打本地 HTTP fixture”，
现在都是 `real_model_status="simulated"`、`summary_scope="simulated"`。但 `ran`
仍**不**等于“真实模型给了有价值的建议”，以下问题还要另看字段：

| 问题 | 单看 `ran` 能回答吗 | 要看什么 |
|---|---|---|
| 走的是真实网络还是替身？ | **不能只看 `transport`，看 `endpoint_source`/`result_source`** | `transport="urllib"` 只说明怎么发；还要 `endpoint_source="real"` + `result_source="real"`。本地 HTTP 也是 `urllib`，但来源是 `simulated` |
| 有没有真的花钱？ | **不能** | `provider_budget.usd`（`usd_known=false` 就是没单价、金额未知，不是 0）+ `provider_status.budget.price_known` |
| 打到的是哪个 endpoint？ | **不能，但能看来源类别** | `provider_status.base_url_host` + `provider_trace[*].request.url_host`（只有 host，没有 path/query/key）+ `endpoint_source`/`simulated_reason` |
| key 真的来自环境吗？ | **不能** | `provider_status.key_ref`（`env:...`）与 `key_present` |
| 结果能不能当收益证据？ | **不能** | `mocked`、`simulated`、`summary_scope`、门禁 `reasons`；`auto_apply` 恒 `False` |
| mock/替身有没有混进来？ | **不能** | `mocked`（必须 `false`）+ `simulated`（必须 `false`）+ `result_source="real"` |

本仓库的口径因此固定为四句话：

1. **来源先行**：只有 `transport="urllib"` + `endpoint_source="real"` +
   `result_source="real"` 的运行才进真实统计；注入 transport 或本地/私网/非 HTTPS
   endpoint 一律 `simulated`（`summary_scope="simulated"`）；
2. **`ran` 仍只是“provider 成功返回过”**：是必要条件，不是“有价值”的证明；
3. **真实调用 = `ran` + `result_source="real"` + `transport="urllib"`
   + `real_model=true` + `mocked=false` + `simulated=false`
   + trace 里的 host 与 `key_ref` 对得上 + 费用口径（`usd_known`）说清楚**；
4. **报告里不许只写 `ran`**：必须带上 `result_source` / `transport` /
   `provider_status` / `provider_budget` / `provider_trace`，否则读不出
   “真的调了没有、是不是替身、花了多少”。

`blocked`（含 `price_unknown`）连“成功返回”都没有：`calls_ok=0`、
`provider_trace=[]`、`summary=null`，所以更不能被写成任何收益。

---

## 4. 测试

`tests/test_v3_real_ab.py` 共 **19** 个用例，全部不联网（除绑定
`127.0.0.1` 的本地 HTTP fixture）：

| # | 用例 | 断言要点 |
|---|---|---|
| 1 | `test_blocked_without_key_never_fabricates_results` | `blocked`、`missing_env` 精确（单缺 key / 三件全缺）、`summary=None`、`provider_trace=[]`、不出现 `"model_calls": 0`、门禁默认规则 |
| 2 | `test_mock_is_tagged_and_never_mixed_with_real` | `mocked=true`、`real_model_status="mocked"`、`result_source="mock"`、`simulated=false`、`cost_is_fake=true`、指标可算但与 `ran` 互斥 |
| 3 | `test_simulated_provider_is_read_only_and_strips_verdict_fields` | 注入 transport 的只读：运行期 `Path.write_text/write_bytes/mkdir` 全被替换成抛错 → 仍然跑通（无写盘）；夹带 `verified/confirmed` 的动作被剥离并进 `rejected`；文档 `simulated` + 无裁决字段 |
| 4 | `test_wrong_adoption_blocks_simulated_gate` | 替身提 gold 禁止的 `run_epoch` → `no_model_wrong_adoption` 一票否决、`default_arm="rules"`、`read_only_simulated_provider=true`、`auto_apply=False` |
| 5 | `test_key_never_reaches_doc_log_or_artifacts` | key 不进 doc / provider log / 落盘 JSON / markdown；`key_ref` 只到环境变量名；artifact 里 `result_source="simulated"` + `transport="injected"`；`ProviderConfig` 的 `repr`/`to_dict()` 也不含 key |
| 6 | `test_structured_errors_and_budget_stop` | 注入传输全超时 → 整体 `simulated`、`calls_ok=0`、`calls_invoked=8`；`max_calls=1` → 1 ok + 其余 `budget_exhausted`；**默认 urllib 槽位换超时后 real 分支仍记 `failed`**；无价格时 `usd=None`、`usd_known=false` |
| 7 | `test_provider_budget_and_price_guard_are_structured` | `max_usd` 无单价 → `status=blocked` + `price_unknown`；`max_calls=1` → 第二次调用 `budget_exhausted`、`calls_invoked=1` |
| 8 | `test_urllib_transport_really_posts_chat_completions_locally` | 默认 `urllib` 真发 `POST /v1/chat/completions`；`Authorization: Bearer <key>` 只在 header；usage 正确解析；snapshot 不含 key；该本地 endpoint 的 `endpoint_source="simulated"`（只验通路） |
| 9 | `test_provider_transport_never_called_when_price_unknown` | 直接打 provider：`max_usd=0.01` + 无单价 → `status=blocked/price_unknown`、传输 spy **0 次**、`calls_invoked=0`、`calls_ok=0`、`usd=None`；第二次仍拒；补上单价后才 `ready` 且只调 1 次 |
| 10 | `test_real_ab_budget_max_usd_without_price_blocks_before_transport` | `run_real_ab(budget={"max_usd":0.01})` + 环境有 key 但无单价 → 默认 urllib 通路被替换成 spy 且 **0 次**；文档 `blocked`/`price_unknown`、`summary=None`、`provider_trace=[]`、`provider_budget` 全 0、`provider_status.budget.max_usd==0.01`、门禁理由含 `price_unknown`、**不出现 `"real_model_status": "ran"`** |
| 11 | `test_mock_result_never_impersonates_real` | mock 文档 `mocked=true`/`real_model=false`/`real_model_status="mocked"`/`result_source="mock"`，绝不 `ran`；自称 `real_model=True` 又带 `mocked=True` 的对象被 `RealABError` 拒在真实通路外；`_check_status_exclusive()` 对三种篡改组合都判错 |
| 12 | `test_status_reports_transport_and_result_source` | 默认 public HTTPS → `transport="urllib"`/`endpoint_source="real"`/`result_source="real"`/`real_model=true`；注入 → `"injected"`/`endpoint_source="real"`/`simulated_reason="injected_transport"`/`result_source="simulated"`/`real_model=false`/`simulated=true`，`snapshot()` 同口径；status/snapshot 里没有 endpoint 全文与 key |
| 13 | `test_injected_transport_never_reports_ran_or_real` | 注入 transport spy：`calls_ok>0`（确有调用）但文档 `real_model_status="simulated"`、`summary_scope="simulated"`、`real_model=false`、`result_source="simulated"`、`transport="injected"`、门禁查 `read_only_simulated_provider`；doc 里不出现 `"real_model_status": "ran"` / `"summary_scope": "real"`；artifact/markdown 都写来源 |
| 14 | `test_default_urllib_real_branch_is_not_harmed` | 只替换模块级默认传输槽位（`_urllib_transport`）、`provider=None`、endpoint 为 public HTTPS → 仍 `ran`/`summary_scope="real"`/`transport="urllib"`/`endpoint_source="real"`/`result_source="real"`、`read_only_real_provider=true`；真实分支没有被 `simulated` 误伤 |
| 15 | `test_result_source_exclusive_selfcheck_rejects_impersonation` | `_check_status_exclusive()` 对 7 种来源篡改（`ran`+`simulated`、`simulated` 不带 `simulated=true`、`simulated`+`real_model=true`、`blocked`+`result_source=real`、非法来源值、`real`+`endpoint_source=simulated`、`real`+`transport=injected`）全部判错，且合法形状不误判 |
| 16 | `test_endpoint_source_classification_is_machine_readable` | `classify_endpoint()` 矩阵：public HTTPS → `real`；http 公网 → `non_https_endpoint`；127.0.0.1/localhost/::1/0.0.0.0 → `local_endpoint`；10/192.168/172.16/169.254/fe80 → `private_endpoint`；public IP → `real` |
| 17 | `test_local_http_status_is_simulated_but_transport_still_sends` | 本地 HTTP：status `transport="urllib"`、`endpoint_source="simulated"`、`simulated_reason="local_endpoint"`、`result_source="simulated"`、`real_model=false`、`simulated=true`；调用仍 `ok` 且 fixture 收到 1 次 POST |
| 18 | `test_local_http_default_urllib_real_ab_end_to_end_is_simulated` | **本轮 bug 的端到端回归**：`run_real_ab(env=本地 HTTP)` → 请求确实发出、`calls_ok>0`，但文档 `real_model_status="simulated"`（不是 `ran`）、`summary_scope="simulated"`、`result_source="simulated"`、`transport="urllib"`、`endpoint_source="simulated"`、`simulated_reason="local_endpoint"`、`real_model=false`；artifact/markdown 同口径；全文不出现 `"real_model_status": "ran"` / `"summary_scope": "real"` |
| 19 | `test_public_https_status_is_real_without_network_request` | public HTTPS：`status()` 直接给 `endpoint_source="real"`/`result_source="real"`/`real_model=true`/`simulated=false`；把默认传输换成抛错函数后 `status()` 仍成功、`calls_seen=0`（不发请求） |

实测（Python 3.12.14，pytest 9.1.1）：

```bash
python3 -m pytest tests/test_v3_real_ab.py -q
# 19 passed

python3 -m pytest tests/test_v3_week4_ab.py tests/test_v3_week3_handoff.py \
  tests/test_v3_week2_config.py tests/test_v3_p4_report.py -q
# 43 passed in 3.80s

python3 -m pytest tests/test_v3_*.py -q
# 278 passed in 27.33s

python3 -m pytest -q
# 1540 passed, 8 skipped in 130.68s
```

`test_v3_week4_ab.py` 的 8 个原用例**一行未改**，仍全绿：默认 `provider_kind="offline"`
时 `offline=False` 的 provider 一次都不会被调用（`provider_not_offline`）。

---

## 5. 本轮真实 A/B 实测：blocked

运行环境（只列非密钥事实）：

| 项 | 值 |
|---|---|
| endpoint 环境变量 | `BDVE_LLM_ENDPOINT=https://api.deepseek.com/v1/chat/completions` |
| model 环境变量 | `BDVE_LLM_MODEL=deepseek-v4-pro` |
| key 环境变量 | **无**（`VULNMAP_LLM_API_KEY` / `DISCOVERY_LLM_API_KEY` / `BDVE_LLM_API_KEY` / `DEEPSEEK_API_KEY` / `LLM_API_KEY` / `OPENAI_API_KEY` 全空） |

执行：

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 - <<'PY'
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks, SMALL_BUDGET
doc = run_real_ab(tasks=small_ab_tasks(), budget=SMALL_BUDGET, label="v3-real-ab")
print(doc["real_model_status"], doc["missing_env"], doc["summary"])
PY
```

结果：

```text
real_model_status: blocked
mocked: false
missing_env: ["VULNMAP_LLM_API_KEY"]
tasks_total: 8
summary: None
gate.default_arm: rules
gate.auto_apply: False
gate.reasons: ["real_model_blocked"]
provider: RealChatProvider | key_present=false | key_ref=env:unset
          | base_url_host=api.deepseek.com | model=deepseek-v4-pro
```

**没有调用、没有 tokens、没有费用、没有指标。** 不把 `blocked` 写成
“0 次调用 / 0 token / 0 费用”（那会被读成“真实跑过且免费”）。

### 5.1 有 key 时怎么跑（小预算）

```bash
cd /home/root_bupt/桌面/file/vulnmap
export VULNMAP_LLM_API_KEY='<your-key>'          # 只在 shell 里，不写文件
export VULNMAP_LLM_BASE_URL='https://api.deepseek.com/v1'
export VULNMAP_LLM_MODEL='deepseek-chat'
# 可选：export VULNMAP_LLM_PRICE_IN_PER_1K=... VULNMAP_LLM_PRICE_OUT_PER_1K=...

python3 - <<'PY'
from agent.platform.adaptive.real_ab import (
    run_real_ab, small_ab_tasks, SMALL_BUDGET, write_real_ab_artifacts)
doc = run_real_ab(tasks=small_ab_tasks(), budget=SMALL_BUDGET,
                  label="v3-real-ab")
print("status:", doc["real_model_status"], "| mocked:", doc["mocked"])
print("gate:", doc["gate"]["default_arm"], "| auto_apply:", doc["gate"]["auto_apply"])
if doc["summary"]:
    print("correct:", doc["summary"]["correct"])
    print("cost:", doc["summary"]["cost"])
write_real_ab_artifacts(doc, "docs/V3-REAL-AB-artifacts")   # 显式目录才落盘
PY
```

落盘只有 `real-ab.json`（doc + provider_trace）与 `real-ab.md`；key 不在其中。
预算：8 条任务 / ≤12 次调用 / ≤16000 tokens；`max_usd` 默认 `null`
（无单价时金额记 unknown，不填 0）。

### 5.2 显式 `max_usd` + 无单价：blocked（修复前会照跑并记 `ran`）

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 - <<'PY'
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks
env = {"VULNMAP_LLM_API_KEY": "sk-test-xxx",
       "VULNMAP_LLM_BASE_URL": "https://api.example.test/v1",
       "VULNMAP_LLM_MODEL": "test-model"}          # 刻意不给 PRICE_*
doc = run_real_ab(tasks=small_ab_tasks(), env=env,
                  budget={"max_rounds": 2, "max_calls": 12,
                          "max_tokens": 16000, "max_usd": 0.01})
print(doc["real_model_status"], doc["blocked_reason"], doc["summary"])
print(doc["provider_budget"])
PY
```

修复后（本机实测）：

```text
blocked price_unknown None
{'calls_seen': 0, 'calls_invoked': 0, 'calls_ok': 0, 'tokens_in': 0,
 'tokens_out': 0, 'usd': None, 'usd_known': False, 'exhausted': ''}
```

修复前：`_provider_with_budget()` 只在 `price_known` 时才把 `max_usd` 写进
`ProviderConfig`，上限被丢成 `None` → `status=ready` → 真发 1 次请求 →
`calls_ok=1` → `real_model_status="ran"`。**“设了 0.01 美元上限”完全没生效。**
现在 `max_usd` 一律下发，无单价时 provider 在传输前拒绝，传输 0 次。

### 5.3 注入内存 transport：有调用，但报告是 `simulated`（上一轮修复）

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 - <<'PY'
import json
from agent.platform.adaptive.compare import FakeClock
from agent.platform.adaptive.llm_provider import ProviderConfig, RealChatProvider
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks, SMALL_BUDGET

tasks = small_ab_tasks()
index = {t["task_id"]: t for t in tasks}

def transport(request):                      # 内存替身：一次外网都不发
    user = json.loads(request["body"]["messages"][-1]["content"])
    gold = index[user["task_id"]]["gold"]
    return {"choices": [{"message": {"content": json.dumps(
        {"diagnosis": {"code": gold["diagnosis"]}, "actions": []})}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20}}

cfg = ProviderConfig(base_url="https://api.example.test/v1", model="test-model",
                     api_key="sk-test", max_calls=12, max_tokens=16000)
provider = RealChatProvider(cfg, transport=transport, clock=FakeClock(0.01))
doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                  clock=FakeClock())
print(doc["real_model_status"], doc["summary_scope"], doc["result_source"],
      doc["transport"], doc["real_model"], doc["mocked"], doc["simulated"])
print("calls_ok:", doc["provider_budget"]["calls_ok"])
print("gate:", doc["gate"]["default_arm"], doc["gate"]["auto_apply"])
PY
```

本机实测（修复后）：

```text
simulated simulated simulated injected False False True
calls_ok: 10
gate: model False
```

- `calls_ok=10` 说明**确实发生过 10 次“成功调用”**，但来源是注入的替身，
  所以状态是 `simulated`，`summary_scope="simulated"`，**不是** `ran`/`real`；
- 修复前这一行是 `ran real False`（`mocked=false`），报告读起来就是“真实模型
  跑过一次、`summary_scope=real`”——也正是这个 bug 的现场；
- `auto_apply` 仍是 `False`：模拟口径同样不授予任何写权限；`gate.default_arm`
  只表达“框架形状是否允许把建议源换成模型”，不是收益证据（§3.5）。

### 5.4 本地 HTTP fixture：`transport="urllib"`，但来源是 `simulated`（本轮修复）

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 - <<'PY'
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from agent.platform.adaptive.compare import FakeClock
from agent.platform.adaptive.llm_provider import provider_from_env
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks, SMALL_BUDGET

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        content = json.dumps({"diagnosis": {"code": "no_execution"},
                              "actions": [], "reason": "local fixture"})
        data = json.dumps({"choices": [{"message": {"content": content}}],
                           "usage": {"prompt_tokens": 11,
                                     "completion_tokens": 7}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        return

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
env = {"VULNMAP_LLM_API_KEY": "sk-test",
       "VULNMAP_LLM_BASE_URL":
           f"http://127.0.0.1:{server.server_address[1]}/v1",
       "VULNMAP_LLM_MODEL": "local-fixture"}
try:
    _, st = provider_from_env(env)
    print("status:", st["transport"], st["endpoint_source"],
          st["result_source"], st["simulated_reason"],
          st["real_model"], st["simulated"])
    doc = run_real_ab(tasks=small_ab_tasks(), env=env,
                      budget=SMALL_BUDGET, clock=FakeClock())
    print("doc:", doc["real_model_status"], doc["summary_scope"],
          doc["result_source"], doc["transport"],
          doc["endpoint_source"], doc["simulated_reason"])
    print("calls_ok:", doc["provider_budget"]["calls_ok"])
finally:
    server.shutdown(); server.server_close()
PY
```

本机实测（修复后）：

```text
status: urllib simulated simulated local_endpoint False True
doc: simulated simulated simulated urllib simulated local_endpoint
calls_ok: 10
```

- 10 次 `POST` 确实发出去了（`calls_ok=10`），所以**通路可用**；
- 但 endpoint 是 `127.0.0.1`，`endpoint_source="simulated"`，
  `result_source="simulated"`，报告是 `real_model_status="simulated"`，
  **不是** `ran`/`summary_scope="real"`；
- 修复前的这一行正是 `ran real real`（`transport="urllib"`）：
  `transport` 被当成了来源证据，本地 fixture 的响应被写成“真实模型跑过”。

---

## 6. mock 回归数字（`mocked=true`，不是真实模型）

用 `FakeProvider` 照 gold 回放的 8 条小预算回归（**仅验证框架与门禁**）：

| 指标 | 规则臂 | mock 模型臂 |
|---|---|---|
| 正确诊断 / 总任务 | 6/8 | 8/8 |
| 作答 | 8/8 | 8/8 |
| 无效重试 | 2 | 2 |
| 采纳 / 错误采纳 | 6 / 3 | 8 / 0 |
| 调用 / tokens / 费用 | 0 / 0 / 0 | 10 / 10500 / 0.025（fake 单价 0.0025/次） |
| 分层增益 | — | `even +1`、`odd +1` |
| 门禁 | — | `default_arm="model"`、`reasons=[]`、`auto_apply=False` |

口径提醒：这组数字**不能**写成“真实模型 10/10”。它证明的是：同一份回归集、
同一套门禁、同一份控制变量下，“只读建议”通路可以跑通；真实收益必须在
有 key 的环境里按 §5.1 重跑，且仍受 `no_model_wrong_adoption` 一票否决。

mock 文档的来源字段是 `result_source="mock"` / `transport="offline_fake"` /
`simulated=false`；它与“注入 transport 的替身”（`result_source="simulated"` /
`transport="injected"`）是两条不同的线，二者的共同点只有一个：
**都不能被引用成真实模型结果**。

---

## 7. 明确不做

1. **不在无 key 时伪造真实结果**：blocked 就是 blocked，`summary=None`；
2. **不把 mock 混进真实**：`mocked=true` 与 `ran` 互斥，费用标 `cost_is_fake`；
3. **不把注入 transport 的替身混进真实**：`transport="injected"` 一律
   `result_source="simulated"`，`summary_scope="simulated"`，即使 `calls_ok>0`
   也不记 `ran`/`real`；
4. **不把本地/私网/非 HTTPS endpoint 混进真实**：`transport="urllib"` 只是
   怎么发；`endpoint_source="simulated"`（`local_endpoint` / `private_endpoint` /
   `non_https_endpoint`）一律 `result_source="simulated"`，即使请求真的发出、
   `calls_ok>0`，也不记 `ran`/`real`（本轮修复）；
5. **不写状态/证据/判据**：provider 没有写路径；建议逐条过
   `Registry.get()` + `spec.validate()` + `prune_verdict_fields`；
6. **不自动应用**：`auto_apply=False` 无分支；错误采纳 > 0 直接退回规则；
7. **不产裁决**：`verdict="not_evaluated"`，不写 `verified/confirmed`；
8. **不改既有 A 臂规则**：`DiagnoseRole` 与两个已知盲区保持原样；
9. **不做显著性**：8 条单次运行只做分层一致性（`stable_gain`），不吹“提升百分比”；
10. **不把 key 落盘**：环境变量 → 请求头局部变量 → 丢弃；日志只留 `key_ref`。

---

## 8. 复核清单

```bash
cd /home/root_bupt/桌面/file/vulnmap

# ① 新测试（含 endpoint 来源 4 个）
python3 -m pytest tests/test_v3_real_ab.py -q
# 19 passed

# ② 原 W4 口径未放松（offline=False provider 仍一次不调）
python3 -m pytest tests/test_v3_week4_ab.py -q

# ③ V3 全量与全量
python3 -m pytest tests/test_v3_*.py -q
python3 -m pytest -q

# ④ 预算门禁自检（有 key 但无单价 + 显式 max_usd，应为 blocked/0 次）
python3 - <<'PY'
from agent.platform.adaptive.real_ab import _provider_with_budget
env = {"VULNMAP_LLM_API_KEY": "k", "VULNMAP_LLM_BASE_URL": "https://x.test/v1",
       "VULNMAP_LLM_MODEL": "m"}
p = _provider_with_budget(env, {"max_usd": 0.01})
assert p.config.max_usd == 0.01                      # 上限必须真下发
assert p.status()["blocked_reason"] == "price_unknown"
assert p({"task_id": "t", "round_no": 1,
          "observation": {}})["error"] == "price_unknown"
assert p.snapshot()["calls_invoked"] == 0
print("budget gate ok")
PY

# ⑤ blocked 自检（当前环境无 key，应输出 blocked + missing_env）
python3 - <<'PY'
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks
doc = run_real_ab(tasks=small_ab_tasks())
print(doc["real_model_status"], doc["missing_env"], doc["summary"])
assert doc["real_model_status"] == "blocked"
assert doc["summary"] is None
PY

# ⑥ 来源口径自检（注入 transport 必须 simulated，绝不 ran/real）
python3 - <<'PY'
from agent.platform.adaptive.compare import FakeClock
from agent.platform.adaptive.llm_provider import ProviderConfig, RealChatProvider
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks, SMALL_BUDGET

def transport(request):                      # 内存替身
    return {"choices": [{"message": {"content":
            '{"diagnosis":{"code":"no_execution"},"actions":[]}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}

cfg = ProviderConfig(base_url="https://x.test/v1", model="m", api_key="k",
                     max_calls=12, max_tokens=16000)
p = RealChatProvider(cfg, transport=transport)
assert p.transport == "injected" and p.result_source == "simulated"
assert p.status()["real_model"] is False and p.status()["simulated"] is True

doc = run_real_ab(tasks=small_ab_tasks(), provider=p, budget=SMALL_BUDGET,
                  clock=FakeClock())
assert doc["real_model_status"] == "simulated"     # 不是 ran / failed
assert doc["summary_scope"] == "simulated"
assert doc["real_model"] is False and doc["mocked"] is False
assert doc["result_source"] == "simulated" and doc["transport"] == "injected"
assert doc["auto_apply_allowed"] is False
print("source guard ok:", doc["real_model_status"], doc["result_source"],
      "calls_ok=", doc["provider_budget"]["calls_ok"])
PY
```

静态自检：

```bash
grep -n "import requests\|import httpx" agent/platform/adaptive/llm_provider.py   # 空
grep -n "write_text\|write_bytes\|\.open(" agent/platform/adaptive/llm_provider.py # 空
grep -n "verified\|confirmed" agent/platform/adaptive/llm_provider.py              # 只有禁止字段的说明
grep -n "result_source\|transport\|endpoint_source" agent/platform/adaptive/real_ab.py  # 来源字段贯穿文档/artifact
```
