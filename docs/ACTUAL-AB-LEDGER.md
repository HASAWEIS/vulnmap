# A/B 实际入口账本验收（`docs/ACTUAL-AB-LEDGER.md`）

> **一句话结论**：用本地 `127.0.0.1` HTTP fixture 走**真实入口**
> `run_real_ab()`，设 `VULNMAP_LLM_LEDGER=<临时文件>`（主名
> `VULNMAP_CALL_LEDGER` 仍兼容），每次调用（含被预算拒绝的）都往 append-only
> JSONL 追加一条完整记录——`call_id / task_id / round / model / prompt_version /
> endpoint_source / transport / request_sha256 / response_sha256 / usage /
> params_sent / params_not_sent / params_missing` 一个不少；顶层
> `result_source="simulated"`（**不是** `real`）；账本里没有 key 原文、没有
> `Bearer`、没有 `authorization` 键；两次入口运行只追加、不重写。
>
> 代码：[real_ab.py](../agent/platform/adaptive/real_ab.py)、
> [llm_provider.py](../agent/platform/adaptive/llm_provider.py)、
> [call_ledger.py](../agent/platform/adaptive/call_ledger.py)。
> 回归：[test_actual_ab_ledger.py](../tests/test_actual_ab_ledger.py)（12 组；
> 本地 fixture，不联网、不用真实 key）。
> 口径底座：[CALL-LEDGER.md](CALL-LEDGER.md)。

---

## 0. 验收对象与命令

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_actual_ab_ledger.py -q     # 12 passed
python3 -m pytest tests/test_call_ledger.py -q          # 14 passed（未回归）
python3 -m pytest tests/test_v3_real_ab.py -q           # 19 passed（未回归）
```

入口调用形状（测试里就是这么跑的，**没有真实 key**）：

```python
env = {
    "VULNMAP_LLM_API_KEY": "sk-actual-ab-fixture-0123456789abcdef",  # 假 key
    "VULNMAP_LLM_BASE_URL": "http://127.0.0.1:PORT/v1",              # 本机 fixture
    "VULNMAP_LLM_MODEL": "fixture-model",
    "VULNMAP_LLM_LEDGER": str(tmp_path / "calls.jsonl"),             # 临时账本
}
doc = run_real_ab(tasks=small_ab_tasks()[:3], env=env,
                  budget={"max_rounds": 1, "max_calls": 4,
                          "max_tokens": 16000, "max_usd": None})
```

`run_real_ab(provider=None)` → `_provider_with_budget(env, budget, ledger=…)` →
`ledger_from_env(env)` → `RealChatProvider(config, ledger=…)` → 默认 `urllib`
真的 `POST http://127.0.0.1:PORT/v1/chat/completions` → 每次处理都
`CallLedger.append(record)`。**入口不是直接构造 provider 的旁路测试**：
HTTP 请求数与账本行数在同一个 fixture 里对齐。

---

## 1. 环境变量（两个名字，一条开关）

| 名字 | 角色 | 语义 |
|---|---|---|
| `VULNMAP_LLM_LEDGER` | A/B 入口侧推荐名 | 非空 → 建账本 |
| `VULNMAP_CALL_LEDGER` | 主名 / 历史兼容名 | 同上；两者等价 |
| 都不设 / 空串 | 不记账 | 一个文件都不写（默认只读语义） |
| 两个都设且**指向不同文件** | 配置冲突 | `ledger_from_env()` 抛 `CallLedgerError`，**在传输前拦住**（一次 HTTP 都不发） |

优先级：显式参数 `run_real_ab(..., ledger=CallLedger(...))` > 环境变量。
冲突不静默二选一的原因：账本“到底落在哪”必须是可核事实，猜一个等于制造
不可核证据（与 [CALL-LEDGER.md](CALL-LEDGER.md) §2「宁缺勿假」同口径）。
同一文件的相对/绝对两种写法按 `Path.resolve()` 归一，不算冲突。

---

## 2. 每条记录的字段（验收点 2）

`REQUIRED_FIELDS` 命中 + 值可核。样例（真实跑出来的一条，`messages` 只列哈希）：

```json
{
  "call_id": "call-0001",
  "task_id": "w4-t01",
  "round": 1,
  "model": "fixture-model",
  "prompt_version": "real-chat-json-v1",
  "endpoint_source": "simulated",
  "transport": "urllib",
  "request_sha256": "55567867e14ad2ea7d58fc3b316e99660b9b68c6d5c232231eeedec4ba19a19b",
  "response_sha256": "a5357c44d234bc401c6ab2e279c7788e6b80f8f63edc2b92e50d99e39cd63c2e",
  "usage": {"prompt_tokens": 11, "completion_tokens": 7,
            "total_tokens": null, "reasoning_tokens": null,
            "state": "sent", "reason": ""},
  "params_sent": {"model": "fixture-model", "temperature": 0.0,
                  "max_tokens": 512,
                  "response_format": {"type": "json_object"}},
  "params_not_sent": {"top_p": "absent_by_design", "seed": "absent_by_design",
                      "stream": "absent_by_design",
                      "request_id": "never_captured_by_client"},
  "params_missing": {},
  "call_state": "sent", "status": "ok", "invoked": true,
  "seq": 1, "schema": "vulnmap.adaptive.call_ledger.v1", "schema_version": 1,
  "recorded_at": 1795691914.83,
  "request": {"built": true, "method": "POST", "url_host": "127.0.0.1",
              "url_path": "/v1/chat/completions", "timeout_s": 30.0,
              "body_sha256": "55567867…", "body_keys": ["max_tokens","messages","model","response_format","temperature"],
              "messages_count": 2, "messages_roles": ["system","user"],
              "messages_sha256": "dcf4435b…", "auth_header_present": true},
  "response": {"present": true, "chars": 97, "sha256": "a5357c44…",
               "finish_reason": "stop", "state": "sent", "reason": ""}
}
```

| 字段 | 值从哪来 | 验收断言 |
|---|---|---|
| `call_id` | provider 实例内序号 `call-0001`… | 非空、本次运行内唯一 |
| `task_id` / `round` | A/B payload 的 `task_id` / `round_no` | 与 `small_ab_tasks()` 顺序一致、1 轮时 `round=1` |
| `model` | `ProviderConfig.model`（= 请求体 `model`） | 与 env 一致 |
| `prompt_version` | `RealChatProvider.prompt_version` | 非空、等于 `PROMPT_VERSION` |
| `endpoint_source` | `classify_endpoint(base_url)` | 本机 → `simulated` |
| `transport` | 是否注入 transport | 默认 → `urllib`；注入 → `injected` |
| `request_sha256` | `sha256(canonical_json(body))` | 用 fixture 真收到的 body 独立复算，逐字节相等 |
| `response_sha256` | `sha256(choices[0].message.content)` | 用 fixture 真回的 content 复算，逐字节相等 |
| `usage` | 回包 `usage` 原值 | `state=sent` + 11/7；不拿 0 回填 |
| `params_sent` | 请求体里真出现的键（原值） | `temperature=0.0` 只有发了才在 |
| `params_not_sent` | 客户端结构性不发送（只有理由码） | `top_p/seed/request_id` 等，值一律不记 |
| `params_missing` | 应有但未记录（`null` + 理由） | 成功调用为空 `{}` |
| `call_state` | `sent` / `not_invoked` | 预算拒绝 → `not_invoked` + 四个 body 参数 `missing/no_request_built` |

三态两两不交、并集覆盖 `TRACKED_PARAMS`，由 `validate_record()` 在写盘前与读回时
各硬断言一次；`read_records()` 还额外校验 `seq` 严格递增。

---

## 3. 来源必须是 `simulated`，不是 `real`（验收点 3）

本轮的全部调用都满足“本地 HTTP fixture”条件，因此：

| 字段 | 值 | 含义 |
|---|---|---|
| `real_model_status` | `simulated` | 不是 `ran`/`failed` |
| `summary_scope` | `simulated` | 指标只在本口径内成立 |
| `result_source` | `simulated` | 不进入真实统计 |
| `real_model` / `simulated` / `mocked` | `false` / `true` / `false` | 三者互斥 |
| `transport` | `urllib` | 只说明“怎么发”：请求真的发出去了 |
| `endpoint_source` | `simulated` | 才说明“响应从哪来”：本机 |
| `simulated_reason` | `local_endpoint` | 机读理由 |
| `auto_apply_allowed` | `false` | 模拟结果永不自动应用 |

账本与文档来源字段**必须一致**（`record["endpoint_source"] == doc["endpoint_source"]`、
`record["transport"] == doc["transport"]`）：不允许“账本说 real、结果说 simulated”。
`_check_status_exclusive()` 仍是硬门禁：`result_source=real` 却带 `simulated` 标记
会直接抛 `RealABError`。

补充：即使 endpoint 写成 public HTTPS，只要**注入 transport**（本地替身 / spy），
`run_real_ab` 仍走 `simulated` 分支，账本记 `transport="injected"`——注入永远不算真实。

---

## 4. 凭据零落盘（验收点 3）

| 检查 | 结果 |
|---|---|
| 账本文件包含 key 原文（`sk-actual-ab-fixture-…`） | 否 |
| 账本文件出现 `bearer` / `authorization` / `api_key` / `x-api-key`（大小写不敏感） | 否 |
| 任意层级 JSON 键名命中 `FORBIDDEN_KEYS` | 否（`headers` 整块禁止，连 header 名都不进） |
| fixture 侧确实收到了 `Authorization: Bearer …` | 是（证明通路真实） |
| 账本里对应的布尔事实 | `request.auth_header_present=true` |

写入前的 `assert_no_secret_record(secret=config.api_key)` 是 fail-closed：命中就
**不写那一条**，错误进 `snapshot()["ledger"]["errors"]` / 文档 `call_ledger.errors`，
调用语义不变。注意短 key（如 `"k"`）会因子串命中而拒写——这是护栏的正确行为，
真实 key 不会这么短。

---

## 5. append-only（验收点 3）

同一个账本路径连续跑两次入口（各 2 个任务）：

| 检查 | 结果 |
|---|---|
| 第二次写入后的文件**字节前缀** == 第一次全文 | 是 |
| 行数 | 2 → 4（只增不减） |
| `seq` | `[1,2,3,4]`，严格递增、不重号 |
| `call_id` | `call-0001, call-0002, call-0001, call-0002`（实例内序号，唯一键是 `seq`） |
| 第一次的 2 条记录 | 字节级不变（`records[:2] == first_records`） |
| `call_ledger.written` | 每次运行只报**本次**写入条数（2 / 2），不是总数 |

---

## 6. 接线修复（验收点 5）

验收时发现的入口缺口与修法（只动 `adaptive/`，不动 `verify` / `benchmark` 判据）：

| 缺口 | 现象 | 修法 |
|---|---|---|
| 环境变量名不认 `VULNMAP_LLM_LEDGER` | 按入口文档设了 `VULNMAP_LLM_LEDGER`，账本文件根本不出现 | `call_ledger.ENV_LEDGER_PATH_ALIASES` 认两个名字；`ledger_path_from_env()` 统一解析，冲突抛错 |
| 注入 provider 时不挂账本 | `run_real_ab(provider=RealChatProvider(transport=spy), env=…)` 跑了 N 次、账本 0 行（“入口跑了、账本空着”＝没有证据） | `run_real_ab` 先解析账本，再 `attach_ledger_to_provider(provider, ledger)`：provider 没有账本才接，已有的不覆盖 |
| 文档里看不到账本状态 | 只能去翻文件，报告无法自证“记了几条/有没有记失败” | 所有分支（`ran`/`simulated`/`blocked`）新增顶层块 `call_ledger = {enabled, path, written, errors, note}`；`real-ab.md` 增一行账本摘要 |

`_provider_with_budget(env, budget, ledger=None)` 现在接受显式账本；不传仍按环境
解析（默认不写文件）。`provider_from_env(env, ledger=None)` 行为不变（同样认两个名字）。

**没有改动**：`compare.py` 的 A/B 判据、`verify`/`benchmark_policy`、`prune_verdict_fields`、
`auto_apply`（恒 `False`）。账本是旁路文件 + 一个只读文档块。

---

## 7. 12 组回归（`tests/test_actual_ab_ledger.py`）

| 组 | 用例 | 断言 |
|---|---|---|
| 1 | `test_run_real_ab_writes_ledger_via_llm_env` | 3 任务 → 3 次 HTTP → 3 行；`call_ledger` 块与文件一致；`task_id` 顺序对齐 |
| 2 | `test_every_record_carries_required_audit_fields` | 13 个必填字段齐全且值对得上（含 `usage` 真值、`params_missing={}`） |
| 3 | `test_hashes_bind_to_fixture_bytes` | 用 fixture 收到的 body / 回的 content 复算两个 sha256，逐字节相等 |
| 4 | `test_result_source_is_simulated_not_real` | `simulated` 全套 + 账本来源字段与文档一致 |
| 5 | `test_ledger_never_stores_key_or_bearer` | 无 key/`Bearer`/`authorization`；`auth_header_present=true` |
| 6 | `test_append_only_across_two_entry_runs` | 字节前缀、`seq` 连续、首轮记录不变 |
| 7 | `test_ledger_off_by_default_at_entry` | 不设环境变量 → 不建文件、`call_ledger.enabled=false` |
| 8 | `test_injected_provider_still_gets_ledger` | 注入 provider 也接账本；`transport=injected`、仍 `simulated` |
| 9 | `test_explicit_ledger_argument_wins` | 显式 `ledger=` 压过环境路径（环境文件不出现） |
| 10 | `test_conflicting_env_names_refused` | 两个名字指向不同文件 → `CallLedgerError`，HTTP 0 次 |
| 11 | `test_budget_refusal_is_recorded_as_not_invoked` | 硬顶 1 次：3 条账 = 1 `sent` + 2 `not_invoked`，拒绝条目 `missing/no_request_built` |
| 12 | `test_provider_from_env_honours_llm_ledger_name` | `provider_from_env` 同样认 `VULNMAP_LLM_LEDGER` |

---

## 8. 边界：本验收**不**主张什么

| 不主张 | 原因 |
|---|---|
| 响应来自真实模型 | endpoint 是 `127.0.0.1`；`simulated` 只证明通路与账本形状 |
| 服务端按此参数采样 | 账本记的是客户端**实际发送**的键值 |
| 修复历史 run 的 `missing` | 历史请求体没落盘，回填即伪造（[CALL-LEDGER.md](CALL-LEDGER.md) §2.4） |
| 证明成本受控 | fixture 的 usage 是假数；真实成本只认 provider 的 `usd_known` |
| 账本一定写得进去 | 命中凭据护栏 / IO 故障时那一条不写，错误可见但调用照常 |
| 改 `verify` / `benchmark` 判据 | 本改动只在 `adaptive/`、`tests/`、`docs/`；`strict_submittable` / D2 不变 |
