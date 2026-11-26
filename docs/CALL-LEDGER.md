# 逐调用参数账本（`call_ledger`）

> **一句话结论**：从下一次调用起，`RealChatProvider` 每发一次请求（以及每一次**没发出去**
> 的拒绝）都往 append-only JSONL 追加一条三态记录——`sent`（真发出去的键值）/
> `not_sent`（客户端结构性不发送，只有理由）/ `missing`（应有但未记录，值一律 `null`）——
> 并带上请求体哈希、响应哈希、原始 usage。**唯一例外**：账本自己写不进去（IO 故障、
> 或条目命中凭据护栏）时那一条不写，只落 `snapshot()["ledger"]["errors"]`；调用语义不变。**它不修复历史 run 的 `missing`**：
> `CG07-CG18-PARAM-FORENSICS.md` 的结论仍然成立，D2 仍不通过，历史参数永久不可回填。
> 本账本只保证「以后每一次调用都自带参数与哈希绑定」。

> 代码：[call_ledger.py](../agent/platform/adaptive/call_ledger.py)、
> 接入点：[llm_provider.py](../agent/platform/adaptive/llm_provider.py)（`RealChatProvider(ledger=…)`）、
> [real_ab.py](../agent/platform/adaptive/real_ab.py)（`VULNMAP_LLM_LEDGER` / `VULNMAP_CALL_LEDGER` 才落盘）。
> 回归：[test_call_ledger.py](../tests/test_call_ledger.py)（14 组，本地 HTTP fixture，不联网）。
> A/B 实际入口验收：[ACTUAL-AB-LEDGER.md](ACTUAL-AB-LEDGER.md)、
> [test_actual_ab_ledger.py](../tests/test_actual_ab_ledger.py)（12 组）。
> 上游证据口径：[CG07-CG18-PARAM-FORENSICS.md](CG07-CG18-PARAM-FORENSICS.md) §4（D2b 逐调用口径）、
> [MODEL-PARAMS.md](MODEL-PARAMS.md)（历史缺口：verify 参数 0/9 未记录）。

---

## 0. 为什么要这张表

取证文档的结论是「已记录调用缺逐调用参数 → D2b fail」，并且明确写了三条不可做的事：
用 `LlmConfig` 默认值回填、用 `task.json.model` 当实际请求 model、重跑改写历史 DB。
那就只剩一条正路：**让新调用自己落参数**。本模块只做这件事，并且把「缺」和「不发」
分开记——因为这两者的补救方式完全不同：

| 情况 | 历史做法 | 本账本 |
|---|---|---|
| `top_p` / `seed` / `request_id` 从未出现 | 记成「缺参数」，看起来像漏记 | 记 `not_sent` + 机读理由（`absent_by_design` / `never_captured_by_client`）——**本来就没有，不用补** |
| `temperature` 没落盘但代码必发 0.0 | 结构性证明后仍写「缺」 | 发就记 `sent`（原值）；没发就记 `missing`（`null`），**绝不写 0.0 冒充** |
| `usage` 缺失 | provider 内部 `tokens or 0` | 账本记 `null` + `usage_absent`，0 和「未知」不再混为一谈 |

---

## 1. 一条记录长什么样

一行一个 JSON 对象（`json.dumps(sort_keys=True, separators=(",",":"))` + `\n`）：

```json
{
  "schema": "vulnmap.adaptive.call_ledger.v1",
  "schema_version": 1,
  "seq": 1,
  "recorded_at": 123.45,
  "call_id": "call-0001",
  "task_id": "w4-t01",
  "round": 1,
  "call_state": "sent",
  "status": "ok",
  "error": "",
  "invoked": true,
  "model": "local-fixture",
  "prompt_version": "real-chat-json-v1",
  "endpoint_source": "simulated",
  "transport": "urllib",
  "request_sha256": "…64 hex…",
  "response_sha256": "…64 hex…",
  "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": null,
            "reasoning_tokens": null, "state": "sent", "reason": ""},
  "params_sent": {"model": "local-fixture", "temperature": 0.0,
                  "max_tokens": 512, "response_format": {"type": "json_object"}},
  "params_not_sent": {"top_p": "absent_by_design", "request_id": "never_captured_by_client", "…": "…"},
  "params_missing": {},
  "request": {"built": true, "method": "POST", "url_host": "127.0.0.1",
              "url_path": "/v1/chat/completions", "timeout_s": 30.0,
              "body_sha256": "…", "body_keys": ["max_tokens", "messages", "model",
                                               "response_format", "temperature"],
              "messages_sha256": "…", "messages_count": 2,
              "messages_roles": ["system", "user"], "auth_header_present": true},
  "response": {"present": true, "chars": 88, "sha256": "…",
               "finish_reason": "stop", "state": "sent", "reason": ""}
}
```

### 1.1 顶层字段

| 字段 | 类型 | 含义 / 口径 |
|---|---|---|
| `seq` | int | 由账本分配，单调递增；续号公式 `max(行数, 最大 seq)+1`（有 `seq` 的行按最大编号走，跳号不会重号；无 `seq` 的旧式行只按行数计）。**账本内的唯一键是 `seq`** |
| `recorded_at` | float | 写盘时刻（`CallLedger(clock=…)` 可注入，测试用 `FakeClock`） |
| `call_id` | str | provider **实例内**的调用序号（`call-0001` 起）。多实例写同一账本时可能重号——所以唯一键是 `seq`，不是 `call_id` |
| `task_id` / `round` | str / int | 取自 payload（`round` 即 `round_no`） |
| `call_state` | `sent`/`not_invoked` | 这次调用**有没有真的走传输层**（与三态正交：拒绝的调用也有完整三态） |
| `status` / `error` | str | `ok` / `environment_error` / `budget_exhausted` + 机读错误码 |
| `model` / `prompt_version` | str | `prompt_version` 是本模块模板常量 `PROMPT_VERSION`（**不是**历史 run 的推断值）；内容绑定另由 `request.messages_sha256` 给出 |
| `endpoint_source` | `real`/`simulated` | 只有 public HTTPS 是 `real`（与 `status()` 同源，不重复判定） |
| `transport` | `urllib`/`injected` | 只说明「怎么发」，不证明响应来自真实模型 |
| `request_sha256` | 64 hex / `null` | 见 §2；`null` = 请求体根本没构造出来 |
| `response_sha256` | 64 hex / `null` | 见 §2；`null` = 没有可绑定的响应内容 |
| `usage` | object | 见 §3；缺字段就是 `null`，不写 0 |
| `params_sent` / `params_not_sent` / `params_missing` | object | 见 §4 三态 |

### 1.2 `request` / `response` 子块

- `request.built=false` 时 `method`/`url_host`/`url_path`/`timeout_s`/`body_*` 全为空或 `null`——
  这是「没发」的**结构化**表达，不是空字符串猜出来的。
- `request.auth_header_present` 是**唯一**与鉴权有关的信息：一个布尔。
  header 值（`Authorization: Bearer …`）与 header 名都不进账本。
- `messages`（prompt 正文）不进 `params_sent`：它是载荷不是参数，绑定靠
  `request.body_sha256` + `request.messages_sha256`（整段 messages 数组的规范化哈希）。
- `response.finish_reason` 直接取 `choices[0].finish_reason`；拿不到就是空串。

---

## 2. 哈希绑定（可被任何人复算）

```text
canonical_json(v)   = json.dumps(v, ensure_ascii=False, sort_keys=True,
                                separators=(",",":"), default=str)
request_sha256      = sha256(canonical_json(request_body).encode("utf-8")).hexdigest()
request.messages_sha256 = sha256(canonical_json(body["messages"]).encode("utf-8")).hexdigest()
response_sha256     = sha256(choices[0].message.content.encode("utf-8")).hexdigest()
```

- **请求侧**绑的是请求体（不含 header、不含 URL 全文，只留 host/path）；
  复算方式：把 HTTP 服务端收到的那串 body 用同一套 `canonical_json` 序列化再哈希，
  与 `request_sha256` **逐字节相等**（`test_request_and_response_hash_bind_fixture_bytes`
  就是这么验的）。
- **响应侧**绑的是模型返回的 `content` 字符串——也就是被解析成建议的那段文本，
  不是整个回包 JSON（回包里的 `id`/`created` 等元数据不由客户端消费，也不假装绑定了）。
- 目的：把「这条记录说的是哪一次请求、哪一段响应」变成可复核的事实，而不是自述。

响应侧按路径分**五种**形状（`response.present` / `chars` 同时给出，避免"没回来"被误读成"空"）：

| 路径 | `response.present` | `response_sha256` | 能否从线路字节复算 |
|---|---|---|---|
| `ok` | `true` | `sha256(content)` | **能**（原文） |
| `invalid_json`（回包不是 JSON 对象） | `true` | `sha256(content)` | **能**（原文；该路径只在确认无 key 后才会走到） |
| `empty_response`（content 去空白后为空） | `true`、`chars=len(content)` | `sha256(content)` | **能**（空串记 `sha256("")`；纯空白 content 记实际长度与那段文本的哈希，不是 `null`） |
| `timeout` / `network_error` / `http_*` / 协议错误 | `false` | `null` + `response.reason=response_absent` | 不适用（响应没回来） |
| `secret_in_output` | `true` | `sha256(脱敏后文本)` | **不能**——有意为之：原文含 key，不得以任何形式落盘 |

- `empty_response` 不再被记成 `response_absent`：「响应回来了但是空的」与「响应没回来」
  是两种归因，账本按 `present/chars` 分开表达。

---

## 3. usage：未知不是 0

| 情况 | `usage.state` | 值 | `reason` |
|---|---|---|---|
| 响应带 `prompt_tokens`/`completion_tokens` | `sent` | 原值（`total_tokens`/`reasoning_tokens` 有就记，没有就 `null`） | `""` |
| 响应没有 `usage`，或缺这两个字段 | `missing` | 缺的字段 `null`，有的字段照实记 | `usage_absent` |
| 失败但回包带 `usage`（`invalid_json` / `secret_in_output` / `empty_response`） | `sent` | 照实记（token 数不含敏感材料，没有理由记成"不存在"） | `""` |
| 调用根本没发生（缺 key / 预算拒绝） | `missing` | 全 `null` | `call_not_invoked` |

`validate_record()` 会拒绝「`state=missing` 却写了 `0/0`」的记录——现有 provider 为了
返回结构稳定用 `tokens or 0`，那是**返回值**的约定，**不得**流进账本。

---

## 4. 三态：`sent` / `not_sent` / `missing`

### 4.1 定义

| 态 | 判据 | 值长什么样 | 能不能补 |
|---|---|---|---|
| `sent` | 该键**确实出现在本次请求体里** | 原值（不归一化、不换算） | 不需要 |
| `not_sent` | 客户端结构性不发送（代码里从不写这个键） | **只有理由码**，没有值 | 不需要（本来就没有） |
| `missing` | 应有但未记录：请求体没构造出来 / 响应没回来 / 该参数不在 body 里 | 只有理由码，值一律 `null` | 只能靠新调用重记；**不可回填** |

硬约束（`build_call_record` / `validate_record` 都断言）：三态**两两不交**，
并集**覆盖** `TRACKED_PARAMS`；重叠或缺项直接抛 `CallLedgerError`，不写盘。

### 4.2 `not_sent` 参数表（`NOT_SENT_PARAMS`）

| 参数 | 理由码 | 依据 |
|---|---|---|
| `top_p` / `seed` / `stop` / `presence_penalty` / `frequency_penalty` / `logit_bias` / `logprobs` / `top_logprobs` / `n` / `stream` / `tools` / `tool_choice` / `user` / `max_retries` | `absent_by_design` | `RealChatProvider` 构造请求体时**从不**写这些键（代码事实）；与取证文档 §2.2 / §3.4 的 `absent_by_design` 同口径 |
| `request_id` | `never_captured_by_client` | 客户端不在请求体发送，也不解析响应 `id`；账本**刻意不**记录响应 `id`，以免制造一个假的 `request_id` |
| `response_format`（仅当 `json_mode=False`） | `disabled_by_config` | 本次配置下刻意不发；不是缺，也不是从不发 |

### 4.3 `missing` 理由码（`MISSING_REASONS`）

| 理由码 | 何时出现 |
|---|---|
| `no_request_built` | 缺 key/endpoint/model、预算触顶、`max_usd` 无单价——请求体没构造出来，四个 body 参数全 `missing` |
| `response_absent` | 请求发出去了，但响应没回来（超时 / 网络错误 / HTTP 错误 / 提前失败） |
| `usage_absent` | 响应回来了却没有可用的 usage 字段 |
| `value_not_recorded` | 请求体构造了，但该参数不在里面，也没声明 `not_sent` |
| `call_not_invoked` | 调用没发生，因此不存在该值（拒绝类调用的 usage / response） |

> 例：`max_calls=1` 时第二次调用 → `status="budget_exhausted"`、`invoked=false`、
> `call_state="not_invoked"`、`request_sha256=null`、`params_missing` 四个
> `no_request_built`、`usage.state="missing"`（`call_not_invoked`）。
>
> 限定：`json_mode=False` 时 `response_format` 记 `not_sent/disabled_by_config`（这是
> **配置事实**，与本次是否发出无关），此时拒绝类调用的 `params_missing` 只有
> `model` / `temperature` / `max_tokens` 三项。
> **不会**出现「预算拒绝但账本里 `temperature=0.0` 已发送」这种自欺记录。

---

## 5. provider 接入

```python
from agent.platform.adaptive.call_ledger import CallLedger
from agent.platform.adaptive.llm_provider import provider_from_env

provider, status = provider_from_env(
    env,                          # key/base/model…
    ledger=CallLedger("runs/calls.jsonl"),
)
provider({"task_id": "w4-t01", "round_no": 1, "observation": {...}})
```

| 路径 | 记账内容 |
|---|---|
| 成功（`status="ok"`） | 请求/响应哈希 + `params_sent` + 原始 usage + `finish_reason` |
| 响应没回来的失败（超时 / 网络 / HTTP / 传输协议错误） | 请求哈希 + `params_sent` + `auth_header_present=true`；`response_sha256=null` + `response.reason=response_absent` |
| 响应到了但不可用（`empty_response` / `invalid_json`） | 请求哈希 + `params_sent` + `auth_header_present=true`；`response.present=true`，哈希是**收到的那段 content**（空串也有哈希）；回包带 `usage`/`finish_reason` 就照实记 |
| 回包含 key（`secret_in_output`） | 同上，但哈希绑的是脱敏后文本（不可从线路字节复算，见 §2） |
| 缺 key / 预算拒绝 / `price_unknown` | `status` + `error` + `call_state=not_invoked`；四个 body 参数 `missing/no_request_built`（`json_mode=False` 时 `response_format` 记 `not_sent`） |

- **默认不记账**：`ledger=None` → 一个文件都不写（保持 provider 的只读语义，
  `tests/test_v3_real_ab.py` 里「运行期禁止任何写入」的断言不受影响）。
- **环境变量**：`VULNMAP_LLM_LEDGER=<path>`（A/B 入口侧主用名）或
  `VULNMAP_CALL_LEDGER=<path>`（主名 / 历史兼容名）时 `provider_from_env()` 与
  `run_real_ab()`（内部 `_provider_with_budget`）自动挂账本；设为空串 = 不记账。
  两个都设且指向**不同文件**时 `ledger_path_from_env()` 抛 `CallLedgerError`
  （不静默二选一；同一文件的相对/绝对写法按 `resolve()` 归一，不算冲突）。
  传了 `env` mapping 时**只**读这个 mapping，不回落 `os.environ`。
- **注入 provider 也接账本**：`run_real_ab(provider=…)` 时按 `ledger=` 参数或
  环境变量解析，再 `attach_ledger_to_provider()` 挂到没有账本的 provider 上
  （已有账本不覆盖）；文档顶层因此带
  `call_ledger = {"enabled","path","written","errors","note"}`。
- **记账失败不改调用语义**：IO 故障只让 `snapshot()["ledger"]["errors"]` 里多一行，
  调用结果照常返回；但**出现凭据材料**时该条直接不写（fail-closed on secret）。
- `status()` / `snapshot()` 的 `ledger` 块：`{"enabled", "path", "written", "errors"}`，
  路径里没有 key。

### 5.1 key 不落盘的护栏

`assert_no_secret_record()` 在**写盘前**与**读回时**各跑一遍；provider 侧把
`config.api_key` 作为 `secret=` 传进 `build_call_record()` 与 `CallLedger.append()`
（不是只靠"记录里恰好没有 key"）：

- 键名黑名单（`FORBIDDEN_KEYS`）：`api_key` / `apikey` / `api-key` / `x-api-key` /
  `authorization` / `auth` / `headers` / `bearer` / `access_token` / `secret` / `password`；
- 文本特征：调用方给出的 key 原文、`Bearer `、`"api_key"` / `"authorization"` 字面量。

命中即抛 `CallLedgerError`，**那一行不写**（`test_key_and_bearer_never_persisted`
验证文件字节数不变）。

---

## 6. append-only 语义

| 规则 | 实现 |
|---|---|
| 只追加 | `os.open(path, O_WRONLY\|O_CREAT\|O_APPEND)` + `os.write(line + "\n")`（`fsync=True` 时另做 `os.fsync`） |
| 不重写/不截断/不排序 | 打开已有文件时**只读**内容定续号起点 `max(行数, 最大 seq)`，不写任何旧行 |
| 尾行必须完整 | 打开时与追加时都检查「文件以 `\n` 结尾」；缺尾换行＝写一半崩溃／被截断，**拒写**（否则新行会拼到旧行上，把旧记录毁掉） |
| 坏账本不续写 | 打开时逐行 `json.loads`；坏行直接抛 `CallLedgerError`（不跳过、不当空文件） |
| 写盘前先校验 | `append()` 先 `validate_record()`：字段齐全、三态不交且覆盖全集、哈希 64 hex、无凭据——一条坏条目不会让整本账不可读 |
| 多实例不重号 | 追加时持 `fcntl.flock` 独占锁，锁内**重算** `seq`（`max(行数, 最大 seq)+1`；文件被别人改过、或中间被拿掉一行，都按最大值续，不会重号；POSIX 之外退化为进程内计数）。锁获取失败时只 `close` 不 `unlock`，不漏 fd |
| 读回即校验 | `read_records(path)`：逐条 `validate_record()` + `seq` **严格递增**（重号／篡改／多实例撞号都会报错）。`seq` 校验**不受 `validate=False` 影响**——它查的是文件结构不变量 |
| 内存模式 | `CallLedger(None)` 只在内存留 `entries()`/`written`，供「不落盘」场景与单测 |

**无 `seq` 的旧式行**（手工拼接/早期文件）口径统一：`validate_record` 允许缺 `seq`、
`read_records` 与 `_count_existing`、锁内重算都只把它计入行数、不做编号校验；
编号相同的两行、或编号倒退，仍然一律拒读写。

`seq` 的作用：**账本内的唯一键**。重号、倒序、篡改都会在 `read_records()` 报错；
缺号（`seq` 跳号）也说明有记录被拿掉。`call_id` 只是 provider **实例内**序号，
多实例写同一账本时可能重号——所以唯一键是 `seq`。

---

## 7. 无害固定样例（不调用真实模型）

`tests/test_call_ledger.py` 起一个 `127.0.0.1` 的 `ThreadingHTTPServer`（默认
`urllib` 传输，不注入 transport），跑 **2 次调用**，然后：

| 验证点 | 断言 |
|---|---|
| append-only | 2 行；第二次写入的**字节前缀**包含第一次的全文；`seq=1,2`；`call_id=call-0001,call-0002` |
| 三态 | `params_sent` 与 fixture 收到的 body 逐键对齐；`params_not_sent` 只有理由码；成功调用 `params_missing={}`；三态不交、覆盖全集 |
| 不回填 | 缺 key / 预算拒绝的两条：`params_sent={}`、四个 `missing/no_request_built`、`temperature` 不在 `params_sent` |
| 哈希绑定 | 用 fixture 收到的 body 与回包的 content 独立复算，与 `request_sha256` / `response_sha256` 逐字节相等 |
| 无 key | 文件里没有 key 原文 / `Bearer` / `authorization`；带凭据键名的条目被拒且文件字节不变 |
| usage | 不带 usage 的 fixture → `null` + `usage_absent`，文件里不出现 `"prompt_tokens":0` |
| 失败事实位 | 超时记录 `auth_header_present=true`（请求确实带 Authorization）、`response_sha256=null`；空 content 记录 `present=true/chars=0`；坏 JSON 的响应哈希可由原文复算；`invalid_json` / `secret_in_output` 回包带的 `usage`/`finish_reason` 照实记，`secret_in_output` 落的是脱敏后文本的哈希 |
| seq 唯一 | 两个实例**先都打开空账本**再交叉 append → `seq` 1..6 不重号（覆盖锁内重算分支）；跳号文件按 `max(行数,最大 seq)+1` 续；手工改成重号后 `read_records()` 报错 |
| 拒绝坏条目 | 尾行缺换行／三态重叠／缺字段的条目一律拒写，文件字节数不变 |

本地 fixture 的 endpoint 是 `127.0.0.1`，所以账本里 `endpoint_source="simulated"`、
`transport="urllib"`：**通路被验证，但结论不进真实统计**（与 `real_ab` 的来源口径一致）。

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 -m pytest tests/test_call_ledger.py -q      # 期望 14 passed
python3 -m pytest tests/test_v3_real_ab.py -q       # 期望 19 passed（未回归）
```

---

## 8. 边界：这个账本**不做**什么

| 不做 | 原因 |
|---|---|
| 回填历史 run 的参数 | 历史请求体没落盘，回填即伪造（取证文档 §2.4 已纠正过一次） |
| 证明「服务端按此采样」 | 账本记的是**客户端实际发送**的键值；服务端是否照做，账本管不了（与 `public_params()` 的限定同口径） |
| 记录响应 `id` 当 `request_id` | 客户端不消费它；记了会制造一个假的「已捕获」 |
| 改 `verify` / `benchmark` 判定 | 本改动只在 `adaptive/`、`tests/`、`docs/`；`strict_submittable` / D2 判据不变 |
| 默认开启落盘 | 默认 `ledger=None`；要记账必须显式给路径或设 `VULNMAP_LLM_LEDGER` / `VULNMAP_CALL_LEDGER` |
| 保证账本一定写得进去 | 写失败（IO／凭据护栏／尾行损坏）时那一条不写，错误只进 `snapshot()["ledger"]["errors"]`；调用结果与调用语义都不变 |
| 改写已有 A/B 报告格式 | 账本是旁路文件；A/B 文档只**新增**只读块 `call_ledger`（开关/路径/条数/错误）与 markdown 一行摘要，既有字段与判据不变 |

要让 D2 这条真正过，仍需要取证文档 §7 那三步（业务代码逐调用落 `public_params()`、
`LlmResult` 落 `request_id`、重跑受影响案例）；本账本是其中的**参数侧最小实现**，
且只对**新调用**生效。
