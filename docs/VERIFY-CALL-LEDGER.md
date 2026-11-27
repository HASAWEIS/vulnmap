# 课程验证入口的逐调用账本（VERIFY-CALL-LEDGER）

> 范围：agent/llm.py（账本唯一落盘点）、agent/stages/base.py（run 上下文绑定）、
> agent/stages/verify.py（参数证据判定）、tests/test_verify_call_ledger.py（四场景）、
> experiments/verify-ledger-demo/（脱敏账本 + 轨迹 + 对账 + 日志）。
> **不动**：verify 的漏洞判据、benchmark policy、执行器语义、历史 case.json。

## 0. 一句话

课程验证入口（VerifyStage 的模型闭环）现在**每次调用都留一条可按 (run_id, call_id) 追溯的记录**，
记录里只有**实际发送**的值；调用前被拒也留痕，且证明“没有发出去”。
**这只说明新运行具备取证能力，不改变 CG-07 / CG-18 历史缺参的事实。**

## 1. 为什么挂在 agent/llm.py

VerifyStage 的模型闭环走 run_diverse_loop → call_llm → llm.call_json。
call_json 是课程路径上**唯一的** HTTP 出口，所以账本只在这里写一次：
入口换了、阶段换了，只要还经过 call_json，就一定有记录。

## 2. 关联键：为什么必须是 (run_id, call_id)

- call_id 只在单次 run 内递增（call-0001、call-0002…），便于人读；
- 跨 run 只靠 call_id 会串账，因此记录里同时写 run_id 与派生键：
  - run_id：由 Stage 在执行期间绑定（set_run_context(run_id, stage)）；
  - call_key = “<run_id>::<call_id>”，归档与对账都用它；
- 轨迹侧（attempts / blackboard）用同一个 run_id，因此“轨迹里的这次调用”与
  “账本里的这一行”能一一对上。

## 3. 三态字段：sent / not_sent / missing

| 字段 | 含义 | 来源 |
|---|---|---|
| params_sent | **实际出现在请求体里**的键值 | config.request_body() 真正构造出的 body |
| params_not_sent | 客户端结构性不发送（top_p / seed / n / stop） | NOT_SENT_PARAMS，理由码 absent_by_design |
| params_missing | 本该有却没记到（请求未构造 / body 未捕获 / 缺关键键） | 按 body 实际内容判定 |

三条纪律：

1. **不用默认值回填**。temperature=0.0 只有在它真的进了 body 时才算 sent；
2. 预算拒绝 / 无 key 的调用：四个参数全部 missing（reason=request_not_built），
   并且 request_sha256 为空——证明“没发出去”；
3. prompt_version 是**本地运行元数据**（客户端不发送它），记录里单独作为字段，
   不混进 params_sent。

## 4. 不落凭据

- 记录里没有 api_key、没有 Authorization 头值；
- 只保留 endpoint_host（不含 path/query）与 header 是否存在；
- 测试断言账本全文不含 sk-、authorization、bearer。

## 5. 证据缺失不能悄悄通过

VerifyStage 新增 _param_evidence(loop_rounds)，只读账本汇总，输出：

| status | 触发条件 |
|---|---|
| not_recorded | 账本未配置（VULNMAP_LLM_LEDGER 未设） |
| incomplete | 坏行、sent 行缺 request_sha256、写盘失败、有闭环轮次但本 run 无行 |
| complete | 有行、有请求哈希、无坏行、且模型闭环确实产生过调用 |

**它不参与漏洞判定**：verify 的 verdict 仍由既有双端判据决定。
参数证据不完整只写进结果（result.param_evidence）与报告，
不会把“账本坏了”写成“漏洞没验证通过”。

## 6. 四个验收场景（tests/test_verify_call_ledger.py）

| # | 场景 | 断言 |
|---|---|---|
| 1 | 正常调用 | 账本 1 行；run_id / call_id / call_key 正确；sent 值与 mock 服务**收到的请求体**逐项相等；request_sha256 与真实字节一致；usage.state=sent；无 key |
| 2 | 预算拒绝 | 抛 BudgetExhausted；**HTTP 请求 0 次**；账本 1 行 refused_before_send；request_sha256 为空；missing=request_not_built |
| 3 | 同任务连续两次运行 | 两个 run_id 各 2 行；call_id 各自从 0001 起；按 run_id 汇总互不串账 |
| 4 | 账本不可写 | res.ledger.written=false；ledger_summary 不是 complete；_param_evidence 判 incomplete |
| 4b | 无行 / 未配置 | _param_evidence 判 not_recorded / incomplete，绝不为 complete |

```bash
python3 -m pytest tests/test_verify_call_ledger.py -q
# 5 passed
```

## 7. 交付物（experiments/verify-ledger-demo/）

| 文件 | 内容 |
|---|---|
| run_demo.py | 走真实入口 call_json，生成下列产物（本地 fixture，不用真 key） |
| calls.jsonl / calls.sanitized.jsonl | 脱敏账本（原始 / 脱敏两份，脱敏件附 SHA256） |
| trajectory.json | 轨迹行：run_id / round / status / ledger_call_id / 请求响应哈希 |
| reconciliation.json | 按 run_id 对账：call_keys、states、request_hashes、trajectory_matched |
| logs/00-all.log … 04-unwritable.log | 四组测试日志 |

对账结果（本次）：3 个 run（r-demo-A / r-demo-B / r-demo-budget），5 条轨迹行全部
匹配到账本行；预算 run 的 request_hashes 为空串；no_key_material=true。

## 8. 边界

- 本能力只覆盖**新运行**。CG-07 / CG-18 的历史记录仍是 missing，不因本次改造变成通过；
- 账本默认关闭（不设 VULNMAP_LLM_LEDGER 就不写文件），避免默认产生额外落盘；
- 账本只证明“发了什么”，不证明“模型说得对”；
- 与 adaptive/call_ledger.py（A/B 用）是两套入口、同一套三态口径，字段名保持一致。
## 9. 门禁修正（2026-11-27）：必需调用逐条核对

上一版 `_param_evidence` 只比“有没有行 / 有没有哈希”，因此**轨迹要求 2 条、账本只剩 1 条**
时仍会返回 `complete`。修正后：

1. 轨迹（每轮 `llm_calls`）显式记下 `llm_call_id` 与 `request_sha256`；
2. `param_evidence` 改为按 `(run_id, call_id)` **逐条**核对，不再拿轮数比行数；
3. 四类问题分别报告：`missing`（本 run 无此 id）/ `foreign`（只在别的 run）/
   `hash_mismatch`（哈希不符）/ `wrong_state`（不是 sent，如预算拒绝不能顶替）；
4. 有任一问题即 `incomplete`，并列出具体缺失引用；**判定与历史记录都不动**。

五个验收场景（`tests/test_verify_call_ledger.py`）：

| 场景 | 预期 | 结果 |
|---|---|---|
| 必需调用全对上 | complete | ✅ |
| 缺一条必需调用 | incomplete + missing | ✅（旧口径会误报 complete，测试里显式断言了这一点） |
| 行数够但一条来自别的 run | incomplete + foreign | ✅ |
| 引用对上但哈希不一致 | incomplete + hash_mismatch | ✅ |
| 只有预算拒绝记录 | incomplete + wrong_state，拒绝记录保留 | ✅ |

```bash
python3 -m pytest tests/test_verify_call_ledger.py -q     # 11 passed
```
