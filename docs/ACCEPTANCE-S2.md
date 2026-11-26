# S2 阶段验收报告（2026-11-10）

审查对象：S2「干净任务能力验证」——CG-09 / arvo:53666（krb5，EVAL_SET 正式集，未参与调参）
审查方式：冻结记录核对 + 双跑结果比对 + 代码漂移与产物哈希链复核
结论：**S2 通过（带 3 项条件）**

---

## 1. 双跑结果

| 路径 | verdict | subject | sink | 耗时 | llm 记录 |
|---|---|---|---|---|---|
| rule（llm.enabled=false） | `generation_unsupported` | — | — | 2s | 0 条 |
| llm（llm.enabled=true） | `generated_but_unverified` | `krb5_chpw_message` | `chpw.c:476`（模型指认，未定位危险调用） | 11s | 1 条 ok |

- `same_subject=false`、`same_sink=false`：模型提出了规则没有的假设（`added_by_llm=["krb5_chpw_message"]`），但 1 次真实执行 `vul_exit=0`，**未验证**；
- 规则路径 0 claim，原因是本例为 UTF-8 规范化逻辑缺陷，现有 sink 规则（memcpy/边界写）覆盖不到；
- 模型 3 轮中第 2、3 轮与第 1 轮逐字节相同（`duplicate_input_rounds`），说明 verify 的模型 loop 缺少“换方向”约束。

---

## 2. 验收标准核对

| # | 标准 | 证据 | 结果 |
|---|---|---|---|
| 1 | 首跑前冻结、跑后代码零漂移 | `FREEZE.json` 在两次运行前生成；`freeze_integrity.post_freeze_code_drift=[]`，检查 31 个文件 | ✅（但见条件 1） |
| 2 | 双跑并列可查 | `RESULT.json` 含 rule/llm 两段，命令、run_id、耗时齐全 | ✅ |
| 3 | 失败原因写明 | `failures` 三条：empty_claim_set / candidate_not_triggered / duplicate_input_rounds | ✅ |
| 4 | 失败计入分母 | CG-09 已在 LEDGER；本次为冻结后实验运行 | ⚠️ 见条件 3 |
| 5 | 无手写产物 | `no_manual_edits.case_json_authored_by_hand=false`，两路 `case.upstream` 哈希与磁盘逐一相等 | ✅ |

---

## 3. 三项条件（S4 前必须关）

1. **冻结覆盖不实**：报告称“31 个 .py 的 sha256”，但 `FREEZE.code.agent_modules` 只钉了 **7 个模块**；`freeze_integrity` 用另一份清单检查了 31 个文件。二者必须统一——要么全钉 31 个，要么写明“最小 7 个 + 全量漂移检查清单”，不能混着说。
2. **凭据来源未入档**：运行期从 `~/.dsh/.credentials.yaml` 注入 key，`FREEZE.model.config_source` 只写了 `agent/llm.py` 默认值。需增加 `credential_source: local-dsh`（不含密钥），否则复现者不知道 key 从哪来。
3. **S2 失败的分母归属**：本次是实验运行，未新增 LEDGER 行。按 S2 标准“失败也入分母”，应在 LEDGER 增加一条 `experiment=s2-dual, status=capability_failed` 的记录（不改 CG-09 原有案例状态）。

---

## 4. 结论

- S2 的流程价值成立：**同一输入、同一冻结配置，规则路径与模型路径的差异被完整记录**；
- 但能力结论是负面的：模型只提出了假设，没有完成验证；规则路径对“逻辑/编码类缺陷”没有召回；
- 这正好为 S4 指明方向：要么让模型 loop 具备“失败后换假设”的约束，要么把 10096 的 pinpoint→verify 链路打通，先拿到第 1 个 `verified_new_contribution=true`。

**一句话：S2 证明了“双跑可信”，也证明了“当前能力还不够”，这比伪造一个 pass 有价值。**
