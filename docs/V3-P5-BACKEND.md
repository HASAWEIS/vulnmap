# V3 P5：可选单一新后端（V3-018）

对应《VULNMAP-V3 完整升级方案》§14「引擎适配与部署」、§5「执行感知」、
§10「执行可靠性、取消与恢复」，以及 §19.6「每项实际代码修改需产出可复算证据」
的工程口径。前置 P5（[V3-P5-PATCH.md](V3-P5-PATCH.md)）。

一句话边界：**新增一个纯 HTTP 服务型后端，把 VulnGym 基线/修补两侧的行为差分
做成可复核的执行事实；它只产 `diff / no_diff / timeout / unreachable`，
漏洞结论仍只由 `agent.platform.verify` 与 `benchmark_policy` 推导。**

本批改动没有改 `verify.py`、`benchmark_policy`、执行器分派、DB schema 与任何写
端点，也没有 `git commit`。落点是新子包 `agent/platform/adaptive/backends/`、
三个经 Registry 暴露的工具、一份验收测试和本文。

---

## 0. 实施清单

| 项 | 状态 | 验收口径 | 落点 | tests |
|---|---|---|---|---|
| P5-018-1 后端接口 | 已实施 | `Backend` 同时提供 `capabilities / execute / collect / lease / recover`；具体后端只实现前两个，其余从公共壳继承 | `backends/base.py` | `test_capabilities_fixed_version_and_probe_evidence` |
| P5-018-2 能力探测与阻断 | 已实施 | 版本固定为 `vulnmap.backend.http_service.v1`；能力逐项 `supported/unsupported` 并写原因；`probe` 带源码哈希；缺 `behavior_diff` 时在发请求前 `rejected` | `backends/contracts.py`（`Capability/Capabilities`）、`backends/http_service.py`、`backends/tools.py` | 同上 + `test_missing_capability_blocks_tool_before_any_request` |
| P5-018-3 HTTP 服务型后端 | 已实施 | 两侧各打一次 HTTP；不跟 3xx、禁代理、1 MiB 截断、体哈希现场算；连接断开/拒绝如实记账；**不依赖任何镜像** | `backends/http_service.py` | `test_success_is_applied_no_diff_and_collect_writes_evidence`、`test_behavior_difference_detected_without_verdict` |
| P5-018-4 失败/超时/UNKNOWN | 已实施 | 超时 → `failed + backend_timeout:<side>`；不可达 → `failed + backend_unreachable`；请求已发出但租约丢失 → `unknown`，不自宣成功/失败 | `backends/http_service.py`、`backends/base.py` | `test_timeout_is_failed_gap_not_no_diff`、`test_unreachable_is_failed_with_blocker`、`test_lease_lost_mid_flight_is_unknown_not_failure_or_success` |
| P5-018-5 证据与快照 | 已实施 | `collect()` 写 `backend_request / backend_result / backend_snapshot / backend_<side>_body`；快照七组事实，缺项为 `unknown`，不填 0 | `backends/base.py`（`build_snapshot`） | `test_success_...`、`test_collect_without_store_...` |
| P5-018-6 接 Registry/ToolContext | 已实施 | `backend_capabilities`（L0）、`backend_diff`（L1/execution/explore）、`backend_recover`（L0）经同一 `Registry.invoke`；写 session trial 与 `execution_facts` 失效 | `backends/tools.py`、`ToolContext.backend` 槽位 | `test_registry_tool_writes_evidence_snapshot_trial_and_invalidation` |
| P5-018-7 身份一致 | 已实施 | 伪造 `binding_hash`、task/execution 不一致、非 vulngym benchmark → 发请求前 `rejected` | `backends/http_service.py`（`_identity_problem`） | `test_forged_binding_and_wrong_benchmark_are_rejected_before_request` |
| P5-018-8 租约与恢复 | 已实施 | owner + fence + TTL 互斥；恢复顺序：终态 reuse → 证据 adopt → 活跃租约 hold → 只读 requeue → 外部副作用 hold/mark_unknown | `backends/base.py` | `test_recovery_reuses_adopts_requeues_and_holds` |
| P5-018-9 不写裁决 | 已实施 | `BackendResult` 构造期递归拒绝 `verified/confirmed/verdict/pass/trusted` 键；测试对结果、快照、能力表逐项扫描 | `backends/contracts.py`（`_assert_no_verdict`） | `test_result_contract_refuses_verdict_fields_and_bad_status` |
| P5-018-10 文档 | 本文 | 接口、语义、证据路径、恢复表、测试矩阵、边界 | `docs/V3-P5-BACKEND.md` | — |

### 0.1 文件清单

| 文件 | 变化 | 行数 |
|---|---|---|
| `agent/platform/adaptive/backends/__init__.py` | 新增。子包门面与用法说明 | 61 |
| `agent/platform/adaptive/backends/contracts.py` | 新增。能力表、请求/结果、租约、恢复决定、裁决字段硬拒 | 539 |
| `agent/platform/adaptive/backends/base.py` | 新增。`Backend` 公共壳：租约、证据落库、七组快照、恢复对账 | 433 |
| `agent/platform/adaptive/backends/http_service.py` | 新增。HTTP 服务型后端（VulnGym 基线/修补、不依赖镜像） | 446 |
| `agent/platform/adaptive/backends/tools.py` | 新增。三个工具 + 组合 Registry（基础工具表 + 后端表） | 310 |
| `agent/platform/adaptive/contracts.py` | 改动。`ToolContext` 增加 `backend` 槽位（默认 `None`，向后兼容） | +2 |
| `agent/platform/adaptive/tools.py` | 改动。`make_context(..., backend=None)` 透传 | +2 |
| `agent/platform/adaptive/__init__.py` | 改动。导出 `backends` 门面（不改变既有导出） | +8 |
| `tests/test_v3_backend_http.py` | 新增。14 个测试函数 | 552 |
| `docs/V3-P5-BACKEND.md` | 本文 | — |

`agent/platform/verify.py`、`adaptive/policy.py`、`benchmark_policy`、执行器
分派、DB schema 与任何写端点**未改**。

---

## 1. 为什么先声明能力，再执行

§14 要求“Capabilities 逐项写 supported/unsupported 及探测证据；缺必需能力在
模型调用前阻断”。本实现把它写成两处硬约束：

```python
# backends/contracts.py
class Capabilities:
    def require(self, *names):
        missing = [n for n in (names or self.required) if not self.supports(n)]
        if missing:
            raise CapabilityMissing("backend_capability_missing", ...)
```

```python
# backends/tools.py  backend_diff 开头
caps = backend.capabilities()
missing = [n for n in ("behavior_diff",) if not caps.supports(n)]
if missing:
    return ToolOutcome(status="rejected", error={
        "code": "backend_capability_missing", ...})
```

能力表（`HttpServiceBackend.capabilities()`）：

| 能力 | 状态 | 探测证据 / 不支持的原因 |
|---|---|---|
| `behavior_diff` | supported | `transport=urllib.request`、`redirects_followed=false`、`proxy=disabled`、`max_body=1048576`、方法白名单 |
| `timeout` | supported | 单侧超时，blocker 词形 `backend_timeout:<side>` |
| `connection_closed` | supported | reset/refused 作为有效差分信号 |
| `tls` | supported | 只接受 `http/https`，urllib 默认校验 |
| `redirect_follow` | unsupported | 3xx 原样记账，避免“拦截页 302 到登录页”被当成 200 |
| `proxy` | unsupported | 显式 `ProxyHandler({})`，防止请求被 `HTTP_PROXY` 带出声明主机 |
| `container_image` | unsupported | **按设计不依赖任何镜像** |
| `sanitizer` | unsupported | HTTP 行为差分没有内存 sanitizer 观测 |
| `coverage` | unsupported | 行为差分不产覆盖率，不能横向冒充百分比 |
| `fuzz` | unsupported | 输入级 fuzz 仍由既有 covfuzz 执行器承担 |

固定版本：`BACKEND_VERSION = "vulnmap.backend.http_service.v1"`；`probe` 里另有
`source_sha256`（现场读 `http_service.py` 计算）与 `generated_at`，便于复核
“这份证据是哪个实现产出的”。

---

## 2. 接口与执行语义

### 2.1 五个接口

| 接口 | 签名 | 责任 |
|---|---|---|
| `capabilities` | `capabilities(*, probe=False) -> Capabilities` | 声明能力与探测证据 |
| `execute` | `execute(request, *, binding=None) -> BackendResult` | 做一次受控动作，只产事实 |
| `collect` | `collect(result, *, store=None, task_id="", evidence_root=None, binding=None, task=None) -> dict` | 写证据 + 七组快照 |
| `lease` | `lease(key, *, ttl=None, owner="") -> Lease` | 认领执行权（owner + fence + TTL） |
| `recover` | `recover(record) -> RecoveryAction` | UNKNOWN 先对账，不盲目重放 |

`lease` 另有 `renew / release / check_lease`：提交前必须
`owner + fence + 未过期` 三者同时成立，否则 `LeaseLost`；迟到的释放/提交
不会覆盖新 owner。

### 2.2 结果四态

| 状态 | 含义 | 本后端的产生条件 | 不允许的替代 |
|---|---|---|---|
| `applied` | 真的跑完并留下观测事实 | 两侧都拿到响应（含一侧断开、另一侧有响应） | 不能因为“有差异”就写 `verified` |
| `failed` | 确定没跑完 | 任一侧超时 → `timeout`；两侧都没响应 → `unreachable` | 超时/不可达不能洗成 `no_diff` |
| `unknown` | 不知道成没成 | 请求已发出但租约丢失/过期 | 不能自宣成功或失败，必须先对账 |
| `rejected` | 动作根本没发出去 | 身份不符、能力缺失、URL/method/timeout 非法、租约被占 | 不能“先打一枪再看” |

`BackendResult` 构造期还会拒绝：`status` 不在四态内、`applied` 不写 outcome、
`failed/unknown/rejected` 既无 blocker 又无 error、证据 sha256 不是 64 位小写
十六进制、任何层级出现 `verified/confirmed/verdict/pass/trusted` 键。

### 2.3 请求规则

- 只接受 `http/https` 且必须有主机；
- 方法白名单 `GET / POST / HEAD`；
- 不跟 3xx（`_NoRedirect`），不读跳转后的第三个主机；
- 显式 `ProxyHandler({})` 关闭环境代理；
- 响应体截断 1 MiB，`body_sha256` 现场计算；
- 连接被拒/重置记 `connection_closed=True`；超时记 `timed_out=True`；
- 缺 `baseline_url` 或 `patched_url` → `rejected(backend_not_configured)`，
  不拿 task target 顶替修补侧。

### 2.4 身份一致

`execute` 在发请求前检查：

1. `request.binding_hash` 非空且与 `binding.hash` 不同 → `forged_identity`；
2. `request.task_id` 与绑定不同 → `forged_identity`；
3. `request.execution_id` 与绑定不同 → `cross_execution`；
4. 绑定 identity 的 `benchmark` 非空且不是 `vulngym` → `unsupported_benchmark`。

以上都在 `server.hits == 0` 的前提下测试（测试里显式断言没有发出请求）。

---

## 3. 证据与快照

### 3.1 证据 kind

`collect()` 写入内容寻址证据库（`EvidenceStore`，`evidence/<sha256>`）：

| kind | 内容 |
|---|---|
| `backend_request` | 规范化请求文档（request_id/action/params/binding_hash/task/execution） |
| `backend_result` | 结果文档（status/outcome/checks/sides/blockers/error） |
| `backend_snapshot` | 七组事实快照 |
| `backend_baseline_body` | 基线侧响应体（≤1 MiB） |
| `backend_patched_body` | 修补侧响应体（≤1 MiB） |

没有 `store` 时仍返回快照和本地计算出的引用（`persisted=False`），方便离线复核；
有 `store` 时按既有 `EvidenceStore.put_bytes` 落库，测试逐条复算哈希。

### 3.2 七组事实

| 组 | 本后端填什么 | 不填什么 |
|---|---|---|
| `identity` | task/campaign/epoch/job/execution、source/harness/build/image、binding_hash、`backend`、`backend_version` | — |
| `config` | `engine=http_service`、`kind_override=behavior_diff`、`sanitizer=none`、`command`、`isolation=none`、`network=declared_hosts_only`、`budget_declared` | 不把“宿主网络”写成 isolated |
| `program` | 全 `unknown`（HTTP 差分没有 ProgramIndex） | 不填 0 个函数 |
| `input` | `format=http`、`observation_source=observed`、`target_reached` 三值 | `input_consumed` 观测不到 → `unknown`；`program_started` / `input_processed` / `checkpoint_reached` 后端不观测 → 全 `unknown`（口径见 `docs/V3-TARGET-SEMANTICS.md`） |
| `coverage` | `status=unsupported`、`metric_kind=behavior_diff`、`comparable=false` | 不填 covered/百分比 |
| `fault` | `outcome`、`timeout` 三值、`error`、`log_ref`（首个证据哈希） | `candidates` 留给候选层 → `unknown` |
| `budget` | `used_seconds`、`used_execs=2`（两侧各一次）、`limits` | 剩余额度观测不到 → `unknown` |

`unknown` 路径写进 `unknowns`；`false` 与 `unknown` 不互相顶替。快照的
`complete` 只在 `applied/failed` 时为 true；`unknown`（租约丢失）时
`status=unknown`，不声称“跑完了”。

---

## 4. 接 Registry / ToolContext

`backends/tools.py` 在基础工具表（`adaptive.tools.build_specs()`）之上追加三个
工具，返回组合 Registry；没有改基础 `REGISTRY`，所以 P2a 的“工具表恰好 10 个”
断言仍然成立。

| 工具 | 组 | 权限 | 模式 | 变更类别 | 失效范围 |
|---|---|---|---|---|---|
| `backend_capabilities` | read | L0 | 全部 | none | — |
| `backend_diff` | experiment | L1 | explore | execution | `execution_facts, trial_compare, coverage_baseline` |
| `backend_recover` | read | L0 | 全部 | none | — |

`ToolContext` 新增 `backend` 槽位（默认 `None` = 用进程内默认 HTTP 后端），
`make_context(..., backend=None)` 透传。控制器/测试可注入替身；测试用
`set_default_backend()` 或直接传 `ctx.backend`。

`backend_diff` 的 handler 只做四件事：

1. 读能力表，缺 `behavior_diff` 立刻 `rejected`；
2. 组装 `BackendRequest`（request_id 随机、binding_hash/task/execution 来自
   `ctx.binding`，不接受模型自带身份）；
3. `backend.execute()` → `backend.collect()`；
4. 把结果归一成 session trial（`kind=http_diff`），按结果状态返回
   `applied/failed/unknown/rejected`。

执行类失效（`execution_facts / trial_compare / coverage_baseline`）由
`ToolSpec.changes="execution"` 同源派生，进入 `Registry` 待消费集合；测试断言
`pending_invalidations(TASK)` 里确实有 `execution_facts`。

---

## 5. 租约与恢复

### 5.1 租约

- `lease(key)` 原子地 `fence + 1` 并写 owner/TTL；同 key 被别的 owner 持有且
  未过期 → `rejected(lease_held)`；
- `check_lease()` 在提交前检查 `owner + fence + 未过期`，任一不满足 →
  `LeaseLost`；
- HTTP 执行在两侧请求都完成后才 `check_lease()`：如果这时租约已丢，返回
  `unknown`（请求确实发出过，不能自宣失败）；
- `release()` 只在 fence 匹配时删除，迟到的释放不能撤销新 owner。

### 5.2 恢复顺序

`Backend.recover(record)` 的判定是确定性的：

| 顺序 | 条件 | 决定 | status | needs_manual |
|---|---|---|---|---|
| 1 | `status ∈ applied/failed/rejected` | `reuse` | 原状态 | false |
| 2 | 证据路径存在且哈希可复算 | `adopt` | applied | false |
| 3 | 租约仍活跃（未过期） | `hold` | unknown | false |
| 4 | 租约过期/缺失 + `effect=read_only` | `requeue` | unknown | false |
| 5 | 租约过期 + 外部副作用 | `hold` | unknown | true |
| 6 | 连租约都没有 + 外部副作用 | `mark_unknown` | unknown | true |

HTTP 服务型后端声明 `effect="read_only"`：GET 差分幂等，租约过期且无证据时
允许重派；其余后端若声明 `possible/external`，一律人工对账，不自动重放。

---

## 6. 验收测试

```bash
python3 -m pytest tests/test_v3_backend_http.py -q
# 14 passed
```

| 测试 | 覆盖 |
|---|---|
| `test_capabilities_fixed_version_and_probe_evidence` | 版本固定、能力逐项、unsupported 有原因、probe 源码哈希、`require("fuzz")` 抛 `CapabilityMissing` |
| `test_success_is_applied_no_diff_and_collect_writes_evidence` | 两侧 200 同体 → `applied/no_diff`；五种证据 kind；逐条复算哈希；快照七组 |
| `test_behavior_difference_detected_without_verdict` | 200 vs 403 → `diff`；体哈希不同；`expect_matches=true`；无 `verified` |
| `test_timeout_is_failed_gap_not_no_diff` | 0.25s 超时 → `failed/timeout` + `backend_timeout:baseline`；快照 `fault.timeout=true` |
| `test_unreachable_is_failed_with_blocker` | 关闭端口 → `failed/unreachable`；`connection_closed=true`；`target_reached=false` |
| `test_lease_lost_mid_flight_is_unknown_not_failure_or_success` | 请求发出后租约过期 → `unknown`；快照 `status=unknown` |
| `test_recovery_reuses_adopts_requeues_and_holds` | reuse / adopt / 篡改证据不 adopt / 活跃租约 hold / 只读 requeue / 外部副作用 hold+mark_unknown / 租约互斥与释放 |
| `test_forged_binding_and_wrong_benchmark_are_rejected_before_request` | 伪造 hash、跨 benchmark、跨 task → `rejected` 且 `server.hits == 0` |
| `test_registry_tool_writes_evidence_snapshot_trial_and_invalidation` | Registry 闸门、session trial、证据落库、`execution_facts` 失效 |
| `test_missing_capability_blocks_tool_before_any_request` | 替身后端缺能力 → `rejected`，`execute()` 一次都没调 |
| `test_backend_tool_specs_are_derived_from_handlers` | 三个后端工具的 schema/required/权限/失效范围与 handler 签名同源 |
| `test_backend_capabilities_and_recover_tools_through_registry` | L0 工具同样走 Registry：能力表可读、终态记录 `reuse` |
| `test_collect_without_store_returns_snapshot_and_local_refs` | 离线 collect 仍返回快照与本地哈希引用 |
| `test_result_contract_refuses_verdict_fields_and_bad_status` | 裁决字段、非法状态、失败无证据、未知 binding 分量全部拒绝 |

回归（同批一起跑）：

```bash
python3 -m pytest tests/test_v3_*.py -q
# 205 passed（含本次 14 个）
```

---

## 7. 边界与限制

- **只做一个后端**：不接 libFuzzer/OSS-Fuzz/Qiling，不扩镜像矩阵；`container_image`
  在能力表里明确 unsupported；
- **只做执行事实**：不写 `verified/confirmed/verdict`，不创建 candidate，不推进
  任务状态；候选与结论仍走既有 `executors` / `verify` / `benchmark_policy`；
- **网络边界**：只连请求里显式声明的两个 URL，不跟跳转、不走代理；没有实现
  容器/命名空间隔离，`config.network` 如实写 `declared_hosts_only`，不冒充
  isolated；
- **证据是内容寻址的**：同一结果重复 `collect()` 不会写重复字节；响应体超过
  1 MiB 截断，`body_bytes` 记录实际落盘长度；
- **恢复不承诺 exactly-once**：`read_only` 才允许自动重派；外部副作用必须人工
  对账（`hold + needs_manual` / `mark_unknown`）；
- **前端/API 未改**：本批没有新增 HTTP 路由；工具通过库接口与既有 Registry
  调用，后续若要在 UI 暴露，走 §15 的 API/CLI 增量，不在本批伪造写端点。
