"""V3-018：可选单一新后端（P5）。

方案落点见《VULNMAP-V3 完整升级方案》§14「引擎适配与部署」：
先支持现有 covfuzz、replay 与 HTTP 差分；统一
`prepare/build/smoke/execute/observe/cancel/capabilities` 接口；能力逐项写
supported/unsupported 与探测证据，缺必需能力在模型调用前阻断。

本子包只做**一个**后端：纯 HTTP 服务型（VulnGym 基线/修补请求），不需要新镜像。

```
Capabilities  capabilities()        能力表（版本固定 + 探测证据）
Backend       execute(request)      两侧各一次 HTTP，只产事实
              collect(result)       写证据 + 七组事实快照
              lease(key)            进程内 owner + fence 租约
              recover(record)       UNKNOWN 先对账，不盲目重放
```

边界：

- 不写 `verified / confirmed / verdict`；漏洞结论仍由
  `agent.platform.verify` 与 `benchmark_policy` 推导；
- 失败/超时/不可达都是**缺口**：`status=failed` + 具体 blocker，不洗成
  `no_diff`；所有权不明时 `status=unknown`，先对账；
- 证据按内容寻址落 `EvidenceStore`（`backend_request / backend_result /
  backend_snapshot / backend_<side>_body`）；
- 工具经 `BACKEND_REGISTRY` 走同一 Registry/ToolContext 闸门，不绕开权限、
  预算与失效登记。

用法：

```python
from agent.platform.adaptive.backends import HttpServiceBackend, BackendRequest

backend = HttpServiceBackend(workdir=".platform/backend")
caps = backend.capabilities(probe=True)
caps.require("behavior_diff")
result = backend.execute(BackendRequest.behavior_diff(
    request_id="be-1", baseline_url=..., patched_url=...), binding=binding)
collected = backend.collect(result, store=store, task_id=task_id,
                            evidence_root=".platform/evidence")
```
"""
from .base import Backend, build_snapshot, process_owner
from .contracts import (BACKEND_NAME, BACKEND_VERSION, BackendError,
                        BackendRefused, BackendRequest, BackendResult,
                        BackendUnavailable, Capabilities, Capability,
                        CapabilityMissing, Lease, LeaseLost, RecoveryAction)
from .http_service import HttpServiceBackend, source_sha256
from .tools import (BACKEND_REGISTRY, backend_capabilities, backend_diff,
                    backend_recover, build_registry, build_specs,
                    default_backend, set_default_backend)

__all__ = [
    "BACKEND_NAME", "BACKEND_VERSION", "BACKEND_REGISTRY", "Backend",
    "BackendError", "BackendRefused", "BackendRequest", "BackendResult",
    "BackendUnavailable", "Capabilities", "Capability", "CapabilityMissing",
    "HttpServiceBackend", "Lease", "LeaseLost", "RecoveryAction",
    "backend_capabilities", "backend_diff", "backend_recover",
    "build_registry", "build_snapshot", "build_specs", "default_backend",
    "process_owner", "set_default_backend", "source_sha256",
]
