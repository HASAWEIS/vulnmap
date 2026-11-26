"""V3-018：后端契约（Capabilities / BackendRequest / BackendResult / Lease）。

口径（《VULNMAP-V3 完整升级方案》§14「引擎适配与部署」、§5「执行感知」、
§10「执行可靠性、取消与恢复」）：

- **能力先声明、再执行**：`Capabilities` 逐项写 `supported / unsupported` 与
  探测证据；缺必需能力在动作发生**之前**阻断（`Capabilities.require`），
  不允许“先打一枪再看能不能用”。
- **后端只产事实**：`BackendResult` 只装两侧状态、体哈希、是否断开、是否超时、
  阻断原因与证据引用。它**没有**、也不允许出现 `verified / confirmed / verdict`
  字段——漏洞结论只能由 `agent.platform.verify` 与 `benchmark_policy` 推导。
- **四态结果**：`applied / failed / unknown / rejected`。
  - `applied`：一次动作真的跑完并留下观测事实（有差异、无差异都算跑完）；
  - `failed`：确定没跑完（超时、不可达、两侧都没响应），是缺口不是负结果；
  - `unknown`：不知道成没成（租约丢失、恢复时证据不足），必须先对账；
  - `rejected`：请求本身不合法/身份不一致/能力缺失，动作根本没发出去。
- **身份一致**：请求可携带 `binding_hash`；与本次会话的可信 `Binding.hash`
  不一致就是伪造，`rejected(forged_identity)`，不会“以后端返回的为准”。
- **租约带栅栏**：`Lease` 的 `owner + fence` 是提交结果的唯一钥匙；
  过期或被抢走就是 `LeaseLost`，迟到的结果不覆盖新 owner。
- **恢复不盲重放**：`RecoveryAction` 只有
  `reuse / adopt / requeue / hold / mark_unknown` 五种决定；只有声明为
  `read_only` 的外部动作（HTTP GET 差分）在租约过期且无证据时才允许 `requeue`，
  其余一律 `hold + needs_manual`。

本模块只定义契约与判定词形，不跑目标、不写结论。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA = "vulnmap.adaptive.backend.v1"
SCHEMA_VERSION = 1

#: 后端对外词形：能力表、结果、证据 kind 都用这一份，不各写一套
BACKEND_NAME = "http_service"
BACKEND_VERSION = "vulnmap.backend.http_service.v1"

#: 结果四态（与 `contracts.STATUSES` 的 applied/failed/unknown/rejected 对齐）
STATUSES = ("applied", "failed", "unknown", "rejected")

#: 一次执行的事实结局（不是漏洞结论）
OUTCOMES = ("diff", "no_diff", "timeout", "unreachable", "rejected",
            "unknown")

#: 能力状态
CAPABILITY_STATUSES = ("supported", "unsupported")

#: 恢复决定（§10：UNKNOWN 先对账，不盲目重放）
RECOVERY_ACTIONS = ("reuse", "adopt", "requeue", "hold", "mark_unknown")

#: 后端请求里允许出现的动作
REQUEST_ACTIONS = ("behavior_diff", "probe")

SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,120}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: 任何后端工件都不许出现的裁决字段名（递归按键名检查，不做字符串误伤）
VERDICT_KEYS = frozenset({"verified", "confirmed", "verdict", "pass", "trusted"})


# ====================================================================== 错误
class BackendError(ValueError):
    """后端契约错误（参数/证据/租约不自洽）。"""


class BackendRefused(BackendError):
    """可修正的拒绝：动作没发出去（身份不符、能力缺失、租约被占）。"""

    def __init__(self, code: str, reason: str, *, field_name: str = "",
                 hint: str = "") -> None:
        self.code = str(code or "backend_refused")
        self.reason = str(reason or "")
        self.field_name = str(field_name or "")
        self.hint = str(hint or "")
        super().__init__(f"{self.code}: {self.reason}")

    def to_dict(self) -> dict:
        return {"code": self.code, "reason": self.reason,
                "field": self.field_name, "hint": self.hint}


class BackendUnavailable(BackendRefused):
    """后端/能力不可用：在模型调用前就阻断。"""


class CapabilityMissing(BackendUnavailable):
    """必需能力没有声明为 supported。"""


class LeaseLost(BackendError):
    """租约丢失/过期：当前 worker 已不是 owner，必须停手且不提交结果。"""

    def __init__(self, key: str, reason: str = "") -> None:
        self.key = str(key or "")
        self.reason = str(reason or "lease_lost")
        super().__init__(f"lease lost for {self.key}: {self.reason}")


# ====================================================================== 通用
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(doc: Any) -> str:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest_of(doc: Any) -> str:
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _assert_no_verdict(doc: Any, *, where: str = "backend") -> None:
    """递归按键名拒绝裁决字段：后端不写结论，别名也不行。"""
    if isinstance(doc, Mapping):
        for key, value in doc.items():
            if str(key).lower() in VERDICT_KEYS:
                raise BackendError(
                    f"{where} 不得携带裁决字段 {key!r}（结论只由 verify 写）")
            _assert_no_verdict(value, where=where)
    elif isinstance(doc, (list, tuple)):
        for item in doc:
            _assert_no_verdict(item, where=where)


# ====================================================================== 能力
@dataclass(frozen=True)
class Capability:
    """一项能力的声明：状态 + 探测证据 + 不支持时的原因。"""

    name: str
    status: str
    reason: str = ""
    evidence: Mapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        name = _clean(self.name)
        if not name:
            raise BackendError("capability.name is required")
        status = _clean(self.status)
        if status not in CAPABILITY_STATUSES:
            raise BackendError(
                f"capability {name}: status must be one of "
                f"{CAPABILITY_STATUSES}, got {status!r}")
        if status == "unsupported" and not _clean(self.reason):
            raise BackendError(
                f"capability {name}: unsupported 必须写原因（不能只留空）")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "reason", _clean(self.reason))
        object.__setattr__(self, "evidence", dict(self.evidence or {}))

    @property
    def supported(self) -> bool:
        return self.status == "supported"

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status,
                "reason": self.reason, "evidence": dict(self.evidence)}


@dataclass(frozen=True)
class Capabilities:
    """一个后端的完整能力表：`require()` 在动作前阻断缺能力。"""

    backend: str
    version: str
    items: Mapping = field(default_factory=dict)
    required: tuple = ()
    probe: Mapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        backend = _clean(self.backend)
        version = _clean(self.version)
        if not backend or not version:
            raise BackendError("capabilities need backend name and version")
        items = {}
        for key, value in dict(self.items or {}).items():
            cap = value if isinstance(value, Capability) else Capability(**value)
            if cap.name != str(key):
                raise BackendError(
                    f"capability key {key!r} != declared name {cap.name!r}")
            items[str(key)] = cap
        required = tuple(_clean(name) for name in (self.required or ()))
        for name in required:
            if name not in items:
                raise BackendError(f"required capability {name!r} is not declared")
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "items", items)
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "probe", dict(self.probe or {}))

    def get(self, name: str) -> Capability | None:
        return self.items.get(str(name or ""))

    def supports(self, name: str) -> bool:
        cap = self.get(name)
        return bool(cap and cap.supported)

    def require(self, *names: str) -> None:
        """缺能力就在动作之前拒绝（不先跑一次再解释）。"""
        names = tuple(names) or self.required
        missing = [name for name in names if not self.supports(name)]
        if missing:
            detail = []
            for name in missing:
                cap = self.get(name)
                detail.append(f"{name}:{cap.status if cap else 'undeclared'}"
                              + (f"({cap.reason})" if cap and cap.reason else ""))
            raise CapabilityMissing(
                "backend_capability_missing",
                f"后端 {self.backend} 缺少必需能力：{', '.join(detail)}",
                field_name="capability",
                hint="换后端或在能力表里补齐实现后再调用")

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "backend": self.backend,
            "version": self.version,
            "required": list(self.required),
            "probe": dict(self.probe),
            "capabilities": {name: cap.to_dict()
                             for name, cap in self.items.items()},
        }


# ====================================================================== 请求
@dataclass(frozen=True)
class BackendRequest:
    """一次后端动作的请求：动作 + 参数 + 声称的绑定摘要。

    `params` 由各后端自己解释（HTTP 服务型后端认 `baseline_url /
    patched_url / method / headers / timeout / expect`），但身份字段由服务端
    填，模型不能自己拼一个 `binding_hash` 冒充。
    """

    request_id: str
    action: str = "behavior_diff"
    params: Mapping = field(default_factory=dict)
    binding_hash: str = ""
    task_id: str = ""
    execution_id: str = ""

    def __post_init__(self) -> None:
        request_id = _clean(self.request_id)
        if not SAFE_KEY.match(request_id):
            raise BackendError(f"unsafe backend request_id: {request_id!r}")
        action = _clean(self.action)
        if action not in REQUEST_ACTIONS:
            raise BackendError(
                f"unsupported backend action {action!r}; "
                f"allowed {list(REQUEST_ACTIONS)}")
        if not isinstance(self.params, Mapping):
            raise BackendError("backend params must be a mapping")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "binding_hash", _clean(self.binding_hash))
        object.__setattr__(self, "task_id", _clean(self.task_id))
        object.__setattr__(self, "execution_id", _clean(self.execution_id))

    # ---- 便捷读取（不改变“参数由后端解释”的边界） ----
    @property
    def baseline_url(self) -> str:
        return _clean(self.params.get("baseline_url"))

    @property
    def patched_url(self) -> str:
        return _clean(self.params.get("patched_url"))

    @property
    def method(self) -> str:
        return _clean(self.params.get("method") or "GET").upper()

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "request_id": self.request_id,
            "action": self.action,
            "params": dict(self.params),
            "binding_hash": self.binding_hash,
            "task_id": self.task_id,
            "execution_id": self.execution_id,
        }

    @classmethod
    def behavior_diff(cls, *, request_id: str, baseline_url: str,
                      patched_url: str, method: str = "GET",
                      headers: Mapping | None = None, timeout: float = 10.0,
                      expect: Mapping | None = None,
                      binding_hash: str = "", task_id: str = "",
                      execution_id: str = "") -> "BackendRequest":
        """构造一次 VulnGym 基线/修补差分的请求（只填参数，不做判断）。"""
        return cls(
            request_id=request_id,
            action="behavior_diff",
            params={
                "baseline_url": _clean(baseline_url),
                "patched_url": _clean(patched_url),
                "method": _clean(method or "GET").upper(),
                "headers": dict(headers or {}),
                "timeout": float(timeout),
                "expect": dict(expect or {}),
            },
            binding_hash=binding_hash,
            task_id=task_id,
            execution_id=execution_id,
        )


# ====================================================================== 结果
@dataclass(frozen=True)
class BackendResult:
    """一次后端执行的结算：事实 + 证据引用 + 快照；没有裁决字段。"""

    backend: str
    backend_version: str
    request_id: str
    task_id: str = ""
    execution_id: str = ""
    status: str = "applied"
    outcome: str = ""
    binding_hash: str = ""
    request: Mapping = field(default_factory=dict)
    checks: Mapping = field(default_factory=dict)
    sides: Mapping = field(default_factory=dict)
    blockers: tuple = ()
    evidence: tuple = ()
    snapshot: Mapping = field(default_factory=dict)
    seconds: float = 0.0
    lease: Mapping | None = None
    error: Mapping | None = None
    collected_at: str = ""

    def __post_init__(self) -> None:
        for label, value in (("backend", self.backend),
                             ("backend_version", self.backend_version),
                             ("request_id", self.request_id)):
            if not _clean(value):
                raise BackendError(f"backend result {label} is required")
        status = _clean(self.status)
        if status not in STATUSES:
            raise BackendError(
                f"backend result status must be one of {STATUSES}, "
                f"got {status!r}")
        outcome = _clean(self.outcome)
        if outcome and outcome not in OUTCOMES:
            raise BackendError(
                f"backend result outcome must be one of {OUTCOMES}, "
                f"got {outcome!r}")
        if status in ("failed", "unknown", "rejected") and not (
                self.blockers or self.error):
            raise BackendError(
                f"{status} 结果必须带 blockers 或 error（不能空着解释）")
        if status == "applied" and not outcome:
            raise BackendError("applied 结果必须写 outcome（diff/no_diff）")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "blockers",
                           tuple(str(b) for b in (self.blockers or ())))
        evidence = []
        for item in self.evidence or ():
            entry = dict(item)
            path = _clean(entry.get("path"))
            digest = _clean(entry.get("sha256"))
            if digest and not HEX64.match(digest):
                raise BackendError(f"bad evidence sha256: {digest!r}")
            evidence.append({"kind": _clean(entry.get("kind")),
                             "path": path, "sha256": digest,
                             "size": int(entry.get("size") or 0)})
        object.__setattr__(self, "evidence", tuple(evidence))
        object.__setattr__(self, "request", dict(self.request or {}))
        object.__setattr__(self, "checks", dict(self.checks or {}))
        object.__setattr__(self, "sides", dict(self.sides or {}))
        object.__setattr__(self, "snapshot", dict(self.snapshot or {}))
        object.__setattr__(self, "seconds", float(self.seconds or 0.0))
        object.__setattr__(self, "lease",
                           dict(self.lease) if self.lease else None)
        object.__setattr__(self, "error",
                           dict(self.error) if self.error else None)
        if not self.collected_at:
            object.__setattr__(self, "collected_at", now())
        _assert_no_verdict(self.to_dict(), where=f"backend result {self.request_id}")

    @property
    def ok(self) -> bool:
        """只有“真的跑完并留下事实”才算 ok；unknown 不是 ok 也不是失败。"""
        return self.status == "applied"

    @property
    def timed_out(self) -> bool:
        return self.outcome == "timeout"

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "backend": self.backend,
            "backend_version": self.backend_version,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "execution_id": self.execution_id,
            "status": self.status,
            "ok": self.ok,
            "outcome": self.outcome,
            "binding_hash": self.binding_hash,
            "request": dict(self.request),
            "checks": dict(self.checks),
            "sides": dict(self.sides),
            "blockers": list(self.blockers),
            "evidence": [dict(item) for item in self.evidence],
            "snapshot": dict(self.snapshot),
            "seconds": self.seconds,
            "lease": dict(self.lease) if self.lease else None,
            "error": dict(self.error) if self.error else None,
            "collected_at": self.collected_at,
        }


# ====================================================================== 租约
@dataclass(frozen=True)
class Lease:
    """一次认领的凭据：owner + fence 是提交结果的唯一钥匙。"""

    key: str
    owner: str
    fence: int
    backend: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0
    attempt: int = 1

    def __post_init__(self) -> None:
        key = _clean(self.key)
        owner = _clean(self.owner)
        if not key or not owner:
            raise BackendError("lease needs key and owner")
        fence = int(self.fence or 0)
        if fence <= 0:
            raise BackendError("lease fence must be > 0")
        expires = float(self.expires_at or 0.0)
        if expires <= 0:
            raise BackendError("lease expires_at must be > 0")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "fence", fence)
        object.__setattr__(self, "backend", _clean(self.backend))
        object.__setattr__(self, "issued_at", float(self.issued_at or 0.0))
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "attempt", int(self.attempt or 1))

    def expired(self, now_ts: float) -> bool:
        return float(now_ts) >= self.expires_at

    def to_dict(self) -> dict:
        return {"key": self.key, "owner": self.owner, "fence": self.fence,
                "backend": self.backend, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "attempt": self.attempt}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "Lease":
        if not isinstance(doc, Mapping):
            raise BackendError("lease must be a mapping")
        return cls(key=_clean(doc.get("key")), owner=_clean(doc.get("owner")),
                   fence=int(doc.get("fence") or 0),
                   backend=_clean(doc.get("backend")),
                   issued_at=float(doc.get("issued_at") or 0.0),
                   expires_at=float(doc.get("expires_at") or 0.0),
                   attempt=int(doc.get("attempt") or 1))


@dataclass(frozen=True)
class RecoveryAction:
    """恢复决定：先对账再决定复用/采纳/重派/挂起/标未知。"""

    key: str
    action: str
    reason: str
    status: str = "unknown"
    needs_manual: bool = False
    evidence: Mapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        key = _clean(self.key)
        action = _clean(self.action)
        if not key:
            raise BackendError("recovery action needs a key")
        if action not in RECOVERY_ACTIONS:
            raise BackendError(
                f"unknown recovery action {action!r}; "
                f"allowed {list(RECOVERY_ACTIONS)}")
        if action == "hold" and not _clean(self.reason):
            raise BackendError("hold 必须写原因（为什么不能自动重放）")
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "reason", _clean(self.reason))
        object.__setattr__(self, "status", _clean(self.status) or "unknown")
        object.__setattr__(self, "needs_manual", bool(self.needs_manual))
        object.__setattr__(self, "evidence", dict(self.evidence or {}))

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "key": self.key,
            "action": self.action,
            "reason": self.reason,
            "status": self.status,
            "needs_manual": self.needs_manual,
            "evidence": dict(self.evidence),
        }


__all__ = [
    "BACKEND_NAME", "BACKEND_VERSION", "BackendError", "BackendRefused",
    "BackendResult", "BackendRequest", "BackendUnavailable", "Capabilities",
    "Capability", "CapabilityMissing", "OUTCOMES", "RECOVERY_ACTIONS",
    "REQUEST_ACTIONS", "RecoveryAction", "Lease", "LeaseLost", "SCHEMA",
    "SCHEMA_VERSION", "STATUSES", "canonical_json", "digest_of", "now",
    "sha256_hex",
]
