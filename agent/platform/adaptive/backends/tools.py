"""V3-018：把后端接进 Registry / ToolContext（同一闸门，不另开旁路）。

三个工具（沿用 `adaptive.contracts.ToolSpec` 的同源规则）：

| 工具 | 组 | 权限 | 变更类别 | 失效范围 |
|---|---|---|---|---|
| backend_capabilities | read       | L0 | none      | — |
| backend_diff         | experiment | L1 | execution | execution_facts, trial_compare, coverage_baseline |
| backend_recover      | read       | L0 | none      | — |

口径：

- 执行动作照样过 `Registry.invoke`：身份、权限、模式、预算、参数校验与失效
  登记都在 `contracts.Registry`，handler 只负责“调后端 + 落证据/快照 + 记 trial”；
- **能力先检查**：`backend_diff` 在发请求前读 `capabilities()`，缺
  `behavior_diff` 直接 `rejected(backend_capability_missing)`，不先打一枪；
- **结果写 evidence/snapshot**：`Backend.collect()` 把请求、结果、快照与两侧响应体
  写进内容寻址证据库，payload 里回传快照；
- **不写 verified**：后端结果只有 `diff / no_diff / timeout / unreachable /
  rejected`，裁决仍由 `agent.platform.verify` 推导。
"""
from __future__ import annotations

import secrets
from typing import Any

from ..contracts import (ActionRejected, Registry, ToolContext, ToolOutcome,
                         ToolSpec, applied, now)
from ..tools import MODE_EXPLORE, build_registry as build_base_registry
from .base import Backend
from .contracts import (BackendError, BackendRequest, BackendResult,
                        RecoveryAction)
from .http_service import HttpServiceBackend

#: 本批唯一实现的后端名（能力表里也用这个名字）
DEFAULT_BACKEND = "http_service"

_DEFAULT: Backend | None = None


def default_backend() -> HttpServiceBackend:
    """进程内默认后端（缓存实例，租约表才不会被每次调用清空）。"""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = HttpServiceBackend()
    return _DEFAULT


def set_default_backend(backend: Backend | None) -> None:
    """测试/控制器可替换默认后端；传 None 恢复惰性默认实例。"""
    global _DEFAULT
    _DEFAULT = backend


def _require_backend(ctx: ToolContext) -> Backend:
    backend = getattr(ctx, "backend", None)
    if backend is None:
        backend = default_backend()
    if not isinstance(backend, Backend):
        missing = [name for name in ("capabilities", "execute", "collect",
                                     "lease", "recover")
                   if not callable(getattr(backend, name, None))]
        if missing:
            raise ActionRejected(
                "backend_unavailable",
                f"注入的后端缺少接口：{missing}",
                hint="后端必须实现 capabilities/execute/collect/lease/recover")
    return backend


def _evidence_refs(collected: dict) -> tuple[str, ...]:
    out = []
    for item in (collected or {}).get("evidence") or ():
        digest = str((item or {}).get("sha256") or "")
        if digest:
            out.append(digest)
    return tuple(out)


def _trial_record(ctx: ToolContext, backend: Backend,
                  request: BackendRequest, result: BackendResult,
                  collected: dict) -> dict:
    session = ctx.state()
    unknowns = []
    checks = dict(result.checks or {})
    if not checks:
        unknowns.append("checks")
    if result.status == "unknown":
        unknowns.append("outcome")
    trial = {
        "trial_id": f"bd-{len(session.trials) + 1:03d}",
        "kind": "http_diff",
        "mode": str(ctx.mode or ""),
        "backend": str(getattr(backend, "name", "")),
        "backend_version": str(getattr(backend, "version", "")),
        "request_id": request.request_id,
        "execution_id": result.execution_id,
        "status": result.status,
        "outcome": result.outcome or "unknown",
        "checks": checks,
        "blockers": list(result.blockers),
        "evidence_sha256": (collected.get("snapshot") or {}).get(
            "groups", {}).get("fault", {}).get("log_ref", ""),
        "snapshot_status": (collected.get("snapshot") or {}).get("status", ""),
        "unknowns": unknowns,
        "seconds": float(result.seconds or 0.0),
        "created_at": now(),
    }
    session.trials[trial["trial_id"]] = trial
    session.touch()
    return trial


# ====================================================================== 工具
def backend_capabilities(ctx: ToolContext, probe: bool = False) -> ToolOutcome:
    """读后端能力表（supported/unsupported + 版本 + 探测证据）。"""
    backend = _require_backend(ctx)
    caps = backend.capabilities(probe=bool(probe))
    doc = caps.to_dict()
    return applied(
        {"backend": caps.backend, "version": caps.version,
         "required": list(caps.required), "capabilities": doc},
        after={"backend": caps.backend, "version": caps.version})


def backend_diff(ctx: ToolContext, baseline_url: str = "",
                 patched_url: str = "", method: str = "GET",
                 timeout: float = 5.0) -> ToolOutcome:
    """打两侧 HTTP 差分：先查能力，再执行，最后落证据 + 快照 + trial。"""
    backend = _require_backend(ctx)
    caps = backend.capabilities()
    missing = [name for name in ("behavior_diff",) if not caps.supports(name)]
    if missing:
        return ToolOutcome(
            status="rejected",
            payload={"backend": caps.backend, "version": caps.version,
                     "missing": missing,
                     "capabilities": caps.to_dict()},
            error={"code": "backend_capability_missing",
                   "reason": f"后端 {caps.backend} 缺少必需能力 {missing}",
                   "field": "capability",
                   "hint": "换后端或在能力表里补齐实现后再调用"})

    execution_id = str(ctx.binding.execution_id or
                       f"be-{secrets.token_hex(6)}")
    request = BackendRequest.behavior_diff(
        request_id=f"be-{secrets.token_hex(8)}",
        baseline_url=baseline_url, patched_url=patched_url,
        method=method, timeout=float(timeout),
        binding_hash=ctx.binding.hash, task_id=ctx.binding.task_id,
        execution_id=execution_id)
    try:
        result = backend.execute(request, binding=ctx.binding)
    except BackendError as exc:
        return ToolOutcome(
            status="rejected",
            payload={"backend": getattr(backend, "name", ""),
                     "request_id": request.request_id},
            error={"code": "backend_refused", "reason": str(exc),
                   "field": "", "hint": "修正后端请求后重试"})
    task = None
    if ctx.store is not None:
        try:
            task = ctx.store.get_task(ctx.binding.task_id)
        except Exception:                       # noqa: BLE001 - 任务读不到就不填
            task = None
    collected = backend.collect(
        result, store=ctx.store, task_id=ctx.binding.task_id,
        evidence_root=ctx.evidence_root, binding=ctx.binding, task=task,
        tools_allowed=ctx.tools_allowed)
    trial = _trial_record(ctx, backend, request, result, collected)
    payload = {
        "backend": result.backend,
        "backend_version": result.backend_version,
        "request_id": result.request_id,
        "execution_id": result.execution_id,
        "status": result.status,
        "outcome": result.outcome,
        "checks": dict(result.checks),
        "sides": dict(result.sides),
        "blockers": list(result.blockers),
        "seconds": result.seconds,
        "error": dict(result.error) if result.error else None,
        "evidence": list(collected.get("evidence") or []),
        "snapshot": dict(collected.get("snapshot") or {}),
        "trial": trial,
    }
    refs = _evidence_refs(collected)
    if result.status == "applied":
        return applied(payload, changed=("trials",),
                       after={"trial_id": trial["trial_id"]},
                       evidence_refs=refs)
    error = dict(result.error or {
        "code": f"backend_{result.status}", "reason": "",
        "field": "", "hint": ""})
    return ToolOutcome(status=result.status, payload=payload,
                       changed_fields=("trials",), error=error,
                       evidence_refs=refs)


def backend_recover(ctx: ToolContext, request_id: str,
                    record_status: str = "unknown",
                    effect: str = "read_only",
                    lease_expires_at: float = 0.0,
                    evidence_ref: str = "") -> ToolOutcome:
    """对一个非终态后端执行做对账：reuse/adopt/requeue/hold/mark_unknown。"""
    backend = _require_backend(ctx)
    record: dict[str, Any] = {
        "key": request_id, "status": record_status, "effect": effect,
    }
    if lease_expires_at > 0:
        record["lease"] = {
            "key": request_id, "owner": "unknown", "fence": 1,
            "backend": str(getattr(backend, "name", "")),
            "issued_at": 0.0, "expires_at": float(lease_expires_at),
        }
    if evidence_ref:
        entry = {"sha256": evidence_ref}
        if ctx.store is not None:
            for row in ctx.store.list_evidence(ctx.binding.task_id):
                if str(row.get("sha256") or "") == evidence_ref:
                    entry.update({"path": row.get("path"),
                                  "size": int(row.get("size") or 0)})
                    break
        record["evidence"] = [entry]
    try:
        action = backend.recover(record)
    except BackendError as exc:
        raise ActionRejected("recovery_refused", str(exc),
                             field_name="execution_id") from exc
    if not isinstance(action, RecoveryAction):
        raise ActionRejected(
            "backend_unavailable",
            f"recover() 返回 {type(action).__name__}，不是 RecoveryAction",
            field_name="execution_id")
    return applied({"recovery": action.to_dict()},
                   after={"action": action.action})


# ====================================================================== 组装
def build_specs() -> tuple[ToolSpec, ...]:
    return (
        ToolSpec(
            name="backend_capabilities", group="read", permission="L0",
            summary="读取后端能力表（supported/unsupported、版本与探测证据）",
            handler=backend_capabilities,
            params={
                "probe": {"type": "boolean", "default": False,
                          "description": "是否附带本次探测证据"},
            }, changes="none"),
        ToolSpec(
            name="backend_diff", group="experiment", permission="L1",
            summary="打 VulnGym 基线/修补两侧 HTTP 差分并落证据与快照",
            handler=backend_diff,
            params={
                "baseline_url": {"type": "string", "default": "",
                                 "max_length": 2048,
                                 "description": "基线侧 URL（http/https）"},
                "patched_url": {"type": "string", "default": "",
                                "max_length": 2048,
                                "description": "修补侧 URL（http/https）"},
                "method": {"type": "string", "default": "GET",
                           "enum": ("GET", "POST", "HEAD")},
                "timeout": {"type": "number", "default": 5.0, "minimum": 0.1,
                            "maximum": 120.0,
                            "description": "单侧请求超时（秒）"},
            }, changes="execution", allowed_modes=(MODE_EXPLORE,),
            cost=lambda p: {"seconds": float(p["timeout"]) * 2.0, "turns": 1},
            returns={"outcome": "diff/no_diff/timeout/unreachable",
                     "snapshot": "七组执行事实（不含裁决）"}),
        ToolSpec(
            name="backend_recover", group="read", permission="L0",
            summary="对非终态后端执行做对账（复用/采纳/重派/挂起）",
            handler=backend_recover,
            params={
                "request_id": {"type": "string", "max_length": 120,
                               "description": "要恢复的后端 request/execution id"},
                "record_status": {"type": "string", "default": "unknown",
                                  "enum": ("unknown", "applied", "failed",
                                           "rejected")},
                "effect": {"type": "string", "default": "read_only",
                           "enum": ("read_only", "possible", "external")},
                "lease_expires_at": {"type": "number", "default": 0.0,
                                     "minimum": 0.0},
                "evidence_ref": {"type": "string", "default": "",
                                 "max_length": 64,
                                 "description": "结果证据 sha256（用于 adopt）"},
            }, changes="none"),
    )


def build_registry(base: Registry | None = None) -> Registry:
    """基础工具表 + 后端工具表（同一 Registry 闸门，不另开旁路）。"""
    base = base or build_base_registry()
    registry = Registry(base.specs())
    for spec in build_specs():
        registry.register(spec)
    return registry


#: 后端工具表（只读消费；新增后端工具只改 build_specs()）
BACKEND_REGISTRY = build_registry()
BACKEND_SPECS = BACKEND_REGISTRY.specs()
BACKEND_HANDLERS = {spec.name: spec.handler for spec in BACKEND_SPECS}


__all__ = ["BACKEND_HANDLERS", "BACKEND_REGISTRY", "BACKEND_SPECS",
           "DEFAULT_BACKEND", "backend_capabilities", "backend_diff",
           "backend_recover", "build_registry", "build_specs",
           "default_backend", "set_default_backend"]
