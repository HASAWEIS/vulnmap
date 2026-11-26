"""V3-018：后端公共壳（Backend）——能力、租约、证据落库、快照、恢复。

五个接口（《VULNMAP-V3 完整升级方案》§14）：

| 接口 | 职责 | 这里的实现 |
|---|---|---|
| `capabilities()` | 逐项声明 supported/unsupported + 探测证据 | 抽象：由具体后端给出 |
| `execute()` | 真的做一次受控动作，只产事实 | 抽象：由具体后端给出 |
| `collect()` | 把结果写成证据与可信快照 | 公共实现：内容寻址 + 七组事实 |
| `lease()` | 认领执行权（owner + fence + TTL） | 公共实现：进程内栅栏租约 |
| `recover()` | UNKNOWN 先对账，不盲目重放 | 公共实现：reuse/adopt/requeue/hold |

边界：

- **不写裁决**：`collect()` 产出的快照只是执行事实（身份/配置/输入/覆盖/故障/
  预算），`verified` 仍只由 `agent.platform.verify` 推导；
- **失败也留证**：超时/不可达同样写 `backend_result` 与 `backend_snapshot`，
  不把“没跑完”洗成“没有差异”；
- **恢复先看证据**：有可复算的结果工件就 `adopt`，有活跃租约就 `hold`，
  只有声明 `read_only` 的动作才允许在租约过期后 `requeue`；
- **证据根**：优先用调用方给的 `evidence_root`，否则用 `store.path` 同级的
  `evidence/`，与既有 `EvidenceStore` 完全一致（内容寻址 `evidence/<sha256>`）。
"""
from __future__ import annotations

import os
import socket
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Mapping

from ..snapshot import (Cursor, FACT_GROUPS, GROUP_SOURCE, UNKNOWN,
                        TrustedExecutionSnapshot, tri)
from .contracts import (BackendError, BackendRefused, BackendRequest,
                        BackendResult, Capabilities, Lease, LeaseLost,
                        RecoveryAction, canonical_json, now, sha256_hex)

#: 租约默认 TTL（秒）：一次 HTTP 差分最多两轮请求，30s 足够；超时靠续租
DEFAULT_TTL = 30.0

_PROCESS_BOOT = f"{int(time.time())}-{os.getpid()}-{os.urandom(3).hex()}"


def process_owner() -> str:
    """本次进程的 owner 身份：`host:pid:boot`（boot 是进程启动标记）。"""
    return f"{socket.gethostname()}:{os.getpid()}:{_PROCESS_BOOT}"


def _norm(value: Any) -> Any:
    """空字符串/空集合一律按 unknown 落账，不伪造 0 或空结论。"""
    if value is None or value == UNKNOWN:
        return UNKNOWN
    if isinstance(value, str) and not value.strip():
        return UNKNOWN
    if isinstance(value, (list, tuple, dict)) and len(value) == 0:
        return UNKNOWN
    return value


def _evidence_ok(entry: Mapping) -> bool:
    """证据可复算：路径在、字节哈希与登记值一致。"""
    path = str((entry or {}).get("path") or "")
    digest = str((entry or {}).get("sha256") or "")
    if not path or not digest:
        return False
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    return sha256_hex(data) == digest


class Backend(ABC):
    """后端公共壳：具体后端只实现 capabilities/execute，其余从这里继承。"""

    #: 后端名/版本（固定写死，不随运行环境漂移；写进证据与绑定摘要）
    name = "backend"
    version = "vulnmap.backend.v0"
    #: 外部副作用声明：read_only 的动作才允许恢复时自动重派
    effect = "read_only"

    def __init__(self, *, workdir: Path | str | None = None,
                 clock=time.time, lease_ttl: float = DEFAULT_TTL,
                 owner: str = "") -> None:
        self.workdir = Path(workdir).expanduser() if workdir else None
        if self.workdir is not None:
            self.workdir.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._ttl = max(float(lease_ttl), 1.0)
        self._owner = str(owner or process_owner())
        self._lock = threading.Lock()
        self._leases: dict[str, Lease] = {}
        self._fence = 0

    # ------------------------------------------------------------ 抽象接口
    @abstractmethod
    def capabilities(self, *, probe: bool = False) -> Capabilities:
        """返回能力表；`probe=True` 时附带本次探测证据。"""

    @abstractmethod
    def execute(self, request: BackendRequest, *,
                binding: Any = None) -> BackendResult:
        """执行一次受控动作，只产事实与证据引用。"""

    # ------------------------------------------------------------ 租约
    def lease(self, key: str, *, ttl: float | None = None,
              owner: str = "", attempt: int = 1) -> Lease:
        """认领执行权；同一 key 被别的 owner 持有时拒绝（可修正的拒绝）。"""
        key = str(key or "").strip()
        if not key:
            raise BackendRefused("lease_key_required", "租约 key 不能为空",
                                 field_name="execution_id")
        owner = str(owner or self._owner)
        ttl = self._ttl if ttl is None else max(float(ttl), 1.0)
        now_ts = float(self._clock())
        with self._lock:
            current = self._leases.get(key)
            if current is not None and not current.expired(now_ts) \
                    and current.owner != owner:
                raise BackendRefused(
                    "lease_held",
                    f"{key} 已被 {current.owner} 持有（fence={current.fence}）",
                    field_name="execution_id",
                    hint="等租约过期或由 owner 显式 release 后再试")
            self._fence += 1
            lease = Lease(key=key, owner=owner, fence=self._fence,
                          backend=self.name, issued_at=now_ts,
                          expires_at=now_ts + ttl, attempt=int(attempt or 1))
            self._leases[key] = lease
            return lease

    def renew(self, lease: Lease, *, ttl: float | None = None) -> Lease:
        """续租：只有当前 owner + fence 还能延长。"""
        self.check_lease(lease)
        ttl = self._ttl if ttl is None else max(float(ttl), 1.0)
        now_ts = float(self._clock())
        renewed = Lease(key=lease.key, owner=lease.owner, fence=lease.fence,
                        backend=lease.backend, issued_at=lease.issued_at,
                        expires_at=now_ts + ttl, attempt=lease.attempt)
        with self._lock:
            self._leases[lease.key] = renewed
        return renewed

    def release(self, lease: Lease) -> bool:
        """释放租约；fence 对不上就不动（迟到的释放不能撤销新 owner）。"""
        if not isinstance(lease, Lease):
            return False
        with self._lock:
            current = self._leases.get(lease.key)
            if current is None or current.fence != lease.fence:
                return False
            self._leases.pop(lease.key, None)
            return True

    def check_lease(self, lease: Lease) -> None:
        """提交前的唯一闸门：owner + fence + 未过期，缺一不可。"""
        if not isinstance(lease, Lease):
            raise LeaseLost("", "invalid_lease")
        with self._lock:
            current = self._leases.get(lease.key)
            if current is None:
                raise LeaseLost(lease.key, "lease_released")
            if current.fence != lease.fence or current.owner != lease.owner:
                raise LeaseLost(lease.key, "fence_stale")
            if current.expired(float(self._clock())):
                raise LeaseLost(lease.key, "lease_expired")

    # ------------------------------------------------------------ 证据与快照
    def collect(self, result: BackendResult, *, store: Any = None,
                task_id: str = "", evidence_root: Any = None,
                binding: Any = None, task: Mapping | None = None,
                tools_allowed: Any = None) -> dict:
        """把一次结果写成内容寻址证据 + 七组事实快照。

        返回 `{"evidence": [...], "snapshot": {...}, "task_id": ...}`。
        没有绑定 store 时仍返回快照与本地计算出的引用（`persisted=False`），
        方便离线复核；有 store 时按既有 `EvidenceStore` 落库。
        """
        if not isinstance(result, BackendResult):
            raise BackendError(
                f"collect() needs BackendResult, got {type(result).__name__}")
        task_id = str(task_id or result.task_id or
                      (getattr(binding, "task_id", "") if binding else ""))
        snap = build_snapshot(result, binding=binding, task=task,
                              tools_allowed=tools_allowed)
        snapshot_doc = snap.to_dict()

        docs: list[tuple[str, bytes]] = [
            ("backend_request", canonical_json(result.request).encode("utf-8")),
            ("backend_result", canonical_json(result.to_dict()).encode("utf-8")),
            ("backend_snapshot", canonical_json(snapshot_doc).encode("utf-8")),
        ]
        for entry in result.evidence:
            path = Path(str(entry.get("path") or ""))
            kind = str(entry.get("kind") or "")
            if not kind or not path.is_file():
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            # 体文件按内容寻址保存；kind 前缀区分来源
            docs.append((f"backend_{kind}", data))

        refs: list[dict] = []
        if store is not None:
            from ...evidence import EvidenceStore     # 延迟导入，避免循环
            root = Path(evidence_root) if evidence_root is not None else (
                Path(getattr(store, "path", Path("."))).parent / "evidence")
            evidence = EvidenceStore(store, root)
            for kind, data in docs:
                ref = evidence.put_bytes(task_id, kind, data,
                                         source_stage="backend")
                refs.append({"kind": ref.kind, "sha256": ref.sha256,
                             "size": ref.size, "path": ref.path,
                             "persisted": True})
        else:
            for kind, data in docs:
                refs.append({"kind": kind, "sha256": sha256_hex(data),
                             "size": len(data), "path": "", "persisted": False})
        return {"task_id": task_id, "evidence": refs, "snapshot": snapshot_doc}

    # ------------------------------------------------------------ 恢复
    def recover(self, record: Mapping) -> RecoveryAction:
        """对一个不是终态的执行记录做对账（不重放，除非明确安全）。

        `record` 至少可带：`request_id/key`、`status`、`effect`、`lease`、
        `evidence`（`[{path,sha256,size}]`）。判定顺序：

        1. 终态（applied/failed/rejected）→ `reuse`，别再跑一遍；
        2. 有可复算证据 → `adopt`，把已有结果采纳为完成；
        3. 租约仍活跃 → `hold`，等 owner 自己收尾（不抢、不重放）；
        4. 租约过期/不存在 + 动作为 `read_only` → `requeue`（幂等安全）；
        5. 其余（外部副作用不明确）→ `hold + needs_manual`。
        """
        if not isinstance(record, Mapping):
            raise BackendError("recovery record must be a mapping")
        key = str(record.get("request_id") or record.get("key")
                  or record.get("execution_id") or "")
        status = str(record.get("status") or "").strip()
        if status in ("applied", "failed", "rejected"):
            return RecoveryAction(key, "reuse", f"terminal:{status}",
                                  status=status)

        evidence = [dict(e) for e in (record.get("evidence") or ())
                    if isinstance(e, Mapping)]
        if evidence and all(_evidence_ok(e) for e in evidence):
            return RecoveryAction(
                key, "adopt", "evidence_present", status="applied",
                evidence={"entries": evidence})

        lease_doc = record.get("lease") or record.get("lease_doc")
        now_ts = float(self._clock())
        if isinstance(lease_doc, Mapping) and lease_doc:
            try:
                lease = Lease.from_dict(lease_doc)
            except BackendError:
                lease = None
            if lease is not None and not lease.expired(now_ts):
                with self._lock:
                    current = self._leases.get(lease.key)
                if current is None or current.fence == lease.fence:
                    return RecoveryAction(
                        key, "hold", "lease_active", status="unknown",
                        evidence={"lease": lease.to_dict()})

        effect = str(record.get("effect") or self.effect)
        if effect == "read_only":
            return RecoveryAction(
                key, "requeue", "lease_expired_read_only", status="unknown",
                evidence={"effect": effect})
        if isinstance(lease_doc, Mapping) and lease_doc:
            return RecoveryAction(
                key, "hold", "unknown_with_external_effect", status="unknown",
                needs_manual=True, evidence={"effect": effect})
        # 连租约都没有：所有权完全不明，先标 unknown 等人工对账
        return RecoveryAction(
            key, "mark_unknown", "no_lease_no_evidence", status="unknown",
            needs_manual=True, evidence={"effect": effect})


# ====================================================================== 快照
def build_snapshot(result: BackendResult, *, binding: Any = None,
                    task: Mapping | None = None,
                    tools_allowed: Any = None) -> TrustedExecutionSnapshot:
    """把后端结果落成七组执行事实；缺的字段一律 unknown（不填 0）。"""
    task_id = str(result.task_id or
                  (getattr(binding, "task_id", "") if binding else ""))
    identity = dict(getattr(binding, "identity", {}) or {}) if binding else {}
    request = dict(result.request or {})
    checks = dict(result.checks or {})
    sides = dict(result.sides or {})
    error = dict(result.error or {})

    base = TrustedExecutionSnapshot.empty(
        task_id, execution_id=result.execution_id,
        binding_hash=result.binding_hash or
        (getattr(binding, "hash", "") if binding else ""))
    groups = {name: dict(base.groups.get(name) or {}) for name in FACT_GROUPS}
    unknowns = set(base.unknowns)

    def put(group: str, path: str, value: Any) -> Any:
        norm = _norm(value)
        groups.setdefault(group, {})[path] = norm
        key = f"{group}.{path}"
        if norm == UNKNOWN:
            unknowns.add(key)
        else:
            unknowns.discard(key)
        return norm

    # ---- identity（声明/服务端填） ----
    put("identity", "task_id", task_id)
    put("identity", "campaign", getattr(binding, "campaign", ""))
    put("identity", "epoch", getattr(binding, "epoch", 0))
    put("identity", "job_id", getattr(binding, "job_id", ""))
    put("identity", "execution_id", result.execution_id
        or getattr(binding, "execution_id", ""))
    put("identity", "source_sha256", identity.get("source_sha256"))
    put("identity", "harness_revision", identity.get("harness_revision"))
    put("identity", "build_id", identity.get("build_id"))
    put("identity", "image", identity.get("image"))
    put("identity", "policy_version", identity.get("policy_version"))
    put("identity", "binding_hash", result.binding_hash
        or getattr(binding, "hash", ""))
    # 后端身份也进身份组：以后换后端时不能拿旧快照冒充
    put("identity", "backend", result.backend)
    put("identity", "backend_version", result.backend_version)

    # ---- config（本次实际配置） ----
    put("config", "engine", result.backend)
    put("config", "kind_override", "behavior_diff"
        if result.backend == "http_service" else "")
    put("config", "sanitizer", "none")
    put("config", "command", _command_of(request))
    put("config", "isolation", "none")
    put("config", "network", "declared_hosts_only")
    put("config", "workdir", request.get("workdir"))
    put("config", "tools_allowed", tools_allowed)
    declared = dict((task or {}).get("budget") or {})
    put("config", "budget_declared", declared)

    # ---- input（请求与可达） ----
    put("input", "format", "http")
    put("input", "observation_source", "observed")
    put("input", "input_consumed", UNKNOWN)      # 服务端是否读完请求体，观测不到
    responded = [side for side, data in sides.items()
                 if isinstance(data, Mapping) and _responded(data)]
    put("input", "target_reached",
        tri(bool(responded)) if sides else UNKNOWN)
    put("input", "seeds", UNKNOWN)
    put("input", "dictionary_tokens", UNKNOWN)

    # ---- coverage（行为差分不是覆盖率，别冒充百分比） ----
    put("coverage", "status", "unsupported")
    put("coverage", "metric_kind", "behavior_diff")
    put("coverage", "baseline_id", checks.get("baseline_body_sha256"))
    put("coverage", "delta", UNKNOWN)
    put("coverage", "comparable", tri(False))
    put("coverage", "evidence_sha256", _first_digest(result))

    # ---- fault（结局、超时、错误） ----
    put("fault", "outcome", result.outcome)
    put("fault", "setup_error",
        error.get("code") if result.status == "rejected" else "")
    put("fault", "timeout", tri(result.outcome == "timeout"))
    put("fault", "cancelled", tri(False))
    put("fault", "budget_stopped", tri(False))
    put("fault", "sanitizer_type", "none")
    put("fault", "candidates", UNKNOWN)
    put("fault", "candidate_signature", UNKNOWN)
    put("fault", "log_ref", _first_digest(result))
    put("fault", "error", error.get("reason"))

    # ---- budget（本次执行实际消耗） ----
    used_execs = 2 if result.status in ("applied", "failed") and sides else 0
    put("budget", "used_seconds", result.seconds)
    put("budget", "used_execs", used_execs)
    put("budget", "limits", declared)
    put("budget", "remaining_seconds", UNKNOWN)
    put("budget", "remaining_execs", UNKNOWN)
    put("budget", "remaining_tokens", UNKNOWN)
    put("budget", "remaining_turns", UNKNOWN)
    put("budget", "violations", UNKNOWN)
    put("budget", "denials", UNKNOWN)
    put("budget", "tools_allowed", tools_allowed)

    sources = {name: (UNKNOWN if all(
        value == UNKNOWN for value in groups.get(name, {}).values())
        else GROUP_SOURCE[name]) for name in FACT_GROUPS}
    complete = result.status in ("applied", "failed")
    return TrustedExecutionSnapshot(
        task_id=task_id,
        execution_id=result.execution_id,
        groups=groups,
        cursor=Cursor(result.execution_id, 1 if complete else 0),
        sources=sources,
        unknowns=tuple(sorted(unknowns)),
        events=1 if complete else 0,
        binding_hash=result.binding_hash
        or (getattr(binding, "hash", "") if binding else ""),
        complete=complete,
        collected_at=now(),
    )


def _responded(side: Mapping) -> bool:
    """是否拿到可观测响应：断开/超时不算“到达”（不填 true 冒充观测）。"""
    return (side.get("status") is not None
            or bool(str(side.get("body_sha256") or "")))


def _command_of(request: Mapping) -> str:
    params = dict(request.get("params") or {})
    method = str(params.get("method") or "GET").upper()
    baseline = str(params.get("baseline_url") or "")
    patched = str(params.get("patched_url") or "")
    if not baseline and not patched:
        return ""
    return f"{method} {baseline} | {method} {patched}"


def _first_digest(result: BackendResult) -> str:
    for entry in result.evidence:
        digest = str(entry.get("sha256") or "")
        if digest:
            return digest
    return ""


__all__ = ["Backend", "DEFAULT_TTL", "build_snapshot", "process_owner"]
