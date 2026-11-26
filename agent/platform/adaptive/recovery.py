"""V3-012：重启恢复与外部副作用对账（UNKNOWN 先对账，不盲目重放）。

口径（《V3 完整升级方案》§10「执行可靠性、取消与恢复」）：

- **已完成复用**：`SUCCEEDED / FAILED / CANCELLED` 一律不再执行，直接把
  既有结果交回去（`action="reuse"`）。相同请求的 job 由 `create_campaign_job`
  在提交期就去重，这里只负责“别再跑一遍”。
- **RUNNING 且所有权不明 → UNKNOWN**：租约过期、boot 身份不是本次进程、
  或进程已不在，都不能当成“还在跑”，也不能直接重派；先落 `UNKNOWN`
  （`mark_unknown`）再对账。
- **对账先看外部副作用**：`launcher_probe`（启动器 job 的进程事实）与
  `evidence_probe`（结果/证据 artifact）是唯一裁决依据：
  - 结果 artifact 在且能对上请求 → 采纳 `SUCCEEDED`（复用，不重跑）；
  - 启动器非 0 退出、且登记的副作用是 `none` → `FAILED`（不重跑，失败也是事实）；
  - 启动器从未起来 / 明确没执行过、副作用 `none` → 才允许 `requeue`（重派）；
  - **副作用 `possible`/`external`（网络 flag 提交、外部写）证据不足 →
    `hold` + `needs_manual`**：宁可人工看一眼，也不自动重放造成二次副作用。
- **取消撤销 lease**：`cancel_requested_at` 非空的非终态 job 直接 `cancel`，
  终态 + `fence+1` 之后迟到的 worker 写不进来。
- **`apply=False` 是 shadow**：只产出计划，不改库；迁移期默认先 shadow。

本模块不改 verify/benchmark，也不把 UNKNOWN 读成失败或 0。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..store import TERMINAL_CAMPAIGN_STATES

SCHEMA = "vulnmap.adaptive.recovery.v1"
SCHEMA_VERSION = 1

ACTIONS = ("reuse", "dispatch", "mark_unknown", "reconcile", "requeue", "hold",
           "cancel")


@dataclass(frozen=True)
class RecoveryAction:
    """一条恢复决定：做什么、为什么、是否需要人来看。"""

    job_key: str
    action: str
    reason: str
    status: str = ""
    needs_manual: bool = False
    evidence: Mapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"unknown recovery action: {self.action!r}")

    def to_dict(self) -> dict:
        return {"job_key": self.job_key, "action": self.action,
                "reason": self.reason, "status": self.status,
                "needs_manual": bool(self.needs_manual),
                "evidence": dict(self.evidence)}


@dataclass
class RecoveryReport:
    """一次恢复扫描的结算（可 dry-run）。"""

    boot_id: str = ""
    applied: bool = False
    scanned: int = 0
    actions: list[RecoveryAction] = field(default_factory=list)
    released_reservations: int = 0
    started_at: str = ""
    finished_at: str = ""

    def counts(self) -> dict:
        out: dict[str, int] = {name: 0 for name in ACTIONS}
        for item in self.actions:
            out[item.action] = out.get(item.action, 0) + 1
        out["needs_manual"] = sum(1 for item in self.actions
                                  if item.needs_manual)
        return out

    @property
    def replayed(self) -> int:
        """真正重新派发的数量：只有 `requeue` 算（`dispatch` 是首次派发）。"""
        return sum(1 for item in self.actions if item.action == "requeue")

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "schema_version": SCHEMA_VERSION,
                "boot_id": self.boot_id, "applied": bool(self.applied),
                "scanned": int(self.scanned),
                "counts": self.counts(), "replayed": self.replayed,
                "released_reservations": int(self.released_reservations),
                "actions": [item.to_dict() for item in self.actions],
                "started_at": self.started_at, "finished_at": self.finished_at}


# ====================================================================== 探针
def _launcher_view(job: Mapping, probe: Callable[[Mapping], Mapping] | None
                   ) -> dict:
    """启动器视角（进程事实）；没有探针就是 unknown，不是“没跑”。"""
    if probe is None:
        return {"status": "unknown", "exit_code": None, "evidence": {}}
    try:
        raw = probe(dict(job)) or {}
    except Exception as exc:              # noqa: BLE001 - 探针坏 = 事实不明
        return {"status": "unknown", "exit_code": None,
                "evidence": {"error": f"{type(exc).__name__}: {exc}"}}
    status = str(raw.get("status") or "unknown")
    return {"status": status, "exit_code": raw.get("exit_code"),
            "evidence": dict(raw)}


def _evidence_view(job: Mapping, probe: Callable[[Mapping], Mapping] | None
                   ) -> dict:
    """结果 artifact 视角：present + 内容摘要（能不能对上本次请求）。"""
    if probe is None:
        return {"present": False, "known": False, "sha256": "",
                "result": {}}
    try:
        raw = probe(dict(job)) or {}
    except Exception as exc:              # noqa: BLE001
        return {"present": False, "known": False, "sha256": "",
                "result": {}, "error": f"{type(exc).__name__}: {exc}"}
    return {"present": bool(raw.get("present")),
            "known": True,
            "sha256": str(raw.get("sha256") or ""),
            "result": dict(raw.get("result") or {}),
            "request_hash": str(raw.get("request_hash") or "")}


# ====================================================================== 判定
def decide(job: Mapping, *, boot_id: str, now_ts: float,
           launcher_probe=None, evidence_probe=None) -> RecoveryAction:
    """单个 job 的恢复决定（纯函数，不写库）。"""
    status = str(job.get("status") or "")
    job_key = str(job.get("job_key") or "")
    effect = str(job.get("external_effect") or "none")

    if status in TERMINAL_CAMPAIGN_STATES:
        return RecoveryAction(job_key=job_key, action="reuse", status=status,
                              reason="terminal:复用既有结果，不重跑")
    if status == "PENDING":
        return RecoveryAction(job_key=job_key, action="dispatch",
                              status="PENDING", reason="never_started:首次派发")
    if str(job.get("cancel_requested_at") or ""):
        return RecoveryAction(job_key=job_key, action="cancel", status=status,
                              reason="cancel_requested:撤销 lease 并落终态")

    launcher = _launcher_view(job, launcher_probe)
    evidence = _evidence_view(job, evidence_probe)
    alive = launcher["status"] == "RUNNING"
    finished = launcher["status"] in ("EXITED", "FAILED", "MISSING")

    if status == "RUNNING":
        lease = float(job.get("lease_expires_at") or 0.0)
        same_boot = str(job.get("boot_id") or "") == str(boot_id or "")
        if lease > now_ts and same_boot and not alive:
            # 租约还在、还是本进程的 job：可能只是慢，不抢
            return RecoveryAction(job_key=job_key, action="hold",
                                  status="RUNNING",
                                  reason="lease_live:租约未过期，等待续租",
                                  evidence={"launcher": launcher})
        if alive:
            return RecoveryAction(
                job_key=job_key, action="hold", status="RUNNING",
                reason="process_alive:进程还在跑，保持 RUNNING 不重放",
                evidence={"launcher": launcher})
        if evidence["present"]:
            return RecoveryAction(
                job_key=job_key, action="reconcile", status="SUCCEEDED",
                reason="artifact_present:执行已完成，采纳结果（不重跑）",
                evidence={"launcher": launcher, "evidence": evidence})
        if finished and launcher.get("exit_code") not in (None, 0) \
                and effect == "none":
            return RecoveryAction(
                job_key=job_key, action="reconcile", status="FAILED",
                reason="launcher_failed:非 0 退出且无外部副作用",
                evidence={"launcher": launcher})
        return RecoveryAction(
            job_key=job_key, action="mark_unknown", status="UNKNOWN",
            reason="ownership_unknown:租约过期且所有权不明，先对账",
            evidence={"launcher": launcher, "evidence": evidence})

    if status == "UNKNOWN":
        if evidence["present"] and evidence.get("known"):
            return RecoveryAction(
                job_key=job_key, action="reconcile", status="SUCCEEDED",
                reason="reconciled:artifact 在，复用结果",
                evidence={"evidence": evidence})
        if effect in ("possible", "external"):
            return RecoveryAction(
                job_key=job_key, action="hold", status="UNKNOWN",
                needs_manual=True,
                reason=f"external_effect:{effect}:副作用不明确，禁止自动重放",
                evidence={"launcher": launcher, "evidence": evidence})
        if launcher["status"] == "MISSING" or \
                (finished and launcher.get("exit_code") == 0
                 and not evidence["present"]):
            # 启动器明确没有产出结果、副作用 none：可以安全重派
            return RecoveryAction(
                job_key=job_key, action="requeue", status="PENDING",
                reason="reconciled:无结果 artifact 且无外部副作用，允许重派",
                evidence={"launcher": launcher})
        if finished and launcher.get("exit_code") not in (None, 0):
            return RecoveryAction(
                job_key=job_key, action="reconcile", status="FAILED",
                reason="reconciled:启动器非 0 退出且副作用 none",
                evidence={"launcher": launcher})
        return RecoveryAction(
            job_key=job_key, action="hold", status="UNKNOWN",
            reason="insufficient_evidence:证据不足，保持 UNKNOWN 并等人看",
            needs_manual=True, evidence={"launcher": launcher,
                                         "evidence": evidence})

    return RecoveryAction(job_key=job_key, action="hold", status=status,
                          reason=f"unknown_status:{status}", needs_manual=True)


# ====================================================================== 执行
def recover(store, *, boot_id: str, jobs: Any = None,
            launcher_probe: Callable[[Mapping], Mapping] | None = None,
            evidence_probe: Callable[[Mapping], Mapping] | None = None,
            apply: bool = True, clock: Callable[[], float] = time.time,
            lease_reaper: Any = None, campaign: str = "",
            task_id: str = "") -> RecoveryReport:
    """扫描所有 campaign job 并（可选）落实决定；返回可审计报告。

    `apply=False` 只出计划（迁移期 shadow）。`lease_reaper` 传预算账本时，
    顺手把陈旧的未结算预留释放掉（worker 崩溃后不永久占额）。
    """
    from .contracts import now as _now

    stamp = _now()
    report = RecoveryReport(boot_id=str(boot_id), applied=bool(apply),
                            started_at=stamp)
    now_ts = float(clock())
    rows = store.list_campaign_jobs(campaign=campaign, task_id=task_id,
                                    limit=5000)
    report.scanned = len(rows)
    for job in rows:
        decision = decide(job, boot_id=boot_id, now_ts=now_ts,
                          launcher_probe=launcher_probe,
                          evidence_probe=evidence_probe)
        report.actions.append(decision)
        if not apply:
            continue
        try:
            _apply(store, decision, evidence_probe=evidence_probe)
        except Exception as exc:          # noqa: BLE001 - 单个 job 失败不能中断整轮
            # 一个 job 的落地失败（状态竞争、契约错误）不能让后面的 job 全都不处理：
            # 把它降级成“保持 + 需要人看”，并在报告里留原因。
            report.actions[-1] = RecoveryAction(
                job_key=decision.job_key, action="hold",
                status=str((store.get_campaign_job(decision.job_key) or {})
                           .get("status") or ""),
                needs_manual=True,
                reason=f"apply_failed:{type(exc).__name__}: {exc}"[:400],
                evidence=dict(decision.evidence))
    if apply and lease_reaper is not None:
        try:
            released = lease_reaper.expire_open_reservations(
                max_age_seconds=3600.0)
            report.released_reservations = len(released)
        except Exception:                 # noqa: BLE001 - 账本清理失败不改结论
            report.released_reservations = 0
    report.finished_at = _now()
    return report


def _apply(store, decision: RecoveryAction, *,
           evidence_probe=None) -> None:
    job_key = decision.job_key
    if decision.action == "cancel":
        store.cancel_campaign_job(job_key, reason=decision.reason,
                                  actor="recovery")
        return
    if decision.action == "mark_unknown":
        store.mark_campaign_job_unknown(job_key, reason=decision.reason)
        return
    if decision.action == "reconcile":
        # §4 的「RUNNING → 对账 → SUCCEEDED」必须**先落 UNKNOWN**：reconcile 只
        # 接受 UNKNOWN，所有权不明的 RUNNING 直接对账会被契约拒绝。
        current = store.get_campaign_job(job_key) or {}
        if str(current.get("status") or "") == "RUNNING":
            store.mark_campaign_job_unknown(
                job_key, reason=f"recovery:{decision.reason}"[:400])
        result = {}
        if decision.status == "SUCCEEDED":
            evidence = dict(decision.evidence.get("evidence") or {})
            result = dict(evidence.get("result") or {})
            if not result and evidence_probe is not None:
                probe = evidence_probe(store.get_campaign_job(job_key) or {})
                result = dict((probe or {}).get("result") or {})
        store.reconcile_campaign_job(
            job_key, verdict=decision.status, result=result,
            note=decision.reason[:400])
        return
    if decision.action == "requeue":
        store.reconcile_campaign_job(job_key, verdict="PENDING",
                                     note=decision.reason[:400])
        return
    # reuse / dispatch / hold：不改库（reuse 的数本来就在；dispatch 由派发方认领）
    return None


def reconcile_job(store, job_key: str, *, verdict: str,
                  launcher_probe=None, evidence_probe=None,
                  apply: bool = True, force: bool = False) -> RecoveryAction:
    """人工/对账入口：对单个 UNKNOWN job 给出结论并（可选）落实。"""
    job = store.get_campaign_job(job_key)
    if job is None:
        raise ValueError(f"没有 campaign job {job_key!r}")
    decision = decide(job, boot_id="", now_ts=time.time(),
                      launcher_probe=launcher_probe,
                      evidence_probe=evidence_probe)
    if decision.status not in ("", verdict) and decision.action != "hold":
        decision = RecoveryAction(job_key=job_key, action="hold",
                                  status=job["status"],
                                  reason=f"probe_verdict:{decision.status}"
                                         f" != {verdict}", needs_manual=True,
                                  evidence=dict(decision.evidence))
    if apply:
        if decision.action in ("reconcile", "requeue"):
            _apply(store, decision, evidence_probe=evidence_probe)
        elif decision.action == "hold" and verdict:
            if verdict == "PENDING" \
                    and str(job.get("external_effect") or "none") != "none" \
                    and not force:
                # 人工入口也不能绕过副作用闸门：要重派必须显式 force
                return RecoveryAction(
                    job_key=job_key, action="hold", status=job["status"],
                    needs_manual=True, reason=decision.reason,
                    evidence=dict(decision.evidence))
            store.reconcile_campaign_job(job_key, verdict=verdict,
                                         note=decision.reason[:400], force=force)
    return decision


__all__ = ["SCHEMA", "SCHEMA_VERSION", "ACTIONS", "RecoveryAction",
           "RecoveryReport", "decide", "recover", "reconcile_job"]
