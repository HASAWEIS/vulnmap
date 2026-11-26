"""V2 P3.6 生命周期控制：取消（CANCELLED）/ 预算终止（TERMINATED）/ 证据快照。

口径：

- **取消**只从非终态发起（`CANCELLABLE`）；`RUNNING`/`PLANNED` 是主路径，
  终态（含 CANCELLED/TERMINATED）再取消是契约错误，不改任何状态；
- **预算终止**由 [budget.py](budget.py) 的判定驱动，`reason` 只可能是
  `budget_seconds / budget_execs / budget_tokens / budget_turns`；
- 两条路径都**先落证据再改状态**：`cancel_snapshot` / `budget_snapshot` 是
  可复算的 JSON 证据（sha256 进 events 的 payload），事件流里同时留
  `task.cancel_requested → task.cancelled` 与 `budget.exceeded → task.terminated`；
- 取消/终止都不是“没有跑出结果”，因此**永远不写 NO_REPRO**。
"""
from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

from .budget import BudgetGuard, usage_from_events
from .evidence import EvidenceStore
from .store import TERMINAL_CAMPAIGN_STATES
from .task import CANCELLABLE, TERMINAL, TaskError, now

CANCEL_SNAPSHOT_KIND = "cancel_snapshot"
BUDGET_SNAPSHOT_KIND = "budget_snapshot"
EXEC_ERROR_KIND = "exec_error"
EXEC_STATS_KIND = "exec_stats"

#: 取消/超时/失败回收的固定顺序（§10）：任何一步都不许跳，尤其不能先改状态再撤租约
RECLAIM_ORDER = ("event", "refuse_new", "revoke_lease", "kill", "evidence",
                 "final_state")

#: 取消信号：先 SIGTERM 给进程组，宽限后再 SIGKILL（进程树一次带掉）
KILL_GRACE_SECONDS = 2.0


def snapshot_evidence(store, task_id: str, kind: str, doc: dict, *,
                      evidence_root=None, source_stage: str = ""):
    """把一份 JSON 快照写进内容寻址证据库，返回 EvidenceRef。"""
    root = (Path(evidence_root) if evidence_root
            else Path(store.path).parent / "evidence")
    body = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
                      default=str) + "\n"
    return EvidenceStore(store, root).put_bytes(
        task_id, kind, body.encode("utf-8"), source_stage=source_stage)


def is_cancelled(store, task_id: str) -> bool:
    """取消是由状态机承载的：RUNNING 任务被打成 CANCELLED 即为取消信号。"""
    return store.get_task(task_id)["state"] == "CANCELLED"


def budget_usage(task_id: str, store) -> dict:
    return usage_from_events(store.list_events(task_id))


def cancel_task(task_id: str, store, bus, *, reason: str = "",
                actor: str = "cli", evidence_root=None) -> dict:
    """取消一个非终态任务：证据 → 事件 → 状态，终态拒绝。"""
    task = store.get_task(task_id)
    state = task["state"]
    if state in TERMINAL:
        raise TaskError(
            f"cannot cancel terminal task {task_id} in {state}")
    if state not in CANCELLABLE:
        raise TaskError(f"state {state} is not cancellable")

    reason_text = str(reason or "user request")
    events = bus.list(task_id) if bus is not None else store.list_events(task_id)
    bus.emit(task_id, "task.cancel_requested", stage=state, payload={
        "from": state,
        "reason": reason_text,
        "actor": actor,
        "budget": task["budget"],
        "usage": usage_from_events(events),
        "events": len(events),
        "requested_at": now(),
    })
    snapshot = {
        "task_id": task_id,
        "from": state,
        "reason": reason_text,
        "actor": actor,
        "budget": task["budget"],
        "usage": usage_from_events(events),
        "events": len(events),
        "at": now(),
    }
    ref = snapshot_evidence(store, task_id, CANCEL_SNAPSHOT_KIND, snapshot,
                            evidence_root=evidence_root, source_stage=state)
    task = store.transition(task_id, "CANCELLED",
                            reason=f"cancelled: {reason_text}")
    seq = bus.emit(task_id, "task.cancelled", stage="CANCELLED", payload={
        "from": state,
        "reason": reason_text,
        "actor": actor,
        "evidence_sha256": ref.sha256,
        "budget": task["budget"],
    })
    return {
        "task_id": task_id,
        "state": task["state"],
        "from": state,
        "reason": reason_text,
        "actor": actor,
        "terminal_reason": task["terminal_reason"],
        "evidence_sha256": ref.sha256,
        "event_seq": seq,
    }


def terminate_budget(task_id: str, store, bus, *, guard: BudgetGuard,
                     reason: str, stage: str = "", exec_id: str = "",
                     evidence_root=None, stats: dict | None = None,
                     error: str = "", extra: dict | None = None) -> dict:
    """预算超限终止：写 budget.exceeded + task.terminated + 快照证据。

    `reason` 必须是 budget_*；状态从 PLANNED/RUNNING 落 TERMINATED。
    若任务已被人工取消（state=CANCELLED），取消优先，不再改状态。
    """
    if not str(reason).startswith("budget_"):
        raise TaskError(f"terminate_budget requires budget_* reason, got {reason!r}")
    task = store.get_task(task_id)
    state = task["state"]
    snapshot = guard.snapshot(extra=extra or {})
    snapshot.update({
        "task_id": task_id,
        "reason": reason,
        "stage": stage or state,
        "from": state,
        "exec_id": exec_id,
        "stats": stats or {},
        "error": error,
        "at": now(),
    })
    ref = snapshot_evidence(store, task_id, BUDGET_SNAPSHOT_KIND, snapshot,
                            evidence_root=evidence_root,
                            source_stage=stage or state)
    bus.emit(task_id, "budget.exceeded", stage=stage or state, payload={
        "reason": reason,
        "from": state,
        "limits": snapshot["limits"],
        "used": snapshot["used"],
        "violations": snapshot["violations"],
        "exec_id": exec_id,
        "stats": stats or {},
        "evidence_sha256": ref.sha256,
        "error": error,
    })

    cancelled = state == "CANCELLED"
    if not cancelled and state not in TERMINAL:
        task = store.transition(task_id, "TERMINATED", reason=reason)
        state = task["state"]
    seq = bus.emit(task_id, "task.terminated", stage=state, payload={
        "reason": reason,
        "from": snapshot["from"],
        "state": state,
        "limits": snapshot["limits"],
        "used": snapshot["used"],
        "exec_id": exec_id,
        "stats": stats or {},
        "evidence_sha256": ref.sha256,
        "note": ("cancelled task wins over budget stop" if cancelled else ""),
    })
    return {
        "task_id": task_id,
        "state": state,
        "reason": reason,
        "terminal_reason": task["terminal_reason"],
        "used": snapshot["used"],
        "limits": snapshot["limits"],
        "evidence_sha256": ref.sha256,
        "event_seq": seq,
    }


# ====================================================================== V3 P3
class LifecycleError(TaskError):
    """回收/取消/守卫错误：`code` 是稳定词表，API 与测试都按它断言。

    `forged_identity` / `cross_task` / `stale_fence` / `late_result` /
    `privilege_denied` / `terminal_override` —— 这些是**安全反例**的拒绝码，
    不是“参数没填对”的可修正错误：拿到它们就该停手。
    """

    CODES = ("forged_identity", "cross_task", "cross_execution", "stale_fence",
             "late_result", "privilege_denied", "terminal_override",
             "not_cancellable", "unknown_job")

    def __init__(self, code: str, reason: str, *, detail: dict | None = None):
        if code not in self.CODES:
            raise TaskError(f"unknown lifecycle code: {code!r}")
        self.code = code
        self.reason = reason
        self.detail = dict(detail or {})
        super().__init__(f"{code}: {reason}")

    def to_dict(self) -> dict:
        return {"code": self.code, "reason": self.reason, "detail": self.detail}


def guard_task_scope(store, task_id: str, *, claimed_task_id: str = "",
                     job_task_id: str = "") -> None:
    """跨任务守卫（T07）：请求里的 task 与本次受信 task/job 的 task 必须一致。"""
    trusted = str(task_id or "")
    for claimed in (claimed_task_id, job_task_id):
        if claimed and str(claimed) != trusted:
            raise LifecycleError(
                "cross_task",
                f"请求的 task={claimed!r} 与受信 task={trusted!r} 不一致",
                detail={"trusted": trusted, "claimed": str(claimed)})
    store.get_task(trusted)          # 不存在 → TaskError：不存在的任务不能当“通过”


def guard_job_owner(job: dict, *, owner: str = "", fence: int = 0,
                    execution_id: str = "") -> None:
    """伪造身份/迟到结果守卫（T07/T12）：owner+fence+execution 必须同时对得上。"""
    if not job:
        raise LifecycleError("unknown_job", "job 不存在")
    key = str(job.get("job_key") or "")
    status = str(job.get("status") or "")
    if status in TERMINAL_CAMPAIGN_STATES:
        raise LifecycleError(
            "late_result",
            f"{key} 已是终态 {status}：迟到结果只能归档，不能改终态",
            detail={"job_key": key, "status": status})
    if not str(owner or "").strip():
        raise LifecycleError("forged_identity", "缺少 owner：不能匿名提交结果")
    if str(job.get("owner") or "") != str(owner):
        raise LifecycleError(
            "forged_identity",
            f"{key} 的 owner 是 {job.get('owner')!r}，不是 {owner!r}",
            detail={"job_key": key, "owner": job.get("owner")})
    if int(job.get("fence") or 0) != int(fence):
        raise LifecycleError(
            "stale_fence",
            f"{key} 的 fence 是 {job.get('fence')}，提交声明 {fence}",
            detail={"job_key": key, "fence": job.get("fence")})
    bound = str(job.get("execution_id") or "")
    if execution_id and bound and str(execution_id) != bound:
        raise LifecycleError(
            "cross_execution",
            f"{key} 绑的执行是 {bound!r}，提交声明 {execution_id!r}",
            detail={"job_key": key, "execution_id": bound})


def guard_permission(metadata: dict | None, level: str = "L1") -> None:
    """越权守卫（T07）：按任务元数据严格解析授权，L3 永不放开。"""
    from .adaptive.contracts import NEVER_EXPOSED, grant_for, permission_allows

    if str(level) in NEVER_EXPOSED:
        raise LifecycleError(
            "privilege_denied",
            f"{level} 属于裁决/可信面，永不暴露给研究 Agent")
    grant = grant_for(metadata or {})
    if not permission_allows(str(level), grant):
        raise LifecycleError(
            "privilege_denied",
            f"需要 {level}，本次授权={sorted(grant)}",
            detail={"grant": sorted(grant), "level": str(level)})


def kill_process_tree(pid: int | None, *,
                      grace: float = KILL_GRACE_SECONDS) -> dict:
    """按进程组终止（spawn 用 start_new_session：pid 即组长），返回发放的信号。

    先对**进程组**发 SIGTERM 等一个宽限，再升级 SIGKILL；组不在了就退化成对
    pid 单发。返回 `alive` 让调用方能如实报“没杀掉”，而不是假装清理干净。
    """
    if not pid:
        return {"pid": None, "pgid": None, "signals": [], "alive": False}
    if int(pid) == os.getpid():
        # 自己的进程（或自己的组）：绝不在这里“顺手”杀掉调度进程本身。
        # 真实 worker 是独立进程组的子进程；出现这种调用说明台账 pid 不可信。
        return {"pid": int(pid), "pgid": None, "signals": [],
                "alive": True, "skipped": "self_pid"}
    sent: list[str] = []
    try:
        pgid = os.getpgid(int(pid))
    except (ProcessLookupError, PermissionError, OSError):
        pgid = None
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
            sent.append("pg:SIGTERM")
        except (ProcessLookupError, PermissionError, OSError):
            pass
    elif _pid_alive(int(pid)):
        try:
            os.kill(int(pid), signal.SIGTERM)
            sent.append("pid:SIGTERM")
        except (ProcessLookupError, PermissionError, OSError):
            pass
    if sent and grace > 0:
        time.sleep(min(float(grace), 0.2))
    if _pid_alive(int(pid)):
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
                sent.append("pg:SIGKILL")
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            os.kill(int(pid), signal.SIGKILL)
            sent.append("pid:SIGKILL")
        except (ProcessLookupError, PermissionError, OSError):
            pass
    return {"pid": int(pid), "pgid": pgid, "signals": sent,
            "alive": _pid_alive(int(pid))}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError):
        return False
    return True


def cancel_campaign_jobs(store, task_id: str, *, reason: str = "",
                         actor: str = "lifecycle", jobs=None,
                         kill: bool = True) -> list[dict]:
    """撤租约 + 杀进程 + 落 CANCELLED；不给新 job 留认领机会（fence+1）。"""
    out: list[dict] = []
    rows = store.list_campaign_jobs(task_id=task_id, limit=5000)
    for job in rows:
        if job["status"] in TERMINAL_CAMPAIGN_STATES:
            out.append({"job_key": job["job_key"], "status": job["status"],
                        "already": True, "killed": ""})
            continue
        pid = job.get("pid")
        killable = bool(pid) and int(pid) != os.getpid()
        killed = kill_process_tree(pid) if (kill and killable) else {
            "signals": [], "skipped": "self_pid" if pid else "no_pid"}
        if jobs is not None:
            updated = jobs.cancel(job["job_key"], reason=reason, actor=actor,
                                  kill=kill)
        else:
            updated = store.cancel_campaign_job(job["job_key"], reason=reason,
                                                actor=actor)
        out.append({"job_key": job["job_key"], "status": updated.get("status"),
                    "fence": updated.get("fence"),
                    "lease_expires_at": updated.get("lease_expires_at"),
                    "already": bool(updated.get("already")),
                    "killed": killed.get("signals") or []})
    return out


def cancel_task_full(task_id: str, store, bus, *, jobs=None, launcher=None,
                     reason: str = "", actor: str = "api",
                     evidence_root=None, kill: bool = True) -> dict:
    """§10 取消序列：事件 → 拒绝新动作 → 撤 lease → 杀进程树 → 证据 → 终态。

    与 `cancel_task()` 的区别：这里把 campaign 子 Job 的 lease 与进程组一起
    收掉，并把“哪些 job 被取消、发了什么信号”写进同一份可复算证据。
    """
    task = store.get_task(task_id)
    state = task["state"]
    if state in TERMINAL:
        raise TaskError(f"cannot cancel terminal task {task_id} in {state}")
    if state not in CANCELLABLE:
        raise TaskError(f"state {state} is not cancellable")
    reason_text = str(reason or "user request")

    # 1) 事件先记（之后任何一步失败都留痕）
    events = bus.list(task_id) if bus is not None else store.list_events(task_id)
    bus.emit(task_id, "task.cancel_requested", stage=state, payload={
        "from": state, "reason": reason_text, "actor": actor,
        "budget": task["budget"], "usage": usage_from_events(events),
        "events": len(events), "order": list(RECLAIM_ORDER),
        "requested_at": now(),
    })
    # 2)+3) 拒绝新 job / 回收 lease（终态 + fence+1 之后新的认领一律失败）
    cancelled = cancel_campaign_jobs(store, task_id, reason=reason_text,
                                     actor=actor, jobs=jobs, kill=kill)
    # 4) 启动器侧进程组（campaign job 未带 pid 时仍按 launcher_job_id 收）
    killed_launchers: list[dict] = []
    if kill and launcher is not None:
        for job in store.list_campaign_jobs(task_id=task_id, limit=5000):
            launcher_id = str(job.get("launcher_job_id") or "")
            if not launcher_id:
                continue
            try:
                killed_launchers.append({
                    "launcher_job_id": launcher_id,
                    "signal": launcher.cancel(launcher_id, reason=reason_text)})
            except Exception as exc:      # noqa: BLE001 - 杀不掉也要落终态
                killed_launchers.append({
                    "launcher_job_id": launcher_id,
                    "error": f"{type(exc).__name__}: {exc}"})
    # 5) 证据
    snapshot = {
        "task_id": task_id, "from": state, "reason": reason_text,
        "actor": actor, "order": list(RECLAIM_ORDER),
        "budget": task["budget"], "usage": usage_from_events(events),
        "events": len(events), "campaign_jobs": cancelled,
        "launcher": killed_launchers, "at": now(),
        "killed_at": time.time(),
    }
    ref = snapshot_evidence(store, task_id, CANCEL_SNAPSHOT_KIND, snapshot,
                            evidence_root=evidence_root, source_stage=state)
    # 6) 终态
    task = store.transition(task_id, "CANCELLED",
                            reason=f"cancelled: {reason_text}")
    seq = bus.emit(task_id, "task.cancelled", stage="CANCELLED", payload={
        "from": state, "reason": reason_text, "actor": actor,
        "evidence_sha256": ref.sha256, "budget": task["budget"],
        "campaign_jobs": len(cancelled), "launcher": killed_launchers,
    })
    return {
        "task_id": task_id, "state": task["state"], "from": state,
        "reason": reason_text, "actor": actor,
        "terminal_reason": task["terminal_reason"],
        "evidence_sha256": ref.sha256, "event_seq": seq,
        "campaign_jobs": cancelled, "launcher": killed_launchers,
        "order": list(RECLAIM_ORDER),
    }


def reclaim_expired_leases(store, *, clock=None, grace: float = 0.0,
                          bus=None) -> list[dict]:
    """超时回收：租约过期的 RUNNING → UNKNOWN（不发 FAILED，事实不明就是不明）。"""
    reclaimed = store.expire_campaign_job_leases(clock=clock, max_grace=grace)
    if bus is not None:
        for job in reclaimed:
            try:
                bus.emit(job["task_id"], "job.unknown", stage="UNKNOWN",
                         payload={"job_key": job["job_key"],
                                  "campaign": job["campaign"],
                                  "reason": "lease_expired",
                                  "fence": job["fence"]})
            except Exception:             # noqa: BLE001 - 事件失败不改事实
                pass
    return reclaimed


def reclaim_failed_task(task_id: str, store, bus, *, reason: str,
                        exec_id: str = "", evidence_root=None,
                        jobs=None, launcher=None, kill: bool = True) -> dict:
    """失败回收：撤 lease → 杀进程树 → 证据 → 落 FAILED（不是 NO_REPRO）。"""
    task = store.get_task(task_id)
    state = task["state"]
    if state in TERMINAL:
        raise TaskError(f"cannot reclaim terminal task {task_id} in {state}")
    cancelled = cancel_campaign_jobs(store, task_id,
                                     reason=f"task_failed: {reason}",
                                     actor="lifecycle", jobs=jobs, kill=kill)
    killed: list[dict] = []
    if kill and launcher is not None:
        for job in store.list_campaign_jobs(task_id=task_id, limit=5000):
            launcher_id = str(job.get("launcher_job_id") or "")
            if launcher_id:
                try:
                    killed.append({"launcher_job_id": launcher_id,
                                   "signal": launcher.cancel(
                                       launcher_id, reason=reason)})
                except Exception as exc:  # noqa: BLE001
                    killed.append({"launcher_job_id": launcher_id,
                                   "error": f"{type(exc).__name__}: {exc}"})
    snapshot = {
        "task_id": task_id, "from": state, "reason": reason, "exec_id": exec_id,
        "campaign_jobs": cancelled, "launcher": killed, "at": now(),
    }
    ref = snapshot_evidence(store, task_id, EXEC_ERROR_KIND, snapshot,
                            evidence_root=evidence_root, source_stage=state)
    task = store.transition(task_id, "FAILED", reason=f"failed: {reason}")
    seq = bus.emit(task_id, "task.failed", stage="FAILED", payload={
        "from": state, "reason": reason, "exec_id": exec_id,
        "evidence_sha256": ref.sha256, "campaign_jobs": len(cancelled),
    })
    return {"task_id": task_id, "state": task["state"], "from": state,
            "reason": reason, "evidence_sha256": ref.sha256, "event_seq": seq,
            "campaign_jobs": cancelled, "launcher": killed}
