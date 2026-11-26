"""V3-011：Campaign 子 Job —— lease / fencing / 与既有启动器 job 的关联。

口径（《V3 完整升级方案》§10「执行可靠性、取消与恢复」、§16）：

- **状态**：`PENDING / RUNNING / SUCCEEDED / FAILED / UNKNOWN / CANCELLED`。
  `SUCCEEDED / FAILED / CANCELLED` 是终态；**`UNKNOWN` 不是终态**，它是
  “所有权不明”的显式事实，必须由 `recovery` 对账之后才会变成终态或重派。
- **至少一次 + 幂等提交**：认领前先写执行意图（`create_campaign_job` 的
  request 哈希），结果提交成功后 `finish` 才把 `result_sha256` 落库；
  **相同规范化请求已成功过 → 直接复用**（`reusable()` / `submit()` 返回
  `reused=True`），不同 job_key 不能绕过去重。
- **lease + fencing**：认领时 `fence+1` 并写 owner/boot/pid/expiry；提交条件
  是 `owner + fence + status=RUNNING`。续租失败或 owner 变了 → `LeaseLost`，
  迟到的结果只归档成 late（`campaign_job_late`），**不覆盖新 owner 的终态**。
- **不承诺外部副作用 exactly-once**：`external_effect`（none/possible/external）
  随请求登记，`recovery` 据此决定“能不能自动重放”（网络 flag 提交这类副作用
  不明确时不自动重放）。
- **复用既有启动器**：`launcher_job_id` 指回 `vulnmap_platform` 的 `jobs.job_id`
  （进程视角：pid/exit_code/log）；本模块只负责 campaign 视角的归属与租约，
  不重造第二套进程台账，也不改启动器状态机。

本模块不跑目标、不调模型、不写裁决。
"""
from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..store import (CAMPAIGN_EFFECTS, CAMPAIGN_JOB_STATES,
                     TERMINAL_CAMPAIGN_STATES, CampaignJobError)

SCHEMA = "vulnmap.adaptive.campaign_job.v1"
SCHEMA_VERSION = 1

JOB_STATUSES = CAMPAIGN_JOB_STATES
TERMINAL_STATES = TERMINAL_CAMPAIGN_STATES
EFFECTS = CAMPAIGN_EFFECTS

#: 默认租约（秒）：短事务认领，长任务靠续租；比一次 fuzz 切片长，比一轮研究短
DEFAULT_TTL = 30.0

_PROCESS_BOOT = f"{int(time.time())}-{os.getpid()}-{os.urandom(3).hex()}"


class JobError(ValueError):
    """campaign job 层错误（状态不允许、租约丢失之外的可预期失败）。"""


class LeaseLost(RuntimeError):
    """续租失败 / fencing 失效：当前 worker 已不是 owner，必须停手且不提交结果。"""

    def __init__(self, job_key: str, reason: str = "") -> None:
        self.job_key = str(job_key)
        self.reason = str(reason or "lease_lost")
        super().__init__(f"lease lost for {self.job_key}: {self.reason}")


def process_identity() -> str:
    """本次进程的身份：`host:pid:boot`（boot 是进程启动标记，不是 OS boot id）。"""
    return f"{socket.gethostname()}:{os.getpid()}:{_PROCESS_BOOT}"


def default_owner() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


@dataclass(frozen=True)
class Lease:
    """一次认领的凭据：owner + fence 是提交结果的唯一钥匙。"""

    job_key: str
    owner: str
    boot_id: str
    fence: int
    attempt: int = 1
    expires_at: float = 0.0
    pid: int | None = None

    def to_dict(self) -> dict:
        return {"job_key": self.job_key, "owner": self.owner,
                "boot_id": self.boot_id, "fence": int(self.fence),
                "attempt": int(self.attempt),
                "expires_at": float(self.expires_at), "pid": self.pid}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "Lease":
        return cls(job_key=str(doc.get("job_key") or ""),
                   owner=str(doc.get("owner") or ""),
                   boot_id=str(doc.get("boot_id") or ""),
                   fence=int(doc.get("fence") or 0),
                   attempt=int(doc.get("attempt") or 0),
                   expires_at=float(doc.get("expires_at") or 0.0),
                   pid=doc.get("pid"))


@dataclass(frozen=True)
class JobOutcome:
    """一次提交的结算：accepted/late 必须分开讲，迟到不等于失败。"""

    job_key: str
    accepted: bool
    late: bool = False
    reason: str = ""
    status: str = ""
    job: Mapping = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"job_key": self.job_key, "accepted": bool(self.accepted),
                "late": bool(self.late), "reason": self.reason,
                "status": self.status, "job": dict(self.job or {})}


class CampaignJobs:
    """campaign 子 Job 的唯一入口：提交/认领/续租/提交结果/取消/关联启动器。"""

    def __init__(self, store, *, owner: str = "", boot_id: str = "",
                 ttl: float = DEFAULT_TTL, launcher: Any = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.store = store
        self.owner = str(owner or default_owner())
        self.boot_id = str(boot_id or process_identity())
        self.ttl = float(ttl)
        self.launcher = launcher
        self.clock = clock

    # ------------------------------------------------------------------ 提交
    def submit(self, *, campaign: str, task_id: str, kind: str,
               request: Mapping | None = None, epoch: int = 0,
               external_effect: str = "none", job_key: str = "",
               note: str = "") -> dict:
        job = self.store.create_campaign_job(
            campaign=campaign, task_id=task_id, kind=kind, request=request,
            epoch=epoch, job_key=job_key, external_effect=external_effect,
            note=note)
        job["reused"] = bool(job.get("reused"))
        return job

    def reusable(self, *, campaign: str, task_id: str,
                 request: Mapping | None = None) -> dict | None:
        """同一请求已成功过 → 返回那条 job（调用方直接复用结果，不再执行）。"""
        return self.store.find_campaign_job(
            campaign=campaign, task_id=task_id, request=request,
            status="SUCCEEDED")

    def get(self, job_key: str) -> dict | None:
        return self.store.get_campaign_job(job_key)

    def list(self, *, campaign: str = "", task_id: str = "",
             status: str = "", limit: int = 200) -> list[dict]:
        return self.store.list_campaign_jobs(campaign=campaign, task_id=task_id,
                                            status=status, limit=limit)

    # ------------------------------------------------------------------ 认领
    def claim(self, job_key: str, *, pid: int | None = None) -> Lease | None:
        job = self.store.claim_campaign_job(
            job_key, owner=self.owner, boot_id=self.boot_id, ttl=self.ttl,
            pid=os.getpid() if pid is None else pid, clock=self.clock)
        if job is None:
            return None
        return Lease(job_key=job["job_key"], owner=self.owner,
                     boot_id=self.boot_id, fence=int(job["fence"]),
                     attempt=int(job["attempt"]),
                     expires_at=float(job["lease_expires_at"]),
                     pid=job.get("pid"))

    def claim_next(self, *, campaign: str = "", task_id: str = "") -> Lease | None:
        """按创建顺序认领第一个能抢到的 PENDING job（短事务，失败就下一个）。"""
        for job in self.list(campaign=campaign, task_id=task_id, status="PENDING",
                             limit=200):
            lease = self.claim(job["job_key"])
            if lease is not None:
                return lease
        return None

    def heartbeat(self, lease: Lease) -> bool:
        ok = self.store.renew_campaign_job_lease(
            lease.job_key, owner=lease.owner, fence=lease.fence, ttl=self.ttl,
            clock=self.clock)
        return bool(ok)

    def require_lease(self, lease: Lease) -> None:
        """续租失败 = 已不是 owner：抛 `LeaseLost`，调用方必须停手。"""
        if not self.heartbeat(lease):
            raise LeaseLost(lease.job_key, "renew_rejected")

    # ------------------------------------------------------------------ 结果
    def finish(self, lease: Lease, status: str, result: Mapping | None = None,
               *, execution_id: str = "", note: str = "") -> JobOutcome:
        out = self.store.finish_campaign_job(
            lease.job_key, owner=lease.owner, fence=lease.fence, status=status,
            result=result, execution_id=execution_id, note=note)
        job = out.get("job") or {}
        return JobOutcome(job_key=lease.job_key,
                          accepted=bool(out.get("accepted")),
                          late=bool(out.get("late")),
                          reason=str(out.get("reason") or ""),
                          status=str(job.get("status") or ""), job=job)

    def abandon(self, lease: Lease, reason: str) -> dict:
        """所有权/事实不明 → UNKNOWN（不是失败也不是成功），交给 recovery 对账。"""
        return self.store.mark_campaign_job_unknown(
            lease.job_key, reason=reason, owner=lease.owner, fence=lease.fence)

    def run(self, job_key: str, worker: Callable[..., Any], *,
            pid: int | None = None) -> JobOutcome:
        """认领 → 执行 → 提交：worker(lease) 返回 `(status, result)` 或 Mapping。

        `LeaseLost` 说明租约在 worker 跑的时候丢了：**不提交**，本轮结果作废
        （宁可让 recovery 对账，也不让旧 owner 覆盖新 owner）。
        """
        lease = self.claim(job_key, pid=pid)
        if lease is None:
            raise JobError(f"{job_key} 不可认领（不是 PENDING 或已被认领）")
        job = self.get(job_key) or {}
        try:
            raw = worker(lease)
        except LeaseLost:
            raise
        except Exception as exc:            # noqa: BLE001 - 失败也提交（state=FAILED）
            self.require_lease(lease)
            return self.finish(lease, "FAILED",
                               result={"error": f"{type(exc).__name__}: {exc}"})
        status, result, execution_id = _normalize_result(raw)
        self.require_lease(lease)
        return self.finish(lease, status, result, execution_id=execution_id,
                           note=str(job.get("kind") or ""))

    # ------------------------------------------------------------------ 取消
    def cancel(self, job_key: str, *, reason: str = "", actor: str = "api",
               kill: bool = True) -> dict:
        """取消：先落终态+撤 lease（fence+1），再对启动器进程组发信号。

        顺序不能反：先撤租约，迟到的 worker 就写不进来了；再杀进程只是省资源。
        """
        job = self.store.cancel_campaign_job(job_key, reason=reason, actor=actor)
        killed = ""
        if kill and job.get("launcher_job_id") and self.launcher is not None:
            try:
                killed = self.launcher.cancel(job["launcher_job_id"],
                                              reason=reason)
            except Exception as exc:        # noqa: BLE001 - 杀不掉也要落终态
                killed = f"error:{type(exc).__name__}: {exc}"
        job = dict(job)
        job["killed"] = killed
        return job

    def cancel_task(self, task_id: str, *, reason: str = "",
                    actor: str = "api") -> list[dict]:
        """取消一个任务下所有非终态 campaign job（供 lifecycle 的取消序列调用）。"""
        out = []
        for job in self.list(task_id=task_id, limit=5000):
            if job["status"] in TERMINAL_STATES:
                continue
            out.append(self.cancel(job["job_key"], reason=reason, actor=actor))
        return out

    def expire_leases(self) -> list[dict]:
        return self.store.expire_campaign_job_leases(clock=self.clock)

    # ------------------------------------------------------------------ 启动器
    def link_launcher(self, lease: Lease, launcher_job_id: str) -> bool:
        """把既有启动器 job 挂到本次认领上（旧 owner 挂不上）。"""
        return self.store.attach_campaign_launcher(
            lease.job_key, launcher_job_id, owner=lease.owner, fence=lease.fence)

    def summary(self, *, campaign: str = "", task_id: str = "") -> dict:
        jobs = self.list(campaign=campaign, task_id=task_id, limit=5000)
        states: dict[str, int] = {}
        for job in jobs:
            states[job["status"]] = states.get(job["status"], 0) + 1
        return {"total": len(jobs), "states": states,
                "pending": [j["job_key"] for j in jobs if j["status"] == "PENDING"],
                "running": [j["job_key"] for j in jobs if j["status"] == "RUNNING"],
                "unknown": [j["job_key"] for j in jobs if j["status"] == "UNKNOWN"]}


# ====================================================================== 内部
def _normalize_result(raw: Any) -> tuple[str, dict, str]:
    """worker 返回值归一：只接受 SUCCEEDED/FAILED，执行 id 单独传。"""
    if isinstance(raw, Mapping):
        status = str(raw.get("status") or "").upper()
        result = dict(raw.get("result") or {})
        execution_id = str(raw.get("execution_id") or "")
    elif isinstance(raw, tuple) and len(raw) >= 2:
        status = str(raw[0] or "").upper()
        result = dict(raw[1] or {})
        execution_id = str(raw[2] if len(raw) > 2 else "")
    else:
        status = "FAILED"
        result = {"error": f"worker 返回 {type(raw).__name__}，不是 (status, result)"}
        execution_id = ""
    if status not in ("SUCCEEDED", "FAILED"):
        status = "FAILED"
        result.setdefault("error", "worker 返回了非法状态（只接受 SUCCEEDED/FAILED）")
    return status, result, execution_id


class LeaseGuard:
    """带心跳的租约上下文：`with guard as lease:`，丢租约时 `lost` 置真。"""

    def __init__(self, jobs: CampaignJobs, lease: Lease,
                 interval: float | None = None) -> None:
        self.jobs = jobs
        self.lease = lease
        self.interval = float(interval if interval is not None
                              else max(0.01, jobs.ttl / 3.0))
        self.lost = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "LeaseGuard":
        def beat() -> None:
            while not self._stop.wait(self.interval):
                if not self.jobs.heartbeat(self.lease):
                    self.lost = True
                    return
        self._thread = threading.Thread(target=beat, daemon=True,
                                        name=f"lease-{self.lease.job_key}")
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        return None


__all__ = ["SCHEMA", "SCHEMA_VERSION", "JOB_STATUSES", "TERMINAL_STATES",
           "EFFECTS", "DEFAULT_TTL", "JobError", "LeaseLost", "Lease",
           "JobOutcome", "CampaignJobs", "LeaseGuard", "process_identity",
           "default_owner", "CampaignJobError"]
