"""目标准入：只读检查目标/授权，决定 READY 或 BLOCKED。

F1（授权口径）：`metadata.authorized` 一律经 `authorization.resolve()` 严格解析，
不再 `bool(authorized)`——字符串 "false"/"0"/"no"/"off" 必须阻断，非法值
按 fail-closed 阻断，缺失按 `MISSING_POLICY`（默认 block）处理。

F4（恢复入口）：BLOCKED 不是死路。补齐材料（建目标目录、补元数据）后可以
再次准入：BLOCKED → PREFLIGHT → READY/BLOCKED。事件流是 append-only，
重试只追加事件、不删旧事件，旧事件仍可完整重放。
"""
from __future__ import annotations

from pathlib import Path

from . import authorization
from .events import EventBus

#: 可受理准入的状态：首次准入 RECEIVED，材料补齐后从 BLOCKED 重试（F4）
ENTRY_STATES = ("RECEIVED", "BLOCKED")

#: 阻断性检查项（image_declared 只是 warning）
BLOCKING_CHECKS = ("target_path", "target_service", "authorized")


def _check_target(task: dict) -> list[dict]:
    checks: list[dict] = []
    target = str(task.get("target") or "")
    benchmark = str(task.get("benchmark") or "")
    if benchmark == "vulngym":
        ok = target.startswith(("http://", "https://"))
        checks.append({"name": "target_service", "ok": ok,
                       "detail": target if ok else "vulngym target must be http(s) URL"})
    else:
        p = Path(target)
        ok = p.exists()
        checks.append({"name": "target_path", "ok": ok,
                       "detail": str(p) if ok else f"missing: {target}"})
    auth = authorization.resolve(task.get("metadata"))
    checks.append({"name": "authorized", "ok": auth["ok"],
                   "detail": auth["detail"],
                   "declared": auth["declared"],
                   "reason": auth["reason"],
                   "policy": auth["policy"]})
    if benchmark in ("cybergym", "exploitgym"):
        image = (task.get("metadata") or {}).get("image_vul", "")
        checks.append({"name": "image_declared", "ok": bool(image),
                       "detail": image or "metadata.image_vul not set (warning only)"})
    return checks


def run_preflight(task_id: str, store, bus: EventBus) -> dict:
    task = store.get_task(task_id)
    previous = task["state"]
    if previous not in ENTRY_STATES:
        raise ValueError(
            f"preflight requires RECEIVED or BLOCKED (retry), got {previous}")
    retry = previous == "BLOCKED"
    store.transition(task_id, "PREFLIGHT",
                     reason="preflight retry from BLOCKED" if retry
                     else "preflight started")
    checks = _check_target(task)
    # image_declared 是 warning，不阻断；target/authorized 才阻断
    blockers = [c["name"] for c in checks
                if not c["ok"] and c["name"] in BLOCKING_CHECKS]
    dst = "BLOCKED" if blockers else "READY"
    reason = "blocked: " + ",".join(blockers) if blockers else "admission passed"
    store.transition(task_id, dst, reason=reason)
    bus.emit(task_id, "preflight.passed" if not blockers else "preflight.failed",
             stage=dst, payload={"checks": checks, "blockers": blockers,
                                 "retry": retry, "previous_state": previous,
                                 "policy": authorization.MISSING_POLICY})
    return {"task_id": task_id, "state": dst, "checks": checks,
            "blockers": blockers, "retry": retry,
            "previous_state": previous,
            "policy": authorization.MISSING_POLICY}
