"""Append-only EventBus：所有阶段迁移/执行事件都从这里写。"""
from __future__ import annotations

from .task import assert_transition


class EventBus:
    def __init__(self, store):
        self.store = store

    def emit(self, task_id: str, event_type: str, stage: str = "",
             payload: dict | None = None) -> int:
        return self.store.append_event(task_id, event_type, stage=stage,
                                       payload=payload or {})

    def list(self, task_id: str, after_seq: int = 0) -> list[dict]:
        return self.store.list_events(task_id, after_seq=after_seq)

    def replay(self, task_id: str) -> dict:
        """从事件流重建状态，并校验每条 state.changed 都是合法迁移。"""
        events = self.list(task_id)
        state = "RECEIVED"
        transitions = []
        for ev in events:
            if ev["event_type"] != "state.changed":
                continue
            p = ev.get("payload") or {}
            src, dst = p.get("from"), p.get("to")
            if src != state:
                raise ValueError(f"event seq={ev['seq']} from={src} != replayed={state}")
            assert_transition(src, dst)
            transitions.append({"seq": ev["seq"], "from": src, "to": dst,
                                "reason": p.get("reason", "")})
            state = dst
        return {"task_id": task_id, "state": state, "events": len(events),
                "transitions": transitions}
