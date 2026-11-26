"""V2 P3.6 预算强制：max_seconds / max_execs / max_tokens / max_turns。

口径（与 PLATFORM-V2-P36.md 逐条对应）：

- 预算是**任务级上限**（TaskSpec.Budget）；Plan.budget 只是本次执行的请求值，
  执行前把请求值截断到剩余额度，执行中按 fuzz stats / 耗时判定，超限就终止；
- 用量**从事件流推出来**，不新增表：`exec.started` 记 1 回合，`exec.finished` 的
  `seconds / fuzz.execs / tokens` 累加，LLM 用量事件按 `payload.tokens` 累加；
- 判定只回答“还能不能继续跑”，不产任何漏洞结论（`reason` 只有 `budget_*`）；
- 超限不是负结果：编排层写 `budget.exceeded` + `task.terminated` 事件和
  `budget_snapshot` 证据，状态落 `TERMINATED`，永远不落 `NO_REPRO`。
"""
from __future__ import annotations

import time

from .task import TaskError

BUDGET_KEYS = ("max_seconds", "max_execs", "max_tokens", "max_turns")

#: 预算键 → 终止原因（写进 task.terminated / tasks.terminal_reason）
REASON_BY_KEY = {
    "max_seconds": "budget_seconds",
    "max_execs": "budget_execs",
    "max_tokens": "budget_tokens",
    "max_turns": "budget_turns",
}

#: 用量键（与预算键同名去掉 max_ 前缀）
USAGE_KEYS = ("seconds", "execs", "tokens", "turns")

#: 会带上 LLM 用量的事件类型（只按显式 tokens 字段累加，不做估算）
USAGE_EVENTS = ("model.used", "llm.used", "hypothesis.used", "plan.used")


class BudgetExceeded(RuntimeError):
    """预算耗尽：`reason` 只可能是 budget_seconds/execs/tokens/turns。"""

    def __init__(self, key: str, *, limit, used, stage: str = "",
                 detail: str = ""):
        if key not in REASON_BY_KEY:
            raise TaskError(f"unknown budget key: {key!r}")
        self.key = key
        self.reason = REASON_BY_KEY[key]
        self.limit = limit
        self.used = used
        self.stage = stage
        self.detail = detail
        super().__init__(
            f"{self.reason}: used={used} limit={limit}"
            + (f" ({detail})" if detail else ""))

    def to_dict(self) -> dict:
        return {"reason": self.reason, "key": self.key, "limit": self.limit,
                "used": self.used, "stage": self.stage, "detail": self.detail}


def normalize(budget) -> dict:
    """Budget | dict | 任意带同名属性的对象 → {max_*: int}。"""
    if hasattr(budget, "to_dict"):
        budget = budget.to_dict()
    if not isinstance(budget, dict):
        budget = {k: getattr(budget, k, None) for k in BUDGET_KEYS}
    out: dict[str, int] = {}
    for key in BUDGET_KEYS:
        value = budget.get(key)
        if value is None:
            raise TaskError(f"budget missing {key}")
        value = int(value)
        if value <= 0:
            raise TaskError(f"{key} must be > 0")
        out[key] = value
    return out


def zero_usage() -> dict:
    return {"seconds": 0.0, "execs": 0, "tokens": 0, "turns": 0}


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def usage_from_events(events) -> dict:
    """从事件流累加用量：秒数/execs/tokens/回合数（可重放，不依赖内存状态）。"""
    used = zero_usage()
    for ev in events or []:
        payload = (ev or {}).get("payload") or {}
        event_type = str((ev or {}).get("event_type") or "")
        if event_type == "exec.started":
            used["turns"] += 1
        elif event_type == "exec.finished":
            seconds = payload.get("seconds")
            if isinstance(seconds, (int, float)):
                used["seconds"] += float(seconds)
            fuzz = payload.get("fuzz") or {}
            if isinstance(fuzz, dict):
                used["execs"] += _as_int(fuzz.get("execs"))
            used["tokens"] += _as_int(payload.get("tokens"))
        elif event_type in USAGE_EVENTS:
            used["tokens"] += _as_int(payload.get("tokens")
                                      or payload.get("total_tokens"))
    return used


def merge_usage(*parts) -> dict:
    out = zero_usage()
    for part in parts:
        if not part:
            continue
        for key in USAGE_KEYS:
            if part.get(key) is None:
                continue
            if key == "seconds":
                out[key] += float(part[key])
            else:
                out[key] += _as_int(part[key])
    return out


def violations(budget, used, *, strict: bool = False) -> list[dict]:
    """返回全部越限项（按 BUDGET_KEYS 顺序），空列表=预算内。

    `strict=False`（默认，预检口径）：`used >= limit` —— 已经没有额度再开一次执行；
    `strict=True`（结算口径）：`used > limit` —— 真正超出上限。结算用严格口径，
    这样“正好用满额度”的一次执行仍按真实结果落 CANDIDATE/NO_REPRO，
    不会被误记成超限终止。
    """
    budget = normalize(budget)
    out = []
    for key in BUDGET_KEYS:
        name = key.split("_", 1)[1]
        spend = used.get(name) or 0
        if key == "max_seconds":
            spend = float(spend)
        else:
            spend = _as_int(spend)
        limit = budget[key]
        over = spend > limit if strict else spend >= limit
        if over:
            out.append({"key": key, "reason": REASON_BY_KEY[key],
                        "limit": limit, "used": spend})
    return out


def check(budget, used, *, stage: str = "", detail: str = "",
          strict: bool = False) -> None:
    """越限即抛 BudgetExceeded（第一项，按 BUDGET_KEYS 顺序）。"""
    found = violations(budget, used, strict=strict)
    if not found:
        return
    first = found[0]
    raise BudgetExceeded(first["key"], limit=first["limit"],
                         used=first["used"], stage=stage, detail=detail)


class BudgetGuard:
    """一次执行的预算账本：执行前预检、执行中观测、剩余额度/截止时间。

    - `begin()` 开表（记录单调起点，用于“执行中耗时”）；
    - `precheck()` 用**已有用量**判定，越限抛错（此时还没开始执行）；
    - `remaining_seconds()` / `deadline()` 给执行器截断本次运行时长；
    - `absorb(seconds=..., execs=...)` 结算本次运行并再次判定，越限抛错。
    """

    def __init__(self, budget, *, used=None, clock=time.monotonic):
        self.budget = normalize(budget)
        self.used = merge_usage(used)
        self.clock = clock
        self._started: float | None = None

    # ---- 账本 ----
    def begin(self) -> "BudgetGuard":
        self._started = self.clock()
        return self

    def elapsed(self) -> float:
        if self._started is None:
            return 0.0
        return max(0.0, float(self.clock() - self._started))

    def live_usage(self) -> dict:
        used = dict(self.used)
        used["seconds"] = float(used.get("seconds") or 0.0) + self.elapsed()
        return used

    def record(self, *, execs: int = 0, tokens: int = 0) -> dict:
        """记账但不判定（取消路径也要如实记下已经跑掉的 execs/耗时）。"""
        self.used["execs"] = _as_int(self.used.get("execs")) + _as_int(execs)
        self.used["tokens"] = _as_int(self.used.get("tokens")) + _as_int(tokens)
        self.used["seconds"] = float(self.used.get("seconds") or 0.0) + self.elapsed()
        if self._started is not None:
            self._started = self.clock()
        return self.live_usage()

    def absorb(self, *, execs: int = 0, tokens: int = 0,
               stage: str = "running") -> dict:
        live = self.record(execs=execs, tokens=tokens)
        check(self.budget, live, stage=stage, strict=True)
        return live

    # ---- 判定 ----
    def precheck(self, *, stage: str = "precheck") -> None:
        check(self.budget, self.live_usage(), stage=stage)

    def remaining_seconds(self) -> float:
        return max(0.0, float(self.budget["max_seconds"])
                   - float(self.live_usage()["seconds"]))

    def remaining_execs(self) -> int:
        return max(0, int(self.budget["max_execs"])
                   - _as_int(self.live_usage()["execs"]))

    def deadline(self) -> float:
        """单调时钟绝对截止点（给执行器做硬截断）。"""
        return self.clock() + self.remaining_seconds()

    def cap_seconds(self, requested: float) -> float:
        """把本次请求的秒数夹到剩余额度内。"""
        return max(0.0, min(float(requested), self.remaining_seconds()))

    def snapshot(self, *, extra: dict | None = None) -> dict:
        used = self.live_usage()
        found = violations(self.budget, used, strict=True)
        out = {
            "limits": dict(self.budget),
            "used": used,
            "remaining": {
                "seconds": max(0.0, self.budget["max_seconds"] - used["seconds"]),
                "execs": max(0, self.budget["max_execs"] - _as_int(used["execs"])),
                "tokens": max(0, self.budget["max_tokens"] - _as_int(used["tokens"])),
                "turns": max(0, self.budget["max_turns"] - _as_int(used["turns"])),
            },
            "exceeded": found[0]["reason"] if found else None,
            "violations": found,
            # 非严格口径：used >= limit（没有额度再开一次执行；正好用满也列出）
            "at_limit": [v["reason"] for v in
                         violations(self.budget, used)],
            "elapsed": round(self.elapsed(), 3),
        }
        if extra:
            out["extra"] = extra
        return out
