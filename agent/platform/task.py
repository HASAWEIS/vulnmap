"""V2 任务契约：TaskSpec / Budget / TaskState。

P0 只做状态与契约，不执行目标。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import re
import secrets
import time

from .authorization import AuthorizationError, normalize_metadata

BENCHMARKS = ("cybergym", "exploitgym", "vulngym", "target_yaml")

STATES = (
    "RECEIVED", "PREFLIGHT", "READY",
    "UNDERSTANDING", "HYPOTHESES", "PLANNED", "RUNNING",
    "CANDIDATE", "VERIFYING", "REVIEW", "REPORTED", "CLOSED",
    "BLOCKED", "FAILED", "NO_REPRO", "NEEDS_EVIDENCE", "REJECTED",
    "CANCELLED", "TERMINATED",
)
#: 终态不可取消、不可再迁移；CANCELLED=人工取消，TERMINATED=预算强制终止（P3.6）
TERMINAL = {"CLOSED", "BLOCKED", "FAILED", "NO_REPRO", "NEEDS_EVIDENCE",
            "REJECTED", "CANCELLED", "TERMINATED"}

#: 可取消的非终态（RUNNING/PLANNED 是 P3.6 的主路径；其余非终态同样允许显式取消）
CANCELLABLE = (
    "RECEIVED", "PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES",
    "PLANNED", "RUNNING", "CANDIDATE", "VERIFYING", "REVIEW", "REPORTED",
)

TRANSITIONS: dict[str, set[str]] = {
    "RECEIVED": {"PREFLIGHT", "BLOCKED"},
    "PREFLIGHT": {"READY", "BLOCKED"},
    "READY": {"UNDERSTANDING", "BLOCKED"},
    "UNDERSTANDING": {"HYPOTHESES", "FAILED", "BLOCKED"},
    "HYPOTHESES": {"PLANNED", "FAILED", "BLOCKED"},
    "PLANNED": {"RUNNING", "FAILED", "BLOCKED", "TERMINATED", "CANCELLED"},
    # NEEDS_EVIDENCE：执行跑完但证据不够（static 复核缺口、两侧只有一侧可观测），
    # 与 NO_REPRO（跑完没差异）分开——它是“缺证据”，不是负结果。
    "RUNNING": {"CANDIDATE", "FAILED", "BLOCKED", "NO_REPRO",
                "NEEDS_EVIDENCE", "TERMINATED", "CANCELLED"},
    "CANDIDATE": {"VERIFYING", "REJECTED", "NO_REPRO"},
    "VERIFYING": {"REVIEW", "REJECTED", "NO_REPRO", "NEEDS_EVIDENCE"},
    "REVIEW": {"REPORTED", "NEEDS_EVIDENCE", "REJECTED"},
    "REPORTED": {"CLOSED"},
    "CLOSED": set(),
    "BLOCKED": {"PREFLIGHT", "READY"},  # 允许补材料后重入
    "FAILED": {"READY"},
    "NO_REPRO": {"RUNNING", "CLOSED"},
    # 补齐证据后可重跑（与 NO_REPRO → RUNNING 同口径），否则缺口任务只能重开
    "NEEDS_EVIDENCE": {"REVIEW", "CLOSED", "RUNNING"},
    "REJECTED": {"CLOSED"},
    "CANCELLED": set(),
    "TERMINATED": set(),
}

# 其余非终态也允许显式取消（终态集合里的不开放任何出边）
for _state in CANCELLABLE:
    if _state in TRANSITIONS:
        TRANSITIONS[_state] = TRANSITIONS[_state] | {"CANCELLED"}
del _state

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,120}$")


class TaskError(ValueError):
    """任务契约/状态迁移错误。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_task_id(prefix: str = "task") -> str:
    return f"{prefix}-{int(time.time())}-{secrets.token_hex(3)}"


@dataclass(frozen=True)
class Budget:
    max_seconds: int = 3600
    max_execs: int = 1_000_000
    max_tokens: int = 2_000_000
    max_turns: int = 40

    def __post_init__(self) -> None:
        for name in ("max_seconds", "max_execs", "max_tokens", "max_turns"):
            if int(getattr(self, name)) <= 0:
                raise TaskError(f"{name} must be > 0")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TaskSpec:
    task_id: str
    benchmark: str
    target: str
    budget: Budget = field(default_factory=Budget)
    mode: str = "fuzz"
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not SAFE_ID.match(self.task_id or ""):
            raise TaskError(f"unsafe task_id: {self.task_id!r}")
        if self.benchmark not in BENCHMARKS:
            raise TaskError(f"unsupported benchmark: {self.benchmark!r}")
        if not str(self.target or "").strip():
            raise TaskError("target is required")
        if not isinstance(self.budget, Budget):
            self.budget = Budget(**self.budget)
        if not isinstance(self.metadata, dict):
            raise TaskError("metadata must be a dict")
        # 授权声明在这里就归一化成布尔：CLI 的 --meta 与 API 的 JSON 走同一条路，
        # 字符串 "false" 不允许以原样落库（F1：bool("false") 恒为真）。
        try:
            self.metadata = normalize_metadata(self.metadata)
        except AuthorizationError as exc:
            raise TaskError(str(exc)) from exc

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "benchmark": self.benchmark,
            "target": self.target,
            "mode": self.mode,
            "budget": self.budget.to_dict(),
            "metadata": self.metadata,
        }


def can_transition(src: str, dst: str) -> bool:
    return src in TRANSITIONS and dst in TRANSITIONS[src]


def assert_transition(src: str, dst: str) -> None:
    if not can_transition(src, dst):
        raise TaskError(f"illegal transition: {src} -> {dst}")
