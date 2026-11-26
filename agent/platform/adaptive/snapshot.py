"""V3-006：可信执行快照（TrustedExecutionSnapshot）。

口径（《V3 完整升级方案》§5「执行感知」、§9「统一数据契约」）：

- **快照只读**：由 collector 从事实源（事件流 + ProgramIndex + 语料台账）构建，
  模型只读；本模块不写状态、不产候选、不改裁决字段。
- **七组事实**：身份 / 实际配置 / 程序上下文 / 输入与可达 / 覆盖 / 故障 /
  决策资源。“跑的是哪个 build”和“worker 实际用了什么参数”分开列，
  因为两者经常不一致。
- **三值语义**：`true / false / unknown`。缺寄存器、缺调用图、缺覆盖、
  缺预算读数一律 `unknown`，**绝不填 0**——`new_coverage_bits=0` 与
  “没有覆盖指标”是两件事，后者不许冒充前者。
- **目标语义三段分开**（`docs/V3-TARGET-SEMANTICS.md`）：`program_started`
  （进程真的起来）/ `input_processed`（输入真的被处理，需探针）/
  `checkpoint_reached`（目标分支或检查点命中，需显式探针或显式字段）。
  三者各自三值、互不派生；`target_reached` 只是 `checkpoint_reached` 的兼容别名。
  `coverage_bits` / `execs` / `new_coverage_bits` / 崩溃数**永远**推不出
  `checkpoint_reached`——最多说明程序跑了、覆盖面动了。
- **来源四分类**：`observed`（本次观测）/ `declared`（上游声明，例如
  exec.started 写的 kind 与预算）/ `synthetic`（本快照派生的三值判断，例如
  `coverage.comparable`）/ `assumed`（模型假设；本模块永不产出，槽位留给上层）。
- **游标即边界**：快照带 `execution_id + 游标 seq`；用别的 execution 的游标
  续读、或把两个 execution 的快照合并，一律 `SnapshotError(cross_execution)`——
  不允许“拼接出一个更完整的结论”。
- **事实字段来自执行器的只读钩子**（`executors.execution_fact_view`）：新增执行
  事件字段时只改那一处，快照跟着变，不用两边各写一套字段名。
- **配置效果只报观测**（`docs/V3-W2-CONFIG.md` §2/§5.1）：`config` 组新增
  `planned_config_sha256` / `loaded_config_sha256` / `config_effective` /
  `config_source`，取值只来自 `executors.config_effect_view()`；`planned` 只来自
  revision 侧声明、`loaded` **只**来自执行器回报。执行器没报就是 `unknown`，
  **绝不把 planned 回填成 loaded**——“没观测到”不是“没生效”。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .contracts import digest_of

SCHEMA = "vulnmap.adaptive.execution_snapshot.v1"
SCHEMA_VERSION = 1

UNKNOWN = "unknown"
TRUE = "true"
FALSE = "false"
TRI = (TRUE, FALSE, UNKNOWN)

#: 事实组（§5 表格的行）
FACT_GROUPS = ("identity", "config", "program", "input", "coverage", "fault",
               "budget")

#: 每条事实的来源分类（§5：“防止拼接成无条件结论”）
FACT_SOURCES = ("observed", "declared", "synthetic", "assumed")

#: 只有这些组有值才说明“本次执行真的被观测到”
OBSERVED_GROUPS = ("program", "input", "coverage", "fault")

#: 判定“真有观测”的实质字段：**排除合成的标签字段**
#: （`input.observation_source`、`fault.*_detail`、`coverage.status/sampling/error`）。
#: 标签是“我怎么知道的”，不是“知道了什么”——只有一个标签的快照仍然没有结论。
OBSERVED_FIELDS: dict[str, tuple[str, ...]] = {
    "program": ("index_sha256", "entry_points", "functions", "call_sites",
                "formats", "source_count"),
    "input": ("corpus_version", "corpus_hash", "corpus_build_id",
              "corpus_comparable", "input_consumed", "program_started",
              "input_processed", "checkpoint_reached", "target_reached",
              "seeds", "dictionary_tokens", "format"),
    "coverage": ("metric_kind", "baseline_id", "covered", "uncovered",
                 "planned", "delta", "evidence_sha256"),
    "fault": ("outcome", "setup_error", "timeout", "cancelled",
              "budget_stopped", "sanitizer_type", "candidates",
              "candidate_signature", "log_ref", "error"),
}

#: 各组默认来源
GROUP_SOURCE = {
    "identity": "declared",
    "config": "declared",
    "program": "observed",
    "input": "observed",
    "coverage": "observed",
    "fault": "observed",
    "budget": "declared",
}

#: 跨 execution 拼接的错误码（唯一词形，测试与文档都用它）
CROSS_EXECUTION = "cross_execution"

#: 执行事件类型（快照只读这三类）
EXEC_STARTED = "exec.started"
EXEC_FINISHED = "exec.finished"
CANDIDATE_CREATED = "candidate.created"


class SnapshotError(RuntimeError):
    """快照边界错误：跨 execution 拼接、游标非法、事实源不可读。"""

    def __init__(self, code: str, reason: str) -> None:
        self.code = str(code or "snapshot_error")
        self.reason = str(reason or "")
        super().__init__(f"{self.code}: {self.reason}")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def tri(value: Any) -> str:
    """三值化：只有真正的 bool 才给 true/false，其余（含 None/缺失）一律 unknown。"""
    if value is True:
        return TRUE
    if value is False:
        return FALSE
    return UNKNOWN


def is_unknown(value: Any) -> bool:
    return value is None or value == UNKNOWN


# ====================================================================== 游标
@dataclass(frozen=True)
class Cursor:
    """(execution_id, seq) 读取游标：游标绑 execution，换 execution 即非法。"""

    execution_id: str
    seq: int = 0

    def __post_init__(self) -> None:
        seq = int(self.seq or 0)
        if seq < 0:
            raise SnapshotError("invalid_cursor", "cursor.seq must be >= 0")
        object.__setattr__(self, "execution_id", str(self.execution_id or ""))
        object.__setattr__(self, "seq", seq)

    def advance(self, seq: int) -> "Cursor":
        nxt = int(seq or 0)
        if nxt < self.seq:
            raise SnapshotError("invalid_cursor",
                                f"游标只能前进：{self.seq} -> {nxt}")
        return Cursor(self.execution_id, nxt)

    def to_dict(self) -> dict:
        return {"execution_id": self.execution_id, "seq": self.seq}

    @classmethod
    def from_dict(cls, doc: Mapping | None) -> "Cursor":
        if not isinstance(doc, Mapping):
            raise SnapshotError("invalid_cursor", "cursor must be a mapping")
        return cls(str(doc.get("execution_id") or ""), int(doc.get("seq") or 0))


# ====================================================================== 构建器
class _Facts:
    """逐字段落盘 + 自动登记 unknown 路径（缺数据不填 0）。"""

    def __init__(self) -> None:
        self.groups: dict[str, dict] = {name: {} for name in FACT_GROUPS}
        self.unknowns: list[str] = []

    def put(self, group: str, path: str, value: Any,
            *, keep_empty: bool = False) -> Any:
        if value is None or value == UNKNOWN:
            value = UNKNOWN
        elif isinstance(value, str) and not value.strip() and not keep_empty:
            value = UNKNOWN
        elif isinstance(value, (list, tuple, dict)) and len(value) == 0 \
                and not keep_empty:
            value = UNKNOWN
        self.groups[group][path] = value
        key = f"{group}.{path}"
        if value == UNKNOWN:
            if key not in self.unknowns:
                self.unknowns.append(key)
        elif key in self.unknowns:
            self.unknowns.remove(key)
        return value

    def raw(self, group: str, path: str, value: Any) -> Any:
        """显式“空值也是观测结果”的落点（例如 denials=[] 表示确实没有被拒）。"""
        return self.put(group, path, value, keep_empty=True)

    def group_source(self, group: str) -> str:
        values = list(self.groups[group].values())
        if not values or all(v == UNKNOWN for v in values):
            return UNKNOWN
        return GROUP_SOURCE[group]


# ====================================================================== 快照
@dataclass(frozen=True)
class TrustedExecutionSnapshot:
    """一次 execution 的只读事实视图（不可变；合并/续读都返回新快照）。"""

    task_id: str
    execution_id: str
    groups: Mapping[str, Mapping]
    cursor: Cursor
    sources: Mapping[str, str] = field(default_factory=dict)
    unknowns: tuple[str, ...] = ()
    events: int = 0
    binding_hash: str = ""
    complete: bool = False
    foreign_executions: int = 0
    collected_at: str = ""

    # ---- 读取 ----
    def group(self, name: str) -> dict:
        if name not in FACT_GROUPS:
            raise SnapshotError("unknown_group", f"未知事实组：{name!r}")
        return dict(self.groups.get(name) or {})

    def facts(self) -> dict:
        return {name: self.group(name) for name in FACT_GROUPS}

    def has(self, group: str) -> bool:
        return any(value != UNKNOWN
                   for value in (self.groups.get(group) or {}).values())

    def get(self, path: str, default: Any = UNKNOWN) -> Any:
        """按 `group.field` 取值；未知路径返回 default（默认 unknown）。"""
        group, _, field_name = str(path).partition(".")
        if not field_name:
            return default
        return (self.groups.get(group) or {}).get(field_name, default)

    def tri(self, path: str) -> str:
        value = self.get(path)
        return value if value in TRI else UNKNOWN

    def unknown_paths(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.unknowns)))

    def observed(self) -> bool:
        """是否真的有“实质观测”（标签字段不算）。"""
        for group, fields in OBSERVED_FIELDS.items():
            values = self.groups.get(group) or {}
            if any(values.get(name) not in (None, UNKNOWN) for name in fields):
                return True
        return False

    @property
    def status(self) -> str:
        """整体状态：**看到 exec.finished 且真的有实质观测**才算 applied。

        - 只有 `exec.started`（还在跑）：`unknown`——结果还没出现，别把
          “正在跑”读成“跑过并得到结论”；
        - 只有身份/预算声明：`unknown`——声明不等于跑过；
        - 已经结束但所有观测都缺失（只有一个空 finish 事件）：`unknown`——
          合成的标签（如 `observation_source`）不算结论。
        """
        if not self.complete:
            return UNKNOWN
        return "applied" if self.observed() else UNKNOWN

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id,
            "execution_id": self.execution_id,
            "binding_hash": self.binding_hash,
            "status": self.status,
            "complete": bool(self.complete),
            "cursor": self.cursor.to_dict(),
            "groups": {name: dict(self.groups.get(name) or {})
                       for name in FACT_GROUPS},
            "sources": {name: self.sources.get(name, UNKNOWN)
                        for name in FACT_GROUPS},
            "unknowns": list(self.unknown_paths()),
            "events": int(self.events),
            "foreign_executions": int(self.foreign_executions),
            "collected_at": self.collected_at or now(),
        }

    # ---- 合并（同 execution 才允许） ----
    def merge(self, other: "TrustedExecutionSnapshot"
              ) -> "TrustedExecutionSnapshot":
        """同 execution 的两个窗口合并；换 execution 一律拒绝。"""
        if not isinstance(other, TrustedExecutionSnapshot):
            raise SnapshotError("invalid_merge", "只能合并快照对象")
        if other.execution_id != self.execution_id:
            raise SnapshotError(
                CROSS_EXECUTION,
                f"拒绝跨 execution 拼接：{self.execution_id!r} + "
                f"{other.execution_id!r}")
        if self.task_id != other.task_id:
            raise SnapshotError(
                CROSS_EXECUTION,
                f"拒绝跨任务拼接：{self.task_id!r} + {other.task_id!r}")
        if self.binding_hash and other.binding_hash \
                and self.binding_hash != other.binding_hash:
            raise SnapshotError(
                "binding_mismatch",
                f"两个快照的绑定不同（{self.binding_hash[:12]}… vs "
                f"{other.binding_hash[:12]}…），不是同一次会话的事实")
        merged: dict[str, dict] = {}
        for name in FACT_GROUPS:
            base = dict(self.groups.get(name) or {})
            for key, value in (other.groups.get(name) or {}).items():
                if value != UNKNOWN or key not in base:
                    base[key] = value
            merged[name] = base
        resolved = {f"{g}.{k}" for g, fields in merged.items()
                    for k, v in fields.items() if v != UNKNOWN}
        unknowns = tuple(sorted(u for u in set(self.unknowns) | set(other.unknowns)
                                if u not in resolved))
        return TrustedExecutionSnapshot(
            task_id=self.task_id,
            execution_id=self.execution_id,
            groups=merged,
            cursor=Cursor(self.execution_id,
                          max(self.cursor.seq, other.cursor.seq)),
            sources={name: (other.sources.get(name)
                            if other.sources.get(name) not in (None, UNKNOWN)
                            else self.sources.get(name, UNKNOWN))
                     for name in FACT_GROUPS},
            unknowns=unknowns,
            events=max(int(self.events), int(other.events)),
            binding_hash=self.binding_hash or other.binding_hash,
            complete=bool(self.complete or other.complete),
            foreign_executions=max(int(self.foreign_executions),
                                   int(other.foreign_executions)),
            collected_at=now(),
        )

    # ---- 构建 ----
    @classmethod
    def empty(cls, task_id: str, *, execution_id: str = "",
              binding_hash: str = "", cursor: Cursor | None = None
              ) -> "TrustedExecutionSnapshot":
        """没有任何执行事实时的诚实快照：全组 unknown，不伪造 0。"""
        facts = _Facts()
        for group in FACT_GROUPS:
            for path in _GROUP_PATHS[group]:
                facts.put(group, path, UNKNOWN)
        facts.raw("identity", "task_id", task_id)
        if execution_id:
            facts.raw("identity", "execution_id", execution_id)
        return cls(
            task_id=task_id,
            execution_id=execution_id,
            groups=facts.groups,
            cursor=cursor or Cursor(execution_id, 0),
            sources={name: facts.group_source(name) for name in FACT_GROUPS},
            unknowns=tuple(facts.unknowns),
            events=0,
            binding_hash=binding_hash,
            collected_at=now(),
        )

    @classmethod
    def collect(cls, store, task_id: str, *, execution_id: str = "",
                cursor: Cursor | None = None, index: Any = None,
                task: Mapping | None = None, corpus: Any = None,
                binding_hash: str = "", campaign: str = "",
                epoch: int | None = None, job_id: str = "",
                tools_allowed: Iterable[str] | None = None,
                denials: Iterable[str] | None = None
                ) -> "TrustedExecutionSnapshot":
        """从事实源构建快照：事件流（带游标）+ ProgramIndex + 语料台账。"""
        if store is None:
            raise SnapshotError("no_store", "collect() 需要一个已打开的存储")
        task = dict(task or store.get_task(task_id))
        if cursor is not None and not isinstance(cursor, Cursor):
            cursor = Cursor.from_dict(cursor)
        if cursor is not None and cursor.execution_id and execution_id \
                and cursor.execution_id != execution_id:
            raise SnapshotError(
                CROSS_EXECUTION,
                f"游标 execution_id={cursor.execution_id!r} 与请求 "
                f"{execution_id!r} 不一致（禁止跨 execution 续读）")
        if cursor is not None and not execution_id:
            execution_id = cursor.execution_id
        after = int(cursor.seq) if cursor else 0
        events = list(store.list_events(task_id, after_seq=after))

        starts: list[dict] = []
        finishes: list[dict] = []
        foreign = 0
        last_seq = after
        for ev in events:
            last_seq = max(last_seq, int(ev.get("seq") or 0))
            payload = dict(ev.get("payload") or {})
            exec_ref = str(payload.get("exec_id") or "")
            if not exec_ref:
                continue
            if not execution_id and ev.get("event_type") == EXEC_STARTED:
                execution_id = exec_ref
            if exec_ref != execution_id:
                if ev.get("event_type") == EXEC_STARTED:
                    foreign += 1
                continue
            if ev.get("event_type") == EXEC_STARTED:
                starts.append(payload)
            elif ev.get("event_type") == EXEC_FINISHED:
                finishes.append(payload)

        if not execution_id:
            snap = cls.empty(task_id, binding_hash=binding_hash,
                             cursor=Cursor("", last_seq))
            return _with_task_declarations(snap, task, campaign=campaign,
                                           epoch=epoch, job_id=job_id,
                                           tools_allowed=tools_allowed,
                                           denials=denials)

        view = _exec_view(starts[-1] if starts else None,
                          finishes[-1] if finishes else None)
        # 配置效果是**单独的一组只读视图**：它只读 exec.started 的声明与
        # exec.finished 的回报，不参与目标三态的推断（两套字段互不冒充）。
        config_view = _config_view(starts[-1] if starts else None,
                                   finishes[-1] if finishes else None)
        consumed = sum(1 for ev in events
                       if str((ev.get("payload") or {}).get("exec_id") or "")
                       == execution_id)
        facts = _Facts()
        _fill_identity(facts, task_id, execution_id, task, view, index=index,
                       binding_hash=binding_hash, campaign=campaign,
                       epoch=epoch, job_id=job_id)
        _fill_config(facts, view, tools_allowed=tools_allowed,
                     config_view=config_view)
        _fill_program(facts, index)
        _fill_input(facts, view, corpus=corpus)
        _fill_coverage(facts, view)
        _fill_fault(facts, view)
        _fill_budget(facts, task, view, tools_allowed=tools_allowed,
                     denials=denials)
        return cls(
            task_id=task_id,
            execution_id=execution_id,
            groups=facts.groups,
            cursor=Cursor(execution_id, last_seq),
            sources={name: facts.group_source(name) for name in FACT_GROUPS},
            unknowns=tuple(facts.unknowns),
            events=consumed,
            binding_hash=binding_hash,
            complete=bool(finishes),
            foreign_executions=foreign,
            collected_at=now(),
        )


# ====================================================================== 字段表
#: 每组“必须汇报的字段”（空快照按这些路径逐个登记 unknown，方便上层对账）
_GROUP_PATHS: dict[str, tuple[str, ...]] = {
    "identity": ("task_id", "campaign", "epoch", "job_id", "execution_id",
                 "plan_sha256", "source_sha256", "harness_revision", "build_id",
                 "image", "policy_version", "binding_hash"),
    "config": ("engine", "kind_override", "sanitizer", "command", "isolation",
               "network", "workdir", "tools_allowed", "budget_declared",
               "planned_config_sha256", "loaded_config_sha256",
               "config_effective", "config_source"),
    "program": ("index_sha256", "source_root", "entry_points", "functions",
                "call_sites", "formats", "source_count", "truncated", "notes"),
    "input": ("corpus_version", "corpus_hash", "corpus_build_id",
              "corpus_comparable", "input_consumed", "program_started",
              "input_processed", "checkpoint_reached", "target_reached",
              "observation_source", "seeds", "dictionary_tokens", "format"),
    "coverage": ("status", "metric_kind", "baseline_id", "covered", "uncovered",
                 "planned", "delta", "sampling", "truncated", "comparable",
                 "error", "evidence_sha256"),
    "fault": ("outcome", "setup_error", "timeout", "cancelled", "budget_stopped",
              "sanitizer_type", "candidates", "candidate_signature", "log_ref",
              "error"),
    "budget": ("limits", "remaining_seconds", "remaining_execs",
               "remaining_tokens", "remaining_turns", "remaining_usd",
               "used_seconds", "used_execs", "used_tokens", "used_turns",
               "violations", "tools_allowed", "denials"),
}


# ====================================================================== 事实钩子
def _exec_view(start: Mapping | None, finish: Mapping | None) -> dict:
    """执行事实视图：优先用执行器的只读钩子，钩子不在就退回事件原始字段。"""
    try:
        from ..executors import execution_fact_view
    except Exception:                       # noqa: BLE001 - 纯离线单模块可用
        return _fallback_view(start, finish)
    try:
        return dict(execution_fact_view(start, finish))
    except Exception:                       # noqa: BLE001 - 钩子坏了不静默编造
        return _fallback_view(start, finish)


def _config_view(start: Mapping | None, finish: Mapping | None) -> dict:
    """配置效果视图：优先用执行器的只读钩子，钩子不在就退回事件原始字段。

    口径（`docs/V3-W2-CONFIG.md` §2/§3）：`planned` 只来自 revision 侧声明
    （`exec.started.payload.config_planned_sha256`），`loaded` **只**来自执行器
    回报（`exec.finished.payload.config_loaded_sha256` /
    `exec.finished.fuzz.loaded_config_sha256`）。缺失一律 `unknown`，
    绝不把 `planned` 回填成 `loaded`。
    """
    try:
        from ..executors import config_effect_view
    except Exception:                       # noqa: BLE001 - 纯离线单模块可用
        return _fallback_config_view(start, finish)
    try:
        return dict(config_effect_view(start, finish))
    except Exception:                       # noqa: BLE001 - 钩子坏了不静默编造
        return _fallback_config_view(start, finish)


def _fallback_config_view(start: Mapping | None, finish: Mapping | None) -> dict:
    """配置钩子不可用时的最小视图：只读事件原字段，三值表与文档 §3 一致。"""
    s = dict(start or {})
    f = dict(finish or {})
    fuzz = dict(f.get("fuzz") or {})
    planned = str(s.get("config_planned_sha256")
                  or f.get("config_planned_sha256") or "")
    # loaded 只认执行器的 finish 回报（顶层字段优先，其次 fuzz 统计）
    loaded = str(f.get("config_loaded_sha256")
                 or fuzz.get("loaded_config_sha256") or "")
    if not planned:
        effective, status, source = None, "unknown", "planned_missing"
    elif not loaded:
        effective, status, source = None, "unknown", "loaded_unreported"
    else:
        effective = planned == loaded
        status = "effective" if effective else "not_effective"
        source = "reported"
    return {"config_planned_sha256": planned,
            "config_loaded_sha256": loaded,
            "config_effective": effective, "config_status": status,
            "config_source": source,
            "config_present": {"planned": bool(planned),
                               "loaded": bool(loaded)}}


def _fallback_view(start: Mapping | None, finish: Mapping | None) -> dict:
    """钩子不可用时的最小视图（只读事件原字段，缺失一律 None）。"""
    s = dict(start or {})
    f = dict(finish or {})
    checkpoint = f.get("checkpoint_reached")
    if not isinstance(checkpoint, bool):
        checkpoint = None
    legacy = f.get("target_reached")
    source = None
    if checkpoint is not None:
        source = "checkpoint_reached"
    elif isinstance(legacy, bool):
        checkpoint = legacy
        source = "legacy_target_reached"
    return {
        "present": {"start": bool(start), "finish": bool(finish)},
        "execution_id": s.get("exec_id") or f.get("exec_id"),
        "kind": s.get("kind") or f.get("kind"),
        "kind_override": s.get("kind_override"),
        "plan_sha256": s.get("plan_sha256") or f.get("plan_sha256"),
        "workdir": s.get("workdir"),
        "budget_declared": s.get("budget"),
        "outcome": f.get("outcome"),
        "build": dict(f.get("build") or {}) or None,
        "fuzz": dict(f.get("fuzz") or {}) or None,
        "coverage": dict(f.get("coverage") or {}) or None,
        "candidates": f.get("candidates"),
        "evidence_sha256": f.get("evidence_sha256"),
        "error": f.get("error"),
        "seeds": f.get("seeds"),
        "dictionary_tokens": f.get("dictionary_tokens"),
        "format": f.get("format"),
        "budget": dict(f.get("budget") or {}) or None,
        "program_started": (f.get("program_started")
                            if isinstance(f.get("program_started"), bool)
                            else None),
        "input_processed": (f.get("input_processed")
                            if isinstance(f.get("input_processed"), bool)
                            else None),
        "checkpoint_reached": checkpoint,
        "target_reached": checkpoint,
        "target_reached_source": source,
        "flags": {"error_observed": "error" in f},
    }


# ====================================================================== 各组
def _with_task_declarations(snap: TrustedExecutionSnapshot, task: Mapping, *,
                            campaign: str, epoch: int | None, job_id: str,
                            tools_allowed: Iterable[str] | None,
                            denials: Iterable[str] | None
                            ) -> TrustedExecutionSnapshot:
    """无执行时也如实报任务身份与预算声明（其余仍 unknown）。"""
    groups = {name: dict(fields) for name, fields in snap.groups.items()}
    groups["identity"]["task_id"] = str(task.get("task_id") or "")
    groups["identity"]["campaign"] = campaign or UNKNOWN
    groups["identity"]["epoch"] = epoch if epoch is not None else UNKNOWN
    groups["identity"]["job_id"] = job_id or UNKNOWN
    groups["budget"]["limits"] = dict(task.get("budget") or {}) or UNKNOWN
    groups["budget"]["tools_allowed"] = (
        list(tools_allowed) if tools_allowed is not None else UNKNOWN)
    groups["budget"]["denials"] = (list(denials) if denials is not None
                                   else UNKNOWN)
    unknowns = []
    for group in FACT_GROUPS:
        for path_name, value in groups[group].items():
            if value == UNKNOWN:
                unknowns.append(f"{group}.{path_name}")
    sources = {name: (UNKNOWN if all(v == UNKNOWN for v in groups[name].values())
                      else GROUP_SOURCE[name]) for name in FACT_GROUPS}
    return TrustedExecutionSnapshot(
        task_id=snap.task_id, execution_id=snap.execution_id, groups=groups,
        cursor=snap.cursor, sources=sources, unknowns=tuple(sorted(set(unknowns))),
        events=snap.events, binding_hash=snap.binding_hash,
        complete=snap.complete, foreign_executions=snap.foreign_executions,
        collected_at=snap.collected_at)


def _fill_identity(facts: _Facts, task_id: str, execution_id: str,
                   task: Mapping, view: Mapping, *, index: Any,
                   binding_hash: str, campaign: str, epoch: int | None,
                   job_id: str) -> None:
    facts.raw("identity", "task_id", task_id)
    facts.raw("identity", "execution_id", execution_id)
    facts.put("identity", "campaign", campaign)
    facts.put("identity", "epoch", epoch)
    facts.put("identity", "job_id", job_id)
    facts.put("identity", "plan_sha256", view.get("plan_sha256"))
    facts.put("identity", "binding_hash", binding_hash)
    index_doc = _index_doc(index)
    facts.put("identity", "source_sha256", index_doc.get("sha256"))
    build = dict(view.get("build") or {})
    facts.put("identity", "harness_revision",
              build.get("harness") or index_doc.get("harness"))
    facts.put("identity", "build_id",
              build.get("build_id") or build.get("sha256"))
    facts.put("identity", "image", view.get("image"))
    facts.put("identity", "policy_version", view.get("policy_version"))


def _fill_config(facts: _Facts, view: Mapping, *,
                 tools_allowed: Iterable[str] | None,
                 config_view: Mapping | None = None) -> None:
    facts.put("config", "engine", view.get("kind"))
    facts.put("config", "kind_override", view.get("kind_override"))
    # worker 实际生效的 sanitizer/命令/隔离/网络：事件里没有就不猜
    facts.put("config", "sanitizer", view.get("sanitizer"))
    facts.put("config", "command", view.get("command"))
    facts.put("config", "isolation", view.get("isolation"))
    facts.put("config", "network", view.get("network"))
    facts.put("config", "workdir", view.get("workdir"))
    facts.put("config", "budget_declared", view.get("budget_declared"))
    facts.put("config", "tools_allowed",
              list(tools_allowed) if tools_allowed is not None else None)
    # ---- 配置效果（W2）：只落观测到的东西，缺就是 unknown ----
    # `loaded` 绝不回填 `planned`：执行器没报就是“没观测到”，不是“加载了同一版”。
    cfg = dict(config_view or {})
    facts.put("config", "planned_config_sha256",
              cfg.get("config_planned_sha256"))
    facts.put("config", "loaded_config_sha256",
              cfg.get("config_loaded_sha256"))
    facts.put("config", "config_effective", tri(cfg.get("config_effective")))
    facts.put("config", "config_source", cfg.get("config_source"))


def _fill_program(facts: _Facts, index: Any) -> None:
    doc = _index_doc(index)
    if not doc:
        for path in _GROUP_PATHS["program"]:
            facts.put("program", path, None)
        return
    counts = dict(doc.get("counts") or {})
    facts.put("program", "index_sha256", doc.get("sha256") or digest_of(doc))
    facts.put("program", "source_root", doc.get("root"))
    # counts 缺失时退回“真实列表长度”，不是填 0
    for path, key in (("entry_points", "entry_points"),
                      ("functions", "functions"),
                      ("call_sites", "call_sites")):
        if key in counts:
            facts.put("program", path, counts.get(key))
        else:
            facts.put("program", path,
                      len(doc.get(key) or []) or None)
    facts.put("program", "formats", doc.get("formats"))
    facts.put("program", "source_count", doc.get("source_count"))
    if "warnings" in doc:
        facts.put("program", "truncated", tri(bool(doc.get("warnings"))))
    else:
        facts.put("program", "truncated", None)
    facts.raw("program", "notes", list(doc.get("notes") or []))


def _fill_input(facts: _Facts, view: Mapping, *, corpus: Any) -> None:
    build = dict(view.get("build") or {})
    build_id = str(build.get("build_id") or build.get("sha256") or "")
    corpus_snap: dict = {}
    if corpus is not None:
        try:
            corpus_snap = dict(corpus.snapshot() or {})
        except Exception:               # noqa: BLE001 - 台账不可读=未知，不是 0
            corpus_snap = {}
    if corpus_snap:
        facts.put("input", "corpus_version", corpus_snap.get("corpus_version"))
        facts.put("input", "corpus_hash", corpus_snap.get("corpus_hash"))
        facts.put("input", "corpus_build_id", corpus_snap.get("build_id"))
        corpus_build = str(corpus_snap.get("build_id") or "")
        if not corpus_build or not build_id:
            facts.put("input", "corpus_comparable", None)
        else:
            facts.put("input", "corpus_comparable",
                      tri(corpus_build == build_id))
    else:
        for path in ("corpus_version", "corpus_hash", "corpus_build_id",
                     "corpus_comparable"):
            facts.put("input", path, None)

    fuzz = dict(view.get("fuzz") or {})
    execs = fuzz.get("execs")
    facts.put("input", "input_consumed",
              None if execs is None else tri(int(execs) > 0))
    # ---- 目标语义三段（P1 拆分）：各自独立落盘，缺就是 unknown ----
    # `input_consumed`（语料被喂进 fuzz 执行器）不是 `input_processed`
    # （目标真的处理了输入），`execs>0` 也不是，别拿前者冒充后者。
    facts.put("input", "program_started",
              tri(_view_tri(view, "program_started")))
    facts.put("input", "input_processed",
              tri(_view_tri(view, "input_processed")))
    reached, source = _target_reached(view)
    facts.put("input", "checkpoint_reached", reached)
    facts.put("input", "target_reached", reached)   # 兼容别名：同一来源，不再独立推断
    facts.put("input", "observation_source", source)
    facts.put("input", "seeds", view.get("seeds"))
    facts.put("input", "dictionary_tokens", view.get("dictionary_tokens"))
    facts.put("input", "format", view.get("format"))


def _view_tri(view: Mapping, name: str) -> bool | None:
    """从执行事实视图取一个三段事实：只认真正的 bool，其余一律 None。"""
    value = view.get(name)
    return value if isinstance(value, bool) else None


def _target_reached(view: Mapping) -> tuple[str, str | None]:
    """目标检查点是否真的命中：**只认 checkpoint_reached**（或它映射来的旧字段）。

    `coverage_bits` / `execs` / `new_coverage_bits` / 崩溃数一律**不能**推出
    “命中”——它们最多说明程序跑了、覆盖变了，说明不了目标分支被走到。
    没有显式探针就是 `unknown`，并给出一个说明来源的标签。
    """
    present = dict(view.get("present") or {})
    if not present.get("finish"):
        # 还没有 exec.finished：连“探针有没有报”都还不知道，不能写标签
        return UNKNOWN, None
    checkpoint = _view_tri(view, "checkpoint_reached")
    if checkpoint is None:
        # 兼容钩子不可用时的原始视图（legacy 字段没有映射）
        checkpoint = _view_tri(view, "target_reached")
        source = "legacy_target_reached"
    else:
        declared = str(view.get("target_reached_source") or "")
        source = ("legacy_target_reached" if declared == "legacy_target_reached"
                  else "checkpoint_probe")
    if checkpoint is None:
        return UNKNOWN, "no_checkpoint_probe"
    return tri(checkpoint), source


#: 覆盖读数端口：任一存在才算“真的有覆盖指标”
COVERAGE_PORTS = ("covered", "uncovered", "planned", "pcs", "mapped_locations")


def _fill_coverage(facts: _Facts, view: Mapping) -> None:
    coverage = dict(view.get("coverage") or {})
    status = str(coverage.get("status") or "")
    # 只有“状态可用 + 真的带了读数”才算有指标：光有 status=complete 什么都证明不了
    has_metric = any(port in coverage for port in COVERAGE_PORTS)
    usable = status in ("complete", "partial") and has_metric
    facts.put("coverage", "status", status)
    facts.put("coverage", "metric_kind", "call_site" if usable else None)
    baseline = view.get("baseline_id") or coverage.get("baseline_id")
    facts.put("coverage", "baseline_id", baseline)
    for port in COVERAGE_PORTS:
        if port in ("covered", "uncovered", "planned"):
            facts.put("coverage", port, coverage.get(port) if usable else None)
    # 新增量必须有基线才能算：没有基线不是 0
    facts.put("coverage", "delta",
              coverage.get("delta") if (baseline and usable) else None)
    facts.put("coverage", "sampling", coverage.get("sampling"))
    if "truncated" in coverage:
        facts.put("coverage", "truncated", tri(coverage.get("truncated")))
    elif usable and status == "complete":
        facts.put("coverage", "truncated", FALSE)      # complete 且读数为真
    else:
        facts.put("coverage", "truncated", None)
    facts.put("coverage", "error", coverage.get("error"))
    facts.put("coverage", "evidence_sha256", view.get("evidence_sha256"))
    metric = facts.groups["coverage"]["metric_kind"]
    covered = facts.groups["coverage"]["covered"]
    truncated = facts.groups["coverage"]["truncated"]
    baseline_known = facts.groups["coverage"]["baseline_id"]
    if metric == UNKNOWN or baseline_known == UNKNOWN or covered == UNKNOWN:
        comparable = UNKNOWN
    elif truncated == TRUE:
        comparable = FALSE
    else:
        comparable = TRUE
    facts.put("coverage", "comparable", comparable)


def _fill_fault(facts: _Facts, view: Mapping) -> None:
    present = dict(view.get("present") or {})
    flags = dict(view.get("flags") or {})
    if not present.get("finish"):
        for path in ("outcome", "setup_error", "timeout", "cancelled",
                     "budget_stopped", "sanitizer_type", "candidates",
                     "candidate_signature", "log_ref", "error"):
            facts.put("fault", path, None)
        return
    facts.put("fault", "outcome", view.get("outcome"))
    fuzz = dict(view.get("fuzz") or {})
    setup_error = view.get("setup_error") or fuzz.get("setup_error")
    if flags.get("setup_error_observed"):
        facts.put("fault", "setup_error", tri(bool(setup_error)))
    else:
        facts.put("fault", "setup_error", None)
    facts.raw("fault", "setup_error_detail", str(setup_error or ""))
    stopped = str(fuzz.get("stopped") or "")
    if flags.get("stopped_observed") and stopped:
        facts.put("fault", "timeout", tri(stopped == "deadline"))
        facts.put("fault", "cancelled", tri(stopped == "cancelled"))
        facts.put("fault", "budget_stopped",
                  tri(stopped in ("deadline", "execs")))
    else:
        for path in ("timeout", "cancelled", "budget_stopped"):
            facts.put("fault", path, None)
    facts.put("fault", "sanitizer_type",
              view.get("crash_type") or view.get("sanitizer"))
    candidates = view.get("candidates")
    facts.put("fault", "candidates",
              candidates if isinstance(candidates, int) else None)
    facts.put("fault", "candidate_signature", view.get("stack_hashes"))
    facts.put("fault", "log_ref", view.get("evidence_sha256"))
    if flags.get("error_observed"):
        facts.put("fault", "error", tri(bool(view.get("error"))))
    else:
        facts.put("fault", "error", None)
    if view.get("error"):
        facts.raw("fault", "error_detail", str(view.get("error")))


def _fill_budget(facts: _Facts, task: Mapping, view: Mapping, *,
                 tools_allowed: Iterable[str] | None,
                 denials: Iterable[str] | None) -> None:
    facts.put("budget", "limits", dict(task.get("budget") or {}))
    live = dict(view.get("budget") or {})
    remaining = dict(live.get("remaining") or {})
    used = dict(live.get("used") or {})
    for name, key in (("seconds", "remaining_seconds"),
                      ("execs", "remaining_execs"),
                      ("tokens", "remaining_tokens"),
                      ("turns", "remaining_turns")):
        facts.put("budget", key, remaining.get(name) if remaining else None)
    # 金额：没有价格表就没有读数（§11：不谎称成本受控）
    facts.put("budget", "remaining_usd", None)
    for name, key in (("seconds", "used_seconds"), ("execs", "used_execs"),
                      ("tokens", "used_tokens"), ("turns", "used_turns")):
        facts.put("budget", key, used.get(name) if used else None)
    facts.raw("budget", "violations", list(live.get("violations") or []))
    facts.put("budget", "tools_allowed",
              list(tools_allowed) if tools_allowed is not None else None)
    facts.raw("budget", "denials",
              list(denials) if denials is not None else UNKNOWN)


def _index_doc(index: Any) -> dict:
    if index is None:
        return {}
    if isinstance(index, Mapping):
        return dict(index)
    if hasattr(index, "to_dict"):
        try:
            return dict(index.to_dict())
        except Exception:               # noqa: BLE001 - 索引坏了按未知处理
            return {}
    return {}


__all__ = ["SCHEMA", "SCHEMA_VERSION", "UNKNOWN", "TRUE", "FALSE", "TRI",
           "FACT_GROUPS", "FACT_SOURCES", "OBSERVED_GROUPS", "OBSERVED_FIELDS",
           "GROUP_SOURCE",
           "CROSS_EXECUTION", "SnapshotError", "Cursor",
           "TrustedExecutionSnapshot", "tri", "is_unknown", "now"]
