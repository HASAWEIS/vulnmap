"""V3-008：ResearchSession —— 慢循环的决策侧（Context / Seed / Diagnose 三角色）。

口径（《V3 完整升级方案》§4「双循环与状态模型」、§7「种子与语料」、§8）：

- **输入是可信快照，不是聊天记录**：`ContextRole.observe()` 只读
  `TrustedExecutionSnapshot`（三值语义），把“目标是否真的被跑到、覆盖是否可比、
  候选是不是执行反馈里真的出现”归一成 `Observation`；缺的字段保持 `unknown`。
- **目标语义三段分开**（`docs/V3-TARGET-SEMANTICS.md`）：`program_started` /
  `input_processed` / `checkpoint_reached` 各自三值、各进 `facts_hash`；
  诊断据此区分“没启动”“输入没处理”“处理了但没命中”“不知道”，
  而不是把它们压成一句 `target_reached`。
- **默认确定性**：`DiagnoseRole` 用固定优先级规则给出诊断码，`SeedRole` 用
  “attempt 0 raw → attempt 1 magic → attempt 2 framed”的可解释序列改变种子策略；
  同样的输入永远得到同样的计划（没有随机数、没有隐式状态漂移）。
- **LLM 可选且只建议**：注入的 `advisor(observation, diagnosis)` 返回值逐条校验
  （工具已注册、参数过 schema、模式允许、不含裁决字段），最多作为附加建议；
  校验失败/抛异常只记 `advisor_errors`，不影响确定性计划，也拿不到身份与写权限。
- **模型不能写裁决**：本模块只产出 `ProposedAction`（工具名+参数）与
  `RevisionPlan`（待 stage 的文件内容）；身份由控制器的 `Binding` 注入，
  `verified/confirmed` 出现在建议里一律拒绝。
- **配置效果只报观测**（`docs/V3-W2-CONFIG.md` §5.2）：`Observation.config`
  只放 `planned/loaded/effective/status/source`，取值全部来自快照；
  `not_effective` 是**观测到的**“没生效”（可以停流程），`unknown` 只是
  “没观测到”（只能报 `config_unverified`，不能冒充 `false`，也不能顶替
  `program_started/input_processed/checkpoint_reached` 的真观测）。
  `ConfigRole` 是配置模式下的确定性变更序列（不读盘、不执行）。

本模块不执行工具、不写盘、不调外部服务。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .contracts import (ActionRejected, ActionRequest, Binding, Registry,
                        SessionState, digest_of)
from .policy import prune_verdict_fields
from .snapshot import TrustedExecutionSnapshot, UNKNOWN

SCHEMA = "vulnmap.adaptive.research_session.v1"
SCHEMA_VERSION = 1

#: 诊断码（固定词表；控制器/测试/文档都用同一套）
DIAGNOSIS_CODES = (
    "no_execution",        # 还没有任何执行事实
    "program_not_started",  # program_started=false：目标没起来/启动失败
    "input_not_processed",  # input_processed=false：输入没被目标处理
    "target_unreached",    # checkpoint_reached=false：起来了、也处理了，但检查点没命中
    "coverage_unknown",    # 真跑过、无终止态、目标态未知（没有可信覆盖指标）
    "low_coverage",        # 有覆盖但无可比增益
    "progress",            # 同一 build 下覆盖/输入有增益
    "candidate_observed",  # 执行反馈里出现了候选（单端证据，不是漏洞结论）
    "execution_error",     # 执行报错/超时（不是 no_repro）
    "config_not_effective",  # config.status=not_effective：执行器加载的配置≠计划配置
    "config_unverified",   # config.status=unknown：改了配置，但没有“实际加载”的回报
    "no_signal",           # 事实不足且没有新信息
)

#: 配置面（`docs/V3-W2-CONFIG.md` §1/§2）：唯一可写的配置路径与 schema。
#: 常量只在 `adaptive.workspace` 定义一处，这里引用而不是另抄一份。
from .workspace import (CONFIG_ACTIVE_SCHEMA, CONFIG_RELPATH)  # noqa: E402

#: 配置效果的三值状态（与 `ConfigEffectRecord.status` 同词表）
CONFIG_STATUSES = ("effective", "not_effective", "unknown")

#: 种子策略的确定性序列（attempt 0/1/2 …）
SEED_FORMATS = ("raw", "magic", "framed")

#: 默认生成器编辑只改“已存在的种子参数文件”，不凭空造文件
SEED_PARAM_CANDIDATES = ("seed_params.json", "harness/seed_params.json",
                         "configs/seed.json")

#: 建议动作的用途标签（审计用，不参与权限）
PURPOSES = ("seed", "materialize", "variant", "execute", "compare", "close",
            "advisor")


def _unknown(value: Any) -> str:
    return UNKNOWN if value is None or value == UNKNOWN else str(value)


def _tri_bool(value: Any) -> str:
    """布尔事实保持三值：False 不能写成字符串 "False" 被当成真值。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None or value == UNKNOWN:
        return UNKNOWN
    text = str(value).strip().lower()
    return text if text in ("true", "false") else UNKNOWN


@dataclass(frozen=True)
class ProposedAction:
    """一条待授权的动作建议：工具名 + 参数 + 用途（身份稍后由控制器注入）。"""

    action: str
    params: Mapping = field(default_factory=dict)
    purpose: str = ""
    ref: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", dict(self.params or {}))
        object.__setattr__(self, "purpose", str(self.purpose or ""))
        object.__setattr__(self, "ref", str(self.ref or ""))

    def to_dict(self) -> dict:
        return {"action": self.action, "params": dict(self.params),
                "purpose": self.purpose, "ref": self.ref}


@dataclass(frozen=True)
class RevisionPlan:
    """一次提议的 harness/生成器副本修改（只描述文件，不执行、不登记）。"""

    files: Mapping = field(default_factory=dict)
    reason: str = ""
    hypothesis_id: str = ""
    tool: str = "generator_editor"
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        files = {str(path): (data.encode("utf-8") if isinstance(data, str)
                             else bytes(data))
                 for path, data in dict(self.files or {}).items()}
        object.__setattr__(self, "files", files)
        object.__setattr__(self, "reason", str(self.reason or ""))
        object.__setattr__(self, "hypothesis_id",
                           str(self.hypothesis_id or ""))
        object.__setattr__(self, "tool", str(self.tool or "generator_editor"))
        object.__setattr__(self, "evidence_refs",
                           tuple(str(r) for r in (self.evidence_refs or ())))

    @property
    def empty(self) -> bool:
        return not self.files

    def to_dict(self) -> dict:
        from .revision import sha256_bytes
        return {
            "files": [{"path": path, "sha256": sha256_bytes(data),
                       "size": len(data)} for path, data in self.files.items()],
            "reason": self.reason, "hypothesis_id": self.hypothesis_id,
            "tool": self.tool, "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class Observation:
    """快照的动作侧视图：只放诊断需要的事实，不含任何裁决。"""

    task_id: str
    round_no: int
    facts_hash: str
    program_started: str = UNKNOWN
    input_processed: str = UNKNOWN
    checkpoint_reached: str = UNKNOWN
    target_reached: str = UNKNOWN
    coverage: Mapping = field(default_factory=dict)
    candidates: Any = UNKNOWN
    fault: Mapping = field(default_factory=dict)
    input_facts: Mapping = field(default_factory=dict)
    #: 配置效果（W2）：planned/loaded/effective/status/source 只来自快照
    config: Mapping = field(default_factory=dict)
    budget: Mapping = field(default_factory=dict)
    trials: int = 0
    unknowns: tuple[str, ...] = ()
    revision: Mapping = field(default_factory=dict)
    workspace: Mapping = field(default_factory=dict)
    hypothesis_id: str = ""
    site_id: str = ""
    snapshot_status: str = UNKNOWN
    execution_id: str = ""
    collected_at: str = ""

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id, "round": int(self.round_no),
            "facts_hash": self.facts_hash,
            "program_started": self.program_started,
            "input_processed": self.input_processed,
            "checkpoint_reached": self.checkpoint_reached,
            "target_reached": self.target_reached,
            "coverage": dict(self.coverage), "candidates": self.candidates,
            "fault": dict(self.fault), "input": dict(self.input_facts),
            "config": dict(self.config),
            "budget": dict(self.budget), "trials": int(self.trials),
            "unknowns": list(self.unknowns),
            "revision": dict(self.revision), "workspace": dict(self.workspace),
            "hypothesis_id": self.hypothesis_id, "site_id": self.site_id,
            "snapshot_status": self.snapshot_status,
            "execution_id": self.execution_id,
            "collected_at": self.collected_at,
        }


@dataclass(frozen=True)
class Diagnosis:
    """一次诊断：固定码 + 可复核的理由 + 事实指纹（幂等）。"""

    code: str
    severity: str = "info"
    reasons: tuple[str, ...] = ()
    facts_hash: str = ""
    hypothesis_id: str = ""
    candidates: int = 0
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.code not in DIAGNOSIS_CODES:
            raise ValueError(f"unknown diagnosis: {self.code!r}")
        object.__setattr__(self, "reasons",
                           tuple(str(r) for r in (self.reasons or ())))
        object.__setattr__(self, "candidates", int(self.candidates or 0))
        object.__setattr__(self, "evidence_refs",
                           tuple(str(r) for r in (self.evidence_refs or ())))

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity,
                "reasons": list(self.reasons), "facts_hash": self.facts_hash,
                "hypothesis_id": self.hypothesis_id,
                "candidates": int(self.candidates),
                "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class ResearchPlan:
    """一轮的动作建议：要改哪些副本文件 + 要调哪些工具。"""

    actions: tuple[ProposedAction, ...] = ()
    revision: RevisionPlan | None = None
    requests: tuple[ActionRequest, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", tuple(self.actions or ()))
        object.__setattr__(self, "requests", tuple(self.requests or ()))
        object.__setattr__(self, "note", str(self.note or ""))

    @property
    def empty(self) -> bool:
        return not self.actions and self.revision is None

    def to_dict(self) -> dict:
        return {
            "actions": [action.to_dict() for action in self.actions],
            "revision": self.revision.to_dict() if self.revision else None,
            "requests": [request.to_dict() for request in self.requests],
            "note": self.note,
        }


# ====================================================================== Context
class ContextRole:
    """把可信快照读成 Observation：只读、三值、无副作用。"""

    def __init__(self, *, store: Any = None) -> None:
        self.store = store

    def observe(self, snapshot: TrustedExecutionSnapshot, *,
                workspace: Any = None, revision: Any = None,
                session_state: SessionState | None = None,
                round_no: int = 0) -> Observation:
        if not isinstance(snapshot, TrustedExecutionSnapshot):
            raise TypeError("observe() 需要 TrustedExecutionSnapshot")
        task_id = snapshot.task_id
        coverage = {
            "status": _unknown(snapshot.get("coverage.status")),
            "covered": snapshot.get("coverage.covered"),
            "uncovered": snapshot.get("coverage.uncovered"),
            "planned": snapshot.get("coverage.planned"),
            "delta": snapshot.get("coverage.delta"),
            "comparable": _unknown(snapshot.get("coverage.comparable")),
            "metric_kind": _unknown(snapshot.get("coverage.metric_kind")),
            "baseline_id": _unknown(snapshot.get("coverage.baseline_id")),
        }
        fault = {
            "outcome": _unknown(snapshot.get("fault.outcome")),
            "setup_error": _unknown(snapshot.get("fault.setup_error")),
            "timeout": _tri_bool(snapshot.get("fault.timeout")),
            "error": _unknown(snapshot.get("fault.error")),
            "cancelled": _tri_bool(snapshot.get("fault.cancelled")),
            "budget_stopped": _tri_bool(snapshot.get("fault.budget_stopped")),
        }
        # 目标语义三段：各自独立三值，别用 input_consumed（语料喂进执行器）
        # 冒充 input_processed（目标真处理了输入）
        program_started = _unknown(snapshot.get("input.program_started"))
        input_processed = _unknown(snapshot.get("input.input_processed"))
        checkpoint_reached = _unknown(snapshot.get("input.checkpoint_reached"))
        input_facts = {
            "format": _unknown(snapshot.get("input.format")),
            "seeds": snapshot.get("input.seeds"),
            "dictionary_tokens": snapshot.get("input.dictionary_tokens"),
            "input_consumed": _unknown(snapshot.get("input.input_consumed")),
            "program_started": program_started,
            "input_processed": input_processed,
            "checkpoint_reached": checkpoint_reached,
            "corpus_hash": _unknown(snapshot.get("input.corpus_hash")),
            "corpus_comparable": _unknown(
                snapshot.get("input.corpus_comparable")),
        }
        # 配置效果：planned 只来自 revision 侧、loaded 只来自执行器回报；
        # status 只是 effective/not_effective/unknown 的规范化拼写，不做推断。
        config = self._config_facts(snapshot)
        budget = {}
        for key in ("remaining_seconds", "remaining_execs", "remaining_turns",
                    "used_seconds", "used_turns"):
            budget[key] = snapshot.get(f"budget.{key}")
        budget["violations"] = snapshot.get("budget.violations")
        candidates = snapshot.get("fault.candidates")
        if candidates != UNKNOWN and candidates is not None:
            try:
                candidates = int(candidates)
            except (TypeError, ValueError):
                candidates = UNKNOWN
        else:
            candidates = UNKNOWN
        revision_doc: dict = {}
        if revision is not None:
            revision_doc["current"] = getattr(revision, "revision_id", "")
            revision_doc["manifest_sha256"] = getattr(
                revision, "manifest_sha256", "")
        if workspace is not None:
            store = getattr(workspace, "revisions", None)
            current = workspace.current_revision()
            revision_doc.setdefault("current",
                                    current.revision_id if current else "")
            if store is not None and revision_doc["current"]:
                build = store.latest_build(revision_doc["current"])
                smoke = store.latest_smoke(revision_doc["current"])
                revision_doc["build"] = build.status if build else UNKNOWN
                revision_doc["build_id"] = build.build_id if build else UNKNOWN
                revision_doc["smoke"] = smoke.status if smoke else UNKNOWN
                revision_doc["smoke_kind"] = smoke.kind if smoke else ""
                revision_doc["origin_ok"] = bool(
                    workspace.origin_integrity().get("ok"))
                revision_doc["files"] = list(
                    current.files if current is not None else ())
        hypothesis_id, site_id = self._hypothesis(task_id)
        workspace_doc = {}
        if workspace is not None:
            workspace_doc = {
                "origin_ok": bool(workspace.origin_integrity().get("ok")),
                "current_revision": revision_doc.get("current", ""),
                "current_files": list(revision_doc.get("files") or ()),
            }
        target_reached = _unknown(snapshot.get("input.target_reached"))
        facts = self._facts_hash(
            program_started=program_started,
            input_processed=input_processed,
            checkpoint_reached=checkpoint_reached,
            target_reached=target_reached,
            coverage=coverage, candidates=candidates, fault=fault,
            input_consumed=input_facts["input_consumed"],
            config=config)
        return Observation(
            task_id=task_id, round_no=int(round_no), facts_hash=facts,
            program_started=program_started,
            input_processed=input_processed,
            checkpoint_reached=checkpoint_reached,
            target_reached=target_reached,
            coverage=coverage, candidates=candidates, fault=fault,
            input_facts=input_facts, config=config, budget=budget,
            trials=len(session_state.trials) if session_state else 0,
            unknowns=snapshot.unknown_paths(), revision=revision_doc,
            workspace=workspace_doc, hypothesis_id=hypothesis_id,
            site_id=site_id, snapshot_status=snapshot.status,
            execution_id=snapshot.execution_id,
            collected_at=snapshot.collected_at)

    @staticmethod
    def _config_facts(snapshot: TrustedExecutionSnapshot) -> dict:
        """把快照的 config 组读成配置效果视图（缺失一律 unknown）。

        `effective` 与 `status` 是同一件事的两种拼写：
        `true`↔`effective`、`false`↔`not_effective`、`unknown`↔`unknown`。
        这里**不**做任何推断：`loaded` 缺就是 unknown，绝不回填 `planned`。
        """
        planned = _unknown(snapshot.get("config.planned_config_sha256"))
        loaded = _unknown(snapshot.get("config.loaded_config_sha256"))
        effective = _tri_bool(snapshot.get("config.config_effective"))
        status = _unknown(snapshot.get("config.config_status"))
        if status == UNKNOWN:
            # 快照只登记四个字段（文档 §5.1）；status 由 effective 规范拼写回来
            status = ("effective" if effective == "true" else
                      "not_effective" if effective == "false" else UNKNOWN)
        return {
            "planned": planned,
            "loaded": loaded,
            "effective": effective,
            "status": status,
            "source": _unknown(snapshot.get("config.config_source")),
        }

    def _hypothesis(self, task_id: str) -> tuple[str, str]:
        if self.store is None or not task_id:
            return "", ""
        try:
            items = self.store.list_hypotheses(task_id)
        except Exception:                   # noqa: BLE001 - 读不到就当没有
            return "", ""
        for item in items or ():
            if str(item.get("id") or ""):
                return str(item.get("id")), str(item.get("site_id") or "")
        return "", ""

    @staticmethod
    def _facts_hash(*, program_started: str, input_processed: str,
                    checkpoint_reached: str, target_reached: str,
                    coverage: Mapping, candidates: Any, fault: Mapping,
                    input_consumed: str, config: Mapping | None = None) -> str:
        """只对“进展事实”取指纹：时间、轮数、execution id 变化不算进展。

        三段目标语义都在指纹里：`program_started` 翻成 true、`input_processed`
        从 unknown 变 true、`checkpoint_reached` 命中，是三种不同的进展。
        配置身份也在指纹里（`config_status` + `planned_config_sha256`）：
        换配置就是新事实——但仅仅只是新事实，**不是**“有进展”。
        """
        config = dict(config or {})
        body = {
            "program_started": program_started,
            "input_processed": input_processed,
            "checkpoint_reached": checkpoint_reached,
            "target_reached": target_reached,
            "coverage": {key: coverage.get(key) for key in
                         ("status", "covered", "uncovered", "delta",
                          "comparable", "metric_kind", "baseline_id")},
            "candidates": candidates,
            "fault": {key: fault.get(key) for key in
                      ("outcome", "setup_error", "timeout", "error")},
            "input_consumed": input_consumed,
            "config_status": config.get("status", UNKNOWN),
            "planned_config_sha256": config.get("planned", UNKNOWN),
        }
        return digest_of(body)[:16]


# ====================================================================== Diagnose
class DiagnoseRole:
    """固定优先级诊断：先判“这一轮的事实能不能算数”，再判“跑没跑起来/跑没跑完”，
    最后才判“有没有候选/覆盖增益”。

    完整优先级（一条链，位置即优先级；重叠状态只产**一个**码，见
    `docs/RULE-DIAGNOSIS-PRIORITY.md` §1）：

    1. `config_not_effective`——执行器加载的不是计划配置，**输入被污染**，
       连候选也不能当数（`docs/V3-W2-CONFIG.md` §5.2 的既有口径）。
    2. `candidate_observed`——候选是**已经发生的正证据**：执行被取消/报错/
       预算中止**之前**就出了候选时，终止态不能把它抹掉
       （`docs/AB-ERROR-REVIEW.md` §5.8 R2）。
    3. 终止态闸门（“跑没跑完”），内部再排序：
       `cancelled` > `budget_stopped` > `error` > `timeout`；四者都落到同一个
       码 `execution_error`，只在 `reasons` 上留是哪个旗标赢的
       （`cancelled` / `budget_stopped` / `error:true` / `timeout`）。
       语义：跑被截断，**基于“没有”的结论**（没有候选、没有覆盖）全部失效，
       但被截断之前已经看见的东西仍然算数（所以候选排在它前面）。
    4. 目标语义三段：`program_not_started` → `input_not_processed` →
       `target_unreached` → `progress`/`low_coverage`。
    5. `config_unverified`：改了配置但没有“实际加载”的回报；排在目标三态
       **之后**，没观测到的配置效果不许顶替真观测。
    6. 零执行：`no_execution`（`trials == 0` **且**没有“跑过”的正证据；
       不再要求 `snapshot_status` 也是 `unknown`——快照采到了但一次没跑，
       仍然是零执行。`program_started=="true"` 时不能报它：报告路径根本没有
       `SessionState`、`trials` 恒 0，那是“没计数”不是“没执行”）。
    7. 兜底：`coverage_unknown`；改完后它的成立前提自动收紧为
       “`trials > 0` ∧ 无终止态 ∧ 目标态未知”。

    **为什么零执行排在目标三态之后**：`trials` 只是试验计数，正证据
    （`checkpoint_reached=true`）比“计数为零”更硬；两者同时出现说明快照自相
    矛盾，此时按“真观测优先”处理，不自造第二个结论。
    """

    #: 终止态旗标的重叠判定顺序（第一个命中的赢；不合并成两条诊断）
    TERMINAL_FAULT_ORDER = ("cancelled", "budget_stopped", "error", "timeout")

    #: 旗标 → `reasons` 里的可复核理由（保持既有拼写，不换词表）
    TERMINAL_REASONS = {"cancelled": "cancelled",
                        "budget_stopped": "budget_stopped",
                        "error": "error:true",
                        "timeout": "timeout"}

    def diagnose(self, observation: Observation, *,
                 evidence_refs: Iterable[str] = ()) -> Diagnosis:
        refs = tuple(str(r) for r in evidence_refs or ())
        base = {"facts_hash": observation.facts_hash,
                "hypothesis_id": observation.hypothesis_id,
                "evidence_refs": refs}
        fault = dict(observation.fault or {})
        # 1) 输入被污染：观测到的 false 让本轮所有结论都算不了数
        config = dict(observation.config or {})
        config_status = str(config.get("status") or UNKNOWN)
        if config_status == "not_effective":
            return Diagnosis(code="config_not_effective", severity="blocked",
                             reasons=(f"loaded!={config.get('planned')}",),
                             **base)
        # 2) 已发生的正证据：终止态不能把它抹掉
        candidates = observation.candidates
        if isinstance(candidates, int) and candidates > 0:
            return Diagnosis(code="candidate_observed", severity="info",
                             reasons=(f"candidates={candidates}",), **base,
                             candidates=candidates)
        # 3) 终止态闸门：cancelled > budget_stopped > error > timeout
        for flag in self.TERMINAL_FAULT_ORDER:
            if _tri_bool(fault.get(flag)) == "true":
                return Diagnosis(
                    code="execution_error", severity="blocked",
                    reasons=(self.TERMINAL_REASONS[flag],), **base)
        # ---- 目标语义三段（各自判断，不互相冒充） ----
        started = str(observation.program_started or UNKNOWN)
        if started == "false":
            return Diagnosis(code="program_not_started", severity="warn",
                             reasons=("program_started=false",), **base)
        processed = str(observation.input_processed or UNKNOWN)
        if processed == "false":
            return Diagnosis(code="input_not_processed", severity="warn",
                             reasons=("input_processed=false",), **base)
        target = str(observation.checkpoint_reached or UNKNOWN)
        if target == UNKNOWN:
            # 兼容路径：后端快照只写 target_reached（没有探针字段）时照读它，
            # 但 checkpoint_reached 一旦有值就以它为准（同一来源，不是两次推断）
            target = str(observation.target_reached or UNKNOWN)
        if target == "false":
            reason = ("setup_error" if str(fault.get("setup_error", UNKNOWN))
                      == "true" else "target_not_reached")
            return Diagnosis(code="target_unreached", severity="warn",
                             reasons=(reason,), **base)
        if target == "true":
            delta = observation.coverage.get("delta")
            if isinstance(delta, (int, float)) and not isinstance(delta, bool) \
                    and float(delta) > 0:
                return Diagnosis(code="progress", severity="info",
                                 reasons=(f"delta={delta}",), **base)
            return Diagnosis(code="low_coverage", severity="info",
                             reasons=("target_reached_without_measurable_gain",),
                             **base)
        # 改了配置，但没有任何“实际加载”的回报：只能报 unknown。
        # 放在目标三态之后——没观测到的配置效果不许顶替真观测。
        if config_status not in ("effective", "not_effective") \
                and str(config.get("planned") or UNKNOWN) not in ("", UNKNOWN):
            return Diagnosis(code="config_unverified", severity="warn",
                             reasons=("loaded_config_sha256_unreported",),
                             **base)
        # 零执行：一次试验都没记录，**而且**没有任何“程序真的跑过”的正证据。
        # 不再要求 `snapshot_status=="unknown"`——快照采到了但一次没跑，仍然是
        # 零执行；但 `program_started=="true"` 说明确实跑过（只是没有试验计数，
        # 报告路径根本没有 SessionState，`trials` 恒 0），此时只能报覆盖未知，
        # 不能倒过来说“没执行”（`docs/V3-TARGET-SEMANTICS.md` 的无观测手段组）。
        if observation.trials == 0 and started != "true":
            return Diagnosis(code="no_execution", severity="info",
                             reasons=("no_execution_facts",), **base)
        return Diagnosis(code="coverage_unknown", severity="warn",
                         reasons=("target_reached_unknown",), **base)


# ====================================================================== Seed
class SeedRole:
    """确定性的种子/生成器策略：按 attempt 前进，不随机、不越权写盘。"""

    def __init__(self, *, max_attempts: int = 3,
                 editor: Callable[[Observation, Diagnosis],
                                  RevisionPlan | None] | None = None) -> None:
        self.max_attempts = int(max_attempts)
        self.editor = editor

    def attempt_for(self, attempt: int) -> int:
        return max(0, min(int(attempt), self.max_attempts - 1))

    def format_for(self, attempt: int) -> str:
        return SEED_FORMATS[min(self.attempt_for(attempt),
                                len(SEED_FORMATS) - 1)]

    def constraints_for(self, attempt: int) -> dict:
        fmt = self.format_for(attempt)
        if fmt == "magic":
            return {"prefix": "MAGIC", "length": 8}
        if fmt == "framed":
            return {"frame": "len32be", "length": 16}
        return {}

    def dictionary_for(self, attempt: int) -> list[str]:
        fmt = self.format_for(attempt)
        if fmt == "magic":
            return ["MAGIC", "magic", "MAGIC0"]
        if fmt == "framed":
            return ["MAGIC", "FRAME", "len"]
        return ["A", "0", "raw"]

    def revision_plan(self, observation: Observation, diagnosis: Diagnosis, *,
                      attempt: int) -> RevisionPlan | None:
        """默认只更新“已存在的种子参数文件”；注入 editor 时以注入者为准。"""
        if diagnosis.code not in ("target_unreached", "coverage_unknown",
                                  "low_coverage", "program_not_started",
                                  "input_not_processed"):
            return None
        if self.attempt_for(attempt) == 0:
            return None                    # 第一次先按原配置执行，有反馈再改
        if self.editor is not None:
            return self.editor(observation, diagnosis)
        current = set(observation.workspace.get("current_files") or ())
        target = next((path for path in SEED_PARAM_CANDIDATES
                       if path in current), "")
        if not target:
            return None                    # 没有可改的参数文件就不假装改
        fmt = self.format_for(attempt)
        body = json.dumps({"format": fmt, "seed_count": 2,
                           "constraints": self.constraints_for(attempt)},
                          ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        return RevisionPlan(
            files={target: body},
            reason=(f"{diagnosis.code}: switch seed format to {fmt} "
                    f"(attempt {attempt})"),
            hypothesis_id=observation.hypothesis_id)


# ====================================================================== Config
def _catalog_ids(items: Any) -> tuple[str, ...]:
    """把样例/观测点目录归一成 id 序列（接受 str、`{"id": ...}`、带 `.id` 的对象）。"""
    out: list[str] = []
    for item in items or ():
        if isinstance(item, Mapping):
            ident = str(item.get("id") or "")
        else:
            ident = str(getattr(item, "id", item) or "")
        if ident and ident not in out:
            out.append(ident)
    return tuple(out)


class ConfigRole:
    """配置模式下的**确定性**变更序列：只产 `RevisionPlan`，不读盘、不执行。

    口径（`docs/V3-W2-CONFIG.md` §5.2）：白名单只允许“切换已有样例 + 启用已有
    观测点”，所以这里的变更永远是目录里**已经存在**的 id，产物永远是
    `RevisionPlan(files={"config/active.json": <规范化 JSON>},
    tool="config_editor")`。

    attempt 序列（与 `SeedRole` 同风格：可解释、可复算，没有随机数）：

    | attempt | 变更 |
    |---|---|
    | 0 | 不改（先按原配置跑出反馈） |
    | 1 | 启用目录里下一个未启用的观测点 |
    | ≥2 | 启用剩余观测点 + 切到目录里下一个样例 |

    目录是构造时注入的（`samples` / `observation_points`），当前选择由
    `current_provider()` 提供：本类**不读盘**，避免“提议”变成一次隐式 IO。
    """

    def __init__(self, *, samples: Any = (), observation_points: Any = (),
                 current_provider: Callable[[], Mapping] | None = None,
                 max_attempts: int = 3) -> None:
        self.samples = _catalog_ids(samples)
        self.observation_points = _catalog_ids(observation_points)
        self.current_provider = current_provider
        self.max_attempts = int(max_attempts)

    def attempt_for(self, attempt: int) -> int:
        return max(0, min(int(attempt), self.max_attempts - 1))

    def current(self) -> dict:
        """当前选择（provider 给什么就是什么；读不到就按空配置处理）。"""
        if self.current_provider is None:
            return {}
        try:
            doc = self.current_provider()
        except Exception:                   # noqa: BLE001 - 读不到就当没有选择
            return {}
        if not isinstance(doc, Mapping):
            return {}
        points = [str(item) for item in (doc.get("observation_points") or ())
                  if str(item)]
        return {"schema": CONFIG_ACTIVE_SCHEMA,
                "sample": str(doc.get("sample") or ""),
                "observation_points": points}

    def _next_sample(self, current: str) -> str:
        """目录顺序里的下一个样例（只有一个就保持不变）。"""
        if len(self.samples) <= 1:
            return current or (self.samples[0] if self.samples else "")
        if current in self.samples:
            index = (self.samples.index(current) + 1) % len(self.samples)
            return self.samples[index]
        return self.samples[0]

    def target_config(self, *, attempt: int) -> dict | None:
        """按 attempt 算出“这次的配置选择”；算不出变更就返回 None。"""
        step = self.attempt_for(attempt)
        if step == 0:
            return None                     # 第一次先按原配置执行，有反馈再改
        current = self.current()
        enabled = list(current.get("observation_points") or ())
        sample = str(current.get("sample") or "")
        if step == 1:
            extra = next((point for point in self.observation_points
                          if point not in enabled), "")
            if not extra:
                return None                 # 目录里没有可启用的观测点：不假装改
            enabled = enabled + [extra]
        else:
            # 剩余观测点全开（目录顺序，保持确定性），再切到下一个样例
            enabled = [point for point in self.observation_points]
            sample = self._next_sample(sample)
        doc = {"schema": CONFIG_ACTIVE_SCHEMA, "sample": sample,
               "observation_points": enabled}
        if doc == current:
            return None                     # 变更与当前完全相同：没有可主张的差异
        return doc

    def revision_plan(self, observation: Observation, diagnosis: Diagnosis, *,
                      attempt: int) -> RevisionPlan | None:
        doc = self.target_config(attempt=attempt)
        if doc is None:
            return None
        body = json.dumps(doc, ensure_ascii=False, indent=2,
                          sort_keys=True) + "\n"
        return RevisionPlan(
            files={CONFIG_RELPATH: body},
            reason=(f"{diagnosis.code}: config attempt {attempt} "
                    f"(sample={doc['sample']} "
                    f"points={doc['observation_points']})"),
            hypothesis_id=observation.hypothesis_id, tool="config_editor",
            evidence_refs=(diagnosis.facts_hash,) if diagnosis.facts_hash else ())


# ====================================================================== Session
class ResearchSession:
    """一个研究会话：观察 → 诊断 → 建议；执行与授权在控制器。"""

    def __init__(self, *, binding: Binding, registry: Registry,
                 mode: str = "explore", store: Any = None,
                 session_state: SessionState | None = None,
                 seed_role: SeedRole | None = None,
                 diagnose_role: DiagnoseRole | None = None,
                 context_role: ContextRole | None = None,
                 advisor: Callable[[Mapping, Mapping], Any] | None = None,
                 config_role: ConfigRole | None = None,
                 max_attempts: int = 3) -> None:
        self.binding = binding
        self.registry = registry
        self.mode = str(mode or "explore")
        self.store = store
        self.state = session_state or SessionState()
        self.seed_role = seed_role or SeedRole(max_attempts=max_attempts)
        self.diagnose_role = diagnose_role or DiagnoseRole()
        self.context_role = context_role or ContextRole(store=store)
        # 配置模式专用（§5.2）：为 None 时与第 1 周完全一致（generator 模式）
        self.config_role = config_role
        self.advisor = advisor
        self.max_attempts = int(max_attempts)
        self.round_no = 0
        self._actions: list[ProposedAction] = []
        self._history: list[dict] = []
        self.attempt = 0
        self.advisor_calls = 0
        self.advisor_errors: list[str] = []
        self.llm_suggestions = 0

    # ---- 轮次 ----
    def begin_round(self, round_no: int, binding: Binding | None = None) -> None:
        self.round_no = int(round_no)
        if binding is not None:
            self.binding = binding
        self._actions = []

    def observe(self, snapshot: TrustedExecutionSnapshot, *,
                workspace: Any = None, revision: Any = None) -> Observation:
        return self.context_role.observe(
            snapshot, workspace=workspace, revision=revision,
            session_state=self.state, round_no=self.round_no)

    def diagnose(self, observation: Observation, *,
                 evidence_refs: Iterable[str] = ()) -> Diagnosis:
        return self.diagnose_role.diagnose(observation,
                                           evidence_refs=evidence_refs)

    def config_plan(self, observation: Observation, diagnosis: Diagnosis, *,
                    attempt: int) -> RevisionPlan | None:
        """配置模式下的确定性变更（不读盘、不执行）；未注入 ConfigRole 时返回 None。"""
        if self.config_role is None:
            return None
        return self.config_role.revision_plan(observation, diagnosis,
                                              attempt=attempt)

    # ---- 提议 ----
    def propose(self, diagnosis: Diagnosis,
                observation: Observation) -> ResearchPlan:
        attempt = self.seed_role.attempt_for(self.attempt)
        actions: list[ProposedAction] = []
        revision: RevisionPlan | None = None
        note = ""
        miss = diagnosis.code in ("no_execution", "program_not_started",
                                  "input_not_processed", "target_unreached",
                                  "coverage_unknown", "low_coverage",
                                  "no_signal")
        if diagnosis.code in ("no_execution", "program_not_started",
                              "input_not_processed", "target_unreached",
                              "coverage_unknown", "low_coverage", "progress"):
            revision = self.seed_role.revision_plan(
                observation, diagnosis, attempt=attempt)
            if revision is None and self.config_role is not None:
                # 配置模式：种子侧没有可改的参数文件时，改配置（白名单内）
                revision = self.config_plan(observation, diagnosis,
                                            attempt=attempt)
            fmt = self.seed_role.format_for(attempt)
            actions.append(ProposedAction(
                action="propose_seed_spec",
                params={"hypothesis_id": observation.hypothesis_id,
                        "site_id": observation.site_id, "format": fmt,
                        "count": 2,
                        "constraints": self.seed_role.constraints_for(attempt)},
                purpose="seed"))
            actions.append(ProposedAction(
                action="materialize_seeds",
                params={"spec_id": {"$ref": "seed_spec.spec_id"},
                        "max_seeds": 2},
                purpose="materialize", ref="seed_spec"))
            if attempt > 0:
                actions.append(ProposedAction(
                    action="set_dictionary",
                    params={"tokens": self.seed_role.dictionary_for(attempt)},
                    purpose="variant", ref="dictionary"))
            actions.append(ProposedAction(
                action="run_epoch",
                params={"kind": "fuzz", "seconds": 0.2, "workers": 1,
                        "hypothesis_id": observation.hypothesis_id},
                purpose="execute", ref="trial"))
        elif diagnosis.code in ("candidate_observed",):
            note = "candidate observed; hand off to independent verification"
        elif diagnosis.code in ("execution_error",):
            note = "execution failed; do not infer a negative result"
        else:
            note = f"no action for diagnosis {diagnosis.code}"
        if miss:
            self.attempt = min(self.attempt + 1, self.max_attempts)
        plan = ResearchPlan(actions=tuple(actions), revision=revision,
                            note=note)
        plan = self.remint(plan, self.binding)
        return self._with_advisor(plan, observation, diagnosis)

    def remint(self, plan: ResearchPlan, binding: Binding) -> ResearchPlan:
        """构建/采纳换了 build 身份后，用新 binding 重新签发同一批动作。"""
        self.binding = binding
        requests: list[ActionRequest] = []
        for index, action in enumerate(plan.actions, start=1):
            params = dict(action.params)          # `$ref` 留给控制器按序解析
            requests.append(ActionRequest(
                action_id=self._action_id(index), action=action.action,
                binding=binding.to_dict(), params=params,
                hypothesis_id=str(params.get("hypothesis_id") or "")))
        self._actions = list(plan.actions)
        return ResearchPlan(actions=plan.actions, revision=plan.revision,
                            requests=tuple(requests), note=plan.note)

    def _action_id(self, index: int) -> str:
        return (f"s{int(self.binding.epoch):02d}r{int(self.round_no):02d}"
                f"-{int(index):02d}")

    # ---- LLM 顾问（只建议） ----
    def _with_advisor(self, plan: ResearchPlan, observation: Observation,
                      diagnosis: Diagnosis) -> ResearchPlan:
        if self.advisor is None:
            return plan
        self.advisor_calls += 1
        try:
            raw = self.advisor(observation.to_dict(), diagnosis.to_dict())
        except Exception as exc:                # noqa: BLE001 - 顾问失败不致命
            self.advisor_errors.append(f"{type(exc).__name__}: {exc}")
            return plan
        suggestions = raw.get("actions") if isinstance(raw, Mapping) else raw
        if not isinstance(suggestions, (list, tuple)):
            self.advisor_errors.append("advisor must return a list of actions")
            return plan
        extra: list[ProposedAction] = []
        for index, item in enumerate(suggestions):
            try:
                action = self._validate_suggestion(item)
            except (ActionRejected, ValueError, TypeError) as exc:
                self.advisor_errors.append(
                    f"suggestion[{index}]: {type(exc).__name__}: {exc}")
                continue
            extra.append(action)
            self.llm_suggestions += 1
            if len(extra) >= 1:                 # 每轮最多采纳一条“建议”
                break
        if not extra:
            return plan
        return ResearchPlan(actions=plan.actions + tuple(extra),
                            revision=plan.revision,
                            requests=plan.requests + tuple(
                                self._request_for(action, len(plan.actions) + i)
                                for i, action in enumerate(extra, start=1)),
                            note=plan.note or "advisor suggestion appended")

    def _validate_suggestion(self, item: Any) -> ProposedAction:
        if not isinstance(item, Mapping):
            raise ValueError("suggestion must be a mapping")
        action = str(item.get("action") or "")
        params = item.get("params") or {}
        if not isinstance(params, Mapping):
            raise ValueError("params must be a mapping")
        clean, stripped = prune_verdict_fields(params)
        if stripped:
            raise ValueError(f"verdict fields forbidden: {list(stripped)}")
        spec = self.registry.get(action)
        if self.mode not in spec.allowed_modes:
            raise ValueError(f"{action} not allowed in mode {self.mode}")
        spec.validate(clean)                    # 参数必须过同一份 schema
        return ProposedAction(action=action, params=clean, purpose="advisor")

    def _request_for(self, action: ProposedAction, index: int) -> ActionRequest:
        return ActionRequest(
            action_id=self._action_id(len(self._actions) + index),
            action=action.action, binding=self.binding.to_dict(),
            params=dict(action.params),
            hypothesis_id=str(action.params.get("hypothesis_id") or ""))

    # ---- 记录 ----
    def record(self, result: Mapping) -> dict:
        """把 ActionResult（或其 dict）记进会话历史；只读快照用途。"""
        doc = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        self._history.append(doc)
        return doc

    def history(self) -> tuple[dict, ...]:
        return tuple(self._history)


def _resolve_refs(params: Mapping, refs: Mapping) -> dict:
    """把 `{"$ref": "seed_spec.spec_id"}` 换成上一动作 payload 里的值。"""
    def resolve(value: Any) -> Any:
        if isinstance(value, Mapping) and set(value) == {"$ref"}:
            path = str(value["$ref"] or "").split(".")
            current: Any = refs
            for part in path:
                if not isinstance(current, Mapping) or part not in current:
                    return None
                current = current[part]
            return current
        if isinstance(value, Mapping):
            return {key: resolve(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [resolve(item) for item in value]
        return value
    return {key: resolve(value) for key, value in dict(params or {}).items()}


#: 控制器用它把动作 payload 汇总成 refs（`seed_spec` / `trial` / `dictionary`）
def collect_refs(result: Mapping, refs: dict) -> dict:
    doc = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    payload = dict(doc.get("payload") or {})
    for key in ("seed_spec", "trial", "dictionary"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            refs[key] = dict(value)
    return refs


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "DIAGNOSIS_CODES", "SEED_FORMATS",
    "SEED_PARAM_CANDIDATES", "PURPOSES", "CONFIG_RELPATH",
    "CONFIG_ACTIVE_SCHEMA", "CONFIG_STATUSES", "ProposedAction", "RevisionPlan",
    "Observation", "Diagnosis", "ResearchPlan", "ContextRole", "DiagnoseRole",
    "SeedRole", "ConfigRole", "ResearchSession", "collect_refs",
]
