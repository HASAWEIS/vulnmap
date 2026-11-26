"""V3-008：慢循环控制器 —— 一轮一个实验批次，失效必须被消费。

固定阶段（《V3 完整升级方案》§4）：

```
OBSERVE → DIAGNOSE → PROPOSE → AUTHORIZE → STAGE → BUILD/SMOKE
        → EXECUTE → COLLECT → CONFIG → COMPARE → ADOPT/REVERT/STOP
```

配置门（`docs/V3-W2-CONFIG.md` §5.3）：

- **planned 只来自 revision，loaded 只来自执行器回报**：COLLECT 之后算一次配置
  效果并落 `ConfigEffectRecord`（同时进 `RoundRecord.config_effect` 与时间线）；
- `not_effective`（观测到“加载了另一版”）→ `blocked/config_not_effective`，
  回退到父 revision；`unknown`（没有实际加载回报）→ `blocked/config_unverified`；
  两者**都不写** `adoptions.jsonl`、**都不产生** verification；
- 配置模式下 ADOPT 延后：`policy.engineering()` 说 adopt 时先挂起
  （`ADOPT=deferred`），等本轮 `CONFIG` 判 `effective` 才真正 `record_adoption()`；
- generator 模式（没有配置面）**不出现** CONFIG 行、不落配置账：行为与第 1 周一致。

口径：

- **观察只信快照**：OBSERVE 从 `TrustedExecutionSnapshot.collect()` 取事实；
  COLLECT 用本次 execution_id 再取一次。诊断、比较、停止都基于这两个观察。
- **相同事实/相同动作有限停止**：`facts_hash` 只对进展事实取指纹；
  同一事实出现 `max_same_facts` 次 → `repeated_facts`；某动作在相同事实下
  已执行过 → 跳过并计入 `repeated_actions`，整轮无可执行动作即停。
  换 action_id 重试不算进展（§11）。
- **授权在唯一入口**：动作仍走 `Registry.invoke()`（身份/权限/模式/预算/失效）；
  副本写入要求 L1（`workspace.stage(grant=...)`）；研究循环固定 `explore` 模式，
  不在本循环里切 `verify`。
- **失效要被消费**：每轮把 `Registry.consume_invalidations()` 与
  `RevisionStore.consume_invalidations()` 取出，逐项给出落实它的动作/事实；
  没落实的保持 `unhandled`，且跨 build 比较一律不可比。
- **工程采纳 ≠ 漏洞通过**：ADOPT 只写 `policy.engineering()` 的工程结论并落
  `adoptions.jsonl`；候选只触发 `policy.verification_request()`，**不写**
  `verified/confirmed`，也不调用 `verify`。
- **预算/取消**：每轮前检查预算端口与 `cancel` 钩子；取消优先于结果升级。

本模块不执行目标、不改 verify/benchmark、不写裁决。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .budget import BudgetLedger, LedgerBudget
from .contracts import (BUDGET_LIMIT_KEYS, ActionRejected, ActionResult,
                        ActionRequest, Binding, DeclaredBudget, NullBudget,
                        Registry, SessionState, ToolContext, digest_of,
                        now)
from .handoff import ProposalGate
from .policy import AdoptionPolicy, Decision, VerificationRequest
from .session import (Diagnosis, Observation, ResearchPlan, ResearchSession,
                      collect_refs)
from .snapshot import UNKNOWN, TrustedExecutionSnapshot
from .tools import build_registry, make_binding, make_context
from .workspace import WorkspaceError

SCHEMA = "vulnmap.adaptive.controller.v1"
SCHEMA_VERSION = 1

#: 阶段顺序（时间线按此校验；同一轮里 AUTHORIZE 可出现多次）
PHASES = ("OBSERVE", "DIAGNOSE", "PROPOSE", "AUTHORIZE", "STAGE", "BUILD",
          "SMOKE", "EXECUTE", "COLLECT", "CONFIG", "COMPARE", "ADOPT",
          "REVERT", "STOP")

#: 控制器终态
STATUSES = ("completed", "blocked", "cancelled", "budget", "failed")

#: 这些拒绝码说明“继续跑也没有意义”（身份伪造/无权限/模式错/未接通）
FATAL_REJECTIONS = frozenset({"forged_identity", "permission_denied",
                              "unsupported", "mode_not_allowed",
                              "cross_execution", "trusted_field_forbidden"})


@dataclass(frozen=True)
class PhaseRecord:
    """时间线的一行：第几轮、哪个阶段、结果与说明。"""

    round_no: int
    phase: str
    status: str = "ok"
    detail: str = ""

    def __post_init__(self) -> None:
        if self.phase not in PHASES:
            raise ValueError(f"unknown phase: {self.phase!r}")

    def to_dict(self) -> dict:
        return {"round": int(self.round_no), "phase": self.phase,
                "status": self.status, "detail": self.detail}


@dataclass
class RoundRecord:
    """一轮的完整结算（诊断、计划、动作、构建/冒烟、采纳与比较）。"""

    round_no: int
    facts_hash: str = ""
    diagnosis: Diagnosis | None = None
    plan: ResearchPlan | None = None
    actions: list[dict] = field(default_factory=list)
    revision: str = ""
    build: dict | None = None
    smoke: dict | None = None
    engineering: Decision | None = None
    adopted: bool = False
    reverted: str = ""
    #: 配置效果（W2）：planned/loaded/status/source/effect_id（只来自观测）
    config_effect: dict | None = None
    compare: dict | None = None
    invalidations: list[dict] = field(default_factory=list)
    #: V3 W3：隔离/授权未验收时的**建议清单**（只记录，不应用）
    advisories: list[dict] = field(default_factory=list)
    stop_reason: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "round": int(self.round_no), "facts_hash": self.facts_hash,
            "diagnosis": self.diagnosis.to_dict() if self.diagnosis else None,
            "plan": self.plan.to_dict() if self.plan else None,
            "actions": [dict(item) for item in self.actions],
            "revision": self.revision,
            "build": dict(self.build) if self.build else None,
            "smoke": dict(self.smoke) if self.smoke else None,
            "engineering": self.engineering.to_dict() if self.engineering else None,
            "adopted": bool(self.adopted), "reverted": self.reverted,
            "config_effect": dict(self.config_effect)
            if self.config_effect else None,
            "compare": dict(self.compare) if self.compare else None,
            "invalidations": [dict(item) for item in self.invalidations],
            "advisories": [dict(item) for item in self.advisories],
            "stop_reason": self.stop_reason, "note": self.note,
        }


@dataclass
class ControllerResult:
    """慢循环的最终结算；`verification.allowed` 不等于已验证。"""

    status: str = "completed"
    stop_reason: str = ""
    rounds: list[RoundRecord] = field(default_factory=list)
    timeline: list[PhaseRecord] = field(default_factory=list)
    revisions: list[str] = field(default_factory=list)
    verification: VerificationRequest | None = None
    invalidations: list[dict] = field(default_factory=list)
    final: Observation | None = None
    budget: dict = field(default_factory=dict)
    error: str = ""
    started_at: str = ""
    finished_at: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown controller status: {self.status!r}")

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "status": self.status, "stop_reason": self.stop_reason,
            "rounds": [record.to_dict() for record in self.rounds],
            "timeline": [phase.to_dict() for phase in self.timeline],
            "revisions": list(self.revisions),
            "verification": (self.verification.to_dict()
                             if self.verification else None),
            "invalidations": [dict(item) for item in self.invalidations],
            "final": self.final.to_dict() if self.final else None,
            "budget": dict(self.budget), "error": self.error,
            "started_at": self.started_at, "finished_at": self.finished_at,
        }


class ResearchController:
    """任务级慢循环：确定性驱动 ResearchSession，所有动作过 Registry。"""

    def __init__(self, *, task: Mapping, store: Any,
                 workspace: Any = None, registry: Registry | None = None,
                 index: Any = None, corpus: Any = None,
                 exec_runner: Callable | None = None,
                 session: ResearchSession | None = None,
                 policy: AdoptionPolicy | None = None,
                 budget: Any = None, extra_grant: Iterable[str] = (),
                 campaign: str = "", max_rounds: int = 6,
                 max_same_facts: int = 2, max_actions: int = 8,
                 cancel: Callable[[], bool] | None = None,
                 emit_events: bool = False,
                 proposal_gate: ProposalGate | None = None,
                 policy_version: str = "v3-p2b",
                 clock: Callable[[], float] = time.time) -> None:
        self.task = dict(task or {})
        self.store = store
        self.workspace = workspace
        self.registry = registry or build_registry()
        self.index = index
        self.corpus = corpus
        self.exec_runner = exec_runner
        self.policy = policy or AdoptionPolicy()
        self.policy_version = str(policy_version)
        self.campaign = str(campaign or self.task.get("benchmark") or "v3-p2b")
        self.max_rounds = int(max_rounds)
        self.max_same_facts = int(max_same_facts)
        self.max_actions = int(max_actions)
        self.cancel = cancel
        self.emit_events = bool(emit_events)
        #: V3 W3：隔离/授权验收闸。None = 旧行为（不启用）；给了闸就只在验收后应用
        self.proposal_gate = proposal_gate
        self.clock = clock
        self.state = SessionState()
        self._grant_extra = tuple(extra_grant)
        if budget is not None:
            self.budget = budget
        else:
            limits = {}
            for name, key in BUDGET_LIMIT_KEYS.items():
                value = (self.task.get("budget") or {}).get(key)
                if value is not None:
                    limits[name] = float(value)
            # 默认走**事务账本**（V3-010）：`DeclaredBudget` 是内存账本，两个
            # worker 会同时读到“还剩 1 个回合”，这里换成 run/task 两级、
            # BEGIN IMMEDIATE 预留的账本。历史事件的用量作为起点，不凭空回血。
            self.budget = self._ledger_budget(limits) or DeclaredBudget(
                limits=limits)
        self.session = session or ResearchSession(
            binding=self._binding(1), registry=self.registry, mode="explore",
            store=store, session_state=self.state,
            config_role=self._config_role())
        self.session.binding = self._binding(1)

    def _ledger_budget(self, limits: Mapping) -> LedgerBudget | None:
        """按任务库所在目录建预算账本；没有真库（纯离线替身）就返回 None。"""
        path = getattr(self.store, "path", None)
        if path is None:
            return None
        try:
            ledger = BudgetLedger(path, clock=self.clock)
            ids = ledger.ensure_chain(
                run=self.campaign or str(self.task.get("task_id") or "run"),
                task=str(self.task.get("task_id") or ""),
                limits_by_level={"task": dict(limits)})
            used = {}
            try:
                from ..budget import usage_from_events
                used = usage_from_events(
                    self.store.list_events(str(self.task.get("task_id") or "")))
            except Exception:              # noqa: BLE001 - 读不到历史用量就按 0 起账
                used = {}
            ledger.seed_usage(ids["task"],
                              {k: float(v) for k, v in used.items()
                               if k in limits and v is not None})
            return LedgerBudget(ledger, ids["task"])
        except Exception:                  # noqa: BLE001 - 账本不可用则退回内存口径
            return None

    # ------------------------------------------------------------------ 绑定
    def _revision(self):
        if self.workspace is None:
            return None
        return self.workspace.current_revision()

    def _binding(self, round_no: int, execution_id: str = "",
                 revision: Any = None) -> Binding:
        rev = revision if revision is not None else self._revision()
        build_id = ""
        harness = ""
        if rev is not None:
            harness = getattr(rev, "revision_id", "")
            record = None
            if self.workspace is not None:
                store = getattr(self.workspace, "revisions", None)
                if store is not None:
                    record = store.latest_build(harness)
            if record is not None and getattr(record, "ok", False):
                build_id = record.build_id
        return make_binding(
            self.task, campaign=self.campaign, epoch=int(round_no),
            execution_id=str(execution_id or ""), index=self.index,
            corpus=self.corpus, harness_revision=harness, build_id=build_id,
            policy_version=self.policy_version, registry=self.registry)

    def _context(self, binding: Binding) -> ToolContext:
        ctx = make_context(
            self.task, binding=binding, store=self.store, index=self.index,
            corpus=self.corpus, session=self.state, mode="explore",
            exec_runner=self.exec_runner, extra_grant=self._grant_extra,
            tools_allowed=self.registry.names(), registry=self.registry)
        if self.budget is not None:
            ctx.budget = self.budget
        return ctx

    # ------------------------------------------------------------------ 主循环
    def run(self) -> ControllerResult:
        result = ControllerResult(started_at=now())
        started = self.clock()
        seen_facts: dict[str, int] = {}
        seen_actions: set[tuple[str, str]] = set()
        previous: Observation | None = None
        last_execution = ""
        stop_reason = ""
        status = "completed"
        all_invalidations: list[dict] = []
        verification: VerificationRequest | None = None
        round_no = 1
        try:
            while round_no <= self.max_rounds:
                record = RoundRecord(round_no=round_no)
                result.rounds.append(record)
                # ---- 预算 / 取消（先于一切） ----
                budget_reason = self._budget_exhausted()
                if budget_reason:
                    stop_reason, status = "budget", "budget"
                    self._phase(result, round_no, "STOP", "budget", budget_reason)
                    break
                if self._cancelled():
                    stop_reason, status = "cancelled", "cancelled"
                    self._phase(result, round_no, "STOP", "cancelled", "cancel hook")
                    break

                binding = self._binding(round_no)
                self.session.begin_round(round_no, binding)
                ctx = self._context(binding)

                # ---- OBSERVE ----
                snapshot = self._collect(binding, last_execution)
                observation = self.session.observe(
                    snapshot, workspace=self.workspace,
                    revision=self._revision())
                record.facts_hash = observation.facts_hash
                self._phase(result, round_no, "OBSERVE", "ok",
                            f"snapshot={snapshot.status} "
                            f"facts={observation.facts_hash}")
                done = seen_facts.get(observation.facts_hash, 0)
                seen_facts[observation.facts_hash] = done + 1
                if done >= self.max_same_facts - 1:
                    stop_reason, status = "repeated_facts", "completed"
                    self._phase(result, round_no, "STOP", "repeated",
                                f"facts {observation.facts_hash} seen {done + 1}x")
                    break

                # ---- DIAGNOSE ----
                diagnosis = self.session.diagnose(
                    observation, evidence_refs=tuple(result_evidence(result)))
                record.diagnosis = diagnosis
                self._phase(result, round_no, "DIAGNOSE", "ok",
                            f"{diagnosis.code} ({diagnosis.severity})")
                if diagnosis.code == "candidate_observed":
                    verification = self.policy.verification_request(
                        diagnosis=diagnosis, candidates=diagnosis.candidates,
                        engineering=None, mode=self.session.mode,
                        evidence_refs=tuple(result_evidence(
                            result, candidates_only=True)))
                    result.verification = verification
                    stop_reason = "candidate_ready"
                    record.stop_reason = stop_reason
                    self._phase(result, round_no, "STOP", "ok",
                                f"candidate_ready allowed={verification.allowed}")
                    break
                if diagnosis.code in ("execution_error",):
                    stop_reason, status = "execution_error", "blocked"
                    self._phase(result, round_no, "STOP", "blocked",
                                "execution error is not a negative result")
                    break
                if diagnosis.code in ("config_not_effective",
                                      "config_unverified"):
                    # 观察阶段就看清了配置问题：不进入提议/执行，也不写采纳
                    stop_reason, status = diagnosis.code, "blocked"
                    record.stop_reason = stop_reason
                    self._phase(result, round_no, "STOP", "blocked",
                                f"{diagnosis.code}: config gate before propose")
                    break

                # ---- PROPOSE ----
                plan = self.session.propose(diagnosis, observation)
                record.plan = plan
                self._phase(result, round_no, "PROPOSE", "ok",
                            f"actions={[a.action for a in plan.actions]} "
                            f"revision={'yes' if plan.revision else 'no'}")

                # ---- 验收闸（V3 W3）：隔离/授权未验收 → 只给建议 ----
                # 位置在 PROPOSE 之后、AUTHORIZE 之前：未验收时不进入授权/执行/
                # 写盘，只把提议原样记进建议清单（不建 revision、不写采纳）。
                if self.proposal_gate is not None and (
                        plan.actions or plan.revision is not None):
                    proposal = {
                        "actions": [item.to_dict() for item in plan.actions],
                        "revision": (plan.revision.to_dict()
                                     if plan.revision is not None else None),
                    }
                    gate = self.proposal_gate.admit(
                        scope="engineering", action="propose",
                        params=proposal)
                    if gate.status != "apply":
                        record.advisories.append(self.proposal_gate.record(
                            round_no=round_no, action="propose",
                            params=proposal, decision=gate))
                        record.note = "advisory_only"
                        record.stop_reason = "advisory_only"
                        stop_reason, status = "advisory_only", "completed"
                        self._phase(result, round_no, "PROPOSE",
                                    "advisory", gate.note)
                        self._phase(result, round_no, "STOP", "advisory",
                                    "advisory_only: " + ",".join(
                                        gate.blockers))
                        break
                    self._phase(result, round_no, "AUTHORIZE", "accepted",
                                gate.note)

                # ---- AUTHORIZE（静态部分；带 $ref 的动作在执行前再校验） ----
                allowed, rejected = self._static_authorize(plan, ctx)
                for item in rejected:
                    self._phase(result, round_no, "AUTHORIZE", "rejected",
                                item)
                self._phase(result, round_no, "AUTHORIZE", "ok",
                            f"allowed={len(allowed)} rejected={len(rejected)}")
                if plan.actions and not allowed:
                    stop_reason, status = "policy_blocked", "blocked"
                    self._phase(result, round_no, "STOP", "blocked",
                                "no authorized action")
                    break

                # ---- STAGE / BUILD / SMOKE / ADOPT|REVERT ----
                current = self._revision()
                decision: Decision | None = None
                build = smoke = None
                #: 本轮真的 stage 出来的 revision（配置门回退时以它为基准）
                round_revision = None
                #: 配置模式下挂起的 ADOPT：等本轮 CONFIG 判 effective 才落地
                pending_adopt = None
                if plan.revision is not None:
                    try:
                        revision = self._stage(plan, ctx, round_no)
                    except Exception as exc:        # noqa: BLE001 - 副本不可用即停
                        # 配置模式下 stage() 就是白名单入口：非白名单路径以
                        # `stage_failed: <code>` 停住，不把拒绝读成“改成功了”。
                        code = _error_code(exc)
                        self._phase(result, round_no, "STAGE", "failed",
                                    (f"stage_failed: {code}" if code else
                                     f"{type(exc).__name__}: {exc}"))
                        stop_reason, status = "stage_failed", "blocked"
                        record.stop_reason = stop_reason
                        record.note = code or record.note
                        break
                    round_revision = revision
                    record.revision = revision.revision_id
                    result.revisions.append(revision.revision_id)
                    self._phase(result, round_no, "STAGE", "ok",
                                f"{revision.revision_id} "
                                f"files={list(revision.files)}")
                    # 构建/冒烟跑不起来（没有命令、目录不在、超时边界）也是事实：
                    # 落 stage_failed/harness_error 并停，不让控制器崩成一团异常，
                    # 也不把“装置没跑起来”读成目标行为。
                    try:
                        build = self.workspace.build(revision, grant=ctx.grant)
                    except WorkspaceError as exc:
                        self._phase(result, round_no, "BUILD", "failed",
                                    f"{type(exc).__name__}: {exc}")
                        record.invalidations.extend(self._consume_invalidations(
                            round_no, record, None, None, []))
                        stop_reason, status = "stage_failed", "blocked"
                        record.stop_reason = stop_reason
                        break
                    record.build = build.to_dict()
                    self._phase(result, round_no, "BUILD", build.status,
                                f"exit={build.exit_code} log={build.log_path}")
                    try:
                        smoke = self.workspace.smoke(revision, build=build,
                                                     grant=ctx.grant)
                    except WorkspaceError as exc:
                        self._phase(result, round_no, "SMOKE", "failed",
                                    f"{type(exc).__name__}: {exc}")
                        record.invalidations.extend(self._consume_invalidations(
                            round_no, record, build, None, []))
                        stop_reason, status = "harness_error", "blocked"
                        record.stop_reason = stop_reason
                        break
                    record.smoke = smoke.to_dict()
                    self._phase(result, round_no, "SMOKE", smoke.status,
                                f"exit={smoke.exit_code} kind={smoke.kind}")
                    decision = self.policy.engineering(
                        revision=revision, build=build, smoke=smoke,
                        origin=self.workspace.origin_integrity(),
                        compare=None, trial=None)
                    record.engineering = decision
                    if decision.adopt:
                        if self._config_mode() == "config":
                            # 配置模式：ADOPT 延后到 CONFIG 判定之后（§5.3）。
                            # 现在挂起，等 execute/COLLECT 拿到“实际加载版本”再定。
                            pending_adopt = revision
                            self._phase(result, round_no, "ADOPT", "deferred",
                                        "waiting_for_config_effect")
                        else:
                            record.adopted = True
                            self.workspace.revisions.record_adoption(
                                decision.to_dict())
                            self._phase(result, round_no, "ADOPT", "ok",
                                        "engineering scope only")
                        current = revision
                    else:
                        try:
                            reverted = self.workspace.revert(
                                to_revision=revision.parent_id,
                                reason="engineering_rejected:"
                                       + ",".join(decision.failed),
                                grant=ctx.grant)
                            record.reverted = reverted.revision_id
                            result.revisions.append(reverted.revision_id)
                            current = reverted
                            self._phase(result, round_no, "REVERT", "ok",
                                        f"{reverted.revision_id} "
                                        f"reverted_to={revision.revision_id}")
                        except Exception as exc:    # noqa: BLE001
                            self._phase(result, round_no, "REVERT", "failed",
                                        f"{type(exc).__name__}: {exc}")
                        record.invalidations.extend(
                            self._consume_invalidations(
                                round_no, record, build, smoke, [],
                                extra_handled={
                                    "coverage_baseline":
                                        f"revert:{reverted.revision_id}",
                                    "corpus_members":
                                        "deferred:revalidation_required",
                                }))
                        if smoke.harness_failed or build.status != "ok":
                            stop_reason = "harness_error"
                        else:
                            stop_reason = "engineering_rejected"
                        status = "blocked"
                        record.stop_reason = stop_reason
                        break
                    self._phase(result, round_no, "COMPARE", "skipped",
                                "no cross-build comparison at adoption")

                # ---- 采用后重绑：新 build 仍是新身份 ----
                final_binding = self._binding(round_no, revision=current)
                self.session.begin_round(round_no, final_binding)
                plan = self.session.remint(plan, final_binding)
                record.plan = plan
                ctx = self._context(final_binding)

                # ---- EXECUTE ----
                refs: dict = {}
                executed: list[ActionResult] = []
                skipped = 0
                stopped = ""
                for request in plan.requests:
                    try:
                        params = _resolve_refs(request.params, refs)
                    except ActionRejected as exc:
                        self._phase(result, round_no, "EXECUTE", "rejected",
                                    f"{request.action}: {exc.reason}")
                        stopped = str(exc.code)
                        break
                    fingerprint = (record.facts_hash, request.action,
                                   digest_of(params))
                    if fingerprint in seen_actions:
                        skipped += 1
                        record.actions.append({
                            "action_id": request.action_id,
                            "tool": request.action, "status": "skipped",
                            "reason": "same_facts_same_action",
                        })
                        self._phase(result, round_no, "EXECUTE", "skipped",
                                    f"{request.action}: 相同事实下已执行过")
                        continue
                    seen_actions.add(fingerprint)
                    concrete = ActionRequest(
                        action_id=request.action_id, action=request.action,
                        binding=ctx.binding.to_dict(), params=params,
                        hypothesis_id=request.hypothesis_id)
                    outcome = self.registry.invoke(concrete, ctx)
                    self.session.record(outcome)
                    collect_refs(outcome, refs)
                    executed.append(outcome)
                    record.actions.append({
                        "action_id": outcome.action_id, "tool": outcome.tool,
                        "status": outcome.status,
                        "before_sha256": outcome.before_sha256,
                        "after_sha256": outcome.after_sha256,
                        "invalidations": list(outcome.invalidations),
                        "evidence_refs": list(outcome.evidence_refs),
                        "candidates": _trial_candidates(outcome),
                        "error": dict(outcome.error) if outcome.error else None,
                    })
                    self._phase(result, round_no, "EXECUTE", outcome.status,
                                f"{outcome.tool} {outcome.action_id}")
                    if outcome.status == "rejected":
                        code = str((outcome.error or {}).get("code") or "")
                        if code in FATAL_REJECTIONS:
                            stopped = "policy_blocked"
                            break
                    if outcome.status == "failed":
                        stopped = "action_failed"
                        break
                    trial = (outcome.payload or {}).get("trial") or {}
                    if isinstance(trial, Mapping) and trial.get("execution_id"):
                        candidate_exec = str(trial["execution_id"])
                        if candidate_exec not in ("", "unknown"):
                            last_execution = candidate_exec
                record.invalidations.extend(
                    self._consume_invalidations(round_no, record, build, smoke,
                                                executed))
                if not stopped and plan.actions and skipped == len(plan.requests):
                    stopped = "repeated_actions"
                if stopped:
                    stop_reason, status = stopped, (
                        "blocked" if stopped == "policy_blocked" else "completed")
                    record.stop_reason = stop_reason
                    self._phase(result, round_no, "STOP", status, stopped)
                    break

                # ---- COLLECT ----
                snapshot2 = self._collect(ctx.binding, last_execution)
                observation2 = self.session.observe(
                    snapshot2, workspace=self.workspace,
                    revision=self._revision())
                self._phase(result, round_no, "COLLECT", "ok",
                            f"snapshot={snapshot2.status} "
                            f"exec={last_execution or 'unknown'}")

                # ---- CONFIG（配置效果：planned 来自 revision，loaded 来自回报） ----
                effect = self._record_config_effect(
                    round_no, observation2, last_execution, record)
                if effect is not None:
                    config_status = str(effect.get("status") or "unknown")
                    self._phase(
                        result, round_no, "CONFIG", config_status,
                        f"planned={effect.get('planned_sha256') or '-'} "
                        f"loaded={effect.get('loaded_sha256') or '-'} "
                        f"source={effect.get('source') or '-'}")
                    if config_status == "not_effective":
                        # 观测到的 false：执行器加载的**不是**计划那一版配置
                        stop_reason, status = "config_not_effective", "blocked"
                        record.stop_reason = stop_reason
                        self._phase(result, round_no, "STOP", "blocked",
                                    "config_not_effective: loaded!=planned")
                        self._revert_config_change(round_no, round_revision, ctx,
                                                   record, result, build, smoke,
                                                   "config_not_effective")
                        break
                    if config_status != "effective":
                        # unknown 只是“没观测到实际加载版本”，不能冒充 false；
                        # 但也不能让一轮“不知道跑的是哪版配置”的结果进入采纳。
                        stop_reason, status = "config_unverified", "blocked"
                        record.stop_reason = stop_reason
                        self._phase(result, round_no, "STOP", "blocked",
                                    "config_unverified: loaded unreported")
                        break

                # ---- COMPARE（跨 build 一律不可比） ----
                compare_tool = self._compare_trials(round_no, ctx, result, record)
                record.compare = self._compare(previous, observation2,
                                               executions=last_execution)
                if compare_tool:
                    record.compare["tool"] = compare_tool
                self._phase(result, round_no, "COMPARE",
                            record.compare.get("status", "unknown"),
                            str(record.compare.get("reason", "")))
                previous = observation2

                # ---- 延后的 ADOPT：CONFIG 判 effective 之后才真正采纳 ----
                if pending_adopt is not None:
                    record.adopted = True
                    self.workspace.revisions.record_adoption(
                        decision.to_dict())
                    self._phase(result, round_no, "ADOPT", "ok",
                                f"deferred:config_effective "
                                f"{pending_adopt.revision_id}")

                # ---- 轮末停止判定 ----
                post = self.session.diagnose(
                    observation2, evidence_refs=tuple(result_evidence(result)))
                record.note = post.code
                if post.code == "candidate_observed":
                    refs = tuple(result_evidence(result, candidates_only=True))
                    if not refs:
                        refs = tuple(result_evidence(result))
                    verification = self.policy.verification_request(
                        diagnosis=post, candidates=post.candidates,
                        engineering=decision, mode=self.session.mode,
                        evidence_refs=refs)
                    result.verification = verification
                    stop_reason = ("candidate_ready" if verification.allowed
                                   else "verification_blocked")
                    status = "completed" if verification.allowed else "blocked"
                    record.stop_reason = stop_reason
                    self._phase(result, round_no, "STOP", "ok",
                                f"{stop_reason} blockers={list(verification.blockers)}")
                    break
                if self._budget_exhausted():
                    stop_reason, status = "budget", "budget"
                    record.stop_reason = stop_reason
                    self._phase(result, round_no, "STOP", "budget",
                                str(self._budget_snapshot()))
                    break
                round_no += 1
            else:
                stop_reason = "max_rounds"
                status = "completed"
                self._phase(result, round_no, "STOP", "max_rounds", "")

            for item in result.rounds:
                if item.invalidations:
                    all_invalidations.extend(item.invalidations)
            result.invalidations = all_invalidations
        except Exception as exc:                 # noqa: BLE001 - 控制器崩溃要如实报
            result.status = "failed"
            result.stop_reason = f"error:{type(exc).__name__}"
            result.error = f"{type(exc).__name__}: {exc}"
            self._phase(result, round_no, "STOP", "failed", result.error)
            result.finished_at = now()
            result.budget = self._budget_snapshot()
            return result

        result.stop_reason = stop_reason
        result.status = status
        result.verification = verification
        result.final = previous
        result.finished_at = now()
        result.budget = self._budget_snapshot()
        if self.emit_events and self.store is not None:
            try:
                self.store.append_event(
                    str(self.task.get("task_id") or ""), "research.finished",
                    stage=status,
                    payload={"stop_reason": stop_reason,
                             "rounds": len(result.rounds),
                             "revisions": list(result.revisions),
                             "duration": round(self.clock() - started, 3)})
            except Exception:                    # noqa: BLE001 - 事件失败不改结论
                pass
        return result

    # ------------------------------------------------------------------ 阶段实现
    def _collect(self, binding: Binding, execution_id: str
                 ) -> TrustedExecutionSnapshot:
        return TrustedExecutionSnapshot.collect(
            self.store, str(self.task.get("task_id") or ""),
            execution_id=str(execution_id or ""), index=self.index,
            task=self.task, corpus=self.corpus, binding_hash=binding.hash,
            campaign=self.campaign, epoch=int(binding.epoch), job_id="",
            tools_allowed=self.registry.names(), denials=())

    # ------------------------------------------------------------------ 配置
    def _config_mode(self) -> str:
        """配置模式判定：workspace 没有配置面就是 `generator`（第 1 周行为不变）。"""
        if self.workspace is None:
            return "generator"
        mode = getattr(self.workspace, "config_mode", "generator")
        return str(mode or "generator")

    def _config_role(self):
        """配置模式下的确定性 `ConfigRole`；generator 模式返回 None。

        目录与当前选择全部取自 workspace 的配置面（W2-A）：这里只做**读**，
        变更仍然由 `ConfigRole` 产出的 `RevisionPlan` 经 `workspace.stage()` 落地。
        """
        if self._config_mode() != "config":
            return None
        surface = getattr(self.workspace, "config_surface", None)
        if surface is None:
            return None
        try:
            from .session import ConfigRole
            workspace = self.workspace
            catalogue = surface.catalogue()
            return ConfigRole(
                samples=[item["id"] for item in catalogue.get("samples") or ()],
                observation_points=[item["id"] for item in
                                    catalogue.get("observation_points") or ()],
                # 每次取当前选择（commit/revert 之后工作区已经变了，不能吃旧快照）
                current_provider=workspace.active_config_doc,
                max_attempts=int(getattr(getattr(self, "session", None),
                                         "max_attempts", 3)))
        except Exception:                    # noqa: BLE001 - 配置面不可读则不提议
            return None

    def _record_config_effect(self, round_no: int, observation: Observation,
                              execution_id: str,
                              record: RoundRecord) -> dict | None:
        """COLLECT 之后算一次配置效果并落账；generator 模式返回 None。

        口径（`docs/V3-W2-CONFIG.md` §2/§5.3）：`planned` **只**来自 revision 侧
        （`workspace.active_config_sha256()`），`loaded` **只**来自执行器回报
        （`observation.config["loaded"]`）。缺失一律 `unknown`——绝不回填 planned。
        """
        if self._config_mode() != "config":
            return None
        planned = ""
        try:
            planned = str(self.workspace.active_config_sha256() or "")
        except Exception:                    # noqa: BLE001 - 读不到配置身份=未知
            planned = ""
        config = dict(observation.config or {})
        loaded_raw = config.get("loaded")
        loaded = "" if loaded_raw in (None, UNKNOWN, "unknown") \
            else str(loaded_raw)
        source = str(config.get("source") or "")
        if not planned:
            status, source = "unknown", source or "planned_missing"
        elif not loaded:
            status, source = "unknown", source or "loaded_unreported"
        elif planned == loaded:
            status = "effective"
        else:
            status = "not_effective"
        effect = {"planned_sha256": planned, "loaded_sha256": loaded,
                  "status": status, "source": source,
                  "revision_id": getattr(self._revision(), "revision_id", ""),
                  "execution_id": str(execution_id or ""),
                  "round": int(round_no)}
        stored = self._write_config_effect(effect, round_no)
        if stored:
            effect["effect_id"] = stored
        record.config_effect = dict(effect)
        return effect

    def _write_config_effect(self, effect: Mapping, round_no: int) -> str:
        """把配置效果写进 revision 账本；账本还没落地就只留 RoundRecord。"""
        store = getattr(self.workspace, "revisions", None)
        if store is None or not hasattr(store, "record_config_effect"):
            return ""
        record = _config_effect_record(
            effect, round_no=int(round_no))
        if record is None:
            return ""
        try:
            saved = store.record_config_effect(record)
        except Exception:                    # noqa: BLE001 - 落账失败不改观测结论
            return ""
        return str(getattr(saved, "effect_id", "") or getattr(
            record, "effect_id", "") or "")

    def _revert_config_change(self, round_no: int, round_revision, ctx,
                              record: RoundRecord, result: ControllerResult,
                              build, smoke, reason: str) -> None:
        """配置不生效：回退到**父 revision**（配置变更之前的那一版）并停。

        只做回退：不写 `adoptions.jsonl`、不产生 verification——裁决只认 verify，
        而这条路径根本没走到 verify。
        """
        target = round_revision or self._revision()
        parent_id = str(getattr(target, "parent_id", "") or "")
        if not parent_id:
            self._phase(result, round_no, "REVERT", "skipped",
                        "no_parent_revision")
            return
        try:
            reverted = self.workspace.revert(
                to_revision=parent_id,
                reason=f"{reason}: revert to {parent_id}",
                grant=getattr(ctx, "grant", ()))
        except Exception as exc:             # noqa: BLE001 - 回退失败如实记
            self._phase(result, round_no, "REVERT", "failed",
                        f"{type(exc).__name__}: {exc}")
            return
        record.reverted = reverted.revision_id
        result.revisions.append(reverted.revision_id)
        self._phase(result, round_no, "REVERT", "ok",
                    f"{reverted.revision_id} reverted_to={parent_id}")
        record.invalidations.extend(self._consume_invalidations(
            round_no, record, build, smoke, [],
            extra_handled={"coverage_baseline":
                           f"revert:{reverted.revision_id}",
                           "corpus_members":
                           "deferred:revalidation_required",
                           "config_effect": f"revert:{parent_id}"}))

    def _static_authorize(self, plan: ResearchPlan, ctx: ToolContext
                          ) -> tuple[list, list[str]]:
        allowed: list = []
        rejected: list[str] = []
        if len(plan.actions) > self.max_actions:
            rejected.append(f"too_many_actions:{len(plan.actions)}"
                            f">{self.max_actions}")
            return allowed, rejected
        for request in plan.requests:
            try:
                spec = self.registry.get(request.action)
                if ctx.mode not in spec.allowed_modes:
                    raise ActionRejected("mode_not_allowed",
                                         f"{request.action} 不允许模式 {ctx.mode}")
                if spec.permission not in ctx.grant:
                    raise ActionRejected(
                        "permission_denied",
                        f"{request.action} 需要 {spec.permission}")
                _static_params(request.params)
                allowed.append(request)
            except ActionRejected as exc:
                rejected.append(f"{request.action}: {exc.code}: {exc.reason}")
        return allowed, rejected

    def _stage(self, plan: ResearchPlan, ctx: ToolContext, round_no: int):
        if self.workspace is None:
            raise RuntimeError("no workspace: 无法 stage/build/smoke")
        revision_plan = plan.revision
        if revision_plan is None:
            raise RuntimeError("no revision plan")
        action_id = (plan.requests[0].action_id if plan.requests else
                     f"stage-r{round_no:02d}")
        self.workspace.stage(revision_plan.files, grant=ctx.grant,
                             reason=revision_plan.reason)
        environment = {"toolchain": getattr(self.workspace, "toolchain", ""),
                       "policy_version": self.policy_version,
                       "round": str(round_no)}
        return self.workspace.commit(
            reason=revision_plan.reason,
            hypothesis_id=revision_plan.hypothesis_id,
            action_id=action_id, tool=revision_plan.tool,
            environment=environment)

    # ------------------------------------------------------------------ 失效
    def _consume_invalidations(self, round_no: int, record: RoundRecord,
                               build, smoke, executed: list[ActionResult],
                               extra_handled: Mapping | None = None
                               ) -> list[dict]:
        pending: list[str] = []
        for scope in self.registry.consume_invalidations():
            if scope not in pending:
                pending.append(scope)
        if self.workspace is not None:
            store = getattr(self.workspace, "revisions", None)
            if store is not None:
                for scope in store.consume_invalidations():
                    if scope not in pending:
                        pending.append(scope)
        handled: dict[str, str] = {}
        if build is not None:
            handled["build"] = build.build_id
        if smoke is not None:
            handled["smoke"] = smoke.smoke_id
        for result in executed:
            if result.status not in ("applied", "noop"):
                continue
            if result.tool in ("run_epoch", "replay_input"):
                handled["execution_facts"] = result.action_id
                handled["coverage_baseline"] = f"{result.tool}:{result.action_id}"
            if result.tool == "materialize_seeds":
                handled["corpus_members"] = result.action_id
                handled["input_dedup"] = result.action_id
            if result.tool == "set_dictionary":
                handled["input_dedup"] = result.action_id
            if result.tool == "compare_trials":
                handled["trial_compare"] = result.action_id
        if build is not None and smoke is not None:
            handled.setdefault("trial_compare",
                               "new_build:comparison_cache_reset")
        if "input_policy" in pending and "input_dedup" in handled:
            handled["input_policy"] = handled["input_dedup"]
        if "trial_compare" in pending and "trial_compare" not in handled:
            handled["trial_compare"] = (
                f"no_cached_comparison:trials={len(self.state.trials)}")
        out: list[dict] = []
        for scope, by in dict(extra_handled or {}).items():
            if scope in pending:
                handled[scope] = str(by)
        for scope in pending:
            by = handled.get(scope, "")
            if not by:
                state = "unhandled"
            elif by.startswith("deferred:"):
                state = "deferred"
            else:
                state = "handled"
            out.append({"scope": scope, "handled_by": by,
                        "status": state, "round": int(round_no)})
        return out

    # ------------------------------------------------------------------ 比较
    def _compare_trials(self, round_no: int, ctx: ToolContext,
                        result: ControllerResult, record: RoundRecord) -> dict:
        """≥2 个 trial 时真正调一次 compare_trials（走同一 Registry）。"""
        trials = list(self.state.trials.values())
        if len(trials) < 2:
            return {}
        left, right = trials[-2]["trial_id"], trials[-1]["trial_id"]
        request = ActionRequest(
            action_id=f"cmp-r{int(round_no):02d}", action="compare_trials",
            binding=ctx.binding.to_dict(),
            params={"left": left, "right": right, "metric": "coverage"})
        outcome = self.registry.invoke(request, ctx)
        self.session.record(outcome)
        record.actions.append({
            "action_id": outcome.action_id, "tool": outcome.tool,
            "status": outcome.status,
            "invalidations": list(outcome.invalidations),
            "evidence_refs": list(outcome.evidence_refs),
            "error": dict(outcome.error) if outcome.error else None,
        })
        self._phase(result, round_no, "COMPARE", outcome.status,
                    f"compare_trials {left} vs {right}")
        return dict(outcome.payload or {})

    def _compare(self, previous: Observation | None,
                 current: Observation, *, executions: str) -> dict:
        if previous is None:
            return {"status": "unknown", "comparable": "unknown",
                    "reason": "no_previous_observation",
                    "verdict": "not_evaluated"}
        build_a = str(previous.revision.get("build_id") or "unknown")
        build_b = str(current.revision.get("build_id") or "unknown")
        if "unknown" in (build_a, build_b) or build_a != build_b:
            return {"status": "unknown", "comparable": "false",
                    "reason": f"build_changed:{build_a}->{build_b}",
                    "delta": "unknown", "verdict": "not_evaluated"}
        left = previous.coverage.get("covered")
        right = current.coverage.get("covered")
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            return {"status": "unknown", "comparable": "true",
                    "reason": "coverage_unknown", "delta": "unknown",
                    "verdict": "not_evaluated"}
        return {"status": "applied", "comparable": "true",
                "reason": "same_build", "metric": "coverage",
                "delta": float(right) - float(left),
                "execution_id": executions, "verdict": "not_evaluated"}

    # ------------------------------------------------------------------ 预算/取消
    def _budget_port(self):
        return self.budget or NullBudget()

    def _budget_snapshot(self) -> dict:
        try:
            return dict(self._budget_port().snapshot() or {})
        except Exception:                       # noqa: BLE001
            return {}

    def _budget_exhausted(self) -> str:
        snap = self._budget_snapshot()
        remaining = dict(snap.get("remaining") or {})
        for key, value in remaining.items():
            try:
                if float(value) <= 0:
                    return f"remaining:{key}<=0"
            except (TypeError, ValueError):
                continue
        violations = snap.get("violations") or []
        if violations:
            return f"violations:{violations}"
        return ""

    def _cancelled(self) -> bool:
        if self.cancel is None:
            return False
        try:
            return bool(self.cancel())
        except Exception:                       # noqa: BLE001 - 钩子坏了按未取消
            return False

    def _phase(self, result: ControllerResult, round_no: int, phase: str,
               status: str, detail: str) -> None:
        result.timeline.append(PhaseRecord(
            round_no=int(round_no), phase=phase, status=str(status),
            detail=str(detail or "")))


# ====================================================================== 工具
def _error_code(exc: BaseException) -> str:
    """把 `WorkspaceError("<code>: <detail>")` 的 code 取出来（认码不认自然语言）。"""
    for attr in ("code", "error_code"):
        value = getattr(exc, attr, "")
        if value:
            return str(value)
    text = str(exc or "")
    head = text.split(":", 1)[0].strip()
    return head if head and " " not in head else ""


def _surface_value(surface: Any, name: str) -> Any:
    """从配置面上取一个成员（属性/方法/文档字段都认），取不到返回 None。"""
    for candidate in (name, f"{name}_ids", f"{name}_catalog", f"active_{name}"):
        if isinstance(surface, Mapping) and candidate in surface:
            value = surface[candidate]
        else:
            value = getattr(surface, candidate, None)
        if callable(value):
            try:
                value = value()
            except Exception:            # noqa: BLE001 - 取不到就当没有
                continue
        if value not in (None, (), [], {}):
            return value
    return None


def _config_effect_record(effect: Mapping, *, round_no: int):
    """构造 `ConfigEffectRecord`（W2-A 账本）：账本还没落地就不落账。"""
    try:
        from .revision import ConfigEffectRecord
    except Exception:                    # noqa: BLE001 - 并行依赖尚未落地
        return None
    status = str(effect.get("status") or "unknown")
    body = dict(
        revision_id=str(effect.get("revision_id") or ""),
        planned_sha256=str(effect.get("planned_sha256") or ""),
        loaded_sha256=str(effect.get("loaded_sha256") or ""),
        status=status, source=str(effect.get("source") or ""),
        execution_id=str(effect.get("execution_id") or ""),
        round_no=int(round_no),
        reason=(f"config_{status}"), created_at=now(),
    )
    try:
        # `effect_id` 由账本按内容自算（与 `HarnessRevision` 同一口径）：这里不传，
        # 免得先撞一次 `config_effect_tampered` 再靠兜底绕过。
        return ConfigEffectRecord(**body)
    except Exception:                    # noqa: BLE001 - 不变量不过就别落账
        return None


def _static_params(params: Mapping) -> None:
    """带 `$ref` 的参数在授权阶段只检查“形状”，执行前再解析。"""
    if not isinstance(params, Mapping):
        raise ActionRejected("invalid_params", "params 必须是对象")
    for key, value in params.items():
        if isinstance(value, Mapping) and set(value) == {"$ref"}:
            continue
        if isinstance(value, Mapping):
            _static_params(value)


def _resolve_refs(params: Mapping, refs: Mapping) -> dict:
    """解析 `$ref`；解析不到就拒绝（绝不把 None 当参数传下去）。"""
    def walk(value: Any, path: str) -> Any:
        if isinstance(value, Mapping) and set(value) == {"$ref"}:
            parts = str(value["$ref"] or "").split(".")
            current: Any = refs
            for part in parts:
                if not isinstance(current, Mapping) or part not in current:
                    raise ActionRejected(
                        "unresolved_ref",
                        f"参数 {path or '(root)'} 引用的 {value['$ref']} 还没有值",
                        field_name=path.split(".")[0] if path else "",
                        hint="引用只能指向本轮已经成功执行的动作")
                current = current[part]
            return current
        if isinstance(value, Mapping):
            return {key: walk(item, f"{path}.{key}".strip("."))
                    for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [walk(item, path) for item in value]
        return value
    resolved = walk(dict(params or {}), "")
    if not isinstance(resolved, dict):
        raise ActionRejected("invalid_params", "params 必须是对象")
    return resolved


def _trial_candidates(result: ActionResult) -> int:
    payload = dict(result.payload or {})
    trial = payload.get("trial")
    if isinstance(trial, Mapping):
        value = trial.get("candidates")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return 0


def result_evidence(result: ControllerResult, *, candidates_only: bool = False
                    ) -> list[str]:
    """从整轮结果里收集证据引用（action_result.evidence_refs 不可回读）。"""
    refs: list[str] = []
    for round_record in result.rounds:
        for action in round_record.actions:
            if candidates_only and not int(action.get("candidates") or 0):
                continue
            for ref in action.get("evidence_refs") or ():
                if ref not in refs:
                    refs.append(str(ref))
    return refs


__all__ = ["SCHEMA", "SCHEMA_VERSION", "PHASES", "STATUSES",
           "FATAL_REJECTIONS", "PhaseRecord", "RoundRecord",
           "ControllerResult", "ResearchController", "result_evidence"]
