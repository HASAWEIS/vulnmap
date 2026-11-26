"""V2 平台运行时：任务状态机 + 事件 + 证据。"""
from .task import (Budget, TaskSpec, TaskError, STATES, TERMINAL, CANCELLABLE,
                   can_transition, new_task_id)
from .store import PlatformStore
from .events import EventBus
from .evidence import EvidenceStore, EvidenceRef
from .preflight import run_preflight

__all__ = ["Budget", "TaskSpec", "TaskError", "STATES", "TERMINAL",
           "CANCELLABLE", "can_transition", "new_task_id", "PlatformStore",
           "EventBus", "EvidenceStore", "EvidenceRef", "run_preflight"]

from .program import ProgramIndex, ProgramError
from .hypotheses import (HypothesisError, MAX_HYPOTHESES, propose,
                         run_hypotheses, run_understand, validate as validate_hypotheses)

__all__ += ["ProgramIndex", "ProgramError", "HypothesisError", "MAX_HYPOTHESES",
            "propose", "validate_hypotheses", "run_understand", "run_hypotheses"]

from .planner import (KINDS as PLAN_KINDS, Plan, PlanError, run_plan,
                      select as select_plan, select_kind)
from .candidates import (Candidate, CandidateError, STATES as CANDIDATE_STATES,
                         build_candidates, validate_candidate)
from .executors import (EXECUTORS, DynamicExecError, StaticExecError,
                        executor_unavailable, run_execution)
from .budget import (BUDGET_KEYS, BudgetExceeded, BudgetGuard, REASON_BY_KEY,
                     check as check_budget, usage_from_events,
                     violations as budget_violations)
from .lifecycle import cancel_task, is_cancelled, terminate_budget

__all__ += ["PLAN_KINDS", "Plan", "PlanError", "run_plan", "select_plan",
            "select_kind",
            "Candidate", "CandidateError", "CANDIDATE_STATES", "build_candidates",
            "validate_candidate", "run_execution",
            "EXECUTORS", "DynamicExecError", "StaticExecError",
            "executor_unavailable",
            "BUDGET_KEYS", "BudgetExceeded", "BudgetGuard", "REASON_BY_KEY",
            "check_budget", "usage_from_events", "budget_violations",
            "cancel_task", "is_cancelled", "terminate_budget"]

from .verify import (BENCHMARK_KIND, KINDS as VERIFICATION_KINDS, Verification,
                     VerificationError, evaluate as evaluate_verification,
                     evaluate_cybergym, evaluate_exploitgym, evaluate_vulngym,
                     normalize_spec, run_verification)
from .review import Review, ReviewError, run_review
from .casepack import CasePackError, build_casepack

__all__ += ["BENCHMARK_KIND", "VERIFICATION_KINDS", "Verification",
            "VerificationError", "evaluate_verification", "evaluate_cybergym",
            "evaluate_exploitgym", "evaluate_vulngym", "normalize_spec",
            "run_verification", "Review", "ReviewError", "run_review",
            "CasePackError", "build_casepack"]
