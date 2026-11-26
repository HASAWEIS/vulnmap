"""V3 自适应研究 Harness 的构件（P1 / P2a / P2b 已落地部分）。

- P1（V3-004）持久语料与构建身份：`corpus.CorpusStore` / `build_identity`；
- P2a（V3-005）单一动作契约与工具表：`contracts`（ActionRequest/ActionResult/
  ToolSpec/Registry）+ `tools`（首批只读/输入/实验/收口工具）；
- P2a（V3-006）可信执行快照：`snapshot.TrustedExecutionSnapshot`；
- P2b（V3-007）实验副本与版本事务：`revision`（HarnessRevision/BuildRecord/
  SmokeRecord/RevisionStore）+ `workspace`（TaskWorkspace：原件只读、副本可写、
  build/smoke 真跑、revert 不改旧账）；
- P2b（V3-008）研究会话与慢循环：`session`（Context/Seed/Diagnose + 确定性计划）
  + `controller`（OBSERVE→…→ADOPT/REVERT/STOP，失效消费与有限停止）；
- P2b（V3-009）采纳策略：`policy`（工程采纳与漏洞验证分离；harness 自崩/
  建模不冒充通过；只有既有 verify 能写 verified/confirmed）。
- P2C 研究 CLI：`cli`（`run --research` 的依赖装配、fuzz 短切片执行 worker、
  控制器结果 → 平台状态的唯一映射表、`research.json` 报告）。
- P3（V3-010）预算与网关：`budget`（run/task/finding/action 层级原子预留、
  保守结算、价格表）+ `llm_gateway`（模型调用统一过预算/权限、key 不进工作区）；
- P3（V3-011/012/013）可靠性：`jobs`（campaign 子 Job、lease/fencing、关联
  既有启动器 job）+ `recovery`（UNKNOWN 先对账、已完成复用、取消撤销 lease）。
- P5（V3-018）可选新后端：`backends`（Backend 能力/执行/证据快照/租约/恢复 +
  HTTP 服务型后端，不依赖新镜像；结论仍由 verify 推导）。
"""
from . import (budget, cli, contracts, controller, handoff, jobs, llm_gateway,
               recovery, revision, session, snapshot, tools, workspace,
               backends)
from .contracts import (ActionResult, ActionRequest, Binding, Registry,
                        SessionState, ToolContext, ToolOutcome, ToolSpec,
                        UNKNOWN, grant_for)
from .corpus import (SCHEMA as CORPUS_SCHEMA, SCHEMA_VERSION,
                     CorpusError, CorpusStore, build_identity)
from .policy import (AdoptionPolicy, Decision, VerificationRequest,
                     POLICY_VERSION, prune_verdict_fields)
from .handoff import (Acceptance, GateDecision, HandoffError,
                      IndependentVerifier, ProposalGate, RawRecord,
                      RawRecordReader, ReviewItem, handoff_view, open_pending,
                      review_item)
from .revision import (BuildRecord, ConfigEffectRecord, FileEntry,
                       HarnessRevision, RevisionError, RevisionStore,
                       SmokeRecord, manifest_of)
from .controller import ControllerResult, ResearchController
from .session import (ContextRole, DiagnoseRole, Diagnosis, Observation,
                      ProposedAction, ResearchPlan, ResearchSession, SeedRole)
from .snapshot import Cursor, SnapshotError, TrustedExecutionSnapshot
from .tools import REGISTRY, SPECS, make_binding, make_context
from .workspace import (CONFIG_ACTIVE_SCHEMA, CONFIG_RELPATH, ConfigError,
                        ConfigSurface, StageResult, TaskWorkspace,
                        WorkspaceError, classify_smoke)
from .budget import (BudgetError, BudgetLedger, BudgetRefused, BudgetStop,
                     EMPTY_PRICES, LedgerBudget, PriceTable, Reservation)
from .llm_gateway import (CALL_STATES, GatewayError, GatewayRefused,
                          LLMGateway, ModelCall, ModelSpec, SecretLeak)
from .jobs import (CampaignJobs, JobError, JobOutcome, Lease, LeaseGuard,
                   LeaseLost)
from .recovery import RecoveryAction, RecoveryReport, decide as recovery_decision
from .recovery import recover as recover_jobs
from .cli import (DEFAULT_MAX_ROUNDS as RESEARCH_MAX_ROUNDS,
                  RESEARCH_SCHEMA, RESEARCH_SCHEMA_VERSION, FuzzEpochRunner,
                  ResearchError, map_state as map_research_state,
                  run_research)
from .backends import (BACKEND_REGISTRY, Backend, BackendError, BackendRefused,
                       BackendRequest, BackendResult, Capabilities,
                       HttpServiceBackend, Lease, LeaseLost, RecoveryAction)

__all__ = [
    # corpus（P1）
    "CORPUS_SCHEMA", "SCHEMA_VERSION", "CorpusError", "CorpusStore",
    "build_identity",
    # contracts（P2a）
    "contracts", "ActionRequest", "ActionResult", "Binding", "Registry",
    "SessionState", "ToolContext", "ToolOutcome", "ToolSpec", "UNKNOWN",
    "grant_for",
    # snapshot（P2a）
    "snapshot", "Cursor", "SnapshotError", "TrustedExecutionSnapshot",
    # tools（P2a）
    "tools", "REGISTRY", "SPECS", "make_binding", "make_context",
    # revision / workspace（P2b, V3-007）
    "revision", "workspace", "FileEntry", "HarnessRevision", "BuildRecord",
    "SmokeRecord", "RevisionStore", "RevisionError", "manifest_of",
    "TaskWorkspace", "WorkspaceError", "ConfigError", "ConfigSurface",
    "CONFIG_RELPATH", "CONFIG_ACTIVE_SCHEMA", "StageResult", "classify_smoke",
    "ConfigEffectRecord",
    # session / controller（P2b, V3-008）
    "session", "Observation", "Diagnosis", "ResearchPlan", "ProposedAction",
    "ContextRole", "DiagnoseRole", "SeedRole", "ResearchSession",
    "controller", "ResearchController", "ControllerResult",
    # policy（P2b, V3-009）
    "policy", "AdoptionPolicy", "Decision", "VerificationRequest",
    "POLICY_VERSION", "prune_verdict_fields",
    # handoff（W3, V3-019）
    "handoff", "HandoffError", "RawRecord", "RawRecordReader", "ReviewItem",
    "IndependentVerifier", "Acceptance", "GateDecision", "ProposalGate",
    "open_pending", "review_item", "handoff_view",
    # budget / jobs / recovery（P3）
    "budget", "BudgetLedger", "LedgerBudget", "PriceTable", "EMPTY_PRICES",
    "BudgetRefused", "BudgetStop", "BudgetError", "Reservation",
    "jobs", "CampaignJobs", "Lease", "LeaseGuard", "LeaseLost", "JobError",
    "JobOutcome",
    "llm_gateway", "LLMGateway", "ModelCall", "ModelSpec", "CALL_STATES",
    "GatewayError", "GatewayRefused", "SecretLeak",
    "recovery", "RecoveryAction", "RecoveryReport", "recover_jobs",
    "recovery_decision",
    # cli（P2C）
    "cli", "RESEARCH_SCHEMA", "RESEARCH_SCHEMA_VERSION", "RESEARCH_MAX_ROUNDS",
    "FuzzEpochRunner", "ResearchError", "run_research", "map_research_state",
    # backends（P5, V3-018）
    "backends", "BACKEND_REGISTRY", "Backend", "BackendError", "BackendRefused",
    "BackendRequest", "BackendResult", "Capabilities", "HttpServiceBackend",
    "Lease", "LeaseLost", "RecoveryAction",
]
