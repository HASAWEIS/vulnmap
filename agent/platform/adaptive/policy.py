"""V3-009：采纳策略 —— 工程采纳与漏洞验证彻底分开，harness 自崩不冒充通过。

三条不可越的线（《V3 完整升级方案》§8「实验自修改与版本事务」、§12「独立验证」）：

1. **工程采纳 / 漏洞验证分离**：`AdoptionPolicy.engineering()` 只回答
   “这份 harness/生成器副本能不能构建、能不能驱动、有没有可测收益”，
   它的结论字段是 `adopt`；漏洞结论字段 `verified/confirmed` 永远不由这里产生。
2. **harness 自崩 / 只建模不执行 不能冒充通过**：
   `smoke.harness_failed`、构建失败、`build_id` 与证据不一致（跨 build 复用旧覆盖）、
   trial 缺真实执行证据，都会让 `engineering()` 与 `verification_request()` 失败；
   `false_positive()` 把这类情况显式判成“不可采纳”，不给“先通过再说”的缝。
3. **只有既有 verify 能写 verified/confirmed**：`verdict()` 是**只读**查询，
   只认 `agent.platform.verify.Verification` 形状（`vulnmap.verification.v1`）
   且 `status=verified / verified=True`；任何研究侧自报的
   `{"verified": true}` 都在 `sanitize()` 里被剥掉，并由 `review_claim()` 拒绝。

本模块不执行、不写库、不改 revision；它给控制器一个可审计的决策对象。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .contracts import digest_of, now

SCHEMA = "vulnmap.adaptive.policy.v1"
SCHEMA_VERSION = 1
POLICY_VERSION = "v3-p2b"

#: 采纳的两种范围（不要合并成一个字段）
SCOPES = ("engineering", "vulnerability")

#: 研究侧输出里永不接受的裁决字段（出现即剥离/拒绝，绝不透传）
VERDICT_FIELDS = frozenset({"verified", "confirmed", "pass", "verdict",
                            "adjudicated", "oracle_result"})

#: 只读判定用的 verify 契约（延迟导入，避免把 benchmark 依赖带进所有入口）
VERIFICATION_SCHEMA = "vulnmap.verification.v1"
VERIFICATION_STATUSES = ("verified", "no_repro", "needs_evidence", "rejected")

#: 满足条件、可以进入独立验证的诊断码
VERIFICATION_DIAGNOSES = ("candidate_observed",)


class PolicyError(ValueError):
    """策略输入非法（例如把“自报通过”当裁决）。"""


@dataclass(frozen=True)
class Check:
    """一条可复核的检查项：名字、结论、证据/原因。"""

    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": bool(self.ok), "detail": self.detail}


@dataclass(frozen=True)
class Decision:
    """一次采纳决策；`scope` 明确它管的是工程还是漏洞。"""

    scope: str
    adopt: bool
    subject: str = ""
    checks: tuple[Check, ...] = ()
    reasons: tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION
    created_at: str = ""

    def __post_init__(self) -> None:
        if self.scope not in SCOPES:
            raise PolicyError(f"unknown decision scope: {self.scope!r}")
        object.__setattr__(self, "checks", tuple(self.checks or ()))
        object.__setattr__(self, "reasons",
                           tuple(str(r) for r in (self.reasons or ())))
        if not self.created_at:
            object.__setattr__(self, "created_at", now())

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(check.name for check in self.checks if not check.ok)

    @property
    def digest(self) -> str:
        return digest_of(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "scope": self.scope, "adopt": bool(self.adopt),
            "subject": self.subject,
            "checks": [check.to_dict() for check in self.checks],
            "failed": list(self.failed), "reasons": list(self.reasons),
            "policy_version": self.policy_version,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class VerificationRequest:
    """“可以去做独立验证了”——不是“验证通过”。"""

    allowed: bool
    blockers: tuple[str, ...] = ()
    mode: str = "verify"
    candidate_refs: tuple[str, ...] = ()
    diagnosis: str = ""
    policy_version: str = POLICY_VERSION

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "allowed": bool(self.allowed), "blockers": list(self.blockers),
            "mode": self.mode, "candidate_refs": list(self.candidate_refs),
            "diagnosis": self.diagnosis, "policy_version": self.policy_version,
            "note": "allowed=true 只表示可以交给既有 verify；不代表已验证",
        }


def _check(name: str, ok: bool, detail: str = "") -> Check:
    return Check(name=name, ok=bool(ok), detail=str(detail or ""))


def prune_verdict_fields(payload: Mapping | None) -> tuple[dict, tuple[str, ...]]:
    """剥掉研究侧 payload 里的裁决字段，返回 (干净副本, 被剥掉的键)。"""
    clean: dict = {}
    stripped: list[str] = []
    for key, value in dict(payload or {}).items():
        if str(key).lower() in VERDICT_FIELDS:
            stripped.append(str(key))
            continue
        if isinstance(value, Mapping):
            value, nested = prune_verdict_fields(value)
            stripped.extend(f"{key}.{item}" for item in nested)
        clean[key] = value
    return clean, tuple(stripped)


def _verify_contract() -> tuple[str, tuple[str, ...]]:
    try:                                  # 延迟导入：保持 adaptive 轻量
        from .. import verify as verify_mod
        return str(verify_mod.SCHEMA), tuple(verify_mod.STATUSES)
    except Exception:                     # noqa: BLE001 - 契约缺失就按已知常量
        return VERIFICATION_SCHEMA, VERIFICATION_STATUSES


class AdoptionPolicy:
    """工程采纳 / 漏洞验证的唯一判定入口（纯函数式，不做 IO）。"""

    def __init__(self, *, min_coverage_gain: float = 0.0,
                 require_gain: bool = False,
                 require_evidence: bool = True) -> None:
        self.min_coverage_gain = float(min_coverage_gain)
        self.require_gain = bool(require_gain)
        self.require_evidence = bool(require_evidence)

    # ------------------------------------------------------------------ 工程
    def engineering(self, *, revision=None, build=None, smoke=None,
                    origin: Mapping | None = None,
                    compare: Mapping | None = None,
                    trial: Mapping | None = None,
                    claimed_payload: Mapping | None = None,
                    subject: str = "") -> Decision:
        """判断一次 harness 副本变更是否可作“工程采纳”。

        必需：原件未变、构建成功、冒烟通过且不是 harness 自崩、trial 真实执行过
        且 build 与本次一致、没有夹带裁决字段。收益（compare）默认只记录不强制；
        一旦提供且不可比/无增益，则**不采纳**（宁可少采纳，也不虚报收益）。
        """
        checks: list[Check] = []
        reasons: list[str] = []

        if origin is not None:
            checks.append(_check("origin_unchanged", bool(origin.get("ok")),
                                 "; ".join(origin.get("problems") or [])))
        checks.append(_check("revision_present", revision is not None,
                             getattr(revision, "revision_id", "") or "no revision"))
        if revision is not None:
            checks.append(_check(
                "revision_digest", bool(_digest_ok(revision)),
                getattr(revision, "manifest_sha256", "")))

        build_ok = bool(getattr(build, "ok", False))
        checks.append(_check("build_ok", build_ok,
                             f"status={getattr(build, 'status', 'missing')}"))
        harness_failed = bool(getattr(smoke, "harness_failed", False))
        smoke_ok = bool(getattr(smoke, "ok", False))
        checks.append(_check("smoke_passed", smoke_ok and not harness_failed,
                             f"status={getattr(smoke, 'status', 'missing')} "
                             f"kind={getattr(smoke, 'kind', '')}"))
        checks.append(_check("harness_healthy", not harness_failed,
                             getattr(smoke, "detail", "") or "harness did not crash"))

        if self.require_evidence:
            evidence_ok, evidence_detail = _evidence_check(
                trial=trial, build=build, require=bool(trial is not None))
            checks.append(_check("execution_evidence", evidence_ok, evidence_detail))

        if compare is not None:
            status = str(compare.get("status") or "")
            comparable = str(compare.get("comparable") or "")
            delta = compare.get("delta")
            gain_ok = (status == "applied" and comparable == "true"
                       and isinstance(delta, (int, float))
                       and not isinstance(delta, bool)
                       and float(delta) > self.min_coverage_gain)
            checks.append(_check("measurable_gain", gain_ok,
                                 f"status={status} comparable={comparable} "
                                 f"delta={delta} min={self.min_coverage_gain}"))
            if not gain_ok:
                reasons.append("no_measurable_gain")
        elif self.require_gain:
            checks.append(_check("measurable_gain", False, "no comparison"))
            reasons.append("no_measurable_gain")

        clean, stripped = prune_verdict_fields(claimed_payload)
        checks.append(_check("no_verdict_claim", not stripped,
                             f"stripped={list(stripped)}"))
        if stripped:
            reasons.append("verdict_claim_forbidden")

        adopt = all(check.ok for check in checks)
        if not adopt:
            reasons.extend(check.name for check in checks if not check.ok)
        return Decision(scope="engineering", adopt=adopt,
                        subject=subject or getattr(revision, "revision_id", ""),
                        checks=tuple(checks),
                        reasons=tuple(dict.fromkeys(reasons)))

    # ------------------------------------------------------------------ 验证
    def verification_request(self, *, diagnosis: Mapping | str,
                             candidates: int | str = 0,
                             engineering: Decision | None = None,
                             mode: str = "explore",
                             evidence_refs: Iterable[str] = ()) -> VerificationRequest:
        """是否可以把候选交给既有 verify（只放行，不写结论）。"""
        if isinstance(diagnosis, Mapping):
            code = str(diagnosis.get("code") or "")
        else:
            code = str(getattr(diagnosis, "code", "") or diagnosis or "")
        blockers: list[str] = []
        if code not in VERIFICATION_DIAGNOSES:
            blockers.append(f"diagnosis:{code or 'unknown'}")
        count = candidates if isinstance(candidates, int) else 0
        if count <= 0:
            blockers.append("no_candidate")
        if engineering is not None and not engineering.adopt:
            blockers.append("engineering_not_adopted")
        if mode != "explore":
            # 验证必须由独立流程在 verify 模式发起；研究循环不自己切模式
            blockers.append(f"mode:{mode or 'unknown'}")
        if not tuple(evidence_refs):
            blockers.append("no_evidence_ref")
        return VerificationRequest(
            allowed=not blockers, blockers=tuple(blockers),
            candidate_refs=tuple(str(r) for r in evidence_refs), diagnosis=code)

    # ------------------------------------------------------------------ 裁决
    def verdict(self, records: Iterable[Mapping] | None = None, *,
                store=None, task_id: str = "") -> dict:
        """只读：从既有 verify 记录里取结论；本研究侧永不生成 verified。"""
        items: list[Mapping] = []
        if records is not None:
            items = [dict(r) for r in records]
        elif store is not None and task_id:
            items = [dict(r) for r in store.list_verifications(task_id)]
        schema, statuses = _verify_contract()
        verified: list[str] = []
        invalid: list[str] = []
        for record in items:
            problems = _verification_problems(record, schema=schema,
                                              statuses=statuses)
            if problems:
                invalid.append(f"{record.get('verification_id', '?')}:"
                               f"{','.join(problems)}")
            elif record.get("verified") is True and record.get("status") == "verified":
                verified.append(str(record.get("verification_id") or "?"))
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "scope": "vulnerability",
            "verified": bool(verified),
            "status": ("verified" if verified else
                       ("invalid" if invalid and len(invalid) == len(items)
                        else "not_verified")),
            "verification_ids": verified,
            "invalid": invalid,
            "records": len(items),
            "source": "agent.platform.verify",
            "policy_version": POLICY_VERSION,
            "note": "只有 verify 写过的记录能到这里；空结果不等于 no_repro",
        }

    def review_claim(self, claim: Mapping | None, *,
                     records: Iterable[Mapping] | None = None) -> Decision:
        """审一条研究侧“我发现了/我通过了”的自报：没有 verify 记录就不认。"""
        clean, stripped = prune_verdict_fields(claim)
        verdict = self.verdict(records)
        checks = [
            _check("no_verdict_fields", not stripped, f"stripped={list(stripped)}"),
            _check("independent_verification", bool(verdict["verified"]),
                   f"status={verdict['status']}"),
        ]
        reasons = (["verdict_claim_forbidden"] if stripped else []) + (
            [] if verdict["verified"] else ["verdict_only_from_verify"])
        return Decision(scope="vulnerability", adopt=False,
                        subject=str((claim or {}).get("candidate_id") or ""),
                        checks=tuple(checks), reasons=tuple(reasons))

    # ------------------------------------------------------------------ 假阳性
    def false_positive(self, *, build=None, smoke=None,
                       trial: Mapping | None = None,
                       compare: Mapping | None = None,
                       claimed: Mapping | None = None) -> Decision:
        """harness 自崩 / 跨 build 复用 / 只建模不执行 → 显式拒绝。"""
        checks: list[Check] = []
        harness_failed = bool(getattr(smoke, "harness_failed", False))
        checks.append(_check("harness_healthy", not harness_failed,
                             getattr(smoke, "detail", "") or ""))
        build_ok = bool(getattr(build, "ok", False))
        checks.append(_check("build_ok", build_ok,
                             f"status={getattr(build, 'status', 'missing')}"))
        evidence_ok, evidence_detail = _evidence_check(
            trial=trial, build=build, require=bool(trial is not None))
        checks.append(_check("execution_evidence", evidence_ok, evidence_detail))
        if compare is not None:
            checks.append(_check(
                "comparable", str(compare.get("comparable")) == "true",
                f"comparable={compare.get('comparable')}"))
        clean, stripped = prune_verdict_fields(claimed)
        checks.append(_check("no_verdict_claim", not stripped,
                             f"stripped={list(stripped)}"))
        adopt = False                      # 这个方法永远不“采纳”
        reasons = [check.name for check in checks if not check.ok]
        if not reasons:
            reasons = ["no_false_positive_detected"]
        return Decision(scope="vulnerability", adopt=adopt, checks=tuple(checks),
                        reasons=tuple(dict.fromkeys(reasons)))


def _digest_ok(revision) -> bool:
    try:
        return revision.revision_id == revision.compute_id()
    except Exception:                     # noqa: BLE001 - 老对象没有 compute_id
        return False


def _evidence_check(*, trial: Mapping | None, build,
                    require: bool) -> tuple[bool, str]:
    """trial 必须来自真实执行，且 build_id 与本次构建一致（防跨 build 复用）。"""
    if trial is None:
        return (not require), "no trial"
    trial = dict(trial)
    outcome = str(trial.get("outcome") or "")
    unknown_outcome = outcome in ("", "unknown")
    execution_id = str(trial.get("execution_id") or "")
    trial_build = str(trial.get("build_id") or "")
    build_id = str(getattr(build, "build_id", "") or "")
    if unknown_outcome and not execution_id:
        return False, "trial has neither outcome nor execution_id"
    if trial_build and build_id and trial_build != build_id:
        return False, f"build mismatch: trial={trial_build} build={build_id}"
    if not trial_build and build_id:
        return False, "trial build_id missing: cannot attribute evidence"
    return True, f"outcome={outcome or 'unknown'} execution={execution_id or 'unknown'}"


def _verification_problems(record: Mapping, *, schema: str,
                           statuses: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    if str(record.get("schema") or "") != schema:
        problems.append("schema")
    if "confirmed" in record:
        problems.append("confirmed_field")
    status = str(record.get("status") or "")
    if status not in statuses:
        problems.append("status")
    if bool(record.get("verified")) != (status == "verified"):
        problems.append("verified_status_mismatch")
    return problems


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "POLICY_VERSION", "SCOPES", "VERDICT_FIELDS",
    "VERIFICATION_SCHEMA", "VERIFICATION_STATUSES", "VERIFICATION_DIAGNOSES",
    "PolicyError", "Check", "Decision", "VerificationRequest", "AdoptionPolicy",
    "prune_verdict_fields",
]
