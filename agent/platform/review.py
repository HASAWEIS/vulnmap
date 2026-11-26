"""V2 P3：独立复核 —— 只做“降级/确认证据链”，不越过验证结论。

Reviewer 回答三个问题，**全部只读证据**：

1. **证据完整性**：候选/验证引用的每个 sha256 都在 EvidenceStore 里，
   且文件内容复算等于该 sha256（缺失 → `needs_evidence`，篡改 → `reject`）；
2. **根因是否落地**：候选是否带崩溃类型与至少一个真实位置
   （function 或栈帧），诊断是否有效；
3. **验证结论是否成立**：verification 是否存在、`verified=true`、
   kind 是否就是该 benchmark 的判据、主证据是否可复算。

硬约束（代码强制）：

- **只能降级，不能升级**：`verification.verified=false` 时复核结论必然不是
  `accept`；Reviewer 没有“我认为它成立”的分支；
- **不接受凭空结论**：`accept` 要求 verification 的主证据 sha256 能在库里复算，
  否则转 `needs_evidence`；
- **不重复造标签**：Reviewer 不写 `confirmed/exploitable`，
  只写 `verdict(accept|reject|needs_evidence)`，终局阶段由状态机给出。

字段契约：
  review_id / task_id / verification_id / candidate_id / verdict / reason /
  evidence_sha256 / checks / blockers

V3 W3（V3-019）追加**只读桥**：`handoff_items` / `open_handoff_item` /
`review_handoff_item` / `handoff_report` 把
[`adaptive.handoff`](adaptive/handoff.py) 的待复核项队列接到复核者这一侧。
边界写死在这里：

1. **两条链不混**：本条链的对象是**原始执行记录**（`exec.finished` + 内容寻址
   证据），复核者只读原始记录本体并复算哈希，**不接受**模型摘要、候选摘要或
   `research.json` 里的任何 `summary/claim/conclusion`——递摘要直接
   `model_summary_not_accepted`；
2. **run_review 仍是 verification 记录的唯一复核入口**：本桥不改 `run_review`
   的任何语义、不替它写 verdict、更不会把交接项算成“已验证”；
   `Review` 的 `accept/reject/needs_evidence` 只由 `run_review` 产出，
   交接项的 `accepted/rejected/needs_evidence` 只落在 `handoff_verdicts` 台账；
3. **只加桥，不改状态机**：`open_handoff_item` / `review_handoff_item` 只写
   待复核项与定性记录，不迁任务状态、不写 `verifications`、不写 `reviews`；
   状态怎么走仍由调用方按 `task.TRANSITIONS` 决定；
4. **缺证据如实标**：`pending` / `needs_evidence` 一律不算结论，报告只把
   `accepted` 且三方身份（`run_id`/`execution_id`/`evidence_sha256`）齐全的项
   当可追溯结论（口径与 `casepack` 的 `handoff.json` 同源）。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .verify import BENCHMARK_KIND

SCHEMA = "vulnmap.review.v1"
VERDICTS = ("accept", "reject", "needs_evidence")
CHECKS = ("candidate_present", "verification_present", "benchmark_criterion",
          "verification_conclusion", "evidence_complete", "evidence_hash_match",
          "root_cause_present", "input_binding")

# 证据缺口（可补材料后重进 REVIEW）；其余失败一律 reject
GAP_CHECKS = ("evidence_complete", "evidence_hash_match")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReviewError(ValueError):
    """复核契约/顺序错误。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    h = sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Review:
    review_id: str
    task_id: str
    verification_id: str
    candidate_id: str
    verdict: str
    reason: str
    evidence_sha256: str
    checks: dict = field(default_factory=dict)
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    created_at: str = ""
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "review_id": self.review_id,
            "task_id": self.task_id,
            "verification_id": self.verification_id,
            "candidate_id": self.candidate_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence_sha256": self.evidence_sha256,
            "checks": dict(self.checks),
            "blockers": list(self.blockers),
            "detail": dict(self.detail),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "Review":
        if not isinstance(doc, dict):
            raise ReviewError("review doc must be a dict")
        return cls(
            review_id=str(doc.get("review_id") or ""),
            task_id=str(doc.get("task_id") or ""),
            verification_id=str(doc.get("verification_id") or ""),
            candidate_id=str(doc.get("candidate_id") or ""),
            verdict=str(doc.get("verdict") or ""),
            reason=str(doc.get("reason") or ""),
            evidence_sha256=str(doc.get("evidence_sha256") or ""),
            checks=dict(doc.get("checks") or {}),
            blockers=list(doc.get("blockers") or []),
            detail=dict(doc.get("detail") or {}),
            created_at=str(doc.get("created_at") or ""),
            schema=str(doc.get("schema") or SCHEMA),
        )

    def validate(self) -> None:
        if not SAFE_ID.match(self.review_id or ""):
            raise ReviewError(f"unsafe review_id: {self.review_id!r}")
        if not self.task_id:
            raise ReviewError(f"{self.review_id}: task_id required")
        if self.verdict not in VERDICTS:
            raise ReviewError(f"{self.review_id}: verdict must be one of {VERDICTS}")
        if self.evidence_sha256 and not HEX64.match(self.evidence_sha256):
            raise ReviewError(
                f"{self.review_id}: evidence_sha256 must be 64 hex chars")
        if "confirmed" in json.dumps(self.to_dict(), ensure_ascii=False):
            raise ReviewError(f"{self.review_id}: review must not carry 'confirmed'")


def _next_id(existing: list[dict]) -> str:
    used = {str(item.get("review_id") or "") for item in existing}
    index = 1
    while f"R{index}" in used:
        index += 1
    return f"R{index}"


def _evidence_shas(candidate: dict | None, verification: dict) -> list[str]:
    """候选 + 验证引用到的全部 sha256（去重、保持稳定顺序）。"""
    shas: list[str] = []

    def add(value) -> None:
        text = str(value or "").strip()
        if text and text not in shas:
            shas.append(text)

    if candidate:
        add(candidate.get("evidence_sha256"))
        detail = candidate.get("detail") or {}
        add(detail.get("input_evidence_sha256"))
        add(detail.get("log_evidence_sha256"))
        for item in detail.get("evidence") or []:
            if isinstance(item, dict):
                add(item.get("sha256"))
    add(verification.get("evidence_sha256"))
    for item in (verification.get("detail") or {}).get("evidence") or []:
        if isinstance(item, dict):
            add(item.get("sha256"))
    return shas


def _root_cause(candidate: dict | None) -> tuple[bool, dict]:
    if not candidate:
        return False, {}
    detail = candidate.get("detail") or {}
    frames = list(detail.get("frames") or [])
    evidence = {
        "crash_type": str(candidate.get("crash_type") or ""),
        "function": str(detail.get("function") or ""),
        "file": str(detail.get("file") or ""),
        "line": int(detail.get("line") or 0),
        "frames": len(frames),
        "diagnostic_valid": bool(detail.get("diagnostic_valid", False)),
        "stack_hash": str(candidate.get("stack_hash") or ""),
    }
    has_site = bool(evidence["function"]) or bool(evidence["file"]) \
        or evidence["frames"] > 0
    ok = bool(evidence["crash_type"]) and bool(evidence["stack_hash"]) \
        and has_site and evidence["diagnostic_valid"]
    return ok, evidence


def review_checks(task_id: str, store, verification: dict,
                  candidate: dict | None) -> tuple[dict, list[str], dict]:
    """只读检查：返回 (checks, blockers, extra)。不写库、不迁移状态。"""
    checks = {name: False for name in CHECKS}
    blockers: list[str] = []
    benchmark = str((store.get_task(task_id) or {}).get("benchmark") or "").lower()
    detail = verification.get("detail") or {}

    checks["candidate_present"] = bool(candidate) and \
        str(candidate.get("task_id") or candidate.get("task") or "") == task_id
    if not checks["candidate_present"]:
        blockers.append("candidate_missing")

    checks["verification_present"] = bool(verification.get("verification_id"))
    if not checks["verification_present"]:
        blockers.append("verification_missing")

    want_kind = BENCHMARK_KIND.get(benchmark)
    policy = detail.get("policy") or {}
    checks["benchmark_criterion"] = bool(
        want_kind and verification.get("kind") == want_kind
        and (policy.get("benchmark") in (None, "", benchmark))
        and str(policy.get("kind") or want_kind) == want_kind)
    if not checks["benchmark_criterion"]:
        blockers.append(
            f"criterion_mismatch:kind={verification.get('kind')!r},"
            f" benchmark={benchmark or 'unknown'} wants {want_kind!r}")

    checks["verification_conclusion"] = bool(verification.get("verified")) and \
        str(verification.get("status") or "") == "verified"
    if not checks["verification_conclusion"]:
        blockers.append(
            f"verification_not_verified:status="
            f"{verification.get('status') or 'unknown'}")

    shas = _evidence_shas(candidate, verification)
    rows = {str(row["sha256"]): row for row in store.list_evidence(task_id)}
    missing = [s for s in shas if s not in rows]
    checks["evidence_complete"] = bool(shas) and not missing
    if not shas:
        blockers.append("evidence_not_referenced")
    for value in missing:
        blockers.append(f"evidence_not_in_store:{value[:12]}")

    mismatched: list[str] = []
    for value in shas:
        row = rows.get(value)
        if row is None:
            continue
        path = Path(str(row.get("path") or ""))
        if not path.is_file() or sha256_file(path) != value:
            mismatched.append(value)
    checks["evidence_hash_match"] = not mismatched and checks["evidence_complete"]
    for value in mismatched:
        blockers.append(f"evidence_hash_mismatch:{value[:12]}")

    root_ok, root_evidence = _root_cause(candidate)
    checks["root_cause_present"] = root_ok
    if not root_ok:
        blockers.append("root_cause_unsubstantiated")

    binding = detail.get("candidate_binding") or {}
    checks["input_binding"] = bool(binding.get("same_as_candidate")) and \
        bool(binding.get("candidate_input_sha256"))
    if not checks["input_binding"]:
        blockers.append("input_not_bound_to_candidate")

    extra = {"root_cause": root_evidence, "benchmark": benchmark,
             "evidence_shas": len(shas), "missing": missing,
             "mismatched": mismatched, "policy": policy}
    return checks, blockers, extra


def derive_verdict(checks: dict) -> str:
    """证据缺口 → needs_evidence；其余不成立 → reject；全成立 → accept。

    没有任何分支能把 `verification_conclusion` 的 False 变成 accept。
    """
    if any(not checks.get(name) for name in GAP_CHECKS):
        return "needs_evidence"
    if not all(checks.get(name) for name in CHECKS):
        return "reject"
    return "accept"


def run_review(task_id: str, store, bus, *, verification_id: str = "",
               evidence_root=None) -> dict:
    """执行一次复核：VERIFYING → REVIEW / NEEDS_EVIDENCE / REJECTED。"""
    task = store.get_task(task_id)
    if task["state"] not in ("VERIFYING", "REVIEW"):
        raise ReviewError(
            f"review requires VERIFYING or REVIEW, got {task['state']}")

    verifications = store.list_verifications(task_id)
    if not verifications:
        raise ReviewError(
            f"no verification for {task_id}; run `verify` first")
    if verification_id:
        row = store.get_verification(task_id, verification_id)
        if row is None:
            raise ReviewError(
                f"verification {verification_id!r} not found in {task_id}")
        verification = row
    else:
        verification = verifications[-1]

    candidate = store.get_candidate(task_id, str(verification.get("candidate_id") or ""))
    checks, blockers, extra = review_checks(task_id, store, verification, candidate)
    verdict = derive_verdict(checks)

    # 只能降级：verification 未通过时绝不允许 accept
    if verdict == "accept" and not verification.get("verified"):
        verdict = "reject"
        blockers = blockers + ["review_cannot_upgrade_verification"]

    existing = store.list_reviews(task_id)
    rid = _next_id(existing)
    reason = ("all checks passed" if verdict == "accept"
              else "; ".join(blockers) or "unspecified")
    review = Review(
        review_id=rid, task_id=task_id,
        verification_id=str(verification.get("verification_id") or ""),
        candidate_id=str(verification.get("candidate_id") or ""),
        verdict=verdict, reason=reason,
        evidence_sha256=str(verification.get("evidence_sha256") or ""),
        checks=checks, blockers=blockers,
        detail={
            "benchmark": extra["benchmark"],
            "verification_verified": bool(verification.get("verified")),
            "root_cause": extra["root_cause"],
            "evidence_referenced": extra["evidence_shas"],
            "missing_evidence": extra["missing"],
            "hash_mismatch": extra["mismatched"],
            "criterion": (verification.get("detail") or {}).get("criterion", ""),
            "policy": extra["policy"],
            "upgrade_forbidden": True,
            "scope": "review_only_downgrade",
        },
        created_at=now(),
    )
    review.validate()
    saved = store.save_review(review)
    bus.emit(task_id, "review.completed", stage="REVIEW", payload={
        "review_id": rid,
        "verification_id": review.verification_id,
        "candidate_id": review.candidate_id,
        "verdict": verdict,
        "checks": checks,
        "blockers": blockers,
        "verification_verified": bool(verification.get("verified")),
        "evidence_sha256": review.evidence_sha256,
    })

    target = {"accept": "REVIEW", "needs_evidence": "NEEDS_EVIDENCE",
              "reject": "REJECTED"}[verdict]
    if task["state"] != target:
        store.transition(task_id, target,
                         reason=f"{rid} {verdict}: {reason}"[:400])
    return {
        "task_id": task_id,
        "state": store.get_task(task_id)["state"],
        "review_id": rid,
        "verification_id": review.verification_id,
        "candidate_id": review.candidate_id,
        "verdict": verdict,
        "reason": reason,
        "checks": checks,
        "blockers": blockers,
        "verification_verified": bool(verification.get("verified")),
        "review": saved,
    }


def dump(items: list[Review] | list[dict]) -> str:
    docs = [i.to_dict() if isinstance(i, Review) else dict(i) for i in items]
    return json.dumps(docs, ensure_ascii=False, indent=2) + "\n"


# ====================================================================== W3 交接桥
#: 交接桥的口径（与 `casepack.HANDOFF_NOTE` 说的是同一句话）
HANDOFF_BOUNDARY = (
    "待复核项队列 → 独立复核者：复核者只读原始记录本体并复算哈希，"
    "不接受模型摘要；只有 accepted 且 run_id/execution_id/evidence_sha256 "
    "齐全的项算可追溯结论，pending/needs_evidence 一律不算结论，"
    "也不进 verify/review 的 verified 计数")

#: 交接桥**不写**的东西（给调用方的显式承诺，免得多出一条第二套裁决）
HANDOFF_TOUCHES = ("review_items", "handoff_verdicts", "evidence")
HANDOFF_NEVER_TOUCHES = ("verifications", "reviews", "task_state")


def _handoff_module():
    """延迟导入：`review` 是 `agent.platform` 的常驻导出，导入期不拖研究子系统。"""
    from .adaptive import handoff                 # noqa: PLC0415 - 见 docstring
    return handoff


def handoff_items(task_id: str, store, *, status: str = "") -> list[dict]:
    """只读：本任务的待复核项队列（可按 `pending/accepted/...` 过滤）。

    返回台账原文（`vulnmap.adaptive.review_item.v1` 字段），不改任何记录；
    `status` 不认识时抛 `ReviewError`，不静默返回空列表。
    """
    handoff = _handoff_module()
    text = str(status or "")
    if text and text not in handoff.STATUSES:
        raise ReviewError(
            f"handoff status must be one of {handoff.STATUSES}, got {text!r}")
    return store.list_review_items(task_id, status=text)


def open_handoff_item(task_id: str, store, *, execution_id: str,
                      evidence_root=None, revision_id: str = "",
                      build_id: str = "", policy_version: str = "",
                      run_id: str = "") -> dict:
    """把一次**真实执行**封存成待复核项（幂等：三方身份相同只开一条）。

    薄转发到 `adaptive.handoff.open_pending`：不写 `verifications`、不写
    `reviews`、不迁任务状态。`run_id` 只做校验（必须等于派生值）。
    """
    handoff = _handoff_module()
    if not str(execution_id or "").strip():
        raise ReviewError("open_handoff_item requires execution_id")
    return handoff.open_pending(
        store, task_id, execution_id=execution_id, evidence_root=evidence_root,
        revision_id=revision_id, build_id=build_id,
        policy_version=policy_version, run_id=run_id)


def review_handoff_item(task_id: str, store, item_id: str, *,
                        verifier=None, evidence_root=None, revisions=None,
                        policy_version: str = "") -> dict:
    """复核一条待复核项（独立复核者只读原始记录；写 verdict + 项状态）。

    薄转发到 `adaptive.handoff.review_item`：返回
    `{"task_id", "item", "verdict", "status"}`。它不碰 `reviews` 表，
    也不改任务状态——那些仍归 `run_review` 与状态机。
    """
    handoff = _handoff_module()
    result = handoff.review_item(
        store, task_id, item_id, verifier=verifier,
        evidence_root=evidence_root, revisions=revisions,
        policy_version=policy_version)
    item = dict(result.get("item") or {})
    verdict = dict(result.get("verdict") or {})
    return {"task_id": task_id, "item_id": str(item.get("item_id") or item_id),
            "status": str(item.get("status") or ""), "item": item,
            "verdict": verdict,
            "traceable": str(item.get("status") or "") == "accepted",
            "note": HANDOFF_BOUNDARY}


def handoff_report(task_id: str, store, *, revisions=None) -> dict:
    """只读：交接报告视图（`adaptive.handoff.handoff_view` 的原样转发）。

    只有 accepted 且三方身份齐全的项进 `conclusions`；其余如实标
    `pending/accepted/rejected/needs_evidence`，不补默认值。
    """
    handoff = _handoff_module()
    return handoff.handoff_view(store, task_id, revisions=revisions)
