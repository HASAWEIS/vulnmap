"""V2 P2：VulnerabilityCandidate —— 单端执行产生的候选（不是结论）。

Candidate 只证明“这个输入在这套构建上崩了”，并引用可校验的证据哈希：
  - input_sha256：崩溃输入内容哈希（原始字节在 evidence 里另存一份）；
  - evidence_sha256：主证据（ASAN 崩溃日志）内容哈希；
  - stack_hash：triage（D3）同口径签名哈希，用于去重，不是 root cause 结论；
  - state：P2 只产出 `new`，验证/复核状态由 P3 推进。

硬约束：本模块不产出 `confirmed/verified/exploitable` 等结论字段；
独立验证需要 vuln/fix 两端或服务行为差分（P3），单端 fuzz 永远只是 candidate。

字段契约：
  id / task / input_sha256 / crash_type / stack_hash / evidence_sha256 / state
扩展字段（审计需要）：
  schema / exec_id / detail / created_at
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .hypotheses import VERDICT_KEYS

SCHEMA = "vulnmap.candidate.v1"

# P2 只生产 new；后续状态留给 P3（验证/复核），不得在此伪造终点结论
STATES = ("new", "needs_evidence", "rejected")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CandidateError(ValueError):
    """Candidate 契约错误。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _keys(value) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, inner in value.items():
            out.add(str(key))
            out |= _keys(inner)
    elif isinstance(value, list):
        for inner in value:
            out |= _keys(inner)
    return out


@dataclass
class Candidate:
    id: str
    task_id: str
    input_sha256: str
    crash_type: str
    stack_hash: str
    evidence_sha256: str
    state: str = "new"
    exec_id: str = ""
    detail: dict = field(default_factory=dict)
    created_at: str = ""
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "id": self.id,
            "task": self.task_id,
            "task_id": self.task_id,      # SQLite/查询别名，与 task 同值
            "input_sha256": self.input_sha256,
            "crash_type": self.crash_type,
            "stack_hash": self.stack_hash,
            "evidence_sha256": self.evidence_sha256,
            "state": self.state,
            "exec_id": self.exec_id,
            "detail": dict(self.detail),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "Candidate":
        if not isinstance(doc, dict):
            raise CandidateError("candidate doc must be a dict")
        return cls(
            id=str(doc.get("id") or ""),
            task_id=str(doc.get("task_id") or doc.get("task") or ""),
            input_sha256=str(doc.get("input_sha256") or ""),
            crash_type=str(doc.get("crash_type") or ""),
            stack_hash=str(doc.get("stack_hash") or ""),
            evidence_sha256=str(doc.get("evidence_sha256") or ""),
            state=str(doc.get("state") or "new"),
            exec_id=str(doc.get("exec_id") or ""),
            detail=dict(doc.get("detail") or {}),
            created_at=str(doc.get("created_at") or ""),
            schema=str(doc.get("schema") or SCHEMA),
        )

    def validate(self) -> None:
        if not SAFE_ID.match(self.id or ""):
            raise CandidateError(f"unsafe candidate id: {self.id!r}")
        if not self.task_id.strip():
            raise CandidateError(f"{self.id}: task is required")
        if not HEX64.match(self.input_sha256 or ""):
            raise CandidateError(f"{self.id}: input_sha256 must be 64 hex chars")
        if not HEX64.match(self.evidence_sha256 or ""):
            raise CandidateError(f"{self.id}: evidence_sha256 must be 64 hex chars")
        if not self.crash_type.strip():
            raise CandidateError(f"{self.id}: crash_type is required")
        if not self.stack_hash.strip() or any(c.isspace() for c in self.stack_hash):
            raise CandidateError(f"{self.id}: stack_hash must be non-empty text")
        if self.state not in STATES:
            raise CandidateError(
                f"{self.id}: state must be one of {STATES}")
        if not isinstance(self.detail, dict):
            raise CandidateError(f"{self.id}: detail must be a dict")
        for key in _keys(self.to_dict()):
            if key in VERDICT_KEYS:
                raise CandidateError(
                    f"{self.id}: candidate must not carry verdict field {key!r}")


def validate_candidate(doc: Candidate | dict) -> None:
    if not isinstance(doc, Candidate):
        if not isinstance(doc, dict):
            raise CandidateError("candidate doc must be a dict")
        # from_dict 只保留契约字段：未知的结论字段必须在原始 doc 上拒绝
        for key in _keys(doc):
            if key in VERDICT_KEYS:
                raise CandidateError(
                    f"candidate must not carry verdict field {key!r}")
        doc = Candidate.from_dict(doc)
    doc.validate()


def validate(items: list[dict]) -> None:
    if not isinstance(items, list):
        raise CandidateError("candidates must be a list")
    ids: set[str] = set()
    for item in items:
        cand = Candidate.from_dict(item)
        cand.validate()
        if cand.id in ids:
            raise CandidateError(f"duplicate candidate id: {cand.id}")
        ids.add(cand.id)


def from_crash(crash: dict, *, task_id: str, candidate_id: str,
               exec_id: str = "", plan_sha256: str = "",
               build_sha256: str = "", input_evidence_sha256: str = "",
               log_evidence_sha256: str = "", source: str = "fuzz:d2") -> Candidate:
    """把执行器的一条崩溃记录转成 Candidate（不判定可利用性）。"""
    data = crash.get("input_bytes") or b""
    input_sha = str(crash.get("input_sha256") or sha256_hex(data))
    log = str(crash.get("log") or "")
    log_sha = str(log_evidence_sha256 or sha256_hex(log.encode("utf-8")))
    parsed = crash.get("parsed") or {}
    diagnostic_valid = bool(crash.get("diagnostic_valid", True))
    detail = {
        "source": source,
        "exec_id": exec_id,
        "plan_sha256": plan_sha256,
        "build_sha256": build_sha256,
        "input_sha256": input_sha,
        "input_size": len(data),
        "input_evidence_sha256": input_evidence_sha256,
        "log_evidence_sha256": log_sha,
        "input_path": str(crash.get("input_path") or ""),
        "log_path": str(crash.get("log_path") or ""),
        "access": parsed.get("access"),
        "access_size": parsed.get("access_size"),
        "function": parsed.get("function"),
        "file": parsed.get("file"),
        "line": int(parsed.get("line") or 0),
        "frames": list(parsed.get("frames") or []),
        "diagnostic_valid": diagnostic_valid,
        "scope": "single_build_only",   # 单端执行：只到 candidate，不越过验证
    }
    return Candidate(
        id=candidate_id,
        task_id=task_id,
        input_sha256=input_sha,
        crash_type=str(crash.get("crash_type") or parsed.get("crash_type") or ""),
        stack_hash=str(crash.get("stack_hash") or ""),
        evidence_sha256=log_sha,
        # 诊断无效的崩溃保留为候选线索，但降到 needs_evidence
        state="new" if diagnostic_valid else "needs_evidence",
        exec_id=exec_id,
        detail=detail,
        created_at=now(),
    )


def build_candidates(crashes: list[dict], *, task_id: str, exec_id: str = "",
                     plan_sha256: str = "", build_sha256: str = "",
                     max_candidates: int = 8) -> list[Candidate]:
    """把崩溃记录去重、稳定排序后编号为 C1..Cn（同 stack_hash 只留第一条）。"""
    seen: set[str] = set()
    unique: list[dict] = []
    for crash in crashes or []:
        stack_hash = str(crash.get("stack_hash") or "")
        if not stack_hash or stack_hash in seen:
            continue
        seen.add(stack_hash)
        unique.append(crash)
    unique.sort(key=lambda c: (str(c.get("stack_hash") or ""),
                               str(c.get("input_sha256") or "")))
    out: list[Candidate] = []
    for index, crash in enumerate(unique[:max_candidates], start=1):
        out.append(from_crash(
            crash, task_id=task_id, candidate_id=f"C{index}", exec_id=exec_id,
            plan_sha256=plan_sha256, build_sha256=build_sha256))
    return out


def dump(items: list[Candidate] | list[dict]) -> str:
    docs = [c.to_dict() if isinstance(c, Candidate) else dict(c) for c in items]
    return json.dumps(docs, ensure_ascii=False, indent=2) + "\n"
