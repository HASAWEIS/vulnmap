"""V3-017 补丁工作流的四个契约对象：根因、提案、测试、复核。

对应《VULNMAP-V3 完整升级方案》§12「独立验证：发现能力增强，判据不放松」与
§13「可选 PatchWorkflow 与经验库」。这里只定义**可审计的数据形状与硬约束**，
真正的文件读写 / 命令执行在 `workspace.py`，编排在 `workflow.py`。

四条不可越的线：

1. **只进 `patch_validation`**：`PatchReview.scope` 恒为 `patch_validation`；
   补丁通过独立测试只说明「这份工件构建得起来、原版触发、补丁不触发、
   正常回归通过、回滚回原哈希」，不生成也不改写任何漏洞结论。
2. **裁决字段不落在补丁侧**：`verified/confirmed/verdict/...` 一出现就被
   `policy.prune_verdict_fields` 剥掉并视为违规（`PatchError`），
   漏洞 `confirmed` 只能由既有 `agent.platform.verify` 产生。
3. **提案永远不是「已应用」**：`PatchProposal.status` 只允许 `proposed`，
   `applied_to_origin` 只允许 `False`；写错就直接拒绝构造对象。
4. **证据可复算**：根因必须带原始 finding 引用与至少一条可复算证据
   （`EvidenceRef.sha256` 由本模块现场计算，不接受调用方口头声明）。

本模块不执行命令、不写库、不改 origin。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from ..contracts import digest_of, now
from ..policy import VERDICT_FIELDS, prune_verdict_fields

#: 四个 schema 名（一个包一个版本，读旧文档时按 schema 拒绝）
SCHEMA = "vulnmap.adaptive.patch.v1"
SCHEMA_VERSION = 1
PATCH_VERSION = "v3-p5"

ROOT_CAUSE_SCHEMA = "vulnmap.adaptive.patch.root_cause.v1"
PROPOSAL_SCHEMA = "vulnmap.adaptive.patch.proposal.v1"
TEST_SCHEMA = "vulnmap.adaptive.patch.test.v1"
REVIEW_SCHEMA = "vulnmap.adaptive.patch.review.v1"

#: 提案状态只有一种：提出（不是 applied / accepted / merged）
PROPOSAL_STATUSES = ("proposed",)
#: 测试结论（blocked = 前置条件不成立，连跑都没跑）
TEST_STATUSES = ("passed", "failed", "blocked")
#: 复核结论（只管工程可采纳，不管漏洞）
REVIEW_STATUSES = ("accepted", "rejected")

#: 根因来源（§12：observed / upstream_assertion / synthesized_state / model_hypothesis）
CLAIM_SOURCES = ("observed", "upstream_assertion",
                 "synthesized_state", "model_hypothesis")
#: 期望退出码的写法：`zero` / `nonzero` / 显式整数
EXPECT_ZERO = "zero"
EXPECT_NONZERO = "nonzero"

#: 路径与摘要
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_REL = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/-]*$")


class PatchError(ValueError):
    """补丁工件非法（路径越界、证据不可复算、夹带裁决字段……）。"""


class PatchUnsupported(PatchError):
    """没有源码/不支持的目标：直接标 unsupported，不假装能生成补丁。"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(doc) -> bytes:
    """确定性 JSON（同一输入恒得同一字节）：补丁工件全部走这里落盘。"""
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False)
            + "\n").encode("utf-8")


def safe_relpath(value: str) -> str:
    """把路径规范成「相对、无 ../、无绝对前缀」的 repo 内路径。"""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        raise PatchError("path required")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise PatchError(f"absolute path not allowed: {value!r}")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise PatchError(f"path escapes root: {value!r}")
    if not parts:
        raise PatchError(f"empty path: {value!r}")
    rel = "/".join(parts)
    if not SAFE_REL.match(rel):
        raise PatchError(f"unsafe path: {value!r}")
    return rel


def _clean(value) -> str:
    return str(value or "").strip()


def _as_int(value, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ====================================================================== 证据
@dataclass(frozen=True)
class EvidenceRef:
    """一条可复算的证据：路径 + 现场算出的 sha256 + 字节数。"""

    path: str
    sha256: str
    size: int = 0
    kind: str = "file"
    rel: str = ""

    def __post_init__(self) -> None:
        if not _clean(self.path):
            raise PatchError("evidence path required")
        if not HEX64.match(str(self.sha256 or "")):
            raise PatchError(f"evidence sha256 must be 64 hex: {self.sha256!r}")
        if _as_int(self.size, default=-1) < 0:
            raise PatchError("evidence size must be >= 0")

    def verify(self) -> bool:
        """现场重算：文件还在、字节数一致、sha256 一致才算证据成立。"""
        path = Path(self.path)
        try:
            data = path.read_bytes()
        except OSError:
            return False
        return len(data) == self.size and sha256_bytes(data) == self.sha256

    def to_dict(self) -> dict:
        return {"path": self.path, "rel": self.rel, "sha256": self.sha256,
                "size": self.size, "kind": self.kind}

    @classmethod
    def from_path(cls, path: Path | str, *, kind: str = "file",
                  base: Path | None = None) -> "EvidenceRef":
        src = Path(path).expanduser()
        try:
            data = src.read_bytes()
        except OSError as exc:
            raise PatchError(f"evidence unreadable: {src} ({exc})") from exc
        resolved = src.resolve()
        rel = ""
        if base is not None:
            try:
                rel = str(resolved.relative_to(Path(base).resolve()))
            except ValueError:
                rel = ""
        return cls(path=str(resolved), sha256=sha256_bytes(data),
                   size=len(data), kind=kind, rel=rel.replace("\\", "/"))

    @classmethod
    def from_dict(cls, doc: Mapping) -> "EvidenceRef":
        if not isinstance(doc, Mapping):
            raise PatchError("evidence entry must be an object")
        return cls(path=_clean(doc.get("path")), sha256=_clean(doc.get("sha256")),
                   size=_as_int(doc.get("size"), default=-1),
                   kind=_clean(doc.get("kind")) or "file",
                   rel=_clean(doc.get("rel")))


# ====================================================================== finding
@dataclass(frozen=True)
class FindingRef:
    """原始 finding 的只读引用：任务 / 候选 / 输入哈希 / 既有验证编号。

    `verification_status` 是既有 verify 台账的回显（`verified` / `not_verified`），
    不是补丁侧的裁决；这里没有、也不接受 `confirmed` 字段。
    """

    task_id: str
    candidate_id: str
    evidence_sha256: str = ""
    input_sha256: str = ""
    crash_type: str = ""
    verification_ids: tuple[str, ...] = ()
    verification_status: str = "not_verified"
    source: str = "platform.store"

    def __post_init__(self) -> None:
        if not _clean(self.task_id):
            raise PatchError("finding.task_id required")
        if not _clean(self.candidate_id):
            raise PatchError("finding.candidate_id required")
        if self.verification_status not in ("verified", "not_verified"):
            raise PatchError(
                f"finding.verification_status unsupported: "
                f"{self.verification_status!r}")
        for key in self.evidence_sha256, self.input_sha256:
            if key and not HEX64.match(key):
                raise PatchError(f"finding digest must be 64 hex: {key!r}")

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id, "candidate_id": self.candidate_id,
            "evidence_sha256": self.evidence_sha256,
            "input_sha256": self.input_sha256,
            "crash_type": self.crash_type,
            "verification_ids": list(self.verification_ids),
            "verification_status": self.verification_status,
            "source": self.source,
            "note": "只读引用既有 finding/验证；补丁侧不改写漏洞结论",
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "FindingRef":
        if not isinstance(doc, Mapping):
            raise PatchError("finding must be an object")
        return cls(
            task_id=_clean(doc.get("task_id")),
            candidate_id=_clean(doc.get("candidate_id")),
            evidence_sha256=_clean(doc.get("evidence_sha256")),
            input_sha256=_clean(doc.get("input_sha256")),
            crash_type=_clean(doc.get("crash_type")),
            verification_ids=tuple(str(v) for v in doc.get("verification_ids") or ()),
            verification_status=_clean(doc.get("verification_status"))
            or "not_verified",
            source=_clean(doc.get("source")) or "platform.store",
        )


# ====================================================================== 根因
@dataclass(frozen=True)
class RootCause:
    """根因陈述：定位 + 来源 + 论证 + 证据 + 原始 finding。"""

    root_cause_id: str
    task_id: str
    candidate_id: str
    file: str
    line: int
    claim: str
    argument: str
    snippet: str = ""
    snippet_sha256: str = ""
    end_line: int = 0
    function: str = ""
    evidence: tuple[EvidenceRef, ...] = ()
    finding: FindingRef | None = None
    created_at: str = ""
    schema: str = ROOT_CAUSE_SCHEMA

    def __post_init__(self) -> None:
        if not SAFE_ID.match(self.root_cause_id or ""):
            raise PatchError(f"unsafe root_cause_id: {self.root_cause_id!r}")
        if not _clean(self.task_id):
            raise PatchError("root cause: task_id required")
        if not _clean(self.candidate_id):
            raise PatchError("root cause: candidate_id required")
        object.__setattr__(self, "file", safe_relpath(self.file))
        start = _as_int(self.line, default=0)
        end = _as_int(self.end_line, default=0) or start
        if start < 1:
            raise PatchError("root cause: line must be >= 1")
        if end < start:
            raise PatchError("root cause: end_line must be >= line")
        object.__setattr__(self, "line", start)
        object.__setattr__(self, "end_line", end)
        if self.claim not in CLAIM_SOURCES:
            raise PatchError(
                f"root cause claim must be one of {CLAIM_SOURCES}, "
                f"got {self.claim!r}")
        if len(_clean(self.argument)) < 8:
            raise PatchError("root cause: argument required (>= 8 chars)")
        object.__setattr__(self, "evidence", tuple(self.evidence or ()))
        if not self.evidence and not (
                self.finding and (self.finding.evidence_sha256
                                  or self.finding.verification_ids)):
            raise PatchError(
                "root cause needs at least one recomputable evidence ref "
                "or a finding with evidence/verification refs")
        if self.snippet and self.snippet_sha256 != sha256_bytes(
                self.snippet.encode("utf-8")):
            raise PatchError("root cause: snippet sha256 does not match snippet")
        object.__setattr__(self, "created_at", self.created_at or now())

    @property
    def digest(self) -> str:
        return digest_of(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "patch_version": PATCH_VERSION,
            "root_cause_id": self.root_cause_id,
            "task_id": self.task_id, "candidate_id": self.candidate_id,
            "file": self.file, "line": self.line, "end_line": self.end_line,
            "function": self.function, "claim": self.claim,
            "argument": self.argument,
            "snippet": self.snippet, "snippet_sha256": self.snippet_sha256,
            "evidence": [ref.to_dict() for ref in self.evidence],
            "finding": self.finding.to_dict() if self.finding else None,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "RootCause":
        if not isinstance(doc, Mapping):
            raise PatchError("root cause must be an object")
        if _clean(doc.get("schema")) != ROOT_CAUSE_SCHEMA:
            raise PatchError(f"unknown root cause schema: {doc.get('schema')!r}")
        finding = doc.get("finding")
        return cls(
            root_cause_id=_clean(doc.get("root_cause_id")),
            task_id=_clean(doc.get("task_id")),
            candidate_id=_clean(doc.get("candidate_id")),
            file=_clean(doc.get("file")),
            line=_as_int(doc.get("line"), default=0),
            end_line=_as_int(doc.get("end_line"), default=0),
            function=_clean(doc.get("function")),
            claim=_clean(doc.get("claim")),
            argument=_clean(doc.get("argument")),
            snippet=str(doc.get("snippet") or ""),
            snippet_sha256=_clean(doc.get("snippet_sha256")),
            evidence=tuple(EvidenceRef.from_dict(item)
                           for item in doc.get("evidence") or ()),
            finding=FindingRef.from_dict(finding) if finding else None,
            created_at=_clean(doc.get("created_at")),
        )


# ====================================================================== 提案
@dataclass(frozen=True)
class PatchProposal:
    """一份补丁提案：diff + 测试命令 + 回滚方案 + 原件哈希。

    `status` 恒为 `proposed`、`applied_to_origin` 恒为 `False`：
    生成补丁只写实验副本，**不自动应用**（§13 / §19.6）。
    """

    patch_id: str
    task_id: str
    candidate_id: str
    root_cause_id: str
    source_root: str
    diff: str
    files: tuple[dict, ...]
    origin: dict
    tests: dict
    rollback: dict
    strategy: str = ""
    status: str = "proposed"
    applied_to_origin: bool = False
    created_at: str = ""
    schema: str = PROPOSAL_SCHEMA

    def __post_init__(self) -> None:
        if not SAFE_ID.match(self.patch_id or ""):
            raise PatchError(f"unsafe patch_id: {self.patch_id!r}")
        if not _clean(self.task_id) or not _clean(self.candidate_id):
            raise PatchError("proposal: task_id/candidate_id required")
        if self.status not in PROPOSAL_STATUSES:
            raise PatchError(
                f"proposal.status must be {PROPOSAL_STATUSES}, got {self.status!r}")
        if self.applied_to_origin:
            raise PatchError("proposal must not be applied to origin")
        if not str(self.diff or "").strip():
            raise PatchError("proposal: diff required")
        if not self.files:
            raise PatchError("proposal: at least one file change required")
        if not isinstance(self.tests, dict) or not self.tests.get("trigger"):
            raise PatchError("proposal: trigger test command required")
        if not isinstance(self.rollback, dict) or not self.rollback.get("files"):
            raise PatchError("proposal: rollback plan with files required")
        object.__setattr__(self, "files", tuple(dict(f) for f in self.files))
        object.__setattr__(self, "created_at", self.created_at or now())

    @property
    def digest(self) -> str:
        return digest_of(self.to_dict())

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "patch_version": PATCH_VERSION,
            "patch_id": self.patch_id, "task_id": self.task_id,
            "candidate_id": self.candidate_id,
            "root_cause_id": self.root_cause_id,
            "status": self.status,
            "applied_to_origin": bool(self.applied_to_origin),
            "strategy": self.strategy,
            "source_root": self.source_root,
            "origin": dict(self.origin),
            "files": [dict(item) for item in self.files],
            "diff": self.diff,
            "diff_sha256": sha256_bytes(self.diff.encode("utf-8")),
            "tests": dict(self.tests),
            "rollback": dict(self.rollback),
            "created_at": self.created_at,
            "note": "status=proposed 只表示工件已生成到实验副本；未应用到原件",
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "PatchProposal":
        if not isinstance(doc, Mapping):
            raise PatchError("proposal must be an object")
        if _clean(doc.get("schema")) != PROPOSAL_SCHEMA:
            raise PatchError(f"unknown proposal schema: {doc.get('schema')!r}")
        return cls(
            patch_id=_clean(doc.get("patch_id")),
            task_id=_clean(doc.get("task_id")),
            candidate_id=_clean(doc.get("candidate_id")),
            root_cause_id=_clean(doc.get("root_cause_id")),
            source_root=_clean(doc.get("source_root")),
            diff=str(doc.get("diff") or ""),
            files=tuple(doc.get("files") or ()),
            origin=dict(doc.get("origin") or {}),
            tests=dict(doc.get("tests") or {}),
            rollback=dict(doc.get("rollback") or {}),
            strategy=_clean(doc.get("strategy")),
            status=_clean(doc.get("status")) or "proposed",
            applied_to_origin=bool(doc.get("applied_to_origin")),
            created_at=_clean(doc.get("created_at")),
        )


# ====================================================================== 测试
@dataclass(frozen=True)
class Gate:
    """一条可复核的检查项（与 policy.Check 同形，但不复用其对象）。"""

    name: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": bool(self.ok), "detail": self.detail}


@dataclass(frozen=True)
class PatchTest:
    """一次独立测试的结果：原版触发 / 补丁不触发 / 回归 / 回滚。"""

    test_id: str
    patch_id: str
    task_id: str
    status: str
    gates: tuple[Gate, ...] = ()
    runs: tuple[dict, ...] = ()
    blockers: tuple[str, ...] = ()
    proposal_sha256: str = ""
    origin: dict = field(default_factory=dict)
    independent: dict = field(default_factory=dict)
    rollback: dict = field(default_factory=dict)
    created_at: str = ""
    schema: str = TEST_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in TEST_STATUSES:
            raise PatchError(f"unknown test status: {self.status!r}")
        object.__setattr__(self, "gates", tuple(self.gates or ()))
        object.__setattr__(self, "runs",
                           tuple(dict(run) for run in (self.runs or ())))
        object.__setattr__(self, "blockers",
                           tuple(str(b) for b in (self.blockers or ())))
        object.__setattr__(self, "created_at", self.created_at or now())

    @property
    def passed(self) -> bool:
        return self.status == "passed" and not self.blockers

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "patch_version": PATCH_VERSION,
            "test_id": self.test_id, "patch_id": self.patch_id,
            "task_id": self.task_id, "status": self.status,
            "passed": self.passed,
            "gates": [gate.to_dict() for gate in self.gates],
            "runs": [dict(run) for run in self.runs],
            "blockers": list(self.blockers),
            "proposal_sha256": self.proposal_sha256,
            "origin": dict(self.origin),
            "independent": dict(self.independent),
            "rollback": dict(self.rollback),
            "created_at": self.created_at,
            "note": "通过只代表工程工件可复现；漏洞结论仍由既有 verify 决定",
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "PatchTest":
        if not isinstance(doc, Mapping):
            raise PatchError("patch test must be an object")
        if _clean(doc.get("schema")) != TEST_SCHEMA:
            raise PatchError(f"unknown test schema: {doc.get('schema')!r}")
        return cls(
            test_id=_clean(doc.get("test_id")),
            patch_id=_clean(doc.get("patch_id")),
            task_id=_clean(doc.get("task_id")),
            status=_clean(doc.get("status")),
            gates=tuple(Gate(name=_clean(g.get("name")),
                             ok=bool(g.get("ok")),
                             detail=_clean(g.get("detail")))
                        for g in doc.get("gates") or ()),
            runs=tuple(dict(r) for r in doc.get("runs") or ()),
            blockers=tuple(str(b) for b in doc.get("blockers") or ()),
            proposal_sha256=_clean(doc.get("proposal_sha256")),
            origin=dict(doc.get("origin") or {}),
            independent=dict(doc.get("independent") or {}),
            rollback=dict(doc.get("rollback") or {}),
            created_at=_clean(doc.get("created_at")),
        )


# ====================================================================== 复核
@dataclass(frozen=True)
class PatchReview:
    """补丁复核：只判 `patch_validation`（工程可采纳），不判漏洞。"""

    review_id: str
    patch_id: str
    task_id: str
    status: str
    engineering: dict
    gates: tuple[Gate, ...] = ()
    reasons: tuple[str, ...] = ()
    vulnerability: dict = field(default_factory=dict)
    proposal_sha256: str = ""
    test_sha256: str = ""
    scope: str = "patch_validation"
    created_at: str = ""
    schema: str = REVIEW_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in REVIEW_STATUSES:
            raise PatchError(f"unknown review status: {self.status!r}")
        if self.scope != "patch_validation":
            raise PatchError(f"review scope must be patch_validation: {self.scope!r}")
        object.__setattr__(self, "gates", tuple(self.gates or ()))
        object.__setattr__(self, "reasons",
                           tuple(str(r) for r in (self.reasons or ())))
        object.__setattr__(self, "created_at", self.created_at or now())
        # 补丁侧对象里永远不许出现 confirmed（与 verify 的禁令同口径）
        text = json.dumps(self.to_dict(), ensure_ascii=False, default=str)
        if "confirmed" in text:
            raise PatchError("patch review must not carry 'confirmed'")

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "patch_version": PATCH_VERSION,
            "review_id": self.review_id, "patch_id": self.patch_id,
            "task_id": self.task_id, "scope": self.scope,
            "status": self.status, "accepted": self.accepted,
            "engineering": dict(self.engineering),
            "gates": [gate.to_dict() for gate in self.gates],
            "failed": [gate.name for gate in self.gates if not gate.ok],
            "reasons": list(self.reasons),
            "vulnerability": dict(self.vulnerability),
            "proposal_sha256": self.proposal_sha256,
            "test_sha256": self.test_sha256,
            "created_at": self.created_at,
            "note": "scope=patch_validation；漏洞结论只能由 verify 产生",
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "PatchReview":
        if not isinstance(doc, Mapping):
            raise PatchError("patch review must be an object")
        if _clean(doc.get("schema")) != REVIEW_SCHEMA:
            raise PatchError(f"unknown review schema: {doc.get('schema')!r}")
        return cls(
            review_id=_clean(doc.get("review_id")),
            patch_id=_clean(doc.get("patch_id")),
            task_id=_clean(doc.get("task_id")),
            status=_clean(doc.get("status")),
            engineering=dict(doc.get("engineering") or {}),
            gates=tuple(Gate(name=_clean(g.get("name")),
                             ok=bool(g.get("ok")),
                             detail=_clean(g.get("detail")))
                        for g in doc.get("gates") or ()),
            reasons=tuple(str(r) for r in doc.get("reasons") or ()),
            vulnerability=dict(doc.get("vulnerability") or {}),
            proposal_sha256=_clean(doc.get("proposal_sha256")),
            test_sha256=_clean(doc.get("test_sha256")),
            scope=_clean(doc.get("scope")) or "patch_validation",
            created_at=_clean(doc.get("created_at")),
        )


def verdict_fields_in(document) -> tuple[str, ...]:
    """递归找文档里的裁决字段名（用于复核扫描，不修改文档）。"""
    found: list[str] = []

    def walk(node) -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                if str(key).lower() in VERDICT_FIELDS:
                    found.append(str(key))
                walk(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(document)
    return tuple(found)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "PATCH_VERSION", "ROOT_CAUSE_SCHEMA",
    "PROPOSAL_SCHEMA", "TEST_SCHEMA", "REVIEW_SCHEMA",
    "PROPOSAL_STATUSES", "TEST_STATUSES", "REVIEW_STATUSES", "CLAIM_SOURCES",
    "EXPECT_ZERO", "EXPECT_NONZERO",
    "SAFE_ID", "HEX64", "SAFE_REL", "PatchError", "PatchUnsupported",
    "sha256_bytes", "json_bytes",
    "safe_relpath", "EvidenceRef", "FindingRef", "RootCause", "PatchProposal",
    "Gate", "PatchTest", "PatchReview", "verdict_fields_in",
]
