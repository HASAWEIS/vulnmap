"""V3-019（第 3 周）：原始执行证据 → 待复核项 → 独立复核者的**交接**。

口径（《V3 完整升级方案》§5「执行感知」、§8「实验自修改与版本事务」、
§12「独立验证」；本文与 `docs/V3-W3-HANDOFF.md` 是同一套词的唯一出处）：

1. **三段同一身份**：一条交接从头到尾只有一个 ``run_id`` / ``execution_id`` /
   ``evidence_sha256``。三者由**原始记录本体**复算得出，不由调用方声明：

   - ``execution_id``：执行侧写在 ``exec.started`` / ``exec.finished`` 的
     ``exec_id``；
   - ``run_id``：``run-<sha256(task_id, execution_id, plan_sha256)[:16]>``
     ——确定性派生，呼叫方给的 run_id 与派生值不同即 ``run_id_mismatch``；
   - ``evidence_sha256``：封存记录本体（不含该字段自身）的 sha256。

2. **只读原始记录**：``RawRecordReader`` 只从内容寻址证据库读**封存记录本体**，
   复算哈希；``IndependentVerifier`` 不再读 ``research.json``、候选摘要、
   模型自述或任何 ``summary/claim/conclusion`` 字段。给 verifier 递摘要
   （哪怕是"更清楚的复述"）→ ``HandoffError: model_summary_not_accepted``。

3. **未核验/缺证据只标 pending/needs_evidence**：待复核项落库即 ``pending``；
   复核者判 ``accepted`` 才进报告的可追溯结论；缺证据（不在库/文件缺失/
   源证据缺失）落 ``needs_evidence``；身份、任务、版本或来源不对落 ``rejected``。
   本模块**不写** ``verified/confirmed``——漏洞结论只由既有
   ``agent.platform.verify`` 推导（见 `agent/platform/verify.py` 的只读钩子
   `raw_execution_refs()` / `raw_handoff_view()`）。

4. **隔离/授权未验收前只给建议**：``ProposalGate`` 读
   ``metadata.authorized``（严格解析，沿用 `authorization.resolve`）与**平台侧
   隔离验收记录**（`record_isolation_acceptance()` 落库/落文件的那一份，含检查项、
   证据哈希与时间）；任一未验收 → ``advisory``，控制器只把提议写进建议清单，
   不 stage、不构建、不采纳、不产生 revision。任务提交者自填的
   ``metadata.isolation_accepted`` **只是声明**（advisory），永远不放行。

字段契约：
  raw record: `vulnmap.adaptive.raw_execution.v1`
    task_id / run_id / execution_id / plan_sha256 / kind / evidence_sha256 /
    source_evidence_sha256 / source_event_seq / revision_id / build_id /
    policy_version / recorded_by / sealed_at / payload{start, finish}
  review item: `vulnmap.adaptive.review_item.v1`
    item_id / task_id / run_id / execution_id / evidence_sha256 / kind /
    status / revision_id / build_id / source / verdict_id / detail / timestamps
  verdict: `vulnmap.adaptive.handoff_verdict.v1`
    verdict_id / item_id / 三方身份 / status / reason / checks / blockers /
    verifier / created_at
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from .contracts import canonical_json, digest_of, now

SCHEMA = "vulnmap.adaptive.handoff.v1"
RAW_SCHEMA = "vulnmap.adaptive.raw_execution.v1"
ITEM_SCHEMA = "vulnmap.adaptive.review_item.v1"
VERDICT_SCHEMA = "vulnmap.adaptive.handoff_verdict.v1"
SCHEMA_VERSION = 1

#: 封存记录在证据库里的 kind
RAW_KIND = "raw_execution"

#: 只有这些事件能作为交接的原始来源（其余一律不是"执行证据"）
RAW_SOURCES = ("exec.finished",)

#: 原始记录里出现即说明它被模型加工过（原始记录没有这些字段）
SUMMARY_KEYS = frozenset({"summary", "claim", "claims", "narrative",
                          "conclusion", "conclusions", "rationale",
                          "model_summary", "analysis", "verified", "confirmed",
                          "verdict", "adjudicated", "pass"})

#: 待复核项状态；pending 是唯一入口态，后三者是复核结论
STATUSES = ("pending", "accepted", "rejected", "needs_evidence")
TERMINAL_STATUSES = ("accepted", "rejected", "needs_evidence")

#: 复核检查项（顺序稳定，报告按此输出）
CHECKS = ("item_valid", "record_present", "record_hash_match", "task_match",
          "triple_match", "source_evidence_match", "event_binding",
          "revision_current", "version_current", "raw_source_only")

#: 缺证据类（补材料后可重进复核）；其余失败一律 rejected
GAP_CHECKS = ("record_present", "record_hash_match", "source_evidence_match")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
RUN_ID = re.compile(r"^run-[0-9a-f]{16}$")

VERIFIER = "independent-verifier.v1"

#: 隔离/授权验收字段（metadata 里怎么写）
AUTHORIZATION_FIELD = "authorized"
ISOLATION_FIELD = "isolation_accepted"


class HandoffError(ValueError):
    """交接契约/顺序错误（不采纳、不静默修正）。"""


def _sha(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return sha256(data).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _hex64(value: Any) -> bool:
    return bool(HEX64.match(_text(value).lower()))


def derive_run_id(task_id: str, execution_id: str, plan_sha256: str = "") -> str:
    """确定性 run 身份：同一次执行永远是同一个 run_id（呼叫方不能自选）。"""
    body = canonical_json({"task_id": _text(task_id),
                           "execution_id": _text(execution_id),
                           "plan_sha256": _text(plan_sha256)})
    return "run-" + _sha(body)[:16]


# ====================================================================== 原始记录
@dataclass(frozen=True)
class RawRecord:
    """封存的执行原始记录：本体不含自身哈希，`evidence_sha256` 由本体复算。"""

    task_id: str
    run_id: str
    execution_id: str
    plan_sha256: str
    kind: str
    evidence_sha256: str
    source_evidence_sha256: str
    source_event_seq: int
    revision_id: str = ""
    build_id: str = ""
    policy_version: str = ""
    recorded_by: str = "executor"
    sealed_at: str = ""
    payload: dict = field(default_factory=dict)

    # ---- 身份 ----
    def body(self) -> dict:
        """记录本体（不含 `evidence_sha256`，避免自指哈希）。"""
        return {
            "schema": RAW_SCHEMA, "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id, "run_id": self.run_id,
            "execution_id": self.execution_id,
            "plan_sha256": self.plan_sha256, "kind": self.kind,
            "source_evidence_sha256": self.source_evidence_sha256,
            "source_event_seq": int(self.source_event_seq),
            "source_event_type": RAW_SOURCES[0],
            "revision_id": self.revision_id, "build_id": self.build_id,
            "policy_version": self.policy_version,
            "recorded_by": self.recorded_by,
            "sealed_at": self.sealed_at,
            "payload": dict(self.payload),
        }

    def compute_sha256(self) -> str:
        return _sha(canonical_json(self.body()))

    def to_dict(self) -> dict:
        doc = self.body()
        doc["evidence_sha256"] = self.evidence_sha256 or self.compute_sha256()
        return doc

    def bytes(self) -> bytes:
        """落盘字节 = 本体（**不含**自身哈希）：文件哈希就是 `evidence_sha256`。

        自指哈希写不进自己的内容里（和 git commit 同构）：记录里存的是
        ``evidence_sha256``，盘上存的是本体，读回时用本体复算即可校验。
        """
        return canonical_json(self.body()).encode("utf-8")

    @classmethod
    def from_dict(cls, doc: Mapping) -> RawRecord:
        if not isinstance(doc, Mapping):
            raise HandoffError("raw record must be a mapping")
        if _text(doc.get("schema")) != RAW_SCHEMA:
            raise HandoffError(
                f"raw record schema must be {RAW_SCHEMA!r}, got "
                f"{doc.get('schema')!r}")
        declared = _text(doc.get("evidence_sha256")).lower()
        record = cls(
            task_id=_text(doc.get("task_id")),
            run_id=_text(doc.get("run_id")),
            execution_id=_text(doc.get("execution_id")),
            plan_sha256=_text(doc.get("plan_sha256")),
            kind=_text(doc.get("kind")),
            evidence_sha256=_text(doc.get("evidence_sha256")).lower(),
            source_evidence_sha256=_text(
                doc.get("source_evidence_sha256")).lower(),
            source_event_seq=int(doc.get("source_event_seq") or 0),
            revision_id=_text(doc.get("revision_id")),
            build_id=_text(doc.get("build_id")),
            policy_version=_text(doc.get("policy_version")),
            recorded_by=_text(doc.get("recorded_by")) or "executor",
            sealed_at=_text(doc.get("sealed_at")),
            payload=dict(doc.get("payload") or {}),
        )
        record.validate()
        computed = record.compute_sha256()
        if declared and declared != computed:
            raise HandoffError(
                f"raw_record_sha_mismatch:declared={declared[:12]} "
                f"computed={computed[:12]}")
        if not record.evidence_sha256:
            record = cls(**{**record.__dict__, "evidence_sha256": computed})
        return record

    def validate(self) -> None:
        if not self.task_id:
            raise HandoffError("raw record: task_id required")
        if not self.execution_id:
            raise HandoffError("raw record: execution_id required")
        if not RUN_ID.match(self.run_id):
            raise HandoffError(
                f"raw record: run_id must be run-<16 hex>, got {self.run_id!r}")
        for name, value in (("evidence_sha256", self.evidence_sha256),
                            ("source_evidence_sha256",
                             self.source_evidence_sha256)):
            if value and not _hex64(value):
                raise HandoffError(
                    f"raw record: {name} must be 64 hex chars, got {value!r}")
        if self.source_event_seq <= 0:
            raise HandoffError("raw record: source_event_seq must be positive")
        # 模型加工字段**不在解析期**拒收：记录本体完好但被加工，要靠复核者的
        # `raw_source_only` 检查判成 **rejected**（补证据救不了被加工的记录）；
        # 若这里直接抛错，分类会退化成 needs_evidence（看起来像"缺材料"）。
        # 封存入口（seal_execution）自己只从事件流造记录，不会产出这些字段。

    def summary_keys(self) -> tuple[str, ...]:
        """原始记录里**不该有**的模型加工字段（复核者据此判 rejected）。"""
        found: list[str] = []
        for key in self.to_dict():
            if str(key).lower() in SUMMARY_KEYS:
                found.append(str(key))
        payload = dict(self.payload or {})
        for key in payload:
            if str(key).lower() in SUMMARY_KEYS and key not in ("start", "finish"):
                found.append(f"payload.{key}")
        finish = payload.get("finish") if isinstance(payload.get("finish"),
                                                      Mapping) else {}
        for key in finish:
            if str(key).lower() in SUMMARY_KEYS:
                found.append(f"payload.finish.{key}")
        return tuple(dict.fromkeys(found))

    def hashes(self) -> dict:
        return {"evidence_sha256": self.evidence_sha256,
                "source_evidence_sha256": self.source_evidence_sha256,
                "run_id": self.run_id, "execution_id": self.execution_id,
                "task_id": self.task_id}


# ====================================================================== 只读读取
class RawRecordReader:
    """只读：按 sha256 从内容寻址证据库取出封存记录并复算哈希。"""

    def __init__(self, store, *, evidence_root: Path | str | None = None,
                 task_id: str = "") -> None:
        self.store = store
        self.task_id = _text(task_id)
        self.root = Path(evidence_root) if evidence_root else (
            Path(store.path).parent / "evidence")

    def _row(self, sha256_value: str, task_id: str) -> dict | None:
        for row in self.store.list_evidence(task_id):
            if _text(row.get("sha256")).lower() == sha256_value:
                return row
        return None

    def path_of(self, sha256_value: str, task_id: str = "") -> Path:
        task = _text(task_id) or self.task_id
        row = self._row(sha256_value, task)
        if row is None:
            raise HandoffError(f"evidence_not_in_store:{sha256_value[:12]}")
        path = Path(_text(row.get("path")))
        if not path.is_absolute():
            path = self.root / path.name
        return path

    def read(self, sha256_value: str, *, task_id: str = "") -> RawRecord:
        """读回一条原始记录；哈希不符/文件缺失一律报错（不返回半份记录）。"""
        task = _text(task_id) or self.task_id
        value = _text(sha256_value).lower()
        if not _hex64(value):
            raise HandoffError(f"evidence_sha256 must be 64 hex chars: {value!r}")
        path = self.path_of(value, task)
        if not path.is_file():
            raise HandoffError(f"evidence_file_missing:{value[:12]}")
        raw = path.read_bytes()
        if _sha(raw) != value:
            raise HandoffError(f"evidence_hash_mismatch:{value[:12]}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HandoffError(
                f"raw_record_not_json:{value[:12]} ({type(exc).__name__})") from exc
        record = RawRecord.from_dict(doc)
        if record.compute_sha256() != value:
            raise HandoffError(f"raw_record_sha_mismatch:{value[:12]}")
        if record.task_id != task:
            raise HandoffError(
                f"wrong_task:record={record.task_id!r} request={task!r}")
        return record


# ====================================================================== 封存
def _execution_events(store, task_id: str, execution_id: str,
                      event_seq: int = 0
                      ) -> tuple[dict | None, dict | None]:
    """取同一次执行的 started/finished 事件；缺/重复都报错（不猜）。

    `event_seq` 显式指定"以哪一条 exec.finished 为准"（同一 exec_id 出现多条时
    必须由调用方点名，避免在一堆 finish 里挑一条当作事实）。
    """
    starts: list[dict] = []
    finishes: list[dict] = []
    for event in store.list_events(task_id):
        payload = event.get("payload") or {}
        if _text(payload.get("exec_id")) != execution_id:
            continue
        kind = _text(event.get("event_type"))
        if kind == "exec.started":
            starts.append(event)
        elif kind == "exec.finished":
            if event_seq and int(event.get("seq") or 0) != int(event_seq):
                continue
            finishes.append(event)
    if not finishes:
        raise HandoffError(
            f"execution_not_found:{execution_id!r}（没有 exec.finished 事件）")
    if len(finishes) > 1:
        raise HandoffError(
            f"ambiguous_execution:{execution_id!r}（{len(finishes)} 条 exec.finished）")
    return (starts[-1] if starts else None), finishes[-1]


def _evidence_path(store, task_id: str, sha256_value: str,
                   evidence_root: Path | str | None) -> Path:
    reader = RawRecordReader(store, evidence_root=evidence_root,
                             task_id=task_id)
    return reader.path_of(sha256_value, task_id)


def raw_evidence_path(store, task_id: str, sha256_value: str, *,
                      evidence_root: Path | str | None = None) -> Path:
    """只读：某条证据在本机的落地路径（不读内容、不产生副本）。"""
    return _evidence_path(store, task_id, sha256_value, evidence_root)


def seal_execution(store, task_id: str, *, execution_id: str,
                   evidence_root: Path | str | None = None,
                   run_id: str = "", revision_id: str = "",
                   build_id: str = "", policy_version: str = "",
                   recorded_by: str = "executor",
                   event_seq: int = 0) -> RawRecord:
    """把一次**真实执行**的事件 + 证据封成一条原始记录（幂等）。

    只读事件流与证据库；任何缺失/哈希不符都直接报错——不会用"没有证据但看起来
    跑过了"补一条记录。`run_id` 只做校验：传了就必须等于派生值。
    """
    from .. import evidence as evidence_mod  # 延迟导入：避免平台包循环

    task_id = _text(task_id)
    execution_id = _text(execution_id)
    if not task_id or not execution_id:
        raise HandoffError("seal_execution requires task_id and execution_id")
    start, finish = _execution_events(store, task_id, execution_id,
                                      event_seq=int(event_seq or 0))
    payload = dict(finish.get("payload") or {})
    source_sha = _text(payload.get("evidence_sha256")).lower()
    if not _hex64(source_sha):
        raise HandoffError(
            f"evidence_missing:{execution_id}（exec.finished 没有 evidence_sha256）")
    path = _evidence_path(store, task_id, source_sha, evidence_root)
    if not path.is_file():
        raise HandoffError(f"evidence_file_missing:{source_sha[:12]}")
    if _sha(path.read_bytes()) != source_sha:
        raise HandoffError(f"evidence_hash_mismatch:{source_sha[:12]}")

    plan_sha = _text(payload.get("plan_sha256"))
    derived = derive_run_id(task_id, execution_id, plan_sha)
    if run_id and _text(run_id) != derived:
        raise HandoffError(
            f"run_id_mismatch:given={run_id!r} derived={derived!r}")
    build = payload.get("build") if isinstance(payload.get("build"),
                                              Mapping) else {}
    record = RawRecord(
        task_id=task_id, run_id=derived, execution_id=execution_id,
        plan_sha256=plan_sha, kind=_text(payload.get("kind")),
        evidence_sha256="", source_evidence_sha256=source_sha,
        source_event_seq=int(finish.get("seq") or 0),
        revision_id=_text(revision_id) or _text(
            build.get("harness") or (start or {}).get("harness_revision")),
        build_id=_text(build_id) or _text(build.get("build_id")),
        policy_version=_text(policy_version) or _text(
            (start or {}).get("policy_version")),
        recorded_by=_text(recorded_by) or "executor",
        # 封存时间取**源事件**的时间戳（不是封存动作的 now）：同一次执行重复封存
        # 必须得到同一个 evidence_sha256，否则"同一身份"就不成立。
        sealed_at=_text(finish.get("ts")) or now(),
        payload={"start": dict((start or {}).get("payload") or {}),
                 "finish": payload},
    )
    record.validate()
    sealed = RawRecord(
        **{**record.__dict__, "evidence_sha256": record.compute_sha256()})
    sealed.validate()
    if sealed.compute_sha256() != sealed.evidence_sha256:   # pragma: no cover
        raise HandoffError("sealed record hash is not stable")
    root = (Path(evidence_root) if evidence_root
            else Path(store.path).parent / "evidence")
    ref = evidence_mod.EvidenceStore(store, root).put_bytes(
        task_id, RAW_KIND, sealed.bytes(), source_stage="RUNNING")
    if ref.sha256 != sealed.evidence_sha256:
        # 盘上字节的哈希必须等于声明哈希：不一致说明序列化有第二套口径
        raise HandoffError(
            f"sealed_hash_mismatch:computed={sealed.evidence_sha256[:12]} "
            f"stored={ref.sha256[:12]}")
    return sealed


# ====================================================================== 待复核项
@dataclass(frozen=True)
class ReviewItem:
    """待复核项：只有身份与状态，没有结论字段（结论只来自复核者）。"""

    item_id: str
    task_id: str
    run_id: str
    execution_id: str
    evidence_sha256: str
    kind: str = ""
    status: str = "pending"
    revision_id: str = ""
    build_id: str = ""
    source: str = RAW_SOURCES[0]
    verdict_id: str = ""
    detail: dict = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    schema: str = ITEM_SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "item_id": self.item_id,
            "task_id": self.task_id, "run_id": self.run_id,
            "execution_id": self.execution_id,
            "evidence_sha256": self.evidence_sha256, "kind": self.kind,
            "status": self.status, "revision_id": self.revision_id,
            "build_id": self.build_id, "source": self.source,
            "verdict_id": self.verdict_id, "detail": dict(self.detail),
            "created_at": self.created_at, "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> ReviewItem:
        if not isinstance(doc, Mapping):
            raise HandoffError("review item must be a mapping")
        item = cls(
            item_id=_text(doc.get("item_id")),
            task_id=_text(doc.get("task_id")),
            run_id=_text(doc.get("run_id")),
            execution_id=_text(doc.get("execution_id")),
            evidence_sha256=_text(doc.get("evidence_sha256")).lower(),
            kind=_text(doc.get("kind")),
            status=_text(doc.get("status")) or "pending",
            revision_id=_text(doc.get("revision_id")),
            build_id=_text(doc.get("build_id")),
            source=_text(doc.get("source")) or RAW_SOURCES[0],
            verdict_id=_text(doc.get("verdict_id")),
            detail=dict(doc.get("detail") or {}),
            created_at=_text(doc.get("created_at")),
            updated_at=_text(doc.get("updated_at")),
            schema=_text(doc.get("schema")) or ITEM_SCHEMA,
        )
        item.validate()
        return item

    def validate(self) -> None:
        if not SAFE_ID.match(self.item_id or ""):
            raise HandoffError(f"unsafe item_id: {self.item_id!r}")
        if not self.task_id:
            raise HandoffError(f"{self.item_id}: task_id required")
        if not RUN_ID.match(self.run_id or ""):
            raise HandoffError(f"{self.item_id}: unsafe run_id {self.run_id!r}")
        if not self.execution_id:
            raise HandoffError(f"{self.item_id}: execution_id required")
        if not _hex64(self.evidence_sha256):
            raise HandoffError(
                f"{self.item_id}: evidence_sha256 must be 64 hex chars")
        if self.status not in STATUSES:
            raise HandoffError(
                f"{self.item_id}: status must be one of {STATUSES}")
        if self.source not in RAW_SOURCES:
            raise HandoffError(
                f"{self.item_id}: source must be one of {RAW_SOURCES}")
        if "confirmed" in json.dumps(self.to_dict(), ensure_ascii=False):
            raise HandoffError(f"{self.item_id}: item must not carry 'confirmed'")


def _next_item_id(existing: list[dict]) -> str:
    used = {_text(row.get("item_id")) for row in existing}
    index = 1
    while f"HI{index}" in used:
        index += 1
    return f"HI{index}"


def open_pending(store, task_id: str, *, execution_id: str,
                 evidence_root: Path | str | None = None,
                 revision_id: str = "", build_id: str = "",
                 policy_version: str = "", run_id: str = "",
                 event_seq: int = 0) -> dict:
    """封存一次执行并开一条待复核项（同三方身份只开一条，幂等）。

    `event_seq`：同一 exec_id 有多条 exec.finished 时点名以哪一条为准
    （不给就必须唯一，否则 `ambiguous_execution`——不在一堆事件里挑事实）。
    """
    record = seal_execution(
        store, task_id, execution_id=execution_id,
        evidence_root=evidence_root, run_id=run_id, revision_id=revision_id,
        build_id=build_id, policy_version=policy_version,
        event_seq=event_seq)
    existing = store.list_review_items(task_id)
    for row in existing:
        if (_text(row.get("run_id")) == record.run_id
                and _text(row.get("execution_id")) == record.execution_id
                and _text(row.get("evidence_sha256")) == record.evidence_sha256):
            return row
    ts = now()
    item = ReviewItem(
        item_id=_next_item_id(existing), task_id=record.task_id,
        run_id=record.run_id, execution_id=record.execution_id,
        evidence_sha256=record.evidence_sha256, kind=record.kind,
        status="pending", revision_id=record.revision_id,
        build_id=record.build_id, source=RAW_SOURCES[0],
        detail={"plan_sha256": record.plan_sha256,
                "source_evidence_sha256": record.source_evidence_sha256,
                "source_event_seq": record.source_event_seq,
                "policy_version": record.policy_version},
        created_at=ts, updated_at=ts)
    item.validate()
    return store.save_review_item(item)


# ====================================================================== 复核者
@dataclass(frozen=True)
class Verdict:
    verdict_id: str
    item_id: str
    task_id: str
    run_id: str
    execution_id: str
    evidence_sha256: str
    status: str
    reason: str
    checks: dict = field(default_factory=dict)
    blockers: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    verifier: str = VERIFIER
    created_at: str = ""
    schema: str = VERDICT_SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "verdict_id": self.verdict_id,
            "item_id": self.item_id, "task_id": self.task_id,
            "run_id": self.run_id, "execution_id": self.execution_id,
            "evidence_sha256": self.evidence_sha256, "status": self.status,
            "reason": self.reason, "checks": dict(self.checks),
            "blockers": list(self.blockers), "detail": dict(self.detail),
            "verifier": self.verifier, "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> Verdict:
        return cls(
            verdict_id=_text(doc.get("verdict_id")),
            item_id=_text(doc.get("item_id")),
            task_id=_text(doc.get("task_id")),
            run_id=_text(doc.get("run_id")),
            execution_id=_text(doc.get("execution_id")),
            evidence_sha256=_text(doc.get("evidence_sha256")).lower(),
            status=_text(doc.get("status")),
            reason=_text(doc.get("reason")),
            checks=dict(doc.get("checks") or {}),
            blockers=[str(b) for b in (doc.get("blockers") or [])],
            detail=dict(doc.get("detail") or {}),
            verifier=_text(doc.get("verifier")) or VERIFIER,
            created_at=_text(doc.get("created_at")),
            schema=_text(doc.get("schema")) or VERDICT_SCHEMA,
        )

    def validate(self) -> None:
        # 复核者给出的是"未编号的定性"；verdict_id 由落库方分配（HV1..Hn）
        if self.verdict_id and not SAFE_ID.match(self.verdict_id):
            raise HandoffError(f"unsafe verdict_id: {self.verdict_id!r}")
        if self.status not in TERMINAL_STATUSES:
            raise HandoffError(
                f"{self.verdict_id}: status must be one of {TERMINAL_STATUSES}")
        if not self.task_id or not self.item_id:
            raise HandoffError(f"{self.verdict_id}: task_id/item_id required")
        if not _hex64(self.evidence_sha256):
            raise HandoffError(
                f"{self.verdict_id}: evidence_sha256 must be 64 hex chars")
        if "confirmed" in json.dumps(self.to_dict(), ensure_ascii=False):
            raise HandoffError(f"{self.verdict_id}: verdict must not carry "
                               f"'confirmed'")


def derive_verdict(checks: Mapping) -> str:
    """错任务 → rejected；缺证据 → needs_evidence；其余不成立 → rejected。

    "记录属于别的任务"（``record_hash_match=True`` 且 ``task_match=False``）是
    **硬拒绝**：补证据救不了错任务；读取失败（``record_hash_match=False``）才是
    缺证据，可以被补材料后重进复核。
    """
    if checks.get("record_hash_match") and checks.get("task_match") is False:
        return "rejected"
    if any(not checks.get(name) for name in GAP_CHECKS):
        return "needs_evidence"
    if not all(checks.get(name) for name in CHECKS):
        return "rejected"
    return "accepted"


class IndependentVerifier:
    """独立复核者：只读封存记录 + 事件流 + revision 账本，不读模型产物。"""

    def __init__(self, store, *, evidence_root: Path | str | None = None,
                 revisions: Any = None, reader: RawRecordReader | None = None,
                 policy_version: str = "", clock: Any = None) -> None:
        self.store = store
        self.evidence_root = evidence_root
        self.revisions = revisions
        #: 期望的协议/策略版本；空 = 不参与版本判定（不是"任意版本都行"）
        self.policy_version = _text(policy_version)
        self.reader = reader or RawRecordReader(
            store, evidence_root=evidence_root)
        self.clock = clock

    # ---- 期望版本 ----
    def expected_revision(self) -> str:
        """当前 head revision（没有 revision 账本就返回空 = 不参与版本判定）。"""
        if self.revisions is None:
            return ""
        getter = getattr(self.revisions, "current", None)
        revision = getter() if callable(getter) else None
        return _text(getattr(revision, "revision_id", ""))

    def _now(self) -> str:
        return now() if self.clock is None else str(self.clock())

    # ---- 复核 ----
    def verify(self, item: Mapping | ReviewItem, *,
               summary: Any = None) -> dict:
        """复核一条待复核项；返回 verdict 文档（未落库）。

        `summary` 参数只为**拒绝**存在：任何模型摘要/自述都抛
        `model_summary_not_accepted`，不会用它替代原始记录。
        """
        if summary not in (None, "", {}, []):
            raise HandoffError(
                "model_summary_not_accepted: verifier only reads raw records "
                f"(got {type(summary).__name__})")
        try:
            row = (item if isinstance(item, ReviewItem)
                   else ReviewItem.from_dict(item))
            item_error = ""
        except HandoffError as exc:
            row = None
            item_error = str(exc)

        checks = {name: False for name in CHECKS}
        blockers: list[str] = []
        detail: dict = {"verifier": VERIFIER,
                        "reads": "raw_record+event_stream+revision_ledger",
                        "model_summary_accepted": False}

        if row is None:
            blockers.append(f"item_invalid:{item_error or 'unknown'}")
            # 连身份都不成立：只可能是 rejected（没有可复核的原始记录）
            fallback = item if isinstance(item, Mapping) else {}
            return Verdict(
                verdict_id="", item_id=_text(fallback.get("item_id")),
                task_id=_text(fallback.get("task_id")),
                run_id="", execution_id="", evidence_sha256="0" * 64,
                status="rejected", reason="; ".join(blockers),
                checks=checks, blockers=blockers, detail=detail,
                created_at=self._now()).to_dict()

        checks["item_valid"] = True
        manifest = {_text(r.get("sha256")).lower() for r in
                    self.store.list_evidence(row.task_id)}
        checks["record_present"] = row.evidence_sha256 in manifest
        checks["source_evidence_match"] = (
            row.evidence_sha256 in manifest
            and _text(row.detail.get("source_evidence_sha256")).lower() in manifest)
        if not checks["record_present"]:
            blockers.append(f"evidence_not_in_store:{row.evidence_sha256[:12]}")
        elif not checks["source_evidence_match"]:
            blockers.append("source_evidence_not_in_store:"
                            f"{_text(row.detail.get('source_evidence_sha256'))[:12]}")

        record: RawRecord | None = None
        wrong_task = ""
        if checks["record_present"]:
            try:
                record = self.reader.read(row.evidence_sha256,
                                          task_id=row.task_id)
                checks["record_hash_match"] = True
            except HandoffError as exc:
                code = str(exc)
                if code.startswith("wrong_task"):
                    # 记录本身完好，但它属于**另一个任务**：不是缺证据，是错任务
                    wrong_task = code
                    checks["record_hash_match"] = True
                    blockers.append(code)
                else:
                    checks["record_hash_match"] = False
                    checks["record_present"] = not code.startswith(
                        ("evidence_not_in_store", "evidence_file_missing"))
                    blockers.append(code)

        if record is None and wrong_task:
            checks["task_match"] = False
            checks["triple_match"] = False
            checks["event_binding"] = False
            checks["revision_current"] = False
            checks["version_current"] = False
            checks["raw_source_only"] = False
        if record is not None:
            checks["task_match"] = record.task_id == row.task_id
            if not checks["task_match"]:
                blockers.append(
                    f"wrong_task_id:record={record.task_id!r} item={row.task_id!r}")
            checks["triple_match"] = (
                record.run_id == row.run_id
                and record.execution_id == row.execution_id
                and record.evidence_sha256 == row.evidence_sha256)
            if not checks["triple_match"]:
                blockers.append(
                    "identity_mismatch:"
                    f"run_id={record.run_id}/{row.run_id}, "
                    f"execution_id={record.execution_id}/{row.execution_id}, "
                    f"evidence={record.evidence_sha256[:12]}/"
                    f"{row.evidence_sha256[:12]}")
            checks["event_binding"] = self._event_binding(record)
            if not checks["event_binding"]:
                blockers.append(
                    f"raw_event_missing:{record.execution_id}"
                    f"#{record.source_event_seq}")
            expected = self.expected_revision()
            checks["revision_current"] = (
                not expected or not record.revision_id
                or record.revision_id == expected)
            if not checks["revision_current"]:
                blockers.append(
                    f"stale_revision:record={record.revision_id} head={expected}")
            checks["version_current"] = (
                not self.policy_version or not record.policy_version
                or record.policy_version == self.policy_version)
            if not checks["version_current"]:
                blockers.append(
                    f"stale_version:record={record.policy_version} "
                    f"expected={self.policy_version}")
            checks["raw_source_only"] = not record.summary_keys()
            if not checks["raw_source_only"]:
                blockers.append(
                    f"model_summary_in_record:{list(record.summary_keys())}")
            detail.update({
                "plan_sha256": record.plan_sha256,
                "kind": record.kind or row.kind,
                "revision_id": record.revision_id,
                "build_id": record.build_id,
                "policy_version": record.policy_version,
                "source_event_seq": record.source_event_seq,
                "source_evidence_sha256": record.source_evidence_sha256,
                "expected_revision": expected,
                "sealed_at": record.sealed_at,
            })
        else:
            for name in ("task_match", "triple_match", "event_binding",
                         "revision_current", "version_current",
                         "raw_source_only"):
                if not checks.get(name):
                    checks[name] = False
            if not checks["record_hash_match"]:
                blockers.append("record_unreadable")

        status = derive_verdict(checks)
        reason = ("all checks passed" if status == "accepted"
                  else "; ".join(dict.fromkeys(blockers)) or "unspecified")
        verdict = Verdict(
            verdict_id="", item_id=row.item_id, task_id=row.task_id,
            run_id=row.run_id, execution_id=row.execution_id,
            evidence_sha256=row.evidence_sha256, status=status, reason=reason,
            checks=checks, blockers=list(dict.fromkeys(blockers)),
            detail=detail, created_at=self._now())
        verdict.validate()
        return verdict.to_dict()

    def _event_binding(self, record: RawRecord) -> bool:
        """源证据必须真的挂在同一条 `exec.finished` 事件上（不是自己声明的）。

        事件视图**只**从 `agent.platform.verify.raw_execution_refs()` 取
        （验证侧的只读钩子），不在这里另写一套事件字段读法。
        """
        from .. import verify as verify_mod  # 延迟导入：避免平台包循环

        refs = verify_mod.raw_execution_refs(
            self.store, record.task_id, execution_id=record.execution_id)
        for ref in refs:
            if int(ref.get("event_seq") or 0) != record.source_event_seq:
                continue
            if _text(ref.get("evidence_sha256")).lower() != \
                    record.source_evidence_sha256:
                continue
            if _text(ref.get("plan_sha256")) != record.plan_sha256:
                continue
            if not (ref.get("registered") and ref.get("hash_ok")):
                continue
            return True
        return False


def _next_verdict_id(existing: Iterable[dict]) -> str:
    used = {_text(row.get("verdict_id")) for row in existing}
    index = 1
    while f"HV{index}" in used:
        index += 1
    return f"HV{index}"


def review_item(store, task_id: str, item_id: str, *,
                verifier: IndependentVerifier | None = None,
                evidence_root: Path | str | None = None,
                revisions: Any = None, policy_version: str = "") -> dict:
    """复核一条待复核项：写 verdict、把项状态改成 accepted/rejected/needs_evidence。"""
    row = store.get_review_item(task_id, item_id)
    if row is None:
        raise HandoffError(f"review_item_not_found:{task_id}/{item_id}")
    if _text(row.get("status")) not in ("pending", "needs_evidence"):
        raise HandoffError(
            f"review_item_closed:{item_id} status={row.get('status')!r}"
            "（已定性的项不重复复核；补证据请重新封存）")
    verifier = verifier or IndependentVerifier(
        store, evidence_root=evidence_root, revisions=revisions,
        policy_version=policy_version)
    verdict = verifier.verify(row)
    if verdict["task_id"] != task_id:
        raise HandoffError(
            f"wrong_task_id:verdict={verdict['task_id']!r} request={task_id!r}")
    existing = store.list_handoff_verdicts(task_id)
    verdict["verdict_id"] = _next_verdict_id(existing)
    saved = store.save_handoff_verdict(verdict)
    status = _text(saved.get("status"))
    if status not in TERMINAL_STATUSES:
        raise HandoffError(f"verdict_status_invalid:{status!r}")
    item = ReviewItem.from_dict(dict(row))
    updated = ReviewItem(
        **{**item.__dict__, "status": status,
           "verdict_id": _text(saved.get("verdict_id")),
           "updated_at": now()})
    updated.validate()
    store.save_review_item(updated)
    return {"item": store.get_review_item(task_id, item_id), "verdict": saved}


# ====================================================================== 报告视图
def handoff_view(store, task_id: str, *, revisions: Any = None) -> dict:
    """可追溯结论视图：只把 **accepted** 项当结论，其余如实标 pending 等。"""
    items = store.list_review_items(task_id)
    verdicts = {_text(v.get("verdict_id")): v
                for v in store.list_handoff_verdicts(task_id)}
    expected = ""
    if revisions is not None:
        getter = getattr(revisions, "current", None)
        current = getter() if callable(getter) else None
        expected = _text(getattr(current, "revision_id", ""))
    rows: list[dict] = []
    conclusions: list[dict] = []
    for item in items:
        verdict = verdicts.get(_text(item.get("verdict_id"))) or {}
        status = _text(item.get("status")) or "pending"
        row = {
            "item_id": _text(item.get("item_id")),
            "run_id": _text(item.get("run_id")),
            "execution_id": _text(item.get("execution_id")),
            "evidence_sha256": _text(item.get("evidence_sha256")),
            "status": status,
            "kind": _text(item.get("kind")),
            "revision_id": _text(item.get("revision_id")),
            "build_id": _text(item.get("build_id")),
            "verdict_id": _text(item.get("verdict_id")),
            "reason": _text(verdict.get("reason")),
            "blockers": [str(b) for b in (verdict.get("blockers") or [])],
            "traceable": bool(status == "accepted" and item.get("verdict_id")
                              and _hex64(item.get("evidence_sha256"))),
            "revision_current": (not expected
                                 or _text(item.get("revision_id")) == expected),
        }
        rows.append(row)
        if row["traceable"]:
            conclusions.append({
                "item_id": row["item_id"], "run_id": row["run_id"],
                "execution_id": row["execution_id"],
                "evidence_sha256": row["evidence_sha256"],
                "verdict_id": row["verdict_id"], "kind": row["kind"],
                "revision_id": row["revision_id"],
            })
    counts = {status: sum(1 for r in rows if r["status"] == status)
              for status in STATUSES}
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "task_id": task_id,
        "counts": {**counts, "items": len(rows),
                   "conclusions": len(conclusions),
                   "unverified": counts["pending"] + counts["needs_evidence"]},
        "expected_revision": expected,
        "conclusions": conclusions,
        "items": rows,
        "note": ("只有 accepted 且三方身份齐全的项算可追溯结论；"
                 "pending/needs_evidence 一律不算结论，也不进包级 verified 计数"),
    }


def pending_items(store, task_id: str) -> list[dict]:
    """待办队列（pending + needs_evidence）：缺证据的也要能被看见。"""
    return [row for row in store.list_review_items(task_id)
            if _text(row.get("status")) in ("pending", "needs_evidence")]


# ====================================================================== 验收门
# ---------------------------------------------------------------- 隔离验收记录
#: 平台侧隔离验收记录（口径唯一出处：`docs/V3-ISOLATION-ACCEPTANCE.md`）。
#: **任务提交者填的字段只是声明**，放行只认这份记录：记录由平台在真隔离执行
#: 之后生成，带检查项、证据哈希与时间；改一个字节就复算不上。
ISOLATION_ACCEPTANCE_SCHEMA = "vulnmap.adaptive.isolation_acceptance.v1"
ISOLATION_ACCEPTANCE_STATUSES = ("accepted", "rejected")
ISOLATION_ACCEPTANCE_FILE = "isolation-acceptance.jsonl"
#: 合格隔离执行器（与 `discovery.isolation` 的模式阶梯一致；有测试对账）
ISOLATION_EXECUTORS = ("bwrap", "unshare", "container")
#: 一条记录必须成立的检查项（全真才是 accepted；缺项按未通过）
ISOLATION_CHECKS = (
    "isolation_available", "qualified_executor", "executed_isolated",
    "network_denied", "capability_dropped", "root_read_only",
    "probe_write_confined", "probe_network_denied",
)
#: 必须由探针证明的两件事（只靠"参数里写了 --unshare-net"不算证据）
ISOLATION_PROBES = ("write_confined", "network_denied")

def isolation_probe(name: str, *, ok: bool, evidence: Mapping | None = None
                    ) -> dict:
    """一条探针结果：名字 + 结论 + **证据哈希**（没有证据就不算一次检查）。"""
    body = dict(evidence or {})
    if not body:
        raise HandoffError(f"isolation_probe:{name} needs evidence")
    return {"name": _text(name), "ok": bool(ok),
            "evidence_sha256": digest_of(body)}


@dataclass(frozen=True)
class IsolationAcceptance:
    """平台侧隔离验收记录：事实（隔离模式/网络/cap/只读根）+ 检查项 + 证据哈希。"""

    acceptance_id: str
    task_id: str
    status: str
    isolation: str = ""
    network: str = ""
    cap_drop: bool = False
    ro_root: bool = False
    executed_isolated: bool = False
    checks: Mapping = field(default_factory=dict)
    evidence: tuple = ()
    evidence_sha256: str = ""
    reason: str = ""
    checked_at: str = ""
    schema: str = ISOLATION_ACCEPTANCE_SCHEMA

    def body(self) -> dict:
        """参与哈希的本体（去掉 `evidence_sha256` 自身）。"""
        return {
            "schema": self.schema, "task_id": self.task_id,
            "acceptance_id": self.acceptance_id, "status": self.status,
            "isolation": self.isolation, "network": self.network,
            "cap_drop": bool(self.cap_drop), "ro_root": bool(self.ro_root),
            "executed_isolated": bool(self.executed_isolated),
            "checks": dict(self.checks),
            "evidence": [dict(item) for item in self.evidence],
            "reason": self.reason, "checked_at": self.checked_at,
        }

    def compute_sha256(self) -> str:
        return digest_of(self.body())

    def validate(self) -> None:
        if self.status not in ISOLATION_ACCEPTANCE_STATUSES:
            raise HandoffError(
                f"isolation_acceptance_status_invalid:{self.status!r}")
        if not _text(self.task_id):
            raise HandoffError("isolation_acceptance_task_missing")
        if self.status == "accepted" and not list(self.evidence):
            raise HandoffError("isolation_acceptance_evidence_missing")
        if self.evidence_sha256 and self.evidence_sha256 != self.compute_sha256():
            raise HandoffError("isolation_acceptance_tampered: evidence_sha256")

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    def to_dict(self) -> dict:
        return {**self.body(), "evidence_sha256": self.evidence_sha256}

    @classmethod
    def from_dict(cls, doc: Mapping) -> IsolationAcceptance:
        doc = dict(doc or {})
        return cls(
            acceptance_id=_text(doc.get("acceptance_id")),
            task_id=_text(doc.get("task_id")),
            status=_text(doc.get("status")),
            isolation=_text(doc.get("isolation")),
            network=_text(doc.get("network")),
            cap_drop=bool(doc.get("cap_drop")),
            ro_root=bool(doc.get("ro_root")),
            executed_isolated=bool(doc.get("executed_isolated")),
            checks=dict(doc.get("checks") or {}),
            evidence=tuple(dict(item) for item in (doc.get("evidence") or ())),
            evidence_sha256=_text(doc.get("evidence_sha256")),
            reason=_text(doc.get("reason")),
            checked_at=_text(doc.get("checked_at")),
            schema=_text(doc.get("schema")) or ISOLATION_ACCEPTANCE_SCHEMA,
        )


def _record_fact(record, name: str, default=None):
    """读 build/smoke 记录上的隔离事实（记录对象或字典都认）。"""
    if record is None:
        return default
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def build_isolation_acceptance(*, task_id: str, build=None, smoke=None,
                               probes: Iterable[Mapping] = (),
                               checked_at: str = "") -> IsolationAcceptance:
    """按**实际**隔离执行事实生成一份验收记录（accepted 或 rejected）。

    事实只从记录里读：模式/网络/cap-drop/只读根/`executed_isolated`。计划里的
    隔离模式不是输入——没有真跑过的构建/冒烟，这份记录只会是 `rejected`。
    """
    probe_rows = tuple(dict(item) for item in (probes or ()))
    by_name = {_text(row.get("name")): row for row in probe_rows}
    modes = [str(_record_fact(build, "isolation", "") or ""),
             str(_record_fact(smoke, "isolation", "") or "")]
    mode = modes[0] or modes[1]
    checks = {
        "isolation_available": bool(mode) and mode != "none",
        "qualified_executor": mode in ISOLATION_EXECUTORS,
        "executed_isolated": (bool(_record_fact(build, "executed_isolated"))
                              and bool(_record_fact(smoke, "executed_isolated"))),
        "network_denied": (_record_fact(build, "network") == "none"
                           and _record_fact(smoke, "network") == "none"),
        "capability_dropped": (bool(_record_fact(build, "cap_drop"))
                               and bool(_record_fact(smoke, "cap_drop"))),
        "root_read_only": (bool(_record_fact(build, "ro_root"))
                           and bool(_record_fact(smoke, "ro_root"))),
        "probe_write_confined": bool(
            (by_name.get("write_confined") or {}).get("ok")),
        "probe_network_denied": bool(
            (by_name.get("network_denied") or {}).get("ok")),
    }
    evidence: list[dict] = []
    for kind, record, ident in (("build", build, "build_id"),
                                ("smoke", smoke, "smoke_id")):
        if record is None:
            continue
        evidence.append({"kind": kind,
                         "id": str(_record_fact(record, ident, "") or ""),
                         "sha256": str(_record_fact(record, "log_sha256", "") or "")})
    for row in probe_rows:
        evidence.append({"kind": "probe", "id": _text(row.get("name")),
                         "sha256": _text(row.get("evidence_sha256"))})
    missing = [name for name in ISOLATION_PROBES if name not in by_name]
    failed = [name for name in ISOLATION_CHECKS if not checks.get(name)]
    status = "accepted" if not failed else "rejected"
    reason = ("all_isolation_checks_passed" if status == "accepted" else
              ";".join([f"check_failed:{name}" for name in failed]
                       + [f"probe_missing:{name}" for name in missing]))
    body = {
        "schema": ISOLATION_ACCEPTANCE_SCHEMA, "task_id": _text(task_id),
        "acceptance_id": "", "status": status, "isolation": mode,
        "network": str(_record_fact(build, "network", "") or ""),
        "cap_drop": bool(_record_fact(build, "cap_drop")),
        "ro_root": bool(_record_fact(build, "ro_root")),
        "executed_isolated": bool(_record_fact(build, "executed_isolated")),
        "checks": checks, "evidence": evidence, "reason": reason,
        "checked_at": _text(checked_at) or now(),
    }
    acceptance_id = "ia-" + digest_of({**body, "acceptance_id": ""})[:16]
    record = IsolationAcceptance(
        acceptance_id=acceptance_id, task_id=body["task_id"],
        status=status, isolation=mode, network=body["network"],
        cap_drop=body["cap_drop"], ro_root=body["ro_root"],
        executed_isolated=body["executed_isolated"], checks=checks,
        evidence=tuple(evidence), reason=reason,
        checked_at=body["checked_at"])
    signed = replace(record, evidence_sha256=record.compute_sha256())
    signed.validate()
    return signed


def verify_isolation_acceptance(record: Mapping | None, *,
                               task_id: str = "") -> tuple[str, dict]:
    """复核一份平台侧记录 → `(state, detail)`；state 只有 accepted/rejected/missing。

    复算哈希是硬要求：**改一个字节就对不上**，对不上就是 `rejected`——不是
    “没验过”也不是“验过了但宽松”。
    """
    if record is None:
        return "missing", {"reason": "no_platform_record",
                           "authority": "platform_record_only"}
    try:
        row = IsolationAcceptance.from_dict(record)
    except (TypeError, ValueError) as exc:
        return "rejected", {"reason": f"record_invalid:{exc}"}
    detail = {"acceptance_id": row.acceptance_id,
              "evidence_sha256": row.evidence_sha256,
              "checked_at": row.checked_at, "checks": dict(row.checks)}
    if row.schema != ISOLATION_ACCEPTANCE_SCHEMA:
        return "rejected", {**detail, "reason": "schema_mismatch"}
    if task_id and row.task_id and row.task_id != _text(task_id):
        return "rejected", {**detail, "reason": "wrong_task"}
    if row.status != "accepted":
        return "rejected", {**detail, "reason": "recorded_rejected"}
    if row.evidence_sha256 != row.compute_sha256():
        return "rejected", {**detail, "reason": "evidence_hash_mismatch"}
    if not list(row.evidence):
        return "rejected", {**detail, "reason": "evidence_missing"}
    failed = [name for name in ISOLATION_CHECKS if not dict(row.checks).get(name)]
    if failed:
        return "rejected", {**detail, "reason": "checks_failed:" + ",".join(failed)}
    return "accepted", {**detail, "reason": "platform_record_accepted"}


def record_isolation_acceptance(store=None, *, acceptance=None, path=None,
                                **fields) -> dict:
    """把一份验收记录落到平台侧（库 + 可选的追加文件）；返回落库的那一行。

    写入前先验：`evidence_sha256` 必须能复算、检查项必须齐、任务必须对。写库
    走 `PlatformStore.save_isolation_acceptance()`；写文件是同样的 JSON 一行。
    """
    if acceptance is None:
        acceptance = build_isolation_acceptance(**fields)
    elif not isinstance(acceptance, IsolationAcceptance):
        acceptance = IsolationAcceptance.from_dict(acceptance)
    acceptance.validate()
    row = acceptance.to_dict()
    saved = row
    if store is not None:
        saved = dict(store.save_isolation_acceptance(row))
    if path is not None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(row) + "\n")
            fh.flush()
    return saved


def load_isolation_acceptance(path) -> list[dict]:
    """从追加文件里读回记录（坏行跳过：坏行不是记录）。"""
    target = Path(path)
    if not target.is_file():
        return []
    rows: list[dict] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict):
            rows.append(doc)
    return rows


def latest_isolation_acceptance(*, store=None, path=None,
                                task_id: str = "") -> dict | None:
    """最近一条平台侧记录（库优先；没有库再看文件）。"""
    if store is not None and hasattr(store, "latest_isolation_acceptance"):
        row = store.latest_isolation_acceptance(task_id)
        if row is not None:
            return dict(row)
    if path is not None:
        rows = [row for row in load_isolation_acceptance(path)
                if not task_id or _text(row.get("task_id")) == _text(task_id)]
        return rows[-1] if rows else None
    return None


def _accept_token(value: Any) -> tuple[bool, str]:
    """严格解析验收声明：只认明确写法，其余（缺失/空/乱写）一律未验收。"""
    from .. import authorization  # 延迟导入：沿用唯一授权口径
    if value is None:
        return False, "missing"
    try:
        return authorization.parse_authorized(value), "declared"
    except authorization.AuthorizationError:
        return False, "invalid"


@dataclass(frozen=True)
class Acceptance:
    """验收状态：授权（metadata 严格解析）+ 隔离（**只认平台侧记录**）。

    `isolation` 的三个取值 `accepted` / `rejected` / `missing` **全部**来自
    `verify_isolation_acceptance()`：任务提交者在 `metadata.isolation_accepted`
    里写什么都不会让它变成 `accepted`，只会在 `declared_isolation` 里留个痕
    （advisory，不进判定）。
    """

    authorization: str = "missing"      # true|false|invalid
    isolation: str = "missing"          # accepted|rejected|missing
    ok: bool = False
    acceptance_id: str = ""
    evidence_sha256: str = ""
    declared_isolation: str = "missing"  # 提交者自填字段的解析结果（advisory）
    reason: str = ""

    def to_dict(self) -> dict:
        return {"authorization": self.authorization,
                "isolation": self.isolation, "ok": bool(self.ok),
                "acceptance_id": self.acceptance_id,
                "evidence_sha256": self.evidence_sha256,
                "reason": self.reason,
                "declared": {"isolation": ISOLATION_FIELD,
                             "state": self.declared_isolation,
                             "authority": "advisory"},
                "fields": {"authorization": AUTHORIZATION_FIELD,
                           "isolation": ISOLATION_FIELD},
                "policy": ("授权按 metadata 严格解析；隔离只认平台侧记录 "
                           "(accepted)，提交者自填恒为 advisory")}


def resolve_acceptance(task: Mapping | None, *, record: Mapping | None = None,
                       store=None, path=None) -> Acceptance:
    """算验收状态：授权读 metadata，隔离只读**平台侧记录**。

    `record` 显式给一份记录；否则按 `store`（平台库）/`path`（追加文件）取
    该任务最近一条。任务提交者填的 `isolation_accepted` 只解析成
    `declared_isolation`（advisory），**不参与** `ok`。
    """
    meta = dict((task or {}).get("metadata") or {})
    auth_ok, auth_state = _accept_token(meta.get(AUTHORIZATION_FIELD))
    task_id = _text((task or {}).get("task_id"))
    if record is None and (store is not None or path is not None):
        record = latest_isolation_acceptance(store=store, path=path,
                                             task_id=task_id)
    iso_state, iso_detail = verify_isolation_acceptance(record,
                                                       task_id=task_id)
    _declared_ok, declared_state = _accept_token(meta.get(ISOLATION_FIELD))
    return Acceptance(
        authorization=("true" if auth_ok else
                       ("invalid" if auth_state == "invalid" else "false")),
        isolation=iso_state,
        ok=bool(auth_ok and iso_state == "accepted"),
        acceptance_id=_text(iso_detail.get("acceptance_id")),
        evidence_sha256=_text(iso_detail.get("evidence_sha256")),
        declared_isolation=declared_state,
        reason=_text(iso_detail.get("reason")))


@dataclass(frozen=True)
class GateDecision:
    status: str                        # apply | advisory
    blockers: tuple[str, ...] = ()
    acceptance: dict = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "blockers": list(self.blockers),
                "acceptance": dict(self.acceptance),
                "applied": self.status == "apply", "note": self.note}


class ProposalGate:
    """模型提议的验收闸：未验收只给建议，不自动应用。

    控制器在 stage 之前问一次；``advisory`` 分支不写工作副本、不建 revision、
    不写采纳、不产生 verification——只把提议原样记进建议清单。
    """

    def __init__(self, acceptance: Acceptance | Mapping | None = None, *,
                 task: Mapping | None = None,
                 isolation_record: Mapping | None = None,
                 store=None, path=None) -> None:
        if isinstance(acceptance, Acceptance):
            self.acceptance = acceptance
        elif isinstance(acceptance, Mapping):
            self.acceptance = Acceptance(
                authorization=_text(acceptance.get("authorization"))
                or "missing",
                isolation=_text(acceptance.get("isolation")) or "missing",
                ok=bool(acceptance.get("ok")),
                acceptance_id=_text(acceptance.get("acceptance_id")),
                evidence_sha256=_text(acceptance.get("evidence_sha256")))
        elif task is not None:
            # metadata 只贡献授权；隔离来自平台侧记录（`isolation_record` /
            # `store` / `path`）。没有记录就是 missing → advisory。
            self.acceptance = resolve_acceptance(
                task, record=isolation_record, store=store, path=path)
        else:
            self.acceptance = Acceptance()

    @classmethod
    def from_task(cls, task: Mapping | None, *,
                  isolation_record: Mapping | None = None,
                  store=None, path=None) -> ProposalGate:
        return cls(task=task, isolation_record=isolation_record,
                   store=store, path=path)

    def admit(self, *, scope: str = "engineering", action: str = "",
              params: Mapping | None = None) -> GateDecision:
        blockers: list[str] = []
        if self.acceptance.authorization != "true":
            blockers.append(f"authorization:{self.acceptance.authorization}")
        if self.acceptance.isolation != "accepted":
            blockers.append(f"isolation:{self.acceptance.isolation}")
        status = "advisory" if blockers else "apply"
        note = ("未验收（隔离/授权）→ 只给建议，不自动应用"
                if blockers else
                "授权通过 + 平台侧隔离记录 accepted → 允许应用")
        return GateDecision(status=status, blockers=tuple(blockers),
                            acceptance=self.acceptance.to_dict(), note=note)

    def record(self, *, round_no: int, action: str, params: Mapping,
               decision: GateDecision) -> dict:
        """建议清单的一行（给报告用；不含任何结论字段）。"""
        return {
            "round": int(round_no), "action": _text(action),
            "status": "advisory", "applied": False,
            "params_sha256": _sha(canonical_json(dict(params or {}))),
            "blockers": list(decision.blockers),
            "acceptance": dict(decision.acceptance),
            "note": decision.note,
            "created_at": now(),
        }


__all__ = [
    "AUTHORIZATION_FIELD",
    "CHECKS",
    "GAP_CHECKS",
    "ISOLATION_ACCEPTANCE_FILE",
    "ISOLATION_ACCEPTANCE_SCHEMA",
    "ISOLATION_CHECKS",
    "ISOLATION_EXECUTORS",
    "ISOLATION_FIELD",
    "ISOLATION_PROBES",
    "ITEM_SCHEMA",
    "RAW_KIND",
    "RAW_SCHEMA",
    "RAW_SOURCES",
    "SCHEMA",
    "SCHEMA_VERSION",
    "STATUSES",
    "SUMMARY_KEYS",
    "TERMINAL_STATUSES",
    "VERDICT_SCHEMA",
    "VERIFIER",
    "Acceptance",
    "GateDecision",
    "HandoffError",
    "IndependentVerifier",
    "IsolationAcceptance",
    "ProposalGate",
    "RawRecord",
    "RawRecordReader",
    "ReviewItem",
    "Verdict",
    "build_isolation_acceptance",
    "derive_run_id",
    "derive_verdict",
    "handoff_view",
    "isolation_probe",
    "latest_isolation_acceptance",
    "load_isolation_acceptance",
    "open_pending",
    "pending_items",
    "record_isolation_acceptance",
    "resolve_acceptance",
    "review_item",
    "seal_execution",
    "verify_isolation_acceptance",
]
