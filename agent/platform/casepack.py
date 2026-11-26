"""V2 P3：Case Pack —— 把一次任务的“结论 + 证据 + 轨迹”打成可复核的目录。

内容（相对 casepack 目录）：

~~~text
task.json               任务契约（task_id/benchmark/target/mode/budget/metadata）
state.json              状态机现状 + 事件重放结果 + 终止原因
events.jsonl            完整事件流（一行一条，可重放）
candidates.json         全部候选（含被拒/待补证据的负结果）
verifications.json      全部验证记录（按 benchmark 判据）
reviews.json            全部复核记录（accept/reject/needs_evidence）
handoff.json            证据交接视图（待复核项队列 + 可追溯结论；只读快照）
evidence/manifest.json  证据清单：sha256/size/kind/present/hash_ok
report.md               人读报告（确定性渲染）
report.html             人读网页版（确定性渲染、样式内联、零外部资源）
casepack.json           文件清单 + 内容哈希（不参与自身哈希）
~~~

`reports` 台账除了 `content_sha256`，还记 `report_html_sha256`（report.html 的
单文件哈希），这样“台账 → 包 → 网页”三段可以对上。`report.html` 本身不留渲染
时间戳：同一批台账快照重算必得同一份字节，否则它没法进内容哈希。

V3 P4b（V3-015/016）在**有研究产物时**追加六个文件（无研究产物时清单不变）：

~~~text
research.json               研究报告原样字节（sha256 与 research.mapped 登记对账）
research/timeline.json      阶段时间线 + 汇总（无时间戳，可字节复算）
research/rounds.json        每轮：诊断/计划/动作/构建/冒烟/采纳/比较/失效/证据引用
research/decisions.json     工程采纳账（adoptions.jsonl）+ 研究进展 + 漏洞验证三段分离
research/evidence_refs.json 证据引用 → 本任务登记证据的解析结果（未登记不冒充命中）
compare.json                研究循环 vs 单次 fuzz 的对照实验指标（不产裁决）
~~~

三条与 P4b 相关的口径：

1. **研究产物是输入不是结论**：`research.json` 原样复制（字节不动，含它自带的
   `generated_at`），包内其余派生文档一律无时间戳，同一批输入重算字节相同；
2. **三类事实分开写**：工程采纳（可构建/可驱动/有收益）、漏洞验证（只来自
   `verifications`/`reviews`）、研究进展（轮次/动作/覆盖/对照实验）在
   `report.md` 与 `report.html` 里各占一节，动作次数不写成“更聪明”；
3. **冲突即拒绝**：研究报告坏 JSON / schema 不认识 / 属于别的任务 /
   与 `research.mapped` 登记的 `report_sha256` 不一致 → `CasePackError`，
   不半写、不猜一个“更像新的”轮次。

三条硬约束：

1. **负结果也打包**：`rejected/no_repro/needs_evidence` 的候选、验证、复核
   一条都不丢——负结果和正结果是同一套证据链；
2. **内容哈希可复算**：`content_sha256` = 对除 `casepack.json` 外的
   `(相对路径, 文件 sha256)` 有序列表取 sha256；同一批文件重算必得同一值。
   该哈希写 `reports` 表（`path=casepack 目录`），是台账与磁盘之间的唯一纽带，
   同时落在包内 `casepack.json`；
3. **事件只追加**：`report.ready` 是**提交后**事件（payload 带内容哈希），
   因此它不在本包 `events.jsonl` 里——已经算过哈希的文件不回头改写；
   下一次打包的 `events.jsonl` 会包含它。包内以 `casepack.json` + `reports`
   台账为准，上一包的 `report.ready` 在下一包里可见。

V3 W3（V3-019）追加 `handoff.json`，并把它写进每次打包的清单（没有交接时
写一份计数全为 0 的空视图，不装作"有结论"）：

- **它只是快照，不是裁决**：内容来自
  [`adaptive.handoff.handoff_view`](adaptive/handoff.py)，包内不重算、不猜；
  视图由该函数延迟导入取得（`agent.platform` 导入期不拖进研究子系统）；
- **只有 accepted 且 `run_id`/`execution_id`/`evidence_sha256` 齐全的项**
  算可追溯结论；`pending`/`needs_evidence` 一律不算结论，也**不进**
  `benchmark_verified` / `accepted_by_review`（交接项不能冒充 verified）；
- `casepack.json` 的 `handoff` 段与 `verdict.handoff` 段只放计数与口径，
  明细一律指向 `handoff.json`（同一个事实不写两遍）。
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .review import sha256_file

SCHEMA = "vulnmap.casepack.v1"

FILES = (
    "task.json",
    "state.json",
    "events.jsonl",
    "candidates.json",
    "verifications.json",
    "reviews.json",
    "handoff.json",
    "evidence/manifest.json",
    "report.md",
    "report.html",
)

#: V3 P4b：仅当任务有研究产物时追加；无研究产物时 `FILES` 就是全部清单。
RESEARCH_SCHEMA = "vulnmap.research.run.v1"
RESEARCH_DIRNAME = "research"
RESEARCH_FILES = (
    "research.json",
    "research/timeline.json",
    "research/rounds.json",
    "research/decisions.json",
    "research/evidence_refs.json",
    "compare.json",
)

#: 各派生文档的 schema 名（与 P4a 的只读视图区分：包内是快照，不是 API 视图）
TIMELINE_SCHEMA = "vulnmap.casepack.research.timeline.v1"
ROUNDS_SCHEMA = "vulnmap.casepack.research.rounds.v1"
DECISIONS_SCHEMA = "vulnmap.casepack.research.decisions.v1"
REFS_SCHEMA = "vulnmap.casepack.research.evidence_refs.v1"

#: `reports` 表由 P3 定义（store.py 未改）：report.html 的单文件哈希作为
#: 附加列由本模块幂等补齐（SQLite 无 ADD COLUMN IF NOT EXISTS），
#: `SCHEMA_VERSION` / `PRAGMA user_version` 仍是 4。
REPORT_COLUMNS = {"report_html_sha256": "TEXT NOT NULL DEFAULT ''"}
SELF_FILE = "casepack.json"     # 记录哈希的文件本身不参与 content_sha256

PACKABLE_STATES = ("REVIEW", "REPORTED", "CLOSED", "REJECTED", "NO_REPRO",
                   "NEEDS_EVIDENCE")
CLOSABLE_STATES = ("REPORTED", "REJECTED", "NO_REPRO", "NEEDS_EVIDENCE")


class CasePackError(ValueError):
    """Case Pack 打包错误。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_bytes(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
                       default=str) + "\n").encode("utf-8")


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _evidence_manifest(store, task_id: str, evidence_root=None) -> dict:
    rows = store.list_evidence(task_id)
    root = Path(evidence_root) if evidence_root else store.path.parent / "evidence"
    items = []
    for row in rows:
        path = Path(str(row.get("path") or ""))
        if not path.is_absolute():
            path = root / path.name
        present = path.is_file()
        hash_ok = present and sha256_file(path) == row["sha256"]
        items.append({
            "sha256": row["sha256"],
            "size": int(row.get("size") or 0),
            "kind": row["kind"],
            "source_stage": row.get("source_stage", ""),
            "created_at": row.get("created_at", ""),
            "path": str(path),
            "present": present,
            "hash_ok": bool(hash_ok),
            "blob_included": False,
        })
    items.sort(key=lambda x: (x["kind"], x["sha256"]))
    return {
        "schema": "vulnmap.evidence.manifest.v1",
        "task_id": task_id,
        "generated_at": now(),
        "blob_policy": ("全部 blob 留在内容寻址 store（evidence/<sha256>），"
                        "pack 只记哈希与位置，不复制日志"),
        "count": len(items),
        "all_present": all(i["present"] for i in items) if items else True,
        "all_hash_ok": all(i["hash_ok"] for i in items) if items else True,
        "items": items,
        "manifest_sha256": sha256(_json_bytes(items)).hexdigest(),
    }


# ------------------------------------------------------------ 证据交接（W3）
HANDOFF_FILE = "handoff.json"

#: 交接口径的唯一措辞：`handoff.json` / `casepack.json` 的 `handoff` 与
#: `verdict.handoff` / `report.md` / `report.html` 说的是同一句话。
HANDOFF_NOTE = ("只有 accepted 且 run_id/execution_id/evidence_sha256 齐全的项"
                "算可追溯结论；pending/needs_evidence 一律不算结论，"
                "也不进包级 benchmark_verified / accepted_by_review")

#: 计数键（顺序稳定；缺项一律按 0——0 是事实，不是“未知”）
HANDOFF_COUNT_KEYS = ("items", "pending", "accepted", "rejected",
                      "needs_evidence", "conclusions", "unverified")


def _handoff_view(store, task_id: str, *, revisions=None) -> dict:
    """只读交接视图（`adaptive.handoff.handoff_view` 的唯一调用点）。

    延迟导入：`casepack` 是 `agent.platform` 的常驻导出，导入期不该把研究
    子系统整条依赖链拖进来。异常**不吞**：视图取不到就是取不到，不编一份
    空视图冒充“没有待复核项”。
    """
    from .adaptive.handoff import handoff_view       # 延迟导入：避免包级循环
    return handoff_view(store, task_id, revisions=revisions)


def _handoff_counts(handoff: dict | None) -> dict:
    """交接计数：有视图就只转述视图里的数，没有视图就全是 0。"""
    source = handoff or {}
    counts = dict(source.get("counts") or {})
    out = {key: int(counts.get(key) or 0) for key in HANDOFF_COUNT_KEYS}
    if "items" not in counts:
        out["items"] = len(source.get("items") or [])
    if "conclusions" not in counts:
        out["conclusions"] = len(source.get("conclusions") or [])
    if "unverified" not in counts:
        out["unverified"] = out["pending"] + out["needs_evidence"]
    return out


def _handoff_block(handoff: dict | None) -> dict:
    """`casepack.json` 的 `handoff` 段：只放文件名与计数，明细在文件里。"""
    counts = _handoff_counts(handoff)
    return {"file": HANDOFF_FILE,
            "counts": counts,
            "conclusions": counts["conclusions"],
            "unverified": counts["unverified"],
            "note": HANDOFF_NOTE}


def _render_handoff_md(handoff: dict | None) -> list[str]:
    """证据交接段：逐行列出待复核项，并写明什么才算结论。"""
    counts = _handoff_counts(handoff)
    items = list((handoff or {}).get("items") or [])
    lines = [
        "## 证据交接（handoff）", "",
        f"- `{HANDOFF_FILE}`：交接项 {counts['items']} 条 —— pending "
        f"{counts['pending']} / accepted {counts['accepted']} / rejected "
        f"{counts['rejected']} / needs_evidence {counts['needs_evidence']}；"
        f"可追溯结论 {counts['conclusions']} 条，未核验 {counts['unverified']} 条",
        f"- 口径：{HANDOFF_NOTE}。",
        "- 交接项只是**原始执行记录**的排队与复核痕迹；它们不产生"
        " `verified` 之类的裁决字段，漏洞结论仍只来自 verifications/reviews。",
        "",
        "| item_id | status | run_id | execution_id | evidence_sha256 | revision_id |",
        "|---|---|---|---|---|---|",
    ]
    for row in items:
        run_id = str(row.get("run_id") or "")[:16] or "—"
        evidence = str(row.get("evidence_sha256") or "")[:16] or "—"
        lines.append(
            f"| {row.get('item_id') or '—'} | {row.get('status') or '—'} | "
            f"`{run_id}` | `{row.get('execution_id') or '—'}` | "
            f"`{evidence}` | `{row.get('revision_id') or '—'}` |")
    if not items:
        lines.append("| — | — | — | — | — | — |")
    lines.append("")
    return lines


# ------------------------------------------------------------ 研究产物（P4b）
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def research_dir(store, task_id: str, research_root=None) -> Path:
    """研究报告目录：显式 root > `<db 目录>/research/<task_id>`
    （与 `adaptive.cli.paths_for()` 同口径，不另立第二套布局）。"""
    if research_root:
        return Path(research_root)
    return Path(store.path).parent / RESEARCH_DIRNAME / str(task_id)


def research_files(research=None) -> tuple[str, ...]:
    """有研究产物时进包的额外文件；没有就一个都不加（清单不冒充）。

    参数可省：`research_files()` → `()`，`research_files(bundle)` → 六个文件。
    """
    return RESEARCH_FILES if research else ()


def _recorded_report_sha(bus, task_id: str, path: Path) -> str:
    """`research.mapped` 里登记的 `report_sha256`。

    只认 `report_path` 与本次读取路径一致的**最后**一条：研究目录可被
    `--research-root` 改到别处，事件是唯一知道产物真正落在哪的记录。
    """
    if bus is None:
        return ""
    target = str(path)
    recorded = ""
    for event in bus.list(task_id):
        if str(event.get("event_type") or "") != "research.mapped":
            continue
        payload = event.get("payload") or {}
        if str(payload.get("report_path") or "") != target:
            continue
        recorded = str(payload.get("report_sha256") or "")
    return recorded


def load_research(store, task_id: str, *, research_root=None, bus=None,
                  required: bool = False) -> dict | None:
    """读取并校验研究产物；冲突一律 `CasePackError`（不半写、不猜）。

    校验四件事：可解析、schema 认识、属于本任务、与事件登记哈希一致。
    没有研究产物时返回 `None`（研究循环从没跑过不是错误，`required=True` 时才是）。
    """
    root = research_dir(store, task_id, research_root)
    path = root / "research.json"
    if not path.is_file():
        if required:
            raise CasePackError(
                f"casepack requires research.json under {root}; "
                "run `platform run <task> --research` first")
        return None
    raw = path.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CasePackError(f"research.json 不是合法 JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise CasePackError(
            f"research.json 顶层必须是对象，实得 {type(doc).__name__}")
    if str(doc.get("schema") or "") != RESEARCH_SCHEMA:
        raise CasePackError(
            f"research.json schema 不认识: {doc.get('schema')!r}"
            f"（期望 {RESEARCH_SCHEMA}）")
    if str(doc.get("task_id") or "") != str(task_id):
        raise CasePackError(
            f"research.json 属于另一个任务: {doc.get('task_id')!r}"
            f" != {task_id!r}")
    controller = doc.get("controller")
    # 预算预检中止的研究运行会写 `controller: null`：那是真产物（控制器没跑），
    # 不是坏报告——按“0 轮”打包并在块里标注 controller_absent，不替它编轮次。
    if controller is not None:
        if not isinstance(controller, dict):
            raise CasePackError("research.json controller 必须是对象或 null")
        for key in ("rounds", "timeline"):
            if not isinstance(controller.get(key), list):
                raise CasePackError(
                    f"research.json controller.{key} 必须是列表")
    digest = sha256(raw).hexdigest()
    recorded = _recorded_report_sha(bus, task_id, path)
    if recorded and recorded != digest:
        raise CasePackError(
            "research.json 与 research.mapped 登记的 sha256 不一致: "
            f"{digest[:12]} != {recorded[:12]}（产物被改写或不是同一轮）")
    return {"path": path, "root": root, "sha256": digest, "bytes": raw,
            "doc": doc, "recorded_sha256": recorded,
            "match": None if not recorded else (recorded == digest)}


def _pick(doc, keys) -> dict:
    """固定键集合地摘字段：缺的给 None，键永远在（派生文档因此可字节复算）。"""
    source = doc if isinstance(doc, dict) else {}
    return {key: source.get(key) for key in keys}


def _phase_order_ok(rows: list[dict]) -> bool | None:
    """阶段顺序是否仍与 `adaptive.controller.PHASES` 同序（漂移返回 False）。

    延迟导入：`casepack` 是 `agent.platform` 的常驻导出，不该在导入期把它拖进
    研究子系统的全部依赖；导入失败按“未知”处理，不冒充通过。
    """
    try:
        from .adaptive.controller import PHASES
    except Exception:                        # noqa: BLE001 - 未知不是通过
        return None
    order = {name: index for index, name in enumerate(PHASES)}
    seen = -1
    for row in rows:
        phase = str(row.get("phase") or "")
        if phase not in order:
            return False
        index = order[phase]
        if index < seen and not (phase == "AUTHORIZE"):
            return False
        seen = max(seen, index)
    return True


def _timeline_view(task_id: str, doc: dict) -> dict:
    controller = doc.get("controller") or {}
    rows: list[dict] = []
    for item in controller.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        rows.append({"round": int(item.get("round") or 0),
                     "phase": str(item.get("phase") or ""),
                     "status": str(item.get("status") or ""),
                     "detail": str(item.get("detail") or "")})
    summary: dict[str, dict] = {}
    for row in rows:
        bucket = summary.setdefault(row["phase"],
                                    {"phase": row["phase"], "count": 0,
                                     "statuses": {}})
        bucket["count"] += 1
        bucket["statuses"][row["status"]] = (
            bucket["statuses"].get(row["status"], 0) + 1)
    phases = sorted(summary.values(), key=lambda b: b["phase"])
    return {
        "schema": TIMELINE_SCHEMA,
        "task_id": task_id,
        "state": str(doc.get("state") or ""),
        "controller_state": str(doc.get("controller_state") or ""),
        "stop_reason": str(doc.get("stop_reason") or ""),
        "rounds": len(controller.get("rounds") or []),
        "max_rounds": int(doc.get("max_rounds") or 0),
        "timeline": rows,
        "phases": phases,
        "phase_order_ok": _phase_order_ok(rows),
        "counts": {"phases": len(rows),
                   "rounds": len(controller.get("rounds") or []),
                   "distinct_phases": len(phases)},
        "note": ("时间线是控制器阶段的事后快照；同一份 research.json 重算"
                 "必得同一份字节（无时间戳、固定键序）"),
    }


_ACTION_KEYS = ("action_id", "tool", "status", "reason", "hypothesis_id")
_BUILD_KEYS = ("build_id", "revision_id", "status", "exit_code", "duration",
               "log_sha256")
_SMOKE_KEYS = ("smoke_id", "revision_id", "status", "kind", "exit_code",
               "harness_failed")


def _rounds_view(task_id: str, doc: dict) -> dict:
    controller = doc.get("controller") or {}
    rounds: list[dict] = []
    totals: dict[str, int] = {"rounds": 0, "adopted": 0, "reverted": 0,
                             "candidate_rounds": 0, "actions": 0}
    action_status: dict[str, int] = {}
    for raw in controller.get("rounds") or []:
        if not isinstance(raw, dict):
            continue
        diagnosis = raw.get("diagnosis") or {}
        plan = raw.get("plan") or {}
        engineering = raw.get("engineering") or {}
        actions: list[dict] = []
        refs: list[str] = []
        for action in raw.get("actions") or []:
            if not isinstance(action, dict):
                continue
            item = _pick(action, _ACTION_KEYS)
            item["action_id"] = str(item.get("action_id") or "")
            item["tool"] = str(item.get("tool") or "")
            item["status"] = str(item.get("status") or "")
            item["evidence_refs"] = [str(ref) for ref
                                     in (action.get("evidence_refs") or [])]
            actions.append(item)
            action_status[item["status"]] = (
                action_status.get(item["status"], 0) + 1)
            refs.extend(item["evidence_refs"])
        for ref in diagnosis.get("evidence_refs") or []:
            refs.append(str(ref))
        candidates = int(diagnosis.get("candidates") or 0)
        totals["actions"] += len(actions)
        totals["adopted"] += 1 if raw.get("adopted") else 0
        totals["reverted"] += 1 if str(raw.get("reverted") or "") else 0
        totals["candidate_rounds"] += 1 if candidates > 0 else 0
        rounds.append({
            "round": int(raw.get("round") or 0),
            "facts_hash": str(raw.get("facts_hash") or ""),
            "diagnosis": {"code": str(diagnosis.get("code") or ""),
                          "severity": str(diagnosis.get("severity") or ""),
                          "candidates": candidates,
                          "reasons": [str(r) for r
                                      in (diagnosis.get("reasons") or [])],
                          "evidence_refs": sorted({str(ref) for ref in
                                                   (diagnosis.get("evidence_refs") or [])})},
            "plan": {"actions": len(plan.get("actions") or []),
                     "requests": len(plan.get("requests") or []),
                     "revision": bool(plan.get("revision")),
                     "note": str(plan.get("note") or "")},
            "actions": actions,
            "revision": str(raw.get("revision") or ""),
            "build": _pick(raw.get("build"), _BUILD_KEYS),
            "smoke": _pick(raw.get("smoke"), _SMOKE_KEYS),
            "engineering": {"scope": str(engineering.get("scope") or ""),
                            "adopt": bool(engineering.get("adopt")),
                            "subject": str(engineering.get("subject") or ""),
                            "failed": [str(name) for name
                                       in (engineering.get("failed") or [])],
                            "reasons": [str(reason) for reason
                                        in (engineering.get("reasons") or [])]},
            "adopted": bool(raw.get("adopted")),
            "reverted": str(raw.get("reverted") or ""),
            "compare": _pick(raw.get("compare"),
                             ("status", "comparable", "reason", "metric",
                              "delta", "verdict")),
            "invalidations": [dict(item) for item
                              in (raw.get("invalidations") or [])
                              if isinstance(item, dict)],
            "stop_reason": str(raw.get("stop_reason") or ""),
            "note": str(raw.get("note") or ""),
            "evidence_refs": sorted(set(refs)),
        })
    totals["rounds"] = len(rounds)
    return {
        "schema": ROUNDS_SCHEMA,
        "task_id": task_id,
        "counts": {**totals, "action_status": dict(sorted(action_status.items()))},
        "rounds": rounds,
        "note": ("每轮的动作/构建/冒烟/采纳/比较都是台账原文摘录；"
                 "负结果（未采纳、被回退、Δ=0、无候选）一条不删"),
    }


def _adoptions(doc: dict, research_root: Path) -> tuple[list[dict], list[dict]]:
    """工程采纳账：`<ws>/store/adoptions.jsonl`（只读；坏行与错 scope 进 invalid）。"""
    paths = doc.get("paths") or {}
    workspace = Path(str(paths.get("workspace") or research_root / "ws"))
    ledger = workspace / "store" / "adoptions.jsonl"
    items: list[dict] = []
    invalid: list[dict] = []
    if not ledger.is_file():
        return items, invalid
    for lineno, line in enumerate(
            ledger.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            entry = json.loads(text)
        except json.JSONDecodeError as exc:
            invalid.append({"source": "adoptions.jsonl", "line": lineno,
                            "reason": f"not_json: {exc}"})
            continue
        if not isinstance(entry, dict):
            invalid.append({"source": "adoptions.jsonl", "line": lineno,
                            "reason": "not_an_object"})
            continue
        scope = str(entry.get("scope") or "")
        item = {
            "source": "adoptions.jsonl", "line": lineno, "scope": scope,
            "adopt": bool(entry.get("adopt")),
            "subject": str(entry.get("subject") or ""),
            "failed": [str(name) for name in (entry.get("failed") or [])],
            "reasons": [str(reason) for reason in (entry.get("reasons") or [])],
            "policy_version": str(entry.get("policy_version") or ""),
            "at": str(entry.get("at") or ""),
        }
        if scope != "engineering":
            invalid.append({"source": "adoptions.jsonl", "line": lineno,
                            "reason": "scope_not_engineering", "scope": scope})
            continue
        items.append(item)
    return items, invalid


def _decisions_view(task_id: str, doc: dict, rounds_view: dict,
                    verifications: list[dict], reviews: list[dict],
                    research_root: Path) -> dict:
    adoptions, invalid = _adoptions(doc, research_root)
    round_decisions = [{
        "round": item["round"], "scope": item["engineering"]["scope"],
        "adopt": item["engineering"]["adopt"],
        "failed": item["engineering"]["failed"],
        "reasons": item["engineering"]["reasons"],
        "subject": item["engineering"]["subject"],
        "reverted": item["reverted"],
        "source": "controller.round",
    } for item in rounds_view.get("rounds") or []
        if item["engineering"]["scope"] or item["engineering"]["adopt"]]
    verified = [row for row in verifications if row.get("verified")]
    accepted = [row for row in reviews if row.get("verdict") == "accept"]
    return {
        "schema": DECISIONS_SCHEMA,
        "task_id": task_id,
        "note": ("工程采纳 = 可构建/可驱动/有收益；研究进展 = 轮次与动作的工作量记账；"
                 "漏洞验证只来自 verifications/reviews。三段互不代签，"
                 "动作次数不当智能"),
        "engineering": {
            "adoptions": adoptions,
            "round_decisions": round_decisions,
            "invalid": invalid,
            "counts": {"adoptions": len(adoptions),
                       "round_decisions": len(round_decisions),
                       "invalid": len(invalid)},
        },
        "research_progress": {
            "rounds": int(rounds_view["counts"].get("rounds") or 0),
            "executions": int(doc.get("executions") or 0),
            "executions_applied": int(doc.get("executions_applied") or 0),
            "executions_failed": int(doc.get("executions_failed") or 0),
            "observed_rounds": int(doc.get("observed_rounds") or 0),
            "candidates": int(doc.get("candidates") or 0),
            "actions": int(rounds_view["counts"].get("actions") or 0),
            "action_status": dict(rounds_view["counts"].get("action_status") or {}),
            "stop_reason": str(doc.get("stop_reason") or ""),
            "controller_state": str(doc.get("controller_state") or ""),
            "verification_allowed": bool(doc.get("verification_allowed")),
        },
        "vulnerability": {
            "verifications": len(verifications),
            "verified": len(verified),
            "reviews": len(reviews),
            "accepted": len(accepted),
            "note": ("这里只转录已验证/已复核记录；research 的 "
                     "verification_allowed 只表示“可以交给 verify”，不计入本段"),
        },
    }


def _evidence_refs_view(task_id: str, rounds_view: dict, manifest: dict) -> dict:
    registered = {str(item.get("sha256") or ""): item
                  for item in manifest.get("items") or []}
    refs: list[dict] = []
    invalid: dict[str, dict] = {}
    unresolved: dict[str, dict] = {}
    for item in rounds_view.get("rounds") or []:
        entries = [(ref, "action", action.get("action_id") or "",
                    action.get("tool") or "")
                   for action in item.get("actions") or []
                   for ref in action.get("evidence_refs") or []]
        entries += [(ref, "diagnosis", "", "")
                    for ref in (item.get("diagnosis") or {}).get(
                        "evidence_refs") or []]
        for ref, source, action_id, tool in entries:
            text = str(ref or "").strip().lower()
            origin = {"round": item["round"], "action_id": str(action_id),
                      "tool": str(tool), "source": source}
            if not _SHA256_RE.match(text):
                entry = invalid.setdefault(text or "<empty>", {
                    "ref": str(ref or ""), "reason": "not_sha256",
                    "referenced_by": []})
                entry["referenced_by"].append(origin)
                continue
            row = registered.get(text)
            if row is None:
                entry = unresolved.setdefault(text, {
                    "ref": text, "reason": "not_registered_for_this_task",
                    "referenced_by": []})
                entry["referenced_by"].append(origin)
                refs.append({"ref": text, "round": origin["round"],
                             "action_id": origin["action_id"],
                             "tool": origin["tool"], "source": source,
                             "registered": False, "present": False,
                             "hash_ok": False, "kind": "",
                             "path": ""})
                continue
            refs.append({"ref": text, "round": origin["round"],
                         "action_id": origin["action_id"], "tool": origin["tool"],
                         "source": source, "registered": True,
                         "present": bool(row.get("present")),
                         "hash_ok": bool(row.get("hash_ok")),
                         "kind": str(row.get("kind") or ""),
                         "path": str(row.get("path") or "")})
    for entry in list(invalid.values()) + list(unresolved.values()):
        entry["referenced_by"].sort(key=lambda o: (o["round"], o["action_id"],
                                                   o["source"]))
    unique = sorted({row["ref"] for row in refs})
    return {
        "schema": REFS_SCHEMA,
        "task_id": task_id,
        "counts": {"refs": len(refs), "unique": len(unique),
                   "registered": sum(1 for row in refs if row["registered"]),
                   "resolved": sum(1 for row in refs
                                   if row["registered"] and row["hash_ok"]),
                   "unresolved": len(unresolved), "invalid": len(invalid)},
        "refs": sorted(refs, key=lambda row: (row["round"], row["action_id"],
                                              row["source"], row["ref"])),
        "unresolved": [unresolved[key] for key in sorted(unresolved)],
        "invalid": [invalid[key] for key in sorted(invalid)],
        "note": ("引用只有在**本任务** task_evidence 里登记过才算命中；"
                 "跨任务的同名哈希进 unresolved，不冒充证据"),
    }


def _compare_view(task_id: str, doc: dict, events, baseline) -> dict:
    """研究循环 vs 单次 fuzz 的对照实验；没有基准就没有对照（不补 0）。"""
    from .adaptive.compare import build_compare     # 延迟导入：不拖累导入期
    baseline = baseline or {}
    notes = ["baseline=provided" if (baseline.get("report")
                                     or baseline.get("events"))
             else "baseline=absent"]
    compare = build_compare(
        research_report=doc,
        research_events=events or (),
        baseline_report=baseline.get("report"),
        baseline_events=baseline.get("events") or (),
        baseline_label=str(baseline.get("label") or ""),
        notes=notes)
    compare["task_id"] = task_id
    return compare


def research_views(store, task_id: str, research: dict, *, bus=None,
                   manifest: dict | None = None, verifications=(),
                   reviews=(), baseline=None) -> dict:
    """把研究报告派生成包内五份文档（timeline/rounds/decisions/refs/compare）。"""
    doc = research["doc"]
    events = bus.list(task_id) if bus is not None else []
    timeline = _timeline_view(task_id, doc)
    rounds = _rounds_view(task_id, doc)
    decisions = _decisions_view(task_id, doc, rounds, list(verifications),
                                list(reviews), Path(research["root"]))
    refs = _evidence_refs_view(task_id, rounds, manifest or {})
    compare = _compare_view(task_id, doc, events, baseline)
    return {"timeline": timeline, "rounds": rounds, "decisions": decisions,
            "evidence_refs": refs, "compare": compare, "events": events}


def _research_block(task_id: str, research: dict | None, views: dict) -> dict:
    """`casepack.json` 里的研究块：没有产物时如实写 absent，不伪造空轮次。"""
    if research is None:
        return {"status": "absent", "path": "", "sha256": "",
                "recorded_sha256": "", "match": None, "task_id": task_id,
                "rounds": 0, "executions": 0, "candidates": 0,
                "stop_reason": "", "verification_allowed": False,
                "files": [],
                "note": "任务没有研究产物：run --research 之后才有轮次可打包"}
    doc = research["doc"]
    return {
        "status": "ok",
        "path": "research.json",
        "sha256": research["sha256"],
        "recorded_sha256": research["recorded_sha256"],
        "match": research["match"],
        "task_id": str(doc.get("task_id") or ""),
        "state": str(doc.get("state") or ""),
        "controller_state": str(doc.get("controller_state") or ""),
        "rounds": int(views["timeline"]["counts"].get("rounds") or 0),
        "executions": int(doc.get("executions") or 0),
        "candidates": int(doc.get("candidates") or 0),
        "stop_reason": str(doc.get("stop_reason") or ""),
        "verification_allowed": bool(doc.get("verification_allowed")),
        "controller_absent": doc.get("controller") is None,
        "phase_order_ok": views["timeline"]["phase_order_ok"],
        "files": list(RESEARCH_FILES),
        "compare": {"verdict": views["compare"].get("verdict"),
                    "comparable": bool(views["compare"].get("comparable"))},
        "note": ("research.json 原样复制；其余文档由同一份报告确定性派生；"
                 "verification_allowed 只表示可以交给 verify，不是已验证"),
    }


def _fmt_number(value, digits: int = 3) -> str:
    """数字/未知的统一显示：未知显示“未知”，0 显示 0（0 是事实不是缺失）。"""
    if value is None or value == "":
        return "未知"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.{digits}f}".rstrip("0").rstrip(".")
        return text or "0"
    return str(value)


def _yes_no(value) -> str:
    if value is None:
        return "未知"
    return "是" if value else "否"


def _render_research_md(research: dict | None) -> list[str]:
    """研究进展：轮次、阶段、对照实验（工作量与观测事实，不给漏洞结论）。"""
    if not research:
        return ["## 研究进展", "",
                "- 本次打包**没有研究产物**（`platform run --research` 未跑过）："
                "轮次/动作/对照字段如实缺失，不用 0 或空轮次填充。", ""]
    block = research["block"]
    timeline = research["timeline"]
    rounds = research["rounds"]
    match = block.get("match")
    match_text = ("一致" if match else ("事件里没有登记" if match is None
                                        else "不一致"))
    phases = "；".join(f"{row['phase']} ×{row['count']}"
                       for row in timeline.get("phases") or []) or "（无）"
    lines = ["## 研究进展", "",
             f"- 研究报告: `research.json`（sha256 `{block['sha256']}`，"
             f"与 `research.mapped` 登记{match_text}）",
             f"- 控制器: `{block['controller_state'] or '—'}` / 停止原因 "
             f"`{block['stop_reason'] or '—'}` / 轮次 {block['rounds']} / "
             f"执行 {block['executions']} / 候选 {block['candidates']}",
             f"- 阶段顺序与控制器一致: {_yes_no(timeline.get('phase_order_ok'))}",
             f"- 阶段汇总: {phases}",
             "- 可交独立验证: "
             + ("是" if block.get("verification_allowed") else "否")
             + "（`verification_allowed` 只表示“可以交给 verify”，"
               "不是“已经验证”，也不进漏洞验证段）",
             ""]
    lines += ["### 轮次（动作数只记工作量，不推断智能）", "",
              "| round | 诊断 | 候选 | 动作 | 采纳 | 回退 | 覆盖 Δ | 停止原因 |",
              "|---|---|---|---|---|---|---|---|"]
    for item in rounds.get("rounds") or []:
        diagnosis = item.get("diagnosis") or {}
        compare = item.get("compare") or {}
        lines.append(
            f"| {item['round']} | `{diagnosis.get('code') or '—'}`"
            f"（{diagnosis.get('severity') or '—'}） | "
            f"{diagnosis.get('candidates', 0)} | {len(item.get('actions') or [])} | "
            f"{'是' if item.get('adopted') else '否'} | "
            f"`{item.get('reverted') or '—'}` | "
            f"{_fmt_number(compare.get('delta'))} | "
            f"`{item.get('stop_reason') or '—'}` |")
    if not rounds.get("rounds"):
        lines.append("| — | — | — | — | — | — | — | — |")
    counts = rounds.get("counts") or {}
    lines += ["",
              f"- 动作状态计数: `{json.dumps(counts.get('action_status') or {}, ensure_ascii=False, sort_keys=True)}`",
              f"- 采纳 {counts.get('adopted', 0)} 轮 / 回退 {counts.get('reverted', 0)} 轮 / "
              f"有候选 {counts.get('candidate_rounds', 0)} 轮", ""]
    return lines


def _render_decisions_md(research: dict | None) -> list[str]:
    """工程采纳：只说明可构建/可驱动/有收益（scope=engineering）。"""
    if not research:
        return ["## 工程采纳", "",
                "- 没有研究产物 → 没有工程采纳记录。本段不借用候选/复核凑数。", ""]
    engineering = (research["decisions"] or {}).get("engineering") or {}
    lines = ["## 工程采纳", "",
             "- 口径：采纳=副本能构建、冒烟不假阳性、执行有观测（有 compare 时还要"
             " `comparable` 且 `delta>0`）；它**不产生**漏洞结论。",
             ""]
    lines += ["| 来源 | round | scope | adopt | failed | 说明 |",
              "|---|---|---|---|---|---|"]
    rows = []
    for item in engineering.get("adoptions") or []:
        rows.append(
            f"| `adoptions.jsonl:{item.get('line')}` | — | `{item.get('scope')}` | "
            f"{'是' if item.get('adopt') else '否'} | "
            f"{', '.join(item.get('failed') or []) or '—'} | "
            f"{', '.join(item.get('reasons') or []) or '—'} |")
    for item in engineering.get("round_decisions") or []:
        rows.append(
            f"| controller.round | {item.get('round')} | "
            f"`{item.get('scope') or '—'}` | {'是' if item.get('adopt') else '否'} | "
            f"{', '.join(item.get('failed') or []) or '—'} | "
            f"{', '.join(item.get('reasons') or []) or '—'} |")
    lines += rows or ["| — | — | — | — | — | — |"]
    invalid = engineering.get("invalid") or []
    if invalid:
        lines += ["", f"- 无效采纳记录 {len(invalid)} 条（scope 不是 engineering "
                      "或不是 JSON）："]
        for item in invalid:
            lines.append(f"  - `{item.get('source')}:{item.get('line')}` "
                         f"{item.get('reason')}")
    lines.append("")
    return lines


def _render_vulnerability_md(research: dict | None, verifications: list[dict],
                            reviews: list[dict]) -> list[str]:
    """漏洞验证：唯一的裁决来源（研究循环自己不产裁决）。"""
    verified = [row for row in verifications if row.get("verified")]
    accepted = [row for row in reviews if row.get("verdict") == "accept"]
    lines = ["## 漏洞验证", "",
             f"- 验证记录 {len(verifications)} 条，其中 verified {len(verified)} 条；"
             f"复核 {len(reviews)} 条，其中 accept {len(accepted)} 条",
             "- 本段是包内唯一的裁决来源：`verifications`/`reviews`。"
             "研究报告的 `verification_allowed`、工程采纳、动作次数都不在此列。", ""]
    if research:
        allowed = bool((research.get("block") or {}).get("verification_allowed"))
        lines.insert(3, f"- 研究循环 `verification_allowed`: "
                        f"{'true' if allowed else 'false'}"
                        + ("（只表示可以交给 verify，未验证）" if allowed else
                           "（研究循环没有交出可验证候选）"))
    lines += ["| id | kind | status | verified | blockers |",
              "|---|---|---|---|---|"]
    for ver in verifications:
        blockers = ", ".join((ver.get("detail") or {}).get("blockers") or []) or "—"
        lines.append(f"| {ver.get('verification_id')} | {ver.get('kind')} | "
                     f"{ver.get('status')} | {ver.get('verified')} | {blockers} |")
    if not verifications:
        lines.append("| — | — | — | — | — |")
    lines.append("")
    return lines


def _render_report(task: dict, state: dict, candidates: list[dict],
                   verifications: list[dict], reviews: list[dict],
                   manifest: dict, research: dict | None = None,
                   handoff: dict | None = None) -> str:
    lines = [f"# Case Pack: {task['task_id']}", ""]
    lines += ["## 任务", "",
              f"- benchmark: `{task['benchmark']}`",
              f"- target: `{task['target']}`",
              f"- mode: `{task['mode']}`",
              f"- state: `{state['state']}`"
              + (f"（{state['terminal_reason']}）" if state.get("terminal_reason") else ""),
              ""]
    lines += ["## 事件流", "", f"- 事件数: {state['events']}",
              "- 阶段迁移: " + " → ".join(
                  f"{t['to']}" for t in state.get("transitions") or []) if state.get("transitions")
              else "- 阶段迁移: （无）", ""]
    lines += _render_research_md(research)
    if research:
        lines += _compare_md(research.get("compare") or {})
    lines += ["## 候选", "",
              "| id | crash_type | state | stack_hash | 证据 |",
              "|---|---|---|---|---|"]
    for cand in candidates:
        lines.append(f"| {cand.get('id')} | {cand.get('crash_type')} | "
                     f"{cand.get('state')} | `{str(cand.get('stack_hash'))[:16]}` | "
                     f"`{str(cand.get('evidence_sha256'))[:12]}` |")
    if not candidates:
        lines.append("| — | — | — | — | — |")
    lines += [""]
    lines += _render_decisions_md(research)
    lines += _render_vulnerability_md(research, verifications, reviews)
    lines += ["## 复核", "",
              "| id | verdict | verification | 说明 |",
              "|---|---|---|---|"]
    for rev in reviews:
        lines.append(f"| {rev.get('review_id')} | {rev.get('verdict')} | "
                     f"{rev.get('verification_id')} | {rev.get('reason')} |")
    if not reviews:
        lines.append("| — | — | — | — |")
    lines += [""]
    lines += _render_handoff_md(handoff)
    lines += ["## 证据清单", "",
              f"- 条目数: {manifest['count']}；全部存在: {manifest['all_present']}；"
              f"全部哈希可复算: {manifest['all_hash_ok']}",
              f"- manifest sha256: `{manifest['manifest_sha256']}`", ""]
    if research:
        refs = research.get("evidence_refs") or {}
        counts = refs.get("counts") or {}
        lines += [f"- 研究证据引用: {counts.get('refs', 0)} 条（去重 "
                  f"{counts.get('unique', 0)}），命中 "
                  f"{counts.get('resolved', 0)} 条，未登记 "
                  f"{counts.get('unresolved', 0)} 条，非法 "
                  f"{counts.get('invalid', 0)} 条", ""]
    lines += ["## 口径声明", "",
              "- CyberGym 判据：同一输入的 vuln 崩 / fix 干净（双端）；",
              "- ExploitGym 判据：官方入口取到 flag（**不要求** fix 端）；",
              "- VulnGym 判据：基线/修补行为差分；",
              "- 单端 fuzz 只产候选，不产确认结论；本包的结论只来自"
              "验证记录与复核记录。",
              "- 三类事实分开写：工程采纳（可构建/可驱动/有收益）、漏洞验证"
              "（只来自 verifications/reviews）、研究进展（轮次与对照实验）。"
              "动作次数/轮数只当工作量记账，不当智能。", ""]
    return "\n".join(lines)


def _compare_md(compare: dict) -> list[str]:
    """对照实验段落：交给 `adaptive.compare.render_markdown` 渲染（单一渲染口径）。"""
    if not compare:
        return ["## 对照实验（研究循环 vs 单次 fuzz）", "",
                "- 没有研究产物 → 没有对照。", ""]
    from .adaptive.compare import render_markdown
    text = render_markdown(compare).rstrip("\n")
    return text.splitlines() + [""]


# ---------------------------------------------------------------- HTML 渲染
def _h(value) -> str:
    """HTML 转义：台账里的字段（候选/复核/证据路径）一律不可信。"""
    return html.escape("" if value is None else str(value), quote=True)


def _short(value, size: int = 16) -> str:
    text = "" if value is None else str(value)
    return text[:size] or "—"


def _rows(items, empty: str, colspan: int) -> str:
    return "".join(items) if items else (
        f'<tr><td class="muted" colspan="{colspan}">{empty}</td></tr>')


def _flag(value: bool, yes: str = "是", no: str = "否") -> str:
    return (f'<span class="ok">{_h(yes)}</span>' if value
            else f'<span class="bad">{_h(no)}</span>')


def _html_handoff_counts(handoff: dict | None, verdict: dict | None) -> dict:
    """HTML 侧交接计数：优先取交接视图，没有视图就取包里 `verdict.handoff`。

    计数 + 逐项明细行都来自同一份交接视图（`handoff["items"]`）；没传视图时
    计数回落到包里 `verdict.handoff`、明细显示“（无）”。两种来源口径一致，
    所以“用包自身快照重渲染”与包内 `report.html` 逐字相同——网页仍然只是
    所记录快照的确定性函数。
    """
    counts = _handoff_counts(handoff)
    if handoff:
        return counts
    segment = (verdict or {}).get("handoff") or {}
    for key in HANDOFF_COUNT_KEYS:
        if key in segment:
            counts[key] = int(segment.get(key) or 0)
    if "unverified" not in segment:
        counts["unverified"] = counts["pending"] + counts["needs_evidence"]
    return counts


def render_report_html(task: dict, state: dict, candidates: list[dict],
                        verifications: list[dict], reviews: list[dict],
                        manifest: dict, verdict: dict | None = None,
                        research: dict | None = None,
                        handoff: dict | None = None) -> str:
    """确定性 HTML：样式内联、无脚本、无外部资源、无时间戳。

    输入与 `_render_report` 同一组快照，因此同一批台账重算必得同一份字节，
    `report.html` 才能进内容哈希（`content_sha256`）与 `reports` 台账。

    交接小节的明细行来自传入的 `handoff` 视图（`handoff.json` 的同一份字节）；
    没传视图时计数回落到包里 `verdict.handoff`，明细行显示“（无）”——
    两种来源口径一致，网页仍是所记录快照的确定性函数。
    """
    verdict = verdict or _pack_verdict(verifications, reviews, handoff)
    handoff_counts = _html_handoff_counts(handoff, verdict)
    transitions = state.get("transitions") or []
    chips = "".join(f'<span class="chip">{_h(t.get("to"))}</span>'
                    for t in transitions) or '<span class="muted">（无）</span>'

    candidate_rows = []
    for cand in candidates:
        candidate_rows.append(
            "<tr>"
            f'<td class="mono">{_h(cand.get("id"))}</td>'
            f'<td>{_h(cand.get("crash_type"))}</td>'
            f'<td>{_h(cand.get("state"))}</td>'
            f'<td class="mono">{_h(_short(cand.get("stack_hash")))}</td>'
            f'<td class="mono">{_h(_short(cand.get("evidence_sha256"), 12))}</td>'
            "</tr>")

    verification_rows = []
    for ver in verifications:
        blockers = (ver.get("detail") or {}).get("blockers") or []
        verification_rows.append(
            "<tr>"
            f'<td class="mono">{_h(ver.get("verification_id"))}</td>'
            f'<td>{_h(ver.get("kind"))}</td>'
            f'<td>{_h(ver.get("status"))}</td>'
            f'<td>{_flag(bool(ver.get("verified")), "verified", "未通过")}</td>'
            f'<td>{_h(", ".join(str(b) for b in blockers) or "—")}</td>'
            "</tr>")

    review_rows = []
    for rev in reviews:
        review_rows.append(
            "<tr>"
            f'<td class="mono">{_h(rev.get("review_id"))}</td>'
            f'<td>{_h(rev.get("verdict"))}</td>'
            f'<td class="mono">{_h(rev.get("verification_id"))}</td>'
            f'<td>{_h(rev.get("reason"))}</td>'
            "</tr>")

    evidence_rows = []
    for item in manifest.get("items") or []:
        evidence_rows.append(
            "<tr>"
            f'<td>{_h(item.get("kind"))}</td>'
            f'<td class="mono">{_h(item.get("sha256"))}</td>'
            f'<td class="mono">{_h(item.get("size"))}</td>'
            f'<td>{_flag(bool(item.get("present")), "在", "缺失")}</td>'
            f'<td>{_flag(bool(item.get("hash_ok")), "可复算", "不匹配")}</td>'
            f'<td class="mono">{_h(item.get("path"))}</td>'
            "</tr>")

    # ---- W3：证据交接（同一口径在 md 与 html 各说一次；明细逐行进表）
    handoff_rows = []
    for row in (handoff or {}).get("items") or []:
        handoff_rows.append(
            "<tr>"
            f'<td class="mono">{_h(row.get("item_id"))}</td>'
            f'<td>{_h(row.get("status"))}</td>'
            f'<td class="mono">{_h(_short(row.get("run_id"), 16))}</td>'
            f'<td class="mono">{_h(row.get("execution_id"))}</td>'
            f'<td class="mono">{_h(_short(row.get("evidence_sha256"), 16))}</td>'
            "</tr>")
    handoff_html = (
        '<section class="card"><dl class="kv">'
        f'<dt>交接项</dt><dd>{_h(handoff_counts["items"])} 条'
        f'（pending {_h(handoff_counts["pending"])} / accepted '
        f'{_h(handoff_counts["accepted"])} / rejected '
        f'{_h(handoff_counts["rejected"])} / needs_evidence '
        f'{_h(handoff_counts["needs_evidence"])}）</dd>'
        f'<dt>可追溯结论</dt><dd>{_h(handoff_counts["conclusions"])} 条</dd>'
        f'<dt>未核验</dt><dd>{_h(handoff_counts["unverified"])} 条</dd>'
        '</dl></section>'
        '<table><thead><tr><th>item_id</th><th>status</th><th>run_id</th>'
        '<th>execution_id</th><th>evidence_sha256</th></tr></thead><tbody>'
        + _rows(handoff_rows, "（无）", 5) + '</tbody></table>'
        f'<p class="muted">{_h(HANDOFF_NOTE)}。逐项明细与包内 handoff.json'
        ' 同源：网页只是它所记录快照的确定性函数，不另算一套计数，'
        '也不产生裁决字段。</p>')

    # ---- P4b：研究进展 / 对照实验 / 工程采纳（三段分开，互不代签）
    if research:
        block_doc = research["block"]
        timeline = research["timeline"]
        rounds = research["rounds"]
        compare = research.get("compare") or {}
        engineering = (research.get("decisions") or {}).get("engineering") or {}

        progress_rows = []
        for item in rounds.get("rounds") or []:
            diagnosis = item.get("diagnosis") or {}
            cmp_row = item.get("compare") or {}
            progress_rows.append(
                "<tr>"
                f'<td class="mono">{_h(item.get("round"))}</td>'
                f'<td>{_h(diagnosis.get("code"))}</td>'
                f'<td>{_h(diagnosis.get("candidates"))}</td>'
                f'<td>{_h(len(item.get("actions") or []))}</td>'
                f'<td>{_flag(bool(item.get("adopted")), "是", "否")}</td>'
                f'<td class="mono">{_h(item.get("reverted") or "—")}</td>'
                f'<td>{_h(_fmt_number(cmp_row.get("delta")))}</td>'
                f'<td class="mono">{_h(item.get("stop_reason") or "—")}</td>'
                "</tr>")
        phases_chips = "".join(
            f'<span class="chip">{_h(row.get("phase"))} ×{_h(row.get("count"))}</span>'
            for row in timeline.get("phases") or []) or '<span class="muted">（无）</span>'
        progress_html = (
            '<section class="card"><dl class="kv">'
            f'<dt>研究报告</dt><dd class="mono">{_h(block_doc.get("sha256"))}</dd>'
            f'<dt>控制器</dt><dd>{_h(block_doc.get("controller_state"))}</dd>'
            f'<dt>停止原因</dt><dd>{_h(block_doc.get("stop_reason") or "—")}</dd>'
            f'<dt>轮次 / 执行 / 候选</dt><dd>{_h(block_doc.get("rounds"))} / '
            f'{_h(block_doc.get("executions"))} / {_h(block_doc.get("candidates"))}</dd>'
            f'<dt>阶段顺序一致</dt><dd>{_yes_no(timeline.get("phase_order_ok"))}</dd>'
            f'<dt>可交独立验证</dt><dd>'
            f'{_flag(bool(block_doc.get("verification_allowed")), "是（不等于已验证）", "否")}</dd>'
            f'<dt>阶段汇总</dt><dd>{phases_chips}</dd>'
            '</dl></section>'
            '<table><thead><tr><th>round</th><th>诊断</th><th>候选</th><th>动作</th>'
            '<th>采纳</th><th>回退</th><th>覆盖 Δ</th><th>停止原因</th></tr></thead><tbody>'
            + _rows(progress_rows, "—", 8) + '</tbody></table>'
            '<p class="muted">动作数与轮数只记工作量，不推断“更聪明”。</p>')

        compare_rows = []
        for item in compare.get("metrics") or []:
            compare_rows.append(
                "<tr>"
                f'<td>{_h(item.get("metric"))}</td>'
                f'<td>{_h(_fmt_number(item.get("treatment")))}</td>'
                f'<td>{_h(_fmt_number(item.get("baseline")))}</td>'
                f'<td>{_h(_fmt_number(item.get("delta")))}</td>'
                f'<td>{_h(item.get("direction"))}</td>'
                f'<td>{_flag(bool(item.get("known")), "可比", "未知")}</td>'
                f'<td>{_h(item.get("reason") or "")}</td>'
                "</tr>")
        negative = compare.get("negative_results") or []
        negative_html = ('<ul class="terms">' + "".join(
            f'<li>{_h(item.get("item"))}：{_h(item.get("reason"))}</li>'
            for item in negative) + '</ul>') if negative else (
            '<p class="muted">负结果：无（也没有被丢弃的不可比指标）</p>')
        compare_html = (
            '<table><thead><tr><th>指标</th><th>研究循环</th><th>单次 fuzz</th>'
            '<th>Δ</th><th>方向</th><th>状态</th><th>说明</th></tr></thead><tbody>'
            + _rows(compare_rows, "—", 7) + '</tbody></table>'
            '<p class="muted">'
            + _h((compare.get("counts_are_not_intelligence") or {}).get("note") or "")
            + '</p>' + negative_html
            + f'<p class="muted">verdict = {_h(compare.get("verdict") or "not_evaluated")}；'
              '对照实验不产漏洞结论。</p>')

        decision_rows = []
        for item in engineering.get("adoptions") or []:
            decision_rows.append(
                "<tr>"
                f'<td class="mono">{_h("adoptions.jsonl:" + str(item.get("line")))}</td>'
                f'<td>—</td>'
                f'<td>{_h(item.get("scope"))}</td>'
                f'<td>{_flag(bool(item.get("adopt")), "采纳", "拒绝")}</td>'
                f'<td>{_h(", ".join(item.get("failed") or []) or "—")}</td>'
                f'<td>{_h(", ".join(item.get("reasons") or []) or "—")}</td>'
                "</tr>")
        for item in engineering.get("round_decisions") or []:
            decision_rows.append(
                "<tr>"
                f'<td class="mono">controller.round</td>'
                f'<td>{_h(item.get("round"))}</td>'
                f'<td>{_h(item.get("scope") or "—")}</td>'
                f'<td>{_flag(bool(item.get("adopt")), "采纳", "拒绝")}</td>'
                f'<td>{_h(", ".join(item.get("failed") or []) or "—")}</td>'
                f'<td>{_h(", ".join(item.get("reasons") or []) or "—")}</td>'
                "</tr>")
        decisions_html = (
            '<table><thead><tr><th>来源</th><th>round</th><th>scope</th>'
            '<th>结论</th><th>failed</th><th>说明</th></tr></thead><tbody>'
            + _rows(decision_rows, "—", 6) + '</tbody></table>'
            '<p class="muted">工程采纳只说明副本能构建、冒烟不假阳性、执行有观测；'
            '不产生漏洞结论。</p>')

        vuln_html = (
            '<section class="card"><dl class="kv">'
            f'<dt>研究循环 verification_allowed</dt><dd>'
            f'{_flag(bool(block_doc.get("verification_allowed")), "true（只表示可以交给 verify）", "false")}</dd>'
            f'<dt>验证记录</dt><dd>{_h(verdict.get("verifications"))} 条，verified '
            f'{_h(verdict.get("verified"))}</dd>'
            f'<dt>复核</dt><dd>{_h(verdict.get("reviews"))} 条，accept '
            f'{_h(verdict.get("accepted"))}</dd>'
            '</dl></section>')
    else:
        progress_html = (
            '<section class="card"><p class="muted">本次打包没有研究产物'
            '（`run --research` 未跑过）：轮次/动作/对照字段如实缺失，'
            '不用 0 或空轮次填充。</p></section>')
        compare_html = '<p class="muted">没有研究产物 → 没有对照。</p>'
        decisions_html = '<p class="muted">没有研究产物 → 没有工程采纳记录。</p>'
        vuln_html = (
            '<section class="card"><p class="muted">研究循环未运行；本段只转录'
            ' verifications/reviews。</p></section>')

    terminal = _h(state.get("terminal_reason")) if state.get("terminal_reason") else "—"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Case Pack: {_h(task.get("task_id"))}</title>
<style>
:root{{color-scheme:light}}
body{{margin:0;padding:32px;background:#f6f7f9;color:#1b1f24;font:14px/1.6 -apple-system,"Segoe UI",Roboto,"Noto Sans CJK SC",sans-serif}}
main{{max-width:1040px;margin:0 auto}}
h1{{font-size:24px;margin:0 0 4px}}
h2{{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #d8dee6}}
.sub{{color:#5b6572;margin:0 0 18px}}
.card{{background:#fff;border:1px solid #dce2ea;border-radius:8px;padding:16px 18px;margin:0 0 16px}}
dl.kv{{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0}}
dl.kv dt{{color:#5b6572}}
dl.kv dd{{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dce2ea;border-radius:8px;overflow:hidden}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #edf1f5;vertical-align:top}}
th{{background:#f0f3f7;font-weight:600;font-size:13px}}
tr:last-child td{{border-bottom:none}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}}
.chip{{display:inline-block;background:#eef2f8;border:1px solid #d3dce8;border-radius:999px;padding:1px 10px;margin:0 6px 6px 0;font-size:12px}}
.muted{{color:#7b8694}}
.ok{{color:#1a7f45;font-weight:600}}
.bad{{color:#b42318;font-weight:600}}
ul.terms{{margin:0;padding-left:20px}}
ul.terms li{{margin:2px 0}}
footer{{margin-top:24px;color:#7b8694;font-size:12px}}
</style>
</head>
<body>
<main>
<h1>Case Pack: {_h(task.get("task_id"))}</h1>
<p class="sub">{_h(task.get("benchmark"))} · {_h(task.get("target"))} · {_h(task.get("mode"))}</p>

<section class="card">
<dl class="kv">
<dt>state</dt><dd>{_h(state.get("state"))}</dd>
<dt>terminal_reason</dt><dd>{terminal}</dd>
<dt>benchmark</dt><dd>{_h(task.get("benchmark"))}</dd>
<dt>target</dt><dd>{_h(task.get("target"))}</dd>
<dt>mode</dt><dd>{_h(task.get("mode"))}</dd>
</dl>
</section>

<h2>包级摘要</h2>
<section class="card">
<dl class="kv">
<dt>验证</dt><dd>{_h(verdict.get("verifications"))} 条，其中通过 {_h(verdict.get("verified"))} 条</dd>
<dt>复核</dt><dd>{_h(verdict.get("reviews"))} 条，其中 accept {_h(verdict.get("accepted"))} 条</dd>
<dt>benchmark_verified</dt><dd>{_flag(bool(verdict.get("benchmark_verified")))}</dd>
<dt>accepted_by_review</dt><dd>{_flag(bool(verdict.get("accepted_by_review")))}</dd>
<dt>口径</dt><dd>{_h(verdict.get("note"))}</dd>
</dl>
</section>

<h2>事件流</h2>
<section class="card">
<dl class="kv">
<dt>事件数</dt><dd>{_h(state.get("events"))}</dd>
<dt>阶段迁移</dt><dd>{chips}</dd>
<dt>事件重放状态</dt><dd>{_h(state.get("replayed_state"))}</dd>
</dl>
</section>

<h2>研究进展</h2>
{progress_html}

<h2>对照实验（研究循环 vs 单次 fuzz）</h2>
{compare_html}

<h2>候选</h2>
<table>
<thead><tr><th>id</th><th>crash_type</th><th>state</th><th>stack_hash</th><th>证据</th></tr></thead>
<tbody>
{_rows(candidate_rows, "—", 5)}
</tbody>
</table>

<h2>工程采纳</h2>
{decisions_html}

<h2>漏洞验证</h2>
{vuln_html}
<table>
<thead><tr><th>id</th><th>kind</th><th>status</th><th>verified</th><th>blockers</th></tr></thead>
<tbody>
{_rows(verification_rows, "—", 5)}
</tbody>
</table>

<h2>复核</h2>
<table>
<thead><tr><th>id</th><th>verdict</th><th>verification</th><th>说明</th></tr></thead>
<tbody>
{_rows(review_rows, "—", 4)}
</tbody>
</table>

<h2>证据交接（handoff）</h2>
{handoff_html}

<h2>证据清单</h2>
<section class="card">
<dl class="kv">
<dt>条目数</dt><dd>{_h(manifest.get("count"))}</dd>
<dt>全部存在</dt><dd>{_flag(bool(manifest.get("all_present")))}</dd>
<dt>全部哈希可复算</dt><dd>{_flag(bool(manifest.get("all_hash_ok")))}</dd>
<dt>manifest sha256</dt><dd>{_h(manifest.get("manifest_sha256"))}</dd>
</dl>
</section>
<table>
<thead><tr><th>kind</th><th>sha256</th><th>size</th><th>present</th><th>hash_ok</th><th>path</th></tr></thead>
<tbody>
{_rows(evidence_rows, "—", 6)}
</tbody>
</table>

<h2>口径声明</h2>
<section class="card">
<ul class="terms">
<li>CyberGym 判据：同一输入的 vuln 崩 / fix 干净（双端）；</li>
<li>ExploitGym 判据：官方入口取到 flag（<strong>不要求</strong> fix 端）；</li>
<li>VulnGym 判据：基线/修补行为差分；</li>
<li>单端 fuzz 只产候选，不产确认结论；本包的结论只来自验证记录与复核记录。</li>
</ul>
</section>

<footer>本文件由 CasePack 确定性渲染：样式内联、无脚本、无外部资源、无渲染时间戳；
同一批台账重算得到同一 sha256（见包内 casepack.json 的 files 与 reports 台账的
report_html_sha256）。</footer>
</main>
</body>
</html>
"""


def _record_report_html(store, task_id: str, report_id: str,
                        html_sha256: str) -> bool:
    """把 report.html 的哈希写进 `reports` 台账（幂等补列，不动 store 的核心 schema）。

    `reports` 表的 `sha256` 是**整包**内容哈希（`content_sha256`），它是台账与磁盘
    之间的纽带；这里再加一列 `report_html_sha256`，让“台账 → 包 → 网页”能单独对上
    ——只校验网页文件时不必先重算整包。列由 `_ensure_columns` 按 PRAGMA 幂等补齐，
    `SCHEMA_VERSION` / `PRAGMA user_version` 仍是 4（store.py 未改）。
    """
    conn = getattr(store, "conn", None)
    if conn is None:                      # 纯内存 store：只回包内记录
        return False
    from .store import CANDIDATE_ID_SEP, _ensure_columns
    _ensure_columns(conn, "reports", REPORT_COLUMNS)
    db_id = str(report_id)
    if not db_id.startswith(f"{task_id}{CANDIDATE_ID_SEP}"):
        db_id = f"{task_id}{CANDIDATE_ID_SEP}{db_id}"
    cur = conn.execute(
        "UPDATE reports SET report_html_sha256=? WHERE report_id=?",
        (str(html_sha256), db_id))
    conn.commit()
    return cur.rowcount > 0


def build_casepack(task_id: str, store, *, out_dir=None, evidence_root=None,
                   close: bool = False, bus=None, research_root=None,
                   baseline=None, require_research: bool = False) -> dict:
    """打包一次任务；返回文件清单与内容哈希（同时写 reports 表）。

    先做状态迁移（REVIEW→REPORTED，`close` 再→CLOSED），再按**最终**状态
    快照写盘：包里的 task.json/state.json/report.md 必须与台账一致，
    不能出现“包里写 REVIEW、库里已 REPORTED”的双口径。

    P4b 追加参数：`research_root`（研究报告目录，默认与 `adaptive.cli` 同口径）、
    `baseline`（对照实验的单次 fuzz 臂：`{"label","report","events"}`，
    缺省即“没有基准”，不补 0）、`require_research`（要求必须有研究产物）。
    """
    from .events import EventBus
    bus = bus or EventBus(store)

    task = store.get_task(task_id)
    if task["state"] not in PACKABLE_STATES:
        raise CasePackError(
            f"casepack requires one of {PACKABLE_STATES}, got {task['state']}")
    if task["state"] == "REVIEW":
        store.transition(task_id, "REPORTED", reason="casepack requested")
        task = store.get_task(task_id)
    if close and task["state"] in CLOSABLE_STATES:
        store.transition(task_id, "CLOSED", reason="casepack sealed")
        task = store.get_task(task_id)

    state = {"state": task["state"], "terminal_reason": task["terminal_reason"],
             "updated_at": task["updated_at"]}
    replay = bus.replay(task_id)
    events = bus.list(task_id)
    candidates = store.list_candidates(task_id)
    verifications = store.list_verifications(task_id)
    reviews = store.list_reviews(task_id)

    state.update({"events": len(events),
                  "transitions": replay.get("transitions") or [],
                  "replayed_state": replay.get("state")})
    manifest = _evidence_manifest(store, task_id, evidence_root)
    # W3：交接视图只读一次；取不到就抛（不编一份空视图冒充“没有待复核项”）
    handoff = _handoff_view(store, task_id)
    # P4b：研究产物先校验再落盘；冲突在这之前抛错，包内不会出现半份研究视图
    research = load_research(store, task_id, research_root=research_root,
                             bus=bus, required=require_research)
    research_bundle = None
    if research is not None:
        views = research_views(store, task_id, research, bus=bus,
                               manifest=manifest, verifications=verifications,
                               reviews=reviews, baseline=baseline)
        research_bundle = {
            "block": _research_block(task_id, research, views),
            "timeline": views["timeline"], "rounds": views["rounds"],
            "decisions": views["decisions"],
            "evidence_refs": views["evidence_refs"],
            "compare": views["compare"],
        }

    out = Path(out_dir) if out_dir else (
        store.path.parent / "casepacks" / task_id)
    out.mkdir(parents=True, exist_ok=True)

    task_doc = {
        "schema": "vulnmap.task.v1",
        "task_id": task["task_id"],
        "benchmark": task["benchmark"],
        "target": task["target"],
        "mode": task["mode"],
        "budget": task["budget"],
        "metadata": task["metadata"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
        "state": task["state"],
        "terminal_reason": task["terminal_reason"],
    }
    _write(out / "task.json", _json_bytes(task_doc))
    _write(out / "state.json", _json_bytes(state))
    _write(out / "events.jsonl",
           "".join(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n"
                   for ev in events).encode("utf-8"))
    _write(out / "candidates.json", _json_bytes(candidates))
    _write(out / "verifications.json", _json_bytes(verifications))
    _write(out / "reviews.json", _json_bytes(reviews))
    _write(out / "handoff.json", _json_bytes(handoff))
    _write(out / "evidence" / "manifest.json", _json_bytes(manifest))
    verdict = _pack_verdict(verifications, reviews, handoff)
    _write(out / "report.md",
           _render_report(task, state, candidates, verifications, reviews,
                          manifest, research_bundle,
                          handoff=handoff).encode("utf-8"))
    _write(out / "report.html",
           render_report_html(task, state, candidates, verifications, reviews,
                              manifest, verdict,
                              research_bundle, handoff=handoff).encode("utf-8"))

    if research_bundle is not None:
        # research.json 原样复制：字节不动，包内哈希 = 盘上哈希
        _write(out / "research.json", research["bytes"])
        _write(out / "research" / "timeline.json",
               _json_bytes(research_bundle["timeline"]))
        _write(out / "research" / "rounds.json",
               _json_bytes(research_bundle["rounds"]))
        _write(out / "research" / "decisions.json",
               _json_bytes(research_bundle["decisions"]))
        _write(out / "research" / "evidence_refs.json",
               _json_bytes(research_bundle["evidence_refs"]))
        _write(out / "compare.json", _json_bytes(research_bundle["compare"]))

    # 内容哈希：覆盖本次实际生成的文件（不含 casepack.json 自身），保证可复算
    generated = tuple(FILES) + research_files(research_bundle)
    files = []
    for rel in generated:
        path = out / rel
        if not path.is_file():
            raise CasePackError(f"casepack missing generated file: {rel}")
        files.append({"path": rel, "sha256": sha256_file(path),
                      "size": path.stat().st_size})
    files.sort(key=lambda x: x["path"])
    # 研究块在派生阶段已经算过一次；这里只取用，不重算第二份事实
    research_block = (research_bundle["block"] if research_bundle is not None
                      else _research_block(task_id, None, {}))
    content_sha256 = sha256(_json_bytes(files)).hexdigest()
    by_path = {f["path"]: f for f in files}
    html_file = by_path["report.html"]
    pack = {
        "schema": SCHEMA,
        "task_id": task_id,
        "state": task["state"],
        "generated_at": now(),
        "path": str(out),
        "files": files,
        "content_sha256": content_sha256,
        "report": {
            "md": "report.md",
            "html": "report.html",
            "html_sha256": html_file["sha256"],
            "html_size": html_file["size"],
            "html_deterministic": True,
            "html_external_refs": 0,
        },
        "counts": {"events": len(events), "candidates": len(candidates),
                   "verifications": len(verifications),
                   "reviews": len(reviews),
                   "evidence": manifest["count"],
                   "research_files": len(research_files(research_bundle))},
        "verdict": verdict,
        "handoff": _handoff_block(handoff),
        "research": research_block,
        "research_files": list(research_files(research_bundle)),
        "compare": _compare_summary(research_bundle["compare"]
                                    if research_bundle is not None else None),
    }
    _write(out / SELF_FILE, _json_bytes(pack))

    existing = store.list_reports(task_id)
    report_id = f"PACK{len(existing) + 1}"
    store.save_report(report_id, task_id, str(out), content_sha256)
    _record_report_html(store, task_id, report_id, html_file["sha256"])
    bus.emit(task_id, "report.ready", stage="REPORTED", payload={
        "report_id": report_id,
        "path": str(out),
        "content_sha256": content_sha256,
        "report_html": "report.html",
        "report_html_sha256": html_file["sha256"],
        "files": [f["path"] for f in files],
        "counts": pack["counts"],
        "verdict": pack["verdict"],
        "handoff": {"file": HANDOFF_FILE,
                    "items": pack["handoff"]["counts"]["items"],
                    "conclusions": pack["handoff"]["conclusions"],
                    "unverified": pack["handoff"]["unverified"]},
        "research": {"status": pack["research"]["status"],
                     "sha256": pack["research"]["sha256"],
                     "files": pack["research_files"]},
        "state": task["state"],
    })
    pack["report_id"] = report_id
    pack["state"] = store.get_task(task_id)["state"]
    return pack


def _compare_summary(compare: dict | None) -> dict:
    """`casepack.json` 只放对照摘要；完整文档在 `compare.json`（不造第二份事实）。"""
    if not compare:
        return {"schema": "vulnmap.adaptive.compare.v1", "file": "",
                "verdict": "not_evaluated", "comparable": False,
                "note": "没有研究产物 → 没有对照实验"}
    return {
        "schema": str(compare.get("schema") or ""),
        "file": "compare.json",
        "verdict": str(compare.get("verdict") or "not_evaluated"),
        "comparable": bool(compare.get("comparable")),
        "metrics": [{"metric": str(row.get("metric") or ""),
                     "known": bool(row.get("known")),
                     "delta": row.get("delta")}
                    for row in compare.get("metrics") or []],
        "negative_results": len(compare.get("negative_results") or []),
        "note": "摘要；完整对照文档见 compare.json，两处不各自记一套事实",
    }


def _pack_verdict(verifications: list[dict], reviews: list[dict],
                  handoff: dict | None = None) -> dict:
    """包级摘要：只转述验证/复核结论，不新造标签。

    `handoff` 段转述交接计数与口径；它**不参与** `benchmark_verified` /
    `accepted_by_review` 的判定——交接项不是 verified。
    """
    verified = [v for v in verifications if v.get("verified")]
    accepted = [r for r in reviews if r.get("verdict") == "accept"]
    counts = _handoff_counts(handoff)
    return {
        "verifications": len(verifications),
        "verified": len(verified),
        "reviews": len(reviews),
        "accepted": len(accepted),
        "benchmark_verified": bool(verified),
        "accepted_by_review": bool(accepted),
        "handoff": {
            "items": counts["items"],
            "pending": counts["pending"],
            "needs_evidence": counts["needs_evidence"],
            "accepted": counts["accepted"],
            "rejected": counts["rejected"],
            "conclusions": counts["conclusions"],
            "note": HANDOFF_NOTE,
        },
        "note": "包内结论只来自 verifications/reviews；single-end 候选不算确认",
    }
