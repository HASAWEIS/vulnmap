"""V3 P4a：研究轮次的只读视图 —— CLI / API / 页面共用同一份解释器。

数据源（三处，缺一不补）：

1. **研究报告** `<PLATFORM_ROOT>/research/<task_id>/research.json`
   （`bin/platform.py run --research` 的产物；`--research-root` 改过路径时
   以 `research.mapped` 事件里登记的 `report_path` 为准）；
2. **事件流** `task_events`：`research.started / research.finished /
   research.mapped / research.map_failed` 与 `exec.started / exec.finished`
   —— 只作为旁证，`research.mapped` 登记的 `report_sha256` 对不上就是冲突；
3. **证据台账** `task_evidence`（**只限该任务登记过的哈希**）。

口径：

- **只读**：本模块不建库、不写事件、不改任务、不动产物文件；只做
  `read_bytes` + `SELECT`。
- **报告是轮次的唯一事实来源**：`controller.rounds` / `controller.timeline`
  原样读取，本层不“补一轮”也不推断阶段；阶段顺序只用于排序展示。
- **不写裁决**：视图里没有漏洞结论字段；`verification_allowed` 只表示
  “可以交给既有 verify”，不表示做过验证。
- **错误分两类**（API 映射 404/409，CLI 映射 1/2）：
  `ResearchUnavailable` = 没有这个研究记录（任务从未跑过研究循环）；
  `ResearchConflict` = 记录存在但不可用（JSON 坏、schema 不认识、产物属于
  别的任务、与事件流登记的哈希不一致）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

SCHEMA = "vulnmap.platform.research.v1"
SCHEMA_VERSION = 1
EVENTS_SCHEMA = "vulnmap.platform.research.events.v1"
EVIDENCE_SCHEMA = "vulnmap.platform.research.evidence.v1"

#: 研究报告自身的 schema（`agent/platform/adaptive/cli.py` 写入的 `SCHEMA`）
REPORT_SCHEMA = "vulnmap.research.run.v1"

#: 研究目录的根覆盖（默认 `<PLATFORM_ROOT>/research`）
RESEARCH_ROOT_ENV = "PLATFORM_RESEARCH_ROOT"

#: 阶段顺序：与 `adaptive.controller.PHASES` 同序；仅用于排序，
#: 事实以报告 `controller.timeline` 为准（`tests/test_v3_p4_api.py` 交叉校验）
PHASES = ("OBSERVE", "DIAGNOSE", "PROPOSE", "AUTHORIZE", "STAGE", "BUILD",
          "SMOKE", "EXECUTE", "COLLECT", "CONFIG", "COMPARE", "ADOPT",
          "REVERT", "STOP")

#: 研究 session 的事件前缀（其余事件不属于研究轮次）
EVENT_PREFIXES = ("research.", "exec.")

#: 事件类型 → 事件级阶段标签（不是控制器时间线的替代品）
EVENT_PHASE = {"research.started": "START",
               "research.finished": "STOP",
               "research.mapped": "MAP",
               "research.map_failed": "MAP",
               "exec.started": "EXECUTE",
               "exec.finished": "EXECUTE"}

NOTE = ("只读视图：轮次/阶段/动作/结果/证据引用全部来自 research.json 与事件流；"
        "本接口不写任务、不写事件、不改产物，也不给漏洞结论")

EVIDENCE_REF_RE = re.compile(r"^[0-9a-f]{64}$")
_EXEC_ROUND_RE = re.compile(r"-r(\d+)-")


class ResearchUnavailable(Exception):
    """没有这个研究记录（任务从未跑过研究循环 / 产物不存在）→ API 404、CLI 1。"""


class ResearchConflict(Exception):
    """记录存在但不可用（坏 JSON / schema 不认识 / 串任务 / 哈希不一致）→ API 409、CLI 2。"""


# ====================================================================== 路径
def _as_path(value: Any) -> Path:
    return Path(str(value)).expanduser()


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:                      # 路径坏到连解析都失败：按原样用
        return path


def research_root(root: Path | str, task_id: str) -> Path:
    """研究目录：`PLATFORM_RESEARCH_ROOT` 优先，否则 `<root>/research/<task_id>`。"""
    env = (os.environ.get(RESEARCH_ROOT_ENV) or "").strip()
    base = _as_path(env) if env else _as_path(root) / "research"
    return _resolve(base) / str(task_id)


def report_paths(root: Path | str, task_id: str,
                 events: Iterable[Mapping] = ()) -> list[Path]:
    """候选报告路径（按优先级）：默认目录 → 事件里登记的 `report_path`。

    `run --research --research-root X` 的产物不在默认目录，只有事件流知道
    它在哪；因此事件是**补位**，不是覆盖：默认目录里的报告仍然优先。
    """
    out: list[Path] = []

    def add(value: Any) -> None:
        if not value:
            return
        path = _resolve(_as_path(value))
        if path not in out:
            out.append(path)

    add(research_root(root, task_id) / "research.json")
    for ev in reversed(list(events or ())):
        payload = ev.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        add(payload.get("report_path"))
        paths = payload.get("paths") or {}
        if isinstance(paths, Mapping):
            add(paths.get("report"))
    return out


# ====================================================================== 报告
def _check_recorded_hash(path: Path, digest: str,
                         events: Iterable[Mapping]) -> None:
    """`research.mapped` 登记了 report_sha256 就必须对得上（产物被改写 = 冲突）。"""
    latest = ""
    for ev in reversed(list(events or ())):
        if str(ev.get("event_type") or "") != "research.mapped":
            continue
        payload = ev.get("payload") or {}
        if not isinstance(payload, Mapping):
            continue
        recorded_path = str(payload.get("report_path") or "")
        if recorded_path and _resolve(_as_path(recorded_path)) != path:
            continue
        latest = str(payload.get("report_sha256") or "")
        if latest:
            break
    if latest and latest.lower() != digest:
        raise ResearchConflict(
            f"research report sha256 mismatch with research.mapped: "
            f"{path} recorded={latest[:12]} actual={digest[:12]}")


def load_report(root: Path | str, task_id: str,
                events: Iterable[Mapping] = ()) -> dict:
    """读取并校验研究报告；返回 `{path, sha256, bytes, doc}`。

    校验顺序固定：JSON → schema → 归属任务 → controller 块 → 事件登记哈希。
    任何一步不成立都抛 `ResearchConflict`；一条候选都不存在抛
    `ResearchUnavailable`。
    """
    events = list(events or ())
    mismatched: list[tuple[Path, str]] = []
    for path in report_paths(root, task_id, events):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise ResearchConflict(f"research report unreadable: {exc}") from exc
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ResearchConflict(
                f"research report is not valid JSON: {path} ({exc})") from exc
        if not isinstance(doc, dict):
            raise ResearchConflict(f"research report must be a JSON object: {path}")
        schema = str(doc.get("schema") or "")
        if schema != REPORT_SCHEMA:
            raise ResearchConflict(
                f"unsupported research report schema at {path}: {schema!r}"
                f" (expected {REPORT_SCHEMA!r})")
        owner = str(doc.get("task_id") or "")
        if owner != str(task_id):
            mismatched.append((path, owner))
            continue
        controller = doc.get("controller")
        if not isinstance(controller, Mapping):
            raise ResearchConflict(f"research report has no controller block: {path}")
        for key in ("rounds", "timeline"):
            if not isinstance(controller.get(key), list):
                raise ResearchConflict(
                    f"research report controller.{key} must be a list: {path}")
        digest = hashlib.sha256(raw).hexdigest()
        _check_recorded_hash(path, digest, events)
        return {"path": str(path), "sha256": digest, "bytes": len(raw),
                "doc": doc}
    if mismatched:
        path, owner = mismatched[0]
        raise ResearchConflict(
            f"research report belongs to another task: {path} (task_id={owner!r})")
    raise ResearchUnavailable(f"no research report for {task_id}")


# ====================================================================== 轮次
def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _str_list(value: Any) -> list[str]:
    if isinstance(value, (str, bytes)) or value is None:
        return []
    try:
        return [str(item) for item in value]
    except TypeError:
        return []


def _ref_view(doc: Mapping | None, default_round: int = 0,
              action_id: str = "", tool: str = "",
              source: str = "action") -> list[dict]:
    refs = []
    for ref in _str_list((doc or {}).get("evidence_refs")):
        ref = ref.strip().lower()
        if not ref:
            continue
        refs.append({"ref": ref, "round": int(default_round),
                     "action_id": str(action_id), "tool": str(tool),
                     "source": str(source)})
    return refs


def _timeline_view(controller: Mapping) -> list[dict]:
    rows: list[dict] = []
    for item in controller.get("timeline") or ():
        if not isinstance(item, Mapping):
            continue
        rows.append({"round": _int(item.get("round")),
                     "phase": str(item.get("phase") or ""),
                     "status": str(item.get("status") or ""),
                     "detail": str(item.get("detail") or "")})
    order = {phase: idx for idx, phase in enumerate(PHASES)}
    rows.sort(key=lambda row: (row["round"], order.get(row["phase"], len(PHASES))))
    return rows


def _phase_summary(timeline: list[dict]) -> list[dict]:
    """阶段汇总：阶段 → 出现次数 / 各状态计数（按 PHASES 排序）。"""
    table: dict[str, dict] = {}
    for row in timeline:
        entry = table.setdefault(str(row["phase"]),
                                 {"phase": str(row["phase"]), "count": 0,
                                  "statuses": {}})
        entry["count"] += 1
        status = str(row["status"] or "")
        entry["statuses"][status] = entry["statuses"].get(status, 0) + 1
    order = {phase: idx for idx, phase in enumerate(PHASES)}
    return sorted(table.values(),
                  key=lambda item: order.get(item["phase"], len(PHASES)))


def _round_view(item: Mapping, index: int, phases: list[dict]) -> dict:
    round_no = _int(item.get("round"), index + 1)
    diagnosis = item.get("diagnosis") or {}
    plan = item.get("plan") or {}
    actions: list[dict] = []
    for action in item.get("actions") or ():
        if not isinstance(action, Mapping):
            continue
        actions.append({
            "action_id": str(action.get("action_id") or ""),
            "tool": str(action.get("tool") or ""),
            "status": str(action.get("status") or ""),
            "candidates": _int(action.get("candidates")),
            "invalidations": _str_list(action.get("invalidations")),
            "evidence_refs": _str_list(action.get("evidence_refs")),
            "error": dict(action.get("error") or {}),
        })
    build = item.get("build") or {}
    smoke = item.get("smoke") or {}
    compare = item.get("compare") or {}
    engineering = item.get("engineering") or {}
    plan_actions = [str(a.get("action") or "") for a in (plan.get("actions") or ())
                    if isinstance(a, Mapping)]
    refs: list[dict] = []
    seen: set[tuple] = set()

    def push(rows: list[dict]) -> None:
        for row in rows:
            key = (row["ref"], row["round"], row["action_id"], row["source"])
            if key in seen:
                continue
            seen.add(key)
            refs.append(row)

    push(_ref_view(diagnosis, round_no, source="diagnosis"))
    for action in item.get("actions") or ():
        if not isinstance(action, Mapping):
            continue
        push(_ref_view(action, round_no,
                       action_id=str(action.get("action_id") or ""),
                       tool=str(action.get("tool") or "")))
    statuses: dict[str, int] = {}
    for action in actions:
        statuses[action["status"]] = statuses.get(action["status"], 0) + 1
    return {
        "round": round_no,
        "facts_hash": str(item.get("facts_hash") or ""),
        "diagnosis": {"code": str(diagnosis.get("code") or ""),
                      "severity": str(diagnosis.get("severity") or ""),
                      "reasons": _str_list(diagnosis.get("reasons")),
                      "candidates": _int(diagnosis.get("candidates")),
                      "evidence_refs": _str_list(diagnosis.get("evidence_refs"))},
        "plan": {"actions": plan_actions,
                 "tool": str(plan.get("tool") or ""),
                 "revision": bool(plan.get("files")),
                 "note": str(plan.get("note") or "")},
        "phases": [dict(row) for row in phases],
        "actions": actions,
        "results": {
            "action_status": statuses,
            "build": {"status": str(build.get("status") or ""),
                      "exit_code": build.get("exit_code"),
                      "log_path": str(build.get("log_path") or "")},
            "smoke": {"status": str(smoke.get("status") or ""),
                      "kind": str(smoke.get("kind") or ""),
                      "exit_code": smoke.get("exit_code")},
            "compare": {"status": str(compare.get("status") or ""),
                        "comparable": str(compare.get("comparable") or ""),
                        "reason": str(compare.get("reason") or ""),
                        "metric": str(compare.get("metric") or ""),
                        "delta": compare.get("delta"),
                        "verdict": str(compare.get("verdict") or "")},
            "adopted": bool(item.get("adopted")),
            "reverted": str(item.get("reverted") or ""),
            "engineering_failed": _str_list(
                engineering.get("failed") if isinstance(engineering, Mapping) else ()),
            "post_diagnosis": str(item.get("note") or ""),
            "stop_reason": str(item.get("stop_reason") or ""),
        },
        "revision": str(item.get("revision") or ""),
        "invalidations": [dict(row) for row in (item.get("invalidations") or ())
                          if isinstance(row, Mapping)],
        "evidence_refs": refs,
        "stop_reason": str(item.get("stop_reason") or ""),
        "note": str(item.get("note") or ""),
    }


def _results_summary(rounds: list[dict]) -> dict:
    action_status: dict[str, int] = {}
    stop_reasons: dict[str, int] = {}
    compare_status: dict[str, int] = {}
    adopted = reverted = 0
    for row in rounds:
        for action in row["actions"]:
            status = str(action["status"] or "")
            action_status[status] = action_status.get(status, 0) + 1
        results = row["results"]
        reason = str(results.get("stop_reason") or "")
        if reason:
            stop_reasons[reason] = stop_reasons.get(reason, 0) + 1
        status = str(results["compare"].get("status") or "")
        if status:
            compare_status[status] = compare_status.get(status, 0) + 1
        adopted += 1 if results.get("adopted") else 0
        reverted += 1 if results.get("reverted") else 0
    return {"rounds": len(rounds), "action_status": action_status,
            "stop_reasons": stop_reasons, "compare_status": compare_status,
            "adopted": adopted, "reverted": reverted}


def _links(task_id: str) -> dict:
    base = f"/api/platform/tasks/{task_id}"
    return {"self": f"{base}/research",
            "events": f"{base}/research/events",
            "evidence": f"{base}/research/evidence",
            "task": base, "task_events": f"{base}/events"}


# ====================================================================== 视图
def status_view(root: Path | str, task_id: str,
                events: Iterable[Mapping] = ()) -> dict:
    """研究轮次总览：轮次 / 阶段 / 动作 / 结果 / 证据引用（只读）。"""
    report = load_report(root, task_id, events)
    doc = report["doc"]
    controller = doc["controller"]
    timeline = _timeline_view(controller)
    rounds: list[dict] = []
    for index, item in enumerate(controller.get("rounds") or ()):
        if not isinstance(item, Mapping):
            continue
        round_no = _int(item.get("round"), index + 1)
        phases = [row for row in timeline if row["round"] == round_no]
        rounds.append(_round_view(item, index, phases))
    actions = [{**action, "round": row["round"]}
               for row in rounds for action in row["actions"]]
    refs: list[dict] = []
    seen: set[tuple] = set()
    for row in rounds:
        for ref in row["evidence_refs"]:
            key = (ref["ref"], ref["round"], ref["action_id"], ref["source"])
            if key in seen:
                continue
            seen.add(key)
            refs.append(dict(ref))
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "task_id": str(task_id),
        "report": {"path": report["path"], "sha256": report["sha256"],
                   "bytes": report["bytes"],
                   "schema": str(doc.get("schema") or ""),
                   "schema_version": _int(doc.get("schema_version")),
                   "generated_at": str(doc.get("generated_at") or "")},
        "state": str(doc.get("state") or ""),
        "controller_state": str(doc.get("controller_state")
                                or controller.get("status") or ""),
        "stop_reason": str(doc.get("stop_reason") or ""),
        "campaign": str(doc.get("campaign") or ""),
        "benchmark": str(doc.get("benchmark") or ""),
        "max_rounds": _int(doc.get("max_rounds")),
        "rounds_count": len(rounds),
        "executions": _int(doc.get("executions")),
        "executions_applied": _int(doc.get("executions_applied")),
        "executions_failed": _int(doc.get("executions_failed")),
        "candidates": _int(doc.get("candidates")),
        "observed_rounds": _int(doc.get("observed_rounds")),
        "verification_allowed": bool(doc.get("verification_allowed")),
        "rounds": rounds,
        "timeline": timeline,
        "phases": _phase_summary(timeline),
        "actions": actions,
        "results": _results_summary(rounds),
        "evidence_refs": refs,
        "note": NOTE,
        "links": _links(str(task_id)),
    }


def is_research_event(event: Mapping) -> bool:
    return str(event.get("event_type") or "").startswith(EVENT_PREFIXES)


def _round_of(payload: Mapping) -> int | None:
    for key in ("round", "round_no", "epoch"):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    match = _EXEC_ROUND_RE.search(str(payload.get("exec_id") or ""))
    return int(match.group(1)) if match else None


def _payload_refs(payload: Mapping) -> list[str]:
    refs: list[str] = []
    for item in _str_list(payload.get("evidence_refs")):
        if item not in refs:
            refs.append(item)
    single = str(payload.get("evidence_sha256") or "").strip()
    if single and single not in refs:
        refs.append(single)
    return refs


def _event_view(event: Mapping) -> dict:
    payload = event.get("payload") or {}
    if not isinstance(payload, Mapping):
        payload = {}
    event_type = str(event.get("event_type") or "")
    status = (payload.get("outcome") or payload.get("state")
              or payload.get("stop_reason") or "")
    return {
        "seq": _int(event.get("seq")),
        "event_type": event_type,
        "kind": event_type.split(".", 1)[0],
        "phase": EVENT_PHASE.get(event_type, ""),
        "stage": str(event.get("stage") or ""),
        "ts": str(event.get("ts") or ""),
        "round": _round_of(payload),
        "action": str(payload.get("kind") or payload.get("tool") or ""),
        "status": str(status),
        "evidence_refs": _payload_refs(payload),
        "payload": dict(payload),
    }


def events_view(root: Path | str, task_id: str, events: Iterable[Mapping] = (),
                *, after: int = 0, limit: int = 200,
                kind: str = "") -> dict:
    """研究 session 的事件流（只读）。

    没有研究事件时：任务也没跑过研究循环 → 404（`ResearchUnavailable`）；
    报告却说跑过 → 事件流与产物矛盾 → 409（`ResearchConflict`）。
    """
    events = list(events or ())
    after = max(0, _int(after))
    limit = max(1, min(_int(limit, 200), 500))
    wanted = str(kind or "").strip()
    window = [ev for ev in events if is_research_event(ev) and _int(ev.get("seq")) > after]
    if wanted:
        window = [ev for ev in window
                  if wanted == str(ev.get("event_type") or "")
                  or wanted == str(ev.get("event_type") or "").split(".", 1)[0]]
    if not window:
        try:
            load_report(root, task_id, events)
        except ResearchUnavailable as exc:
            raise ResearchUnavailable(
                f"no research events for {task_id}") from exc
        raise ResearchConflict(
            f"research report exists but the event stream has no research "
            f"events for {task_id} after={after} kind={wanted or '*'}")
    visible = window[:limit]
    total_after = len(window)
    rounds = sorted({int(ev["round"]) for ev in (_event_view(e) for e in visible)
                     if ev["round"] is not None})
    counts: dict[str, int] = {}
    for ev in visible:
        event_type = str(ev.get("event_type") or "")
        counts[event_type] = counts.get(event_type, 0) + 1
    items = [_event_view(ev) for ev in visible]
    return {
        "schema": EVENTS_SCHEMA, "schema_version": SCHEMA_VERSION,
        "task_id": str(task_id), "after": after, "kind": wanted,
        "count": len(items), "total_after": total_after,
        "next_after": items[-1]["seq"] if items else after,
        "rounds": rounds, "counts": counts, "items": items,
        "note": ("只读：事件按 seq 升序；round 只在事件 payload 里有事实时给出"
                 "（exec_id 形如 exec-r003-… 时按轮号解析），阶段以 research.json 的"
                 "controller.timeline 为准"),
    }


def _evidence_path(root: Path | str, row: Mapping) -> Path:
    path = _as_path(row.get("path") or "")
    if not path.is_absolute():
        path = _as_path(root) / "evidence" / path.name
    return path


def report_refs(doc: Mapping) -> list[dict]:
    """报告里登记过的证据引用：动作侧 + 诊断侧（顺序稳定、去重）。"""
    controller = doc.get("controller") or {}
    refs: list[dict] = []
    seen: set[tuple] = set()

    def push(rows: list[dict]) -> None:
        for row in rows:
            key = (row["ref"], row["round"], row["action_id"], row["source"])
            if key in seen:
                continue
            seen.add(key)
            refs.append(row)

    for index, item in enumerate(controller.get("rounds") or ()):
        if not isinstance(item, Mapping):
            continue
        round_no = _int(item.get("round"), index + 1)
        push(_ref_view(item.get("diagnosis") or {}, round_no,
                       source="diagnosis"))
        for action in item.get("actions") or ():
            if not isinstance(action, Mapping):
                continue
            push(_ref_view(action, round_no,
                           action_id=str(action.get("action_id") or ""),
                           tool=str(action.get("tool") or "")))
    return refs


def evidence_view(root: Path | str, task_id: str, report: Mapping,
                  rows: Iterable[Mapping] = ()) -> dict:
    """研究证据：报告引用 × 本任务登记的证据（跨任务的哈希不算数）。"""
    doc = report.get("doc") or {}
    registered = {str(row.get("sha256") or "").lower(): dict(row)
                  for row in (rows or ())}
    items: dict[str, dict] = {}
    unresolved: dict[str, dict] = {}
    invalid: dict[str, dict] = {}
    for ref in report_refs(doc):
        row = registered.get(ref["ref"])
        if row is None:
            if EVIDENCE_REF_RE.match(ref["ref"]):
                bucket, reason = unresolved, "not_registered_for_this_task"
            else:
                bucket, reason = invalid, "not_sha256"
            entry = bucket.setdefault(ref["ref"], {**ref, "reason": reason,
                                                   "referenced_by": []})
            entry["referenced_by"].append({"round": ref["round"],
                                           "action_id": ref["action_id"],
                                           "tool": ref["tool"],
                                           "source": ref["source"]})
            continue
        entry = items.get(ref["ref"])
        if entry is None:
            path = _evidence_path(root, row)
            present = path.is_file()
            digest = ""
            if present:
                try:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    present = False
            entry = {"sha256": ref["ref"],
                     "kind": str(row.get("kind") or ""),
                     "source_stage": str(row.get("source_stage") or ""),
                     "created_at": str(row.get("created_at") or ""),
                     "size": _int(row.get("size")),
                     "path": str(path), "present": present,
                     "hash_ok": bool(present and digest == ref["ref"]),
                     "download": (f"/api/platform/tasks/{task_id}/evidence/"
                                  f"{ref['ref']}"),
                     "referenced_by": []}
            items[ref["ref"]] = entry
        entry["referenced_by"].append({"round": ref["round"],
                                       "action_id": ref["action_id"],
                                       "tool": ref["tool"],
                                       "source": ref["source"]})
    listed = list(items.values())
    return {
        "schema": EVIDENCE_SCHEMA, "schema_version": SCHEMA_VERSION,
        "task_id": str(task_id),
        "report": {"path": str(report.get("path") or ""),
                   "sha256": str(report.get("sha256") or "")},
        "count": len(listed),
        "all_present": all(item["present"] for item in listed) if listed else True,
        "all_hash_ok": all(item["hash_ok"] for item in listed) if listed else True,
        "task_evidence_count": len(registered),
        "items": listed,
        "unresolved": list(unresolved.values()),
        "invalid_refs": list(invalid.values()),
        "note": ("只读：只解析该任务 task_evidence 里登记过的哈希；"
                 "unresolved 表示报告引用了本任务没有登记的引用"),
    }


__all__ = [
    "EVENTS_SCHEMA",
    "EVENT_PHASE",
    "EVENT_PREFIXES",
    "EVIDENCE_SCHEMA",
    "NOTE",
    "PHASES",
    "REPORT_SCHEMA",
    "RESEARCH_ROOT_ENV",
    "SCHEMA",
    "SCHEMA_VERSION",
    "ResearchConflict",
    "ResearchUnavailable",
    "events_view",
    "evidence_view",
    "is_research_event",
    "load_report",
    "report_paths",
    "report_refs",
    "research_root",
    "status_view",
]
