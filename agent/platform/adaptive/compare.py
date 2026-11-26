"""V3 P4b：对照实验（研究循环 vs 单次 fuzz）的事实比较。

本模块只做一件事：把**已经发生的执行事实**并排放在一张表里，逐项给出
「研究循环 / 单次 fuzz / Δ / 方向 / 是否可比 / 说明」。它不评价谁更聪明，
也不产任何漏洞结论。

口径（写死，改之前先改契约）：

1. **不产裁决**。`verdict` 恒为 `"not_evaluated"`；不写任何自我裁决字段，
   也不调用 `verify`。指纹/覆盖/候选只是事实，不是结论。
2. **未知就是未知**。拿不到的字段一律 `None` + `known=False` + `reason`，
   绝不填 0、绝不猜。`delta == 0.0` 是**事实**（两侧都已知且相等），不是未知；
   同理 `candidates == 0`、`first_crash_seconds == 0` 只要是被记录下来的读数，
   就按事实处理。
3. **动作次数不是智能**。动作数/轮数/执行次数只进
   `counts_are_not_intelligence` 块当“工作量/成本”记账，那里明确写死
   “不推断更聪明”。
4. **负结果保留**。没有差异、没有基准、被跳过/被拒的动作、指标不可比，
   全部留在文档里（`negative_results`）；不隐藏、不美化。
5. **确定性**。派生文档不含任何时间戳：同一输入两次调用，`json.dumps(doc,
   sort_keys=True)` 必须逐字节相同。事件里的 `ts` 只用来**算时长**，
   不写进文档。

事实来源（与 CLI/控制器对齐，不在本模块重写字段语义）：

- `research.json`（`agent.platform.adaptive.cli._report_body`）顶层：
  `rounds`（轮数，int）、`executions`、`executions_applied`、`executions_failed`、
  `candidates`、`observed_rounds`、`stop_reason`、`controller`（`ControllerResult
  .to_dict()`：`rounds` 是轮记录列表，每项含 `round/facts_hash/diagnosis/plan/
  actions/revision/build/smoke/engineering/adopted/reverted/compare/invalidations/
  stop_reason/note`）。
  逐轮 `compare` 段由 `ResearchController._compare()` 产出：
  `{"status", "comparable", "reason", "metric": "coverage", "delta": float|"unknown"}`。
- 事件表（`PlatformStore.list_events()`）：`{"seq","ts","event_type","stage","payload"}`。
  `exec.started` / `exec.finished`；`exec.finished.payload` 含 `candidates`、
  `fuzz`（含 `first_crash_seconds`，见 `executors._FUZZ_STATS_KEYS`）、`coverage`
  （`covered` / `uncovered` / `delta` / `metric_kind` …）。
- 动作状态取值（`contracts.STATUSES` + 控制器跳过）：
  `applied` / `noop` / `rejected` / `failed` / `unknown` / `skipped`；
  `noop` 与 `applied` 同属“被采纳”（`ToolOutcome.applied` 的判据）。

`reason` 词表（固定，别当拼写漂移改；新增词先改本表）：

| reason | 含义 |
| --- | --- |
| `no_actions` | 有轮次但一个动作都没提 → `proposed == 0`（契约 §1.2 指定） |
| `no_action_facts` | 这一臂根本没有动作事实（例如只有事件） |
| `no_rounds_or_actions` | `rounds + proposed == 0` 或分母未知 → 重复率不可算 |
| `no_clock_facts` | 既无 `fuzz.first_crash_seconds`，也拼不出 wall clock 区间 |
| `no_coverage_facts` | 报告/事件里都没有可用的覆盖读数 |
| `no_candidate_facts` | 两侧都没有候选事实（不是“候选为 0”） |
| `metric_kind_mismatch` | 两侧口径不同（`fuzz_seconds` ↔ `wall_clock_seconds`、`edge` ↔ `branch`） |
| `no_baseline` | 单次 fuzz 臂什么事实都没拿到（无报告、无事件） |
| `no_shared_metric` | 五个指标里没有任何一条两侧都已知 |
| `no_facts` | 兜底：原因缺失且没有更具体的词可用 |

口径备注（不算 reason，进 `notes`）：`coverage_metric_kind_unmapped`（覆盖口径登记了
但不在 `branch`/`edge`/`bits` 里，例如真实快照的 `call_site` → 归一成 `""`）、
`facts_hash_absent`、`events_have_no_actions`、`report_has_no_clock`、
`from_events:<字段>`、`<arm>.<note>`。

纯标准库；**不导入 `agent.platform.*`**（避免与 `platform/__init__` 的
`adaptive` ↔ `cli` 导入链形成环）。所有入口对坏输入都是“降级成未知”，
不抛未捕获异常。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable, Mapping

SCHEMA = "vulnmap.adaptive.compare.v1"
SCHEMA_VERSION = 1

#: 两个臂：研究循环 / 单次 fuzz
ARMS = ("research", "single_fuzz")
ARM_LABELS = {"research": "研究循环", "single_fuzz": "单次 fuzz"}

#: 五个指标（顺序即文档顺序，也是 markdown 表顺序）
METRICS = ("time_to_first_crash", "coverage", "candidates",
           "action_acceptance", "repeat_rate")

#: 越低越好的指标；其余按“越高越好”
LOWER_IS_BETTER = frozenset({"time_to_first_crash", "repeat_rate"})

#: 覆盖率指标可接受的 `metric_kind`（"" 表示没登记口径 → 只按数值比）
COVERAGE_KINDS = ("branch", "edge", "bits")
_KIND_ALIASES = {"branches": "branch", "branch_coverage": "branch",
                 "edges": "edge", "edge_coverage": "edge", "bit": "bits",
                 "coverage_bits": "bits", "bits_coverage": "bits"}

#: 时间指标口径：两种只能各自比，不能混
TIME_KINDS = ("fuzz_seconds", "wall_clock_seconds")

#: 动作状态归类（`noop` 与 `applied` 同属被采纳，见 `ToolOutcome.applied`）
_APPLIED_STATUSES = ("applied", "noop")

#: 方向判定的浮点容差：只影响“持平/更好/更差”的字面，不改数值
_EPS = 1e-9

NOTE = "对照实验只比事实；本文件不产漏洞结论，裁决字段一律不在此产生"
COUNTS_NOTE = "动作数/轮数只当工作量记账，不推断“更聪明”；没有基准就没有对照"

#: 这些口径备注除了 `<arm>.<note>` 溯源条目，还在 `build_compare().notes` 里
#: 留一份裸词（读者/校验要能一眼看出“口径没登记”“0 是观测不是猜”）。
_BARE_NOTES = frozenset({"coverage_metric_kind_unmapped", "facts_hash_absent",
                         "events_have_no_actions"})

_METRIC_LABELS = {
    "time_to_first_crash": "首次崩溃耗时（秒）",
    "coverage": "覆盖率",
    "candidates": "候选数",
    "action_acceptance": "动作采纳率",
    "repeat_rate": "重复率",
}

_DIRECTION_LABELS = {"better": "更好", "worse": "更差",
                     "same": "持平", "unknown": "未知"}


class CompareError(ValueError):
    """对照文档组装错误（臂名不认识等编程错误；不用于“事实缺失”）。"""


# ====================================================================== 小工具
def _is_num(value: Any) -> bool:
    """只认真正的数字：bool 不算（`True` 不能被当成 1 混进指标）。"""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _num(value: Any) -> float | int | None:
    return value if _is_num(value) else None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return int(value)


def _mapping(value: Any) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _plain(value: Any) -> Any:
    """深拷贝成纯 JSON 结构（防御调用方后续改动影响确定性）。"""
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):       # pragma: no cover - 兜底
        return {}


def _arm(arm: str) -> str:
    if arm not in ARMS:
        raise CompareError(f"unknown arm: {arm!r}（只认 {ARMS}）")
    return str(arm)


def _ts(value: Any) -> datetime | None:
    """解析事件 `ts`（ISO8601；`Z` 与 `+00:00` 都认）。失败 → None。"""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _seconds(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    try:
        delta = (later - earlier).total_seconds()
    except (TypeError, ValueError):       # naive ↔ aware
        return None
    return float(delta) if delta >= 0 else None


# ====================================================================== 骨架
def _blank_arm(arm: str = "research", *, source: str = "report") -> dict:
    """一只臂的空文档：全部未知 + 各自的 reason（默认即“没有事实”）。"""
    name = _arm(arm)
    return {
        "arm": name, "arm_label": ARM_LABELS[name], "source": str(source),
        "executions": None, "applied": None, "failed": None,
        "rounds": None, "observed_rounds": None, "candidates": None,
        "time_to_first_crash": {"value": None, "unit": "s", "metric_kind": "",
                                "known": False, "reason": "no_clock_facts"},
        "coverage": {"metric_kind": "", "covered": None, "uncovered": None,
                     "delta": None, "known": False,
                     "reason": "no_coverage_facts"},
        "actions": {"proposed": None, "applied": None, "rejected": None,
                    "skipped": None, "failed": None, "unknown": None},
        "action_acceptance": {"value": None, "known": False,
                              "reason": "no_action_facts"},
        "repeats": {"same_facts": None, "skipped_actions": None,
                    "identical_actions": None},
        "repeat_rate": {"value": None, "known": False,
                        "reason": "no_rounds_or_actions"},
        "stopped": None,
        "notes": [],
    }


def _action_counts(items: list) -> dict:
    """按状态把动作分桶：`applied` 含 `noop`，其余归 unknown。

    恒等式：`proposed == applied + rejected + skipped + failed + unknown`
    （`proposed = len(items)`），契约 §1.2 的公式即由此保证。
    """
    applied = rejected = skipped = failed = unknown = 0
    for item in items:
        status = str(_mapping(item).get("status") or "").strip().lower()
        if status in _APPLIED_STATUSES:
            applied += 1
        elif status == "rejected":
            rejected += 1
        elif status == "skipped":
            skipped += 1
        elif status == "failed":
            failed += 1
        else:
            unknown += 1
    return {"proposed": len(items), "applied": applied, "rejected": rejected,
            "skipped": skipped, "failed": failed, "unknown": unknown}


def _action_digest(item: Mapping) -> str:
    """动作参数指纹：拿不到就返回空串（退回“按 tool 计重复”）。"""
    item = _mapping(item)
    for key in ("params_sha256", "digest", "params_digest", "input_sha256"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    params = item.get("params")
    if isinstance(params, Mapping) and params:
        try:
            body = json.dumps(params, ensure_ascii=False, sort_keys=True,
                              default=str)
        except (TypeError, ValueError):    # pragma: no cover - 兜底
            return ""
        return hashlib.sha256(body.encode("utf-8")).hexdigest()
    return ""


def _identical_actions(items: list) -> int:
    """重复动作数：`(tool, params digest)` 相同即重复；无 digest 时按 `tool`。"""
    seen: list[tuple[str, str]] = []
    for item in items:
        data = _mapping(item)
        key = (str(data.get("tool") or ""), _action_digest(data))
        seen.append(key)
    return len(seen) - len({*seen})


def _coverage_kind(*sources: Any) -> str:
    for source in sources:
        data = _mapping(source)
        for key in ("metric_kind", "coverage_kind", "kind_of_metric"):
            raw = data.get(key)
            if not isinstance(raw, str) or not raw.strip():
                continue
            text = raw.strip().lower()
            if text in COVERAGE_KINDS:
                return text
            if text in _KIND_ALIASES:
                return _KIND_ALIASES[text]
            return ""                     # 登记了但不在可认定的口径里
    return ""


def _coverage_kind_unmapped(*sources: Any) -> bool:
    """有没有“登记了口径但不在可认定枚举里”的来源（如真实快照的 `call_site`）。"""
    for source in sources:
        data = _mapping(source)
        for key in ("metric_kind", "coverage_kind", "kind_of_metric"):
            raw = data.get(key)
            if not isinstance(raw, str) or not raw.strip():
                continue
            text = raw.strip().lower()
            if text in COVERAGE_KINDS or text in _KIND_ALIASES:
                return False
            return True
    return False


def _coverage_block(covered=None, uncovered=None, delta=None, *,
                    kind: str = "", note: str = "") -> dict:
    """覆盖率块：有任何一个数字就是 known；全无 → None + reason。"""
    has = any(_is_num(v) for v in (covered, uncovered, delta))
    return {"metric_kind": str(kind or ""),
            "covered": _num(covered), "uncovered": _num(uncovered),
            "delta": _num(delta), "known": bool(has),
            "reason": "" if has else "no_coverage_facts"}


# ====================================================================== report
def _report_rounds(report: Mapping) -> tuple[list, bool]:
    """取轮记录列表；第二项表示“这份报告确实带了轮列表”（0 轮也是事实）。"""
    controller = _mapping(report.get("controller"))
    items = controller.get("rounds")
    if isinstance(items, list):
        return [dict(item) for item in items if isinstance(item, Mapping)], True
    top = report.get("rounds")
    if isinstance(top, list):             # 兼容直接把轮列表挂在顶层的报告
        return [dict(item) for item in top if isinstance(item, Mapping)], True
    return [], False


def _report_coverage(report: Mapping, controller: Mapping,
                     rounds: list) -> dict:
    """覆盖率事实：优先 `controller.final.coverage`，缺项用最后一条轮 compare 补。"""
    final = _mapping(controller.get("final"))
    final_cov = _mapping(final.get("coverage"))
    covered = _num(final_cov.get("covered"))
    uncovered = _num(final_cov.get("uncovered"))
    delta = _num(final_cov.get("delta"))
    kind = _coverage_kind(final_cov)

    last_delta = None
    last_covered = None
    last_uncovered = None
    last_kind = ""
    for item in rounds:
        cmp_ = _mapping(item.get("compare"))
        if not cmp_:
            continue
        d = _num(cmp_.get("delta"))
        c = _num(cmp_.get("covered"))
        u = _num(cmp_.get("uncovered"))
        if d is None and c is None and u is None:
            continue
        last_delta = d if d is not None else last_delta
        last_covered = c if c is not None else last_covered
        last_uncovered = u if u is not None else last_uncovered
        last_kind = _coverage_kind(cmp_) or last_kind

    if covered is None:
        covered = last_covered
    if uncovered is None:
        uncovered = last_uncovered
    if delta is None:
        delta = last_delta
    if not kind:
        kind = last_kind
    block = _coverage_block(covered, uncovered, delta, kind=kind)
    # 口径登记了但不在枚举里（例如 `call_site`）→ kind 归一成 ""，但要说出来，
    # 不然读者会以为“口径已登记为空”。返回值第二项供调用方落 note。
    unmapped = bool(_coverage_kind_unmapped(final_cov)
                    or any(_coverage_kind_unmapped(item.get("compare"))
                           for item in rounds))
    return block, unmapped


def metrics_from_report(report: Mapping, *, arm: str = "research") -> dict:
    """从 `research.json`（或其同形 dict）读事实。空/坏报告 → 全未知。"""
    doc = _blank_arm(arm, source="report")
    notes = doc["notes"]
    if report is None:
        notes.append("no_report")
        return doc
    if not isinstance(report, Mapping):
        notes.append("report_not_mapping")
        return doc
    data = dict(report)
    if not data:
        notes.append("empty_report")
        return doc

    rounds, rounds_known = _report_rounds(data)
    controller = _mapping(data.get("controller"))

    top_rounds = _int_or_none(data.get("rounds"))
    if top_rounds is not None:
        doc["rounds"] = top_rounds
    elif rounds_known:
        doc["rounds"] = len(rounds)
    else:
        notes.append("rounds_unknown")

    doc["executions"] = _int_or_none(data.get("executions"))
    doc["applied"] = _int_or_none(data.get("executions_applied"))
    doc["failed"] = _int_or_none(data.get("executions_failed"))
    doc["observed_rounds"] = _int_or_none(data.get("observed_rounds"))
    doc["candidates"] = _int_or_none(data.get("candidates"))
    if doc["candidates"] is None:
        notes.append("candidates_unknown")

    stopped = data.get("stop_reason")
    if stopped is None:
        stopped = controller.get("stop_reason")
    doc["stopped"] = str(stopped) if isinstance(stopped, str) else None

    # ---- 动作（含被跳过的：跳过也是事实，留在账上） ----
    actions: list = []
    for item in rounds:
        items = item.get("actions")
        if isinstance(items, list):
            actions.extend(dict(a) for a in items if isinstance(a, Mapping))
    if rounds_known:
        counts = _action_counts(actions)
        doc["actions"] = counts
        if counts["proposed"] == 0:
            doc["action_acceptance"] = {"value": None, "known": False,
                                        "reason": "no_actions"}
        else:
            doc["action_acceptance"] = {
                "value": counts["applied"] / counts["proposed"],
                "known": True, "reason": ""}
    else:
        notes.append("actions_unknown")

    # ---- 重复事实 ----
    hashes = [str(r.get("facts_hash") or "") for r in rounds]
    hashes = [h for h in hashes if h]
    if rounds_known:
        if hashes:
            doc["repeats"]["same_facts"] = len(hashes) - len({*hashes})
        else:
            # 轮记录里没有 facts_hash：按“观测到的重复为 0”记，并注明口径
            doc["repeats"]["same_facts"] = 0
            if rounds:
                notes.append("facts_hash_absent")
        doc["repeats"]["skipped_actions"] = counts["skipped"]
        doc["repeats"]["identical_actions"] = _identical_actions(actions)

    # ---- 重复率：分子 (same_facts + skipped) / 分母 (rounds + proposed) ----
    same = doc["repeats"]["same_facts"]
    skipped = doc["repeats"]["skipped_actions"]
    rounds_n = doc["rounds"]
    proposed_n = doc["actions"]["proposed"]
    if None in (same, skipped, rounds_n, proposed_n):
        doc["repeat_rate"] = {"value": None, "known": False,
                              "reason": "no_rounds_or_actions"}
    else:
        denom = int(rounds_n) + int(proposed_n)
        if denom <= 0:
            doc["repeat_rate"] = {"value": None, "known": False,
                                  "reason": "no_rounds_or_actions"}
        else:
            value = (int(same) + int(skipped)) / denom
            doc["repeat_rate"] = {"value": min(1.0, value), "known": True,
                                  "reason": ""}

    # ---- 覆盖率 ----
    coverage, kind_unmapped = _report_coverage(data, controller, rounds)
    doc["coverage"] = coverage
    if not coverage["known"]:
        notes.append("coverage_unknown")
    if kind_unmapped:
        notes.append("coverage_metric_kind_unmapped")

    # ---- 时间：报告里没有“首次崩溃秒数”这一事实 ----
    notes.append("report_has_no_clock")
    return doc


# ====================================================================== events
def _event_rows(events: Iterable[Mapping] | None) -> list:
    """把事件行收成 list；有 `seq` 就按 `seq` 稳定排序，否则保持原序。"""
    if events is None:
        return []
    try:
        items = list(events)
    except TypeError:                     # 不是可迭代 → 当作没有
        return []
    rows = [dict(item) for item in items if isinstance(item, Mapping)]
    seqs = [row.get("seq") for row in rows]
    if rows and all(isinstance(s, int) and not isinstance(s, bool) for s in seqs):
        rows.sort(key=lambda row: int(row["seq"]))
    return rows


def _payload(row: Mapping) -> dict:
    return _mapping(_mapping(row).get("payload"))


def _finished_candidates(payload: Mapping) -> tuple[int, bool]:
    """`exec.finished.payload.candidates`：int 直接取，list 取 len。"""
    value = _mapping(payload).get("candidates")
    if isinstance(value, bool):
        return 0, False
    if isinstance(value, int):
        return int(value), True
    if isinstance(value, list):
        return len(value), True
    return 0, False


def metrics_from_events(events: Iterable[Mapping], *,
                        arm: str = "single_fuzz") -> dict:
    """从事件行（`store.list_events()` 的形状）读事实。"""
    doc = _blank_arm(arm, source="events")
    notes = doc["notes"]
    rows = _event_rows(events)
    if not rows:
        notes.append("no_events")
        return doc

    starts = [row for row in rows if row.get("event_type") == "exec.started"]
    finishes = [row for row in rows if row.get("event_type") == "exec.finished"]
    doc["executions"] = len(starts)
    if not starts:
        notes.append("no_exec_started")

    # ---- 候选：逐条 exec.finished 累加 ----
    total = 0
    seen = False
    for row in finishes:
        count, ok = _finished_candidates(_payload(row))
        if ok:
            seen = True
            total += count
    if seen:
        doc["candidates"] = total
    else:
        notes.append("candidates_unknown")

    # ---- 首次崩溃耗时：先认 fuzz.first_crash_seconds，再退到 wall clock ----
    values: list[float] = []
    for row in finishes:
        fuzz = _mapping(_payload(row).get("fuzz"))
        value = fuzz.get("first_crash_seconds")
        if _is_num(value):
            values.append(float(value))
    if values:
        doc["time_to_first_crash"] = {
            "value": min(values), "unit": "s", "metric_kind": "fuzz_seconds",
            "known": True, "reason": ""}
    else:
        first_start = _ts(starts[0].get("ts")) if starts else None
        first_crash = None
        for row in finishes:
            count, ok = _finished_candidates(_payload(row))
            if ok and count > 0:
                first_crash = _ts(row.get("ts"))
                break
        seconds = _seconds(first_crash, first_start)
        if seconds is not None:
            doc["time_to_first_crash"] = {
                "value": seconds, "unit": "s",
                "metric_kind": "wall_clock_seconds", "known": True,
                "reason": ""}
            notes.append("time_from_wall_clock")
        else:
            notes.append("no_crash_seen" if finishes else "no_exec_finished")

    # ---- 覆盖率：最后一条带数字 coverage 的 exec.finished ----
    coverage = {}
    for row in finishes:
        candidate = _mapping(_payload(row).get("coverage"))
        if not candidate:
            continue
        if any(_is_num(candidate.get(key))
               for key in ("covered", "uncovered", "delta")):
            coverage = candidate
    if coverage:
        doc["coverage"] = _coverage_block(
            coverage.get("covered"), coverage.get("uncovered"),
            coverage.get("delta"), kind=_coverage_kind(coverage))
        if _coverage_kind_unmapped(coverage):
            notes.append("coverage_metric_kind_unmapped")
    else:
        notes.append("coverage_unknown")

    # ---- 重复：事件侧没有 facts_hash / 动作，按 0 记并注明口径 ----
    doc["repeats"] = {"same_facts": 0, "skipped_actions": 0,
                      "identical_actions": 0}
    notes.append("events_have_no_actions")
    notes.append("rounds_unknown")
    return doc


# ====================================================================== merge
def merge_metrics(primary: Mapping, events: Iterable[Mapping]) -> dict:
    """用事件补主文档里 `known=False` 的项；已知的事实不被更弱的证据覆盖。"""
    doc = _plain(_mapping(primary))
    if not doc:
        return _plain(_blank_arm("research", source="report"))
    doc.setdefault("notes", [])
    if not isinstance(doc.get("notes"), list):
        doc["notes"] = []
    rows = _event_rows(events)
    if not rows:
        return doc

    event_doc = metrics_from_events(rows, arm=str(doc.get("arm") or "research"))
    merged: list[str] = []

    for key in ("time_to_first_crash", "coverage"):
        mine = _mapping(doc.get(key))
        theirs = _mapping(event_doc.get(key))
        if not mine:
            continue
        if not mine.get("known") and theirs.get("known"):
            doc[key] = theirs
            merged.append(key)

    if doc.get("executions") is None and event_doc.get("executions") is not None:
        doc["executions"] = event_doc["executions"]
        merged.append("executions")
    if doc.get("candidates") is None \
            and event_doc.get("candidates") is not None:
        # 候选数在事件侧是观测事实（`exec.finished.payload.candidates`），
        # 主文档为 None 时用它补；已被报告写死的不覆盖。
        doc["candidates"] = event_doc["candidates"]
        merged.append("candidates")
    if doc.get("applied") is None and event_doc.get("applied") is not None:
        doc["applied"] = event_doc["applied"]
        merged.append("applied")
    if doc.get("failed") is None and event_doc.get("failed") is not None:
        doc["failed"] = event_doc["failed"]
        merged.append("failed")

    if merged:
        doc["notes"] = list(doc["notes"]) + [f"from_events:{key}"
                                            for key in merged]
        # 事件侧的口径备注跟着它的事实一起搬过来，别让“口径未登记”被吃掉
        if "coverage" in merged and "coverage_metric_kind_unmapped" \
                in (event_doc.get("notes") or ()):
            if "coverage_metric_kind_unmapped" not in doc["notes"]:
                doc["notes"] = list(doc["notes"]) + [
                    "coverage_metric_kind_unmapped"]
        doc["source"] = "report+events"
    return doc


# ====================================================================== 对比
def _values(metric: str, baseline: Mapping, treatment: Mapping):
    """抽一对可比的数值 + 各自口径 + 已知性与原因。"""
    if metric == "coverage":
        b = _mapping(baseline.get("coverage"))
        t = _mapping(treatment.get("coverage"))
        b_delta, t_delta = _num(b.get("delta")), _num(t.get("delta"))
        b_cov, t_cov = _num(b.get("covered")), _num(t.get("covered"))
        if b_delta is not None and t_delta is not None:
            return b_delta, t_delta, b, t, "delta"
        if b_cov is not None and t_cov is not None:
            return b_cov, t_cov, b, t, "covered"
        return None, None, b, t, ""

    if metric == "candidates":
        # 候选数是臂文档的顶层字段（不是带 known 的子块）
        out = []
        for doc in (baseline, treatment):
            value = _num(doc.get("candidates"))
            out.append({"value": value, "known": value is not None,
                        "reason": "" if value is not None
                        else "no_candidate_facts"})
        return (out[0]["value"], out[1]["value"], out[0], out[1], "value")

    b = _mapping(baseline.get(metric))
    t = _mapping(treatment.get(metric))
    return _num(b.get("value")), _num(t.get("value")), b, t, "value"


def _metric_row(metric: str, baseline: Mapping, treatment: Mapping) -> dict:
    b_value, t_value, b_block, t_block, basis = _values(metric, baseline,
                                                        treatment)
    b_known = bool(b_block.get("known")) and b_value is not None
    t_known = bool(t_block.get("known")) and t_value is not None
    b_reason = str(b_block.get("reason") or "")
    t_reason = str(t_block.get("reason") or "")
    lower = metric in LOWER_IS_BETTER

    kind_b = str(b_block.get("metric_kind") or "") \
        if metric in ("time_to_first_crash", "coverage") else ""
    kind_t = str(t_block.get("metric_kind") or "") \
        if metric in ("time_to_first_crash", "coverage") else ""

    reason = ""
    unknown: list[str] = []
    if not b_known:
        unknown.append("baseline")
    if not t_known:
        unknown.append("treatment")
    if len(unknown) == 2:
        # 两臂都未知：两侧原因都要留下（不同则 `|` 连接，同则只留一份）
        reason = b_reason or t_reason or "no_facts"
        if b_reason and t_reason and b_reason != t_reason:
            reason = f"{b_reason}|{t_reason}"
    elif unknown == ["baseline"]:
        reason = b_reason or "no_facts"
    elif unknown == ["treatment"]:
        reason = t_reason or "no_facts"

    kind_mismatch = bool(b_known and t_known and kind_b != kind_t)
    if kind_mismatch:
        reason = "metric_kind_mismatch"
        unknown = []

    known = bool(b_known and t_known and not kind_mismatch)
    delta = None
    ratio = None
    direction = "unknown"
    if known:
        delta = float(t_value) - float(b_value)
        if abs(float(b_value)) > _EPS:
            ratio = float(t_value) / float(b_value)
        # baseline == 0 → ratio 未知（不是 inf），但 delta 仍是事实
        if abs(delta) <= _EPS:
            direction = "same"
        elif (delta < 0) == bool(lower):
            direction = "better"
        else:
            direction = "worse"

    row = {"metric": metric, "baseline": b_value, "treatment": t_value,
           "delta": delta, "ratio": ratio, "direction": direction,
           "known": known, "reason": reason,
           # 哪一臂缺事实：区分“这一臂未知”与“两臂都未知”
           "unknown_arms": unknown}
    if metric in ("time_to_first_crash", "coverage"):
        row["basis"] = basis
        row["metric_kind"] = {"baseline": kind_b, "treatment": kind_t}
    return row


def _looks_absent(doc: Mapping) -> bool:
    """这只臂是不是“什么都没拿到”（用于 no_baseline 判定）。"""
    if doc.get("executions") is not None or doc.get("rounds") is not None:
        return False
    if doc.get("candidates") is not None:
        return False
    for key in ("time_to_first_crash", "coverage"):
        if _mapping(doc.get(key)).get("known"):
            return False
    actions = _mapping(doc.get("actions"))
    if actions.get("proposed") is not None:
        return False
    return True


def compare_arms(baseline: Mapping, treatment: Mapping) -> dict:
    """把两只臂并排成一张表。`baseline` 为单次 fuzz，`treatment` 为研究循环。"""
    base = _plain(_mapping(baseline)) or _plain(_blank_arm("single_fuzz"))
    treat = _plain(_mapping(treatment)) or _plain(_blank_arm("research"))
    for doc, default in ((base, "single_fuzz"), (treat, "research")):
        if doc.get("arm") not in ARMS:
            doc["arm"] = default
            doc["arm_label"] = ARM_LABELS[default]

    if base["arm"] == treat["arm"]:
        arms = {"baseline": base, "treatment": treat}
    else:
        arms = {base["arm"]: base, treat["arm"]: treat}

    rows = [_metric_row(metric, base, treat) for metric in METRICS]

    no_baseline = _looks_absent(base)
    reasons: list[str] = []
    if no_baseline:
        reasons.append("no_baseline")
    for row in rows:
        if not row["known"] and row["reason"]:
            token = f"{row['metric']}:{row['reason']}"
            if token not in reasons:
                reasons.append(token)
    comparable = any(row["known"] for row in rows)
    if not comparable and "no_shared_metric" not in reasons:
        reasons.append("no_shared_metric")

    research = arms.get("research", treat)
    single = arms.get("single_fuzz", base)

    def _per_candidate(doc: Mapping):
        proposed = _mapping(doc.get("actions")).get("proposed")
        candidates = doc.get("candidates")
        if proposed is None or candidates is None:
            return None
        try:
            if int(candidates) <= 0:
                return None
            return float(proposed) / float(int(candidates))
        except (TypeError, ValueError):    # pragma: no cover - 兜底
            return None

    doc = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "arms": arms,
        "comparable": bool(comparable),
        "comparability": {"comparable": bool(comparable), "reasons": reasons},
        "metrics": rows,
        "counts_are_not_intelligence": {
            "actions_proposed": {
                "research": _mapping(research.get("actions")).get("proposed"),
                "single_fuzz": _mapping(single.get("actions")).get("proposed"),
            },
            "actions_per_candidate": {
                "research": _per_candidate(research),
                "single_fuzz": _per_candidate(single),
            },
            "rounds": {"research": research.get("rounds"),
                       "single_fuzz": single.get("rounds")},
            "note": COUNTS_NOTE,
        },
        "rounds": [],
        "negative_results": [{"item": row["metric"], "reason": row["reason"]}
                             for row in rows
                             if not row["known"] and row["reason"]],
        "verdict": "not_evaluated",
        "note": NOTE,
        "label": "",
    }
    return doc


# ====================================================================== 轮级
def _round_rows(report: Mapping | None) -> list:
    """研究循环逐轮账：覆盖增益 / 候选 / 采纳动作数 / 增益类型。"""
    if not isinstance(report, Mapping) or not report:
        return []
    rounds, known = _report_rounds(report)
    if not known:
        return []
    rows = []
    for index, item in enumerate(rounds):
        round_no = _int_or_none(item.get("round"))
        if round_no is None:
            round_no = index + 1
        cmp_ = _mapping(item.get("compare"))
        delta = _num(cmp_.get("delta"))
        candidates = 0
        applied = 0
        for action in item.get("actions") or ():
            data = _mapping(action)
            if not data:
                continue
            if str(data.get("status") or "").lower() in _APPLIED_STATUSES:
                applied += 1
            value = data.get("candidates")
            if isinstance(value, list):
                candidates += len(value)
            elif _is_num(value):
                candidates += int(value)
        if delta is None:
            gain = "candidate" if candidates else "unknown"
        elif abs(delta) <= _EPS:
            gain = "candidate" if candidates else "none"
        else:
            gain = "both" if candidates else "coverage"
        rows.append({"round": int(round_no), "coverage_delta": delta,
                     "candidates": int(candidates),
                     "actions_applied": int(applied), "gain": gain,
                     "note": str(item.get("note") or "")})
    return rows


def _round_negatives(rows: list) -> list:
    out = []
    for row in rows:
        delta = row.get("coverage_delta")
        if delta is not None and abs(float(delta)) <= _EPS:
            out.append({"item": f"round:{row['round']}",
                        "reason": "coverage_delta_zero"})
        elif row.get("gain") == "none":
            out.append({"item": f"round:{row['round']}", "reason": "no_gain"})
    return out


# ====================================================================== 组装
def build_compare(*, research_report: Mapping | None = None,
                  research_events: Iterable[Mapping] = (),
                  baseline_report: Mapping | None = None,
                  baseline_events: Iterable[Mapping] = (),
                  baseline_label: str = "",
                  notes: Iterable[str] = ()) -> dict:
    """组装 compare 文档：研究循环 vs 单次 fuzz。任何坏输入都降级成未知。"""
    extra: list[str] = []
    try:
        extra = [str(item) for item in (notes or ())]
    except TypeError:                     # pragma: no cover - 兜底
        extra = []

    try:
        r_events = _event_rows(research_events)
        b_events = _event_rows(baseline_events)

        if research_report is None:
            research = metrics_from_events(r_events, arm="research")
        else:
            research = merge_metrics(
                metrics_from_report(research_report, arm="research"), r_events)

        baseline = merge_metrics(
            metrics_from_report(baseline_report or {}, arm="single_fuzz"),
            b_events)
        if _looks_absent(baseline) and not b_events:
            extra = _append(extra, "no_baseline")

        doc = compare_arms(baseline, research)
        doc["label"] = str(baseline_label or "")

        round_rows = _round_rows(research_report)
        doc["rounds"] = round_rows

        negatives = list(doc.get("negative_results") or [])
        for item in _round_negatives(round_rows):
            if item not in negatives:
                negatives.append(item)
        if not doc.get("comparable"):
            for reason in (doc.get("comparability") or {}).get("reasons", []):
                if reason in ("no_baseline", "no_shared_metric"):
                    negatives = _append(negatives, {"item": "compare",
                                                    "reason": reason},
                                        key="reason")
        doc["negative_results"] = negatives

        merged_notes = list(extra)
        bare_signals: list[str] = []
        for key in ("research", "single_fuzz"):
            for note in _mapping(doc["arms"].get(key)).get("notes") or ():
                merged_notes = _append(merged_notes, f"{key}.{note}")
                if str(note) in _BARE_NOTES:
                    bare_signals = _append(bare_signals, str(note))
        # 口径类备注除了带臂前缀的溯源条目，再留一份裸词：
        # 读者/校验可以直接在 notes 里命中“口径没登记”，不会误以为登记为空。
        for note in bare_signals:
            merged_notes = _append(merged_notes, note)
        doc["notes"] = merged_notes
        doc["verdict"] = "not_evaluated"
        return doc
    except Exception as exc:              # noqa: BLE001 - 对照也要能降级
        doc = compare_arms(_blank_arm("single_fuzz"), _blank_arm("research"))
        doc["notes"] = _append(list(extra), f"error:{type(exc).__name__}")
        doc["rounds"] = []
        doc["label"] = str(baseline_label or "")
        return doc


def _append(items: list, value, *, key: str | None = None) -> list:
    """按值（或按 dict 的某个键）去重后追加，保持顺序不变。"""
    if key is not None and isinstance(value, Mapping):
        if any(isinstance(item, Mapping) and item.get(key) == value.get(key)
               for item in items):
            return items
    elif value in items:
        return items
    out = list(items)
    out.append(value)
    return out


# ====================================================================== 渲染
def _show(value: Any) -> str:
    """表格里的数值写法；未知一律 `未知`（不写 0）。"""
    if value is None:
        return "未知"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.6f}".rstrip("0")
        if text.endswith("."):
            text += "0"
        return text
    return str(value)


def _cell(row: Mapping, side: str) -> str:
    value = row.get(side)
    if not row.get("known") and row.get("metric") in ("time_to_first_crash",
                                                      "coverage"):
        return "未知"
    return _show(value)


def render_markdown(doc: Mapping) -> str:
    """把 compare 文档渲染成 markdown 片段（确定性，无时间戳）。"""
    data = _mapping(doc)
    arms = _mapping(data.get("arms"))
    research = _mapping(arms.get("research"))
    single = _mapping(arms.get("single_fuzz"))
    lines: list[str] = ["## 对照实验（研究循环 vs 单次 fuzz）", ""]

    comparability = _mapping(data.get("comparability"))
    verdict = str(data.get("verdict") or "not_evaluated")
    lines.append(f"- 结果判定：`{verdict}`（只记事实，不出结论）")
    lines.append(f"- 可比性：{'可比' if data.get('comparable') else '不可比'}")
    reasons = [str(item) for item in comparability.get("reasons") or ()]
    if reasons:
        lines.append(f"- 不可比原因：{'、'.join(f'`{r}`' for r in reasons)}")
    if data.get("label"):
        lines.append(f"- 基准标签：{data['label']}")
    lines.append("")

    lines.append("| 指标 | 研究循环 | 单次 fuzz | Δ | 方向 | 可比 | 说明 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for row in data.get("metrics") or ():
        item = _mapping(row)
        metric = str(item.get("metric") or "")
        label = _METRIC_LABELS.get(metric, metric)
        direction = _DIRECTION_LABELS.get(str(item.get("direction") or ""),
                                          "未知")
        reason = str(item.get("reason") or "")
        if not reason:
            reason = "—"
        if item.get("metric") == "coverage":
            basis = str(item.get("basis") or "")
            if basis:
                reason = f"{reason}（按 {basis} 比）" if reason != "—" \
                    else f"按 {basis} 比"
        lines.append(
            f"| {label} | {_cell(item, 'treatment')} | {_cell(item, 'baseline')} | "
            f"{_show(item.get('delta'))} | {direction} | "
            f"{'可比' if item.get('known') else '不可比'} | {reason} |")
    lines.append("")

    lines.append("### 动作次数不是智能")
    lines.append("")
    counts = _mapping(data.get("counts_are_not_intelligence"))
    proposed = _mapping(counts.get("actions_proposed"))
    per_candidate = _mapping(counts.get("actions_per_candidate"))
    rounds = _mapping(counts.get("rounds"))
    lines.append(
        f"研究循环提出 {_show(proposed.get('research'))} 个动作、"
        f"单次 fuzz 提出 {_show(proposed.get('single_fuzz'))} 个；"
        f"每候选动作数：研究循环 {_show(per_candidate.get('research'))}、"
        f"单次 fuzz {_show(per_candidate.get('single_fuzz'))}；"
        f"轮数：研究循环 {_show(rounds.get('research'))}、"
        f"单次 fuzz {_show(rounds.get('single_fuzz'))}。")
    lines.append("")
    lines.append(f"> {counts.get('note') or COUNTS_NOTE}")
    lines.append("")

    round_rows = data.get("rounds") or []
    if round_rows:
        lines.append("### 逐轮账（研究循环）")
        lines.append("")
        lines.append("| 轮 | 覆盖增益 | 候选 | 采纳动作 | 增益类型 | 说明 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in round_rows:
            item = _mapping(row)
            lines.append(
                f"| {_show(item.get('round'))} | "
                f"{_show(item.get('coverage_delta'))} | "
                f"{_show(item.get('candidates'))} | "
                f"{_show(item.get('actions_applied'))} | "
                f"{item.get('gain') or 'unknown'} | "
                f"{item.get('note') or '—'} |")
        lines.append("")

    lines.append("### 负结果")
    lines.append("")
    negatives = data.get("negative_results") or []
    if not negatives:
        lines.append("- （无：没有记录到零增益轮次或未知指标）")
    else:
        for item in negatives:
            entry = _mapping(item)
            lines.append(f"- `{entry.get('item') or '?'}`："
                         f"{entry.get('reason') or '未知'}")
    lines.append("")
    lines.append(f"> {data.get('note') or NOTE}")
    lines.append("")
    return "\n".join(lines)


# ====================================================================== 便捷
def metrics_for_store(store=None, task_id: str = "") -> dict:
    """可选便捷函数：只读 `store.list_events(task_id)`，产出事件侧指标。

    不读库、不写库、不导入 `agent.platform.*`；只当 `store` 是鸭子类型。
    """
    if store is None or not str(task_id or "").strip():
        doc = _blank_arm("research", source="events")
        doc["notes"].append("no_store")
        return doc
    try:
        events = store.list_events(str(task_id))
    except Exception as exc:              # noqa: BLE001 - 读不到就如实记未知
        doc = _blank_arm("research", source="events")
        doc["notes"].append(f"store_unreadable:{type(exc).__name__}")
        return doc
    return metrics_from_events(events, arm="research")


# ====================================================================== W4 A/B
#: 第 4 周对照框架：同一回归集 / 同一初始配置 / 同一预算 / 同一人工规则下，
#: A 臂 = 现有确定性规则（`adaptive.session.DiagnoseRole` + `ResearchSession
#: .propose`），B 臂 = 模型**只读建议**（外部 provider 给的诊断码 + 动作建议，
#: 逐条过同一份工具 schema，永不自动应用）。
#:
#: 口径（写死，改之前先改契约）：
#:
#: 1. **两臂吃同一份输入**：回归集 / 初始配置 / 预算 / 人工规则由 `controls`
#:    记录一次，两臂各存一份摘要；摘要不同就是框架 bug（`arms_share_controls`
#:    写死为两臂摘要相等的判定结果，不是“相信调用方”）。
#: 2. **只读建议**：B 臂的每条建议都要过 `Registry.get()` + `spec.validate()` +
#:    裁决字段剥离；过不了的进 `rejected`，**不采纳**。建议里出现
#:    `verified/confirmed/...` 一律拒（沿用 `policy.prune_verdict_fields`）。
#: 3. **不自动应用**：`gate.auto_apply` 恒为 `False`。即使门禁通过，模型建议也只
#:    进建议清单（“建议源”换人，不是“写权限”换人）；真正应用仍走隔离/授权验收门
#:    （`handoff.ProposalGate`）。
#: 4. **错误采纳优先**：B 臂 `wrong_adoptions > 0` → 门禁直接判“默认规则”，
#:    不再看收益；收益只有在“没有错误采纳 + 覆盖够 + 每个分层都有严格增益”时才算稳定。
#: 5. **保留坏结果**：环境错误 / 无建议 / 建议被拒 / 预算耗尽四条一律留档
#:    （`summary.retained`），既不从分母里悄悄删掉，也不当成“模型答错”。
#: 6. **不产裁决**：`verdict` 恒为 `"not_evaluated"`；门禁结论只关于“建议源”，
#:    不关于漏洞。
#:
#: 时间口径：`elapsed_seconds` 用注入的 `clock()` 实测（默认 `perf_counter`）；
#: 除耗时外的字段对同一输入逐字节确定，测试用 `FakeClock` 让耗时也确定。

AB_SCHEMA = "vulnmap.adaptive.ab.v1"
AB_GATE_SCHEMA = "vulnmap.adaptive.ab.gate.v1"
AB_REQUEST_SCHEMA = "vulnmap.adaptive.ab.request.v1"
AB_SCHEMA_VERSION = 1

#: 两只臂：现有规则 / 模型只读建议
AB_ARMS = ("rules", "model")
AB_ARM_LABELS = {"rules": "现有规则", "model": "模型只读建议"}

#: 七个指标（顺序即文档顺序，也是 markdown 表顺序）
AB_METRICS = ("correct_diagnoses", "invalid_retries", "elapsed_seconds",
              "model_calls", "model_tokens", "model_usd", "wrong_adoptions")
AB_METRIC_LABELS = {
    "correct_diagnoses": "正确诊断数",
    "invalid_retries": "无效重试次数",
    "elapsed_seconds": "耗时（秒）",
    "model_calls": "模型调用次数",
    "model_tokens": "模型 tokens",
    "model_usd": "模型费用（USD）",
    "wrong_adoptions": "错误采纳数",
}
#: 越低越好的指标；其余按“越高越好”
AB_LOWER_IS_BETTER = frozenset({"invalid_retries", "elapsed_seconds",
                               "model_calls", "model_tokens", "model_usd",
                               "wrong_adoptions"})

#: 一臂在一项任务上的状态（`ok` 之外的四类都要保留，不进“答对/答错”分母）
AB_STATUSES = ("ok", "no_suggestion", "rejected", "budget_exhausted",
               "environment_error")
AB_RETAINED = ("environment_error", "no_suggestion", "rejected",
               "budget_exhausted")

#: 规划类动作：不改执行、不写结论，采纳它们不算“错误采纳”
AB_PLANNING_ACTIONS = frozenset({"propose_seed_spec", "materialize_seeds",
                                 "set_dictionary", "get_task_facts",
                                 "get_execution_facts", "read_source_window",
                                 "compare_trials"})
#: 执行/结论类动作：只有 gold 明确允许时才算“没采纳错”
AB_EXECUTING_ACTIONS = frozenset({"run_epoch", "replay_input",
                                  "finish_research"})

#: 预算默认值（两臂共用；见 `controls.budget`）。
#: 四项都按“`<= 0` 表示不限”解释：默认值全是正数，所以默认是限的。
AB_DEFAULT_BUDGET = {"max_rounds": 3, "max_calls": 32,
                     "max_tokens": 200000, "max_usd": 2.0}
#: 人工规则默认值（两臂共用；见 `controls.human_rules`）
AB_DEFAULT_RULES = {"require_no_wrong_adoption": True,
                    "min_answered_ratio": 0.8,
                    "require_stable_gain": True,
                    "allow_auto_apply": False,
                    "max_suggestions_per_round": 1,
                    "adoption_policy": "counterfactual"}

AB_NOTE = "A/B 只比事实与成本；门禁结论是“建议源是否可用”，不是漏洞裁决"
AB_GATE_NOTE = ("模型建议永不自动应用：门禁通过也只进建议清单，"
                "应用仍走隔离/授权验收门（ProposalGate）")
AB_VERDICT = "not_evaluated"

#: provider 的三种口径：
#: - `offline`（默认）：W4 的硬门，provider 必须 `offline=True`，禁止真实 key；
#: - `real`：真实模型只读 A/B，provider 必须 `real_model=True` + `read_only=True`，
#:   且**不**要求 offline；门禁里把 `offline_provider` 换成
#:   `read_only_real_provider`，`auto_apply` 仍恒为 False。
#: - `simulated`：注入 transport 的本地替身（`result_source="simulated"` /
#:   `transport="injected"`）：只比指标与门禁形状，**永不进真实统计**；门禁检查
#:   叫 `read_only_simulated_provider`，`auto_apply` 同样恒为 False。
AB_PROVIDER_KINDS = ("offline", "real", "simulated")
AB_REAL_PROVIDER_NOTE = ("真实模型只读：provider 只回建议，不写状态/证据/判据；"
                         "auto_apply 恒 False")


def _ab_is_simulated_provider(provider) -> bool:
    """provider 是否是“注入 transport 的本地替身”（结果不进真实统计）。"""
    return (str(getattr(provider, "result_source", "") or "")
            == "simulated"
            or str(getattr(provider, "transport", "") or "") == "injected")


class ABError(ValueError):
    """A/B 组装错误（回归集为空、任务重名等编程错误；不用于“事实缺失”）。"""


# ---------------------------------------------------------------------- 小工具
def _ab_digest(value: Any) -> str:
    """规范化 JSON 的 sha256（键排序；`default=str` 保证可序列化）。"""
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _ab_gold(gold: Any) -> dict:
    doc = _mapping(gold)
    code = str(doc.get("diagnosis") or "").strip()
    if not code:
        raise ABError("gold.diagnosis 不能为空（人工规则必须给出期望诊断码）")
    return {
        "diagnosis": code,
        "actions": sorted({str(a) for a in (doc.get("actions") or ()) if str(a)}),
        "forbid": sorted({str(a) for a in (doc.get("forbid") or ()) if str(a)}),
        "note": str(doc.get("note") or ""),
    }


def ab_task(task_id: str, *, rounds: Iterable[Mapping] | None = None,
            observation: Mapping | None = None, gold: Mapping | None = None,
            note: str = "") -> dict:
    """把一条回归任务规范化成框架认的形状（单个 `observation` 或 `rounds` 列表）。

    一轮 = 一次“同一任务上的执行反馈”；多轮任务的第 2..n 轮就是重试。
    """
    tid = str(task_id or "").strip()
    if not tid:
        raise ABError("task_id 不能为空")
    specs: list[dict] = []
    if rounds is not None:
        specs = [dict(item) for item in rounds]
    elif observation is not None:
        specs = [dict(observation)]
    if not specs:
        raise ABError(f"{tid}: rounds 不能为空（至少一轮观测）")
    for item in specs:
        if not isinstance(item, Mapping):
            raise ABError(f"{tid}: 每一轮观测必须是 mapping")
    return {"task_id": tid, "rounds": specs, "gold": _ab_gold(gold),
            "note": str(note or "")}


_OBS_KEYS = ("program_started", "input_processed", "checkpoint_reached",
             "target_reached", "coverage", "candidates", "fault", "config",
             "budget", "trials", "unknowns", "revision", "workspace",
             "hypothesis_id", "site_id", "snapshot_status", "execution_id",
             "collected_at", "input_facts")


#: 事实指纹只覆盖“进展事实”：轮数/耗时/执行 id/试验次数变了不算新事实
#: （与 `session.ContextRole._facts_hash` 同一口径，只是不重写那套键）。
_AB_FACT_KEYS = ("program_started", "input_processed", "checkpoint_reached",
                 "target_reached", "coverage", "candidates", "fault",
                 "config", "input_facts")


def _ab_observation(spec: Any, *, task_id: str, round_no: int) -> dict:
    """规范化一轮观测：只留 `Observation` 认的键，并算事实指纹。"""
    src = _mapping(spec)
    doc: dict = {"task_id": task_id, "round_no": int(round_no)}
    for key in _OBS_KEYS:
        if key in src:
            doc[key] = src[key]
    if "input" in src and "input_facts" not in doc:
        doc["input_facts"] = src["input"]
    facts = {key: doc[key] for key in _AB_FACT_KEYS if key in doc}
    doc["facts_hash"] = _ab_digest(facts)[:16]
    return doc


def _ab_blank_record(arm: str) -> dict:
    name = str(arm or "")
    if name not in AB_ARMS:
        raise ABError(f"unknown arm: {arm!r}（只认 {AB_ARMS}）")
    return {
        "arm": name, "arm_label": AB_ARM_LABELS[name],
        "status": "ok", "diagnosis": "", "actions": [],
        "correct": None, "adopted": 0, "wrong_adoption": 0,
        "wrong_reasons": [], "retries": 0, "invalid_retries": 0,
        "executed_rounds": 0, "elapsed_seconds": 0.0,
        "calls": 0, "tokens_in": 0, "tokens_out": 0, "tokens": 0,
        "usd": (0.0 if name == "rules" else None),
        "usd_known": name == "rules",
        "rejected": [], "error": "", "rounds": [],
    }


def _ab_judge(record: dict, task: Mapping) -> dict:
    """按人工 gold 判“诊断对不对”“采纳有没有错”。

    - 状态不是 `ok`（环境错误/无建议/被拒/预算耗尽）→ `correct=None`，不进分母；
    - `correct` = 该臂**最后一轮**的诊断码是否等于 `gold.diagnosis`；
    - `adopted` = 这一臂这一轮真提了动作（空计划不算采纳）；
    - `wrong_adoption` = 采纳了但诊断不符，或提了 gold 明确禁止/不该执行的动作。
    """
    gold = _mapping(task.get("gold"))
    if record.get("status") != "ok":
        record["correct"] = None
        record["adopted"] = 0
        record["wrong_adoption"] = 0
        return record
    diagnosis = str(record.get("diagnosis") or "")
    actions = [str(item) for item in (record.get("actions") or ())]
    record["correct"] = diagnosis == str(gold.get("diagnosis") or "")
    adopted = bool(actions)
    record["adopted"] = 1 if adopted else 0
    reasons: list[str] = []
    if diagnosis != str(gold.get("diagnosis") or ""):
        reasons.append("diagnosis_mismatch")
    forbid = set(gold.get("forbid") or ())
    allowed = set(gold.get("actions") or ())
    for action in actions:
        if action in forbid:
            reasons.append(f"forbidden_action:{action}")
        elif action in AB_EXECUTING_ACTIONS and action not in allowed:
            reasons.append(f"unexpected_action:{action}")
        elif action not in allowed and action not in AB_PLANNING_ACTIONS:
            # 既不在 gold、也不在规划白名单：只有在工具表扩了新工具时才会命中
            reasons.append(f"unexpected_action:{action}")
    record["wrong_adoption"] = 1 if (adopted and reasons) else 0
    record["wrong_reasons"] = sorted(set(reasons))
    return record


# ---------------------------------------------------------------------- 引擎
def _ab_engine() -> dict:
    """延迟导入规则引擎（`adaptive.session`/`tools`），避免与 `platform` 成环。"""
    from .policy import prune_verdict_fields
    from .session import DIAGNOSIS_CODES, Observation, ResearchSession
    from .tools import REGISTRY, make_binding
    return {"Observation": Observation, "Session": ResearchSession,
            "Registry": REGISTRY, "make_binding": make_binding,
            "codes": tuple(DIAGNOSIS_CODES),
            "prune": prune_verdict_fields}


def _ab_rules_task(task: Mapping, *, engine: Mapping, clock, budget: Mapping)\
        -> dict:
    """A 臂：现有确定性规则（`DiagnoseRole` + `ResearchSession.propose`）。"""
    record = _ab_blank_record("rules")
    started = float(clock())
    tid = str(task.get("task_id") or "")
    max_rounds = int(budget.get("max_rounds") or 0)
    try:
        binding = engine["make_binding"]({"task_id": tid},
                                         registry=engine["Registry"])
        session = engine["Session"](binding=binding, registry=engine["Registry"])
    except Exception as exc:              # noqa: BLE001 - 规则引擎起不来就是环境错误
        record["status"] = "environment_error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["elapsed_seconds"] = float(clock()) - started
        return record

    previous = ""
    executed = 0
    for index, spec in enumerate(task.get("rounds") or ()):
        if max_rounds > 0 and executed >= max_rounds:
            record["status"] = "budget_exhausted"
            record["error"] = "max_rounds"
            break
        doc = _ab_observation(spec, task_id=tid, round_no=index + 1)
        try:
            observation = engine["Observation"](**doc)
            diagnosis = session.diagnose(observation)
            plan = session.propose(diagnosis, observation)
        except Exception as exc:          # noqa: BLE001 - 单轮失败不冒充诊断
            record["status"] = "environment_error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            break
        executed += 1
        record["diagnosis"] = diagnosis.code
        record["actions"] = [action.action for action in plan.actions]
        if index >= 1 and doc["facts_hash"] == previous:
            record["invalid_retries"] += 1
        previous = doc["facts_hash"]
        record["rounds"].append({"round": index + 1,
                                 "facts_hash": doc["facts_hash"],
                                 "diagnosis": diagnosis.code,
                                 "actions": list(record["actions"])})
    record["executed_rounds"] = executed
    record["retries"] = max(0, executed - 1)
    record["elapsed_seconds"] = float(clock()) - started
    return _ab_judge(record, task)


def _ab_usage(raw: Mapping) -> tuple[int, int, Any]:
    """从 provider 返回值里读 usage：拿不到就是 0 计数 + 金额未知（不是 0 元）。"""
    usage = _mapping(raw.get("usage"))
    tokens_in = _int_or_none(usage.get("tokens_in"))
    tokens_out = _int_or_none(usage.get("tokens_out"))
    if tokens_in is None:
        tokens_in = _int_or_none(usage.get("prompt_tokens")) or 0
    if tokens_out is None:
        tokens_out = _int_or_none(usage.get("completion_tokens")) or 0
    usd = raw.get("usd", usage.get("usd"))
    return int(tokens_in or 0), int(tokens_out or 0), usd


def _ab_validate_suggestion(raw: Mapping, *, engine: Mapping,
                            mode: str = "explore") -> tuple[str, list, list]:
    """逐条校验模型建议：诊断码、工具名、参数 schema、裁决字段。"""
    rejected: list[str] = []
    diagnosis = ""
    doc = raw.get("diagnosis")
    codes = engine["codes"]
    if isinstance(doc, Mapping):
        code = str(doc.get("code") or "").strip()
    elif isinstance(doc, str):
        code = doc.strip()
    else:
        code = ""
    if code:
        if code in codes:
            diagnosis = code
        else:
            rejected.append(f"invalid_diagnosis:{code}")
    actions: list[str] = []
    items = raw.get("actions")
    if items is None:
        items = []
    if not isinstance(items, (list, tuple)):
        rejected.append("actions_not_list")
        items = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            rejected.append(f"action[{index}]:not_mapping")
            continue
        name = str(item.get("action") or "").strip()
        params = item.get("params") or {}
        if not isinstance(params, Mapping):
            rejected.append(f"action[{index}]:params_not_mapping")
            continue
        clean, stripped = engine["prune"](params)
        if stripped:
            rejected.append(f"action[{index}]:verdict_fields:"
                            f"{','.join(sorted(stripped))}")
            continue
        try:
            spec = engine["Registry"].get(name)
            if mode not in spec.allowed_modes:
                rejected.append(f"action[{index}]:mode:{name}")
                continue
            spec.validate(clean)
        except Exception as exc:          # noqa: BLE001 - 过不了闸就是“被拒”
            rejected.append(f"action[{index}]:{type(exc).__name__}:{name}")
            continue
        actions.append(name)
    return diagnosis, actions, rejected


def _ab_model_task(task: Mapping, *, provider, engine: Mapping, clock,
                   budget: Mapping, counters: dict) -> dict:
    """B 臂：模型只读建议（provider 每轮调一次；建议过闸才进“采纳”）。"""
    record = _ab_blank_record("model")
    started = float(clock())
    tid = str(task.get("task_id") or "")
    max_rounds = int(budget.get("max_rounds") or 0)
    max_calls = int(budget.get("max_calls") or 0)
    tokens_in_total = 0
    tokens_out_total = 0
    usd_total = 0.0
    usd_known = True
    previous = ""
    executed = 0
    stop = False
    rounds = list(task.get("rounds") or ())
    for index, spec in enumerate(rounds):
        if max_rounds > 0 and executed >= max_rounds:
            record["status"] = "budget_exhausted"
            record["error"] = "max_rounds"
            break
        if max_calls > 0 and counters["calls"] >= max_calls:
            record["status"] = "budget_exhausted"
            record["error"] = "max_calls"
            stop = True
            break
        doc = _ab_observation(spec, task_id=tid, round_no=index + 1)
        payload = {"schema": AB_REQUEST_SCHEMA, "task_id": tid,
                   "round_no": index + 1, "observation": doc}
        try:
            raw = provider(payload)
        except Exception as exc:          # noqa: BLE001 - provider 崩了就是环境错误
            record["status"] = "environment_error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            break
        counters["calls"] += 1
        record["calls"] += 1
        if not isinstance(raw, Mapping):
            record["status"] = "environment_error"
            record["error"] = "provider_returned_non_mapping"
            break
        tokens_in, tokens_out, usd = _ab_usage(raw)
        counters["tokens_in"] += tokens_in
        counters["tokens_out"] += tokens_out
        tokens_in_total += tokens_in
        tokens_out_total += tokens_out
        if _is_num(usd):
            usd_total += float(usd)
            counters["usd"] = float(counters["usd"]) + float(usd)
        else:
            usd_known = False
            counters["usd_known"] = False

        status = str(raw.get("status") or "ok").strip().lower()
        if status in ("budget_exhausted", "budget"):
            record["status"] = "budget_exhausted"
            record["error"] = "provider_budget_exhausted"
            break
        if status in ("error", "failed", "environment_error") or raw.get("error"):
            record["status"] = "environment_error"
            record["error"] = str(raw.get("error") or status)
            break

        diagnosis, actions, rejected = _ab_validate_suggestion(
            raw, engine=engine)
        record["rejected"].extend(rejected)
        if not diagnosis and not actions:
            record["status"] = "rejected" if rejected else "no_suggestion"
            record["error"] = "no_usable_suggestion"
            break
        executed += 1
        record["diagnosis"] = diagnosis
        record["actions"] = list(actions)
        if index >= 1 and doc["facts_hash"] == previous:
            record["invalid_retries"] += 1
        previous = doc["facts_hash"]
        record["rounds"].append({"round": index + 1,
                                 "facts_hash": doc["facts_hash"],
                                 "diagnosis": diagnosis,
                                 "actions": list(actions),
                                 "rejected": list(rejected)})

        # 预算最贵的两项只有 provider 自己知道用量，所以按“调用后结算”判耗尽
        # （与 `llm_gateway` 的 reserve→settle 同构）。
        over_tokens = int(budget.get("max_tokens") or 0) > 0 and \
            (counters["tokens_in"] + counters["tokens_out"]) > \
            int(budget.get("max_tokens") or 0)
        max_usd = budget.get("max_usd")
        over_usd = _is_num(max_usd) and float(counters["usd"]) > float(max_usd)
        if over_tokens or over_usd:
            record["status"] = "budget_exhausted"
            record["error"] = "max_tokens" if over_tokens else "max_usd"
            stop = True
            break

    record["executed_rounds"] = executed
    record["retries"] = max(0, executed - 1)
    record["tokens_in"] = tokens_in_total
    record["tokens_out"] = tokens_out_total
    record["tokens"] = tokens_in_total + tokens_out_total
    record["usd"] = (usd_total if (usd_known and record["calls"]) else None)
    record["usd_known"] = bool(usd_known and record["usd"] is not None)
    record["elapsed_seconds"] = float(clock()) - started
    record["_stop"] = bool(stop and record["status"] == "budget_exhausted")
    return _ab_judge(record, task)


# ---------------------------------------------------------------------- 夹具
class FakeClock:
    """确定性时钟：每调用一次前进 `step` 秒（测试/文档复算用）。"""

    def __init__(self, step: float = 0.01) -> None:
        self.step = float(step)
        self.now = 0.0

    def __call__(self) -> float:
        self.now += self.step
        return self.now


class FakeProvider:
    """离线 fake provider：按 `task_id` 回放脚本，不联网、不需要任何 key。

    脚本值是下面三种之一：

    - `Mapping`：原样当建议返回（可带 `diagnosis` / `actions` / `status` /
      `usage` / `usd`）；缺省的 usage 由构造参数补齐；
    - `Exception` 实例：抛出去（模拟 provider 崩了 → 环境错误）；
    - `callable(payload)`：自己算建议（同样要返回 Mapping 或抛异常）。

    没写进脚本的 task 一律返回 `{"status": "no_suggestion"}`。
    """

    offline = True

    def __init__(self, script: Mapping | None = None, *, name: str = "fake",
                 tokens_in: int = 900, tokens_out: int = 150,
                 usd: float | None = 0.0025) -> None:
        self.name = str(name or "fake")
        self.script = dict(script or {})
        self.tokens_in = int(tokens_in)
        self.tokens_out = int(tokens_out)
        self.usd = usd
        self.calls: list[dict] = []

    def __call__(self, payload: Mapping) -> Any:
        tid = str(payload.get("task_id") or "")
        self.calls.append({"task_id": tid,
                           "round_no": int(payload.get("round_no") or 0)})
        entry = self.script.get(tid)
        if entry is None:
            return {"status": "no_suggestion"}
        if isinstance(entry, BaseException):
            raise entry
        if callable(entry):
            value = entry(payload)
        else:
            value = entry
        if not isinstance(value, Mapping):
            return value
        doc = dict(value)
        usage = dict(doc.get("usage") or {})
        usage.setdefault("tokens_in", self.tokens_in)
        usage.setdefault("tokens_out", self.tokens_out)
        doc["usage"] = usage
        if "usd" not in doc:
            doc["usd"] = self.usd
        return doc


def _obs(**kwargs: Any) -> dict:
    """回归集里一轮观测的简写（键必须是 `Observation` 认的字段）。"""
    return dict(kwargs)


def ab_regression_tasks() -> list[dict]:
    """第 4 周回归集：10 条任务，覆盖 10 个诊断码与 2 个已知规则盲区。

    gold 由**人工规则**给出（不是拿规则臂的输出当答案），两条盲区在
    `tests/test_v3_week4_ab.py` 与 `docs/V3-W4-AB.md` 里逐字段写明：

    - `w4-t08`：`trials == 0` 但快照已经采集（`snapshot_status="ok"`）——
      `no_execution` 的触发条件还要求 `snapshot_status` 也是 `unknown`，
      所以规则臂给 `coverage_unknown`，人工规则给 `no_execution`；
    - `w4-t09`：`fault.cancelled="true"`（执行被取消）——诊断规则不看
      `cancelled`/`budget_stopped`，所以规则臂给 `coverage_unknown`，
      人工规则给 `execution_error`（没跑完不能记成“覆盖未知”）。
    """
    unknown = "unknown"
    return [
        ab_task(
            "w4-t01",
            observation=_obs(trials=0, snapshot_status=unknown),
            gold={"diagnosis": "no_execution",
                  "actions": ["run_epoch", "get_task_facts"],
                  "note": "零执行事实：先跑一次，别猜"}),
        ab_task(
            "w4-t02",
            observation=_obs(program_started="false", trials=1,
                             snapshot_status="ok"),
            gold={"diagnosis": "program_not_started",
                  "actions": ["get_execution_facts", "run_epoch"],
                  "note": "目标没起来：先看执行事实再决定重跑"}),
        ab_task(
            "w4-t03",
            rounds=[
                _obs(program_started="true", input_processed="false",
                     trials=1, snapshot_status="ok"),
                _obs(program_started="true", input_processed="false",
                     trials=2, snapshot_status="ok"),
            ],
            gold={"diagnosis": "input_not_processed",
                  "actions": ["get_task_facts", "propose_seed_spec",
                              "materialize_seeds", "set_dictionary"],
                  "forbid": ["run_epoch"],
                  "note": "输入没被处理：换种子，不要原样重跑（无效重试）"}),
        ab_task(
            "w4-t04",
            rounds=[
                _obs(program_started="true", input_processed="true",
                     checkpoint_reached="false", trials=1,
                     snapshot_status="ok"),
                _obs(program_started="true", input_processed="true",
                     checkpoint_reached="false", trials=2,
                     snapshot_status="ok"),
                _obs(program_started="true", input_processed="true",
                     checkpoint_reached="true", candidates=2, trials=3,
                     snapshot_status="ok"),
            ],
            gold={"diagnosis": "candidate_observed",
                  "actions": ["finish_research", "get_execution_facts"],
                  "forbid": ["run_epoch"],
                  "note": "出现候选：交给独立验证，不再重跑"}),
        ab_task(
            "w4-t05",
            observation=_obs(fault={"error": "true"}, trials=1,
                             snapshot_status="ok"),
            gold={"diagnosis": "execution_error",
                  "actions": ["get_execution_facts", "get_task_facts"],
                  "forbid": ["run_epoch"],
                  "note": "执行报错 ≠ no_repro：先读执行事实"}),
        ab_task(
            "w4-t06",
            rounds=[
                _obs(checkpoint_reached="true",
                     coverage={"delta": 0.5, "metric_kind": "edge"},
                     trials=1, snapshot_status="ok"),
                _obs(checkpoint_reached="true",
                     coverage={"delta": 0.5, "metric_kind": "edge"},
                     trials=2, snapshot_status="ok"),
            ],
            gold={"diagnosis": "progress",
                  "actions": ["run_epoch", "compare_trials"],
                  "note": "同一 build 下有可比增益：继续推进"}),
        ab_task(
            "w4-t07",
            observation=_obs(config={"status": "not_effective",
                                     "planned": "a" * 8,
                                     "loaded": "b" * 8},
                             trials=1, snapshot_status="ok"),
            gold={"diagnosis": "config_not_effective",
                  "actions": ["get_task_facts", "read_source_window"],
                  "forbid": ["run_epoch"],
                  "note": "执行器加载的不是计划配置：本轮结论不算数"}),
        ab_task(
            "w4-t08",
            rounds=[_obs(trials=0, snapshot_status="ok"),
                    _obs(trials=0, snapshot_status="ok")],
            gold={"diagnosis": "no_execution",
                  "actions": ["run_epoch", "get_task_facts"],
                  "note": "规则盲区：快照采到了但一次执行都没有"}),
        ab_task(
            "w4-t09",
            observation=_obs(program_started="true", input_processed="true",
                             fault={"cancelled": "true"}, trials=1,
                             snapshot_status="ok"),
            gold={"diagnosis": "execution_error",
                  "actions": ["get_execution_facts", "finish_research"],
                  "forbid": ["run_epoch"],
                  "note": "规则盲区：执行被取消时不能报 coverage_unknown"}),
        ab_task(
            "w4-t10",
            observation=_obs(checkpoint_reached="true",
                             coverage={"delta": 0.0, "metric_kind": "edge"},
                             trials=2, snapshot_status="ok"),
            gold={"diagnosis": "low_coverage",
                  "actions": ["run_epoch", "propose_seed_spec",
                              "materialize_seeds"],
                  "note": "命中但无可比增益：换种子再试"}),
    ]


# ---------------------------------------------------------------------- 汇总
def _ab_controls(tasks: list, config: Any, budget: Mapping,
                 rules: Mapping) -> dict:
    """两臂共用的四件套：回归集 / 初始配置 / 预算 / 人工规则。"""
    ids = [str(task.get("task_id")) for task in tasks]
    base = {"regression_set": ids, "regression_set_sha256": _ab_digest(
        [{"task_id": task["task_id"], "rounds": task["rounds"],
          "gold": task["gold"]} for task in tasks]),
        "initial_config": {"keys": sorted(_mapping(config)),
                           "sha256": _ab_digest(_mapping(config))},
        "budget": dict(budget), "human_rules": dict(rules)}
    digest = _ab_digest(base)
    doc = dict(base)
    doc["digest"] = digest
    doc["arms"] = {"rules": digest, "model": digest}
    doc["arms_share_controls"] = True
    doc["note"] = ("回归集/初始配置/预算/人工规则只定义一次；两臂摘要相同"
                   "（不同就是框架 bug，不是差异来源）")
    return doc


def _ab_metric_row(metric: str, rules_value: Any, model_value: Any) -> dict:
    lower = metric in AB_LOWER_IS_BETTER
    b_known = _is_num(rules_value)
    t_known = _is_num(model_value)
    reason = ""
    if not b_known:
        reason = "rules_unknown"
    elif not t_known:
        reason = "model_unknown"
    known = bool(b_known and t_known)
    delta = None
    ratio = None
    direction = "unknown"
    if known:
        delta = float(model_value) - float(rules_value)
        if abs(float(rules_value)) > _EPS:
            ratio = float(model_value) / float(rules_value)
        if abs(delta) <= _EPS:
            direction = "same"
        elif (delta < 0) == bool(lower):
            direction = "better"
        else:
            direction = "worse"
    return {"metric": metric, "label": AB_METRIC_LABELS.get(metric, metric),
            "rules": rules_value, "model": model_value, "delta": delta,
            "ratio": ratio, "direction": direction, "known": known,
            "reason": reason}


def _ab_summary(tasks: list, counters: Mapping, budget: Mapping) -> dict:
    """把逐任务记录折成指标表 + 保留类清单 + 分层（稳定性）视图。"""
    records = [{"task_id": task["task_id"], "gold": task["gold"],
                "rules": task["rules"], "model": task["model"]}
               for task in tasks]
    total = len(records)
    answered = {arm: 0 for arm in AB_ARMS}
    correct = {arm: 0 for arm in AB_ARMS}
    adopted = {arm: 0 for arm in AB_ARMS}
    wrong = {arm: 0 for arm in AB_ARMS}
    retries = {arm: 0 for arm in AB_ARMS}
    invalid = {arm: 0 for arm in AB_ARMS}
    elapsed = {arm: 0.0 for arm in AB_ARMS}
    calls = {"rules": 0, "model": int(counters.get("calls") or 0)}
    tokens = {"rules": 0,
              "model": int(counters.get("tokens_in") or 0)
              + int(counters.get("tokens_out") or 0)}
    usd = {"rules": 0.0,
           "model": (float(counters["usd"])
                     if counters.get("usd_known", True) else None)}
    status_counts = {arm: {status: 0 for status in AB_STATUSES}
                     for arm in AB_ARMS}
    retained = {status: [] for status in AB_RETAINED}
    per_arm = {arm: [] for arm in AB_ARMS}
    for item in records:
        for arm in AB_ARMS:
            record = _mapping(item.get(arm))
            status = str(record.get("status") or "ok")
            status_counts[arm][status] = status_counts[arm].get(status, 0) + 1
            if status in retained:
                retained[status].append(item["task_id"])
            if status == "ok":
                answered[arm] += 1
                if record.get("correct") is True:
                    correct[arm] += 1
                adopted[arm] += int(record.get("adopted") or 0)
                wrong[arm] += int(record.get("wrong_adoption") or 0)
            retries[arm] += int(record.get("retries") or 0)
            invalid[arm] += int(record.get("invalid_retries") or 0)
            elapsed[arm] += float(record.get("elapsed_seconds") or 0.0)
            per_arm[arm].append({"task_id": item["task_id"], "status": status,
                                 "correct": record.get("correct"),
                                 "diagnosis": record.get("diagnosis"),
                                 "gold": item["gold"].get("diagnosis"),
                                 "adopted": int(record.get("adopted") or 0),
                                 "wrong_adoption": int(
                                     record.get("wrong_adoption") or 0),
                                 "wrong_reasons": list(
                                     record.get("wrong_reasons") or ()),
                                 "rejected": list(record.get("rejected") or ()),
                                 "error": str(record.get("error") or "")})

    metrics = [
        _ab_metric_row("correct_diagnoses", correct["rules"], correct["model"]),
        _ab_metric_row("invalid_retries", invalid["rules"], invalid["model"]),
        _ab_metric_row("elapsed_seconds", round(elapsed["rules"], 6),
                       round(elapsed["model"], 6)),
        _ab_metric_row("model_calls", calls["rules"], calls["model"]),
        _ab_metric_row("model_tokens", tokens["rules"], tokens["model"]),
        _ab_metric_row("model_usd", usd["rules"], usd["model"]),
        _ab_metric_row("wrong_adoptions", wrong["rules"], wrong["model"]),
    ]

    strata = {}
    for name, predicate in (("even", lambda index: index % 2 == 0),
                            ("odd", lambda index: index % 2 == 1)):
        picked = [item for index, item in enumerate(records)
                  if predicate(index)]
        row = {"tasks": [item["task_id"] for item in picked],
               "tasks_total": len(picked),
               "rules_correct": 0, "model_correct": 0,
               "rules_answered": 0, "model_answered": 0}
        for item in picked:
            for arm in AB_ARMS:
                record = _mapping(item.get(arm))
                if record.get("status") != "ok":
                    continue
                row[f"{arm}_answered"] += 1
                if record.get("correct") is True:
                    row[f"{arm}_correct"] += 1
        row["gain"] = row["model_correct"] - row["rules_correct"]
        strata[name] = row

    return {
        "tasks_total": total,
        "answered": answered,
        "answered_ratio": {arm: (round(answered[arm] / total, 6) if total
                                else 0.0) for arm in AB_ARMS},
        "correct": correct,
        "accuracy": {arm: (round(correct[arm] / answered[arm], 6)
                           if answered[arm] else None) for arm in AB_ARMS},
        # “正确诊断数 / 总任务”的显式形状：答得少不粉饰成覆盖高
        "correct_over_total": {arm: {"correct": correct[arm],
                                     "total": total,
                                     "ratio": (round(correct[arm] / total, 6)
                                               if total else None)}
                               for arm in AB_ARMS},
        "adopted": adopted,
        "wrong_adoptions": wrong,
        "retries": retries,
        "invalid_retries": invalid,
        "elapsed_seconds": {arm: round(elapsed[arm], 6) for arm in AB_ARMS},
        "cost": {"calls": calls, "tokens": tokens, "usd": usd,
                 "usd_known": bool(counters.get("usd_known", True))},
        "status_counts": status_counts,
        "retained": retained,
        "strata": strata,
        "metrics": metrics,
        "per_task": per_arm,
        "budget": dict(budget),
    }


def _ab_gate(tasks: list, summary: Mapping, rules: Mapping, *,
             provider=None, engine_error: str = "",
             provider_kind: str = "offline") -> dict:
    """建议门禁：默认规则还是默认模型建议 + 为什么（自动应用恒为 False）。"""
    total = int(summary.get("tasks_total") or 0)
    checks: list[dict] = []
    reasons: list[str] = []

    def _check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            reasons.append(name)

    model_wrong = int((summary.get("wrong_adoptions") or {}).get("model") or 0)
    rules_wrong = int((summary.get("wrong_adoptions") or {}).get("rules") or 0)
    require_no_wrong = bool(rules.get("require_no_wrong_adoption", True))
    _check("no_model_wrong_adoption",
           (model_wrong == 0) if require_no_wrong else True,
           f"model={model_wrong} rules={rules_wrong}")

    min_ratio = float(rules.get("min_answered_ratio") or 0.0)
    answered = int((summary.get("answered") or {}).get("model") or 0)
    ratio = (answered / total) if total else 0.0
    _check("answered_coverage", ratio >= min_ratio,
           f"model={answered}/{total}={ratio:.3f} min={min_ratio:.3f}")

    regressions = []
    for item in summary.get("per_task", {}).get("model", []) or ():
        rules_row = next((row for row in
                          summary.get("per_task", {}).get("rules", []) or ()
                          if row.get("task_id") == item.get("task_id")), {})
        if item.get("status") != "ok":
            continue
        if rules_row.get("correct") is True and item.get("correct") is False:
            regressions.append(str(item.get("task_id")))
    _check("no_task_regression", not regressions,
           f"rules 对而 model 错的任务={regressions}")

    strata = _mapping(summary.get("strata"))
    gains = {name: int(_mapping(row).get("gain") or 0)
             for name, row in strata.items()}
    stable = bool(gains) and all(gain > 0 for gain in gains.values())
    require_stable = bool(rules.get("require_stable_gain", True))
    _check("stable_gain", stable if require_stable else True,
           "分层增益=" + "、".join(f"{name}:{gain}"
                                   for name, gain in sorted(gains.items())))

    if provider_kind == "real":
        real_ok = provider is not None \
            and getattr(provider, "real_model", False) is True \
            and getattr(provider, "read_only", False) is True \
            and getattr(provider, "offline", True) is False
        _check("read_only_real_provider", real_ok,
               "provider.real_model=True + read_only=True + offline=False"
               if real_ok else
               f"provider={type(provider).__name__} 未声明真实只读")
    elif provider_kind == "simulated":
        simulated_ok = provider is not None \
            and getattr(provider, "read_only", False) is True \
            and getattr(provider, "offline", True) is False \
            and _ab_is_simulated_provider(provider)
        _check("read_only_simulated_provider", simulated_ok,
               "provider.result_source=simulated + read_only=True + offline=False"
               if simulated_ok else
               f"provider={type(provider).__name__} 未声明模拟来源")
    else:
        offline_ok = provider is not None and \
            getattr(provider, "offline", False) is True
        _check("offline_provider", offline_ok,
               "provider.offline=True（禁止真实 key）" if offline_ok
               else f"provider={type(provider).__name__} 未声明 offline")
    _check("engine_available", not engine_error,
           engine_error or "规则引擎可导入")

    gate_ok = all(check["ok"] for check in checks)
    default_arm = "model" if gate_ok else "rules"

    proposal_gate: dict = {"status": "unavailable", "applied": False,
                           "note": "ProposalGate 不可导入"}
    try:
        from .handoff import ProposalGate
        decision = ProposalGate().admit(scope="engineering",
                                       action="model_suggestion",
                                       params={"default_arm": default_arm})
        proposal_gate = dict(decision.to_dict())
    except Exception as exc:              # noqa: BLE001 - 拿不到就如实记不可用
        proposal_gate = {"status": "unavailable", "applied": False,
                         "note": f"{type(exc).__name__}: {exc}"}

    auto_apply = False
    blocked_rules = []
    if bool(rules.get("allow_auto_apply")):
        blocked_rules.append("human_rule:allow_auto_apply=true 被框架拒绝")
    if not bool(proposal_gate.get("applied")):
        blocked_rules.append("proposal_gate:advisory")

    return {
        "schema": AB_GATE_SCHEMA, "schema_version": AB_SCHEMA_VERSION,
        "default_arm": default_arm,
        "default_arm_label": AB_ARM_LABELS[default_arm],
        "model_advisory_allowed": bool(default_arm == "model"),
        "auto_apply": auto_apply,
        "auto_apply_blockers": blocked_rules,
        "reasons": reasons,
        "checks": checks,
        "human_rules": dict(rules),
        "proposal_gate": proposal_gate,
        "decided_on": [str(task.get("task_id")) for task in tasks],
        "note": AB_GATE_NOTE,
    }


def run_ab(*, tasks: Iterable[Mapping], provider=None, config: Mapping | None = None,
           budget: Mapping | None = None, human_rules: Mapping | None = None,
           label: str = "", clock: Any = None,
           provider_kind: str = "offline") -> dict:
    """跑一次离线 A/B：A=现有规则，B=模型只读建议，输出指标 + 门禁。

    两臂吃同一份回归集/配置/预算/人工规则；默认 `provider_kind="offline"` 时
    provider 必须是离线的（`offline=True`），否则整臂记环境错误、门禁直接判
    “默认规则”。`provider_kind="real"` 是真实模型只读 A/B：要求
    `real_model=True` + `read_only=True` + `offline=False`，门禁改查
    `read_only_real_provider`；`provider_kind="simulated"` 是注入 transport 的
    本地替身，要求 `read_only=True` + `offline=False` + `result_source="simulated"`，
    门禁查 `read_only_simulated_provider`；三种口径的 `auto_apply` 都恒为 False。
    """
    if clock is None:
        import time
        clock = time.perf_counter
    if provider_kind not in AB_PROVIDER_KINDS:
        raise ABError(f"unknown provider_kind: {provider_kind!r}"
                      f"（只认 {AB_PROVIDER_KINDS}）")
    budget_doc = dict(AB_DEFAULT_BUDGET)
    budget_doc.update({str(key): value
                       for key, value in _mapping(budget).items()})
    rules_doc = dict(AB_DEFAULT_RULES)
    rules_doc.update({str(key): value
                      for key, value in _mapping(human_rules).items()})

    normalized = _ab_task_list(tasks)
    controls = _ab_controls(normalized, _mapping(config), budget_doc, rules_doc)

    engine: dict = {}
    engine_error = ""
    try:
        engine = _ab_engine()
    except Exception as exc:              # noqa: BLE001 - 引擎缺失是环境错误
        engine_error = f"{type(exc).__name__}: {exc}"

    offline_ok = provider is not None and \
        getattr(provider, "offline", False) is True
    real_ok = provider is not None \
        and getattr(provider, "real_model", False) is True \
        and getattr(provider, "read_only", False) is True \
        and getattr(provider, "offline", True) is False
    simulated_ok = provider is not None \
        and getattr(provider, "read_only", False) is True \
        and getattr(provider, "offline", True) is False \
        and _ab_is_simulated_provider(provider)
    if provider_kind == "real":
        provider_ok = bool(real_ok)
    elif provider_kind == "simulated":
        provider_ok = bool(simulated_ok)
    else:
        provider_ok = bool(offline_ok)
    counters = {"calls": 0, "tokens_in": 0, "tokens_out": 0, "usd": 0.0,
                "usd_known": True}
    records: list[dict] = []
    stop_model = False
    for task in normalized:
        if engine_error:
            rules_record = _ab_blank_record("rules")
            rules_record["status"] = "environment_error"
            rules_record["error"] = engine_error
        else:
            rules_record = _ab_rules_task(task, engine=engine, clock=clock,
                                          budget=budget_doc)
        if engine_error:
            model_record = _ab_blank_record("model")
            model_record["status"] = "environment_error"
            model_record["error"] = engine_error
            model_record["usd"] = None
            model_record["usd_known"] = False
        elif not provider_ok:
            model_record = _ab_blank_record("model")
            model_record["status"] = "environment_error"
            model_record["error"] = (
                "provider_not_read_only_real" if provider_kind == "real"
                else "provider_not_simulated_injected"
                if provider_kind == "simulated" else "provider_not_offline")
            model_record["usd"] = None
            model_record["usd_known"] = False
        elif stop_model:
            model_record = _ab_blank_record("model")
            model_record["status"] = "budget_exhausted"
            model_record["error"] = "global_budget"
            model_record["usd"] = None
            model_record["usd_known"] = False
        else:
            model_record = _ab_model_task(task, provider=provider,
                                          engine=engine, clock=clock,
                                          budget=budget_doc, counters=counters)
            stop_model = bool(model_record.pop("_stop", False))
        for record in (rules_record, model_record):
            record["task_id"] = task["task_id"]
        records.append({"task_id": task["task_id"], "gold": task["gold"],
                        "note": task["note"], "rules": rules_record,
                        "model": model_record})

    summary = _ab_summary(records, counters, budget_doc)
    gate = _ab_gate(normalized, summary, rules_doc, provider=provider,
                    engine_error=engine_error, provider_kind=provider_kind)
    return {
        "schema": AB_SCHEMA, "schema_version": AB_SCHEMA_VERSION,
        "label": str(label or ""),
        "controls": controls,
        "arms": {"rules": {"label": AB_ARM_LABELS["rules"],
                           "kind": "deterministic_rules"},
                 "model": {"label": AB_ARM_LABELS["model"],
                           "kind": "read_only_suggestions",
                           "provider": type(provider).__name__
                           if provider is not None else "",
                           "provider_kind": provider_kind,
                           "offline": bool(offline_ok),
                           "real_model": bool(real_ok),
                           "simulated": bool(simulated_ok),
                           "transport": str(getattr(provider, "transport", "")
                                            or ""),
                           "result_source": str(
                               getattr(provider, "result_source", "") or ""),
                           "read_only": bool(getattr(provider, "read_only",
                                                     False)),
                           "mocked": bool(getattr(provider, "mocked", False))}},
        "tasks": records,
        "summary": summary,
        "gate": gate,
        "verdict": AB_VERDICT,
        "provider_kind": provider_kind,
        "note": AB_NOTE,
    }


def _ab_task_list(tasks: Iterable[Mapping]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for item in tasks or ():
        if not isinstance(item, Mapping):
            raise ABError("回归集里的任务必须是 mapping")
        if "task_id" not in item:
            raise ABError("回归集里的任务缺 task_id")
        task = ab_task(item.get("task_id"), rounds=item.get("rounds"),
                       observation=item.get("observation"),
                       gold=item.get("gold"), note=item.get("note", ""))
        tid = task["task_id"]
        if tid in seen:
            raise ABError(f"回归集里任务重名：{tid}")
        seen.add(tid)
        out.append(task)
    if not out:
        raise ABError("回归集不能为空")
    return out


# ---------------------------------------------------------------------- 渲染
def _ab_show(value: Any) -> str:
    if value is None:
        return "未知"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.6f}".rstrip("0")
        if text.endswith("."):
            text += "0"
        return text
    return str(value)


def render_ab_markdown(doc: Mapping) -> str:
    """把 A/B 文档渲染成 markdown 片段（确定性，无时间戳）。"""
    data = _mapping(doc)
    summary = _mapping(data.get("summary"))
    gate = _mapping(data.get("gate"))
    controls = _mapping(data.get("controls"))
    lines: list[str] = ["## 第 4 周 A/B（现有规则 vs 模型只读建议）", ""]
    if data.get("label"):
        lines.append(f"- 标签：{data['label']}")
    lines.append(f"- 结果判定：`{data.get('verdict') or AB_VERDICT}`"
                 "（只记事实，不产漏洞结论）")
    lines.append(f"- 门禁默认建议源：**{gate.get('default_arm_label')}**"
                 f"（`{gate.get('default_arm')}`）")
    lines.append(f"- 自动应用：{'是' if gate.get('auto_apply') else '否'}"
                 "（模型建议永不自动应用）")
    if gate.get("reasons"):
        lines.append("- 门禁未通过项："
                     + "、".join(f"`{item}`" for item in gate["reasons"]))
    lines.append("")

    lines.append("| 指标 | 现有规则 | 模型只读建议 | Δ | 方向 | 说明 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for row in summary.get("metrics") or ():
        item = _mapping(row)
        reason = str(item.get("reason") or "") or "—"
        lines.append(
            f"| {item.get('label') or item.get('metric')} | "
            f"{_ab_show(item.get('rules'))} | {_ab_show(item.get('model'))} | "
            f"{_ab_show(item.get('delta'))} | "
            f"{_DIRECTION_LABELS.get(str(item.get('direction') or ''), '未知')} | "
            f"{reason} |")
    lines.append("")
    lines.append(f"- 任务数：{_ab_show(summary.get('tasks_total'))}；"
                 f"作答：规则 {_ab_show((summary.get('answered') or {}).get('rules'))}、"
                 f"模型 {_ab_show((summary.get('answered') or {}).get('model'))}")
    correct_over_total = _mapping(summary.get("correct_over_total"))
    lines.append(
        "- 正确诊断数/总任务：规则 "
        f"{_ab_show(_mapping(correct_over_total.get('rules')).get('correct'))}"
        f"/{_ab_show(summary.get('tasks_total'))}；模型 "
        f"{_ab_show(_mapping(correct_over_total.get('model')).get('correct'))}"
        f"/{_ab_show(summary.get('tasks_total'))}")
    lines.append(f"- 采纳：规则 {_ab_show((summary.get('adopted') or {}).get('rules'))}、"
                 f"模型 {_ab_show((summary.get('adopted') or {}).get('model'))}；"
                 f"错误采纳：规则 "
                 f"{_ab_show((summary.get('wrong_adoptions') or {}).get('rules'))}、"
                 f"模型 "
                 f"{_ab_show((summary.get('wrong_adoptions') or {}).get('model'))}")
    lines.append(f"- 无效重试：规则 "
                 f"{_ab_show((summary.get('invalid_retries') or {}).get('rules'))}、"
                 f"模型 "
                 f"{_ab_show((summary.get('invalid_retries') or {}).get('model'))}")
    lines.append("")

    lines.append("### 保留类（不进“答对/答错”分母）")
    lines.append("")
    retained = _mapping(summary.get("retained"))
    labels = {"environment_error": "环境错误", "no_suggestion": "无建议",
              "rejected": "建议被拒", "budget_exhausted": "预算耗尽"}
    empty = True
    for key in AB_RETAINED:
        items = [str(item) for item in retained.get(key) or ()]
        if not items:
            continue
        empty = False
        lines.append(f"- {labels[key]}（{len(items)}）：{'、'.join(items)}")
    if empty:
        lines.append("- （无：本次没有环境错误/无建议/被拒/预算耗尽）")
    lines.append("")

    lines.append("### 分层稳定性（奇数/偶数位任务）")
    lines.append("")
    lines.append("| 分层 | 任务数 | 规则答对 | 模型答对 | 增益 |")
    lines.append("| --- | --- | --- | --- | --- |")
    for name, row in sorted(_mapping(summary.get("strata")).items()):
        item = _mapping(row)
        lines.append(f"| {name} | {_ab_show(item.get('tasks_total'))} | "
                     f"{_ab_show(item.get('rules_correct'))} | "
                     f"{_ab_show(item.get('model_correct'))} | "
                     f"{_ab_show(item.get('gain'))} |")
    lines.append("")

    lines.append("### 门禁检查")
    lines.append("")
    lines.append("| 检查 | 结论 | 说明 |")
    lines.append("| --- | --- | --- |")
    for check in gate.get("checks") or ():
        item = _mapping(check)
        lines.append(f"| {item.get('name')} | "
                     f"{'通过' if item.get('ok') else '未通过'} | "
                     f"{item.get('detail') or '—'} |")
    lines.append("")

    lines.append("### 控制变量")
    lines.append("")
    lines.append(f"- 回归集：{'、'.join(controls.get('regression_set') or [])}")
    lines.append(f"- 回归集 sha256：`{controls.get('regression_set_sha256')}`")
    lines.append(f"- 初始配置 sha256：`"
                 f"{_mapping(controls.get('initial_config')).get('sha256')}`")
    lines.append(f"- 预算：{json.dumps(_mapping(controls.get('budget')), ensure_ascii=False, sort_keys=True)}")
    lines.append(f"- 人工规则：{json.dumps(_mapping(controls.get('human_rules')), ensure_ascii=False, sort_keys=True)}")
    lines.append(f"- 两臂共用控制变量："
                 f"{'是' if controls.get('arms_share_controls') else '否'}")
    lines.append("")
    lines.append(f"> {gate.get('note') or AB_GATE_NOTE}")
    lines.append(f"> {data.get('note') or AB_NOTE}")
    lines.append("")
    return "\n".join(lines)

__all__ = [
    "AB_ARMS",
    "AB_ARM_LABELS",
    "AB_GATE_SCHEMA",
    "AB_METRICS",
    "AB_PROVIDER_KINDS",
    "AB_REAL_PROVIDER_NOTE",
    "AB_RETAINED",
    "AB_SCHEMA",
    "AB_SCHEMA_VERSION",
    "AB_STATUSES",
    "ARMS",
    "ARM_LABELS",
    "COVERAGE_KINDS",
    "METRICS",
    "SCHEMA",
    "SCHEMA_VERSION",
    "TIME_KINDS",
    "ABError",
    "CompareError",
    "FakeClock",
    "FakeProvider",
    "ab_regression_tasks",
    "ab_task",
    "build_compare",
    "compare_arms",
    "merge_metrics",
    "metrics_for_store",
    "metrics_from_events",
    "metrics_from_report",
    "render_ab_markdown",
    "render_markdown",
    "run_ab",
]
