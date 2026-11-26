"""V2 P3.9 static 执行器：ProgramIndex + 假设集的**只读静态复核**。

定位：static 是复核，不是判定。它只回答两件事：

1. 程序事实够不够——源码树/入口/危险调用点/上游锚点能不能复算；
2. 每条假设在静态事实里有没有落点——能不能定位到文件、函数、危险调用或
   `SOURCE.md` 锚点（repo+commit+file+line）。

产物只有两种结尾（都在状态机里，都不是结论）：

- `no_repro`      —— 复核完成，静态事实没有支撑任何一条假设，且没有证据缺口；
- `needs_evidence`—— 有证据缺口（无源码树、锚点未复算、无危险调用点、假设文本
                     定位不到落点），或静态事实支撑了某条假设（支撑 ≠ 成立：
                     静态找到落点只说明“值得去跑动态”，仍然要动态证据）。

硬约束：

- **不产 Candidate**：静态复核没有输入/没有崩溃证据，把它写成候选就是伪造执行；
- **不写结论字段**：`verdict/confirmed/exploitable/...` 等词表一律不出现
  （[hypotheses.VERDICT_KEYS](../hypotheses.py) 是唯一口径）；
- **只读**：不构建、不执行、不联网、不写 workspace；产物只是一份内存文档，
  由编排层落成 `static_review` 证据（内容寻址，可复算）；
- **失败要炸**：plan/index 契约不符（缺字段、benchmark 不一致）抛
  `StaticExecError`，由编排层落 FAILED + `exec_error`，绝不把“没法复核”
  降级成 `no_repro`。

契约字段（`review()` 的返回）：
  task_id / benchmark / outcome / review / gaps / requests
`review` 子文档字段：
  schema / plan_sha256 / index_sha256 / program / anchors / sites / hypotheses /
  gaps / status / notes / reviewed_at
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

SCHEMA = "vulnmap.static_review.v1"

#: 复核文档里最多列多少个调用点/锚点/假设（证据要可读，不是全量 dump）
MAX_REVIEW_SITES = 12
MAX_REVIEW_ANCHORS = 8
MAX_REVIEW_HYPOTHESES = 8
MAX_MATCHES_PER_HYPOTHESIS = 5

#: 假设文本 → 标识符：只认能落到代码里的名字（长度 >= 3，避免 a/b/i 之类噪声）
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

OUTCOME_NO_REPRO = "no_repro"
OUTCOME_NEEDS_EVIDENCE = "needs_evidence"
OUTCOMES = (OUTCOME_NO_REPRO, OUTCOME_NEEDS_EVIDENCE)


class StaticExecError(RuntimeError):
    """静态复核无法进行（plan/index 契约不符），必须落 FAILED 而不是 no_repro。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _text(value) -> str:
    return str(value or "").strip()


def _tokens(*texts) -> set[str]:
    out: set[str] = set()
    for text in texts:
        out |= {m.group(0).lower() for m in TOKEN.finditer(_text(text))}
    return out


def _bounded(items, limit: int) -> list:
    return list(items or [])[:int(limit)]


# ---------------------------------------------------------------- 视图
def _site_view(site: dict) -> dict:
    """调用点：只保留复核需要的静态事实（不含可达性结论措辞）。"""
    return {
        "id": _text(site.get("id")),
        "file": _text(site.get("file")),
        "line": int(site.get("line") or 0),
        "callee": _text(site.get("callee")),
        "function": _text(site.get("function")),
        "category": _text(site.get("category")),
        "controlled": bool(site.get("controlled")),
        "reachable": bool(site.get("reachable")),
        "score": site.get("score"),
    }


def _anchor_view(anchor: dict) -> dict:
    return {
        "kind": _text(anchor.get("kind")),
        "file": _text(anchor.get("file")),
        "resolved_file": _text(anchor.get("resolved_file")),
        "line": int(anchor.get("line") or 0),
        "symbol": _text(anchor.get("symbol")),
        "repo": _text(anchor.get("repo")),
        "commit": _text(anchor.get("commit")),
        # verified 在这里只表示“workspace 内能复算这一行”，不是漏洞结论
        "verified": bool(anchor.get("verified")),
        "note": _text(anchor.get("note")),
    }


# ---------------------------------------------------------------- 假设落点
def _hypothesis_view(hyp: dict, sites: list[dict], anchors: list[dict]) -> dict:
    """一条假设的静态落点：命中哪些调用点/锚点，还是根本定位不到。"""
    hid = _text(hyp.get("id")) or "H?"
    tokens = _tokens(hyp.get("statement"), hyp.get("falsifiable_by"),
                     hyp.get("evidence_gap"))
    matched_sites: list[str] = []
    matched_anchors: list[str] = []
    for site in sites:
        view = _site_view(site)
        haystack = _tokens(view["callee"], view["function"], view["file"])
        if tokens & haystack:
            matched_sites.append(view["id"])
        if len(matched_sites) >= MAX_MATCHES_PER_HYPOTHESIS:
            break
    for anchor in anchors:
        view = _anchor_view(anchor)
        haystack = _tokens(view["file"], view["resolved_file"], view["symbol"])
        if tokens & haystack:
            matched_anchors.append(
                f"{view['file'] or view['symbol'] or view['kind']}"
                f":{view['line']}")
        if len(matched_anchors) >= MAX_MATCHES_PER_HYPOTHESIS:
            break
    locatable = bool(tokens)
    support = ("static_support" if (matched_sites or matched_anchors)
               else "no_static_support")
    if not locatable:
        note = "假设文本里没有可对到代码的标识符：静态无法定位落点，需要更具体的文件/函数"
    elif support == "static_support":
        note = "静态事实里有落点：这只说明值得跑动态，不构成成立"
    else:
        note = "静态事实里没有落点：该假设在 ProgramIndex 范围内未被支撑"
    return {
        "id": hid,
        "statement": _text(hyp.get("statement")),
        "support": support,
        "locatable": locatable,
        "matched_sites": matched_sites,
        "matched_anchors": matched_anchors,
        "cost": dict(hyp.get("cost") or {}),
        "note": note,
    }


# ---------------------------------------------------------------- 复核
def _program_view(index) -> dict:
    coverage = getattr(index, "coverage", {}) or {}
    return {
        "source_count": int(getattr(index, "source_count", 0) or 0),
        "entry_points": len(list(getattr(index, "entry_points", []) or [])),
        "functions": len(list(getattr(index, "functions", []) or [])),
        "call_sites": len(list(getattr(index, "call_sites", []) or [])),
        "anchors": len(list(getattr(index, "anchors", []) or [])),
        "formats": list(getattr(index, "formats", []) or []),
        "coverage_mode": _text((coverage or {}).get("mode")),
        "coverage_status": _text((coverage or {}).get("status")),
        "truncated_sources": int((coverage or {}).get("truncated_sources") or 0),
        "truncated_sites": int((coverage or {}).get("truncated_sites") or 0),
    }


def _gaps_for(program: dict, hypotheses: list[dict], anchors: list[dict]) -> list[str]:
    """证据缺口：缺了它，静态复核就说不清楚自己在复核什么。"""
    gaps: list[str] = []
    if not hypotheses:
        gaps.append("no_hypotheses")
    if program["source_count"] == 0 and program["anchors"] == 0:
        gaps.append("no_program_facts")
    elif program["source_count"] == 0:
        gaps.append("no_source_tree")
    if program["source_count"] and program["call_sites"] == 0:
        gaps.append("no_call_sites")
    unverified = [a for a in anchors if not a["verified"]]
    if unverified:
        labels = [f"{a['file'] or a['symbol'] or a['kind']}:{a['line']}"
                  for a in unverified[:3]]
        gaps.append("anchor_unverified:" + ",".join(labels))
    for view in hypotheses:
        if not view["locatable"]:
            gaps.append(f"hypothesis_unlocatable:{view['id']}")
        elif view["support"] == "static_support":
            gaps.append(f"static_support_needs_dynamic:{view['id']}")
    # 去重但保序（同一假设可能同时命中多类缺口）
    seen: set[str] = set()
    return [g for g in gaps if not (g in seen or seen.add(g))]


def review(plan: dict, index, hypotheses=()) -> dict:
    """对 ProgramIndex + 假设集做一次静态复核，返回复核文档（不写任何状态）。"""
    if not isinstance(plan, dict):
        raise StaticExecError("static executor needs a plan dict")
    task_id = _text(plan.get("task_id"))
    benchmark = _text(plan.get("benchmark"))
    if not task_id:
        raise StaticExecError("static executor: plan.task_id is required")
    if not benchmark:
        raise StaticExecError("static executor: plan.benchmark is required")
    if index is None:
        raise StaticExecError("static executor: a ProgramIndex is required")
    index_benchmark = _text(getattr(index, "benchmark", ""))
    if index_benchmark and index_benchmark != benchmark:
        raise StaticExecError(
            f"static executor: ProgramIndex benchmark {index_benchmark!r} "
            f"does not match plan benchmark {benchmark!r}")
    index_task = _text(getattr(index, "task_id", ""))
    if index_task and index_task != task_id:
        raise StaticExecError(
            f"static executor: ProgramIndex belongs to {index_task!r}, "
            f"not {task_id!r}")

    hyp_docs = [dict(h) for h in (hypotheses or []) if isinstance(h, dict)]
    sites = list(getattr(index, "call_sites", []) or [])
    anchors_raw = list(getattr(index, "anchors", []) or [])
    anchors = [_anchor_view(a) for a in _bounded(anchors_raw, MAX_REVIEW_ANCHORS)]
    program = _program_view(index)

    views = [_hypothesis_view(h, sites, anchors_raw)
             for h in _bounded(hyp_docs, MAX_REVIEW_HYPOTHESES)]
    gaps = _gaps_for(program, views, anchors)
    status = OUTCOME_NEEDS_EVIDENCE if gaps else OUTCOME_NO_REPRO

    notes = [
        "static 复核只读：不构建、不执行、不联网",
        "支撑（static_support）不等于成立：静态落点只说明该假设值得跑动态取证",
        f"复核范围：程序事实 {program['source_count']} 源文件 / "
        f"{program['call_sites']} 危险调用点 / {program['anchors']} 个锚点",
    ]
    if status == OUTCOME_NO_REPRO:
        notes.append("静态事实未支撑任何假设且无证据缺口：本轮静态复核到 No Repro")
    else:
        notes.append("存在证据缺口或静态支撑：补动态证据前不给负结果之外的结论")

    doc = {
        "schema": SCHEMA,
        "task_id": task_id,
        "benchmark": benchmark,
        "plan_sha256": _text(plan.get("sha256")),
        "index_sha256": _text(getattr(index, "sha256", "")),
        "program": program,
        "anchors": anchors,
        "sites": [_site_view(s) for s in _bounded(sites, MAX_REVIEW_SITES)],
        "hypotheses": views,
        "gaps": gaps,
        "status": status,
        "notes": notes,
        "reviewed_at": now(),
    }
    return {
        "task_id": task_id,
        "benchmark": benchmark,
        "outcome": status,
        "review": doc,
        "gaps": gaps,
        # 静态复核没有执行数：预算账本里记 0（不虚构 execs）
        "requests": 0,
        "review_sha256": _sha256_text(json.dumps(doc, ensure_ascii=False,
                                                 sort_keys=True, default=str)),
    }


def execute(plan: dict, index, hypotheses=(), *, workdir=None,
            **_: object) -> dict:
    """编排层入口：与 fuzz/replay/dynamic 同形（workdir 保留但不使用）。"""
    return review(plan, index, hypotheses)


def dump(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
