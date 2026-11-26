"""V2 P1：≤8 条可证伪假设（hypothesis set）。

边界：
- 只从 ProgramIndex 的调用点/窗口/锚点生成“可被实验否定”的命题；
- 可选接 D1.5 LLM（`agent.discovery.agents.llm_analyze`），失败严格回退规则；
- 不产出 verdict：本阶段没有执行/验证证据，任何“确认/可利用”结论都属于 P3；
- 硬上限 8 条：假设集是预算单位，不是候选清单。

字段契约：
  id / statement / falsifiable_by / evidence_gap / cost / confidence / source
（evidence_gap 为缺失证据列表，cost 为 {level, execs, seconds}）
"""
from __future__ import annotations

import json
from pathlib import Path

from ..discovery import agents
from .program import ProgramError, ProgramIndex

SCHEMA = "vulnmap.hypothesis.v1"
MAX_HYPOTHESES = 8
WINDOW_LINES = 30
WINDOW_STORE_LIMIT = 2000
LLM_SITE_LIMIT = 4

REQUIRED_FIELDS = ("id", "statement", "falsifiable_by", "evidence_gap",
                   "cost", "confidence", "source")
COST_LEVELS = ("low", "medium", "high")
VERDICT_KEYS = {"verdict", "verdicts", "confirmed", "exploitable",
                "is_vulnerable", "severity", "conclusion"}
VERDICT_TOKENS = ("verdict", "confirmed", "已确认", "确认漏洞", "确认缺陷",
                  "exploitable", "可利用", "漏洞成立")

CATEGORY_ZH = {"copy": "拷贝/写越界", "format": "格式化/截断", "input": "输入读取边界",
               "alloc": "分配-使用长度不一致"}


class HypothesisError(ValueError):
    """假设集契约错误（超上限/字段缺失/夹带 verdict）。"""


# ---------------------------------------------------------------- 工具
def _text_of(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def contains_verdict(text: str) -> bool:
    low = (text or "").lower()
    return any(token in low for token in VERDICT_TOKENS)


def _window(root: Path | None, rel: str, line: int) -> str:
    if not root or not rel:
        return ""
    path = Path(root) / rel
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    idx = max(0, int(line) - 1)
    start = max(0, idx - WINDOW_LINES // 2)
    return "\n".join(lines[start:start + WINDOW_LINES])[:WINDOW_STORE_LIMIT]


def _cost(category: str, reachable: bool, controlled: bool) -> dict:
    base = {"copy": 200, "format": 200, "input": 400, "alloc": 600}.get(category, 600)
    if not reachable:
        base *= 3
    if not controlled:
        base *= 2
    level = "low" if base <= 400 else ("medium" if base <= 1200 else "high")
    return {"level": level, "execs": int(base), "seconds": max(15, int(base) // 20)}


def _confidence(reachable: bool, controlled: bool, category: str) -> float:
    value = 0.30
    if reachable:
        value += 0.25
    if controlled:
        value += 0.20
    if category in ("copy", "format"):
        value += 0.05
    return round(min(0.85, value), 2)


def _probe(category: str, callee: str, function: str) -> str:
    if category == "copy":
        return (f"构造长度字段大于目标缓冲容量的样例（如 0xFFFF），"
                f"让执行流走到 {function} 的 {callee}")
    if category == "format":
        return (f"构造超长/含格式符的字段，让 {function} 的 {callee} 输出长度超过输出缓冲")
    if category == "input":
        return (f"构造短读与超大长度并存的样例，让 {function} 的 {callee} 返回值与后续解析不一致")
    return (f"构造分配长度与后续写入长度不一致的样例，让 {function} 的 {callee} 进入分配-使用路径")


def _statement_for_site(site: dict) -> str:
    category = str(site.get("category") or "")
    callee = str(site.get("callee") or "?")
    function = str(site.get("function") or "?")
    file_ = str(site.get("file") or "")
    line = int(site.get("line") or 0)
    args = str(site.get("args") or "")[:120]
    kind = CATEGORY_ZH.get(category, "危险调用")
    reach = "近似调用图显示从 main 可达" if site.get("reachable") else "近似调用图尚未证明可达"
    return (f"{kind}假设：{file_}:{line} 的 {function} 调用 {callee}({args}) 时，"
            f"长度/边界参数可能由输入决定；若输入使该参数越出目标对象边界，则出现越界访问，"
            f"否则该假设被否定（{reach}）。")


def _falsifiable_by_for_site(site: dict) -> str:
    category = str(site.get("category") or "")
    callee = str(site.get("callee") or "?")
    function = str(site.get("function") or "?")
    probe = _probe(category, callee, function)
    return (f"{probe}；在 ASAN+调试构建下运行，检查是否出现 heap/stack-buffer-overflow "
            f"且崩溃栈含 {function}。无 ASAN 报告或崩溃栈不含该函数即否定该假设。")


def _gaps_for_site(site: dict) -> list[str]:
    gaps: list[str] = []
    if site.get("reachable"):
        gaps.append("可达性只有近似调用图（BFS）支持，缺少动态覆盖证据")
    else:
        gaps.append("近似调用图未从 main 到达该函数，缺少可达性证据")
    if not site.get("controlled"):
        gaps.append("实参未含输入变量（静态近似），缺少输入到该参数的数据流证据")
    gaps.append("调用点覆盖率 covered=0：尚未被 fuzz 命中，无法区分‘不可达’与‘未触发’")
    gaps.append("无 fix 端/行为差分对照：单端崩溃最多到 CANDIDATE（P3 才接入独立验证）")
    return gaps


def _record_site(site: dict, index_no: int, task_id: str, benchmark: str,
                 root: Path | None, window: str) -> dict:
    category = str(site.get("category") or "")
    return {
        "schema": SCHEMA,
        "id": f"H{index_no}",
        "task_id": task_id,
        "benchmark": benchmark,
        "statement": _statement_for_site(site),
        "falsifiable_by": _falsifiable_by_for_site(site),
        "evidence_gap": _gaps_for_site(site),
        "cost": _cost(category, bool(site.get("reachable")),
                      bool(site.get("controlled"))),
        "confidence": _confidence(bool(site.get("reachable")),
                                  bool(site.get("controlled")), category),
        "source": "rule:call_site",
        "site_id": site.get("id", ""),
        "function": site.get("function", "?"),
        "file": site.get("file", ""),
        "line": int(site.get("line") or 0),
        "category": category,
        "callee": site.get("callee", ""),
        "reachable": bool(site.get("reachable")),
        "controlled": bool(site.get("controlled")),
        "citations": ([f"{site.get('file')}:{int(site.get('line') or 0)}"]
                      if site.get("file") else []),
        "window": window,
        "llm": False,
        "llm_status": "disabled",
    }


def _record_anchor(anchor: dict, index_no: int, task_id: str) -> dict:
    file_ = str(anchor.get("file") or "")
    line = int(anchor.get("line") or 0)
    symbol = str(anchor.get("symbol") or "")
    repo = str(anchor.get("repo") or "")
    commit = str(anchor.get("commit") or "")
    verified = bool(anchor.get("verified"))
    location = f"{repo}@{commit} 的 {file_}:{line}" if repo and commit else f"{file_}:{line}"
    statement = (f"静态锚点假设：{location}"
                 f"{f'（{symbol}）' if symbol else ''} 处的服务端处理分支直接由请求参数驱动；"
                 "若该分支缺少授权/边界校验，则对定向请求的响应（状态码/连接状态）"
                 "应与受保护分支不同，否则该假设被否定。")
    falsifiable_by = (
        "依据锚点分支构造定向请求（对 %s 的输入做超长/越权参数变形），"
        "记录响应状态码与连接是否关闭；再与补丁版或受保护分支对照。"
        "两端响应无差异即否定该假设。" % (symbol or file_ or "该分支"))
    gaps = ["workspace 无源码树：锚点行号必须按 repo+commit 在上游复算"]
    if not verified:
        gaps.append("锚点未在本仓验证（源码/镜像缺失），存在行号漂移风险")
    gaps.append("缺少补丁版/行为差分基线：单端观测不能确认结论（P3 才接入）")
    gaps.append("锚点未给出请求参数名与判定口径：probe 需按上游源码复核")
    return {
        "schema": SCHEMA,
        "id": f"H{index_no}",
        "task_id": task_id,
        "benchmark": "vulngym",
        "statement": statement,
        "falsifiable_by": falsifiable_by,
        "evidence_gap": gaps,
        "cost": {"level": "medium", "execs": 20, "seconds": 120},
        "confidence": 0.45 if verified else 0.25,
        "source": "rule:anchor",
        "site_id": "",
        "function": symbol,
        "file": file_,
        "line": line,
        "category": "service_behavior",
        "callee": "",
        "reachable": False,
        "controlled": bool(symbol),
        # 锚点行的行号来自 SOURCE.md，不是本仓可验证的事实：不给 citations
        "citations": [],
        "window": "",
        "llm": False,
        "llm_status": "disabled",
        "anchor_kind": anchor.get("kind", ""),
        "repo": repo,
        "commit": commit,
    }


def _record_entry(entry: dict, index_no: int, task_id: str, benchmark: str) -> dict:
    file_ = str(entry.get("file") or "")
    line = int(entry.get("line") or 0)
    name = str(entry.get("name") or "?")
    statement = (f"入口假设：从 {file_}:{line} 的入口 {name} 出发的解析路径中存在危险 sink，"
                 "但当前有界静态扫描没有识别到；若扩大扫描/动态 fuzz 后发现可达 sink，"
                 "则假设成立，否则否定。")
    falsifiable_by = ("对该入口喂入格式种子并扩大静态扫描范围（全量 D1 + 覆盖率）；"
                      "既无 ASAN 报告也没有新的 sink 命中即否定该假设。")
    return {
        "schema": SCHEMA,
        "id": f"H{index_no}",
        "task_id": task_id,
        "benchmark": benchmark,
        "statement": statement,
        "falsifiable_by": falsifiable_by,
        "evidence_gap": ["未识别到危险调用点（扫描子集内 0 命中）",
                         "入口到 sink 的调用链未建立",
                         "无 fix 端/行为差分对照：单端结论不可确认（P3 才接入）"],
        "cost": {"level": "high", "execs": 2000, "seconds": 300},
        "confidence": 0.10,
        "source": "rule:entry_point",
        "site_id": "",
        "function": name,
        "file": file_,
        "line": line,
        "category": "entry_point",
        "callee": "",
        "reachable": True,
        "controlled": False,
        "citations": [f"{file_}:{line}"] if file_ else [],
        "window": "",
        "llm": False,
        "llm_status": "disabled",
    }


# ---------------------------------------------------------------- LLM（可选）
def _llm_statement(site: dict, root: Path | None) -> dict | None:
    """调 D1.5 LLM 分析；返回 {statement, confidence, citations} 或 None。

    只接受能解析的 citations；夹带 verdict 的文本直接丢弃并回退规则。
    """
    if root is None or not Path(root).is_dir():
        return None
    try:
        result = agents.llm_analyze(site, Path(root))
    except Exception:  # noqa: BLE001 - 网络/解析失败一律回退
        return None
    if not isinstance(result, dict):
        return None
    statement = _text_of(result.get("hypothesis"))
    if not statement or contains_verdict(statement):
        return None
    try:
        confidence = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = 0.5
    return {"statement": statement, "confidence": confidence,
            "citations": list(result.get("citations") or []),
            "model": agents.llm_model() or "unknown"}


# ---------------------------------------------------------------- 入口
def resolve_llm_mode(use_llm: bool | None) -> tuple[bool, str]:
    """把三态参数解析成 (effective_use_llm, mode)。

    - ``None``（默认）= ``auto``：与 D1.5/Discovery 默认一致——只要没有显式禁用
      （``DISCOVERY_LLM_DISABLED``/``VULNMAP_DISABLE_LLM``）就先尝试 LLM；没配置
      key 时 `agents.llm_analyze` 返回 None，明确回退规则（``llm_status=no_key``）。
    - ``True`` = ``on``：调用方显式要求 LLM（仍然要求真的配置了 key）。
    - ``False`` = ``off``：显式关闭，一次模型调用都不发。
    """
    if use_llm is None:
        return (not agents.llm_disabled()), "auto"
    return bool(use_llm), ("on" if use_llm else "off")


def propose(index: ProgramIndex | dict, *, root: str | Path | None = None,
            use_llm: bool | None = None,
            max_count: int = MAX_HYPOTHESES) -> list[dict]:
    """从 ProgramIndex 生成假设集。

    默认（``use_llm=None``）优先 LLM、无配置严格回退规则；``use_llm=False`` 是
    显式离线模式（F2）。
    """
    # 让 auto 的三态语义在所有入口一致（CLI / API / 直接调用 propose）
    use_llm, _mode = resolve_llm_mode(use_llm)
    if isinstance(index, dict):
        index = ProgramIndex.from_dict(index)
    if not isinstance(index, ProgramIndex):
        raise ProgramError("propose expects ProgramIndex or its dict")
    max_count = max(1, min(int(max_count), MAX_HYPOTHESES))
    source_root = Path(root) if root else (Path(index.root) if index.root else None)
    if source_root is not None and not source_root.exists():
        source_root = None

    # 锚点文件优先：task.json component / SOURCE.md 指向的文件排在同分调用点之前
    anchored: set[str] = set()
    for anchor in index.anchors:
        for name in ("resolved_file", "file"):
            value = str(anchor.get(name) or "")
            if value:
                anchored.add(value)
                anchored.add(Path(value).name)

    def priority(site: dict) -> tuple:
        rel = str(site.get("file") or "")
        is_anchor = 0 if (rel in anchored or Path(rel).name in anchored) else 1
        return (is_anchor, -int(site.get("score") or 0), rel,
                int(site.get("line") or 0), str(site.get("callee") or ""))

    sites: list[dict] = []
    seen: set[tuple] = set()
    for site in sorted(index.call_sites, key=priority):
        # 同一 (file, line, callee) 才是同一个调用点；不同行是不同的命题，
        # 不按函数折叠——否则大函数里的多个 sink 会互相吞掉预算。
        key = (str(site.get("file") or ""), int(site.get("line") or 0),
               str(site.get("callee") or ""))
        if key in seen:
            continue
        seen.add(key)
        sites.append(site)
        if len(sites) >= max_count:
            break

    records: list[dict] = []
    llm_used = False
    llm_attempts = 0
    for site in sites:
        window = _window(source_root, str(site.get("file") or ""),
                         int(site.get("line") or 0))
        rec = _record_site(site, len(records) + 1, index.task_id,
                           index.benchmark, source_root, window)
        if use_llm and llm_attempts < LLM_SITE_LIMIT:
            llm_attempts += 1
            got = _llm_statement(site, source_root)
            if got:
                rec["statement"] = got["statement"]
                rec["confidence"] = got["confidence"]
                rec["citations"] = got["citations"]
                rec["source"] = f"llm:{got['model']}"
                rec["llm"] = True
                rec["llm_status"] = "ok"
                llm_used = True
        records.append(rec)

    if not records and index.anchors:
        for anchor in index.anchors[:max_count]:
            records.append(_record_anchor(anchor, len(records) + 1, index.task_id))

    if not records and index.entry_points:
        for entry in index.entry_points[:min(2, max_count)]:
            records.append(_record_entry(entry, len(records) + 1, index.task_id,
                                         index.benchmark))

    if not use_llm:
        # 显式关闭（--no-llm / use_llm=False）：如实记 disabled，不装成 no_key，
        # 也不假装尝试过（auto 模式在无 key 时走上面的 no_key 分支）
        for rec in records:
            rec["llm_status"] = "disabled"
    elif not llm_used:
        for rec in records:
            if not rec.get("llm"):
                rec["llm_status"] = ("no_key" if agents.llm_status() == "no_key"
                                     else agents.llm_status())
    validate(records)
    return records


def validate(items: list[dict], *, max_count: int = MAX_HYPOTHESES) -> None:
    if not isinstance(items, list):
        raise HypothesisError("hypotheses must be a list")
    if len(items) > max_count:
        raise HypothesisError(f"hypothesis budget exceeded: {len(items)} > {max_count}")
    ids: set[str] = set()
    for rec in items:
        if not isinstance(rec, dict):
            raise HypothesisError("hypothesis must be a dict")
        for name in REQUIRED_FIELDS:
            if name not in rec:
                raise HypothesisError(f"hypothesis missing field: {name}")
        if not isinstance(rec["id"], str) or not rec["id"].startswith("H"):
            raise HypothesisError(f"hypothesis id must look like H1: {rec['id']!r}")
        if rec["id"] in ids:
            raise HypothesisError(f"duplicate hypothesis id: {rec['id']}")
        ids.add(rec["id"])
        for name in ("statement", "falsifiable_by", "source"):
            if not isinstance(rec[name], str) or not rec[name].strip():
                raise HypothesisError(f"{rec['id']}: {name} must be non-empty text")
        gaps = rec["evidence_gap"]
        if not isinstance(gaps, list) or not gaps or not all(
                isinstance(g, str) and g.strip() for g in gaps):
            raise HypothesisError(f"{rec['id']}: evidence_gap must be a non-empty text list")
        cost = rec["cost"]
        if not isinstance(cost, dict):
            raise HypothesisError(f"{rec['id']}: cost must be a dict")
        if cost.get("level") not in COST_LEVELS:
            raise HypothesisError(f"{rec['id']}: cost.level must be one of {COST_LEVELS}")
        for name in ("execs", "seconds"):
            value = cost.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise HypothesisError(f"{rec['id']}: cost.{name} must be a positive int")
        confidence = rec["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise HypothesisError(f"{rec['id']}: confidence must be a number")
        if not 0.0 <= float(confidence) <= 1.0:
            raise HypothesisError(f"{rec['id']}: confidence must be within [0,1]")
        for key in _keys(rec):
            if key in VERDICT_KEYS:
                raise HypothesisError(
                    f"{rec['id']}: hypotheses stage must not carry verdict field {key!r}")
        if contains_verdict(str(rec["statement"])):
            raise HypothesisError(
                f"{rec['id']}: statement contains a verdict claim; hypotheses stay falsifiable")


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


def dump(items: list[dict]) -> str:
    return json.dumps(items, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- 编排（CLI 用）
def run_hypotheses(task_id: str, store, bus, *, use_llm: bool | None = None,
                   max_count: int = MAX_HYPOTHESES) -> dict:
    """UNDERSTANDING → HYPOTHESES：读已存 ProgramIndex → 生成 → 存 → 发事件。

    ``use_llm=None``（默认，F2）优先 LLM、无配置回退规则；``use_llm=False``
    是 CLI ``--no-llm`` 的显式离线口径。事件里如实记录 ``llm_mode``。
    """
    use_llm, llm_mode = resolve_llm_mode(use_llm)
    task = store.get_task(task_id)
    state = task["state"]
    if state not in ("UNDERSTANDING", "HYPOTHESES"):
        raise HypothesisError(
            f"hypotheses requires UNDERSTANDING/HYPOTHESES, got {state}")
    row = store.get_program_index(task_id)
    if row is None:
        raise HypothesisError(f"no ProgramIndex for {task_id}; run `understand` first")
    index = ProgramIndex.from_dict(row["doc"])

    items = propose(index, root=index.root, use_llm=use_llm, max_count=max_count)
    if not items:
        # 没有调用点/锚点/入口就没有可证伪命题：宁可停在 UNDERSTANDING，也不装进空假设集
        raise HypothesisError(
            f"no static anchors or call sites for {task_id}: cannot propose "
            "falsifiable hypotheses; provide workspace/SOURCE.md or a source tree")
    validate(items)
    transitions = []
    if state == "UNDERSTANDING":
        store.transition(task_id, "HYPOTHESES", reason=f"hypotheses proposed: {len(items)}")
        transitions.append("HYPOTHESES")
    store.save_hypotheses(task_id, items)
    seq = bus.emit(task_id, "hypothesis.proposed", stage="HYPOTHESES", payload={
        "count": len(items),
        "max": MAX_HYPOTHESES,
        "llm": use_llm,
        "llm_mode": llm_mode,
        "llm_status": agents.llm_status() if use_llm else "disabled",
        "hypotheses": [{"id": h["id"], "statement": h["statement"][:200],
                        "source": h["source"], "confidence": h["confidence"],
                        "cost": h["cost"].get("level"), "site_id": h.get("site_id", "")}
                       for h in items],
    })
    return {"task_id": task_id, "state": store.get_task(task_id)["state"],
            "count": len(items), "hypotheses": items, "event_seq": seq,
            "llm": use_llm, "llm_mode": llm_mode,
            "llm_status": agents.llm_status() if use_llm else "disabled",
            "transitioned": bool(transitions)}


def run_understand(task_id: str, store, bus, *, max_sources: int | None = None,
                   max_call_sites: int | None = None,
                   unpack_root: str | None = None) -> dict:
    """READY → UNDERSTANDING：构建 ProgramIndex → 存 → 发 program.indexed。"""
    task = store.get_task(task_id)
    if task["state"] != "READY":
        raise ProgramError(f"understand requires READY, got {task['state']}")
    store.transition(task_id, "UNDERSTANDING", reason="program understanding started")
    try:
        index = ProgramIndex.build(
            task, max_sources=max_sources,
            max_call_sites=(max_call_sites or 240),
            unpack_root=unpack_root or None)
    except Exception as exc:
        store.transition(task_id, "FAILED",
                         reason=f"program index failed: {type(exc).__name__}")
        raise
    row = store.save_program_index(task_id, index)
    seq = bus.emit(task_id, "program.indexed", stage="UNDERSTANDING", payload={
        "sha256": row["sha256"],
        "benchmark": index.benchmark,
        "root": index.root,
        "entry_points": len(index.entry_points),
        "functions": len(index.functions),
        "call_sites": len(index.call_sites),
        "source_count": index.source_count,
        "formats": index.formats,
        "coverage": index.coverage,
        "anchors": len(index.anchors),
    })
    return {"task_id": task_id, "state": store.get_task(task_id)["state"],
            "sha256": row["sha256"], "index": index.to_dict(),
            "summary": {k: v for k, v in row.items() if k != "doc"},
            "event_seq": seq}
