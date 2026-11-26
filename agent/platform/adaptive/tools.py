"""V3-005：首批工具（只读 / 输入 / 实验 / 收口），每个 handler 都走同一闸门。

工具表（名称、分组、权限、失效范围见 `REGISTRY.describe()`）：

| 工具 | 组 | 权限 | 变更类别 | 失效范围 |
|---|---|---|---|---|
| get_task_facts          | read       | L0 | none        | — |
| get_execution_facts     | read       | L0 | none        | — |
| read_source_window      | read       | L0 | none        | — |
| propose_seed_spec       | input      | L1 | proposal    | — |
| materialize_seeds       | input      | L1 | corpus      | input_dedup, corpus_members |
| set_dictionary          | input      | L1 | dictionary  | input_dedup |
| run_epoch               | experiment | L1 | execution   | execution_facts, trial_compare, coverage_baseline |
| replay_input            | experiment | L1 | execution   | execution_facts, trial_compare, coverage_baseline |
| compare_trials          | experiment | L0 | none        | — |
| finish_research         | close      | L1 | proposal    | — |

所有参数校验、权限、模式（explore/verify）、预算预留与失效登记都在
`contracts.Registry` 里统一执行；handler 只负责“事实/工件怎么产生”，
并且**只能**返回 `ToolOutcome`（不返回身份、不写裁决）。

口径提醒：
- 读不到就报 `unknown`（例如没有 execution 事件、没有覆盖指标），不填 0；
- 隔离执行由注入的 `ctx.exec_runner` 完成；没绑定 worker 时是**可修正的拒绝**
  （`executor_unavailable`），不是假装跑过；
- `finish_research` 只能记录“结束理由”，不能写 `verified/confirmed`——
  这些字段在 `contracts.RESERVED_PARAMS` 里，带了直接拒绝。
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..budget import usage_from_events
from ..authorization import resolve as resolve_auth
from .contracts import (BUDGET_LIMIT_KEYS, ActionRejected, Binding,
                        DeclaredBudget, Registry, SessionState, ToolContext,
                        ToolOutcome, ToolSpec, UNKNOWN, applied, canonical_json,
                        digest_of, failed, grant_for, noop, now, unknown)
from .snapshot import (CROSS_EXECUTION, Cursor, SnapshotError, tri,
                       TrustedExecutionSnapshot)

#: 本批工具支持的执行方式（与 `executors.EXECUTORS` 同步；
#: tests/test_v3_p2_contracts.py 会对账，避免“schema 里支持、执行器不支持”）
EXEC_KINDS = ("fuzz", "replay", "static", "dynamic")

#: 有界读取/生成的上限（超限是可修正的拒绝，不是静默截断）
MAX_SOURCE_LINES = 120
#: 单文件读取上限：超过就拒绝（不把整份大文件塞进内存/prompt）
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_SEEDS_PER_SPEC = 8
MAX_SEED_SPECS = 32
MAX_DICTIONARY_TOKENS = 256
MAX_TOKEN_BYTES = 64
MAX_PARAM_KEYS = 16

#: 研究模式（探索与独立验证必须分开：T14）
MODE_EXPLORE = "explore"
MODE_VERIFY = "verify"


# ====================================================================== 通用
def _require_store(ctx: ToolContext):
    if ctx.store is None:
        raise ActionRejected("store_unavailable",
                             "工具未绑定任务库（ctx.store 为空）",
                             hint="由控制器在建立会话时注入 PlatformStore")
    return ctx.store


def _require_index(ctx: ToolContext):
    if ctx.index is None:
        raise ActionRejected("no_program_index",
                             "本次会话没有 ProgramIndex（先跑 understand）",
                             hint="没有程序上下文就无法定位源码/调用点")
    return ctx.index


def _require_corpus(ctx: ToolContext):
    if ctx.corpus is None:
        raise ActionRejected("corpus_unavailable",
                             "本次会话没有绑定持久语料（ctx.corpus 为空）",
                             hint="语料由 CorpusStore 提供，先 begin() 再物化")
    return ctx.corpus


def _require_runner(ctx: ToolContext):
    if ctx.exec_runner is None:
        raise ActionRejected(
            "executor_unavailable",
            "本次会话没有绑定执行 worker（ctx.exec_runner 为空）",
            hint="实验动作必须在隔离 worker 上执行；没有 worker 就不假装跑过")
    return ctx.exec_runner


def _session(ctx: ToolContext) -> SessionState:
    return ctx.state()


def _index_doc(index: Any) -> dict:
    if index is None:
        return {}
    if isinstance(index, Mapping):
        return dict(index)
    if hasattr(index, "to_dict"):
        try:
            return dict(index.to_dict())
        except Exception:               # noqa: BLE001 - 索引坏了按“未知”处理
            return {}
    return {}


def _remaining(limits: Mapping, used: Mapping) -> dict:
    out: dict[str, Any] = {}
    for name, key in BUDGET_LIMIT_KEYS.items():
        limit = limits.get(key)
        if limit is None:
            out[name] = UNKNOWN
            continue
        out[name] = float(limit) - float(used.get(name) or 0.0)
    return out


# ====================================================================== 只读
def get_task_facts(ctx: ToolContext, include_evidence: bool = False) -> ToolOutcome:
    """任务级事实：状态、预算、授权口径、假设/候选/证据计数、程序索引摘要。"""
    store = _require_store(ctx)
    task_id = ctx.binding.task_id
    task = store.get_task(task_id)
    events = store.list_events(task_id)
    used = usage_from_events(events)
    limits = dict(task.get("budget") or {})

    index_row = store.get_program_index(task_id)
    index_doc = dict((index_row or {}).get("doc") or {})
    program = {
        "present": tri(bool(index_row)),
        "sha256": index_doc.get("sha256") or UNKNOWN,
        "counts": dict(index_doc.get("counts") or {}) or UNKNOWN,
        "warnings": list(index_doc.get("warnings") or []),
    }
    evidence = UNKNOWN
    if include_evidence:
        evidence = [
            {"sha256": row["sha256"], "kind": row["kind"], "size": row["size"]}
            for row in store.list_evidence(task_id)
        ]
    payload = {
        "task": {
            "task_id": task["task_id"],
            "benchmark": task["benchmark"],
            "target": task["target"],
            "mode": task["mode"],
            "state": task["state"],
            "terminal_reason": task.get("terminal_reason") or "",
            "created_at": task.get("created_at"),
            "updated_at": task.get("updated_at"),
        },
        "authorization": resolve_auth(task.get("metadata")),
        "budget": {
            "limits": limits,
            "used": used,
            "remaining": _remaining(limits, used),
        },
        "counts": {
            "hypotheses": len(store.list_hypotheses(task_id)),
            "candidates": len(store.list_candidates(task_id)),
            "events": len(events),
            "evidence": len(store.list_evidence(task_id)),
            "program_index": 1 if index_row else 0,
        },
        "program": program,
        "evidence": evidence,
    }
    return applied(payload)


def get_execution_facts(ctx: ToolContext, execution_id: str = "",
                        cursor: int = 0, groups: Iterable[str] | None = None
                        ) -> ToolOutcome:
    """一次 execution 的可信事实（三值语义；游标绑 execution）。"""
    store = _require_store(ctx)
    target = str(execution_id or ctx.binding.execution_id or "")
    if execution_id and ctx.binding.execution_id \
            and execution_id != ctx.binding.execution_id:
        raise ActionRejected(
            "cross_execution",
            f"参数 execution_id={execution_id!r} 与绑定 "
            f"{ctx.binding.execution_id!r} 不同（禁止跨 execution 拼接）",
            field_name="execution_id")
    cur = Cursor(target, int(cursor or 0))
    index = ctx.index
    if index is None:
        row = store.get_program_index(ctx.binding.task_id)
        if row is not None:
            from ..program import ProgramIndex
            index = ProgramIndex.from_dict(row["doc"])
    try:
        snap = TrustedExecutionSnapshot.collect(
            store, ctx.binding.task_id, execution_id=target, cursor=cur,
            index=index, corpus=ctx.corpus,
            binding_hash=ctx.binding.hash,
            campaign=ctx.binding.campaign, epoch=ctx.binding.epoch,
            job_id=ctx.binding.job_id,
            tools_allowed=ctx.tools_allowed,
            denials=ctx.denials)
    except SnapshotError as exc:
        if exc.code in (CROSS_EXECUTION, "invalid_cursor"):
            raise ActionRejected(exc.code, exc.reason,
                                 field_name="cursor") from exc
        return failed(exc.code, exc.reason)
    payload = snap.to_dict()
    wanted = tuple(str(g) for g in (groups or ()))
    if wanted:
        bad = [g for g in wanted if g not in payload["groups"]]
        if bad:
            raise ActionRejected("unknown_group",
                                 f"未知事实组：{bad}",
                                 field_name="groups",
                                 hint=f"可选 {sorted(payload['groups'])}")
        payload["groups"] = {g: payload["groups"][g] for g in wanted}
    if snap.status == UNKNOWN:
        return unknown(payload, reason="本次 execution 没有可观测量"
                       if target else "还没有任何 execution",
                       code="no_execution_facts")
    return applied(payload)


def read_source_window(ctx: ToolContext, path: str, start_line: int = 1,
                       max_lines: int = 40) -> ToolOutcome:
    """只读源码窗口：限定在 ProgramIndex 根内，返回有界片段 + 哈希。"""
    index = _require_index(ctx)
    root_text = str(getattr(index, "root", "") or
                    (index.get("root") if isinstance(index, Mapping) else "") or "")
    if not root_text:
        raise ActionRejected("no_source_root",
                            "ProgramIndex 没有 root，无法定位源码")
    root = Path(root_text).expanduser().resolve()
    raw = Path(str(path or ""))
    candidate = (raw if raw.is_absolute() else (root / raw))
    try:
        target = candidate.resolve()
    except OSError as exc:                      # pragma: no cover
        return failed("source_unreadable", f"路径无法解析：{exc}")
    if not (target == root or root in target.parents):
        raise ActionRejected(
            "source_path_outside_root",
            f"{path!r} 解析到 {target}，不在索引根 {root} 内",
            field_name="path",
            hint="只读受绑定 artifact；宿主其他文件不在范围内")
    if not target.is_file():
        return failed("source_unreadable", f"不是普通文件：{target}")
    try:
        size = target.stat().st_size
    except OSError as exc:                      # pragma: no cover
        return failed("source_unreadable", f"{target}: {exc}")
    if size > MAX_SOURCE_BYTES:
        return failed("source_too_large",
                      f"{target} 有 {size} 字节，超过单次读取上限 "
                      f"{MAX_SOURCE_BYTES}（请按行窗口读取更小的源文件）")
    try:
        data = target.read_bytes()
    except OSError as exc:
        return failed("source_unreadable", f"{target}: {exc}")
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    total = len(lines)
    start = max(1, int(start_line))
    cap = max(1, min(int(max_lines), MAX_SOURCE_LINES))
    chunk = lines[start - 1:start - 1 + cap]
    end = start - 1 + len(chunk)
    window = "\n".join(chunk)
    payload = {
        "path": str(target),
        "relative": str(target.relative_to(root)) if target != root else "",
        "root": str(root),
        "start_line": start,
        "end_line": end,
        "total_lines": total,
        "returned_lines": len(chunk),
        "truncated": end < total,
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "window_sha256": hashlib.sha256(window.encode("utf-8")).hexdigest(),
        "lines": [{"n": start + i, "text": row}
                  for i, row in enumerate(chunk)],
    }
    return applied(payload)


# ====================================================================== 输入
def _seed_spec_doc(hypothesis: Mapping, *, site_id: str, fmt: str, count: int,
                   constraints: Mapping | None) -> dict:
    body = {
        "hypothesis_id": str(hypothesis.get("id") or ""),
        "site_id": str(site_id or hypothesis.get("site_id") or ""),
        "format": str(fmt or ""),
        "count": int(count),
        "constraints": dict(constraints or {}),
        "statement": str(hypothesis.get("statement") or ""),
        "falsifiable_by": str(hypothesis.get("falsifiable_by") or ""),
    }
    return {"spec_id": "ss-" + digest_of(body)[:16], **body}


def propose_seed_spec(ctx: ToolContext, hypothesis_id: str, site_id: str = "",
                      format: str = "", count: int = 1,
                      constraints: Mapping | None = None) -> ToolOutcome:
    """把一条假设落成结构化 SeedSpec（只提案，不物化、不改语料）。"""
    store = _require_store(ctx)
    if not str(hypothesis_id or "").strip():
        raise ActionRejected("invalid_params", "hypothesis_id 不能为空",
                             field_name="hypothesis_id")
    hypothesis = store.get_hypothesis(ctx.binding.task_id, hypothesis_id)
    if hypothesis is None:
        raise ActionRejected(
            "unknown_hypothesis",
            f"任务 {ctx.binding.task_id} 没有假设 {hypothesis_id!r}",
            field_name="hypothesis_id",
            hint="先跑 hypotheses 阶段；seed 必须能反查父假设")
    hyp_site = str(hypothesis.get("site_id") or "")
    if site_id and hyp_site and site_id != hyp_site:
        raise ActionRejected(
            "site_mismatch",
            f"假设 {hypothesis_id!r} 绑在 site={hyp_site!r}，不是 {site_id!r}",
            field_name="site_id")
    constraints = dict(constraints or {})
    if len(constraints) > MAX_PARAM_KEYS:
        raise ActionRejected(
            "invalid_params",
            f"constraints 最多 {MAX_PARAM_KEYS} 个键（实际 {len(constraints)}）",
            field_name="constraints")
    session = _session(ctx)
    if len(session.seed_specs) >= MAX_SEED_SPECS:
        raise ActionRejected(
            "too_many_specs",
            f"一个会话最多 {MAX_SEED_SPECS} 个 SeedSpec",
            field_name="hypothesis_id",
            hint="先物化并执行，再提新的")
    doc = _seed_spec_doc(hypothesis, site_id=site_id, fmt=format,
                         count=count, constraints=constraints)
    session.seed_specs[doc["spec_id"]] = doc
    session.touch()
    return applied({"seed_spec": doc, "specs": len(session.seed_specs)},
                   changed=("seed_specs",),
                   after={"spec_id": doc["spec_id"]})


def materialize_seeds(ctx: ToolContext, spec_id: str,
                      max_seeds: int = 4) -> ToolOutcome:
    """按 SeedSpec 在受信侧生成种子字节并写入持久语料（内容寻址）。"""
    session = _session(ctx)
    spec = session.seed_specs.get(str(spec_id or ""))
    if spec is None:
        raise ActionRejected("unknown_seed_spec",
                             f"会话里没有 SeedSpec {spec_id!r}",
                             field_name="spec_id",
                             hint="先 propose_seed_spec")
    corpus = _require_corpus(ctx)
    wanted = min(int(max_seeds), int(spec.get("count") or 1),
                 MAX_SEEDS_PER_SPEC)
    members: list[str] = []
    duplicates = 0
    for index in range(wanted):
        body = {
            "hypothesis_id": spec.get("hypothesis_id", ""),
            "site_id": spec.get("site_id", ""),
            "spec_id": spec["spec_id"],
            "format": spec.get("format", ""),
            "index": index,
            "constraints": spec.get("constraints") or {},
        }
        data = canonical_json(body).encode("utf-8")
        try:
            entry = corpus.add(
                data, hypothesis_id=str(spec.get("hypothesis_id") or ""),
                site_id=str(spec.get("site_id") or ""),
                source=f"seed_spec:{spec['spec_id']}",
                origin="proposed", format=str(spec.get("format") or ""),
                basis=[f"hypothesis:{spec.get('hypothesis_id', '')}",
                       f"site:{spec.get('site_id', '')}"])
        except Exception as exc:                # noqa: BLE001 - 语料不可写
            if not members:
                # 一条都没写进去：干净拒绝，会话不需要回滚
                raise ActionRejected(
                    "corpus_unavailable", f"语料写入失败：{exc}",
                    field_name="spec_id",
                    hint="CorpusStore 需先 begin(build_identity)") from exc
            # 已经写进去的成员是既成事实：不能报“拒绝”，否则台账（会话为空）
            # 与磁盘（已有成员）对不上，失效登记也会漏掉
            session.touch()
            return ToolOutcome(
                status="failed",
                payload={"spec_id": spec["spec_id"], "requested": wanted,
                         "materialized": list(members),
                         "duplicates": duplicates},
                changed_fields=("seeds", "corpus_members"),
                invalidations=("input_dedup", "corpus_members"),
                error={"code": "corpus_write_failed",
                       "reason": f"语料在第 {index + 1} 条写入时失败：{exc}",
                       "field": "spec_id",
                       "hint": "已写入的成员保留在语料台账里；先修好语料再重试"})
        if entry.get("duplicate"):
            duplicates += 1
            continue
        members.append(str(entry["sha256"]))
        session.seeds[str(entry["sha256"])] = {
            "sha256": entry["sha256"],
            "size": entry["size"],
            "spec_id": spec["spec_id"],
            "hypothesis_id": spec.get("hypothesis_id", ""),
            "site_id": spec.get("site_id", ""),
        }
    if not members:
        return noop({"spec_id": spec["spec_id"], "requested": wanted,
                     "materialized": [], "duplicates": duplicates},
                    reason="全部内容已在语料中（内容寻址去重）")
    session.touch()
    return applied({"spec_id": spec["spec_id"], "requested": wanted,
                    "materialized": members, "duplicates": duplicates},
                   changed=("seeds", "corpus_members"),
                   after={"members": members})


def set_dictionary(ctx: ToolContext, tokens: Iterable[str],
                   max_tokens: int = 64) -> ToolOutcome:
    """设置本轮字典（有界、去重、可复算）；同内容重复设置是 noop。"""
    session = _session(ctx)
    cap = min(int(max_tokens), MAX_DICTIONARY_TOKENS)
    cleaned: list[str] = []
    for raw in tokens or ():
        token = str(raw or "").strip()
        if not token:
            continue
        if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise ActionRejected(
                "invalid_params",
                f"token 超过 {MAX_TOKEN_BYTES} 字节：{token[:16]!r}…",
                field_name="tokens")
        if not token.isascii():
            raise ActionRejected("invalid_params",
                                 f"token 必须是 ASCII：{token!r}",
                                 field_name="tokens")
        if token not in cleaned:
            cleaned.append(token)
    if not cleaned:
        raise ActionRejected("invalid_params", "tokens 不能全为空",
                             field_name="tokens")
    if len(cleaned) > cap:
        raise ActionRejected(
            "invalid_params",
            f"tokens 最多 {cap} 个（实际 {len(cleaned)}）",
            field_name="tokens", hint="分批提交或缩小字典")
    ordered = sorted(cleaned)
    body = {"tokens": ordered, "count": len(ordered)}
    digest = digest_of(body)
    previous = dict(session.dictionary or {})
    if previous.get("digest") == digest:
        return noop({"dictionary": previous}, reason="字典内容未变化")
    version = int(previous.get("version") or 0) + 1
    session.dictionary = {"tokens": ordered, "count": len(ordered),
                          "digest": digest, "version": version,
                          "updated_at": now()}
    session.touch()
    return applied({"dictionary": dict(session.dictionary)},
                   changed=("dictionary",),
                   before={"digest": previous.get("digest", ""),
                           "version": previous.get("version", 0)},
                   after={"digest": digest, "version": version})


# ====================================================================== 实验
def _trial_from_feedback(feedback: Mapping, *, kind: str, mode: str,
                         session: SessionState,
                         hypothesis_id: str = "") -> dict:
    """把执行反馈归一成 trial 记录；缺的字段一律 unknown，不填 0。"""
    fb = dict(feedback or {})
    fuzz = dict(fb.get("fuzz") or {})
    coverage = dict(fb.get("coverage") or {})
    usable = str(coverage.get("status") or "") in ("complete", "partial")
    trial_id = f"t-{len(session.trials) + 1:03d}"
    unknowns: list[str] = []
    metrics = {
        "coverage_status": coverage.get("status") or UNKNOWN,
        "covered": coverage.get("covered") if usable else UNKNOWN,
        "new_coverage_bits": fuzz.get("new_coverage_bits"),
        "execs": fuzz.get("execs"),
        "crashes": fuzz.get("crashes"),
    }
    for key, value in list(metrics.items()):
        if value is None or value == UNKNOWN:
            metrics[key] = UNKNOWN
            unknowns.append(key)
    record = {
        "trial_id": trial_id,
        "kind": str(kind),
        "mode": str(mode),
        "hypothesis_id": str(hypothesis_id or ""),
        "execution_id": str(fb.get("execution_id") or UNKNOWN),
        "build_id": str(fb.get("build_id")
                        or (fb.get("build") or {}).get("sha256") or UNKNOWN),
        "outcome": str(fb.get("outcome") or UNKNOWN),
        "candidates": fb.get("candidates") if isinstance(
            fb.get("candidates"), int) else UNKNOWN,
        "metrics": metrics,
        "unknowns": unknowns,
        "budget_used": dict(fb.get("budget_usage") or {}),
        "created_at": now(),
    }
    return record


def run_epoch(ctx: ToolContext, kind: str = "fuzz", seconds: float = 2.0,
              workers: int = 1, timeout: float = 2.0,
              hypothesis_id: str = "") -> ToolOutcome:
    """跑一轮探索执行（探索态专用：验证态不许跑探索）。"""
    runner = _require_runner(ctx)
    if kind not in EXEC_KINDS:
        raise ActionRejected(
            "unknown_executor", f"未接通的执行方式：{kind!r}",
            field_name="kind", hint=f"可选 {list(EXEC_KINDS)}")
    session = _session(ctx)
    feedback = runner(kind=kind, mode=ctx.mode,
                      params={"seconds": float(seconds),
                              "workers": int(workers),
                              "timeout": float(timeout),
                              "hypothesis_id": str(hypothesis_id or "")},
                      binding=ctx.binding)
    if not isinstance(feedback, Mapping):
        return failed("executor_error",
                      f"执行 worker 返回了 {type(feedback).__name__}，不是反馈对象")
    trial = _trial_from_feedback(feedback, kind=kind, mode=ctx.mode,
                                 session=session, hypothesis_id=hypothesis_id)
    session.trials[trial["trial_id"]] = trial
    session.touch()
    return applied({"trial": trial, "trials": len(session.trials)},
                   changed=("trials",), after={"trial_id": trial["trial_id"]},
                   evidence_refs=[str(feedback.get("evidence_sha256"))]
                   if feedback.get("evidence_sha256") else (),
                   budget_used=dict(feedback.get("budget_usage") or {}))


def replay_input(ctx: ToolContext, input_sha256: str, timeout: float = 2.0,
                 note: str = "") -> ToolOutcome:
    """重放一条已登记输入（验证态专用：独立重放，不产结论）。"""
    corpus = _require_corpus(ctx)
    runner = _require_runner(ctx)
    digest = str(input_sha256 or "").strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ActionRejected("invalid_params", "input_sha256 必须是 64 位十六进制",
                             field_name="input_sha256")
    entry = corpus.resolve(digest)
    if entry is None:
        raise ActionRejected(
            "unknown_input",
            f"语料里没有输入 {digest[:12]}…（不能重放没登记过的字节）",
            field_name="input_sha256",
            hint="先 materialize_seeds 或让它进 fuzz 语料")
    session = _session(ctx)
    feedback = runner(kind="replay", mode=ctx.mode,
                      params={"input_sha256": digest,
                              "timeout": float(timeout),
                              "note": str(note or "")},
                      binding=ctx.binding)
    if not isinstance(feedback, Mapping):
        return failed("executor_error",
                      f"重放 worker 返回了 {type(feedback).__name__}")
    trial = _trial_from_feedback(feedback, kind="replay", mode=ctx.mode,
                                 session=session)
    trial["input_sha256"] = digest
    trial["reproduced"] = tri(feedback.get("crashed"))
    if trial["reproduced"] == UNKNOWN:
        trial["unknowns"].append("reproduced")
    trial["parent_hypothesis"] = str(entry.get("hypothesis_id") or "")
    session.trials[trial["trial_id"]] = trial
    session.touch()
    return applied({"trial": trial}, changed=("trials",),
                   after={"trial_id": trial["trial_id"]},
                   evidence_refs=[str(feedback.get("evidence_sha256"))]
                   if feedback.get("evidence_sha256") else ())


def compare_trials(ctx: ToolContext, left: str, right: str,
                   metric: str = "coverage") -> ToolOutcome:
    """对照两个 trial：不同 build 的覆盖不可比，差额只能是 unknown。"""
    session = _session(ctx)
    a = session.trials.get(str(left or ""))
    b = session.trials.get(str(right or ""))
    missing = [t for t, rec in ((left, a), (right, b)) if rec is None]
    if missing:
        raise ActionRejected("unknown_trial", f"会话里没有 trial {missing}",
                             field_name="left" if a is None else "right",
                             hint=f"已有 {sorted(session.trials)}")
    if metric not in ("coverage", "crashes", "execs"):
        raise ActionRejected("invalid_params", f"不认识的对照指标 {metric!r}",
                             field_name="metric")
    build_a = str(a.get("build_id") or UNKNOWN)
    build_b = str(b.get("build_id") or UNKNOWN)
    if UNKNOWN in (build_a, build_b):
        comparable = UNKNOWN
        why = "build_id 缺失：无法判定可比性"
    elif build_a != build_b:
        comparable = "false"
        why = f"build 不同（{build_a[:12]} != {build_b[:12]}），覆盖不可比"
    else:
        comparable = "true"
        why = "同一 build"
    key = {"coverage": "covered", "crashes": "crashes", "execs": "execs"}[metric]
    left_value = a.get("metrics", {}).get(key, UNKNOWN)
    right_value = b.get("metrics", {}).get(key, UNKNOWN)
    delta = UNKNOWN
    if comparable == "true" and left_value != UNKNOWN and right_value != UNKNOWN:
        delta = float(left_value) - float(right_value)
    payload = {
        "left": {"trial_id": a["trial_id"], "build_id": build_a,
                 "value": left_value},
        "right": {"trial_id": b["trial_id"], "build_id": build_b,
                  "value": right_value},
        "metric": metric,
        "comparable": comparable,
        "delta": delta,
        "reason": why,
        "verdict": "not_evaluated",     # 对照不是裁决：判别结论只由独立验证写
    }
    if comparable == UNKNOWN or delta == UNKNOWN:
        return unknown(payload, reason=why, code="comparison_unknown")
    return applied(payload)


# ====================================================================== 收口
def finish_research(ctx: ToolContext, reason: str, stop: str = "no_progress",
                    next_action: str = "") -> ToolOutcome:
    """结束本轮研究：只记理由与停止原因，不能写任何裁决字段。"""
    session = _session(ctx)
    text = str(reason or "").strip()
    if not text:
        raise ActionRejected("invalid_params", "reason 不能为空",
                             field_name="reason")
    body = {
        "reason": text,
        "stop": str(stop),
        "next_action": str(next_action or ""),
        "trials": len(session.trials),
        "seeds": len(session.seeds),
        "at": now(),
    }
    previous = dict(session.finished or {})
    if previous.get("reason") == text and previous.get("stop") == body["stop"]:
        return noop({"finished": previous}, reason="同样的结束理由已记录")
    session.finished = body
    session.touch()
    return applied({"finished": body}, changed=("finished",),
                   after={"stop": body["stop"]})


# ====================================================================== 工具表
def build_specs() -> tuple[ToolSpec, ...]:
    """工具表的唯一声明处：schema 由 handler 签名派生，权限/失效显式声明。"""
    return (
        ToolSpec(
            name="get_task_facts", group="read", permission="L0",
            summary="查询任务级事实：状态、预算、授权口径、假设/候选/证据计数",
            handler=get_task_facts, params={
                "include_evidence": {
                    "type": "boolean", "default": False,
                    "description": "是否返回证据清单（默认只给计数）"},
            }, changes="none"),
        ToolSpec(
            name="get_execution_facts", group="read", permission="L0",
            summary="查询一次 execution 的可信快照（三值语义，游标绑 execution）",
            handler=get_execution_facts, params={
                "execution_id": {
                    "type": "string", "default": "", "max_length": 120,
                    "description": "execution id；留空=当前绑定的 execution"},
                "cursor": {
                    "type": "integer", "default": 0, "minimum": 0,
                    "description": "事件游标（只能前进，且绑定 execution）"},
                "groups": {
                    "type": "array", "max_items": 7, "unique": True,
                    "items": {"type": "string"},
                    "description": "只看这些事实组（默认全部）"},
            }, changes="none"),
        ToolSpec(
            name="read_source_window", group="read", permission="L0",
            summary="读取受绑定源码的有界窗口（行号 + 哈希，越界拒绝）",
            handler=read_source_window, params={
                "path": {"type": "string", "max_length": 512,
                         "description": "相对 ProgramIndex 根的源码路径"},
                "start_line": {"type": "integer", "default": 1, "minimum": 1},
                "max_lines": {"type": "integer", "default": 40, "minimum": 1,
                              "maximum": MAX_SOURCE_LINES},
            }, changes="none"),
        ToolSpec(
            name="propose_seed_spec", group="input", permission="L1",
            summary="把假设落成结构化 SeedSpec（只提案，不改语料）",
            handler=propose_seed_spec, params={
                "hypothesis_id": {"type": "string", "max_length": 120,
                                  "description": "父假设 id"},
                "site_id": {"type": "string", "default": "", "max_length": 120},
                "format": {"type": "string", "default": "", "max_length": 32},
                "count": {"type": "integer", "default": 1, "minimum": 1,
                          "maximum": MAX_SEEDS_PER_SPEC},
                "constraints": {"type": "object", "default": None,
                                "nullable": True,
                                "description": "结构约束（有界键值）"},
            }, changes="proposal"),
        ToolSpec(
            name="materialize_seeds", group="input", permission="L1",
            summary="按 SeedSpec 生成种子并写入持久语料（内容寻址去重）",
            handler=materialize_seeds, params={
                "spec_id": {"type": "string", "max_length": 64},
                "max_seeds": {"type": "integer", "default": 4, "minimum": 1,
                              "maximum": MAX_SEEDS_PER_SPEC},
            }, changes="corpus"),
        ToolSpec(
            name="set_dictionary", group="input", permission="L1",
            summary="设置本轮变异字典（有界、ASCII、同内容重复=noop）",
            handler=set_dictionary, params={
                "tokens": {"type": "array", "max_items": MAX_DICTIONARY_TOKENS,
                           "unique": True, "items": {"type": "string"},
                           "description": "字典 token 列表"},
                "max_tokens": {"type": "integer", "default": 64, "minimum": 1,
                               "maximum": MAX_DICTIONARY_TOKENS},
            }, changes="dictionary"),
        ToolSpec(
            name="run_epoch", group="experiment", permission="L1",
            summary="跑一轮探索执行（仅 explore 模式；反馈归一成 trial）",
            handler=run_epoch, params={
                "kind": {"type": "string", "default": "fuzz", "enum": EXEC_KINDS},
                "seconds": {"type": "number", "default": 2.0, "minimum": 0.1,
                            "maximum": 300.0},
                "workers": {"type": "integer", "default": 1, "minimum": 1,
                            "maximum": 16},
                "timeout": {"type": "number", "default": 2.0, "minimum": 0.1,
                            "maximum": 60.0},
                "hypothesis_id": {"type": "string", "default": "",
                                  "max_length": 120},
            }, changes="execution", allowed_modes=(MODE_EXPLORE,),
            cost=lambda p: {"seconds": float(p["seconds"]), "turns": 1},
            returns={"trial": "归一化的执行反馈；缺失指标为 unknown"}),
        ToolSpec(
            name="replay_input", group="experiment", permission="L1",
            summary="重放一条已登记输入（仅 verify 模式；不产结论）",
            handler=replay_input, params={
                "input_sha256": {"type": "string", "max_length": 64,
                                 "description": "语料成员的内容哈希"},
                "timeout": {"type": "number", "default": 2.0, "minimum": 0.1,
                            "maximum": 60.0},
                "note": {"type": "string", "default": "", "max_length": 200},
            }, changes="execution", allowed_modes=(MODE_VERIFY,),
            cost=lambda p: {"seconds": float(p["timeout"]), "turns": 1},
            returns={"trial": "重放反馈；reproduced 为三值"}),
        ToolSpec(
            name="compare_trials", group="experiment", permission="L0",
            summary="对照两个 trial：不同 build 的覆盖不可比，差额只能是 unknown",
            handler=compare_trials, params={
                "left": {"type": "string", "max_length": 64},
                "right": {"type": "string", "max_length": 64},
                "metric": {"type": "string", "default": "coverage",
                           "enum": ("coverage", "crashes", "execs")},
            }, changes="none"),
        ToolSpec(
            name="finish_research", group="close", permission="L1",
            summary="结束本轮研究并记录停止原因（不能写裁决字段）",
            handler=finish_research, params={
                "reason": {"type": "string", "max_length": 500,
                           "pattern": r"\S",
                           "description": "结束理由（必须有实质内容）"},
                "stop": {"type": "string", "default": "no_progress",
                         "enum": ("no_progress", "budget", "blocked",
                                  "candidate_ready", "policy")},
                "next_action": {"type": "string", "default": "",
                                "max_length": 200},
            }, changes="proposal"),
    )


def build_registry() -> Registry:
    return Registry(build_specs())


#: 全局工具表（只读消费；新增工具只改 `build_specs()`）
REGISTRY = build_registry()
SPECS = REGISTRY.specs()
HANDLERS = {spec.name: spec.handler for spec in SPECS}


# ====================================================================== 组装
def make_binding(task: Mapping, *, campaign: str = "", epoch: int = 0,
                 job_id: str = "", execution_id: str = "",
                 index: Any = None, corpus: Any = None,
                 harness_revision: str = "", build_id: str = "",
                 policy_version: str = "v3-p2a",
                 registry: Registry | None = None) -> Binding:
    """按任务事实组装受信绑定（模型不会走这条路；控制器/测试才用）。"""
    reg = registry or REGISTRY
    index_doc = _index_doc(index)
    corpus_snap: dict = {}
    if corpus is not None:
        try:
            corpus_snap = corpus.snapshot()
        except Exception:                   # noqa: BLE001 - 台账不可读就不进绑定
            corpus_snap = {}
    return Binding(
        task_id=str(task.get("task_id") or ""),
        campaign=str(campaign or ""),
        epoch=int(epoch or 0),
        job_id=str(job_id or ""),
        execution_id=str(execution_id or ""),
        identity={
            "source_sha256": str(index_doc.get("sha256") or ""),
            "harness_revision": str(harness_revision
                                    or corpus_snap.get("build_id") or ""),
            "build_id": str(build_id or corpus_snap.get("build_id") or ""),
            "image": "",
            "benchmark": str(task.get("benchmark") or ""),
            "target": str(task.get("target") or ""),
            "policy_version": policy_version,
            "tool_schema_hash": reg.tool_schema_hash,
        })


def make_context(task: Mapping, *, binding: Binding | None = None,
                 store: Any = None, index: Any = None, corpus: Any = None,
                 session: SessionState | None = None, mode: str = MODE_EXPLORE,
                 exec_runner=None, extra_grant: Iterable[str] = (),
                 tools_allowed: Iterable[str] | None = None,
                 denials: Iterable[str] | None = None,
                 registry: Registry | None = None,
                 backend: Any = None) -> ToolContext:
    """按任务事实组装工具上下文：授权/预算/绑定都从一处派生。"""
    reg = registry or REGISTRY
    task = dict(task or {})
    binding = binding or make_binding(task, index=index, corpus=corpus,
                                     registry=reg)
    metadata = task.get("metadata") or {}
    limits = {}
    for name, key in BUDGET_LIMIT_KEYS.items():
        value = (task.get("budget") or {}).get(key)
        if value is not None:
            limits[name] = float(value)
    used = {}
    if store is not None:
        try:
            events = store.list_events(task.get("task_id") or binding.task_id)
            used = usage_from_events(events)
        except Exception:                   # noqa: BLE001 - 读不到用量=不预扣
            used = {}
    return ToolContext(
        binding=binding,
        mode=str(mode),
        grant=grant_for(metadata, extra=extra_grant),
        budget=DeclaredBudget(limits=limits, used=used),
        store=store,
        session=session or SessionState(),
        corpus=corpus,
        index=index,
        exec_runner=exec_runner,
        tools_allowed=tuple(tools_allowed) if tools_allowed is not None
        else reg.names(),
        # None = 本轮没有追踪拒绝记录 → 快照里如实报 unknown（不是“没有被拒”）
        denials=None if denials is None else tuple(denials),
        backend=backend,
    )


__all__ = ["EXEC_KINDS", "MODE_EXPLORE", "MODE_VERIFY", "MAX_SOURCE_LINES", "MAX_SOURCE_BYTES",
           "MAX_SEEDS_PER_SPEC", "MAX_DICTIONARY_TOKENS", "REGISTRY", "SPECS",
           "HANDLERS", "build_specs", "build_registry", "make_binding",
           "make_context", "get_task_facts", "get_execution_facts",
           "read_source_window", "propose_seed_spec", "materialize_seeds",
           "set_dictionary", "run_epoch", "replay_input", "compare_trials",
           "finish_research"]
