#!/usr/bin/env python3
"""V2 平台 CLI：任务提交 / 准入 / 状态 / 事件 / 证据 / 程序理解 / 假设集 / 规划 / 执行 /
独立验证 / 复核 / Case Pack。

P0：状态机 + 事件 + 证据；P1：ProgramIndex + ≤8 条可证伪假设；
P2：Plan 选择 + D2 fuzz 执行器 + Candidate（单端执行，不产确认结论）；
P3：按 benchmark 判据独立验证 + Reviewer 复核 + Case Pack 打包；
P3.5：`verify --execute` 用 benchmark runner 现场取证据（docker / socket / HTTP）；
P3.6：预算强制（max_seconds/execs/tokens/turns → TERMINATED）、取消（`cancel` → CANCELLED）；
P3.7：replay 执行链路 —— 旧 PoC + 旧日志重放（`run --kind replay` / `--replay-cmd`），
      规划器在 CG/EG 工作区发现旧 PoC 时优先 replay，判据输入仍交给 `verify --spec`。
P3.8：`verify --execute --auto` 从 task metadata / workspace `task.json` 自动生成
      runner spec；`smoke` 对 CG-01 / EG-02 / VG-01 做 dry-run 并如实报告本机缺口
      （没有镜像/服务就是 needs_evidence，不写验证记录）。
V3-P2C：`run --research` 把 PLANNED 任务交给 `ResearchController`（观察→诊断→
      改副本→真构建/冒烟→短切片执行→停止），状态按控制器结果映射，
      产物是 `research.json` + 事件；不写裁决（详见 docs/V3-P2C-RESEARCH-CLI.md）。
V3-P4a：`research-status` / `research-events` 只读消费同一份 `research.json` 与
      事件流，输出轮次/阶段/动作/结果/证据引用（与 `/api/platform/tasks/{id}/research*`
      共用 `vulnmap_platform.api.platform_research`，详见 docs/V3-P4-API-TIMELINE.md）。
V3-P5：`patch propose/test/review/rollback` 是可选的补丁工作流：只在
      `<db 目录>/patch/<task>/<P1>/` 的实验副本上生成与测试补丁，不自动应用、
      不写 verified/confirmed；工程采纳与漏洞结论分离（docs/V3-P5-PATCH.md）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (Budget, EventBus, EvidenceStore, PlatformStore,
                            TaskError, TaskSpec, build_casepack, cancel_task,
                            new_task_id, run_execution, run_hypotheses,
                            run_plan, run_preflight, run_review,
                            run_understand, run_verification)  # noqa: E402
from agent.platform.budget import (BudgetGuard, usage_from_events,
                                   violations as budget_violations)  # noqa: E402

DEFAULT_DB = ROOT / ".platform" / "platform.db"


def _db(args) -> PlatformStore:
    return PlatformStore(Path(args.db) if args.db else DEFAULT_DB)


def _meta(items) -> dict:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--meta must be key=value: {item}")
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _target(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    return str(Path(value).resolve())


def cmd_submit(args) -> int:
    store = _db(args)
    try:
        spec = TaskSpec(
            task_id=args.task_id or new_task_id(args.prefix),
            benchmark=args.benchmark,
            target=_target(args.target),
            mode=args.mode,
            budget=Budget(max_seconds=args.budget_seconds,
                          max_execs=args.budget_execs,
                          max_tokens=args.budget_tokens,
                          max_turns=args.budget_turns),
            metadata=_meta(args.meta),
        )
        task = store.create_task(spec)
        EventBus(store).emit(spec.task_id, "task.created", stage="RECEIVED",
                             payload=spec.to_dict())
    except Exception as exc:
        print(f"submit failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(task, ensure_ascii=False, indent=2))
    return 0


def cmd_preflight(args) -> int:
    store = _db(args)
    try:
        out = run_preflight(args.task_id, store, EventBus(store))
    except Exception as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["state"] == "READY" else 1


def cmd_status(args) -> int:
    store = _db(args)
    try:
        out = store.summary(args.task_id)
        out["replay"] = EventBus(store).replay(args.task_id)
    except Exception as exc:
        print(f"status failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_events(args) -> int:
    store = _db(args)
    try:
        events = EventBus(store).list(args.task_id, after_seq=args.after)
    except Exception as exc:
        print(f"events failed: {exc}", file=sys.stderr)
        return 2
    for ev in events:
        print(json.dumps(ev, ensure_ascii=False))
    return 0


def cmd_evidence(args) -> int:
    store = _db(args)
    try:
        rows = store.list_evidence(args.task_id)
    except Exception as exc:
        print(f"evidence failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_attach(args) -> int:
    store = _db(args)
    try:
        store.get_task(args.task_id)
        ref = EvidenceStore(store, Path(args.root)).put_file(
            args.task_id, args.kind, args.path, source_stage=args.stage)
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(ref.__dict__, ensure_ascii=False, indent=2))
    return 0


def cmd_transition(args) -> int:
    store = _db(args)
    try:
        task = store.transition(args.task_id, args.to, reason=args.reason)
    except Exception as exc:
        print(f"transition failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(task, ensure_ascii=False, indent=2))
    return 0


def cmd_replay(args) -> int:
    store = _db(args)
    try:
        out = EventBus(store).replay(args.task_id)
    except Exception as exc:
        print(f"replay failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_understand(args) -> int:
    store = _db(args)
    try:
        out = run_understand(args.task_id, store, EventBus(store),
                             max_sources=args.max_sources or None,
                             max_call_sites=args.max_call_sites or None,
                             unpack_root=args.unpack_cache or None)
    except Exception as exc:
        print(f"understand failed: {exc}", file=sys.stderr)
        return 2
    index = out["index"]
    summary = {
        "task_id": out["task_id"],
        "state": out["state"],
        "sha256": out["sha256"],
        "event_seq": out["event_seq"],
        "benchmark": index["benchmark"],
        "root": index["root"],
        "source_count": index["source_count"],
        "formats": index["formats"],
        "coverage": index["coverage"],
        "counts": index["counts"],
        "entry_points": index["entry_points"][:8],
        "anchors": index["anchors"],
        "unpack": {k: index["unpack"].get(k) for k in
                   ("archive", "sha256", "cache_dir", "src_root", "files",
                    "bytes", "cached")} if index.get("unpack") else {},
        "images": index.get("images") or {},
        "warnings": index.get("warnings") or [],
        "notes": index["notes"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_hypotheses(args) -> int:
    store = _db(args)
    # F2：默认 auto（优先 LLM、无配置回退规则）；--llm 强制、--no-llm 显式关闭
    use_llm = False if args.no_llm else (True if args.llm else None)
    try:
        out = run_hypotheses(args.task_id, store, EventBus(store),
                             use_llm=use_llm)
    except Exception as exc:
        print(f"hypotheses failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_program(args) -> int:
    store = _db(args)
    try:
        row = store.get_program_index(args.task_id)
        if row is None:
            raise ValueError(f"no ProgramIndex for {args.task_id}; run `understand` first")
    except Exception as exc:
        print(f"program failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(row["doc"], ensure_ascii=False, indent=2))
    return 0


def cmd_plan(args) -> int:
    store = _db(args)
    try:
        out = run_plan(args.task_id, store, EventBus(store),
                       seconds=args.seconds or None,
                       workers=args.workers or None,
                       timeout=args.timeout or None)
    except Exception as exc:
        print(f"plan failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_run(args) -> int:
    store = _db(args)
    # 默认与库同目录：<db 目录>/work/<task>、<db 目录>/evidence
    workdir = Path(args.workdir) if args.workdir else (
        store.path.parent / "work" / args.task_id)
    evidence_root = Path(args.evidence_root) if args.evidence_root else (
        store.path.parent / "evidence")
    if getattr(args, "research", False):
        return _cmd_run_research(args, store, workdir, evidence_root)
    try:
        out = run_execution(
            args.task_id, store, EventBus(store),
            workdir=workdir, evidence_root=evidence_root,
            seconds=args.seconds or None,
            workers=args.workers or None,
            timeout=args.timeout or None,
            isolation=args.isolation,
            require_isolation=args.require_isolation,
            tokens_used=args.tokens_used or 0,
            kind_override=args.kind or None,
            replay_cmd=args.replay_cmd or None)
    except Exception as exc:
        print(f"run failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    # 退出码：0=产结果（含取消/预算终止），3=预算终止（便于脚本区分）
    return 3 if out.get("outcome") == "budget_exceeded" else 0


def _cmd_run_research(args, store, workdir: Path, evidence_root: Path) -> int:
    """`run --research`：PLANNED 任务走 ResearchController（不是单次 run_execution）。

    输出是 `ControllerResult` + `research.json` 的合并文档：研究循环不写
    `verified/confirmed`、不建候选记录；状态按控制器结果映射（见
    `agent/platform/adaptive/cli.py` 的映射表）。退出码：
    0=映射到 CANDIDATE/NO_REPRO、1=BLOCKED/FAILED/NEEDS_EVIDENCE、
    2=前置条件不成立（状态不动）、3=TERMINATED（预算）。
    """
    from agent.platform.adaptive.cli import DEFAULT_MAX_ROUNDS, ResearchError
    from agent.platform.adaptive.cli import run_research
    try:
        out = run_research(
            args.task_id, store, EventBus(store),
            workdir=workdir, evidence_root=evidence_root,
            research_root=args.research_root or None,
            campaign=args.campaign or "",
            max_rounds=args.max_rounds or DEFAULT_MAX_ROUNDS,
            seconds=args.seconds or None,
            workers=args.workers or None,
            timeout=args.timeout or None,
            isolation=args.isolation,
            require_isolation=args.require_isolation,
            origin=args.research_origin or None,
            build_command=args.build_cmd or None,
            smoke_command=args.smoke_cmd or None,
            tokens_used=args.tokens_used or 0)
    except ResearchError as exc:
        print(f"run --research failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:                     # noqa: BLE001 - 入口错误如实报
        print(f"run --research failed: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    state = str(out.get("state") or "")
    if state == "TERMINATED":
        return 3
    if state in ("BLOCKED", "FAILED", "NEEDS_EVIDENCE"):
        return 1
    return 0


def cmd_cancel(args) -> int:
    store = _db(args)
    evidence_root = Path(args.evidence_root) if args.evidence_root else (
        store.path.parent / "evidence")
    try:
        out = cancel_task(args.task_id, store, EventBus(store),
                          reason=args.reason, actor=args.actor,
                          evidence_root=evidence_root)
    except Exception as exc:
        print(f"cancel failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_budget(args) -> int:
    """只读：任务预算上限 + 事件流里推出来的用量（与强制判定同一口径）。"""
    store = _db(args)
    try:
        task = store.get_task(args.task_id)
        used = usage_from_events(store.list_events(args.task_id))
        guard = BudgetGuard(task["budget"], used=used)
        snapshot = guard.snapshot(extra={"state": task["state"],
                                         "terminal_reason": task["terminal_reason"]})
    except Exception as exc:
        print(f"budget failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(snapshot, ensure_ascii=False, indent=2))
    return 0


def cmd_candidates(args) -> int:
    store = _db(args)
    try:
        rows = store.list_candidates(args.task_id, state=args.state)
    except Exception as exc:
        print(f"candidates failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_verifications(args) -> int:
    store = _db(args)
    try:
        verified = None
        if args.status:
            verified = args.status == "verified"
        rows = store.list_verifications(args.task_id, verified=verified)
    except Exception as exc:
        print(f"verifications failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_reviews(args) -> int:
    store = _db(args)
    try:
        rows = store.list_reviews(args.task_id, verdict=args.verdict)
    except Exception as exc:
        print(f"reviews failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_reports(args) -> int:
    store = _db(args)
    try:
        rows = store.list_reports(args.task_id)
    except Exception as exc:
        print(f"reports failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


# ====================================================================== 研究轮次
def _research_reader():
    """只读解释器（与 API 共用一份）：延迟导入，CLI 其余命令不必背 FastAPI 依赖。"""
    from vulnmap_platform.api import platform_research
    return platform_research


def _research_context(args) -> tuple[object, list, Path]:
    """任务存在性 + 事件流 + 研究目录根；库不存在按“没有记录”处理。"""
    db_path = Path(args.db) if args.db else DEFAULT_DB
    if not db_path.is_file():
        raise FileNotFoundError(f"platform db not found: {db_path}")
    store = PlatformStore(db_path)
    try:
        store.get_task(args.task_id)              # 任务不存在 → TaskError
        events = EventBus(store).list(args.task_id)
    except Exception:
        store.close()
        raise
    root = Path(args.root).expanduser() if args.root else db_path.parent
    return store, events, root


def cmd_research_status(args) -> int:
    """只读：研究轮次（阶段 / 动作 / 结果 / 证据引用）。

    退出码：0=有研究产物；1=任务存在但没有研究轮次；2=任务不存在/产物不可用。
    """
    research = _research_reader()
    try:
        store, events, root = _research_context(args)
    except Exception as exc:
        print(f"research-status failed: {exc}", file=sys.stderr)
        return 2
    try:
        view = research.status_view(root, args.task_id, events)
    except research.ResearchUnavailable as exc:
        print(f"research-status: {exc}", file=sys.stderr)
        return 1
    except research.ResearchConflict as exc:
        print(f"research-status: conflict: {exc}", file=sys.stderr)
        return 2
    finally:
        try:
            store.close()
        except Exception:                     # noqa: BLE001 - 关闭失败不改输出
            pass
    print(json.dumps(view, ensure_ascii=False, indent=2))
    return 0


def cmd_research_events(args) -> int:
    """只读：研究 session 的事件流（JSONL）；退出码同 research-status。"""
    research = _research_reader()
    try:
        store, events, root = _research_context(args)
    except Exception as exc:
        print(f"research-events failed: {exc}", file=sys.stderr)
        return 2
    try:
        view = research.events_view(root, args.task_id, events,
                                    after=args.after, limit=args.limit,
                                    kind=args.kind)
    except research.ResearchUnavailable as exc:
        print(f"research-events: {exc}", file=sys.stderr)
        return 1
    except research.ResearchConflict as exc:
        print(f"research-events: conflict: {exc}", file=sys.stderr)
        return 2
    finally:
        try:
            store.close()
        except Exception:                     # noqa: BLE001
            pass
    if args.json:
        print(json.dumps(view, ensure_ascii=False, indent=2))
        return 0
    for item in view["items"]:
        print(json.dumps(item, ensure_ascii=False))
    return 0


def _verify_spec(args, benchmark: str) -> dict:
    """把 CLI 参数拼成证据 spec（口径混用交给 verify.normalize_spec 拒绝）。

    这里不按 benchmark 过滤参数：给了别的 benchmark 才用的证据
    （如 CyberGym 任务带 `--flag`）必须原样传下去，由 verify 明确拒绝，
    而不是被 CLI 静默丢掉、再报一个“证据不足”。
    """
    if args.spec:
        path = Path(args.spec).expanduser()
        if not path.is_file():
            raise SystemExit(f"--spec not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    spec: dict = {}

    def put(side: str, key: str, value) -> None:
        if value is None or value == "" or value == []:
            return
        if side:
            spec.setdefault(side, {})[key] = value
        else:
            spec[key] = value

    put("input", "path", args.input)
    put("input", "sha256", args.input_sha256)
    put("vul", "exit_code", args.vul_exit)
    put("vul", "log_path", args.vul_log)
    put("vul", "crashed", args.crashed)
    put("fix", "exit_code", args.fix_exit)
    put("fix", "log_path", args.fix_log)
    put("", "flag", args.flag)
    put("", "flag_path", args.flag_file)
    put("", "expected_flag", args.expected_flag)
    put("exploit", "exit_code", args.exploit_exit)
    put("exploit", "log_path", args.exploit_log)
    put("exploit", "source", args.exploit_source
        or ("official_entry" if (benchmark or "").lower() == "exploitgym" else ""))
    put("baseline", "status", args.baseline_status)
    put("baseline", "body_path", args.baseline_file)
    put("baseline", "body_sha256", args.baseline_sha256)
    put("patched", "status", args.patched_status)
    put("patched", "body_path", args.patched_file)
    put("patched", "body_sha256", args.patched_sha256)
    put("expect", "baseline_status", args.expect_baseline_status)
    put("expect", "patched_status_in", args.expect_patched_status)
    return spec


def _runner_spec(args, benchmark: str, spec: dict) -> dict:
    """`--execute` 的执行参数：命令行显式值覆盖 `--spec` 里的同名键。

    只补该 benchmark 自己的 runner 键，不碰判据键——判据口径仍由
    verify.normalize_spec 把关，runner 只负责把证据跑出来。
    """
    merged = dict(spec)
    name = (benchmark or "").lower()
    if name == "cybergym":
        pairs = [("image_vul", args.image_vul), ("image_fix", args.image_fix),
                 ("docker", args.docker), ("cmd", args.cmd or None)]
        if args.input and not merged.get("input_path"):
            merged["input_path"] = args.input
    elif name == "exploitgym":
        pairs = [("host", args.host), ("port", args.port or None),
                 ("exploit_cmd", args.exploit_cmd)]
    elif name == "vulngym":
        pairs = [("baseline_url", args.baseline_url),
                 ("patched_url", args.patched_url)]
    else:
        pairs = []
    for key, value in pairs:
        if value not in (None, "", []):
            merged[key] = value
    return merged


def cmd_verify(args) -> int:
    store = _db(args)
    evidence_root = Path(args.evidence_root) if args.evidence_root else (
        store.path.parent / "evidence")
    execute = bool(args.execute or args.auto)
    try:
        task = store.get_task(args.task_id)
        spec = _verify_spec(args, task["benchmark"])
        if execute:
            spec = _runner_spec(args, task["benchmark"], spec)
        out = run_verification(
            args.task_id, store, EventBus(store), spec=spec,
            candidate_id=args.candidate or "",
            evidence_root=evidence_root,
            execute=execute, runner=args.runner,
            timeout=args.timeout or None, workdir=args.workdir or None,
            isolation=args.isolation,
            require_isolation=args.require_isolation,
            auto=bool(args.auto),
            workspace=args.workspace or None,
            probe=not args.no_probe)
    except Exception as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["verified"] else 1


def _resolve_workspace(root: Path, case: str) -> Path | None:
    """案例编号 → 工作区目录（`CG-01` → `workspace/CG-01-arvo-44034`）。"""
    name = str(case or "").strip()
    if not name:
        return None
    exact = Path(root) / name
    if (exact / "task.json").is_file():
        return exact
    for path in sorted(Path(root).glob(f"{name}*")):
        if (path / "task.json").is_file():
            return path
    return None


def _smoke_case(case: str, *, root: Path, execute: bool, workdir: Path,
                timeout, isolation: str, require_isolation: bool,
                docker: str, probe: bool) -> dict:
    """一个案例的 dry-run / 尝试：只翻译 spec + 探测本机，不写验证结论。"""
    from agent.platform.runners import select_runner
    from agent.platform.runners.spec import build_runner_spec, summarize
    from agent.platform.verify import evaluate

    workspace = _resolve_workspace(root, case)
    entry: dict = {"case": case, "workspace": str(workspace or ""),
                   "benchmark": "", "status": "needs_evidence",
                   "persisted": False, "executed": False}
    if workspace is None:
        entry.update({"status": "unknown_case",
                      "blockers": [f"workspace_not_found:{case}"],
                      "missing": ["task.json"]})
        return entry
    task_json, task_path = _read_task_json(workspace)
    entry["task_json"] = task_path
    benchmark = str(task_json.get("benchmark") or "").lower()
    entry["benchmark"] = benchmark
    entry["case_id"] = task_json.get("case_id", "")
    entry["task_id"] = task_json.get("task_id", "")
    if not benchmark:
        entry.update({"status": "needs_evidence",
                      "blockers": ["runner_not_configured:benchmark"],
                      "missing": ["benchmark"]})
        return entry
    try:
        doc = build_runner_spec(benchmark, task_json=task_json,
                                workspace=workspace,
                                overrides={"docker": docker} if docker else None,
                                probe=probe)
    except Exception as exc:                     # noqa: BLE001 - 一个案例坏了不影响别的
        entry.update({"status": "error", "blockers": [f"spec_error:{exc}"]})
        return entry
    entry.update({
        "status": "ready" if doc["ready"] else "needs_evidence",
        "ready": bool(doc["ready"]),
        "missing": list(doc["missing"]),
        "blockers": list(doc["blockers"]),
        "warnings": list(doc["warnings"]),
        "notes": list(doc["notes"]),
        "probes": list(doc["probes"]),
        "spec": dict(doc["spec"]),
        "spec_summary": summarize(doc),
    })
    entry["would_execute"] = bool(doc["ready"])
    if not (execute and doc["ready"]):
        return entry

    # ---- 真跑一次：仍然不落验证记录（smoke 只回答“能不能跑”）
    case_dir = Path(workdir) / str(case)
    runner = select_runner(benchmark, workdir=case_dir, timeout=timeout,
                          isolation=isolation,
                          require_isolation=require_isolation)
    result = runner.safe_run(dict(doc["spec"]))
    preview = None
    if result.completed and not result.blockers:
        try:
            preview = evaluate(benchmark, result.spec)
        except Exception as exc:                 # noqa: BLE001 - 预览失败不改结论
            preview = {"verified": False, "status": "needs_evidence",
                       "blockers": [f"evaluate_error:{exc}"]}
    entry.update({
        "executed": True,
        "runner": result.runner,
        "completed": bool(result.completed),
        "timed_out": bool(result.timed_out),
        "runner_blockers": list(result.blockers),
        "evidence": [{"kind": item.get("kind"), "sha256": item.get("sha256"),
                      "size": item.get("size")} for item in result.evidence],
        "workdir": str(case_dir),
    })
    if preview is not None:
        entry["criterion"] = {
            "status": preview.get("status"),
            "criterion_ok": bool(preview.get("verified")),
            "blockers": list(preview.get("blockers") or []),
            "checks": dict(preview.get("checks") or {}),
        }
    if not result.completed or result.blockers:
        entry["status"] = "needs_evidence"
        entry["blockers"] = list(dict.fromkeys(
            entry["blockers"] + list(result.blockers)))
    elif preview is not None and preview.get("verified"):
        # 判据成立也只说“会 verified”，绝不在这里写 verified 记录
        entry["status"] = "would_verify"
    else:
        entry["status"] = "no_repro"
        if preview is not None:
            entry["blockers"] = list(preview.get("blockers") or [])
    return entry


def _read_task_json(workspace: Path) -> tuple[dict, str]:
    path = Path(workspace) / "task.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"task.json unreadable: {path} ({exc})")
    if not isinstance(doc, dict):
        raise SystemExit(f"task.json must be an object: {path}")
    return doc, str(path)


# ------------------------------------------------------------------ smoke 落账
# `smoke` 默认只回答“能不能跑 / 会怎么判”，`--record` 才把这一次的结论写进
# `verifications` 表。三条硬约束（代码强制，不靠调用方自觉）：
#   1. 只有 `status=would_verify`（判据成立 **且** runner 跑完无 blocker）才写
#      `verified=True`；缺口一律 `needs_evidence`，证据为负 `no_repro`，
#      口径/案例错误 `rejected`——没有任何“默认通过”分支；
#   2. 任务必须已存在（或显式 `--ensure-task` 从 `task.json` 登记 RECEIVED），
#      不伪造任务、不猜 benchmark；
#   3. 不写 `confirmed`：本命令只落 `verifications` 一条记录，终局标签仍由
#      CasePack 的验证记录 + 复核记录共同支撑。
SMOKE_RECORD_SCHEMA = "vulnmap.smoke_record.v1"
SMOKE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
# smoke 状态 → 验证状态：只有 would_verify 是 verified，别的一律不能升级
SMOKE_STATUS = {
    "would_verify": "verified",
    "no_repro": "no_repro",
    "needs_evidence": "needs_evidence",
    "ready": "needs_evidence",       # dry-run：spec 齐全但没跑，仍是缺口
    "error": "rejected",             # spec/配置坏了：口径不可用
    "unknown_case": "rejected",      # 案例编号不存在
}


def _smoke_slug(value, *, limit: int = 24) -> str:
    """编号片段：只留 `[A-Za-z0-9._:-]`，首字符必须是字母或数字。"""
    text = str(value or "").strip()
    out = "".join(ch if (ch.isalnum() or ch in "._:-") else "-" for ch in text)
    out = out.strip("-._:")
    while out and not out[0].isalnum():
        out = out[1:]
    return out[:limit] or "x"


def _smoke_manifest(evidence) -> tuple[list[dict], str]:
    """runner 证据清单 → (清单, 清单哈希)。

    清单只保留 `kind/sha256/size`：路径带工作目录、不可复现，不进哈希。
    空清单也给出确定哈希（`sha256("[]")`），所以 `evidence_sha256` 恒为 64 位
    hex，不会因为“没有证据文件”退化成空串。
    """
    items: list[dict] = []
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        items.append({"kind": str(item.get("kind") or ""),
                      "sha256": str(item.get("sha256") or ""),
                      "size": int(item.get("size") or 0)})
    items.sort(key=lambda x: (x["kind"], x["sha256"], x["size"]))
    blob = json.dumps(items, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return items, sha256(blob).hexdigest()


def _smoke_run_id(entry: dict, explicit: str = "") -> str:
    """一次 smoke 的 run 标识（编号稳定，不带时间/随机数）。

    显式 `--run-id` 原样用；省略时按“案例 + 任务 + benchmark + spec”派生：
    同一配方永远得到同一个 id，重复 record 覆盖同一条记录，而不是每跑一次就多一行。
    **证据清单哈希不进 id**——runner 快照带耗时，每次都会变；它是 `evidence_sha256`
    的内容，不是 run 的身份。要保留多次运行的历史，显式给不同的 `--run-id`。
    """
    if explicit:
        return _smoke_slug(explicit, limit=40)
    basis = {
        "case": str(entry.get("case") or ""),
        "task_id": str(entry.get("task_id") or entry.get("case_id") or ""),
        "benchmark": str(entry.get("benchmark") or ""),
        "spec": entry.get("spec") or {},
    }
    blob = json.dumps(basis, ensure_ascii=False, sort_keys=True,
                      default=str).encode("utf-8")
    return f"r{sha256(blob).hexdigest()[:15]}"


def _smoke_verification_id(case: str, run_id: str) -> str:
    """`SMOKE-<case>-<run>`；超长/非法字符退化成哈希编号（仍是稳定编号）。"""
    composed = f"SMOKE-{_smoke_slug(case)}-{_smoke_slug(run_id, limit=40)}"
    if SMOKE_ID_RE.match(composed) and len(composed) <= 64:
        return composed
    return f"SMOKE-{sha256(composed.encode('utf-8')).hexdigest()[:16]}"


def _smoke_record_status(entry: dict) -> str:
    raw = str(entry.get("status") or "").strip()
    return SMOKE_STATUS.get(raw, "needs_evidence")


def _smoke_record_task_id(entry: dict, explicit: str = "") -> str:
    return str(explicit or entry.get("task_id") or entry.get("case_id")
               or "").strip()


def _record_smoke_case(store, entry: dict, *, task_id: str, run_id: str = "",
                       ensure_task: bool = False) -> dict:
    """把一个 smoke 案例的结论落成一条 `Verification`（幂等：同 id 覆盖写）。

    返回写入摘要；任何口径问题（任务不存在、benchmark 不一致）都抛错，
    由调用方转成 `errors[]` + 退出码 2，绝不静默落一条“看起来通过”的记录。
    """
    from agent.platform.verify import (BENCHMARK_KIND, Verification,
                                       now as verification_now)

    case = str(entry.get("case") or "")
    benchmark = str(entry.get("benchmark") or "").lower()
    kind = BENCHMARK_KIND.get(benchmark, "") or "unknown"
    evidence, manifest_sha = _smoke_manifest(entry.get("evidence"))
    resolved_run = _smoke_run_id(entry, explicit=run_id)
    vid = _smoke_verification_id(case, resolved_run)
    status = _smoke_record_status(entry)
    criterion = dict(entry.get("criterion") or {})
    verified = status == "verified" and bool(criterion.get("criterion_ok"))
    if status == "verified" and not verified:
        status = "no_repro"                 # 判据没成立就绝不写 verified

    created_task = False
    try:
        task = store.get_task(task_id)
    except TaskError:
        if not ensure_task:
            raise TaskError(
                f"task not found: {task_id}（smoke --record 只落已存在的任务；"
                "先 `platform submit`/API 建任务，或显式加 --ensure-task 从 "
                "task.json 登记为 RECEIVED）")
        workspace = str(entry.get("workspace") or "")
        task_json, task_path = _read_task_json(Path(workspace))
        task, created_task = store.ensure_task_from_task_json(
            task_json, task_json_path=task_path, workspace=workspace,
            task_id=task_id, benchmark=benchmark, mode="smoke")
    # 任务是不是由 smoke 登记出来的：看 metadata 而不是看“这次调用建没建”，
    # 否则重复 record 会因为 True→False 让 detail 变化（幂等就破了）
    created_by_record = (str((task.get("metadata") or {}).get("source") or "")
                         == "smoke:record")
    task_benchmark = str(task.get("benchmark") or "").lower()
    if task_benchmark != benchmark:
        raise TaskError(
            "benchmark mismatch: task=%r smoke=%r（口径不混用，拒绝落账）"
            % (task_benchmark or "unknown", benchmark or "unknown"))

    prior = store.get_verification(task_id, vid) or {}
    blockers = list(dict.fromkeys(
        [str(item) for item in (criterion.get("blockers") or [])]
        + [str(item) for item in (entry.get("blockers") or [])]))
    detail = {
        "case": case,
        "task": {
            "task_id": task_id,
            "task_json": str(entry.get("task_json") or ""),
            "workspace": str(entry.get("workspace") or ""),
            "case_id": str(entry.get("case_id") or ""),
            "benchmark": task_benchmark,
            "state": str(task.get("state") or ""),
            "created_by_record": created_by_record,
        },
        "benchmark": benchmark,
        "kind": kind,
        "spec": dict(entry.get("spec") or {}),
        "spec_summary": entry.get("spec_summary") or {},
        "evidence": evidence,
        "evidence_manifest_sha256": manifest_sha,
        "criterion": criterion,
        "checks": dict(criterion.get("checks") or {}),
        "blockers": blockers,
        "run_id": resolved_run,
        "smoke_status": str(entry.get("status") or ""),
        "mode": "execute" if entry.get("executed") else "dry-run",
        "runner": str(entry.get("runner") or ""),
        "workdir": str(entry.get("workdir") or ""),
        "record_schema": SMOKE_RECORD_SCHEMA,
        "source": "smoke:record",
    }
    verification = Verification(
        verification_id=vid, task_id=task_id, candidate_id="",
        benchmark=benchmark or "unknown", kind=kind,
        verified=verified, status=status, evidence_sha256=manifest_sha,
        detail=detail,
        # 幂等：重复 record 同一 run 时保留首次时间戳，行内容逐字一致
        created_at=str(prior.get("created_at") or verification_now()),
    )
    verification.validate()
    saved = store.save_verification(verification)
    # 重复 record 同一 run：行内容本来就一样，就不再重复写一条同义事件
    changed = (not prior
               or bool(prior.get("verified")) != verified
               or str(prior.get("status")) != status
               or str(prior.get("evidence_sha256")) != manifest_sha
               or dict(prior.get("detail") or {}) != detail)
    if changed:
        EventBus(store).emit(
            task_id, "verification.recorded",
            stage=str(task.get("state") or "RECEIVED"),
            payload={"verification_id": vid, "status": status,
                     "verified": verified, "benchmark": benchmark, "kind": kind,
                     "case": case, "run_id": resolved_run,
                     "evidence_sha256": manifest_sha,
                     "task_json": str(entry.get("task_json") or ""),
                     "source": "smoke:record", "blockers": blockers[:20]})
    return {
        "verification_id": vid,
        "task_id": task_id,
        "status": status,
        "verified": verified,
        "evidence_sha256": manifest_sha,
        "run_id": resolved_run,
        "created_at": str(saved.get("created_at") or ""),
        "task_created": created_task,
        "idempotent_overwrite": bool(prior),
        "changed": changed,
    }


def cmd_smoke(args) -> int:
    """端到端 dry-run：CG-01 / EG-02 / VG-01 的 runner spec 与本机缺口。

    本机没有 arvo 镜像、没有 ExploitGym socket、没有 VulnGym 实例时，
    输出就是 `needs_evidence` + 缺什么；**不**把缺口写成负结果。
    默认不写验证记录；`--record` 才把本次结论落成 `verifications` 一行
    （只有 `would_verify` 落 `verified`，其余落 `needs_evidence/no_repro/rejected`）。
    """
    root = Path(args.workspace_root)
    cases = list(args.cases) or ["CG-01", "EG-02", "VG-01"]
    workdir = Path(args.workdir) if args.workdir else (
        ROOT / ".platform" / "smoke")
    if args.record and args.task_id and len(cases) > 1:
        print(json.dumps({
            "schema": "vulnmap.smoke.v1", "mode": "execute" if args.execute else "dry-run",
            "workspace_root": str(root), "cases": [], "summary": {},
            "errors": [{"case": "*", "error": "--task-id 只能配单个 case；"
                                              "多案例请按 task.json 映射或逐个 record"}],
            "persisted": False,
        }, ensure_ascii=False, indent=2))
        return 2
    out_cases, errors = [], []
    for case in cases:
        try:
            entry = _smoke_case(
                case, root=root, execute=bool(args.execute), workdir=workdir,
                timeout=args.timeout or None, isolation=args.isolation,
                require_isolation=bool(args.require_isolation),
                docker=args.docker or "", probe=not args.no_probe)
        except SystemExit as exc:
            errors.append({"case": case, "error": str(exc)})
            entry = {"case": case, "status": "error", "persisted": False,
                     "executed": False, "blockers": [str(exc)]}
        if entry.get("status") == "unknown_case":
            # 案例编号打错是操作错误（不是“缺证据”），退出码 2
            errors.append({"case": case,
                           "error": "workspace/task.json not found"})
        out_cases.append(entry)

    recorded: list[dict] = []
    if args.record:
        store = _db(args)
        try:
            for entry in out_cases:
                if entry.get("status") == "unknown_case":
                    continue
                task_id = _smoke_record_task_id(entry, args.task_id)
                if not task_id:
                    entry["persisted"] = False
                    entry["record_error"] = (
                        f"{entry.get('case')}: 无法确定 task_id"
                        "（task.json 缺少 task_id/case_id，且未给 --task-id）")
                    errors.append({"case": entry.get("case"),
                                   "error": entry["record_error"]})
                    continue
                try:
                    summary = _record_smoke_case(
                        store, entry, task_id=task_id, run_id=args.run_id or "",
                        ensure_task=bool(args.ensure_task))
                except (TaskError, SystemExit, ValueError) as exc:
                    entry["persisted"] = False
                    entry["record_error"] = str(exc)
                    errors.append({"case": entry.get("case"), "error": str(exc)})
                    continue
                entry["persisted"] = True
                entry["verification"] = summary
                recorded.append(summary)
        finally:
            store.close()

    statuses = {}
    for entry in out_cases:
        statuses[entry["status"]] = statuses.get(entry["status"], 0) + 1
    out = {
        "schema": "vulnmap.smoke.v1",
        "mode": "execute" if args.execute else "dry-run",
        "workspace_root": str(root),
        "cases": out_cases,
        "summary": statuses,
        # 默认不落账；--record 时只有真的写进 verifications 才为 True
        "persisted": bool(recorded),
    }
    if args.record:
        out["record"] = {
            "enabled": True,
            "run_id": args.run_id or "",
            "task_id": args.task_id or "",
            "ensure_task": bool(args.ensure_task),
            "written": recorded,
        }
    if errors:
        out["errors"] = errors
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if errors:
        return 2
    if args.strict and any(entry.get("status") != "would_verify"
                           for entry in out_cases):
        return 1
    return 0


def cmd_review(args) -> int:
    store = _db(args)
    evidence_root = Path(args.evidence_root) if args.evidence_root else (
        store.path.parent / "evidence")
    try:
        out = run_review(args.task_id, store, EventBus(store),
                         verification_id=args.verification or "",
                         evidence_root=evidence_root)
    except Exception as exc:
        print(f"review failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out["verdict"] == "accept" else 1


def cmd_casepack(args) -> int:
    store = _db(args)
    evidence_root = Path(args.evidence_root) if args.evidence_root else None
    try:
        out = build_casepack(args.task_id, store,
                             out_dir=Path(args.out) if args.out else None,
                             evidence_root=evidence_root,
                             close=args.close, bus=EventBus(store))
    except Exception as exc:
        print(f"casepack failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _patch_root(args, store) -> Path:
    """补丁工件根：默认 <db 目录>/patch（绝不写进目标源码树）。"""
    value = getattr(args, "patch_root", "")
    return Path(value) if value else store.path.parent / "patch"


def _patch_workflow(args, store, task_id: str = ""):
    from agent.platform.adaptive.patch import PatchWorkflow

    return PatchWorkflow(_patch_root(args, store), store=store,
                         task_id=task_id)


def _print_json(doc) -> None:
    print(json.dumps(doc, ensure_ascii=False, indent=2))


def cmd_autonomy_pack(args) -> int:
    """从平台事实生成自主运行包；可选立即独立校验。"""
    from agent.autonomy.platform_adapter import pack_from_platform
    from agent.autonomy.verify import verify

    out = pack_from_platform(args.db, args.task_id, args.pack,
                             event_cap=args.event_cap)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if not out.get("ok"):
        return 2
    if args.expected:
        res = verify(args.pack, expected_path=args.expected,
                     require_autonomous=not args.allow_assisted)
        print(json.dumps({k: res[k] for k in ("class", "verdict", "checks", "reasons")},
                         ensure_ascii=False, indent=2))
        return 0 if res["verdict"] == "pass" else 2
    return 0


def cmd_patch_propose(args) -> int:
    from agent.platform.adaptive.patch import PatchError, PatchUnsupported

    store = _db(args)
    try:
        task = store.get_task(args.task_id)
    except Exception as exc:                      # noqa: BLE001 - 任务不存在
        _print_json({"status": "refused", "reasons": [str(exc)]})
        return 2
    source_root = args.source_root or str(task.get("target") or "")
    workflow = _patch_workflow(args, store, args.task_id)
    try:
        out = workflow.propose(
            candidate_id=args.candidate, source_root=source_root,
            line=args.line, argument=args.argument, claim=args.claim,
            file=args.file, end_line=args.end_line, function=args.function,
            evidence=args.evidence or (), verification_ids=args.verification or (),
            diff=args.diff, patched=args.patched_file,
            trigger_cmd=args.trigger_cmd,
            regression_cmds=args.regression_cmd or (),
            timeout=args.timeout, strategy=args.strategy,
            allow_large=bool(args.allow_large))
    except PatchUnsupported as exc:
        _print_json({"status": "unsupported", "reasons": [str(exc)]})
        return 2
    except PatchError as exc:
        _print_json({"status": "refused", "reasons": [str(exc)]})
        return 2
    _print_json(out)
    return 0


def cmd_patch_test(args) -> int:
    from agent.platform.adaptive.patch import PatchError, PatchWorkflow

    store = _db(args)
    root = _patch_root(args, store)
    task_id = args.task_id
    if not task_id:
        try:
            task_id, _ = PatchWorkflow.find(root, args.patch_id)
        except PatchError as exc:
            _print_json({"status": "refused", "reasons": [str(exc)]})
            return 2
    workflow = _patch_workflow(args, store, task_id)
    try:
        out = workflow.test(args.patch_id,
                            timeout=args.timeout or None,
                            keep_run=bool(args.keep_run))
    except PatchError as exc:
        _print_json({"status": "blocked", "reasons": [str(exc)]})
        return 2
    _print_json(out)
    return 0 if out.get("status") == "passed" else 1


def cmd_patch_review(args) -> int:
    from agent.platform.adaptive.patch import PatchError, PatchWorkflow

    store = _db(args)
    root = _patch_root(args, store)
    task_id = args.task_id
    if not task_id:
        try:
            task_id, _ = PatchWorkflow.find(root, args.patch_id)
        except PatchError as exc:
            _print_json({"status": "rejected", "reasons": [str(exc)]})
            return 2
    workflow = _patch_workflow(args, store, task_id)
    try:
        out = workflow.review(args.patch_id)
    except PatchError as exc:
        _print_json({"status": "rejected", "reasons": [str(exc)]})
        return 2
    _print_json(out)
    return 0 if out.get("accepted") else 1


def cmd_patch_rollback(args) -> int:
    from agent.platform.adaptive.patch import PatchError, PatchWorkflow

    store = _db(args)
    root = _patch_root(args, store)
    task_id = args.task_id
    if not task_id:
        try:
            task_id, _ = PatchWorkflow.find(root, args.patch_id)
        except PatchError as exc:
            _print_json({"status": "refused", "reasons": [str(exc)]})
            return 2
    workflow = _patch_workflow(args, store, task_id)
    try:
        out = workflow.rollback(args.patch_id)
    except PatchError as exc:
        _print_json({"status": "refused", "reasons": [str(exc)]})
        return 2
    _print_json(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="platform",
                                description="V2 任务运行时（P0–P3.7）")
    p.add_argument("--db", default="", help=f"SQLite 路径（默认 {DEFAULT_DB}）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("submit", help="提交任务（RECEIVED）")
    s.add_argument("--benchmark", required=True,
                   choices=["cybergym", "exploitgym", "vulngym", "target_yaml"])
    s.add_argument("--target", required=True, help="目标路径或 http(s) URL")
    s.add_argument("--task-id", default="")
    s.add_argument("--prefix", default="task")
    s.add_argument("--mode", default="fuzz")
    s.add_argument("--budget-seconds", type=int, default=3600)
    s.add_argument("--budget-execs", type=int, default=1_000_000)
    s.add_argument("--budget-tokens", type=int, default=2_000_000)
    s.add_argument("--budget-turns", type=int, default=40)
    s.add_argument("--meta", action="append", default=[], metavar="K=V")
    s.set_defaults(func=cmd_submit)

    for name, fn, help_ in (("preflight", cmd_preflight, "准入检查（PREFLIGHT→READY/BLOCKED）"),
                            ("status", cmd_status, "任务状态 + 事件重放"),
                            ("events", cmd_events, "事件流（JSONL）"),
                            ("evidence", cmd_evidence, "证据列表"),
                            ("replay", cmd_replay, "仅重放状态机")):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("task_id")
        if name == "events":
            sp.add_argument("--after", type=int, default=0)
        sp.set_defaults(func=fn)

    ap_pack = sub.add_parser("autonomy-pack",
                             help="从平台事实生成自主运行包（只读平台库）")
    ap_pack.add_argument("task_id")
    ap_pack.add_argument("--pack", default="")
    ap_pack.add_argument("--event-cap", type=int, default=200)
    ap_pack.add_argument("--expected", default="",
                         help="保留答案路径；给出则立即独立校验")
    ap_pack.add_argument("--allow-assisted", action="store_true")
    ap_pack.set_defaults(func=cmd_autonomy_pack)

    un = sub.add_parser("understand", help="程序理解（READY→UNDERSTANDING，写 program.indexed）")
    un.add_argument("task_id")
    un.add_argument("--max-sources", type=int, default=0,
                    help="workspace 有界扫描源文件上限（0=默认 240）")
    un.add_argument("--max-call-sites", type=int, default=0,
                    help="落库调用点上限（0=默认 240）")
    un.add_argument("--unpack-cache", default="",
                    help="P3.7：源码包解包缓存根（默认 <workspace>/.unpacked，"
                         "缓存键为 repo-vul.tar.gz 的 sha256）")
    un.set_defaults(func=cmd_understand)

    hy = sub.add_parser("hypotheses", help="假设集（UNDERSTANDING→HYPOTHESES，≤8 条）")
    hy.add_argument("task_id")
    # 默认与 Discovery/D1.5 一致：优先 LLM，无 key 严格回退规则（F2）
    _llm = hy.add_mutually_exclusive_group()
    _llm.add_argument("--llm", action="store_true",
                      help="强制使用已配置的 D1.5 LLM（未配置仍回退规则并如实记录 no_key）")
    _llm.add_argument("--no-llm", action="store_true",
                      help="显式关闭 LLM：不发任何模型请求，只用确定性规则")
    hy.set_defaults(func=cmd_hypotheses)

    pg = sub.add_parser("program", help="打印已存储的 ProgramIndex")
    pg.add_argument("task_id")
    pg.set_defaults(func=cmd_program)

    pl = sub.add_parser("plan", help="实验规划（HYPOTHESES→PLANNED，写 plan.selected）")
    pl.add_argument("task_id")
    pl.add_argument("--seconds", type=float, default=0.0,
                    help="覆盖计划预算的执行秒数（0=按 target.yaml/默认）")
    pl.add_argument("--workers", type=int, default=0,
                    help="覆盖计划的 worker 数（0=按 target.yaml/默认）")
    pl.add_argument("--timeout", type=float, default=0.0,
                    help="覆盖计划的单次超时（0=默认 2s）")
    pl.set_defaults(func=cmd_plan)

    rn = sub.add_parser(
        "run", help="执行 Plan（PLANNED→RUNNING→CANDIDATE/NO_REPRO/"
                    "NEEDS_EVIDENCE/FAILED，预算超限→TERMINATED，运行中被 "
                    "cancel→CANCELLED；P3.7 replay、P3.9 static/dynamic 均已接通）")
    rn.add_argument("task_id")
    rn.add_argument("--seconds", type=float, default=0.0,
                    help="本次执行的秒数（0=用计划预算）")
    rn.add_argument("--workers", type=int, default=0,
                    help="本次执行的 worker 数（0=用计划预算）")
    rn.add_argument("--timeout", type=float, default=0.0,
                    help="本次执行的单次超时（0=用计划预算）")
    rn.add_argument("--tokens-used", type=int, default=0,
                    help="本次执行前已消耗的 token（参与 max_tokens 判定）")
    rn.add_argument("--kind", default="",
                    choices=["", "static", "dynamic", "fuzz", "replay"],
                    help="本次执行换用一种执行方式（不改写已存 Plan；空=按 plan.kind；"
                         "static=只读复核→NO_REPRO/NEEDS_EVIDENCE，"
                         "dynamic=VulnGym 两侧 HTTP 差分→CANDIDATE/NO_REPRO）")
    rn.add_argument("--replay-cmd", default="",
                    help="仅 replay 使用：重放命令模板，形如 python3 -c '...{poc}...'，"
                         "{poc} 替换为宿主 PoC 绝对路径；空则按 plan.inputs.replay.cmd "
                         "→ 环境变量 VULNMAP_REPLAY_CMD → docker 的顺序解析")
    rn.add_argument("--isolation", default="auto",
                    choices=["auto", "bwrap", "unshare", "container", "none"])
    rn.add_argument("--require-isolation", action="store_true",
                    help="隔离不可用时直接失败（不退回宿主执行）")
    rn.add_argument("--workdir", default="",
                    help="执行工作目录（默认 <db 目录>/work/<task>）")
    rn.add_argument("--evidence-root", default="",
                    help="内容寻址证据目录（默认 <db 目录>/evidence）")
    # ---- V3-P2C：研究循环（PLANNED → ResearchController → 映射终态）
    rn.add_argument("--research", action="store_true",
                    help="走研究循环（ResearchController：观察→诊断→改副本→构建/冒烟→"
                         "执行→停止），不再单次 run_execution；--kind/--replay-cmd 不参与")
    rn.add_argument("--max-rounds", type=int, default=0,
                    help="研究循环最多轮数（0=默认 6）")
    rn.add_argument("--campaign", default="",
                    help="研究 campaign（默认任务 benchmark；进绑定与语料分代）")
    rn.add_argument("--research-root", default="",
                    help="研究目录（默认 <db 目录>/research/<task>：ws/ work/ corpus/ research.json）")
    rn.add_argument("--research-origin", default="",
                    help="任务 overlay 的原件目录（默认 task.target 是目录时用它）")
    rn.add_argument("--build-cmd", default="",
                    help="overlay 构建命令（默认取 metadata.build_command；缺构建或冒烟命令"
                         "时不建副本，报告里写明原因）")
    rn.add_argument("--smoke-cmd", default="",
                    help="overlay 冒烟命令（默认取 metadata.smoke_command）")
    rn.set_defaults(func=cmd_run)

    cx = sub.add_parser("cancel", help="取消任务（RUNNING/PLANNED 及非终态 → CANCELLED）")
    cx.add_argument("task_id")
    cx.add_argument("--reason", default="", help="取消原因（写事件与终态原因）")
    cx.add_argument("--actor", default="cli", help="发起方（cli/api/…）")
    cx.add_argument("--evidence-root", default="",
                    help="内容寻址证据目录（默认 <db 目录>/evidence）")
    cx.set_defaults(func=cmd_cancel)

    bg = sub.add_parser("budget", help="只读：预算上限与已用额度（事件流推导）")
    bg.add_argument("task_id")
    bg.set_defaults(func=cmd_budget)

    cd = sub.add_parser("candidates", help="列出候选（state=new 等）")
    cd.add_argument("task_id")
    cd.add_argument("--state", default="", help="只列指定 state")
    cd.set_defaults(func=cmd_candidates)

    vf = sub.add_parser(
        "verify", help="独立验证（CANDIDATE→VERIFYING；按 benchmark 判据）")
    vf.add_argument("task_id")
    vf.add_argument("--candidate", default="", help="候选编号（默认 C1/首条）")
    vf.add_argument("--spec", default="",
                    help="证据 JSON（覆盖全部证据类参数；--execute 时也可带 runner 参数）")
    vf.add_argument("--evidence-root", default="",
                    help="内容寻址证据目录（默认 <db 目录>/evidence）")
    vf.add_argument("--input", default="", help="崩溃输入文件（两端口径共用）")
    vf.add_argument("--input-sha256", default="", help="声明的输入内容哈希")
    vf.add_argument("--crashed", dest="crashed", action="store_true", default=None,
                    help="显式声明 vul 端已崩溃")
    vf.add_argument("--vul-exit", type=int, default=None, help="vul 端退出码")
    vf.add_argument("--vul-log", default="", help="vul 端崩溃日志")
    vf.add_argument("--fix-exit", type=int, default=None, help="fix 端退出码")
    vf.add_argument("--fix-log", default="", help="fix 端日志")
    vf.add_argument("--flag", default="", help="ExploitGym 取到的 flag")
    vf.add_argument("--flag-file", default="", help="flag 证据文件")
    vf.add_argument("--expected-flag", default="", help="官方 flag（严格比对）")
    vf.add_argument("--exploit-exit", type=int, default=None,
                    help="ExploitGym 利用脚本退出码")
    vf.add_argument("--exploit-log", default="", help="ExploitGym 利用日志")
    vf.add_argument("--exploit-source", default="",
                    help="利用入口来源（默认 official_entry）")
    vf.add_argument("--baseline-status", type=int, default=None,
                    help="VulnGym 基线响应状态码")
    vf.add_argument("--baseline-file", default="", help="VulnGym 基线响应体")
    vf.add_argument("--baseline-sha256", default="", help="基线响应体内容哈希")
    vf.add_argument("--patched-status", type=int, default=None,
                    help="VulnGym 修补后响应状态码")
    vf.add_argument("--patched-file", default="", help="VulnGym 修补后响应体")
    vf.add_argument("--patched-sha256", default="", help="修补后响应体内容哈希")
    vf.add_argument("--expect-baseline-status", type=int, default=None)
    vf.add_argument("--expect-patched-status", type=int, action="append",
                    default=[], help="可重复：允许的修补后状态码")
    # ---- P3.5：现场执行（不传 --execute 时行为与 P3 完全一致）
    vf.add_argument("--execute", action="store_true",
                    help="用 benchmark runner 现场取证据（docker / socket / HTTP）")
    vf.add_argument("--runner", default="",
                    choices=["", "auto", "cybergym", "exploitgym", "vulngym"],
                    help="runner（默认按 benchmark 自动选；与 benchmark 不符直接拒绝）")
    vf.add_argument("--timeout", type=float, default=0.0,
                    help="单步超时秒数（0=runner 默认 60s）")
    vf.add_argument("--workdir", default="",
                    help="runner 工作目录（默认 <db 目录>/work/<task>/verify-<benchmark>-<n>）")
    vf.add_argument("--isolation", default="auto",
                    choices=["auto", "bwrap", "unshare", "none"],
                    help="宿主侧隔离包裹层（断网 + 只读根 + cap-drop）")
    vf.add_argument("--require-isolation", action="store_true",
                    help="隔离不可用直接失败（fail-closed）")
    vf.add_argument("--image-vul", default="", help="CyberGym vul 镜像")
    vf.add_argument("--image-fix", default="", help="CyberGym fix 镜像")
    vf.add_argument("--docker", default="", help="docker 可执行文件（默认 docker）")
    vf.add_argument("--cmd", action="append", default=[],
                    help="镜像内命令 argv（可重复，例如 --cmd /bin/sh --cmd -c --cmd ...）")
    vf.add_argument("--host", default="", help="ExploitGym 官方入口 host")
    vf.add_argument("--port", type=int, default=0, help="ExploitGym 官方入口 port")
    vf.add_argument("--exploit-cmd", default="",
                    help="本地利用命令（按 shell 规则拆分 argv）")
    vf.add_argument("--baseline-url", default="", help="VulnGym 基线 URL")
    vf.add_argument("--patched-url", default="", help="VulnGym 修补后 URL")
    # ---- P3.8：spec 自动生成（metadata / workspace task.json → runner spec）
    vf.add_argument("--auto", action="store_true",
                    help="从 task metadata / workspace task.json 自动生成 runner spec"
                         "（隐含 --execute；缺口落 needs_evidence）")
    vf.add_argument("--workspace", default="",
                    help="task.json 所在工作区（默认 task.target 是目录时用它）")
    vf.add_argument("--no-probe", action="store_true",
                    help="--auto 不探测本机（只做字段映射，不做镜像/服务可用性检查）")
    vf.set_defaults(func=cmd_verify)

    sm = sub.add_parser(
        "smoke",
        help="端到端 dry-run：生成 runner spec 并报告本机缺口"
             "（加 --record 才把结论落到 verifications）")
    sm.add_argument("cases", nargs="*", default=[],
                    help="案例编号（默认 CG-01 EG-02 VG-01）")
    sm.add_argument("--workspace-root", default=str(ROOT / "workspace"),
                    help="工作区根目录（默认 <repo>/workspace）")
    sm.add_argument("--execute", action="store_true",
                    help="对 spec 就绪的案例真的跑一次 runner")
    sm.add_argument("--record", action="store_true",
                    help="把本次结论落成 verifications 记录（仅 would_verify 落 "
                         "verified；needs_evidence/no_repro/rejected 原样落，"
                         "不写 confirmed）")
    sm.add_argument("--task-id", default="",
                    help="落账目标 task_id（默认取 task.json 的 task_id/case_id）")
    sm.add_argument("--run-id", default="",
                    help="本次 run 标识（默认按案例/任务/benchmark/spec 派生，"
                         "同一配方重复 record 覆盖同一条记录；要保留多次运行"
                         "历史就显式给不同的 id）")
    sm.add_argument("--ensure-task", action="store_true",
                    help="任务不存在时按 task.json 登记一条 RECEIVED 任务"
                         "（默认直接报错，不伪造任务）")
    sm.add_argument("--workdir", default="",
                    help="runner 工作目录（默认 <repo>/.platform/smoke）")
    sm.add_argument("--timeout", type=float, default=0.0,
                    help="单步超时秒数（0=runner 默认 60s）")
    sm.add_argument("--isolation", default="auto",
                    choices=["auto", "bwrap", "unshare", "none"],
                    help="宿主侧隔离包裹层")
    sm.add_argument("--require-isolation", action="store_true",
                    help="隔离不可用直接失败（fail-closed）")
    sm.add_argument("--docker", default="", help="docker 可执行文件（默认 docker）")
    sm.add_argument("--no-probe", action="store_true",
                    help="跳过本机探测（只看字段是否齐全）")
    sm.add_argument("--strict", action="store_true",
                    help="要求每个案例都真的 would_verify（否则退出码 1）")
    sm.set_defaults(func=cmd_smoke)

    vl = sub.add_parser("verifications", help="列出验证记录（P3）")
    vl.add_argument("task_id")
    vl.add_argument("--status", default="", choices=["", "verified", "other"],
                    help="verified=只要已成立；other=只要未成立")
    vl.set_defaults(func=cmd_verifications)

    rl = sub.add_parser("reviews", help="列出复核记录（P3）")
    rl.add_argument("task_id")
    rl.add_argument("--verdict", default="",
                    choices=["", "accept", "reject", "needs_evidence"])
    rl.set_defaults(func=cmd_reviews)

    rp = sub.add_parser("reports", help="列出 Case Pack 台账（reports 表）")
    rp.add_argument("task_id")
    rp.set_defaults(func=cmd_reports)

    # ---- V3-P4a：研究轮次的只读视图（与 API 共用 platform_research 解释器）
    rs = sub.add_parser(
        "research-status",
        help="只读：研究轮次（轮次/阶段/动作/结果/证据引用），"
             "0=有产物 1=没有研究轮次 2=任务不存在或产物不可用")
    rs.add_argument("task_id")
    rs.add_argument("--root", default="",
                    help="研究目录根（默认 <db 目录>；报告在 <root>/research/<task>/research.json）")
    rs.set_defaults(func=cmd_research_status)

    re_ = sub.add_parser(
        "research-events",
        help="只读：研究 session 的事件流（JSONL；--json 给整份文档）")
    re_.add_argument("task_id")
    re_.add_argument("--after", type=int, default=0, help="只取 seq>after 的事件")
    re_.add_argument("--limit", type=int, default=200, help="最多返回条数（上限 500）")
    re_.add_argument("--kind", default="",
                     help="事件前缀（research/exec）或完整事件类型")
    re_.add_argument("--json", action="store_true", help="输出整份视图文档而非 JSONL")
    re_.add_argument("--root", default="",
                     help="研究目录根（默认 <db 目录>）")
    re_.set_defaults(func=cmd_research_events)

    rv = sub.add_parser("review", help="独立复核（VERIFYING→REVIEW/NEEDS_EVIDENCE/REJECTED）")
    rv.add_argument("task_id")
    rv.add_argument("--verification", default="", help="验证编号（默认最近一条）")
    rv.add_argument("--evidence-root", default="")
    rv.set_defaults(func=cmd_review)

    cp = sub.add_parser("casepack", help="打包 Case Pack（REVIEW→REPORTED，--close 到 CLOSED）")
    cp.add_argument("task_id")
    cp.add_argument("--out", default="", help="输出目录（默认 <db 目录>/casepacks/<task>）")
    cp.add_argument("--evidence-root", default="")
    cp.add_argument("--close", action="store_true", help="打包后结案（REPORTED→CLOSED）")
    cp.set_defaults(func=cmd_casepack)

    at = sub.add_parser("attach", help="附加证据文件")
    at.add_argument("task_id")
    at.add_argument("path")
    at.add_argument("--kind", default="log")
    at.add_argument("--stage", default="")
    at.add_argument("--root", default=str(ROOT / ".platform" / "evidence"))
    at.set_defaults(func=cmd_attach)

    tr = sub.add_parser("transition", help="手动迁移（调试/补录）")
    tr.add_argument("task_id")
    tr.add_argument("--to", required=True)
    tr.add_argument("--reason", default="")
    tr.set_defaults(func=cmd_transition)

    # ---- V3-P5：可选补丁工作流（只在实验副本生成/测试，不自动应用）
    pt = sub.add_parser(
        "patch", help="可选补丁工作流（V3-P5）：生成/测试只在实验副本，不自动应用")
    psub = pt.add_subparsers(dest="patch_cmd", required=True)

    pp = psub.add_parser("propose", help="生成补丁提案（只写实验副本，原件不动）")
    pp.add_argument("task_id")
    pp.add_argument("--candidate", required=True, help="原始候选编号（finding 引用）")
    pp.add_argument("--source-root", default="",
                    help="源码树（默认 task.target；无源码 → unsupported）")
    pp.add_argument("--file", default="", help="被修改文件（--patched-file 时必填）")
    pp.add_argument("--line", type=int, required=True, help="根因行号（1 起）")
    pp.add_argument("--end-line", type=int, default=0)
    pp.add_argument("--function", default="")
    pp.add_argument("--claim", default="model_hypothesis",
                    choices=["observed", "upstream_assertion",
                             "synthesized_state", "model_hypothesis"])
    pp.add_argument("--argument", required=True, help="根因论证（>= 8 字符）")
    pp.add_argument("--evidence", action="append", default=[],
                    help="证据文件（可重复；现场算 sha256）")
    pp.add_argument("--verification", action="append", default=[],
                    help="既有 verify 编号（只读引用）")
    pp.add_argument("--diff", default="", help="统一 diff 文件")
    pp.add_argument("--patched-file", default="", help="改好后的整份文件（自动生成 diff）")
    pp.add_argument("--trigger-cmd", required=True,
                    help="触发命令（原版应非零退出、补丁应零退出）")
    pp.add_argument("--regression-cmd", action="append", default=[],
                    help="正常功能回归命令（补丁上应零退出，可重复）")
    pp.add_argument("--timeout", type=float, default=60.0)
    pp.add_argument("--strategy", default="", help="修复策略简述")
    pp.add_argument("--allow-large", action="store_true",
                    help="放宽 diff 行数上限（仍拒绝改测试/吞异常）")
    pp.add_argument("--patch-root", default="", help="补丁工件根（默认 <db 目录>/patch）")
    pp.add_argument("--db", default=argparse.SUPPRESS)
    pp.set_defaults(func=cmd_patch_propose)

    ptst = psub.add_parser("test", help="独立测试（原版触发/补丁不触发/回归/回滚）")
    ptst.add_argument("patch_id")
    ptst.add_argument("--task-id", default="")
    ptst.add_argument("--timeout", type=float, default=0.0)
    ptst.add_argument("--keep-run", action="store_true",
                      help="保留 run/ 下的独立副本（默认测完删除）")
    ptst.add_argument("--patch-root", default="")
    ptst.add_argument("--db", default=argparse.SUPPRESS)
    ptst.set_defaults(func=cmd_patch_test)

    prv = psub.add_parser("review", help="补丁复核（只判 patch_validation）")
    prv.add_argument("patch_id")
    prv.add_argument("--task-id", default="")
    prv.add_argument("--patch-root", default="")
    prv.add_argument("--db", default=argparse.SUPPRESS)
    prv.set_defaults(func=cmd_patch_review)

    prb = psub.add_parser("rollback", help="回滚实验副本并校验哈希（原件不参与）")
    prb.add_argument("patch_id")
    prb.add_argument("--task-id", default="")
    prb.add_argument("--patch-root", default="")
    prb.add_argument("--db", default=argparse.SUPPRESS)
    prb.set_defaults(func=cmd_patch_rollback)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
