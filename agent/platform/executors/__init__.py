"""V2 P2 执行编排：PLANNED → RUNNING → CANDIDATE / NO_REPRO / FAILED，
P3.6 增补：预算越限 → TERMINATED（`budget_*`），人工取消 → CANCELLED。

P3.7 增补：`kind=replay` 接通重放执行器（旧 PoC + 旧日志 → 候选 + 判据输入），
可用 `kind_override` 在**不篡改已存 Plan** 的前提下换执行方式（审计进 exec.started）。

P3.9 增补：`kind=static` / `kind=dynamic` 接通执行器，并把分派显式化——
- static：ProgramIndex + 假设集只读复核 → `static_review` 证据 → NO_REPRO /
  NEEDS_EVIDENCE（**永不** 产 Candidate，永不写结论字段）；
- dynamic：VulnGym 基线/修补 HTTP 行为差分 → `dynamic_diff` + `dynamic_spec`
  （可直接喂 `verify --spec`）→ Candidate / NO_REPRO；服务打不通/超时 →
  `DynamicExecError` → FAILED，并且失败前的证据（spec / runner 结果）照样落库；
- 分派表 `EXECUTORS`（fuzz / replay / static / dynamic）；表里没有的 kind
  一律 `executor_unavailable:<kind>` 失败（`exec_error` 证据 + `exec.finished`
  的 `blockers`），**不静默**换成别的执行方式。

职责边界：
- 状态迁移与事件只在这里发生（exec.started / exec.finished / candidate.created /
  budget.exceeded / task.terminated）；
- 执行细节在 executors.fuzz（包 Discovery D2）与 executors.replay（P3.7 重放），
  证据写 EvidenceStore，候选写 candidates；
- **预算强制**：执行前按事件流推出来的用量预检，越限直接 TERMINATED（PLANNED 态）；
  执行中把本次秒数截断到剩余额度，并把 `max_execs` / 截止时间 / 取消探针交给执行器
  在片边界判定，结束后按 fuzz stats 结算；越限写 `task.terminated`，绝不落 NO_REPRO；
- 失败（构建失败、隔离里目标起不来、执行器缺失、重放跑不动）一律
  exec.finished(outcome=failed) + `exec_error` 证据 + FAILED，不把“没跑起来”降级成 no_repro；
- 取消（RUNNING 被打成 CANCELLED）优先于一切的“结果升级”：exec.finished(outcome=cancelled)，
  不改状态、不产 no_repro；
- 单端执行（fuzz / replay）只产出 Candidate(state=new)，不在这里产出任何确认结论。
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Any, Mapping

from ..budget import BudgetExceeded, BudgetGuard, usage_from_events
from ..candidates import build_candidates
from ..evidence import EvidenceStore
from ..lifecycle import (EXEC_ERROR_KIND, EXEC_STATS_KIND, is_cancelled,
                         snapshot_evidence, terminate_budget)
from ..planner import Plan, PlanError
from ..program import ProgramIndex
from .dynamic import DynamicExecError, execute as execute_dynamic
from .fuzz import FuzzExecError, execute as execute_fuzz
from .replay import ReplayError, execute as execute_replay
from .static import StaticExecError, execute as execute_static

__all__ = ["DynamicExecError", "EXECUTORS", "FuzzExecError", "PlanError",
           "ReplayError", "StaticExecError", "executor_for",
           "executor_unavailable", "execute_dynamic", "execute_replay",
           "execute_static", "run_execution"]

#: kind → 执行器（显式分派表：新增 kind 必须在这里登记，否则 fail-closed）
EXECUTORS = {
    "fuzz": execute_fuzz,
    "replay": execute_replay,
    "static": execute_static,
    "dynamic": execute_dynamic,
}

#: P3.9：static 复核证据 / dynamic 差分证据（与 fuzz 的 crash_*、replay 的
#: replay_* 分开记，便于区分来源）
STATIC_REVIEW_KIND = "static_review"
DYNAMIC_SPEC_KIND = "dynamic_spec"
DYNAMIC_DIFF_KIND = "dynamic_diff"
DYNAMIC_INPUT_KIND = "dynamic_input"
DYNAMIC_LOG_KIND = "dynamic_log"


def executor_for(kind: str) -> str:
    """返回本次能用的执行器名；不可用则抛 `executor_unavailable:<kind>`。"""
    name = str(kind or "").strip()
    if name not in EXECUTORS:
        raise PlanError(executor_unavailable(name))
    return name


def executor_unavailable(kind: str) -> str:
    """不支持的 kind 的唯一词形（CLI/事件/证据都用它，不能各写一套）。"""
    available = ",".join(sorted(EXECUTORS))
    return (f"executor_unavailable:{kind or 'unknown'}"
            f"（kind 没有接通的执行器；可用: {available}）")


#: P3.7：重放证据的 kind（与 fuzz 的 crash_input/crash_log 分开记，便于区分来源）
REPLAY_INPUT_KIND = "replay_input"
REPLAY_LOG_KIND = "replay_log"
REPLAY_SPEC_KIND = "replay_spec"

_FUZZ_STATS_KEYS = ("execs", "crashes", "timeouts", "new_coverage_bits",
                    "workers", "first_crash_seconds", "corpus_files",
                    "crash_files", "setup_errors", "setup_error", "slices",
                    "stopped", "program_started", "input_processed",
                    "checkpoint_reached", "loaded_config_sha256")

#: V3 第 2 周：任务配置面。只有这一份文件允许被白名单变更加改写，
#: 执行器必须回报**它自己真的加载**的那一版（`loaded_config_sha256`）。
CONFIG_RELPATH = "config/active.json"
CONFIG_ACTIVE_SCHEMA = "vulnmap.active_config.v1"

#: 配置效果的四段事实（`exec.started` 写计划版本，`exec.finished` 写两版对比）
CONFIG_FACT_FIELDS = ("config_planned_sha256", "config_loaded_sha256",
                      "config_source", "config_effective")

#: 目标语义的三段事实（P1 拆分）。三者各自独立，**不许互相冒充**：
#: - `program_started`：目标进程真的起来了（能证明“跑过”，不证明“跑到哪”）；
#: - `input_processed`：输入真的被目标处理过（必须有探针/显式字段；execs>0 不算）；
#: - `checkpoint_reached`：目标分支/检查点命中（必须显式探针或显式字段）；
#:   `target_reached` 只是它的兼容别名，**不能**由 `coverage_bits`/`execs` 推出。
EXEC_PROBE_FIELDS = ("program_started", "input_processed", "checkpoint_reached")

#: 执行器因额度截断而停下的原因 → 预算键（同样落 TERMINATED，不冒充“预算内完成”）
_STOP_BUDGET_KEY = {"execs": "max_execs", "deadline": "max_seconds"}


def _exec_id(plan: Plan) -> str:
    return f"exec-{plan.sha256[:10]}-{secrets.token_hex(3)}"


def _stats_summary(stats: dict) -> dict:
    return {key: stats.get(key) for key in _FUZZ_STATS_KEYS}


def _base_result(task_id: str, exec_id: str, plan: Plan, state: str) -> dict:
    return {
        "task_id": task_id,
        "state": state,
        "exec_id": exec_id,
        "plan": plan.to_dict(),
        "candidates": [],
        "outcome": "",
    }


def _replay_summary(result: dict) -> dict:
    """`exec.finished` / `exec_stats` 里的 replay 段（只放执行事实）。"""
    pocs = result.get("poc") or {}
    replay = result.get("replay") or {}
    return {
        "poc_sha256": str(pocs.get("sha256") or ""),
        "exit_code": result.get("exit_code"),
        "method": str(replay.get("method") or ""),
        "source_log": str(replay.get("source_log") or ""),
        "crashed": bool(result.get("crashed")),
        "poc_source": str(replay.get("poc_source") or ""),
    }


def _static_summary(review: dict) -> dict:
    """`exec.finished` / `exec_stats` 里的 static 段（只放复核事实）。"""
    return {
        "status": str(review.get("outcome") or ""),
        "gaps": [str(g) for g in (review.get("gaps") or [])],
        "requests": int(review.get("requests") or 0),
    }


def _dynamic_summary(result: dict) -> dict:
    """`exec.finished` / `exec_stats` 里的 dynamic 段（只放两侧观测事实）。"""
    checks = result.get("checks") or {}
    return {
        "outcome": str(result.get("outcome") or ""),
        "runner": str((result.get("runner") or {}).get("runner") or "vulngym"),
        "baseline_status": checks.get("baseline_status"),
        "patched_status": checks.get("patched_status"),
        "baseline_body_sha256": str(checks.get("baseline_body_sha256") or ""),
        "patched_body_sha256": str(checks.get("patched_body_sha256") or ""),
        "baseline_closed": bool(checks.get("baseline_closed")),
        "patched_closed": bool(checks.get("patched_closed")),
        "differs": bool(checks.get("behavior_differs")),
        "blockers": [str(b) for b in (result.get("blockers") or [])],
    }


def _save_dynamic_candidates(task_id: str, exec_id: str, plan: Plan,
                             result: dict, store, bus,
                             evidence_root: Path) -> list[dict]:
    """把行为差分落成候选：输入=请求文档，主证据=差分日志。"""
    candidates = build_candidates(result["crashes"], task_id=task_id,
                                  exec_id=exec_id, plan_sha256=plan.sha256,
                                  build_sha256="")
    evidence = EvidenceStore(store, evidence_root)
    docs: list[dict] = []
    by_key = {(c["input_sha256"], c["stack_hash"]): c
              for c in result["crashes"]}
    for cand in candidates:
        crash = by_key.get((cand.input_sha256, cand.stack_hash))
        if crash is None:
            raise PlanError(
                f"{cand.id}: diff record disappeared during persistence")
        input_ref = evidence.put_bytes(
            task_id, DYNAMIC_INPUT_KIND, crash["input_bytes"],
            source_stage="RUNNING")
        log_ref = evidence.put_bytes(
            task_id, DYNAMIC_LOG_KIND,
            str(crash.get("log") or "").encode("utf-8"),
            source_stage="RUNNING")
        cand.detail["input_evidence_sha256"] = input_ref.sha256
        cand.detail["log_evidence_sha256"] = log_ref.sha256
        # 溯源必须是 dynamic：差分候选不能冒充 fuzz:d2 / replay
        cand.detail["source"] = "dynamic"
        cand.detail["dynamic"] = {
            "request": dict(result.get("diff", {}).get("request") or {}),
            "summary": dict(result.get("diff", {}).get("summary") or {}),
            "blockers": list(result.get("blockers") or []),
            "runner": str((result.get("runner") or {}).get("runner") or ""),
            "seconds": result.get("seconds"),
        }
        cand.evidence_sha256 = log_ref.sha256
        cand.validate()
        saved = store.save_candidate(cand)
        docs.append(saved)
        bus.emit(task_id, "candidate.created", stage="RUNNING", payload={
            "id": saved["id"],
            "task": task_id,
            "state": saved["state"],
            "crash_type": saved["crash_type"],
            "stack_hash": saved["stack_hash"],
            "input_sha256": saved["input_sha256"],
            "evidence_sha256": saved["evidence_sha256"],
            "exec_id": exec_id,
        })
    return docs


def _save_failure_records(task_id: str, records: dict, store,
                          evidence_root: Path) -> dict:
    """失败前拿到的证据（spec / runner 结果）照样落库，失败也要可复核。"""
    out: dict[str, str] = {}
    for kind, doc in (records or {}).items():
        try:
            ref = snapshot_evidence(store, task_id, str(kind), doc,
                                    evidence_root=evidence_root,
                                    source_stage="RUNNING")
        except Exception:                 # noqa: BLE001 - 证据写失败不盖原始错误
            continue
        out[str(kind)] = ref.sha256
    return out


def _save_replay_candidates(task_id: str, exec_id: str, plan: Plan, result: dict,
                            store, bus, evidence_root: Path) -> list[dict]:
    """把重放崩溃落成候选：输入存 `replay_input`、日志存 `replay_log`。"""
    replay = result.get("replay") or {}
    pocs = result.get("poc") or {}
    candidates = build_candidates(
        result["crashes"], task_id=task_id, exec_id=exec_id,
        plan_sha256=plan.sha256,
        build_sha256=str((result.get("build") or {}).get("sha256") or ""))
    evidence = EvidenceStore(store, evidence_root)
    docs: list[dict] = []
    by_key = {(c["input_sha256"], c["stack_hash"]): c
              for c in result["crashes"]}
    for cand in candidates:
        crash = by_key.get((cand.input_sha256, cand.stack_hash))
        if crash is None:
            raise PlanError(
                f"{cand.id}: crash record disappeared during persistence")
        input_ref = evidence.put_bytes(
            task_id, REPLAY_INPUT_KIND, crash["input_bytes"],
            source_stage="RUNNING")
        log_bytes = str(crash.get("log") or "").encode("utf-8")
        log_ref = evidence.put_bytes(
            task_id, REPLAY_LOG_KIND, log_bytes, source_stage="RUNNING")
        cand.detail["input_evidence_sha256"] = input_ref.sha256
        cand.detail["log_evidence_sha256"] = log_ref.sha256
        # 溯源必须是 replay：候选来自旧 PoC 重放，不能冒充 fuzz:d2
        cand.detail["source"] = "replay"
        cand.detail["replay"] = {
            "poc_source": str(replay.get("poc_source") or ""),
            "poc_sha256": str(pocs.get("sha256") or ""),
            "source_log": str(replay.get("source_log") or ""),
            "source_log_sha256": str(replay.get("source_log_sha256") or ""),
            "method": str(replay.get("method") or ""),
            "exit_code": result.get("exit_code"),
            "log_path": str(result.get("log_path") or ""),
        }
        cand.evidence_sha256 = log_ref.sha256
        cand.validate()
        saved = store.save_candidate(cand)
        docs.append(saved)
        bus.emit(task_id, "candidate.created", stage="RUNNING", payload={
            "id": saved["id"],
            "task": task_id,
            "state": saved["state"],
            "crash_type": saved["crash_type"],
            "stack_hash": saved["stack_hash"],
            "input_sha256": saved["input_sha256"],
            "evidence_sha256": saved["evidence_sha256"],
            "exec_id": exec_id,
        })
    return docs


def run_execution(task_id: str, store, bus, *, workdir: Path,
                  evidence_root: Path, seconds: float | None = None,
                  workers: int | None = None, timeout: float | None = None,
                  isolation: str = "auto",
                  require_isolation: bool = False,
                  tokens_used: int = 0,
                  kind_override: str | None = None,
                  replay_cmd: str | None = None,
                  config_path: Path | str | None = None,
                  config_planned_sha256: str = "") -> dict:
    """执行已选 Plan：读 PLANNED → RUNNING → 产候选/负结果/失败/终止/取消。

    `tokens_used`：本次执行前已消耗的 token（例如规划/假设阶段的 LLM 用量），
    只参与 max_tokens 判定，不写回任何记录。

    `kind_override`：本次执行换用另一种执行方式（`static/dynamic/fuzz/replay`），
    只影响本次运行，不改写已存 Plan；实际 kind 与覆盖值都写进 `exec.started`。
    `replay_cmd`：仅 replay 分支使用的重放命令模板（`{poc}` 替换为宿主 PoC 路径），
    其它分支忽略。
    """
    task = store.get_task(task_id)
    if task["state"] != "PLANNED":
        raise PlanError(f"run requires PLANNED, got {task['state']}")
    row = store.get_plan(task_id)
    if row is None:
        raise PlanError(f"no plan for {task_id}; run `plan` first")
    plan = Plan.from_dict(row["doc"])
    plan.validate()
    effective_kind = str(kind_override or plan.kind)
    replay_cmd = "" if replay_cmd in (None, "") else str(replay_cmd)

    workdir = Path(workdir)
    evidence_root = Path(evidence_root)
    exec_id = _exec_id(plan)

    # ---- V3 第 2 周：配置版本。计划版本只来自调用方/执行器将要加载的那份文件；
    # 实际加载版本只能由执行器回报（`_loaded_config_report`），缺失即 unknown。
    config_file = (Path(config_path) if config_path not in (None, "")
                   else workdir / CONFIG_RELPATH)
    planned_config = _norm_sha(config_planned_sha256) or config_file_sha256(config_file)

    def _config_payload(report: Any = None) -> dict:
        loaded, source = _loaded_config_report(report)
        return config_facts(planned_sha256=planned_config,
                            loaded_sha256=loaded, loaded_source=source)

    # ---- P3.6 执行前预算检查：还没开始跑，也不开 RUNNING
    usage = usage_from_events(store.list_events(task_id))
    usage["tokens"] = int(usage.get("tokens") or 0) + max(0, int(tokens_used or 0))
    guard = BudgetGuard(task["budget"], used=usage)
    guard.begin()
    try:
        guard.precheck(stage=task["state"])
    except BudgetExceeded as exc:
        terminated = terminate_budget(
            task_id, store, bus, guard=guard, reason=exc.reason,
            stage=task["state"], exec_id=exec_id, evidence_root=evidence_root,
            stats={}, error=str(exc),
            extra={"check": "pre", "tokens_used": int(tokens_used or 0)})
        out = _base_result(task_id, exec_id, plan, terminated["state"])
        out.update({"outcome": "budget_exceeded", "terminated": terminated,
                    "budget": guard.snapshot(), "seconds": 0.0,
                    "budget_used": None, "error": str(exc)})
        return out

    budget = dict(plan.budget)
    for name, value in (("seconds", seconds), ("workers", workers),
                        ("timeout", timeout)):
        if value is not None:
            budget[name] = value
    overrides = {name: value for name, value in
                 (("seconds", seconds), ("workers", workers),
                  ("timeout", timeout)) if value is not None}

    # 本次执行只能在剩余额度内跑：秒数夹紧 + 截止点 + exec 上限 + 取消探针
    requested_seconds = float(budget.get("seconds") or 0.0)
    capped_seconds = guard.cap_seconds(requested_seconds)
    budget["seconds"] = capped_seconds
    deadline = guard.deadline()
    max_execs = guard.remaining_execs()
    caps = {
        "requested_seconds": requested_seconds,
        "seconds": capped_seconds,
        "max_execs": max_execs,
        "remaining_seconds": round(guard.remaining_seconds(), 3),
        "tokens_used": int(tokens_used or 0),
    }

    store.transition(task_id, "RUNNING", reason=f"execution started: {exec_id}")
    bus.emit(task_id, "exec.started", stage="RUNNING", payload={
        "exec_id": exec_id,
        "kind": effective_kind,
        "kind_override": kind_override or "",
        "replay_cmd": replay_cmd,
        "benchmark": plan.benchmark,
        "target": plan.target,
        "budget": budget,
        "overrides": overrides,
        "caps": caps,
        "budget_usage_before": guard.live_usage(),
        "plan_sha256": plan.sha256,
        "workdir": str(workdir),
        "config_planned_sha256": planned_config,
        "config_load_path": str(config_file),
    })

    def _exec_stats_payload(stats: dict) -> dict:
        return _stats_summary(stats or {})

    try:
        if effective_kind not in EXECUTORS:
            raise PlanError(executor_unavailable(effective_kind))
        index_row = store.get_program_index(task_id)
        if index_row is None:
            raise PlanError(
                f"no ProgramIndex for {task_id}; run `understand` first")
        index = ProgramIndex.from_dict(index_row["doc"])
        hypotheses = store.list_hypotheses(task_id)

        if effective_kind == "static":
            # ---- P3.9 static：只读复核 → NO_REPRO / NEEDS_EVIDENCE（无候选）
            started = time.time()
            review = execute_static(plan.to_dict(), index, hypotheses,
                                    workdir=workdir / "static")
            elapsed = round(time.time() - started, 2)
            brief = _static_summary(review)
            review_ref = snapshot_evidence(
                store, task_id, STATIC_REVIEW_KIND,
                review.get("review") or {}, evidence_root=evidence_root,
                source_stage="RUNNING")
            stats_ref = snapshot_evidence(
                store, task_id, EXEC_STATS_KIND, {
                    "exec_id": exec_id,
                    "plan_sha256": plan.sha256,
                    "kind": "static",
                    "stopped": "completed",
                    "seconds": elapsed,
                    "budget": budget,
                    "caps": caps,
                    "static": dict(brief, review_sha256=review_ref.sha256),
                    "candidates": [],
                }, evidence_root=evidence_root, source_stage="RUNNING")

            guard.record(execs=int(review.get("requests") or 0))
            if is_cancelled(store, task_id):
                state = store.get_task(task_id)["state"]
                bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                    **exec_probe_facts({}, kind=effective_kind),
                    **_config_payload(review),
                    "exec_id": exec_id, "outcome": "cancelled",
                    "kind": effective_kind, "plan_sha256": plan.sha256,
                    "candidates": 0, "seconds": elapsed, "budget_used": None,
                    "build": None, "fuzz": {}, "static": dict(brief),
                    "coverage": {}, "evidence_sha256": stats_ref.sha256,
                    "budget_usage": guard.live_usage(),
                    "budget": guard.snapshot(),
                    "tokens": int(tokens_used or 0), "error": None,
                })
                out = _base_result(task_id, exec_id, plan, state)
                out.update({"outcome": "cancelled", "kind": effective_kind,
                            "seconds": elapsed, "static": dict(brief),
                            "candidates": [],
                            "evidence_sha256": stats_ref.sha256})
                return out

            target_state = ("NO_REPRO" if review["outcome"] == "no_repro"
                            else "NEEDS_EVIDENCE")
            bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                **exec_probe_facts({}, kind=effective_kind),
                **_config_payload(review),
                "exec_id": exec_id,
                "outcome": review["outcome"],
                "kind": effective_kind,
                "plan_sha256": plan.sha256,
                "candidates": 0,
                "seconds": elapsed,
                "budget_used": None,
                "build": None,
                "fuzz": {},
                "static": dict(brief),
                "coverage": {},
                "gaps": list(review.get("gaps") or []),
                "budget_usage": guard.live_usage(),
                "budget": guard.snapshot(),
                "evidence_sha256": stats_ref.sha256,
                "review_evidence_sha256": review_ref.sha256,
                "tokens": int(tokens_used or 0),
                "error": None,
            })
            store.transition(
                task_id, target_state,
                reason=(f"static review {exec_id}: {review['outcome']}"
                        + (f"（缺口 {len(review.get('gaps') or [])} 项）"
                           if review.get("gaps") else
                           "（静态事实未支撑任何假设，且无证据缺口）")))
            return {
                "task_id": task_id,
                "state": store.get_task(task_id)["state"],
                "exec_id": exec_id,
                "plan": plan.to_dict(),
                "outcome": review["outcome"],
                "kind": effective_kind,
                "kind_override": kind_override or "",
                "static": dict(brief),
                "review": review.get("review"),
                "gaps": list(review.get("gaps") or []),
                "review_evidence_sha256": review_ref.sha256,
                "evidence_sha256": stats_ref.sha256,
                "candidates": [],
                "budget": guard.snapshot(),
                "caps": caps,
                "seconds": elapsed,
            }

        if effective_kind == "dynamic":
            # ---- P3.9 dynamic：VulnGym 行为差分 → Candidate / NO_REPRO
            started = time.time()
            # 失败（配置缺口/服务打不通/超时）会带 records 抛上来：外层先把
            # spec/runner 结果落库再写 FAILED——失败也必须可复核。
            dyn = execute_dynamic(
                plan.to_dict(), index, hypotheses,
                workdir=workdir, timeout=timeout,
                isolation=isolation,
                require_isolation=require_isolation)
            elapsed = round(time.time() - started, 2)
            brief = _dynamic_summary(dyn)

            dyn_docs = _save_dynamic_candidates(
                task_id, exec_id, plan, dyn, store, bus, evidence_root)
            body_refs: list[str] = []
            body_evidence = EvidenceStore(store, evidence_root)
            for body in dyn.get("bodies") or []:
                ref = body_evidence.put_bytes(
                    task_id, str(body.get("kind") or "dynamic_body"),
                    body.get("data") or b"", source_stage="RUNNING")
                body_refs.append(ref.sha256)
            # 判据输入单独落一条证据：`verify --spec` 直接复用（不是结论）
            spec_ref = snapshot_evidence(
                store, task_id, DYNAMIC_SPEC_KIND, dyn.get("spec") or {},
                evidence_root=evidence_root, source_stage="RUNNING")
            diff_ref = snapshot_evidence(
                store, task_id, DYNAMIC_DIFF_KIND, dyn.get("diff") or {},
                evidence_root=evidence_root, source_stage="RUNNING")

            stats_ref = snapshot_evidence(
                store, task_id, EXEC_STATS_KIND, {
                    "exec_id": exec_id,
                    "plan_sha256": plan.sha256,
                    "kind": "dynamic",
                    "stopped": "completed",
                    "seconds": elapsed,
                    "budget": budget,
                    "caps": caps,
                    "dynamic": dict(brief, spec_sha256=spec_ref.sha256,
                                    diff_sha256=diff_ref.sha256,
                                    bodies=body_refs),
                    "candidates": [c["id"] for c in dyn_docs],
                }, evidence_root=evidence_root, source_stage="RUNNING")

            if is_cancelled(store, task_id):
                state = store.get_task(task_id)["state"]
                guard.record(execs=int(dyn.get("requests") or 0))
                bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                    **exec_probe_facts({}, kind=effective_kind),
                    **_config_payload(dyn),
                    "exec_id": exec_id, "outcome": "cancelled",
                    "kind": effective_kind, "plan_sha256": plan.sha256,
                    "candidates": len(dyn_docs), "seconds": elapsed,
                    "budget_used": None, "build": None, "fuzz": {},
                    "dynamic": dict(brief),
                    "coverage": {}, "evidence_sha256": stats_ref.sha256,
                    "budget_usage": guard.live_usage(),
                    "budget": guard.snapshot(),
                    "tokens": int(tokens_used or 0), "error": None,
                })
                out = _base_result(task_id, exec_id, plan, state)
                out.update({"outcome": "cancelled", "kind": effective_kind,
                            "seconds": elapsed, "dynamic": dict(brief),
                            "candidates": dyn_docs,
                            "evidence_sha256": stats_ref.sha256})
                return out

            exceeded: BudgetExceeded | None = None
            try:
                guard.absorb(execs=int(dyn.get("requests") or 0),
                             stage="running")
            except BudgetExceeded as exc:
                exceeded = exc

            outcome = ("candidate" if dyn_docs else "no_repro") \
                if exceeded is None else "budget_exceeded"
            bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                **exec_probe_facts({}, kind=effective_kind),
                **_config_payload(dyn),
                "exec_id": exec_id,
                "outcome": outcome,
                "kind": effective_kind,
                "plan_sha256": plan.sha256,
                "candidates": len(dyn_docs),
                "seconds": elapsed,
                "budget_used": None,
                "build": None,
                "fuzz": {},
                "dynamic": dict(brief),
                "coverage": {},
                "budget_usage": guard.live_usage(),
                "budget": guard.snapshot(),
                "evidence_sha256": stats_ref.sha256,
                "spec_evidence_sha256": spec_ref.sha256,
                "diff_evidence_sha256": diff_ref.sha256,
                "body_evidence_sha256": body_refs,
                "tokens": int(tokens_used or 0),
                "error": None if exceeded is None else str(exceeded),
            })

            if exceeded is not None:
                terminated = terminate_budget(
                    task_id, store, bus, guard=guard, reason=exceeded.reason,
                    stage="RUNNING", exec_id=exec_id,
                    evidence_root=evidence_root, stats={},
                    error=str(exceeded),
                    extra={"kind": "dynamic",
                           "candidates": [c["id"] for c in dyn_docs]})
                out = _base_result(task_id, exec_id, plan, terminated["state"])
                out.update({"outcome": "budget_exceeded", "kind": effective_kind,
                            "seconds": elapsed, "terminated": terminated,
                            "dynamic": dict(brief), "candidates": dyn_docs,
                            "budget": guard.snapshot(),
                            "evidence_sha256": stats_ref.sha256,
                            "error": str(exceeded)})
                return out

            target_state = "CANDIDATE" if dyn_docs else "NO_REPRO"
            store.transition(
                task_id, target_state,
                reason=(f"{len(dyn_docs)} candidates from dynamic diff {exec_id}"
                        if dyn_docs else
                        f"no behavior diff on both sides ({exec_id})"))
            return {
                "task_id": task_id,
                "state": store.get_task(task_id)["state"],
                "exec_id": exec_id,
                "plan": plan.to_dict(),
                "outcome": outcome,
                "kind": effective_kind,
                "kind_override": kind_override or "",
                "dynamic": dict(brief),
                "checks": dyn.get("checks"),
                "sides": dyn.get("sides"),
                "runner": dyn.get("runner"),
                "spec": dyn.get("spec"),
                "diff": dyn.get("diff"),
                "spec_evidence_sha256": spec_ref.sha256,
                "diff_evidence_sha256": diff_ref.sha256,
                "body_evidence_sha256": body_refs,
                "evidence_sha256": stats_ref.sha256,
                "candidates": dyn_docs,
                "budget": guard.snapshot(),
                "caps": caps,
                "seconds": elapsed,
            }

        if effective_kind == "replay":
            replay_started = time.time()
            replay = execute_replay(
                plan.to_dict(), index, hypotheses, workdir=workdir,
                replay_cmd=replay_cmd or None, timeout=timeout,
                isolation=isolation, require_isolation=require_isolation)
            replay_stats = replay.get("stats") or {}
            replay_elapsed = round(time.time() - replay_started, 2)
            replay_stopped = str(replay_stats.get("stopped") or "completed")
            replay_brief = _replay_summary(replay)

            replay_docs = _save_replay_candidates(
                task_id, exec_id, plan, replay, store, bus, evidence_root)
            # 判据输入单独落一条证据：`verify --spec` 可直接复用（不是结论）
            spec_ref = snapshot_evidence(
                store, task_id, REPLAY_SPEC_KIND,
                (replay.get("replay") or {}).get("spec") or {},
                evidence_root=evidence_root, source_stage="RUNNING")
            replay.setdefault("replay", {})["spec_evidence_sha256"] = spec_ref.sha256
            replay_brief["spec_evidence_sha256"] = spec_ref.sha256

            replay_stats_ref = snapshot_evidence(
                store, task_id, EXEC_STATS_KIND, {
                    "exec_id": exec_id,
                    "plan_sha256": plan.sha256,
                    "stopped": replay_stopped,
                    "seconds": replay_elapsed,
                    "budget": budget,
                    "caps": caps,
                    "fuzz": {},
                    "replay": dict(replay_brief),
                    "coverage": replay.get("coverage") or {},
                    "candidates": [c["id"] for c in replay_docs],
                }, evidence_root=evidence_root, source_stage="RUNNING")

            cancelled = (replay_stopped == "cancelled"
                         or is_cancelled(store, task_id))
            if cancelled:
                state = store.get_task(task_id)["state"]
                bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                    **exec_probe_facts({}, kind=effective_kind),
                    **_config_payload(replay),
                    "exec_id": exec_id,
                    "outcome": "cancelled",
                    "kind": effective_kind,
                    "plan_sha256": plan.sha256,
                    "candidates": len(replay_docs),
                    "seconds": replay_elapsed,
                    "budget_used": None,
                    "build": None,
                    "fuzz": {},
                    "replay": dict(replay_brief),
                    "coverage": replay.get("coverage") or {},
                    "evidence_sha256": replay_stats_ref.sha256,
                    "tokens": int(tokens_used or 0),
                    "error": None,
                })
                out = _base_result(task_id, exec_id, plan, state)
                out.update({"outcome": "cancelled", "seconds": replay_elapsed,
                            "budget": guard.snapshot(), "fuzz": {},
                            "replay": dict(replay_brief),
                            "candidates": replay_docs,
                            "evidence_sha256": replay_stats_ref.sha256})
                return out

            replay_exceeded: BudgetExceeded | None = None
            try:
                guard.absorb(execs=int(replay_stats.get("execs") or 0),
                             stage="running")
            except BudgetExceeded as exc:
                replay_exceeded = exc

            replay_outcome = ("candidate" if replay_docs else "no_repro") \
                if replay_exceeded is None else "budget_exceeded"
            bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                **exec_probe_facts({}, kind=effective_kind),
                **_config_payload(replay),
                "exec_id": exec_id,
                "outcome": replay_outcome,
                "kind": effective_kind,
                "plan_sha256": plan.sha256,
                "candidates": len(replay_docs),
                "seconds": replay_elapsed,
                "budget_used": None,
                "build": {"sha256": (replay.get("build") or {}).get("sha256"),
                          "harness": (replay.get("build") or {}).get("harness")},
                "fuzz": {},
                "replay": dict(replay_brief),
                "coverage": replay.get("coverage") or {},
                "budget_usage": guard.live_usage(),
                "budget": guard.snapshot(),
                "evidence_sha256": replay_stats_ref.sha256,
                "tokens": int(tokens_used or 0),
                "error": None if replay_exceeded is None else str(replay_exceeded),
            })

            if replay_exceeded is not None:
                terminated = terminate_budget(
                    task_id, store, bus, guard=guard,
                    reason=replay_exceeded.reason, stage="RUNNING",
                    exec_id=exec_id, evidence_root=evidence_root, stats={},
                    error=str(replay_exceeded),
                    extra={"stopped": replay_stopped,
                           "candidates": [c["id"] for c in replay_docs]})
                out = _base_result(task_id, exec_id, plan, terminated["state"])
                out.update({"outcome": "budget_exceeded",
                            "seconds": replay_elapsed, "terminated": terminated,
                            "budget": guard.snapshot(), "fuzz": {},
                            "replay": dict(replay_brief),
                            "candidates": replay_docs,
                            "evidence_sha256": replay_stats_ref.sha256,
                            "error": str(replay_exceeded)})
                return out

            replay_target = "CANDIDATE" if replay_docs else "NO_REPRO"
            store.transition(
                task_id, replay_target,
                reason=(f"{len(replay_docs)} candidates from replay {exec_id}"
                        if replay_docs
                        else f"no crash on replay within budget ({exec_id})"))
            return {
                "task_id": task_id,
                "state": store.get_task(task_id)["state"],
                "exec_id": exec_id,
                "plan": plan.to_dict(),
                "outcome": replay_outcome,
                "kind": effective_kind,
                "kind_override": kind_override or "",
                "budget": guard.snapshot(),
                "caps": caps,
                "build": replay.get("build"),
                "fuzz": {},
                "replay": replay.get("replay"),
                "replay_summary": dict(replay_brief),
                "poc": replay.get("poc"),
                "command": replay.get("command"),
                "exit_code": replay.get("exit_code"),
                "crashed": replay.get("crashed"),
                "crash_type": replay.get("crash_type"),
                "log_path": replay.get("log_path"),
                "stats": replay_stats,
                "coverage": replay.get("coverage"),
                "candidates": replay_docs,
                "seconds": replay_elapsed,
                "spec_evidence_sha256": spec_ref.sha256,
            }

        started = time.time()
        result = execute_fuzz(
            plan.to_dict(), index, hypotheses, workdir=workdir,
            seconds=capped_seconds, workers=workers, timeout=timeout,
            isolation=isolation, require_isolation=require_isolation,
            max_execs=max_execs, deadline=deadline,
            should_stop=lambda: is_cancelled(store, task_id))

        stats = result.get("stats") or {}
        stopped = str(stats.get("stopped") or "completed")

        candidates = build_candidates(
            result["crashes"], task_id=task_id, exec_id=exec_id,
            plan_sha256=plan.sha256,
            build_sha256=str((result.get("build") or {}).get("sha256") or ""))
        evidence = EvidenceStore(store, evidence_root)
        docs: list[dict] = []
        by_key = {(c["input_sha256"], c["stack_hash"]): c
                  for c in result["crashes"]}
        for cand in candidates:
            crash = by_key.get((cand.input_sha256, cand.stack_hash))
            if crash is None:
                raise PlanError(
                    f"{cand.id}: crash record disappeared during persistence")
            input_ref = evidence.put_bytes(
                task_id, "crash_input", crash["input_bytes"],
                source_stage="RUNNING")
            log_bytes = str(crash.get("log") or "").encode("utf-8")
            log_ref = evidence.put_bytes(
                task_id, "crash_log", log_bytes, source_stage="RUNNING")
            cand.detail["input_evidence_sha256"] = input_ref.sha256
            cand.detail["log_evidence_sha256"] = log_ref.sha256
            cand.evidence_sha256 = log_ref.sha256
            cand.validate()
            saved = store.save_candidate(cand)
            docs.append(saved)
            bus.emit(task_id, "candidate.created", stage="RUNNING", payload={
                "id": saved["id"],
                "task": task_id,
                "state": saved["state"],
                "crash_type": saved["crash_type"],
                "stack_hash": saved["stack_hash"],
                "input_sha256": saved["input_sha256"],
                "evidence_sha256": saved["evidence_sha256"],
                "exec_id": exec_id,
            })

        elapsed = round(time.time() - started, 2)
        # 执行统计快照永远留证（取消/超限/失败都要能事后复核跑了什么）
        stats_ref = snapshot_evidence(
            store, task_id, EXEC_STATS_KIND, {
                "exec_id": exec_id,
                "plan_sha256": plan.sha256,
                "stopped": stopped,
                "seconds": elapsed,
                "budget": budget,
                "caps": caps,
                "fuzz": _exec_stats_payload(stats),
                "coverage": result.get("coverage") or {},
                "candidates": [c["id"] for c in docs],
            }, evidence_root=evidence_root, source_stage="RUNNING")

        # ---- P3.6 取消优先：状态已被打成 CANCELLED 就不再升级结果
        cancelled = stopped == "cancelled" or is_cancelled(store, task_id)
        if cancelled:
            state = store.get_task(task_id)["state"]
            guard.record(execs=int(stats.get("execs") or 0))
            bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
                **exec_probe_facts(stats),
                **_config_payload(stats),
                "exec_id": exec_id,
                "outcome": "cancelled",
                "kind": effective_kind,
                "plan_sha256": plan.sha256,
                "candidates": len(docs),
                "seconds": elapsed,
                "budget_used": result.get("budget"),
                "build": None,
                "fuzz": _exec_stats_payload(stats),
                "coverage": result.get("coverage") or {},
                "evidence_sha256": stats_ref.sha256,
                "budget_usage": guard.live_usage(),
                "budget": guard.snapshot(),
                "tokens": int(tokens_used or 0),
                "error": None,
            })
            out = _base_result(task_id, exec_id, plan, state)
            out.update({"outcome": "cancelled", "seconds": elapsed,
                        "budget": guard.snapshot(),
                        "fuzz": _exec_stats_payload(stats),
                        "candidates": docs,
                        "evidence_sha256": stats_ref.sha256})
            return out

        # ---- P3.6 执行中预算结算：fuzz stats 超限 / 被额度截断 → TERMINATED
        exceeded: BudgetExceeded | None = None
        try:
            guard.absorb(execs=int(stats.get("execs") or 0),
                         stage="running")
        except BudgetExceeded as exc:
            exceeded = exc
        if exceeded is None and stopped in _STOP_BUDGET_KEY:
            key = _STOP_BUDGET_KEY[stopped]
            exceeded = BudgetExceeded(
                key, limit=guard.budget[key], used=guard.live_usage()[
                    key.split("_", 1)[1]],
                stage="running",
                detail=f"executor stopped on {stopped} cap")

        outcome = ("candidate" if docs else "no_repro") if exceeded is None \
            else "budget_exceeded"
        bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
            **exec_probe_facts(stats),
            **_config_payload(result),
            "exec_id": exec_id,
            "outcome": outcome,
            "kind": effective_kind,
            "plan_sha256": plan.sha256,
            "candidates": len(docs),
            "seconds": elapsed,
            "budget_used": result.get("budget"),
            "build": {"sha256": (result.get("build") or {}).get("sha256"),
                      "harness": (result.get("build") or {}).get("harness")},
            "fuzz": _exec_stats_payload(stats),
            "coverage": result.get("coverage") or {},
            "seeds": result.get("seeds"),
            "dictionary_tokens": result.get("dictionary_tokens"),
            "format": result.get("format"),
            "budget_usage": guard.live_usage(),
            "budget": guard.snapshot(),
            "evidence_sha256": stats_ref.sha256,
            "tokens": int(tokens_used or 0),
            "error": None if exceeded is None else str(exceeded),
        })

        if exceeded is not None:
            terminated = terminate_budget(
                task_id, store, bus, guard=guard, reason=exceeded.reason,
                stage="RUNNING", exec_id=exec_id,
                evidence_root=evidence_root, stats=_exec_stats_payload(stats),
                error=str(exceeded),
                extra={"stopped": stopped, "candidates": [c["id"] for c in docs]})
            out = _base_result(task_id, exec_id, plan, terminated["state"])
            out.update({"outcome": "budget_exceeded", "seconds": elapsed,
                        "terminated": terminated,
                        "budget": guard.snapshot(),
                        "fuzz": _exec_stats_payload(stats),
                        "candidates": docs,
                        "evidence_sha256": stats_ref.sha256,
                        "error": str(exceeded)})
            return out

        target_state = "CANDIDATE" if docs else "NO_REPRO"
        reason = (f"{len(docs)} candidates from {exec_id}" if docs
                  else f"no crash within budget ({exec_id})")
        store.transition(task_id, target_state, reason=reason)
        return {
            "task_id": task_id,
            "state": store.get_task(task_id)["state"],
            "exec_id": exec_id,
            "plan": plan.to_dict(),
            "outcome": outcome,
            "budget_used": {"seconds": result.get("budget", {}).get("seconds"),
                            "workers": result.get("budget", {}).get("workers"),
                            "timeout": result.get("budget", {}).get("timeout")},
            "budget": guard.snapshot(),
            "caps": caps,
            "build": result.get("build"),
            "format": result.get("format"),
            "seeds": result.get("seeds"),
            "dictionary_tokens": result.get("dictionary_tokens"),
            "fuzz": _exec_stats_payload(stats),
            "coverage": result.get("coverage"),
            "candidates": docs,
            "paths": result.get("paths"),
            "seconds": elapsed,
        }
    except Exception as exc:  # noqa: BLE001 - 失败要落事件与证据并保留状态
        error = f"{type(exc).__name__}: {exc}"
        # 失败前执行器已经拿到的证据（dynamic 的 spec / runner 结果）先落库
        kept = _save_failure_records(
            task_id, getattr(exc, "records", {}) or {}, store, evidence_root)
        blocker = ""
        if effective_kind not in EXECUTORS:
            blocker = f"executor_unavailable:{effective_kind}"
        ref = None
        try:
            ref = snapshot_evidence(
                store, task_id, EXEC_ERROR_KIND, {
                    "exec_id": exec_id,
                    "kind": effective_kind,
                    "plan_sha256": plan.sha256,
                    "error": error,
                    "type": type(exc).__name__,
                    "blocker": blocker,
                    "evidence": dict(kept),
                    "budget": guard.snapshot(),
                    "stage": store.get_task(task_id)["state"],
                }, evidence_root=evidence_root, source_stage="RUNNING")
        except Exception:  # noqa: BLE001 - 证据写失败不能盖掉原始错误
            ref = None
        bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
            **exec_probe_facts({}, kind=effective_kind),
            **_config_payload(None),
            "exec_id": exec_id,
            "outcome": "failed",
            "kind": effective_kind,
            "plan_sha256": plan.sha256,
            "candidates": 0,
            "seconds": None,
            "build": None,
            "fuzz": None,
            "coverage": None,
            "evidence_sha256": ref.sha256 if ref is not None else "",
            "evidence": dict(kept),
            "blockers": [blocker] if blocker else [],
            "tokens": int(tokens_used or 0),
            "error": error,
        })
        state = store.get_task(task_id)["state"]
        if state == "RUNNING":
            store.transition(task_id, "FAILED",
                             reason=f"execution failed: {error}")
        raise


# ====================================================================== 目标语义
def _tri_bool(value: Any) -> bool | None:
    """只接受真正的 bool：其余（None/缺失/字符串/数字）一律 None（=unknown）。"""
    return value if isinstance(value, bool) else None


def exec_probe_facts(stats: dict | None = None, *, kind: str = "fuzz") -> dict:
    """把执行期统计归一成目标语义三段事实（写进 `exec.finished` 的唯一出口）。

    规则（V3 P1「目标语义拆分」）：

    1. **显式优先**：执行器自己在统计里给出 `program_started` /
       `input_processed` / `checkpoint_reached`（bool）时，原样采用；
    2. **fuzz 只补 `program_started`**：`execs > 0` 证明目标进程至少真的跑过一次；
       `execs == 0` 且带 `setup_error` 证明目标没起来 → `false`；其余 → `None`；
    3. **`input_processed` / `checkpoint_reached` 绝不默认**：fuzz 执行器不提供探针，
       就只能是 `None`（快照层记 `unknown`），**不能**用 `execs>0`、
       `new_coverage_bits>0`、崩溃数或覆盖读数冒充；
    4. `target_reached` 是 `checkpoint_reached` 的兼容别名，只由它派生。
    """
    stats = dict(stats or {})
    facts = {name: _tri_bool(stats.get(name)) for name in EXEC_PROBE_FIELDS}
    if facts["program_started"] is None and str(kind or "") == "fuzz":
        execs = stats.get("execs")
        if isinstance(execs, int) and not isinstance(execs, bool):
            if execs > 0:
                facts["program_started"] = True
            elif str(stats.get("setup_error") or ""):
                # 隔离里目标从没起来：这是“启动失败”的显式证据，不是 0 execs 的猜测
                facts["program_started"] = False
    facts["target_reached"] = facts["checkpoint_reached"]
    return facts


# ====================================================================== 配置效果
def _norm_sha(value: Any) -> str:
    """只认 64 位十六进制哈希；其余（空/None/半截字符串）一律空 = 没观测到。"""
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        return ""
    return text


def config_doc_sha256(doc: Any) -> str:
    """规范化 JSON 的 sha256 = 配置版本（语义哈希，与缩进/键顺序无关）。

    配置身份与执行器回报的「实际加载版本」必须用同一个函数算，否则两边永远对不上：
    同一个配置对象，谁写、写成几行，都得到同一个哈希。
    """
    if not isinstance(doc, dict):
        return ""
    try:
        body = json.dumps(doc, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError):
        return ""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def config_raw_sha256(raw: bytes | str | None) -> str:
    """把配置文件的**字节**解析成对象再取语义哈希；不是 JSON 对象就返回空。"""
    if raw is None:
        return ""
    try:
        doc = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return ""
    return config_doc_sha256(doc)


def config_file_sha256(path: Path | str | None) -> str:
    """读配置文件的语义哈希；文件缺失/不可读/不是 JSON 对象 → 空（没观测到）。"""
    if path in (None, ""):
        return ""
    try:
        return config_raw_sha256(Path(path).read_bytes())
    except OSError:
        return ""


def config_facts(*, planned_sha256: Any = "", loaded_sha256: Any = "",
                 loaded_source: str = "") -> dict:
    """计划版本 vs 实际加载版本 → 四段事实（三值，缺一律 unknown）。

    规则（唯一出口；`loaded` 缺失**绝不**回填 `planned`）：

    | planned | loaded | config_effective | config_source |
    |---|---|---|---|
    | 有 | 有且相等 | True | reported |
    | 有 | 有但不等 | False | reported |
    | 有 | 缺失 | None | loaded_unreported |
    | 缺失 | 任意 | None | planned_missing |

    「执行器没报实际加载版本」与「执行器报了同一版」是两件事：前者是没观测，
    后者是观测到生效。`config_effective=None` 只表示"不知道"，不是"没生效"。
    """
    planned = _norm_sha(planned_sha256)
    loaded = _norm_sha(loaded_sha256)
    source = str(loaded_source or "")
    if not planned:
        effective, source = None, "planned_missing"
    elif not loaded:
        effective, source = None, "loaded_unreported"
    else:
        effective = loaded == planned
        source = source or "reported"
    return {
        "config_planned_sha256": planned,
        "config_loaded_sha256": loaded,
        "config_source": source,
        "config_effective": effective,
    }


def config_effect_view(start: dict | None = None,
                       finish: dict | None = None) -> dict:
    """把 `exec.started` / `exec.finished` 归一成配置效果视图（只读、纯函数）。

    `planned` 先读 start 再读 finish；`loaded` **只**读 finish
    （顶层 `config_loaded_sha256`，或 fuzz 统计里的 `loaded_config_sha256`）——
    执行器没回报就是 `unknown`，不拿计划版本凑数。
    `config_status` 是给人看的词形：`effective` / `not_effective` / `unknown`。
    """
    s = dict(start or {})
    f = dict(finish or {})
    fuzz = dict(f.get("fuzz") or {})
    planned = _norm_sha(s.get("config_planned_sha256")
                        or f.get("config_planned_sha256"))
    loaded = _norm_sha(f.get("config_loaded_sha256")
                       or fuzz.get("loaded_config_sha256"))
    facts = config_facts(planned_sha256=planned, loaded_sha256=loaded)
    effective = facts["config_effective"]
    status = ("effective" if effective is True else
              "not_effective" if effective is False else "unknown")
    return {
        **facts,
        "config_status": status,
        "config_present": {"planned": bool(planned), "loaded": bool(loaded)},
        "config_load_path": str(s.get("config_load_path")
                                or f.get("config_load_path") or ""),
    }


def _loaded_config_report(payload: Any) -> tuple[str, str]:
    """从执行器返回值/统计里取「实际加载版本」；取不到就是空（不猜）。

    执行器可以写在顶层（`loaded_config_sha256`）、`fuzz` 段或 `stats` 段
    （fuzz 执行器原样返回 `stats`）。三处都没有 = 执行器没回报 = unknown，
    **绝不**回落到计划版本。
    """
    doc = dict(payload or {}) if isinstance(payload, Mapping) else {}
    direct = _norm_sha(doc.get("loaded_config_sha256"))
    if direct:
        return direct, "reported"
    for key, label in (("fuzz", "reported_fuzz_stats"),
                       ("stats", "reported_executor_stats")):
        block = doc.get(key) if isinstance(doc.get(key), Mapping) else {}
        nested = _norm_sha((block or {}).get("loaded_config_sha256"))
        if nested:
            return nested, label
    return "", ""


# ====================================================================== 只读钩子
#: V3 P2a：执行事实的字段名单。`adaptive.snapshot` 只读这两类事件的 payload，
#: 字段名与语义**只在这里声明一处**，避免“快照层各写一套字段名”。
#: 新增执行事件字段时同步本表（tests/test_v3_p2_contracts.py 会对账）。
EXEC_FACT_FIELDS = {
    "start": ("exec_id", "kind", "kind_override", "plan_sha256", "benchmark",
              "target", "budget", "caps", "workdir", "policy_version",
              "sanitizer", "isolation", "network", "cmd", "image",
              "config_planned_sha256", "config_load_path"),
    "finish": ("exec_id", "kind", "plan_sha256", "outcome", "seconds", "build",
               "fuzz", "coverage", "candidates", "budget_usage", "budget",
               "evidence_sha256", "error", "seeds", "dictionary_tokens",
               "format", "tokens", "stack_hashes", "crash_type", "setup_error",
               "baseline_id", "program_started", "input_processed",
               "checkpoint_reached", "target_reached", "image",
               "config_planned_sha256", "config_loaded_sha256",
               "config_source", "config_effective", "config_load_path"),
    "fuzz": _FUZZ_STATS_KEYS,
}


def execution_fact_view(start: dict | None = None,
                        finish: dict | None = None) -> dict:
    """把 `exec.started` / `exec.finished` 的 payload 归一成只读事实视图。

    只读：不写事件、不改状态、不产生证据，纯函数，可安全用于快照/查询层。
    缺失字段一律 `None`（**不是 0/False**）——由快照层决定 unknown 语义。
    另外给出 `present` / `flags`，用来区分“字段确实观测到空值”与“根本没这个字段”
    （例如 `error=None` 与“事件里没有 error 字段”是两件事）。

    目标语义（P1 拆分）：`program_started` / `input_processed` /
    `checkpoint_reached` 三段**只从事件里的显式 bool 读**（fuzz 的 `execs`
    等统计由 `exec_probe_facts()` 在执行侧先归一，这里不再做任何推断）。
    `target_reached` 是 `checkpoint_reached` 的兼容别名：事件里写了旧字段
    （没有新字段）时映射到 `checkpoint_reached`，`target_reached_source` 说明来源；
    两个都没有就是 `None`（unknown），**绝不会**由 `coverage_bits`/`execs` 推出。
    """
    s = dict(start or {})
    f = dict(finish or {})
    fuzz = dict(f.get("fuzz") or {})
    coverage = dict(f.get("coverage") or {})
    build = dict(f.get("build") or {})
    kind = str(s.get("kind") or f.get("kind") or "")
    # 统计侧归一（同一套规则）：fuzz 的 execs>0 只能补 program_started；
    # 执行器显式写在 fuzz 统计里的探针字段也在这里被采用。
    stats_probe = exec_probe_facts(fuzz, kind=kind or "fuzz")
    program_started = _tri_bool(f.get("program_started"))
    if program_started is None:
        program_started = stats_probe["program_started"]
    input_processed = _tri_bool(f.get("input_processed"))
    if input_processed is None:
        input_processed = stats_probe["input_processed"]
    checkpoint = _tri_bool(f.get("checkpoint_reached"))
    if checkpoint is None:
        checkpoint = stats_probe["checkpoint_reached"]
    source = "checkpoint_reached" if checkpoint is not None else None
    legacy = _tri_bool(f.get("target_reached"))
    if checkpoint is None and legacy is not None:
        # 兼容旧执行器：旧字段就是“检查点命中”的旧拼写，映射过来而不是另开一套语义
        checkpoint = legacy
        source = "legacy_target_reached"
    return {
        "present": {"start": bool(start), "finish": bool(finish)},
        "flags": {
            "error_observed": "error" in f,
            "setup_error_observed": ("setup_error" in f
                                     or "setup_error" in fuzz),
            "stopped_observed": bool(fuzz.get("stopped")),
            "program_started_observed": program_started is not None,
            "input_processed_observed": input_processed is not None,
            "checkpoint_reached_observed": checkpoint is not None,
            "target_reached_observed": checkpoint is not None,
        },
        "execution_id": s.get("exec_id") or f.get("exec_id"),
        "kind": s.get("kind") or f.get("kind"),
        "kind_override": s.get("kind_override"),
        "plan_sha256": s.get("plan_sha256") or f.get("plan_sha256"),
        "benchmark": s.get("benchmark"),
        "target": s.get("target"),
        "workdir": s.get("workdir"),
        "policy_version": s.get("policy_version"),
        "sanitizer": s.get("sanitizer"),
        "isolation": s.get("isolation"),
        "network": s.get("network"),
        "command": s.get("cmd"),
        "image": s.get("image") or f.get("image"),
        "budget_declared": s.get("budget"),
        "caps": s.get("caps"),
        "outcome": f.get("outcome"),
        "seconds": f.get("seconds"),
        "build": build or None,
        "fuzz": fuzz or None,
        "coverage": coverage or None,
        "candidates": f.get("candidates"),
        "evidence_sha256": f.get("evidence_sha256"),
        "error": f.get("error"),
        "seeds": f.get("seeds"),
        "dictionary_tokens": f.get("dictionary_tokens"),
        "format": f.get("format"),
        "tokens": f.get("tokens"),
        "budget": dict(f.get("budget") or {}) or None,
        "budget_usage": dict(f.get("budget_usage") or {}) or None,
        "stack_hashes": f.get("stack_hashes"),
        "crash_type": f.get("crash_type"),
        "baseline_id": f.get("baseline_id"),
        "setup_error": f.get("setup_error", fuzz.get("setup_error")),
        "program_started": program_started,
        "input_processed": input_processed,
        "checkpoint_reached": checkpoint,
        "target_reached_source": source,
        # 配置效果（V3 第 2 周）：planned 来自执行侧将要加载的那份，loaded 只来自
        # 执行器回报——两者都不做推断，缺失即 None（快照层落 unknown）
        **config_effect_view(start, finish),
        # 兼容字段：只由 checkpoint_reached 派生，不参与任何统计推断
        "target_reached": checkpoint,
    }


__all__ = list(__all__) + ["EXEC_FACT_FIELDS", "EXEC_PROBE_FIELDS",
                           "CONFIG_FACT_FIELDS", "CONFIG_RELPATH",
                           "CONFIG_ACTIVE_SCHEMA", "config_doc_sha256",
                           "config_raw_sha256", "config_file_sha256",
                           "config_facts", "config_effect_view",
                           "exec_probe_facts", "execution_fact_view"]
