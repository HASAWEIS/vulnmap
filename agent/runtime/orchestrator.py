"""编排器：状态机 + 迁移条件 + 检查点复用 + 运行摘要。"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import resolve as resolve_versions
from ..contracts import Budget, StageRequest
from ..paths import ensure_layout
from ..policy import policy_for
from ..stages import STAGE_MODULES
from ..store import Store
from ..util import atomic_write_json, short_hash

TRANSITIONS = {
    "recon": {"ok": "locate", "fail": "blocked"},
    "locate": {"ok": "verify", "fail": "blocked"},
    "verify": {"ok": "exploit", "fail": "locate"},
    "exploit": {"ok": "report", "fail": "report"},
    "report": {"ok": "done", "fail": "done"},
}

STAGE_ORDER = ("recon", "locate", "verify", "exploit", "report")


@dataclass
class RunOutcome:
    run_id: str
    status: str
    stages: dict
    results: dict
    seconds: float

    def to_json(self) -> dict:
        return {"run_id": self.run_id, "status": self.status, "stages": self.stages,
                "results": self.results, "seconds": round(self.seconds, 2)}


class Orchestrator:
    def __init__(self, workspace: Path, *, db_path: Path | None = None, budget: Budget | None = None):
        self.ws = Path(workspace).resolve()
        self.layout = ensure_layout(self.ws)
        db = db_path or (self.layout["runtime"] / "vulnmap.db")
        self.store = Store(db)
        self.budget = budget or Budget(max_turns=40, timeout_seconds=1800)
        self.task = self._load_task()
        self._persist_task_snapshot()
        self.stage_limit: list[str] | None = None
        # re-gate：只重算判据，不重跑执行（report 阶段读这个开关）
        self.regate = bool(self.task.get("regate", False))
        # rule | model_assisted：决定 verify 是否消费模型假设
        self.claim_source = str(self.task.get("claim_source") or "rule")

    def _load_task(self) -> dict:
        p = self.ws / "task.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        return {"task_id": self.ws.name, "benchmark": "cybergym"}

    def _persist_task_snapshot(self) -> None:
        """把 task.json 的稳定摘要写回 .runtime/task.json，保证 run_id 跨次运行不变（检查点前提）。"""
        if self.task.get("run_id"):
            return
        stable = self.task.get("case_id") or self.task.get("task_id") or self.ws.name
        self.task["run_id"] = "r-" + short_hash([stable], 20)
        snapshot = self.layout["runtime"] / "task.json"
        atomic_write_json(snapshot, self.task)
        meta = self.ws / "task.json"
        if not meta.exists():
            atomic_write_json(meta, self.task)

    def _versions(self, stage: str) -> dict:
        return resolve_versions(stage, self.ws)

    def _stage_kwargs(self, stage: str, cls) -> dict:
        """把编排级选项传给阶段实例（如 verify 的 claim_source）。"""
        out = {}
        if stage == "verify":
            out["claim_source"] = self.claim_source
        if stage == "locate":
            exp = self.task.get("experiment") or {}
            out["blind_mode"] = bool(exp.get("symmetry") == "both_sides_no_asan")
            # 默认**不**把规则 sink 喂给模型：否则模型抄规则答案，测不出能力
            out["inject_rule_sink"] = bool(exp.get("inject_rule_sink", False))
        if stage == "report":
            # re-gate：判据改动后用落盘证据重算判定，不重跑执行（镜像可能已不在本机）
            out["regate"] = bool(getattr(self, "regate", False))
        return out

    def _request(self, stage: str) -> StageRequest:
        from ..contracts import OutputContract
        contracts = {
            "recon": (OutputContract("recon/repo_map.json", "vulnmap.repo_map.v1",
                                     ("repo", "build", "entrypoints")),),
            "locate": (OutputContract("locate/findings.json", "vulnmap.locate.v1", ("claims",)),),
            "verify": (OutputContract("verify/result.json", "vulnmap.verify.v1", ("verdict", "poc")),),
            "exploit": (OutputContract("exploit/result.json", "vulnmap.exploit.v1", ("strategy",)),),
            "report": (OutputContract("report/case.json", "vulnmap.case.v1", ("verdict", "checks")),),
        }[stage]
        versions = self._versions(stage)
        return StageRequest(
            run_id=self.task.get("run_id", self.ws.name),
            stage=stage,
            role_version=versions["role_version"],
            prompt_version=versions["prompt_version"],
            prompt=f"{stage} stage",
            required_outputs=tuple(c.logical_name for c in contracts),
            output_contracts=contracts,
            tool_policy=policy_for(stage),
            budget=self.budget,
        )

    def run(self) -> RunOutcome:
        started = time.monotonic()
        run_id = self.task.get("run_id")
        self.task["run_id"] = run_id
        self.store.create_run(run_id, self.task.get("task_id", ""), self.task.get("benchmark", ""), str(self.ws))
        # 全局模型预算在此绑定：run_id 到这里才确定，早绑拿不到断点续跑的历史用量
        guard = getattr(self, "global_budget", None)
        if guard is not None:
            guard.bind(self.store, run_id)
            from ..llm import set_global_budget
            set_global_budget(guard)
        statuses: dict[str, str] = {}
        results: dict[str, dict] = {}
        state = "recon"
        reuse_flags: dict[str, bool] = {}
        stage_seconds: dict[str, float] = {}
        while state not in ("done", "blocked") and state in STAGE_ORDER:
            if self.stage_limit is not None and state not in self.stage_limit:
                # 分段/重判模式：未授权的阶段跳过，但**只向前跳**。
                # 旧实现是"遇到第一个未授权阶段就 break"，于是 `--stages report`
                # 从 recon 起走、到 recon 就停，report 永远跑不到（
                # experiments/remediation-s0/note.md 记过这个坑）。
                # 现在：按 STAGE_ORDER 顺序跳过未授权阶段，只跑被点名的那些。
                statuses[state] = "skipped"
                idx = STAGE_ORDER.index(state)
                state = STAGE_ORDER[idx + 1] if idx + 1 < len(STAGE_ORDER) else "done"
                continue
            stage_cls = STAGE_MODULES[state]
            extra = self._stage_kwargs(state, stage_cls)
            stage = stage_cls(self.store, run_id, self.ws, self._request(state), **extra)
            res = stage.run()
            statuses[state] = res.status
            results[state] = res.data
            reuse_flags[state] = bool(res.usage.get("reused"))
            stage_seconds[state] = float(res.usage.get("seconds", 0.0))
            if res.status != "completed":
                fallback = TRANSITIONS[state]["fail"]
                if state == "verify" and fallback == "locate":
                    # 验证失败退一步：允许带着现有 claim 出报告（降级为疑似）
                    state = "report"
                    continue
                state = "blocked"
                break
            state = TRANSITIONS[state]["ok"]
        # 离线/分段：有阶段因镜像缺失跳过 → partial，而不是假装流程正常走到该阶段
        blocked_missing = self.store._con.execute(
            "SELECT count(*) FROM blackboard WHERE run_id=? AND status='blocked' "
            "AND content LIKE '%reason=image_missing%'", (run_id,)).fetchone()[0]
        if state not in ("done", "blocked") and blocked_missing:
            final_state = "partial"
        elif state == "done":
            final_state = "done"
        else:
            final_state = state
        outcome = RunOutcome(run_id=run_id, status=final_state,
                             stages=statuses, results=results, seconds=time.monotonic() - started)
        summary = outcome.to_json()
        summary["reused"] = reuse_flags
        summary["stage_seconds"] = stage_seconds
        summary["checkpoints"] = len(self.store.checkpoints(run_id))
        summary["versions"] = {s: self._versions(s) for s in STAGE_ORDER}
        atomic_write_json(self.layout["artifacts"] / "run_summary.json", summary)
        return outcome

    def blackboard_context(self) -> dict:
        run_id = self.task.get("run_id")
        return self.store.blackboard_context(run_id) if run_id else {}

    def summary(self) -> dict:
        return {"task": self.task,
                "stages": [self.store.stage_row(self.task.get("run_id", ""), s) for s in STAGE_ORDER],
                "artifacts": self.store.artifacts(self.task.get("run_id", ""))}