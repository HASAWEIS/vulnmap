"""V3-P2C：研究循环的 CLI 接线 —— `platform run --research` 的依赖装配与状态映射。

口径（《V3 完整升级方案》§4 双循环、§5 执行感知、§8 版本事务、§12 独立验证）：

- **PLANNED 才进研究循环**：`run --research` 不再走单次 `run_execution`，而是把
  `ResearchController` 跑起来；状态迁移只在这里发生（`RUNNING` → 由控制器结果
  映射出的终态），映射表是唯一的（`map_state()`），失败一律保留。
- **依赖全部由任务事实构造**：任务行 / 平台库 / `TaskWorkspace`（任务 overlay）/
  `ProgramIndex` / `CorpusStore` / `exec_runner` / 预算端口 / 取消钩子。
  没有真实构建/冒烟命令时**不**建 overlay，并在报告里写明原因——绝不拿一个
  “构建永远失败”的副本冒充慢循环。
- **执行事实只信事件**：`exec_runner` 真调 fuzz 执行器（`executors.fuzz.execute`
  的短切片），并把 `exec.started` / `exec.finished` 写进事件流；目标语义三段
  （`program_started` / `input_processed` / `checkpoint_reached`）由执行侧的
  `exec_probe_facts()` 统一给出，fuzz 只可能补 `program_started`，另两段没有探针
  就是 `null`（见 `docs/V3-TARGET-SEMANTICS.md`）；
  `TrustedExecutionSnapshot` 只读这两条事实，所以“跑过”是可复核的事件，
  不是本模块的自我声明。执行器抛错 → `exec.finished(outcome=failed, error=...)`
  + `exec_error` 证据，绝不降级成 `no_repro`。
- **不写裁决**：`research.json` 与事件里没有 `verified` / `confirmed`；不建候选
  记录；候选只能通过 `policy.verification_request()` 的 `allowed` 交给既有
  `verify`。工程采纳只写 `adoptions.jsonl`（控制器内部）。
- **状态映射**（`map_state()`）：

  | 控制器结果 | 平台状态 |
  |---|---|
  | `status=cancelled` | `CANCELLED`（已成终态则不改） |
  | `status=budget` | `TERMINATED`（走 `terminate_budget`，带 `budget.exceeded` 证据） |
  | `status=failed` | `FAILED` |
  | `stop_reason ∈ {candidate_ready, verification_blocked}` 且 `verification.allowed` | `CANDIDATE` |
  | 同上但 `allowed=false` | `NEEDS_EVIDENCE` |
  | `status=blocked` 或任一轮出现执行错误/动作失败 | `BLOCKED` |
  | `completed` + 有可信观测 + 有执行轮 + 无候选 | `NO_REPRO` |
  | 其余（没有可信观测 / 一轮执行都没有） | `NEEDS_EVIDENCE` |

  `NO_REPRO` 只在“真的有观测、真的跑过执行”时才给：只在返回值里“声称跑过”
  的循环（事件流里没有 finish 事件）只能落 `NEEDS_EVIDENCE`。

本模块不改 `verify` / `benchmark_policy` / 执行器执行语义；执行器只被调用。
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import shlex
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..budget import BudgetExceeded, BudgetGuard, usage_from_events
from ..lifecycle import (EXEC_ERROR_KIND, EXEC_STATS_KIND, is_cancelled,
                         snapshot_evidence, terminate_budget)
from ..task import TERMINAL, TaskError
from .budget import BudgetLedger, LedgerBudget
from .contracts import (BUDGET_LIMIT_KEYS, ActionRejected, DeclaredBudget,
                        digest_of, now)
from .controller import ControllerResult, ResearchController
from .corpus import CorpusError, CorpusStore, build_identity
from .policy import AdoptionPolicy
from .workspace import TaskWorkspace, WorkspaceError

SCHEMA = "vulnmap.research.run.v1"
SCHEMA_VERSION = 1

#: 供 `adaptive.__init__` 转出（避免与 corpus 的 SCHEMA 撞名）
RESEARCH_SCHEMA = SCHEMA
RESEARCH_SCHEMA_VERSION = SCHEMA_VERSION

#: 控制器自身的默认轮数（CLI 的 `--max-rounds 0` 用它）
DEFAULT_MAX_ROUNDS = 6

#: 单次研究 epoch 的短切片上限（秒）：长跑要能被取消/预算切成片
EPOCH_SECONDS = 5.0
MAX_EPOCH_WORKERS = 8
MAX_EPOCH_TIMEOUT = 60.0

#: 预算键 → `terminate_budget` 的 reason（唯一词形，与 budget.py 同源）
_BUDGET_REASONS = {"seconds": "budget_seconds", "execs": "budget_execs",
                   "tokens": "budget_tokens", "turns": "budget_turns",
                   "usd": "budget_usd"}

NOTE = ("研究循环不写裁决：本文件与事件里没有漏洞结论字段、没有候选记录；"
        "候选只通过 verification.allowed 交给既有 verify（allowed 只表示可以去做，"
        "不等于已经做过）")


class ResearchError(RuntimeError):
    """研究入口的前置条件不成立（不是运行期失败的替代品）。"""


# ====================================================================== 路径
def paths_for(task_id: str, store, *, research_root=None, workdir=None,
              evidence_root=None) -> dict:
    """研究目录布局：`<root>/ws`（overlay）、`work/`（epoch 产物）、
    `corpus/`（持久语料）、`research.json`（报告）。"""
    base = (Path(research_root) if research_root
            else Path(store.path).parent / "research" / str(task_id))
    evidence = (Path(evidence_root) if evidence_root
                else Path(store.path).parent / "evidence")
    return {
        "root": base,
        "workspace": base / "ws",
        "work": Path(workdir) if workdir else base / "work",
        "corpus": base / "corpus",
        "report": base / "research.json",
        "evidence": evidence,
    }


def _argv(value: Any, *, field_name: str) -> list[str]:
    """命令声明归一：字符串按 shell 规则拆分，列表原样（不做 shell=False 之外的解释）。"""
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return shlex.split(text) if text else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    raise ResearchError(f"{field_name} must be a string or a list, got {type(value).__name__}")


def task_commands(task: Mapping, *, build_command=None, smoke_command=None
                  ) -> tuple[list[str], list[str]]:
    """overlay 的构建/冒烟命令：CLI 显式值 > 任务 metadata；都没有就是空。"""
    meta = dict(task.get("metadata") or {})
    build = _argv(build_command if build_command not in (None, "")
                  else meta.get("build_command"), field_name="build_command")
    smoke = _argv(smoke_command if smoke_command not in (None, "")
                  else meta.get("smoke_command"), field_name="smoke_command")
    return build, smoke


def open_workspace(paths: Mapping, task: Mapping, *, task_id: str = "",
                   build_command: Sequence[str] = (),
                   smoke_command: Sequence[str] = (),
                   origin=None) -> tuple[TaskWorkspace | None, dict]:
    """建立/复用任务 overlay；前置不成立就返回 `(None, 原因)`，不造假副本。

    只有**同时**声明了构建与冒烟命令时才建副本：慢循环的 REVERT/ADOPT 依据是
    “真构建 + 真冒烟”，缺一项就只能退化成单步执行，并在报告里写明原因。
    """
    origin_path = Path(str(origin or task.get("target") or ""))
    info: dict = {
        "mode": "none", "origin": str(origin_path), "reason": "",
        "build_command": list(build_command), "smoke_command": list(smoke_command),
        "root": str(paths["workspace"]),
    }
    if not build_command or not smoke_command:
        info["reason"] = "no_build_or_smoke_command"
        return None, info
    if not origin_path.is_dir():
        info["reason"] = f"origin_not_a_directory:{origin_path}"
        return None, info
    root = Path(paths["workspace"])
    try:
        if (root / "workspace.json").is_file():
            workspace = TaskWorkspace.open(root)
            if list(workspace.build_command) != list(build_command) or \
                    list(workspace.smoke_command) != list(smoke_command):
                # 已存在的副本以 workspace.json 为准：换命令必须换工作区
                info["reason"] = "workspace_command_mismatch:reuse_existing"
            info["mode"] = "reused"
        else:
            workspace = TaskWorkspace.create(
                root, origin_path, task_id=task_id,
                build_command=build_command, smoke_command=smoke_command,
                toolchain="", environment={"task_id": task_id,
                                           "policy_version": "v3-p2c"})
            info["mode"] = "created"
    except (WorkspaceError, OSError) as exc:
        info["reason"] = f"workspace_unavailable:{type(exc).__name__}: {exc}"
        return None, info
    current = workspace.current_revision()
    info.update({
        "current_revision": current.revision_id if current else "",
        "origin_ok": bool(workspace.origin_integrity().get("ok")),
        "files": list(current.files) if current is not None else [],
        "revisions": len(workspace.revisions.all()),
    })
    return workspace, info


def open_corpus(paths: Mapping, task: Mapping, *, task_id: str = "",
                campaign: str = "", index: Any = None) -> CorpusStore:
    """按 (task, campaign) 打开持久语料，并用“源码身份”开一代。

    这里开出的世代身份来自 ProgramIndex 摘要（研究循环没有二进制构建身份）；
    fuzz 执行器随后会用它自己的 build identity 再 `begin()` 一次——身份不同就
    按 P1 口径归档重建，语料不会混用两代。
    """
    corpus = CorpusStore(paths["corpus"], task_id=str(task_id),
                         campaign=str(campaign or ""))
    index_doc = {}
    if index is not None and hasattr(index, "to_dict"):
        try:
            index_doc = dict(index.to_dict())
        except Exception:                    # noqa: BLE001 - 索引坏了按未知
            index_doc = {}
    source_sha = str(index_doc.get("sha256") or "")
    identity = build_identity(
        {"harness": "adaptive.research", "source_sha256": source_sha},
        binary_sha256=source_sha, harness="adaptive.research",
        target=str(task.get("target") or ""))
    corpus.begin(identity)
    return corpus


def plan_for_runner(store, task: Mapping) -> dict:
    """执行器要的 plan 文档：优先已存 Plan，缺失就按任务事实合成（不造假字段）。"""
    task_id = str(task.get("task_id") or "")
    doc: dict = {}
    try:
        row = store.get_plan(task_id)
    except Exception:                        # noqa: BLE001 - 读不到就当没有
        row = None
    if row is not None:
        stored = row.get("doc")
        if isinstance(stored, Mapping):
            doc = dict(stored)
    doc.setdefault("task_id", task_id)
    doc.setdefault("benchmark", str(task.get("benchmark") or ""))
    doc.setdefault("target", str(task.get("target") or ""))
    inputs = dict(doc.get("inputs") or {})
    inputs.setdefault("target", str(task.get("target") or ""))
    doc["inputs"] = inputs
    doc.setdefault("kind", "fuzz")
    return doc


# ====================================================================== 执行 worker
def _probe_facts(stats: Mapping) -> dict:
    """fuzz 统计 → 目标语义三段事实（唯一出口在执行器层 `exec_probe_facts`）。

    只补 `program_started`（`execs>0` 证明进程真跑过；`execs=0 + setup_error`
    证明没起来）。**`input_processed` / `checkpoint_reached` 一律 unknown**：
    fuzz 执行器没有输入/检查点探针，`execs>0`、`new_coverage_bits>0` 或崩溃
    都不算“输入被处理”“目标分支命中”。`target_reached` 只由
    `checkpoint_reached` 派生，这里永远是 None。
    """
    from ..executors import exec_probe_facts       # 延迟导入：避免环
    return exec_probe_facts(dict(stats or {}), kind="fuzz")


class FuzzEpochRunner:
    """`run_epoch` 的执行 worker：真调 fuzz 执行器（构建 + 分片 run_parallel）。

    只做三件事：把 epoch 参数夹到短切片、把执行事实写进事件流、把反馈归一成
    `run_epoch` 要的形状。**不**判漏洞、**不**写裁决字段、**不**吞执行错误
    （执行器抛错 → `exec.finished(outcome=failed)` + `exec_error` 证据）。
    """

    kind = "fuzz"

    def __init__(self, *, store, task_id: str, index: Any, hypotheses=(),
                 workdir: Path | str, plan: Mapping | None = None,
                 evidence_root=None, campaign: str = "",
                 corpus_root=None, isolation: str = "auto",
                 require_isolation: bool = False,
                 seconds_cap: float = EPOCH_SECONDS, max_execs: int | None = None,
                 cancel: Callable[[], bool] | None = None,
                 on_epoch: Callable[[], Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.store = store
        self.task_id = str(task_id or "")
        self.index = index
        self.hypotheses = tuple(hypotheses or ())
        self.workdir = Path(workdir)
        self.plan = dict(plan or {})
        self.evidence_root = evidence_root
        self.campaign = str(campaign or "")
        self.corpus_root = corpus_root
        self.isolation = str(isolation or "auto")
        self.require_isolation = bool(require_isolation)
        self.seconds_cap = max(0.05, float(seconds_cap or EPOCH_SECONDS))
        self.max_execs = max_execs
        self.cancel = cancel
        self.on_epoch = on_epoch
        self.clock = clock
        self.calls = 0
        self.epochs: list[dict] = []

    # ---- 调用 ----
    def __call__(self, *, kind: str, mode: str, params: Mapping,
                 binding: Any) -> dict:
        name = str(kind or "")
        if name != self.kind:
            raise ActionRejected(
                "unknown_executor",
                f"研究 CLI 只接通 {self.kind!r} 执行器，收到 {name!r}",
                field_name="kind", hint=f"可选 ['{self.kind}']")
        params = dict(params or {})
        seconds = min(float(params.get("seconds") or 0.2), self.seconds_cap)
        workers = max(1, min(int(params.get("workers") or 1), MAX_EPOCH_WORKERS))
        timeout = min(float(params.get("timeout") or 2.0), MAX_EPOCH_TIMEOUT)
        self.calls += 1
        epoch_no = self.calls
        epoch_dir = self.workdir / f"epoch-{epoch_no:03d}"
        plan = dict(self.plan)
        plan["budget"] = {"seconds": seconds, "workers": workers,
                          "timeout": timeout}
        if not str(plan.get("benchmark") or ""):
            plan["benchmark"] = str((plan.get("inputs") or {}).get("benchmark") or "")
        plan_sha = digest_of({k: v for k, v in plan.items() if k != "sha256"})
        exec_id = f"exec-r{epoch_no:03d}-{plan_sha[:8]}-{secrets.token_hex(3)}"
        started = self.clock()
        self._emit("exec.started", {
            "exec_id": exec_id, "kind": self.kind, "mode": str(mode),
            "plan_sha256": plan_sha, "benchmark": plan.get("benchmark"),
            "target": plan.get("target"),
            "workdir": str(epoch_dir), "isolation": self.isolation,
            "budget": dict(plan["budget"]),
            "binding_hash": getattr(binding, "hash", ""),
            "hypothesis_id": str(params.get("hypothesis_id") or ""),
        })
        try:
            out = self._execute(epoch_dir, seconds, workers, timeout)
        except Exception as exc:              # noqa: BLE001 - 执行器失败也要留事实
            return self._failed(exec_id, plan_sha, exc, mode=mode,
                                started=started, seconds=seconds,
                                workers=workers, timeout=timeout)
        return self._applied(exec_id, plan_sha, out, mode=mode, started=started,
                             seconds=seconds, workers=workers, timeout=timeout)

    # ---- 真跑 ----
    def _execute(self, epoch_dir: Path, seconds: float, workers: int,
                 timeout: float) -> dict:
        from ..executors.fuzz import execute as execute_fuzz   # 延迟导入：避免环
        return execute_fuzz(
            dict(self.plan), self.index, list(self.hypotheses),
            workdir=epoch_dir, seconds=seconds, workers=workers,
            timeout=timeout, isolation=self.isolation,
            require_isolation=self.require_isolation, max_execs=self.max_execs,
            deadline=None, should_stop=self.cancel,
            max_slice=min(seconds, EPOCH_SECONDS), task_id=self.task_id,
            campaign=self.campaign, corpus_root=self.corpus_root)

    # ---- 结算 ----
    def _applied(self, exec_id: str, plan_sha: str, out: Mapping, *,
                 mode: str, started: float, seconds: float, workers: int,
                 timeout: float) -> dict:
        stats = dict(out.get("stats") or {})
        probe = _probe_facts(stats)
        coverage = dict(out.get("coverage") or {})
        build = dict(out.get("build") or {})
        crashes = [dict(item) for item in (out.get("crashes") or [])]
        candidates = len(crashes)
        outcome = "candidate" if candidates else "no_repro"
        elapsed = round(max(0.0, self.clock() - started), 3)
        document = {
            "exec_id": exec_id, "kind": self.kind, "task_id": self.task_id,
            "campaign": self.campaign, "plan_sha256": plan_sha,
            "seconds": out.get("seconds"), "budget": dict(out.get("budget") or {}),
            "build": {"sha256": build.get("sha256"),
                      "build_id": out.get("build_id") or build.get("build_id"),
                      "harness": build.get("harness")},
            "stats": stats, "coverage": coverage, "seeds": out.get("seeds"),
            "seed_pool": out.get("seed_pool"), "corpus": out.get("corpus"),
            "dictionary_tokens": out.get("dictionary_tokens"),
            "crashes": [{"input_sha256": item.get("input_sha256"),
                         "stack_hash": item.get("stack_hash"),
                         "crash_type": item.get("crash_type"),
                         "diagnostic_valid": item.get("diagnostic_valid")}
                        for item in crashes],
            "paths": dict(out.get("paths") or {}),
            "note": "单端执行证据：候选不等于漏洞结论",
        }
        ref = snapshot_evidence(self.store, self.task_id, EXEC_STATS_KIND,
                               document, evidence_root=self.evidence_root,
                               source_stage="RUNNING")
        budget_usage = {"seconds": elapsed,
                        "execs": int(stats.get("execs") or 0),
                        "tokens": 0, "turns": 1}
        self._emit("exec.finished", {
            "exec_id": exec_id, "kind": self.kind, "mode": str(mode),
            "plan_sha256": plan_sha, "outcome": outcome,
            "candidates": candidates, "seconds": elapsed,
            "build": {"sha256": build.get("sha256"),
                      "build_id": out.get("build_id") or build.get("build_id"),
                      "harness": build.get("harness"),
                      "cmd": list(build.get("cmd") or [])},
            "fuzz": stats, "coverage": coverage,
            "seeds": out.get("seeds"),
            "dictionary_tokens": out.get("dictionary_tokens"),
            "format": out.get("format"),
            # 目标语义三段：只写真的观测到的；没有探针就是 None（=unknown），
            # 不用 execs/覆盖率冒充。target_reached 是 checkpoint_reached 的别名。
            **probe,
            "stack_hashes": [item["stack_hash"] for item in crashes
                             if item.get("stack_hash")],
            "crash_type": crashes[0].get("crash_type") if crashes else None,
            "evidence_sha256": ref.sha256,
            "budget_usage": budget_usage, "error": None,
            "isolation": self.isolation,
            "budget": {"seconds": seconds, "workers": workers,
                       "timeout": timeout},
        })
        self._refresh_corpus()
        self.epochs.append({"exec_id": exec_id, "outcome": outcome,
                            "candidates": candidates,
                            "evidence_sha256": ref.sha256})
        return {
            "execution_id": exec_id, "kind": self.kind, "mode": str(mode),
            "outcome": outcome, "candidates": candidates,
            "build": {"sha256": build.get("sha256"),
                      "build_id": out.get("build_id") or build.get("build_id"),
                      "harness": build.get("harness")},
            "fuzz": stats, "coverage": coverage, "seeds": out.get("seeds"),
            "dictionary_tokens": out.get("dictionary_tokens"),
            "format": out.get("format"),
            "budget_usage": budget_usage, "evidence_sha256": ref.sha256,
            "error": None,
        }

    def _failed(self, exec_id: str, plan_sha: str, exc: BaseException, *,
                mode: str, started: float, seconds: float, workers: int,
                timeout: float) -> dict:
        error = f"{type(exc).__name__}: {exc}"
        elapsed = round(max(0.0, self.clock() - started), 3)
        ref = snapshot_evidence(self.store, self.task_id, EXEC_ERROR_KIND, {
            "exec_id": exec_id, "kind": self.kind, "task_id": self.task_id,
            "campaign": self.campaign, "plan_sha256": plan_sha, "error": error,
            "budget": {"seconds": seconds, "workers": workers,
                       "timeout": timeout},
            "note": "执行失败不是负结果：不写 no_repro，不产候选",
            "at": now(),
        }, evidence_root=self.evidence_root, source_stage="RUNNING")
        self._emit("exec.finished", {
            "exec_id": exec_id, "kind": self.kind, "mode": str(mode),
            "plan_sha256": plan_sha, "outcome": "failed", "candidates": None,
            "seconds": elapsed, "build": None, "fuzz": {}, "coverage": {},
            # 执行失败时三段事实一律 unknown：抛错发生在哪一步不可知，
            # 不把“构建失败”写成 program_started=false（那是猜测，不是观测）
            **_probe_facts({}),
            "evidence_sha256": ref.sha256, "error": error,
            "budget_usage": {"seconds": elapsed, "execs": 0, "tokens": 0,
                             "turns": 1},
            "isolation": self.isolation,
        })
        self._refresh_corpus()
        self.epochs.append({"exec_id": exec_id, "outcome": "failed",
                            "candidates": 0, "evidence_sha256": ref.sha256})
        return {
            "execution_id": exec_id, "kind": self.kind, "mode": str(mode),
            "outcome": "failed", "candidates": None, "build": None,
            "fuzz": {}, "coverage": {}, "seeds": None,
            "dictionary_tokens": None, "format": None,
            "budget_usage": {"seconds": elapsed, "execs": 0, "tokens": 0,
                             "turns": 1},
            "evidence_sha256": ref.sha256, "error": error,
        }

    # ---- 内部 ----
    def _emit(self, event_type: str, payload: Mapping) -> None:
        try:
            self.store.append_event(self.task_id, event_type,
                                    stage="RUNNING", payload=dict(payload))
        except Exception:                     # noqa: BLE001 - 事件写不进去不改执行
            pass

    def _refresh_corpus(self) -> None:
        """fuzz 执行器自己 `begin()` 过语料：让外部的语料端口复读磁盘真相。"""
        if self.on_epoch is None:
            return
        try:
            self.on_epoch()
        except Exception:                     # noqa: BLE001 - 复读失败不改结论
            pass


# ====================================================================== 映射
def epoch_stats(result: ControllerResult) -> dict:
    """执行轮统计：只数真的走到执行器上的动作用例。"""
    applied = failed = candidates = 0
    for round_record in result.rounds:
        for action in round_record.actions:
            if str(action.get("tool") or "") != "run_epoch":
                continue
            status = str(action.get("status") or "")
            if status in ("applied", "noop"):
                applied += 1
            elif status == "failed":
                failed += 1
            try:
                candidates += int(action.get("candidates") or 0)
            except (TypeError, ValueError):
                continue
    return {"epochs": applied + failed, "applied": applied, "failed": failed,
            "candidates": candidates}


def observed_rounds(result: ControllerResult) -> int:
    """有几轮的 OBSERVE 拿到了 `applied` 快照（控制器阶段明细的唯一口径）。"""
    rounds: set[int] = set()
    for phase in result.timeline:
        if phase.phase != "OBSERVE":
            continue
        if "snapshot=applied" in str(phase.detail or ""):
            rounds.add(int(phase.round_no))
    return len(rounds)


def failure_signal(result: ControllerResult) -> str:
    """执行侧的失败信号（失败不得被映射成负结果）。"""
    if str(result.status) == "failed":
        return "controller_error"
    for round_record in result.rounds:
        diagnosis = round_record.diagnosis
        if diagnosis is not None and str(diagnosis.code) == "execution_error":
            return "execution_error"
        if str(round_record.note or "") == "execution_error":
            return "execution_error"
        for action in round_record.actions:
            if str(action.get("status") or "") == "failed":
                return f"action_failed:{action.get('tool')}"
    return ""


def map_state(result: ControllerResult | None, *, epochs: int | None = None,
              observed: int | None = None) -> str:
    """控制器结果 → 平台状态（唯一映射表，见模块文档）。

    `verification.allowed` 只表示“可以交给既有 verify”，所以它映射到
    `CANDIDATE`（待独立验证），**不是**任何“已验证”状态。
    """
    if result is None:
        return "NEEDS_EVIDENCE"
    status = str(result.status or "")
    stop = str(result.stop_reason or "")
    if status == "cancelled":
        return "CANCELLED"
    if status == "budget":
        return "TERMINATED"
    if status == "failed":
        return "FAILED"
    if stop in ("candidate_ready", "verification_blocked"):
        allowed = bool(result.verification is not None
                       and result.verification.allowed)
        return "CANDIDATE" if allowed else "NEEDS_EVIDENCE"
    if status == "blocked":
        return "BLOCKED"
    if failure_signal(result):
        return "BLOCKED"
    stats = epoch_stats(result)
    ran = int(stats["epochs"] if epochs is None else epochs)
    seen = int(observed_rounds(result) if observed is None else observed)
    if seen <= 0 or ran <= 0:
        return "NEEDS_EVIDENCE"
    return "NO_REPRO"


def _budget_reason(result: ControllerResult | None) -> str:
    """预算终止原因：优先用 STOP 阶段里的 `remaining:<key><=0`，否则 `budget_declared`。"""
    detail = ""
    if result is not None:
        for phase in result.timeline:
            if phase.phase == "STOP" and str(phase.status) == "budget":
                detail = str(phase.detail or "")
    match = re.search(r"remaining:([a-z_]+)<=0", detail)
    key = match.group(1) if match else ""
    return _BUDGET_REASONS.get(key, "budget_declared")


# ====================================================================== 报告
def _corpus_snapshot(corpus: Any) -> dict:
    if corpus is None:
        return {}
    try:
        return dict(corpus.snapshot() or {})
    except Exception:                        # noqa: BLE001 - 台账不可读=未知
        return {}


def _open_handoff_items(store, task_id: str, *, evidence_root,
                        after_seq: int = 0, revision_id: str = "",
                        policy_version: str = "") -> dict:
    """把本次研究循环真跑出来的每一条执行封存成**待复核项**（V3 W3）。

    只对事件流里真有 ``exec.finished`` 的执行开项（按 `after_seq` 只取本次运行
    之后的事件，不把历史执行重开一遍）；封存失败（没有证据/哈希不符）如实记进
    ``skipped``，不补一条"看起来跑过了"的记录，也不改任何结论。
    """
    from .handoff import HandoffError, open_pending    # 延迟导入：避免包循环

    items: list[dict] = []
    skipped: list[dict] = []
    seen: set[str] = set()
    executions: dict[str, int] = {}
    for event in store.list_events(task_id, after_seq=int(after_seq or 0)):
        if str(event.get("event_type") or "") != "exec.finished":
            continue
        exec_id = str((event.get("payload") or {}).get("exec_id") or "")
        if not exec_id:
            continue
        # 同一 exec_id 出现多条 finish 时以**最后一条**为准（append-only 覆盖），
        # 并把序号点名叫给封存器，避免在一堆事件里随便挑一条
        executions[exec_id] = int(event.get("seq") or 0)
        seen.add(exec_id)
    for exec_id, seq in executions.items():
        try:
            item = open_pending(store, task_id, execution_id=exec_id,
                                evidence_root=evidence_root,
                                revision_id=revision_id,
                                policy_version=policy_version,
                                event_seq=seq)
        except HandoffError as exc:                    # 缺证据不算"跑过了"
            skipped.append({"execution_id": exec_id, "reason": str(exc)})
            continue
        items.append({"item_id": item["item_id"], "run_id": item["run_id"],
                      "execution_id": item["execution_id"],
                      "evidence_sha256": item["evidence_sha256"],
                      "status": item["status"]})
    return {
        "schema": "vulnmap.adaptive.handoff_queue.v1",
        "opened": len(items), "skipped": len(skipped),
        "items": items, "unsealed": skipped,
        "note": ("封存成功只代表『有一条可复核的原始记录』，"
                 "不代表已验证；复核结论由独立复核者给出"),
    }


def _report_body(*, task: Mapping, campaign: str, paths: Mapping,
                 result: ControllerResult | None, state: str,
                 guard: BudgetGuard, deps: Mapping, max_rounds: int,
                 epochs: Mapping | None, observed: int | None,
                 stop_reason: str = "", handoff: Mapping | None = None) -> dict:
    stats = dict(epochs or {})
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "task_id": str(task.get("task_id") or ""),
        "benchmark": str(task.get("benchmark") or ""),
        "campaign": str(campaign or ""),
        "generated_at": now(),
        "state": str(state),
        "controller_state": str(result.status) if result is not None else "",
        "stop_reason": str(stop_reason or (result.stop_reason if result else "")),
        "max_rounds": int(max_rounds),
        "rounds": len(result.rounds) if result is not None else 0,
        "executions": int(stats.get("epochs") or 0),
        "executions_applied": int(stats.get("applied") or 0),
        "executions_failed": int(stats.get("failed") or 0),
        "candidates": int(stats.get("candidates") or 0),
        "observed_rounds": int(observed or 0),
        "verification_allowed": bool(result.verification is not None
                                     and result.verification.allowed)
        if result is not None else False,
        "note": NOTE,
        # W3：本次真跑出来的待复核项（只有身份与状态，没有结论字段）
        "handoff": dict(handoff or {"opened": 0, "skipped": 0, "items": [],
                                    "unsealed": []}),
        "controller": result.to_dict() if result is not None else None,
        "deps": dict(deps),
        "budget": guard.snapshot() if guard is not None else {},
        "paths": {key: str(value) for key, value in dict(paths).items()},
    }


def _write_report(path: Path, body: Mapping) -> tuple[Path, str]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    return path, hashlib.sha256(text.encode("utf-8")).hexdigest()


# ====================================================================== 入口
def _settle_state(*, task_id: str, store, bus, state: str,
                  result: ControllerResult | None, guard: BudgetGuard,
                  paths: Mapping) -> str:
    """把映射出的状态落到状态机；被拒绝时如实记事件、不改状态。"""
    current = str(store.get_task(task_id)["state"])
    if state == "TERMINATED":
        terminated = terminate_budget(
            task_id, store, bus, guard=guard, reason=_budget_reason(result),
            stage=current, evidence_root=paths["evidence"],
            error=str(result.error if result is not None else ""),
            extra={"check": "post",
                   "stop_reason": str(result.stop_reason if result else ""),
                   "rounds": len(result.rounds) if result is not None else 0})
        return str(terminated["state"])
    if current in TERMINAL:
        return current
    try:
        return str(store.transition(
            task_id, state,
            reason=f"research: {result.stop_reason if result else state}")["state"])
    except TaskError as exc:
        bus.emit(task_id, "research.map_failed", stage=current, payload={
            "target_state": str(state),
            "stop_reason": str(result.stop_reason if result else ""),
            "error": str(exc),
            "note": "状态未改变：映射被状态机拒绝，失败原样保留"})
        return current


def run_research(task_id: str, store, bus, *, workdir=None, evidence_root=None,
                 research_root=None, campaign: str = "",
                 max_rounds: int = DEFAULT_MAX_ROUNDS, max_same_facts: int = 2,
                 seconds: float | None = None, workers: int | None = None,
                 timeout: float | None = None, isolation: str = "auto",
                 require_isolation: bool = False, origin=None,
                 build_command=None, smoke_command=None,
                 exec_runner: Callable | None = None,
                 cancel: Callable[[], bool] | None = None,
                 policy: Any = None, emit_events: bool = True,
                 proposal_gate: Any = None,
                 tokens_used: int = 0,
                 clock: Callable[[], float] = time.time) -> dict:
    """跑一次研究循环（PLANNED → RUNNING → 映射终态），返回报告文档。

    失败路径分三类，都不互相冒充：

    1. **前置条件不成立**（不是 PLANNED / 没有 ProgramIndex）→ `ResearchError`，
       状态不动（还在 PLANNED），CLI 退出码 2；
    2. **执行/构建/冒烟失败** → 控制器如实停（`blocked`/`failed`），
       映射到 `BLOCKED`/`FAILED`，`research.json` 照写；
    3. **预算耗尽** → `terminate_budget()` 写 `budget.exceeded` 证据 +
       `TERMINATED`，绝不写 `NO_REPRO`。
    """
    task = dict(store.get_task(task_id))
    state = str(task["state"])
    if state != "PLANNED":
        raise ResearchError(f"research requires PLANNED, got {state}")
    # 轮数下限 1：0/负数不是“跑到停”，只是参数写错；夹紧而不是跑一轮空循环
    round_cap = max(1, int(max_rounds))
    paths = paths_for(task_id, store, research_root=research_root,
                      workdir=workdir, evidence_root=evidence_root)
    path_root = Path(paths["root"])
    path_root.mkdir(parents=True, exist_ok=True)
    Path(paths["work"]).mkdir(parents=True, exist_ok=True)

    index_row = store.get_program_index(task_id)
    if index_row is None:
        raise ResearchError(
            f"no ProgramIndex for {task_id}; run `understand` first")
    from ..program import ProgramIndex        # 延迟导入：包内其余入口不必背它
    index = ProgramIndex.from_dict(index_row["doc"])
    hypotheses = store.list_hypotheses(task_id)
    campaign = str(campaign or task.get("benchmark") or "")
    build_cmd, smoke_cmd = task_commands(task, build_command=build_command,
                                        smoke_command=smoke_command)
    workspace, workspace_info = open_workspace(
        paths, task, task_id=task_id, build_command=build_cmd,
        smoke_command=smoke_cmd, origin=origin)
    try:
        corpus = open_corpus(paths, task, task_id=task_id, campaign=campaign,
                            index=index)
    except CorpusError as exc:
        raise ResearchError(f"corpus unavailable: {exc}") from exc

    used = usage_from_events(store.list_events(task_id))
    used["tokens"] = int(used.get("tokens") or 0) + max(0, int(tokens_used or 0))
    guard = BudgetGuard(task["budget"], used=used)
    guard.begin()
    seconds_cap = float(seconds or EPOCH_SECONDS)
    deps = {
        "workspace": workspace_info,
        "index": {"sha256": str(index_row.get("sha256") or ""),
                  "root": str(index_row.get("root") or ""),
                  "call_sites": int(index_row.get("call_site_count") or 0),
                  "hypotheses": len(hypotheses)},
        "corpus": _corpus_snapshot(corpus),
        "executor": {"kind": "fuzz", "source": ("injected" if exec_runner
                                                else "executors.fuzz.execute"),
                     "seconds_cap": seconds_cap,
                     "workers": int(workers or 0),
                     "timeout": float(timeout or 0.0),
                     "isolation": str(isolation),
                     "require_isolation": bool(require_isolation)},
        "paths": {key: str(value) for key, value in paths.items()},
    }

    # ---- 执行前预算检查：不开 RUNNING，直接 TERMINATED（与 run_execution 同口径）
    try:
        guard.precheck(stage=state)
    except BudgetExceeded as exc:
        terminated = terminate_budget(
            task_id, store, bus, guard=guard, reason=exc.reason, stage=state,
            evidence_root=paths["evidence"], error=str(exc),
            extra={"check": "pre", "tokens_used": int(tokens_used or 0)})
        body = _report_body(
            task=task, campaign=campaign, paths=paths, result=None,
            state=str(terminated["state"]), guard=guard, deps=deps,
            max_rounds=round_cap, epochs=None, observed=0,
            stop_reason=exc.reason)
        report_path, report_sha = _write_report(paths["report"], body)
        return {**body, "report_path": str(report_path),
                "report_sha256": report_sha}

    limits: dict[str, float] = {}
    for name, key in BUDGET_LIMIT_KEYS.items():
        value = (task.get("budget") or {}).get(key)
        if value is not None:
            limits[name] = float(value)
    # V3-010：研究主循环的预算必须是**事务账本**（跨 worker 原子预留），
    # 不能再是一次性内存账本。历史事件用量作为起点（`seed_usage`，只抬不降）。
    ledger = BudgetLedger(Path(paths["root"]) / "budget.db", clock=clock)
    scope = ledger.ensure_chain(
        run=campaign or task_id, task=task_id,
        limits_by_level={"task": dict(limits)})
    ledger.seed_usage(scope["task"],
                      {k: v for k, v in used.items()
                       if k in limits and v is not None})
    budget = LedgerBudget(ledger, scope["task"])
    cancel_hook = cancel or (lambda: is_cancelled(store, task_id))
    runner = exec_runner or FuzzEpochRunner(
        store=store, task_id=task_id, index=index, hypotheses=hypotheses,
        workdir=paths["work"], plan=plan_for_runner(store, task),
        evidence_root=paths["evidence"], campaign=campaign,
        corpus_root=paths["corpus"], isolation=isolation,
        require_isolation=require_isolation, seconds_cap=seconds_cap,
        cancel=cancel_hook, on_epoch=corpus.reload)

    store.transition(task_id, "RUNNING",
                     reason=(f"research started: campaign={campaign} "
                             f"max_rounds={round_cap}"))
    bus.emit(task_id, "research.started", stage="RUNNING", payload={
        "campaign": campaign, "max_rounds": round_cap,
        "workspace": dict(workspace_info),
        "index_sha256": str(index_row.get("sha256") or ""),
        "hypotheses": len(hypotheses),
        "corpus": _corpus_snapshot(corpus),
        "executor": dict(deps["executor"]),
        "paths": dict(deps["paths"]),
        "note": NOTE,
    })

    controller = ResearchController(
        task=task, store=store, workspace=workspace, index=index,
        corpus=corpus, exec_runner=runner,
        policy=policy or AdoptionPolicy(), campaign=campaign,
        max_rounds=round_cap, max_same_facts=max(1, int(max_same_facts)),
        budget=budget, cancel=cancel_hook, emit_events=bool(emit_events),
        proposal_gate=proposal_gate, clock=clock)
    started = now()
    # W3：本次运行的事件水位（交接只封存这次跑出来的执行）
    existing = store.list_events(task_id)
    handoff_watermark = int(existing[-1]["seq"]) if existing else 0
    try:
        result = controller.run()
    except Exception as exc:                 # noqa: BLE001 - 控制器崩溃要如实报
        result = ControllerResult(
            status="failed", stop_reason=f"error:{type(exc).__name__}",
            error=f"{type(exc).__name__}: {exc}", started_at=started,
            finished_at=now())

    stats = epoch_stats(result)
    observed = observed_rounds(result)
    # W3：先封存待复核项，再写报告——报告里的交接段与台账同一批记录
    handoff_block = _open_handoff_items(
        store, task_id, evidence_root=paths["evidence"],
        after_seq=handoff_watermark,
        revision_id=(result.revisions[-1] if result.revisions else ""),
        policy_version="v3-w3")
    # 报告反映跑完之后的语料世代（执行器会用自己的构建身份重开一代）
    deps["corpus"] = _corpus_snapshot(corpus)
    mapped = map_state(result, epochs=stats["epochs"], observed=observed)
    body = _report_body(
        task=task, campaign=campaign, paths=paths, result=result,
        state=mapped, guard=guard, deps=deps, max_rounds=round_cap,
        epochs=stats, observed=observed, handoff=handoff_block)
    report_path, report_sha = _write_report(paths["report"], body)
    final_state = _settle_state(task_id=task_id, store=store, bus=bus,
                               state=mapped, result=result, guard=guard,
                               paths=paths)
    bus.emit(task_id, "research.mapped", stage=final_state, payload={
        "state": final_state, "target_state": mapped,
        "controller_state": str(result.status),
        "stop_reason": str(result.stop_reason),
        "rounds": len(result.rounds), "executions": int(stats["epochs"]),
        "candidates": int(stats["candidates"]),
        "observed_rounds": observed,
        "verification_allowed": bool(result.verification is not None
                                     and result.verification.allowed),
        "handoff_items": [item["item_id"] for item in handoff_block["items"]],
        "handoff_skipped": handoff_block["skipped"],
        "report_path": str(report_path), "report_sha256": report_sha,
        "note": NOTE,
    })
    return {**body, "state": final_state, "report_path": str(report_path),
            "report_sha256": report_sha}


__all__ = ["SCHEMA", "SCHEMA_VERSION", "RESEARCH_SCHEMA",
           "RESEARCH_SCHEMA_VERSION", "DEFAULT_MAX_ROUNDS", "EPOCH_SECONDS",
           "MAX_EPOCH_WORKERS", "MAX_EPOCH_TIMEOUT", "NOTE", "ResearchError",
           "paths_for", "task_commands", "open_workspace", "open_corpus",
           "plan_for_runner", "FuzzEpochRunner", "epoch_stats",
           "observed_rounds", "failure_signal", "map_state", "run_research"]
