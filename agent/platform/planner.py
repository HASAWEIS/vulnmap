"""V2 P2：实验规划 —— ProgramIndex + 假设集 → 一条可执行 Plan。

规划只回答“下一步用哪种执行方式、打哪个目标、花多少预算、为什么”，
不产出漏洞结论。Plan.kind：
  static  —— 只读静态复核（无需执行目标；P3.9 已接执行器：static_review 证据）；
  dynamic —— 服务/行为差分（VulnGym；P3.9 已接执行器：两侧 HTTP 差分）；
  fuzz    —— 源码/二进制 harness + D2 覆盖率引导 fuzz（P2 起已接执行器）；
  replay  —— 旧 PoC 重放（P3.7 已接执行器）：workspace 里已有 PoC + 日志时
             直接重放该输入，比重新 fuzz 更快也更可复算；没有旧 PoC 时仍表示
             “先补工作区（解包源码、恢复镜像）再重放”。

选择是确定性的：同一 ProgramIndex + 同一假设集 + 同一 workspace 必得同一
kind/预算；预算受计划上限约束，执行时可被 CLI 覆盖，但覆盖必须记进
exec.started 事件。

契约字段：
  task_id / benchmark / kind / target / budget / reason
扩展字段（审计需要）：
  schema / hypothesis_ids / inputs / reasons / created_at / sha256
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .hypotheses import contains_verdict
from .task import BENCHMARKS

SCHEMA = "vulnmap.plan.v1"
KINDS = ("static", "dynamic", "fuzz", "replay")

DEFAULT_SECONDS = 5.0
DEFAULT_WORKERS = 2
DEFAULT_TIMEOUT = 2.0
DEFAULT_EXECS = 2_000
MAX_SECONDS = 60.0
MAX_WORKERS = 8
MAX_TIMEOUT = 60.0
MAX_EXECS = 1_000_000

#: Plan.inputs.replay.pocs 的上限（够挑一条重放，又不把 plan 文档撑大）
MAX_PLAN_POCS = 8

VERDICT_KEYS = {"verdict", "verdicts", "confirmed", "exploitable",
                "is_vulnerable", "severity", "conclusion"}


def _workspace_path(index, target: str = "") -> Path | None:
    """工作区：index.meta.workspace 优先，其次本地 target 目录。"""
    meta = getattr(index, "meta", {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    for value in (meta.get("workspace"), target):
        text = str(value or "").strip()
        if not text or text.startswith(("http://", "https://")):
            continue
        try:
            path = Path(text).expanduser()
            if path.is_dir():
                return path
        except OSError:
            continue
    return None


def _rel_log(workspace: Path | None, log) -> str:
    """旧日志的 workspace 相对路径（取不到就空串，绝不猜）。"""
    text = str(log or "").strip()
    if not text or workspace is None:
        return ""
    try:
        return str(Path(text).resolve().relative_to(Path(workspace).resolve()))
    except (ValueError, OSError):
        return ""


def _discover_pocs(index, target: str = "") -> list[dict]:
    """只读探测旧 PoC（延迟导入：executors 依赖 planner，反向导入会成环）。"""
    workspace = _workspace_path(index, target)
    if workspace is None:
        return []
    from .executors.replay import discover_pocs
    try:
        return list(discover_pocs(workspace))
    except Exception:                      # noqa: BLE001 - 探测失败按“没有旧 PoC”处理
        return []


class PlanError(ValueError):
    """Plan 契约/规划错误。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest(doc: dict) -> str:
    """内容哈希（忽略 sha256 自身），保证保存前后可复算。"""
    clean = {k: v for k, v in doc.items() if k != "sha256"}
    return hashlib.sha256(_canonical(clean).encode("utf-8")).hexdigest()


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


# ---------------------------------------------------------------- 预算
def budget_from(index, hypotheses: list[dict], *, seconds: float | None = None,
                workers: int | None = None, timeout: float | None = None,
                max_execs: int | None = None) -> dict:
    """计划预算：target.yaml 的 fuzz 段 → 假设 cost → 默认值，逐项夹紧。"""
    meta = getattr(index, "meta", {}) or {}
    declared = meta.get("declared") or {}
    fuzz = declared.get("fuzz") or {}
    if not isinstance(fuzz, dict):
        fuzz = {}

    base_seconds = seconds if seconds is not None else float(
        fuzz.get("seconds") or DEFAULT_SECONDS)
    base_workers = workers if workers is not None else int(
        fuzz.get("workers") or DEFAULT_WORKERS)
    base_timeout = timeout if timeout is not None else float(
        fuzz.get("timeout") or DEFAULT_TIMEOUT)

    hyp_execs = [int((h.get("cost") or {}).get("execs") or 0)
                 for h in hypotheses or []]
    base_execs = max_execs if max_execs is not None else max(
        [DEFAULT_EXECS] + hyp_execs)

    return {
        "seconds": round(min(MAX_SECONDS, max(0.2, float(base_seconds))), 2),
        "execs": max(1, min(MAX_EXECS, int(base_execs))),
        "workers": max(1, min(MAX_WORKERS, int(base_workers))),
        "timeout": round(min(MAX_TIMEOUT, max(0.1, float(base_timeout))), 2),
    }


# ---------------------------------------------------------------- 选择
def select_kind(index, benchmark: str, target: str = "") -> tuple[str, str]:
    """返回 (kind, reason)。确定性规则，不联网、不执行。

    公开给测试/CLI 复用：P3.9 起 static 与 dynamic 都已有执行器，
    “选中哪种执行方式”本身要能被单测直接覆盖（不需要先跑一遍执行）。
    """
    return _select_kind(index, benchmark, target)


def _select_kind(index, benchmark: str, target: str = "") -> tuple[str, str]:
    """返回 (kind, reason)。确定性规则，不联网、不执行。"""
    sites = list(getattr(index, "call_sites", []) or [])
    entries = list(getattr(index, "entry_points", []) or [])
    sources = int(getattr(index, "source_count", 0) or 0)

    if benchmark == "vulngym":
        return "dynamic", (
            "VulnGym 目标只有 HTTP 服务与静态锚点（仓库内无源码/harness），"
            "源码 fuzz 没有可构建入口；本轮规划动态请求序列与行为差分"
            "（P3.9 起 dynamic 执行器已接通：两侧 HTTP 行为差分 → candidate/no_repro）")

    if benchmark in ("cybergym", "exploitgym"):
        # P3.7：工作区里已有旧 PoC（+ 旧日志）时优先重放——同一输入重跑一遍
        # 就能拿到判据输入，比从零 fuzz 更快、更确定，也不会引入新变量。
        pocs = _discover_pocs(index, target)
        if pocs:
            first = pocs[0]
            return "replay", (
                f"工作区已有 {len(pocs)} 条旧 PoC（首选 {first['source']}，"
                f"sha256={first['sha256'][:12]}，{first['size']} 字节"
                + ("，并绑定了旧崩溃日志" if first.get("log") else "")
                + "），旧 PoC 重放优先：直接按这个输入重跑一遍即可产出判据输入，"
                "不需要重新 fuzz 造一份新输入；重放结果仍然只是 candidate，"
                "独立验证留给 verify")
        if sources == 0:
            return "replay", (
                "workspace 没有可用源码树（repo-vul.tar.gz 未解包或 src/ 为空），"
                "既不能静态复核也不能构建 harness；先恢复工作区再重放")
        if sites or entries:
            return "fuzz", (
                f"workspace 有 {sources} 个源文件、{len(entries)} 个入口、"
                f"{len(sites)} 个危险调用点，且 benchmark 自带 ASAN/harness 构建"
                "路径，适合用 D2 覆盖率引导 fuzz 复现")
        return "replay", (
            f"workspace 有 {sources} 个源文件但没有识别到入口/危险调用点，"
            "先按 build.sh 确认构建与入口后重放，避免空跑")

    # target_yaml：有调用点就直接 fuzz；只有入口时也 fuzz（可能漏标 sink）
    if sites:
        return "fuzz", (
            f"target.yaml 目标有 {len(sites)} 个危险调用点与 {len(entries)} 个入口，"
            "Discovery D0/D1 能给出构建与种子依据，直接进 D2 fuzz")
    if entries:
        return "fuzz", (
            f"有 {len(entries)} 个入口但没有识别到危险调用点；静态不充分，"
            "用 fuzz 扩大动态覆盖后再看是否出现新 sink")
    return "static", (
        "没有入口也没有危险调用点，无法构建 harness；先做静态复核补齐程序理解")


def select(task: dict, index, hypotheses: list[dict], *,
           seconds: float | None = None, workers: int | None = None,
           timeout: float | None = None,
           max_execs: int | None = None) -> "Plan":
    """按 benchmark + ProgramIndex + 假设集生成 Plan（不执行目标）。"""
    if not isinstance(task, dict):
        raise PlanError("task must be a dict")
    benchmark = str(task.get("benchmark") or "")
    target = str(task.get("target") or "")
    task_id = str(task.get("task_id") or "")
    if benchmark not in BENCHMARKS:
        raise PlanError(f"unsupported benchmark: {benchmark!r}")
    if not target.strip():
        raise PlanError("task.target is required")
    if not task_id.strip():
        raise PlanError("task.task_id is required")
    if index is None:
        raise PlanError("plan requires a ProgramIndex")
    if getattr(index, "task_id", "") and index.task_id != task_id:
        raise PlanError(
            f"ProgramIndex belongs to {index.task_id!r}, not {task_id!r}")

    hypotheses = list(hypotheses or [])
    kind, kind_reason = select_kind(index, benchmark, target)
    budget = budget_from(index, hypotheses, seconds=seconds, workers=workers,
                         timeout=timeout, max_execs=max_execs)
    ids = [str(h.get("id") or "") for h in hypotheses if h.get("id")][:8]

    reasons = [
        f"benchmark={benchmark}，ProgramIndex 源文件 {index.source_count}、"
        f"入口 {len(index.entry_points)}、调用点 {len(index.call_sites)}",
        f"假设集 {len(hypotheses)} 条，取 {len(ids)} 条作为本轮可证伪命题",
        kind_reason,
        f"预算：{budget['seconds']}s × {budget['workers']} workers，"
        f"单次超时 {budget['timeout']}s，执行数上限 {budget['execs']}",
        ("重放只把旧 PoC 的复现结果标记为 candidate，不产出确认结论（独立验证在 P3）"
         if kind == "replay" else
         "static 只做只读静态复核：产物是 static_review 证据与 "
         "NO_REPRO/NEEDS_EVIDENCE，不产 candidate、不给结论"
         if kind == "static" else
         "dynamic 只把两侧行为差分标记为 candidate，不产出确认结论"
         "（独立验证在 verify 的 behavior_diff 判据）"
         if kind == "dynamic" else
         "P2 只把单端 fuzz 结果标记为 candidate，不产出确认结论（独立验证在 P3）"),
    ]
    reason = "；".join(reasons[:3] + [reasons[-1]])

    yaml_path = ""
    yaml_candidates = []
    root = str(getattr(index, "root", "") or "")
    if root:
        yaml_candidates.append(Path(root) / "target.yaml")
        yaml_candidates.append(Path(root) / "target.yml")
    if target and not target.startswith(("http://", "https://")):
        yaml_candidates.append(Path(target) / "target.yaml")
        yaml_candidates.append(Path(target) / "target.yml")
    for path in yaml_candidates:
        try:
            if path.is_file():
                yaml_path = str(path)
                break
        except OSError:
            continue

    inputs = {
        "target": target,
        "root": root,
        "workspace": str((getattr(index, "meta", {}) or {}).get("workspace") or ""),
        "target_yaml": yaml_path,
    }

    # P3.7：把探测到的旧 PoC 记进 Plan（PoC + 旧日志都留证；执行器按序取用）
    pocs = _discover_pocs(index, target) if benchmark in (
        "cybergym", "exploitgym") else []
    if pocs:
        workspace = _workspace_path(index, target)
        inputs["replay"] = {
            "pocs": [{
                "path": str(item["path"]),
                "source": str(item["source"]),
                "sha256": str(item["sha256"]),
                "size": int(item["size"]),
                "log": _rel_log(workspace, item.get("log")),
                "log_sha256": str(item.get("log_sha256") or ""),
            } for item in pocs[:MAX_PLAN_POCS]],
            "poc_path": str(pocs[0]["path"]),
            "cmd": "",
            "argv": [],
        }
    else:
        inputs["replay"] = {"pocs": []}

    plan = Plan(task_id=task_id, benchmark=benchmark, kind=kind,
                target=target, budget=budget, reason=reason,
                hypothesis_ids=ids, inputs=inputs, reasons=reasons,
                created_at=now())
    plan.validate()
    return plan


# ---------------------------------------------------------------- 契约
@dataclass
class Plan:
    task_id: str
    benchmark: str
    kind: str
    target: str
    budget: dict = field(default_factory=dict)
    reason: str = ""
    hypothesis_ids: list = field(default_factory=list)
    inputs: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)
    created_at: str = ""
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        doc = {
            "schema": self.schema,
            "task_id": self.task_id,
            "benchmark": self.benchmark,
            "kind": self.kind,
            "target": self.target,
            "budget": dict(self.budget),
            "reason": self.reason,
            "hypothesis_ids": list(self.hypothesis_ids),
            "inputs": dict(self.inputs),
            "reasons": list(self.reasons),
            "created_at": self.created_at,
        }
        doc["sha256"] = digest(doc)
        return doc

    @classmethod
    def from_dict(cls, doc: dict) -> "Plan":
        if not isinstance(doc, dict):
            raise PlanError("plan doc must be a dict")
        return cls(
            task_id=str(doc.get("task_id") or ""),
            benchmark=str(doc.get("benchmark") or ""),
            kind=str(doc.get("kind") or ""),
            target=str(doc.get("target") or ""),
            budget=dict(doc.get("budget") or {}),
            reason=str(doc.get("reason") or ""),
            hypothesis_ids=list(doc.get("hypothesis_ids") or []),
            inputs=dict(doc.get("inputs") or {}),
            reasons=list(doc.get("reasons") or []),
            created_at=str(doc.get("created_at") or ""),
            schema=str(doc.get("schema") or SCHEMA),
        )

    @property
    def sha256(self) -> str:
        return digest(self.to_dict())

    def validate(self) -> None:
        if not self.task_id.strip():
            raise PlanError("plan missing task_id")
        if self.benchmark not in BENCHMARKS:
            raise PlanError(f"plan benchmark must be one of {BENCHMARKS}")
        if self.kind not in KINDS:
            raise PlanError(f"plan kind must be one of {KINDS}")
        if not self.target.strip():
            raise PlanError("plan missing target")
        if not self.reason.strip():
            raise PlanError("plan missing reason")
        if not isinstance(self.budget, dict):
            raise PlanError("plan budget must be a dict")
        for name in ("seconds", "execs", "workers", "timeout"):
            value = self.budget.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise PlanError(f"plan budget.{name} must be a number")
            if float(value) <= 0:
                raise PlanError(f"plan budget.{name} must be > 0")
        if not isinstance(self.hypothesis_ids, list):
            raise PlanError("plan hypothesis_ids must be a list")
        for field_name in _keys(self.to_dict()):
            if field_name in VERDICT_KEYS:
                raise PlanError(
                    f"planning stage must not carry verdict field {field_name!r}")
        if contains_verdict(self.reason):
            raise PlanError("plan reason contains a verdict claim; planning stays pre-execution")


def validate(plan: Plan | dict) -> None:
    if isinstance(plan, dict):
        for key in _keys(plan):
            if key in VERDICT_KEYS:
                raise PlanError(
                    f"planning stage must not carry verdict field {key!r}")
        plan = Plan.from_dict(plan)
    if not isinstance(plan, Plan):
        raise PlanError("validate expects Plan or its dict")
    plan.validate()


def dump(plan: Plan | dict) -> str:
    doc = plan.to_dict() if isinstance(plan, Plan) else dict(plan)
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- 编排（CLI 用）
def run_plan(task_id: str, store, bus, *, seconds: float | None = None,
             workers: int | None = None, timeout: float | None = None) -> dict:
    """HYPOTHESES → PLANNED：读 ProgramIndex/假设集 → 选择 Plan → 存 → 发事件。"""
    task = store.get_task(task_id)
    state = task["state"]
    if state != "HYPOTHESES":
        raise PlanError(f"plan requires HYPOTHESES, got {state}")
    index_row = store.get_program_index(task_id)
    if index_row is None:
        raise PlanError(f"no ProgramIndex for {task_id}; run `understand` first")
    hypotheses = store.list_hypotheses(task_id)
    if not hypotheses:
        raise PlanError(
            f"no hypotheses for {task_id}; run `hypotheses` first")

    from .program import ProgramIndex
    index = ProgramIndex.from_dict(index_row["doc"])
    plan = select(task, index, hypotheses, seconds=seconds, workers=workers,
                  timeout=timeout)
    store.save_plan(task_id, plan)
    store.transition(task_id, "PLANNED",
                     reason=f"plan selected: {plan.kind}")
    seq = bus.emit(task_id, "plan.selected", stage="PLANNED", payload={
        "kind": plan.kind,
        "benchmark": plan.benchmark,
        "target": plan.target,
        "budget": plan.budget,
        "reason": plan.reason,
        "hypothesis_ids": plan.hypothesis_ids,
        "sha256": plan.sha256,
        "inputs": plan.inputs,
    })
    return {"task_id": task_id, "state": store.get_task(task_id)["state"],
            "plan": plan.to_dict(), "event_seq": seq}
