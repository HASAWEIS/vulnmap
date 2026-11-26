"""V2 P3.9 dynamic 执行器：VulnGym 基线/修补两侧 HTTP 行为差分。

做法：把 `task.json` / 任务 metadata / plan 覆盖翻译成 VulnGym runner spec
（[runners/spec.py](../runners/spec.py)，只翻译不发明），再用
[runners/vulngym.py](../runners/vulngym.py) 真的打两条 GET（不跟跳转、禁代理、
连接断开/超时如实记账），最后用**判据函数**（[verify.evaluate_vulngym](../verify.py)）
只看 `checks` 推出这一轮属于哪种结局：

- 两侧都拿到响应且行为有差异 → `candidate`（输入=请求文档、主证据=差分日志）；
- 两侧都拿到响应且行为一致   → `no_repro`（跑完了，没有差异，不是失败）；
- 某一侧拿不到响应/超时/两侧同址且无差异之外的空观测 → `DynamicExecError`
  → 编排层落 FAILED + `exec_error`，并保留 `dynamic_spec` / `dynamic_run` 证据。

硬约束：

- **不写结论**：本模块只搬 `checks`（两侧状态/体哈希/是否断开），
  `evaluate_vulngym` 返回里的结论字段不落库——`verified` 仍然只由
  [benchmark_policy](../../benchmark_policy.py) 在 verify 阶段推导；
- **失败留证**：抛错时异常带 `records`（spec / runner 结果 / 两侧原始日志），
  编排层先落证据再写 FAILED，绝不把“服务打不通”洗成 `no_repro`；
- **不猜 URL**：没有任何默认值能造出基线/修补地址；缺字段就是
  `runner_not_configured:*`（缺口），不拿 plan.target 去顶替**修补侧**——
  只有显式声明的一侧才参与差分；
- **isolated**：网络策略与隔离前缀全部交给 runner 自己的策略快照。

契约字段（`execute()` 的返回）：
  task_id / benchmark / outcome / spec / checks / blockers / sides / runner /
  crashes / bodies / requests / seconds
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..runners import RunnerError, RunnerMismatch, select_runner
from ..runners.spec import SpecError, build_runner_spec
from ..verify import evaluate_vulngym

SCHEMA = "vulnmap.dynamic_diff.v1"

#: 候选的崩溃类型：行为差分不是内存崩溃，必须用自己的名字（不冒充 ASAN）
CRASH_TYPE = "behavior_diff"
MAX_BODY = 1 << 20

OUTCOME_CANDIDATE = "candidate"
OUTCOME_NO_REPRO = "no_repro"
OUTCOMES = (OUTCOME_CANDIDATE, OUTCOME_NO_REPRO)


class DynamicExecError(RuntimeError):
    """动态执行失败（配置缺口/服务不可达/超时）。

    `records`：失败过程中已经拿到的证据（kind → JSON 文档），
    编排层负责落库——失败也要能事后复核“打了什么、回了什么”。
    """

    def __init__(self, message: str, *, records: dict | None = None):
        super().__init__(message)
        self.records = dict(records or {})


def _text(value) -> str:
    return str(value or "").strip()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


# ---------------------------------------------------------------- spec
def _index_meta(index) -> dict:
    meta = getattr(index, "meta", {}) or {}
    return dict(meta) if isinstance(meta, dict) else {}


def build_spec(plan: dict, index) -> dict:
    """把 plan + ProgramIndex 摘要翻译成 VulnGym runner spec（probe 关闭）。"""
    plan = dict(plan or {})
    inputs = plan.get("inputs") or {}
    if not isinstance(inputs, dict):
        inputs = {}
    metadata = _index_meta(index)
    # plan.inputs 里显式声明的 url 优先于 workspace 的 task.json
    overrides: dict = {}
    for key in ("baseline_url", "patched_url", "service_url", "method",
                "headers", "expect"):
        value = inputs.get(key)
        if value not in (None, "", [], {}):
            overrides[key] = value
    nested = inputs.get("dynamic") if isinstance(inputs.get("dynamic"), dict) else {}
    for key, value in (nested or {}).items():
        if value not in (None, "", [], {}):
            overrides[str(key)] = value
    workspace = _text(inputs.get("workspace")) or _text(metadata.get("workspace"))
    try:
        doc = build_runner_spec(
            "vulngym", metadata=metadata, workspace=workspace or None,
            overrides=overrides, probe=False)
    except (SpecError, RunnerError) as exc:
        raise DynamicExecError(
            f"dynamic executor: cannot build vulngym spec: {exc}",
            records={"dynamic_spec": {"schema": SCHEMA, "plan_sha256":
                                      _text(plan.get("sha256")),
                                      "benchmark": "vulngym",
                                      "error": f"{type(exc).__name__}: {exc}"}})
    doc = dict(doc)
    doc["schema"] = SCHEMA
    doc["plan_sha256"] = _text(plan.get("sha256"))
    doc["target"] = _text(plan.get("target"))
    return doc


# ---------------------------------------------------------------- 请求/差分
def _request_doc(spec: dict) -> dict:
    """候选输入：真正被打出去的请求（method + 两个 URL + headers）。"""
    return {
        "benchmark": "vulngym",
        "method": _text(spec.get("method")) or "GET",
        "baseline_url": _text(spec.get("baseline_url")),
        "patched_url": _text(spec.get("patched_url")),
        "headers": dict(spec.get("headers") or {}) if isinstance(
            spec.get("headers"), dict) else {},
        "redirects_followed": False,
        "proxy": "disabled",
    }


def _diff_summary(checks: dict, sides: dict) -> dict:
    return {
        "method": _text(checks.get("method")),
        "baseline_status": checks.get("baseline_status"),
        "patched_status": checks.get("patched_status"),
        "baseline_body_sha256": _text(checks.get("baseline_body_sha256")),
        "patched_body_sha256": _text(checks.get("patched_body_sha256")),
        "baseline_closed": bool(checks.get("baseline_closed")),
        "patched_closed": bool(checks.get("patched_closed")),
        "sides": {side: {"status": (sides.get(side) or {}).get("status"),
                         "seconds": (sides.get(side) or {}).get("seconds"),
                         "error": _text((sides.get(side) or {}).get("error"))}
                  for side in ("baseline", "patched")},
    }


def _responded(side: dict) -> bool:
    """这一侧到底有没有拿到响应（断开/超时都算没拿到，那是缺口）。"""
    side = side or {}
    return (side.get("status") is not None
            or bool(_text(side.get("body_sha256")))
            or bool(_text(side.get("body_path"))))


def _diff_log(summary: dict, blockers: list) -> str:
    lines = [
        "# kind=behavior_diff",
        f"# method={summary['method']}",
        f"# baseline_status={summary['baseline_status']} "
        f"body_sha256={summary['baseline_body_sha256'] or '-'} "
        f"closed={summary['baseline_closed']}",
        f"# patched_status={summary['patched_status']} "
        f"body_sha256={summary['patched_body_sha256'] or '-'} "
        f"closed={summary['patched_closed']}",
        f"# blockers={','.join(blockers) if blockers else '-'}",
        "# summary=" + _canonical(summary),
    ]
    return "\n".join(lines) + "\n"


def _crash_record(request: dict, summary: dict, log: str) -> dict:
    input_bytes = _canonical(request).encode("utf-8")
    return {
        "input_bytes": input_bytes,
        "input_sha256": _sha256(input_bytes),
        "crash_type": CRASH_TYPE,
        # 同口径签名：差分事实（不是 root cause），用于候选去重
        "stack_hash": _sha256(_canonical(summary).encode("utf-8")),
        "log": log,
        "parsed": {"crash_type": CRASH_TYPE, "function": "", "file": "",
                   "line": 0, "frames": []},
        "diagnostic_valid": True,
        "input_path": "",
        "log_path": "",
    }


def _body_refs(evidence: list) -> list[dict]:
    """runner 落到磁盘的两侧响应体：原样读回来交给证据库（限 1 MiB）。"""
    out: list[dict] = []
    for item in evidence or []:
        kind = _text(item.get("kind"))
        path = _text(item.get("path"))
        if not kind.startswith("verify_") or not kind.endswith("_body"):
            continue
        if not path:
            continue
        try:
            data = Path(path).read_bytes()[:MAX_BODY]
        except OSError:
            continue
        out.append({"kind": f"dynamic_{kind}", "data": data,
                    "sha256": _sha256(data), "path": path})
    return out


# ---------------------------------------------------------------- 执行
def execute(plan: dict, index, hypotheses=(), *, workdir=None, timeout=None,
            isolation: str = "auto", require_isolation: bool = False,
            **_: object) -> dict:
    """打两侧 HTTP 并给出这一轮的结局（candidate / no_repro）。"""
    plan = dict(plan or {})
    benchmark = _text(plan.get("benchmark"))
    if benchmark != "vulngym":
        raise DynamicExecError(
            "dynamic executor implements vulngym behavior diff only, "
            f"got benchmark={benchmark!r}",
            records={"dynamic_spec": {"schema": SCHEMA, "benchmark": benchmark,
                                      "plan_sha256": _text(plan.get("sha256")),
                                      "error": "unsupported_benchmark"}})

    spec_doc = build_spec(plan, index)
    records: dict = {"dynamic_spec": spec_doc}
    if spec_doc.get("blockers"):
        raise DynamicExecError(
            "dynamic executor: " + ",".join(spec_doc["blockers"]),
            records=records)
    runner_spec = dict(spec_doc.get("spec") or {})
    if not runner_spec.get("baseline_url") or not runner_spec.get("patched_url"):
        raise DynamicExecError(
            "dynamic executor: baseline_url/patched_url are required",
            records=records)

    run_dir = Path(workdir or ".") / "dynamic"
    try:
        runner = select_runner(
            "vulngym", workdir=run_dir, timeout=timeout, isolation=isolation,
            require_isolation=require_isolation)
    except (RunnerError, RunnerMismatch) as exc:
        raise DynamicExecError(
            f"dynamic executor: runner unavailable: {exc}", records=records)
    result = runner.safe_run(runner_spec)
    records["dynamic_run"] = result.to_dict()

    sides = (result.detail or {}).get("sides") or {}
    criterion = dict(result.spec or {})
    try:
        evaluated = evaluate_vulngym(criterion)
    except Exception as exc:                     # noqa: BLE001 - 判据函数拒收即失败
        raise DynamicExecError(
            f"dynamic executor: criterion rejected: {type(exc).__name__}: {exc}",
            records=records)
    # 判据函数给两块：`inputs` 是两侧观测事实，`checks` 是布尔判定；
    # 本模块只搬事实 + 布尔，不搬判据结论。
    facts = dict(evaluated.get("inputs") or {})
    booleans = dict(evaluated.get("checks") or {})
    blockers = [str(b) for b in (evaluated.get("blockers") or [])]
    closed = {side: bool((criterion.get(side) or {}).get("connection_closed"))
              for side in ("baseline", "patched")}
    checks = {
        "method": _text((result.checks or {}).get("method")) or "GET",
        "baseline_status": facts.get("baseline_status"),
        "patched_status": facts.get("patched_status"),
        "baseline_body_sha256": _text(facts.get("baseline_body_sha256")),
        "patched_body_sha256": _text(facts.get("patched_body_sha256")),
        "baseline_closed": closed["baseline"],
        "patched_closed": closed["patched"],
        **booleans,
    }

    if not result.completed:
        raise DynamicExecError(
            "dynamic executor: runner did not complete ("
            + ",".join(result.blockers or ["runner_incomplete"]) + ")",
            records=records)
    # 两侧都没拿到响应（都断开/都超时）：这不是“没有差异”，是没观测到
    responded = [side for side in ("baseline", "patched")
                 if _responded(criterion.get(side) or {})]
    if not responded:
        raise DynamicExecError(
            "dynamic executor: no observable response from baseline,patched"
            + (":" + ",".join(blockers) if blockers else ""),
            records=records)
    missing = [name for name, key in (("baseline", "baseline_recorded"),
                                      ("patched", "patched_recorded"))
               if not booleans.get(key)]
    if missing:
        raise DynamicExecError(
            "dynamic executor: no observable response from "
            + ",".join(missing)
            + (":" + ",".join(blockers) if blockers else ""),
            records=records)

    request = _request_doc({**runner_spec, "method": checks.get("method")})
    summary = _diff_summary(checks, sides)
    log = _diff_log(summary, blockers)
    differs = bool(checks.get("behavior_differs"))
    crashes = [_crash_record(request, summary, log)] if differs else []

    doc = {
        "schema": SCHEMA,
        "task_id": _text(plan.get("task_id")),
        "benchmark": benchmark,
        "plan_sha256": _text(plan.get("sha256")),
        "outcome": OUTCOME_CANDIDATE if differs else OUTCOME_NO_REPRO,
        "request": request,
        "expect": dict(criterion.get("expect") or {}),
        "checks": checks,
        "blockers": blockers,
        "summary": summary,
        "log": log,
        "sides": sides,
        "policy": dict(result.policy or {}),
        "runner": result.runner,
        "evidence": list(result.evidence or []),
        "seconds": float(result.elapsed or 0.0),
        "notes": [
            "两侧各打一次 HTTP：不跟跳转、禁代理、断开与超时如实记账",
            "有差异 ≠ 成立：本模块只产 candidate / no_repro，"
            "结论仍由 verify 的判据（behavior_diff）推导",
        ],
    }
    return {
        "task_id": doc["task_id"],
        "benchmark": benchmark,
        "outcome": doc["outcome"],
        "spec": {"benchmark": "vulngym", **criterion},
        "diff": doc,
        "checks": checks,
        "blockers": blockers,
        "sides": sides,
        "runner": result.to_dict(),
        "policy": doc["policy"],
        "crashes": crashes,
        "bodies": _body_refs(result.evidence),
        # 两条 GET：预算账本里如实记 2 次执行
        "requests": 2,
        "seconds": doc["seconds"],
    }


def dump(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
