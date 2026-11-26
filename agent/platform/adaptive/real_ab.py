"""V3-REAL：真实模型只读 A/B runner（复用无害回归集，结果不伪造）。

口径：

- **A 臂**：现有确定性规则（`compare.run_ab` 内延迟导入 `adaptive.session`）；
- **B 臂**：真实模型只读建议（`llm_provider.RealChatProvider`），建议逐条过
  `Registry.get()` + `spec.validate()` + `prune_verdict_fields`，永不能写；
- **同一初始条件**：回归集/初始配置/预算/人工规则只定义一次，
  `controls.arms_share_controls` 仍是硬判定；
- **无 key/endpoint 不跑**：直接返回 `real_model_status="blocked"` +
  `missing_env`，`summary=None`（不编造 0 调用、0 token、0 费用）；
- **mock 单独标记**：`mocked=True` + `real_model_status="mocked"`，
  与 `ran` 是互斥状态，不混算；
- **来源可核**：`transport` 只说明“怎么发”，`endpoint_source` 才说明“响应从哪来”。
  `real_model_status="ran"/"failed"` 的必要条件是：**`provider=None`（或 provider
  声明未注入 transport）+ 默认 `urllib` + endpoint 是 public HTTPS**，此时
  `transport="urllib"`、`endpoint_source="real"`、`result_source="real"`；
- **本地 HTTP 也是模拟来源**：默认 `urllib` 打到 `127.0.0.1`/localhost/私网/非
  HTTPS 时，请求确实发出（通路验证），但走 `simulated` 分支：
  `real_model_status="simulated"`、`summary_scope="simulated"`、
  `real_model=False`、`result_source="simulated"`，`simulated_reason` 为
  `local_endpoint` / `private_endpoint` / `non_https_endpoint`；
- **注入 transport 一律模拟**：显式注入 `transport=` 的 `RealChatProvider`
  （测试/本地替身）同样走 `simulated` 分支（`transport="injected"`、
  `simulated_reason` 另含 `injected_transport`），即使 `calls_ok>0` 也**绝不**
  进 `real` 统计；
- **永不自动应用**：`auto_apply=False`；错误采纳 > 0 由 `_ab_gate` 一票否决；
- **逐调用可核**：设 `VULNMAP_LLM_LEDGER`（或主名 `VULNMAP_CALL_LEDGER`）
  时，每次调用（含被拒绝的）往 append-only JSONL 追加一条
  `call_id/task_id/round/model/prompt_version/endpoint_source/transport/`
  `request_sha256/response_sha256/usage/params_sent/params_not_sent/params_missing`；
  文档顶层 `call_ledger = {enabled,path,written,errors}`。**注入 provider 也接账本**。

本模块只写调用方显式给的 `artifacts_dir`（默认不写）；落盘内容只有请求/响应摘要、
usage、费用与门禁，没有 key，也没有 `verified/confirmed`。
"""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from .call_ledger import CallLedger, ledger_from_env
from .compare import (AB_GATE_NOTE, AB_GATE_SCHEMA, AB_SCHEMA_VERSION,
                      AB_VERDICT, ab_regression_tasks, render_ab_markdown,
                      run_ab)
from .llm_provider import (ProviderConfig, RealChatProvider,
                            attach_ledger_to_provider, resolve_env)

SCHEMA = "vulnmap.adaptive.real_ab.v1"
SCHEMA_VERSION = 1

#: 真实模型 A/B 的五种状态（互斥；`mocked`/`simulated` 永不与 `ran` 同时出现）
REAL_STATUSES = ("blocked", "mocked", "simulated", "ran", "failed")

#: 结果来源（顶层 `result_source`）：`real` 可作真实统计；`simulated`（注入 transport）
#: 与 `mock`（offline 假 provider）都只做框架回归；`none` 表示本轮没有产出结果。
RESULT_SOURCES = ("real", "simulated", "mock", "none")

#: 小预算真实跑：≤8 任务、≤12 次调用、≤16000 tokens。
#: 选的是回归集里 8 条（t03 有两轮）：去掉多轮依赖强的 t04/t06，避免小预算下
#: “第 3 轮才出现候选”被预算截断误判成模型答错。
SMALL_TASK_IDS = ("w4-t01", "w4-t02", "w4-t03", "w4-t05",
                  "w4-t07", "w4-t08", "w4-t09", "w4-t10")
SMALL_BUDGET = {"max_rounds": 2, "max_calls": 12,
                "max_tokens": 16000, "max_usd": None}

REAL_AB_NOTE = ("真实模型只读 A/B：B 臂建议永不写入工作副本/状态/证据/判据；"
                "门禁只决定“下一轮默认建议源”，auto_apply 恒 False")
SIMULATED_AB_NOTE = ("模拟来源 A/B（transport=injected，result_source=simulated）："
                     "provider 用的是注入的本地替身，不产生外网调用；"
                     "结果只验证框架与门禁形状，永不计入真实统计")


class RealABError(ValueError):
    """真实 A/B 组装错误（编程错误；环境缺失走 blocked，不抛）。"""


def small_ab_tasks() -> list[dict]:
    """回归集的小预算子集（8 条，保持原顺序）。"""
    wanted = set(SMALL_TASK_IDS)
    return [task for task in ab_regression_tasks()
            if task["task_id"] in wanted]


def _blocked_gate(reason: str, missing: Iterable[str]) -> dict:
    return {
        "schema": AB_GATE_SCHEMA, "schema_version": AB_SCHEMA_VERSION,
        "default_arm": "rules", "default_arm_label": "现有规则",
        "model_advisory_allowed": False, "auto_apply": False,
        "auto_apply_blockers": ["real_model_status:blocked",
                                "proposal_gate:advisory"],
        "reasons": [reason], "checks": [],
        "missing_env": sorted({str(item) for item in missing}),
        "note": AB_GATE_NOTE,
    }


def _mock_status(provider: Any) -> dict:
    return {
        "provider": type(provider).__name__, "kind": "offline_fake",
        "real_model": False, "read_only": False, "mocked": True,
        "simulated": False, "transport": "offline_fake",
        "endpoint_source": "", "simulated_reason": "",
        "result_source": "mock",
        "real_model_status": "mocked",
        "missing_env": [],
        "key_present": False, "key_ref": "",
        "cost_is_fake": True,
        "note": ("mock provider：只用于框架/门禁回归；"
                 "mocked=true，禁止与真实结果混算"),
    }


def _provider_transport(provider: Any) -> str:
    """provider 声明的 transport 来源；老的自定义 provider 没声明就是空串。"""
    return str(getattr(provider, "transport", "") or "")


def _provider_result_source(provider: Any) -> str:
    return str(getattr(provider, "result_source", "") or "")


def _provider_endpoint_source(provider: Any) -> str:
    """provider 声明的 endpoint 来源；老的自定义 provider 没声明就是空串。"""
    return str(getattr(provider, "endpoint_source", "") or "")


def _provider_simulated_reason(provider: Any) -> str:
    return str(getattr(provider, "simulated_reason", "") or "")


def _provider_is_simulated(provider: Any) -> bool:
    """是否是模拟来源（注入替身，或 endpoint 是本机/私网/非 HTTPS）。

    `transport="urllib"` 本身不是真实来源的证据：默认 urllib 打到本地 HTTP
    fixture 时，请求真的发出去了，但 endpoint 不是 public HTTPS，结果仍只进
    simulated，绝不进真实统计。
    """
    return (_provider_result_source(provider) == "simulated"
            or _provider_transport(provider) == "injected"
            or _provider_endpoint_source(provider) == "simulated")


def _simulated_note(*, endpoint_source: str, transport: str,
                    simulated_reason: str) -> str:
    """模拟来源的备注：区分“注入替身”与“本地 HTTP 真发了但来源不算真实”。"""
    if endpoint_source == "simulated":
        return ("模拟来源 A/B（transport={}，endpoint_source=simulated，"
                "simulated_reason={}）：endpoint 是本机/私网或非 HTTPS，"
                "HTTP 请求确实发出去了（通路已验证），但响应不能证明来自真实"
                "模型；summary_scope=simulated，永不计入真实统计").format(
                    transport or "declared",
                    simulated_reason or "unknown")
    return SIMULATED_AB_NOTE


def _simulated_auto_apply_reason(*, endpoint_source: str,
                                 transport: str) -> str:
    if endpoint_source == "simulated":
        return ("endpoint 不是 public HTTPS 的模拟结果：不是真实模型证据，"
                "门禁不授予任何自动应用")
    return "注入 transport 的模拟结果：不是真实模型证据，门禁不授予任何自动应用"


def _check_status_exclusive(doc: Mapping) -> None:
    """`mocked`/`simulated` 与 `ran`/`real` 互斥的硬自检（防止替身冒充真实）。

    任何一条都不允许出现在文档里：

    - `mocked=true` 且 `real_model_status="ran"`；
    - `mocked=true` 且 `real_model=true`；
    - `real_model_status="ran"` 但 `real_model=false`；
    - `real_model_status="mocked"` 但 `mocked=false`；
    - `real_model_status="simulated"` 但 `simulated=false`；
    - `result_source="real"` 但状态不是 `ran/failed`，或 `mocked/real_model=false`；
    - `result_source="simulated"/"mock"` 却带 `real_model=true` 或 `ran/failed`；
    - `result_source="real"` 却声明 `endpoint_source="simulated"` 或
      `transport="injected"`（transport 不证明来源，本地/注入都不能算真实）。
    """
    status = str(doc.get("real_model_status") or "")
    mocked = bool(doc.get("mocked"))
    simulated = bool(doc.get("simulated"))
    real = bool(doc.get("real_model"))
    if status not in REAL_STATUSES:
        raise RealABError(f"real_model_status 非法：{status!r}"
                          f"（只认 {REAL_STATUSES}）")
    if mocked and (status != "mocked" or real):
        raise RealABError("mock 结果被标成真实：mocked 与 ran/real 互斥")
    if status == "mocked" and not mocked:
        raise RealABError("real_model_status=mocked 但 mocked=false")
    if status == "simulated" and not simulated:
        raise RealABError("real_model_status=simulated 但 simulated=false")
    if simulated and (status != "simulated" or real or mocked):
        raise RealABError("模拟结果被标成真实：simulated 与 ran/real/mock 互斥")
    if status == "ran" and not real:
        raise RealABError("real_model_status=ran 但 real_model=false")
    source = str(doc.get("result_source") or "none")
    if source not in RESULT_SOURCES:
        raise RealABError(f"result_source 非法：{source!r}"
                          f"（只认 {RESULT_SOURCES}）")
    endpoint = str(doc.get("endpoint_source") or "")
    if endpoint and endpoint not in ("real", "simulated", "declared"):
        raise RealABError(f"endpoint_source 非法：{endpoint!r}"
                          "（只认 real/simulated/declared）")
    if source == "real":
        if mocked or simulated or not real:
            raise RealABError("result_source=real 但 real_model=false 或带 mock/模拟标记")
        if status not in ("ran", "failed"):
            raise RealABError(f"result_source=real 但状态是 {status!r}（只能是 ran/failed）")
        if endpoint == "simulated":
            raise RealABError("result_source=real 却声明 endpoint_source=simulated"
                              "（本机/私网/非 HTTPS 不能算真实模型）")
        if str(doc.get("transport") or "") == "injected":
            raise RealABError("result_source=real 却声明 transport=injected")
    elif source in ("simulated", "mock") and (real or status in ("ran", "failed")):
        raise RealABError(f"result_source={source} 却记成真实结果（real_model/ran）")


#: A/B 文档里的账本块：只放**事实**（开关/路径/写了几条/错在哪），
#: 不含 key、不含 header、不含条目内容（条目在 append-only JSONL 里）。
LEDGER_BLOCK_NOTE = ("逐调用账本：`call_ledger.written` 是真正落盘的条目数，"
                     "`errors` 非空说明有调用没记上账（调用语义不变，但该条不可核）")


def _ledger_doc(raw: Any) -> dict:
    """把 provider 的 `status()["ledger"]` 规整成文档块（缺就全 False/0）。"""
    doc = raw if isinstance(raw, Mapping) else {}
    return {
        "enabled": bool(doc.get("enabled")),
        "path": str(doc.get("path") or ""),
        "written": int(doc.get("written") or 0),
        "errors": [str(item) for item in (doc.get("errors") or ())],
        "note": LEDGER_BLOCK_NOTE,
    }


def _ledger_block(provider: Any) -> dict:
    """从 provider 读账本状态；没有 `status()` 的 provider 返回「没记账」。"""
    status = provider.status() if hasattr(provider, "status") else {}
    raw = status.get("ledger") if isinstance(status, Mapping) else None
    return _ledger_doc(raw)


def _provider_with_budget(env: Mapping[str, str] | None,
                          budget: Mapping | None,
                          ledger: CallLedger | None = None
                          ) -> RealChatProvider:
    """按环境建真实 provider，并把 A/B 预算同步成 provider 的本地硬顶。

    `max_calls` / `max_tokens` / `max_usd` 全部原样下发：预算门禁只认
    provider 自己的 `_precheck`，runner 不允许在中间“软化”任何一个上限。
    `max_usd` 无单价时 provider 会以 `price_unknown` 在传输前拒绝。

    逐调用账本：显式传 `ledger=` 就用它；否则按 `VULNMAP_CALL_LEDGER` /
    `VULNMAP_LLM_LEDGER` 解析（没设就不记账，默认不落盘）。
    """
    resolved = resolve_env(env)
    cfg: ProviderConfig = resolved["config"]
    doc = dict(budget or {})
    updates: dict = {}
    if int(doc.get("max_calls") or 0) > 0:
        updates["max_calls"] = int(doc["max_calls"])
    if int(doc.get("max_tokens") or 0) > 0:
        updates["max_tokens"] = int(doc["max_tokens"])
    if doc.get("max_usd") is not None:
        # 显式 max_usd 一律下发，不在这里按 price_known 做过滤：
        # 丢掉上限 = 调用照跑且仍可能记 ran，等于把“钱的上限”变成装饰。
        # 没有单价时由 provider 在传输前拒绝（environment_error/price_unknown），
        # 传输 0 次、calls_invoked=0，绝不谎称成本受控。
        updates["max_usd"] = float(doc["max_usd"])
    if updates:
        cfg = replace(cfg, **updates)
    # 逐调用账本：只有显式设了 `VULNMAP_CALL_LEDGER`/`VULNMAP_LLM_LEDGER`
    # 才落盘（默认不写文件）；显式 `ledger=` 优先。
    resolved_ledger = ledger if ledger is not None else ledger_from_env(env)
    return RealChatProvider(cfg, ledger=resolved_ledger)


def run_real_ab(*, tasks: Iterable[Mapping] | None = None, provider: Any = None,
                env: Mapping[str, str] | None = None,
                config: Mapping | None = None,
                budget: Mapping | None = None,
                human_rules: Mapping | None = None,
                label: str = "v3-real-ab", clock: Any = None,
                artifacts_dir: str | Path | None = None,
                allow_mock: bool = True,
                ledger: CallLedger | None = None) -> dict:
    """跑一轮真实模型只读 A/B；无 key/endpoint 时返回 blocked（不伪造）。

    来源口径（`transport` / `endpoint_source` / `result_source`）：

    - **`transport` 只说明怎么发**：`urllib` 是默认网络传输，`injected` 是构造时
      注入的测试替身；
    - **`endpoint_source` 才说明响应从哪来**：只有 public HTTPS 是 `"real"`；
      localhost / 127.0.0.1 / ::1 / 0.0.0.0 / 私网 / link-local / 非 HTTPS 一律
      `"simulated"`（`simulated_reason` = `local_endpoint` /
      `private_endpoint` / `non_https_endpoint`）；
    - `provider=None` → 按环境建 `RealChatProvider`，没注入 transport、走默认
      `urllib`；**只有 endpoint 也是 public HTTPS** 时才可能得到 `ran`/`failed`
      （`transport="urllib"`、`endpoint_source="real"`、`result_source="real"`）；
    - 本地 HTTP fixture（默认 `urllib` 真发请求）走 `simulated` 分支：
      `real_model_status="simulated"`、`summary_scope="simulated"`、
      `real_model=False`、`result_source="simulated"`——通路被验证，但响应不能
      证明来自真实模型；
    - 显式传入的对象若带模拟来源（`transport="injected"` /
      `result_source="simulated"` / `endpoint_source="simulated"`，典型就是
      `RealChatProvider(transport=spy)`）同样走 `simulated` 分支——**即使
      `calls_ok>0` 也不记 `ran`，绝不进真实统计**；
    - 显式传入的 mock（`mocked=True` 或无真实来源声明）走 `mocked` 分支。

    账本参数：`ledger=CallLedger(...)` 显式优先；否则按 `VULNMAP_LLM_LEDGER`
    （主名 `VULNMAP_CALL_LEDGER`）解析；两者都没有就不记账。注入 provider 时
    账本会接到它身上（已有账本不覆盖）。文档顶层 `call_ledger` 报开关/路径/
    条数/错误，条目本体只在 append-only JSONL 里。
    """
    task_list = list(tasks) if tasks is not None else ab_regression_tasks()
    if not task_list:
        raise RealABError("回归集不能为空")

    # 逐调用账本：`ledger=` 显式优先，其次 `VULNMAP_CALL_LEDGER` /
    # `VULNMAP_LLM_LEDGER`；调用方注入 provider 时也要接上（否则「入口跑了、
    # 账本空着」，等于没有证据）。
    if ledger is None:
        ledger = ledger_from_env(env)
    if provider is None:
        provider = _provider_with_budget(env, budget, ledger=ledger)
    else:
        provider = attach_ledger_to_provider(provider, ledger)

    mocked = bool(getattr(provider, "mocked", False))
    transport = _provider_transport(provider)
    result_source = _provider_result_source(provider)
    endpoint_source = _provider_endpoint_source(provider)
    simulated_reason = _provider_simulated_reason(provider)
    simulated_origin = _provider_is_simulated(provider)
    provider_is_real = (bool(getattr(provider, "real_model", False))
                        and not mocked and not simulated_origin)

    if provider_is_real:
        status = provider.status() if hasattr(provider, "status") else {}
        if status.get("real_model_status") != "ready":
            # 预算门禁也要能进 blocked 理由：max_usd 无单价 → price_unknown，
            # 不是笼统的 real_model_blocked（否则读不出“到底被什么挡住”）。
            reason = ("price_unknown"
                      if status.get("blocked_reason") == "price_unknown"
                      else "real_model_blocked")
            doc = _blocked_doc(label=label, tasks=task_list, status=status,
                                reason=reason, transport=transport or "declared",
                                endpoint_source=endpoint_source or "real")
            _check_status_exclusive(doc)
            if artifacts_dir is not None:
                write_real_ab_artifacts(doc, artifacts_dir)
            return doc
        ab_doc = run_ab(tasks=task_list, provider=provider,
                        config=config, budget=budget,
                        human_rules=human_rules, label=label, clock=clock,
                        provider_kind="real")
        snapshot = provider.snapshot() if hasattr(provider, "snapshot") else {}
        calls_ok = int(snapshot.get("calls_ok") or 0)
        doc = dict(ab_doc)
        doc.update({
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "real_model_status": "ran" if calls_ok else "failed",
            "summary_scope": "real",
            "mocked": False, "real_model": True, "simulated": False,
            "transport": transport or "declared",
            "endpoint_source": endpoint_source or "declared",
            "simulated_reason": "",
            "result_source": "real",
            "auto_apply_allowed": False,
            "auto_apply_reason": ("错误采纳门禁 + ProposalGate advisory："
                                  "真实模型也不自动应用"),
            "provider_status": snapshot.get("status") or status,
            "call_ledger": _ledger_block(provider),
            "provider_budget": {
                "calls_seen": snapshot.get("calls_seen", 0),
                "calls_invoked": snapshot.get("calls_invoked", 0),
                "calls_ok": calls_ok,
                "tokens_in": snapshot.get("tokens_in", 0),
                "tokens_out": snapshot.get("tokens_out", 0),
                "usd": snapshot.get("usd"),
                "usd_known": snapshot.get("usd_known"),
                "exhausted": snapshot.get("exhausted", ""),
            },
            "provider_trace": list(snapshot.get("log") or ()),
            "missing_env": list(status.get("missing_env") or ()),
            "note": REAL_AB_NOTE,
        })
    elif simulated_origin:
        # 模拟来源（注入 transport，或 endpoint 是本机/私网/非 HTTPS）：
        # 有调用也只是模拟，绝不记 ran/real。
        status = provider.status() if hasattr(provider, "status") else {}
        if status.get("real_model_status") not in (None, "ready"):
            reason = ("price_unknown"
                      if status.get("blocked_reason") == "price_unknown"
                      else "real_model_blocked")
            doc = _blocked_doc(label=label, tasks=task_list, status=status,
                                reason=reason, transport=transport or "declared",
                                endpoint_source=endpoint_source or "declared",
                                simulated_reason=simulated_reason,
                                result_source="none",
                                note_override=("模拟来源（endpoint_source={}，"
                                               "simulated_reason={}）的 provider 被自身"
                                               "门禁挡住（未就绪）：没有跑、没有指标"
                                               ).format(endpoint_source or "declared",
                                                        simulated_reason or "unknown"))
            _check_status_exclusive(doc)
            if artifacts_dir is not None:
                write_real_ab_artifacts(doc, artifacts_dir)
            return doc
        ab_doc = run_ab(tasks=task_list, provider=provider,
                        config=config, budget=budget,
                        human_rules=human_rules, label=label, clock=clock,
                        provider_kind="simulated")
        snapshot = provider.snapshot() if hasattr(provider, "snapshot") else {}
        calls_ok = int(snapshot.get("calls_ok") or 0)
        doc = dict(ab_doc)
        doc.update({
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "real_model_status": "simulated",
            "summary_scope": "simulated",
            "mocked": False, "real_model": False, "simulated": True,
            "transport": transport or "declared",
            "endpoint_source": endpoint_source or "declared",
            "simulated_reason": simulated_reason or (
                "injected_transport" if transport == "injected" else ""),
            "result_source": "simulated",
            "auto_apply_allowed": False,
            "auto_apply_reason": (_simulated_auto_apply_reason(
                endpoint_source=endpoint_source, transport=transport)),
            "provider_status": snapshot.get("status") or status,
            "call_ledger": _ledger_block(provider),
            "provider_budget": {
                "calls_seen": snapshot.get("calls_seen", 0),
                "calls_invoked": snapshot.get("calls_invoked", 0),
                "calls_ok": calls_ok,
                "tokens_in": snapshot.get("tokens_in", 0),
                "tokens_out": snapshot.get("tokens_out", 0),
                "usd": snapshot.get("usd"),
                "usd_known": snapshot.get("usd_known"),
                "exhausted": snapshot.get("exhausted", ""),
            },
            "provider_trace": list(snapshot.get("log") or ()),
            "missing_env": [],
            "note": _simulated_note(endpoint_source=endpoint_source,
                                    transport=transport,
                                    simulated_reason=simulated_reason),
        })
    else:
        if not allow_mock:
            doc = _blocked_doc(label=label, tasks=task_list,
                                status={"missing_env": []},
                                reason="mock_not_allowed",
                                transport=transport or "offline_fake",
                                endpoint_source="")
            _check_status_exclusive(doc)
            if artifacts_dir is not None:
                write_real_ab_artifacts(doc, artifacts_dir)
            return doc
        if getattr(provider, "offline", False) is not True:
            raise RealABError(
                "mock provider 必须 offline=True；真实 provider 必须 "
                "real_model=True/read_only=True/offline=False；"
                "注入 transport 的 provider 必须是 result_source=simulated")
        ab_doc = run_ab(tasks=task_list, provider=provider,
                        config=config, budget=budget,
                        human_rules=human_rules, label=label, clock=clock,
                        provider_kind="offline")
        doc = dict(ab_doc)
        doc.update({
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "real_model_status": "mocked", "summary_scope": "mock",
            "mocked": True, "real_model": False, "simulated": False,
            "transport": transport or "offline_fake",
            "endpoint_source": "", "simulated_reason": "",
            "result_source": "mock",
            "auto_apply_allowed": False,
            "auto_apply_reason": "mock 结果不能作为真实收益证据",
            "provider_status": _mock_status(provider),
            # mock provider 没有账本槽位：这里恒为「没记账」，不假装记过
            "call_ledger": _ledger_doc(None),
            "provider_trace": {
                "mocked": True,
                "calls": [dict(item) for item in
                          (getattr(provider, "calls", None) or ())],
            },
            "missing_env": [],
            "note": ("mock A/B：mocked=true，只验证框架与门禁；"
                     "不得与真实模型结果混算"),
        })

    _check_status_exclusive(doc)
    if artifacts_dir is not None:
        write_real_ab_artifacts(doc, artifacts_dir)
    return doc


def _blocked_doc(*, label: str, tasks: list, status: Mapping,
                 reason: str, transport: str = "",
                 endpoint_source: str = "",
                 simulated_reason: str = "",
                 result_source: str = "none",
                 note_override: str = "") -> dict:
    """没有 key/endpoint 或预算门禁不成立：不跑、不编数；`summary` 为 None。

    `provider_budget` 里的 0 是**“没有发生传输”**的记账（可核对），
    不是“跑过且免费”的指标：`summary` 仍为 None，指标一律缺失。
    """
    missing = sorted({str(item) for item in (status.get("missing_env") or ())})
    blocked_reason = str(status.get("blocked_reason") or "")
    if note_override:
        note = str(note_override)
    elif blocked_reason == "price_unknown":
        note = ("设了 max_usd 但没有单价（price_unknown）：provider 在传输前拒绝，"
                "调用 0 次、没有指标、没有费用；不拿 mock 冒充真实结果")
    else:
        note = ("未配置真实模型（key/endpoint/model 缺失）：本轮没有调用、"
                "没有指标、没有费用；不拿 mock 冒充真实结果")
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "label": str(label or ""),
        "real_model_status": "blocked",
        "blocked_reason": blocked_reason,
        "summary_scope": None,
        "mocked": False, "real_model": False, "simulated": False,
        "transport": str(transport or status.get("transport") or ""),
        "endpoint_source": str(endpoint_source
                               or status.get("endpoint_source") or ""),
        "simulated_reason": str(simulated_reason
                                or status.get("simulated_reason") or ""),
        "result_source": str(result_source or "none"),
        "auto_apply_allowed": False,
        "auto_apply_reason": "没有真实模型结果，门禁不成立",
        "missing_env": missing,
        "provider_status": dict(status),
        "call_ledger": _ledger_doc(
            status.get("ledger") if isinstance(status, Mapping) else None),
        "provider_trace": [],
        "provider_budget": {
            "calls_seen": 0, "calls_invoked": 0, "calls_ok": 0,
            "tokens_in": 0, "tokens_out": 0,
            "usd": None, "usd_known": False, "exhausted": "",
        },
        "tasks_total": len(tasks),
        "summary": None,
        "gate": _blocked_gate(reason, missing),
        "verdict": AB_VERDICT,
        "note": note,
    }


def _iter_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _iter_text(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_text(item)


def assert_no_secret_material(doc: Mapping, *, secret: str = "") -> None:
    """落盘前自检：文档里不能有 Bearer/Authorization/api_key 值或已知 key。"""
    text = "\n".join(_iter_text(doc))
    if secret and secret in text:
        raise RealABError("key 原文出现在 A/B 文档里")
    lowered = text.lower()
    # 只查真正的凭据材料；`authorization:missing` 这类门禁 blocker 是正常内容
    for needle in ("bearer ", '"authorization":', "api_key=", '"api_key":'):
        if needle in lowered:
            raise RealABError(f"文档里出现凭据材料：{needle!r}")


def write_real_ab_artifacts(doc: Mapping, directory: str | Path) -> dict:
    """把 A/B 文档、markdown 与 provider 调用摘要落盘（默认不调用）。"""
    assert_no_secret_material(doc)
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "real_model_status": doc.get("real_model_status"),
        "summary_scope": doc.get("summary_scope"),
        "result_source": doc.get("result_source"),
        "transport": doc.get("transport"),
        "endpoint_source": doc.get("endpoint_source"),
        "simulated_reason": doc.get("simulated_reason"),
        "mocked": bool(doc.get("mocked")),
        "simulated": bool(doc.get("simulated")),
        "doc": dict(doc),
        "provider_trace": doc.get("provider_trace") or [],
    }
    json_path = root / "real-ab.json"
    md_path = root / "real-ab.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2,
                                    sort_keys=True, default=str) + "\n",
                         encoding="utf-8")
    md_path.write_text(render_real_ab_markdown(doc), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def render_real_ab_markdown(doc: Mapping) -> str:
    """真实 A/B 报告（确定性；没有时间戳，不写裁决）。"""
    status = str(doc.get("real_model_status") or "")
    mocked = bool(doc.get("mocked"))
    simulated = bool(doc.get("simulated"))
    real = bool(doc.get("real_model"))
    source = str(doc.get("result_source") or "none")
    transport = str(doc.get("transport") or "")
    endpoint_source = str(doc.get("endpoint_source") or "")
    simulated_reason = str(doc.get("simulated_reason") or "")
    lines: list[str] = ["## 真实模型只读 A/B（A=规则 / B=模型建议）", ""]
    if doc.get("label"):
        lines.append(f"- 标签：{doc['label']}")
    lines.append(f"- 真实模型：{'是' if real else '否'}"
                 + ("（mock，mocked=true）" if mocked else "")
                 + ("（注入 transport，simulated=true）" if simulated else ""))
    lines.append(f"- real_model_status：`{status}`；summary_scope："
                 f"`{doc.get('summary_scope')}`")
    lines.append(f"- 结果来源：`result_source={source}`；`transport={transport}`"
                 "（transport 只说明怎么发）")
    if endpoint_source:
        lines.append(f"- endpoint 来源：`endpoint_source={endpoint_source}`；"
                     f"`simulated_reason={simulated_reason or '-'}`"
                     "（只有 public HTTPS 才是 `real`）")
    if doc.get("missing_env"):
        lines.append("- 缺失环境变量：" +
                     "、".join(f"`{item}`" for item in doc["missing_env"]))
    provider = doc.get("provider_status") or {}
    if isinstance(provider, Mapping) and provider.get("model"):
        lines.append(f"- 模型：`{provider.get('model')}`；endpoint host："
                     f"`{provider.get('base_url_host')}`；key："
                     f"`{provider.get('key_ref')}`（不落盘）")
    ledger = doc.get("call_ledger") or {}
    if isinstance(ledger, Mapping) and ledger.get("enabled"):
        lines.append(f"- 逐调用账本：`{ledger.get('path')}`"
                     f"（written={ledger.get('written')}，"
                     f"errors={len(ledger.get('errors') or [])}）")
    elif isinstance(ledger, Mapping) and ledger.get("path"):
        lines.append(f"- 逐调用账本：`{ledger.get('path')}`（未写入）")
    else:
        lines.append("- 逐调用账本：未开启（设 `VULNMAP_LLM_LEDGER` 才落盘）")
    lines.append("- 自动应用：**否**"
                 "（恒 False；错误采纳 > 0 一票否决）")
    lines.append("- 是否可开放自动应用：**否**"
                 "（" + str(doc.get("auto_apply_reason") or
                            "门禁不成立") + "）")
    lines.append(f"- verdict：`{doc.get('verdict') or AB_VERDICT}`"
                 "（不产漏洞结论）")
    lines.append("")
    if doc.get("summary") is None:
        if str(doc.get("blocked_reason") or "") == "price_unknown":
            lines.append("> 本轮未运行：设了 `max_usd` 但没有单价"
                         "（`price_unknown`），provider 在传输前拒绝；"
                         "调用 0 次，指标、tokens、费用一律为空（不是 0）。")
        else:
            lines.append("> 本轮未运行：没有 key/endpoint/model，指标、tokens、费用"
                         "一律为空（不是 0）。")
        lines.append("")
        gate = doc.get("gate") or {}
        if gate.get("reasons"):
            lines.append(f"- 门禁理由：{ '、'.join(gate['reasons']) }")
        lines.append(f"> {doc.get('note') or ''}")
        lines.append("")
        return "\n".join(lines)

    body = {
        "label": doc.get("label"), "verdict": doc.get("verdict"),
        "summary": doc.get("summary"), "gate": doc.get("gate"),
        "controls": doc.get("controls"), "note": doc.get("note"),
    }
    lines.append(render_ab_markdown(body).rstrip())
    lines.append("")
    lines.append(f"> {doc.get('note') or REAL_AB_NOTE}")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "REAL_STATUSES", "RESULT_SOURCES",
    "SMALL_TASK_IDS",
    "SMALL_BUDGET", "REAL_AB_NOTE", "SIMULATED_AB_NOTE", "RealABError",
    "small_ab_tasks", "run_real_ab", "render_real_ab_markdown",
    "write_real_ab_artifacts", "assert_no_secret_material",
]
