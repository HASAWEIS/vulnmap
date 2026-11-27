"""OpenAI 兼容的 LLM 客户端。

只做一件事：发一次请求，拿一个可校验的 JSON 结构回来。**不做决策**——
决策由调用方（阶段）负责，这里是纯传输层。

关键约束（来自 2025-11-09 冒烟，作为策略而非模型永久属性）：
- 请求参数全部落盘，不假设模型默认值；
- 以下任一情况判为 `incomplete`，不算成功：
  `finish_reason=length` / content 为空 / JSON 或 schema 不合格；
- `thinking.disabled` 是**本次任务验证过的配置**，不等于所有场景都该关。
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
DEFAULT_MODEL = "deepseek-flash"
# ====================================================================== 逐调用账本
# 课程验证入口（VerifyStage）的 LLM 调用都经过本模块的 call_json。
# 账本在这里落盘，目的只有一个：**证明某次运行实际发送了什么**，而不是事后猜。
#
# 三条硬口径：
# 1. 关联键是 (run_id, call_id)。call_id 只在单次 run 内递增；跨 run 必须靠
#    run_id 区分，否则两次运行会串账。
# 2. 只记**实际发送**的值。params_sent 取自真正构造出来的请求体；
#    客户端结构性不发送的参数进 params_not_sent；本该有却没记到的进
#    params_missing。三者互斥，不用默认值回填。
# 3. 调用前就被拒绝（预算 / 无 key）也要有一条 refused_before_send，并且
#    request_sha256 为空——证明"没有发出去"，而不是"发了但没记"。

LEDGER_ENV = ("VULNMAP_LLM_LEDGER", "VULNMAP_CALL_LEDGER")

#: 本客户端从不发送的采样参数（结构性缺席，不是"忘了记"）
NOT_SENT_PARAMS = {
    "top_p": "absent_by_design",
    "seed": "absent_by_design",
    "n": "absent_by_design",
    "stop": "absent_by_design",
}

_RUN_CTX = __import__("contextvars").ContextVar("vulnmap_run_ctx", default=None)
_CALL_SEQ: dict = {}
_CALL_SEQ_LOCK = __import__("threading").Lock()


def set_run_context(run_id: str, stage: str = "", workspace=None):
    """绑定本次运行的 (run_id, stage)；返回 token 供 reset 恢复。"""
    return _RUN_CTX.set({"run_id": str(run_id or ""), "stage": str(stage or ""),
                         "workspace": str(workspace or "")})


def reset_run_context(token) -> None:
    try:
        _RUN_CTX.reset(token)
    except (ValueError, RuntimeError):        # token 来自别的上下文：忽略
        pass


def current_run_context() -> dict:
    return dict(_RUN_CTX.get() or {})


def ledger_path():
    """账本路径；未配置返回 None（默认不写任何文件）。"""
    import os
    from pathlib import Path
    for name in LEDGER_ENV:
        value = (os.environ.get(name) or "").strip()
        if value:
            return Path(value).expanduser()
    return None


def _next_call_id(run_id: str) -> str:
    with _CALL_SEQ_LOCK:
        n = int(_CALL_SEQ.get(run_id, 0)) + 1
        _CALL_SEQ[run_id] = n
    return "call-%04d" % n


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _endpoint_host(url: str) -> str:
    text = str(url or "")
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.split("/", 1)[0].split("?", 1)[0]


def _write_ledger(record: dict):
    """追加一条记录；返回 (ok, error)。写失败必须让调用方知道。"""
    import json
    path = ledger_path()
    if path is None:
        return False, "ledger_disabled"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True, ""
    except Exception as exc:                  # noqa: BLE001 - 失败要上报
        return False, "%s: %s" % (type(exc).__name__, exc)


def _ledger_record(*, cfg, ctx, call_id: str, prompt_version: str,
                   call_state: str, refusal: str = "", res=None,
                   error: str = "") -> dict:
    """组装一条调用记录（纯函数；不含 api_key / Authorization）。"""
    import datetime
    body = {}
    request_sha = ""
    response_sha = ""
    usage = {"state": "missing", "reason": "request_not_sent"}
    status = call_state
    attempts = 0
    if res is not None:
        body = dict(getattr(res, "sent_body", {}) or {})
        request_sha = str(getattr(res, "request_sha256", "") or "")
        response_sha = str(getattr(res, "response_sha256", "") or "")
        status = str(getattr(res, "status", "") or "")
        attempts = int(getattr(res, "requests", 0) or 0)
        if getattr(res, "tokens", 0) or getattr(res, "prompt_tokens", 0):
            usage = {"state": "sent",
                     "prompt_tokens": int(getattr(res, "prompt_tokens", 0) or 0),
                     "completion_tokens": int(getattr(res, "completion_tokens", 0) or 0),
                     "total_tokens": int(getattr(res, "tokens", 0) or 0),
                     "reasoning_tokens": int(getattr(res, "reasoning_tokens", 0) or 0)}
        elif request_sha:
            usage = {"state": "missing", "reason": "usage_absent"}
    sent = {}
    missing = {}
    if body:
        for key in ("model", "temperature", "max_tokens", "response_format",
                    "thinking", "top_p", "seed", "n", "stop"):
            if key in body:
                sent[key] = body.get(key)
        for key in ("model", "temperature", "max_tokens"):
            if key not in body:
                missing[key] = "absent_from_request_body"
    else:
        for key in ("model", "temperature", "max_tokens", "response_format",
                    "thinking"):
            missing[key] = ("request_not_built" if call_state != "sent"
                            else "body_not_captured")
    not_sent = {k: v for k, v in NOT_SENT_PARAMS.items() if k not in body}
    return {
        "schema": "vulnmap.verify_call_ledger.v1",
        "schema_version": 1,
        "run_id": str(ctx.get("run_id") or ""),
        "stage": str(ctx.get("stage") or ""),
        "call_id": call_id,
        "call_key": "%s::%s" % (ctx.get("run_id") or "", call_id),
        "prompt_version": str(prompt_version or ""),
        "model": str(getattr(cfg, "model", "") or ""),
        "endpoint_host": _endpoint_host(getattr(cfg, "base_url", "")),
        "call_state": call_state,
        "refusal": refusal,
        "status": status,
        "attempts": attempts,
        "request_sha256": request_sha,
        "response_sha256": response_sha,
        "params_sent": sent,
        "params_not_sent": not_sent,
        "params_missing": missing,
        "usage": usage,
        "error": error,
        "recorded_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
    }


def ledger_check_required(run_id: str, stage: str, required: list) -> dict:
    """按轨迹声明的“必需调用”逐条核对账本，而不是比行数。

    required 每项形如 call_id + request_sha256，由运行轨迹（verify 每轮 llm_calls）给出。
    检查项：missing（本 run 无此 call_id）/ foreign（只在别的 run）/
    hash_mismatch（哈希不符）/ wrong_state（不是 sent，不能顶替）。

    status=complete 要求 required 非空且四类问题都为空；只描述可追溯性，
    不参与漏洞判定。
    """
    import json
    path = ledger_path()
    if path is None:
        return {"status": "not_recorded", "reason": "ledger_disabled",
                "checked": 0, "missing": [], "foreign": [], "hash_mismatch": [],
                "wrong_state": [], "rows": 0, "refused": 0, "enabled": False}
    rows, bad_lines = [], 0
    try:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:                 # noqa: BLE001
                    bad_lines += 1
    except OSError as exc:
        return {"status": "incomplete", "reason": "ledger_unreadable: %s" % exc,
                "checked": 0, "missing": [], "foreign": [], "hash_mismatch": [],
                "wrong_state": [], "rows": 0, "refused": 0, "enabled": True}

    scoped = [r for r in rows
              if str(r.get("run_id") or "") == str(run_id or "")
              and (not stage or str(r.get("stage") or "") == str(stage or ""))]
    by_id = {str(r.get("call_id") or ""): r for r in scoped}
    any_run = {str(r.get("call_id") or "") for r in rows}

    missing, foreign, mismatch, wrong_state = [], [], [], []
    checked = 0
    for item in required or ():
        cid = str((item or {}).get("call_id") or "")
        if not cid:
            continue
        checked += 1
        row = by_id.get(cid)
        if row is None:
            (foreign if cid in any_run else missing).append(cid)
            continue
        if str(row.get("call_state") or "") != "sent":
            wrong_state.append({"call_id": cid,
                                "call_state": row.get("call_state")})
            continue
        expected = str((item or {}).get("request_sha256") or "")
        got = str(row.get("request_sha256") or "")
        if (expected and got != expected) or not got:
            mismatch.append({"call_id": cid, "expected": expected, "actual": got})

    problems = bool(missing or foreign or mismatch or wrong_state or bad_lines)
    if not required:
        status, reason = "incomplete", "no_required_calls_declared"
    elif problems:
        status, reason = "incomplete", "required_calls_not_fully_traced"
    else:
        status, reason = "complete", ""
    return {"status": status, "reason": reason, "checked": checked,
            "missing": missing, "foreign": foreign,
            "hash_mismatch": mismatch, "wrong_state": wrong_state,
            "rows": len(scoped), "refused": sum(
                1 for r in scoped if r.get("call_state") == "refused_before_send"),
            "enabled": True, "path": str(path)}


def ledger_summary(run_id: str, stage: str = "") -> dict:
    """只读汇总：本次 run（可按 stage 过滤）的账本完整性。

    供 VerifyStage 判断"参数证据是否完整"；**不参与漏洞判定**。
    """
    import json
    path = ledger_path()
    if path is None:
        return {"status": "not_recorded", "reason": "ledger_disabled",
                "enabled": False, "rows": 0, "sent": 0, "refused": 0,
                "with_request_hash": 0, "failed_writes": 0, "path": ""}
    rows, failed = [], 0
    try:
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:             # noqa: BLE001 - 坏行不计入
                    failed += 1
    except OSError as exc:
        return {"status": "incomplete", "reason": "ledger_unreadable: %s" % exc,
                "enabled": True, "rows": 0, "sent": 0, "refused": 0,
                "with_request_hash": 0, "failed_writes": 1, "path": str(path)}
    scoped = [r for r in rows
              if str(r.get("run_id") or "") == str(run_id or "")
              and (not stage or str(r.get("stage") or "") == str(stage or ""))]
    sent = [r for r in scoped if r.get("call_state") == "sent"]
    refused = [r for r in scoped if r.get("call_state") == "refused_before_send"]
    with_hash = [r for r in sent if r.get("request_sha256")]
    status = "complete"
    reason = ""
    if failed:
        status, reason = "incomplete", "malformed_lines:%d" % failed
    elif sent and len(with_hash) != len(sent):
        status, reason = "incomplete", "sent_without_request_hash"
    elif not sent and not refused:
        status, reason = "incomplete", "no_rows_for_run"
    return {"status": status, "reason": reason, "enabled": True,
            "rows": len(scoped), "sent": len(sent), "refused": len(refused),
            "with_request_hash": len(with_hash), "failed_writes": failed,
            "path": str(path)}

# ====================================================================== 逐调用账本
# 课程验证入口（VerifyStage）的 LLM 调用都经过本模块的 call_json。
# 账本在这里落盘，目的只有一个：**证明某次运行实际发送了什么**，而不是事后猜。
#
# 三条硬口径：
# 1. 关联键是 (run_id, call_id)。call_id 只在单次 run 内递增；跨 run 必须靠
#    run_id 区分，否则两次运行会串账。
# 2. 只记**实际发送**的值。params_sent 取自真正构造出来的请求体；
#    客户端结构性不发送的参数进 params_not_sent；本该有却没记到的进
#    params_missing。三者互斥，不用默认值回填。
# 3. 调用前就被拒绝（预算 / 无 key）也要有一条 refused_before_send，并且
#    request_sha256 为空——证明"没有发出去"，而不是"发了但没记"。

LEDGER_ENV = ("VULNMAP_LLM_LEDGER", "VULNMAP_CALL_LEDGER")

#: 本客户端从不发送的采样参数（结构性缺席，不是"忘了记"）
NOT_SENT_PARAMS = {
    "top_p": "absent_by_design",
    "seed": "absent_by_design",
    "n": "absent_by_design",
    "stop": "absent_by_design",
}

_RUN_CTX = __import__("contextvars").ContextVar("vulnmap_run_ctx", default=None)
_CALL_SEQ: dict = {}
_CALL_SEQ_LOCK = __import__("threading").Lock()


def set_run_context(run_id: str, stage: str = "", workspace=None):
    """绑定本次运行的 (run_id, stage)；返回 token 供 reset 恢复。"""
    return _RUN_CTX.set({"run_id": str(run_id or ""), "stage": str(stage or ""),
                         "workspace": str(workspace or "")})


def reset_run_context(token) -> None:
    try:
        _RUN_CTX.reset(token)
    except (ValueError, RuntimeError):        # token 来自别的上下文：忽略
        pass


def current_run_context() -> dict:
    return dict(_RUN_CTX.get() or {})


def ledger_path():
    """账本路径；未配置返回 None（默认不写任何文件）。"""
    import os
    from pathlib import Path
    for name in LEDGER_ENV:
        value = (os.environ.get(name) or "").strip()
        if value:
            return Path(value).expanduser()
    return None


def _next_call_id(run_id: str) -> str:
    with _CALL_SEQ_LOCK:
        n = int(_CALL_SEQ.get(run_id, 0)) + 1
        _CALL_SEQ[run_id] = n
    return "call-%04d" % n


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _endpoint_host(url: str) -> str:
    text = str(url or "")
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.split("/", 1)[0].split("?", 1)[0]


def _write_ledger(record: dict):
    """追加一条记录；返回 (ok, error)。写失败必须让调用方知道。"""
    import json
    path = ledger_path()
    if path is None:
        return False, "ledger_disabled"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True, ""
    except Exception as exc:                  # noqa: BLE001 - 失败要上报
        return False, "%s: %s" % (type(exc).__name__, exc)




@dataclass
class LlmConfig:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str = ""
    temperature: float = 0.0
    max_tokens: int = 1200
    timeout_seconds: int = 120
    max_retries: int = 1
    disabled_reason: str = ""
    # 显式关闭思考链：本次冒烟中思考会耗尽输出预算，必须先关才能拿到 content
    disable_thinking: bool = True
    extra_body: dict[str, Any] = field(default_factory=dict)

    def request_body(self, system: str, user: str) -> dict:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }
        if self.disable_thinking:
            body["thinking"] = {"type": "disabled"}
        body.update(self.extra_body)
        return body

    def public_params(self) -> dict:
        """落盘用：不含 api_key。"""
        return {"base_url": self.base_url, "model": self.model,
                "temperature": self.temperature, "max_tokens": self.max_tokens,
                "disable_thinking": self.disable_thinking,
                "response_format": "json_object", "max_retries": self.max_retries}


@dataclass
class LlmResult:
    status: str                     # ok / incomplete / failed
    content: str = ""
    parsed: dict | None = None
    error: str = ""
    model: str = ""
    prompt_version: str = ""
    tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    finish_reason: str = ""
    seconds: float = 0.0
    requests: int = 0
    #: 实际发送的请求体（不含任何凭据）；账本只从这里取 sent 值
    sent_body: dict = field(default_factory=dict)
    request_sha256: str = ""
    response_sha256: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_record(self, *, role: str, params: dict, accepted: bool = False,
                  added: list | None = None, rejected_reason: str = "") -> dict:
        """写进 attempts.detail.llm 的结构化记录。"""
        return {
            "role": role,
            "status": self.status,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "tokens": self.tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "finish_reason": self.finish_reason,
            "seconds": round(self.seconds, 2),
            "requests": self.requests,
            "params": params,
            "accepted": accepted,
            "added": added or [],
            "error": self.error,
            "rejected_reason": rejected_reason,
        }


_GUARD: "contextvars.ContextVar" = __import__("contextvars").ContextVar(
    "global_model_budget", default=None)


def set_global_budget(guard) -> None:
    """绑定全局模型预算守卫；设为 None 表示不限制。

    在 call_json 内部检查而不是各阶段自查：任何新增调用点都自动受控，
    不会因为漏写一处检查就让预算形同虚设。
    """
    _GUARD.set(guard)


def global_budget() -> object:
    return _GUARD.get()


def call_json(config: LlmConfig, *, system: str, user: str,
              prompt_version: str) -> LlmResult:
    """对外入口：先查全局预算，调用后记账（所有返回路径都算一次真实请求）。

    超预算抛 `BudgetExhausted`——这是终止条件，不是可降级的失败。
    """
    guard = _GUARD.get()
    ctx = current_run_context()
    call_id = _next_call_id(ctx.get("run_id") or "") if ctx.get("run_id") else ""
    ledger = {"enabled": ledger_path() is not None, "written": False,
              "error": "", "call_id": call_id}

    if guard is not None:
        try:
            guard.precheck()
        except Exception as exc:
            # 预算拒绝：一个字节都没发出去。落一条 refused_before_send，
            # 让"没发"与"发了没记"在账本上可区分，然后照常抛出终止。
            if call_id:
                record = _ledger_record(
                    cfg=config, ctx=ctx, call_id=call_id,
                    prompt_version=prompt_version,
                    call_state="refused_before_send",
                    refusal=type(exc).__name__, error=str(exc))
                ok, err = _write_ledger(record)
                ledger.update({"written": ok, "error": err})
            setattr(exc, "ledger", ledger)
            raise
    try:
        res = _call_json_inner(config, system=system, user=user,
                              prompt_version=prompt_version)
    except Exception as exc:
        # 未捕获异常：至少消耗 1 次（具体重试次数在异常路径上不可知）
        if guard is not None:
            guard.note_call(0, requests=1)
        if call_id:
            record = _ledger_record(
                cfg=config, ctx=ctx, call_id=call_id,
                prompt_version=prompt_version, call_state="sent",
                error="uncaught:%s" % type(exc).__name__)
            ok, err = _write_ledger(record)
            ledger.update({"written": ok, "error": err})
        raise
    if guard is not None:
        # 按实际传输次数记账（含内部重试），失败/超时同样计入
        guard.note_call(res.tokens or 0,
                        requests=getattr(res, "requests", 1) or 1)

    if call_id:
        state = "sent" if res.request_sha256 else "not_sent"
        refusal = "" if state == "sent" else (res.error or "no_request")
        record = _ledger_record(
            cfg=config, ctx=ctx, call_id=call_id,
            prompt_version=prompt_version, call_state=state,
            refusal=refusal, res=res, error=res.error)
        ok, err = _write_ledger(record)
        ledger.update({"written": ok, "error": err})
    res.ledger = ledger
    return res


def _call_json_inner(config: LlmConfig, *, system: str, user: str,
                     prompt_version: str) -> LlmResult:
    if not config.api_key:
        # 对照实验显式禁用时，这不是"失败的调用"，而是"没有调用"——
        # 用独立状态区分，避免污染模型调用统计
        reason = getattr(config, "disabled_reason", "") or "no_api_key"
        return LlmResult(status="disabled" if config.disabled_reason else "failed",
                         error=reason, model=config.model,
                         prompt_version=prompt_version)

    url = config.base_url.rstrip("/") + "/chat/completions"
    body = config.request_body(system, user)
    payload = json.dumps(body).encode()
    request_sha = _sha256_bytes(payload)
    last_err = ""
    started = time.monotonic()
    attempts = 0

    for _ in range(config.max_retries + 1):
        attempts += 1
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {config.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=config.timeout_seconds) as resp:
                raw = resp.read()
                response_sha = _sha256_bytes(raw)
                data = json.loads(raw)
        except urllib.error.HTTPError as exc:
            last_err = f"http_{exc.code}:{exc.read()[:160].decode('utf-8', 'ignore')}"
            if exc.code in (401, 403):
                break          # 认证问题，重试无意义
            continue
        except Exception as exc:                      # 超时 / 网络
            last_err = f"{type(exc).__name__}:{exc}"
            continue

        seconds = time.monotonic() - started
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        usage = data.get("usage") or {}
        detail = usage.get("completion_tokens_details") or {}
        res = LlmResult(
            status="ok", content=(msg.get("content") or ""),
            model=data.get("model") or config.model,
            prompt_version=prompt_version,
            tokens=int(usage.get("total_tokens") or 0),
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            reasoning_tokens=int(detail.get("reasoning_tokens") or 0),
            finish_reason=choice.get("finish_reason") or "",
            seconds=seconds, requests=attempts,
            sent_body=body, request_sha256=request_sha,
            response_sha256=response_sha)

        # 三条判为未完成
        if res.finish_reason == "length":
            res.status, res.error = "incomplete", "finish_reason=length"
            return res
        if not res.content.strip():
            res.status, res.error = "incomplete", "empty_content"
            return res
        try:
            parsed = json.loads(res.content)
        except json.JSONDecodeError as exc:
            res.status, res.error = "incomplete", f"invalid_json:{exc.msg}"
            return res
        if not isinstance(parsed, dict):
            res.status, res.error = "incomplete", "json_not_object"
            return res
        res.parsed = parsed
        return res

    return LlmResult(status="failed", error=last_err or "unknown",
                     model=config.model, prompt_version=prompt_version,
                     seconds=time.monotonic() - started, requests=attempts,
                     sent_body=body, request_sha256=request_sha)


def load_config(ws, task: dict | None = None) -> LlmConfig:
    """从环境变量 / 配置文件 / task.json 读取；不硬编码密钥。"""
    import os
    from pathlib import Path

    cfg = LlmConfig()
    task = task or {}
    llm = task.get("llm") if isinstance(task.get("llm"), dict) else {}
    # 对照实验开关：显式关闭模型的全部参与（规则基线 alone）
    if llm.get("enabled") is False or os.environ.get("VULNMAP_DISABLE_LLM") == "1":
        cfg.api_key = ""
        cfg.disabled_reason = "llm_disabled_for_control"
        return cfg

    cfg.api_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("LLM_API_KEY") or ""
    cfg.base_url = (llm.get("base_url") or os.environ.get("LLM_BASE_URL")
                    or cfg.base_url)
    cfg.model = llm.get("model") or os.environ.get("LLM_MODEL") or cfg.model
    if llm.get("max_tokens"):
        cfg.max_tokens = int(llm["max_tokens"])
    if "disable_thinking" in llm:
        cfg.disable_thinking = bool(llm["disable_thinking"])

    # 仓库级配置可覆盖默认值（不含密钥）
    conf = Path(__file__).resolve().parent.parent / "configs" / "llm.json"
    if conf.exists():
        try:
            extra = json.loads(conf.read_text(encoding="utf-8"))
            for key in ("base_url", "model", "max_tokens", "temperature",
                        "disable_thinking", "timeout_seconds", "max_retries"):
                if key in extra and key not in llm:
                    setattr(cfg, key, extra[key])
        except Exception:
            pass
    return cfg
