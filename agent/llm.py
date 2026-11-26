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
    if guard is not None:
        guard.precheck()
    try:
        res = _call_json_inner(config, system=system, user=user,
                              prompt_version=prompt_version)
    except Exception:
        # 未捕获异常：至少消耗 1 次（具体重试次数在异常路径上不可知）
        if guard is not None:
            guard.note_call(0, requests=1)
        raise
    if guard is not None:
        # 按实际传输次数记账（含内部重试），失败/超时同样计入
        guard.note_call(res.tokens or 0,
                        requests=getattr(res, "requests", 1) or 1)
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
                data = json.loads(resp.read())
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
            seconds=seconds, requests=attempts)

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
                     seconds=time.monotonic() - started, requests=attempts)


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
