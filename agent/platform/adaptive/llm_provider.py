"""V3-REAL：真实 OpenAI-compatible chat/completions 只读 provider。

定位（与 `llm_gateway` 的分工）：

- `llm_gateway` 管“一次调用的账、权限、缓存、密钥卫生”，依赖 `BudgetLedger`；
- 本模块是 **A/B 实验用的最薄 provider**：不建账本、不落盘、不写状态/证据/判据，
  只把一轮观测变成一条结构化建议。真实 key **只从环境读取**，且只在发请求那一刻
  作为局部变量进 header，随后丢弃；任何返回值、日志、状态里都只有 `key_ref`。

四条硬口径：

1. **无 key / endpoint / model = blocked**：`status()` 给出 `real_model_status` 与
   `missing_env`；`__call__` 不会发请求，只回结构化错误。绝不拿 mock 冒充真实。
2. **只读**：`READ_ONLY = True`、`real_model = True`；provider 自己没有任何写文件、
   写库、写状态的方法。它只返回建议，过不过闸由 A/B 框架决定。
3. **超时/预算/错误结构化**：`timeout` / `network_error` / `http_<code>` /
   `invalid_json` / `empty_response` / `secret_in_output` 都是稳定机读码，另带
   `error_detail`；预算按调用前（`max_calls`）与调用后（tokens/usd）两段结算。
4. **金额未知不填 0**：没有价格表时 `usd=None`、`usd_known=False`；设了 `max_usd`
   却没有单价 → 直接结构化拒绝（`price_unknown`），不谎称成本受控。
5. **来源可核**：`transport` 只有两种取值——`"urllib"`（默认传输，真实网络）与
   `"injected"`（构造时注入的测试/本地替身）。`status()` 同时给出 `transport` 与
   `result_source`（`real` / `simulated`）；注入 transport 时 `real_model=False`、
   `simulated=True`，`result_source="simulated"`。**注入的替身不可能被标成真实
   模型**：A/B runner 据此把这类运行归入 `summary_scope="simulated"`，永不进
   `real` 统计。

6. **逐调用可核**（本模块唯一的可选写盘）：构造时传 `ledger=CallLedger(path)`（或
   设 `VULNMAP_CALL_LEDGER` 或别名 `VULNMAP_LLM_LEDGER`）才记账——成功 / 失败 / 预算拒绝各写一条三态记录
   （`sent` / `not_sent` / `missing`）+ 请求/响应哈希。**默认 `ledger=None`，一个
   文件都不写**；参数的「没发出去」永不用配置默认值回填。账本实现见
   `call_ledger.py`，口径见 `docs/CALL-LEDGER.md`。

本模块不执行目标、不写裁决字段、不 import 任何数据库；除了显式配置的
`CallLedger`，没有任何文件写入路径。
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .call_ledger import (
    NOT_SENT_DISABLED,
    CallLedger,
    build_call_record,
    ledger_from_env,
)

SCHEMA = "vulnmap.adaptive.llm_provider.v1"
SCHEMA_VERSION = 1

#: provider 类型（报告里只出现这个字符串，不出现 endpoint 全文）
KIND = "openai_compatible_chat"

#: 提示词版本常量：本模块 `_messages()` 打出的 system 模板的版本号。
#: **它不是"历史 run 的 prompt_version"**——那类历史值只能靠落盘证据；这里只声明
#: "这一次调用的 prompt 来自哪一版模板"。真正的内容绑定另由账本里的
#: `request.messages_sha256` 给出（模板里含诊断码/工具表等动态段落，光靠常量不够）。
PROMPT_VERSION = "real-chat-json-v1"

#: 只读标记：A/B 门禁与文档都查这两个布尔
READ_ONLY = True
REAL_MODEL = True

#: endpoint 来源（`status()["endpoint_source"]`）：只看 endpoint 本身。
#: 只有 public HTTPS 才算 `real`；本机/私网/link-local/非 HTTPS 都是 `simulated`。
ENDPOINT_SOURCE_REAL = "real"
ENDPOINT_SOURCE_SIMULATED = "simulated"
ENDPOINT_SOURCES = (ENDPOINT_SOURCE_REAL, ENDPOINT_SOURCE_SIMULATED)

#: 机读的模拟理由码（`status()["simulated_reason"]`）：
#: - `local_endpoint`：localhost / 127.0.0.0/8 / ::1 / 0.0.0.0 / ::；
#: - `private_endpoint`：RFC1918 私网、CGNAT、link-local、其他非 global 地址；
#: - `non_https_endpoint`：scheme 不是 https（含没写 scheme、host 缺失）；
#: - `injected_transport`：构造时注入了测试/本地替身，不产生真实网络调用。
SIMULATED_REASON_LOCAL = "local_endpoint"
SIMULATED_REASON_PRIVATE = "private_endpoint"
SIMULATED_REASON_NON_HTTPS = "non_https_endpoint"
SIMULATED_REASON_INJECTED = "injected_transport"
SIMULATED_REASONS = (SIMULATED_REASON_LOCAL, SIMULATED_REASON_PRIVATE,
                     SIMULATED_REASON_NON_HTTPS, SIMULATED_REASON_INJECTED)

#: 本机主机名白名单（不查 DNS：只按字面判定，避免“解析到 127.0.0.1”漏判）
LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain",
                             "ip6-localhost", "ip6-loopback"})

#: transport 来源（`status()["transport"]`）：
#: - `"urllib"`：没注入 transport，走模块默认的 urllib 网络传输（只说明怎么发，
#:   不证明响应来自真实模型）；
#: - `"injected"`：构造时传了 `transport=`，是测试/本地替身（模拟来源）。
TRANSPORT_URLLIB = "urllib"
TRANSPORT_INJECTED = "injected"

#: 结果来源（`status()["result_source"]`）：
#: - `"real"`：默认 urllib 传输 **且** endpoint 是 public HTTPS，可作真实统计；
#: - `"simulated"`：注入 transport，或 endpoint 是本机/私网/非 HTTPS；结果只用于
#:   框架回归与通路验证，**永不进真实统计**。
RESULT_SOURCE_REAL = "real"
RESULT_SOURCE_SIMULATED = "simulated"
RESULT_SOURCES = (RESULT_SOURCE_REAL, RESULT_SOURCE_SIMULATED)

#: 环境变量（按优先级；key 只从这些名字里取，绝不从文件/参数里取）
ENV_KEY_NAMES = ("VULNMAP_LLM_API_KEY", "DISCOVERY_LLM_API_KEY",
                 "BDVE_LLM_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY",
                 "OPENAI_API_KEY")
ENV_BASE_NAMES = ("VULNMAP_LLM_BASE_URL", "DISCOVERY_LLM_BASE_URL",
                  "LLM_BASE_URL", "BDVE_LLM_ENDPOINT", "OPENAI_BASE_URL")
ENV_MODEL_NAMES = ("VULNMAP_LLM_MODEL", "DISCOVERY_LLM_MODEL",
                   "BDVE_LLM_MODEL", "LLM_MODEL", "OPENAI_MODEL")

#: 可选调参（都不是“能不能跑”的必要条件）
ENV_TIMEOUT = "VULNMAP_LLM_TIMEOUT"
ENV_MAX_CALLS = "VULNMAP_LLM_MAX_CALLS"
ENV_MAX_TOKENS = "VULNMAP_LLM_MAX_TOKENS"
ENV_MAX_USD = "VULNMAP_LLM_MAX_USD"
ENV_PRICE_IN = "VULNMAP_LLM_PRICE_IN_PER_1K"
ENV_PRICE_OUT = "VULNMAP_LLM_PRICE_OUT_PER_1K"
ENV_JSON_MODE = "VULNMAP_LLM_JSON_MODE"

#: 要求的三个必要件（blocked 时逐项进 `missing_env`，用统一逻辑名）
REQUIRED_ENV = ("VULNMAP_LLM_API_KEY", "VULNMAP_LLM_BASE_URL",
                "VULNMAP_LLM_MODEL")

#: 脱敏替换串
REDACTED = "[redacted]"

#: 结果里的稳定错误码（都是机读码，不随异常文本漂移）
ERROR_CODES = ("missing_env", "timeout", "network_error", "http_error",
               "http_401", "http_403", "http_429", "invalid_json",
               "empty_response", "secret_in_output", "price_unknown",
               "protocol_error", "budget_exhausted")

#: 方向：只允许这些动作出现在建议里（与 A/B 的规划/执行分类一致）
DEFAULT_ACTIONS = ("run_epoch", "replay_input", "finish_research",
                   "get_task_facts", "get_execution_facts", "read_source_window",
                   "compare_trials", "propose_seed_spec", "materialize_seeds",
                   "set_dictionary")


class ProviderError(ValueError):
    """provider 配置错误（编程错误，不是环境缺失）。"""


class TransportError(RuntimeError):
    """默认 transport 的结构化失败；`code` 是稳定机读码。"""

    def __init__(self, code: str, reason: str, *, status: int | None = None,
                 retryable: bool = False) -> None:
        self.code = str(code or "network_error")
        self.reason = str(reason or "")
        self.status = status
        self.retryable = bool(retryable)
        super().__init__(f"{self.code}: {self.reason}")


# ====================================================================== 配置
def _pick(env: Mapping[str, str], names: Sequence[str]) -> tuple[str, str]:
    """返回 (值, 命中的环境变量名)；都没有就是 ("", "")。"""
    for name in names:
        value = str(env.get(name) or "").strip()
        if value:
            return value, name
    return "", ""


def _env_float(env: Mapping[str, str], name: str, default: float | None
               ) -> float | None:
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ProviderError(f"{name}={raw!r} 不是数字") from exc
    if value < 0:
        raise ProviderError(f"{name}={value} 不能为负")
    return value


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ProviderError(f"{name}={raw!r} 不是整数") from exc
    if value < 0:
        raise ProviderError(f"{name}={value} 不能为负")
    return value


def _base_url(raw: str) -> str:
    """把 `…/chat/completions` 归一成 base；保留 `/v1` 之类的版本段。"""
    text = str(raw or "").strip().rstrip("/")
    text = text.removesuffix("/chat/completions")
    return text.rstrip("/")


def _host_of(url: str) -> str:
    """只取 host（可审计、又不会把 query/path 里的凭据带出来）。"""
    text = str(url or "")
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.split("/", 1)[0].split("?", 1)[0]


def _host_kind(host: str) -> str:
    """按字面判 host：`local` / `private` / `link_local` / `public` / `unknown`。

    不查 DNS（避免网络依赖与“解析后才变私网”的不确定）；`localhost` 及
    `*.localhost` 直接算 local。IP 字面量用 `ipaddress`：loopback / unspecified
    算 local，link-local 单列，其余非 global（含 RFC1918、CGNAT、保留段）算
    private。主机名不是 IP 时按 public 处理（是否真能解析不影响来源口径：
    public HTTPS 才是 real 的必要条件，不是充分条件）。
    """
    text = str(host or "").strip().lower().rstrip(".")
    if not text:
        return "unknown"
    if text in LOCAL_HOSTNAMES or text.endswith(".localhost"):
        return "local"
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return "public"
    if addr.is_loopback or addr.is_unspecified:
        return "local"
    if addr.is_link_local:
        return "link_local"
    if addr.is_private or not addr.is_global:
        return "private"
    return "public"


def classify_endpoint(base_url: str) -> dict:
    """判定 endpoint 来源：只有 **public HTTPS** 才是 `real`。

    返回 `{"endpoint_source", "simulated_reason", "scheme", "host_kind"}`。
    `simulated_reason` 是稳定机读码（见 `SIMULATED_REASONS`）：

    - `local_endpoint`：localhost / 127.0.0.0/8 / ::1 / 0.0.0.0 / ::；
    - `private_endpoint`：RFC1918、CGNAT、link-local 及其他非 global 地址；
    - `non_https_endpoint`：scheme 不是 https（含没写 scheme、host 缺失）。

    优先级 local > private/link-local > non-HTTPS：`http://127.0.0.1` 报
    `local_endpoint`（更具体），`http://10.0.0.5` 报 `private_endpoint`，
    `http://api.example.test` 报 `non_https_endpoint`。
    """
    text = str(base_url or "").strip()
    scheme = ""
    host = ""
    try:
        parts = urllib.parse.urlsplit(text)
        scheme = str(parts.scheme or "").lower()
        host = str(parts.hostname or "").strip().lower().rstrip(".")
    except ValueError:                     # 畸形 URL 按“不可核”处理
        scheme, host = "", ""
    kind = _host_kind(host)
    reason = ""
    if kind == "local":
        reason = SIMULATED_REASON_LOCAL
    elif kind in ("private", "link_local"):
        reason = SIMULATED_REASON_PRIVATE
    elif kind == "unknown" or scheme != "https":
        reason = SIMULATED_REASON_NON_HTTPS
    return {
        "endpoint_source": (ENDPOINT_SOURCE_SIMULATED if reason
                            else ENDPOINT_SOURCE_REAL),
        "simulated_reason": reason,
        "scheme": scheme,
        "host_kind": kind,
    }


@dataclass(frozen=True)
class ProviderConfig:
    """一次真实调用的配置；`api_key` 永远不进 `repr`/`to_dict()`。"""

    base_url: str
    model: str
    api_key: str = field(default="", repr=False, compare=False)
    timeout_s: float = 30.0
    max_output_tokens: int = 512
    temperature: float = 0.0
    max_calls: int = 16
    max_tokens: int = 20000
    max_usd: float | None = None
    price_in_per_1k: float | None = None
    price_out_per_1k: float | None = None
    json_mode: bool = True
    key_env: str = ""
    base_env: str = ""
    model_env: str = ""

    @property
    def price_known(self) -> bool:
        return (self.price_in_per_1k is not None
                and self.price_out_per_1k is not None)

    @property
    def key_ref(self) -> str:
        return f"env:{self.key_env}" if self.key_env else "env:unset"

    def to_dict(self) -> dict:
        """可落盘形状：**没有 key 字段**。"""
        return {
            "base_url_host": _host_of(self.base_url),
            "model": self.model,
            "key_ref": self.key_ref,
            "timeout_s": float(self.timeout_s),
            "max_output_tokens": int(self.max_output_tokens),
            "temperature": float(self.temperature),
            "budget": {"max_calls": int(self.max_calls),
                       "max_tokens": int(self.max_tokens),
                       "max_usd": self.max_usd,
                       "price_known": self.price_known},
            "json_mode": bool(self.json_mode),
        }


def resolve_env(env: Mapping[str, str] | None = None) -> dict:
    """从环境解析配置；返回 `{"config", "missing_env", "notes"}`。

    只读环境，不修改、不缓存；`config` 里的 key 只在这里出现一次。
    """
    source: Mapping[str, str] = env if env is not None else os.environ
    key, key_env = _pick(source, ENV_KEY_NAMES)
    base, base_env = _pick(source, ENV_BASE_NAMES)
    model, model_env = _pick(source, ENV_MODEL_NAMES)
    missing: list[str] = []
    if not key:
        missing.append(REQUIRED_ENV[0])
    if not base:
        missing.append(REQUIRED_ENV[1])
    if not model:
        missing.append(REQUIRED_ENV[2])
    timeout = _env_float(source, ENV_TIMEOUT, 30.0) or 30.0
    max_calls = _env_int(source, ENV_MAX_CALLS, 16)
    max_tokens = _env_int(source, ENV_MAX_TOKENS, 20000)
    max_usd = _env_float(source, ENV_MAX_USD, None)
    price_in = _env_float(source, ENV_PRICE_IN, None)
    price_out = _env_float(source, ENV_PRICE_OUT, None)
    json_mode = str(source.get(ENV_JSON_MODE, "1")).strip().lower() not in (
        "0", "false", "no", "off")
    return {
        "config": ProviderConfig(
            base_url=_base_url(base), model=model, api_key=key,
            timeout_s=float(timeout), max_calls=int(max_calls),
            max_tokens=int(max_tokens), max_usd=max_usd,
            price_in_per_1k=price_in, price_out_per_1k=price_out,
            json_mode=bool(json_mode), key_env=key_env, base_env=base_env,
            model_env=model_env),
        "missing_env": missing,
        "notes": {
            "key_present": bool(key),
            "base_present": bool(base),
            "model_present": bool(model),
            "price_known": price_in is not None and price_out is not None,
        },
    }


# ====================================================================== 摘要
def _digest(value: Any) -> str:
    import hashlib
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _contains(text: str, secret: str) -> bool:
    return bool(secret) and secret in str(text or "")


def _scrub(value: Any, secret: str) -> Any:
    if not secret:
        return value
    if isinstance(value, Mapping):
        return {k: _scrub(v, secret) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v, secret) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace").replace(secret, REDACTED)
    if isinstance(value, str):
        return value.replace(secret, REDACTED)
    return value


def _parse_content(raw: Any) -> str:
    """从 chat/completions 回包里取第一个 choice 的 content（字符串化）。"""
    if not isinstance(raw, Mapping):
        raise ProviderError("response is not a mapping")
    choices = raw.get("choices")
    if not isinstance(choices, (list, tuple)) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, Mapping):
        return ""
    message = first.get("message") or {}
    if not isinstance(message, Mapping):
        return ""
    content = message.get("content")
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", "replace")
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, Mapping):
                parts.append(str(item.get("text") or ""))
        return "".join(parts)
    return ""


def _finish_reason(raw: Any) -> str:
    """只取 `choices[0].finish_reason`（拿不到就是空串，不猜）。"""
    if not isinstance(raw, Mapping):
        return ""
    choices = raw.get("choices")
    if not isinstance(choices, (list, tuple)) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, Mapping):
        return ""
    return str(first.get("finish_reason") or "")


def _json_object(text: str) -> dict:
    """容忍 ```json 围栏与前后闲话，取第一个 JSON 对象。"""
    body = str(text or "").strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[-1]
        body = body.removesuffix("```")
        body = body.strip()
        if body.lower().startswith("json"):
            body = body[4:].strip()
    try:
        value = json.loads(body)
    except Exception:                     # 再试一次“截取对象”
        start, end = body.find("{"), body.rfind("}")
        if start < 0 or end <= start:
            raise
        value = json.loads(body[start:end + 1])
    if not isinstance(value, Mapping):
        raise ValueError("model output is not a JSON object")
    return dict(value)


def estimate_tokens(text: str) -> int:
    """只用于“请求前”粗估；真实账目只认 provider 的 usage。"""
    return len(str(text or "")) // 4 + 1


# ====================================================================== provider
class RealChatProvider:
    """真实 OpenAI-compatible `POST {base}/chat/completions` 的只读建议器。

    - `offline=False` / `read_only=True` / `mocked=False`：所有实例都一样；
    - **`transport` 只说明怎么发，`endpoint_source` 才说明响应的来源**：
      构造时不传 `transport=` → `transport="urllib"`；传了 `transport=`（测试/本地
      替身）→ `transport="injected"`，理由记 `injected_transport`；
    - `endpoint_source` 由 `classify_endpoint(config.base_url)` 判定：只有 public
      HTTPS 是 `"real"`；localhost / 127.0.0.1 / ::1 / 0.0.0.0 / 私网 / link-local
      / 非 HTTPS 一律 `"simulated"`，`simulated_reason` 为 `local_endpoint` /
      `private_endpoint` / `non_https_endpoint`。**本机 HTTP 仍会真发请求**
      （通路验证），但 `real_model=False`、`simulated=True`、
      `result_source="simulated"`；
    - `result_source="real"` 的必要条件是“没注入 transport **且** endpoint 是
      public HTTPS”。A/B 框架只把这种运行算进真实统计；
    - 所有调用（含失败）进内存 `log`，条目里没有 key、没有 Authorization header；
    - `ledger=CallLedger(path)` 时**另**写一条 append-only 三态账本（含请求/响应
      哈希）；`ledger=None`（默认）不写任何文件。
    """

    offline = False
    read_only = READ_ONLY
    mocked = False
    simulated = False
    result_source = RESULT_SOURCE_REAL
    transport = TRANSPORT_URLLIB
    endpoint_source = ENDPOINT_SOURCE_REAL
    simulated_reason = ""
    kind = KIND

    def __init__(self, config: ProviderConfig, *,
                 transport: Callable[[Mapping], Mapping] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 diagnosis_codes: Sequence[str] | None = None,
                 action_catalog: Sequence[Mapping] | None = None,
                 max_log: int = 64,
                 ledger: CallLedger | None = None,
                 prompt_version: str = PROMPT_VERSION) -> None:
        if not isinstance(config, ProviderConfig):
            raise ProviderError("config 必须是 ProviderConfig")
        # model/base_url 允许为空：那是 blocked 状态，不是构造错误；
        # `status()` 会把缺失项逐条列进 `missing_env`。
        self.config = config
        # 来源 = endpoint 判定 + 是否注入 transport。二者任一为模拟，结果就是
        # simulated：默认 urllib 只证明“请求真的发出去了”，不证明响应来自真实
        # 模型——本地 HTTP fixture 也走 urllib，但 endpoint 是 127.0.0.1。
        injected = transport is not None
        endpoint = classify_endpoint(config.base_url)
        self.endpoint_source = endpoint["endpoint_source"]
        self.endpoint_scheme = endpoint["scheme"]
        self.endpoint_host_kind = endpoint["host_kind"]
        reasons: list[str] = []
        if endpoint["endpoint_source"] == ENDPOINT_SOURCE_SIMULATED:
            reasons.append(endpoint["simulated_reason"])
        if injected:
            reasons.append(SIMULATED_REASON_INJECTED)
        self.simulated_reasons = tuple(reasons)
        self.simulated_reason = self.simulated_reasons[0] if reasons else ""
        self.transport = TRANSPORT_INJECTED if injected else TRANSPORT_URLLIB
        real_model = (not injected
                      and endpoint["endpoint_source"] == ENDPOINT_SOURCE_REAL)
        self.result_source = (RESULT_SOURCE_REAL if real_model
                              else RESULT_SOURCE_SIMULATED)
        self.real_model = real_model
        self.simulated = not real_model
        self.mocked = False
        self._transport = transport if injected else _urllib_transport
        self.clock = clock
        self._diagnosis_codes = tuple(str(c) for c in (diagnosis_codes or ()))
        self._action_catalog = [dict(item) for item in (action_catalog or ())]
        self.max_log = max(1, int(max_log))
        self.log: list[dict] = []
        # 逐调用账本（可选）：None = 不记账（默认不落盘，保持只读语义）
        self.ledger = ledger
        self.prompt_version = str(prompt_version or "")
        self._ledger_written = 0
        self._ledger_errors: list[str] = []
        self._calls_seen = 0
        self._invoked = 0
        self._calls_ok = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._usd_total: float | None = 0.0 if config.price_known else None
        self._exhausted = ""
        self._last_error = ""

    # ------------------------------------------------------------ 身份/状态
    def status(self) -> dict:
        """可落盘状态：`ready` 之外一律 `blocked`，并给出机读的 `blocked_reason`。

        两类 blocker：`missing_env`（key/base/model 缺）与 `price_unknown`
        （设了 `max_usd` 却没有单价）。后者即使 key 齐全也不是 `ready`：
        调一次就无法结算金额，所以 `__call__` 会在传输前拒绝。
        """
        missing = self._missing_env()
        price_unknown = (self.config.max_usd is not None
                         and not self.config.price_known)
        reasons: list[str] = []
        if price_unknown:
            # 设了钱的上限却不知道单价：不谎称成本受控
            reasons.append("price_unknown")
        if missing:
            reasons.append("missing_env")
        if price_unknown:
            missing = list(missing) + [ENV_PRICE_IN, ENV_PRICE_OUT]
        ready = not reasons
        real_model = bool(self.real_model)
        if real_model:
            note = ("真实模型：endpoint 是 public HTTPS 且未注入 transport；"
                    "key 只从环境读取、只在请求头出现一次；"
                    "provider 只回建议，不写状态/证据/判据")
        elif self.endpoint_source == ENDPOINT_SOURCE_SIMULATED:
            note = (f"模拟来源：endpoint 不是 public HTTPS"
                    f"（endpoint_source=simulated，"
                    f"simulated_reason={self.simulated_reason}）；"
                    "HTTP 请求仍会发出（只验证通路），但响应不能证明来自真实"
                    "模型；结果只用于框架/门禁回归，不得进真实统计")
        else:
            note = ("模拟来源：transport 是注入的本地替身"
                    f"（simulated_reason={self.simulated_reason}），"
                    "不产生外网调用；结果只用于框架/门禁回归，不得进真实统计")
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "provider": type(self).__name__, "kind": self.kind,
            "real_model": real_model, "read_only": True, "mocked": False,
            "simulated": bool(self.simulated),
            "transport": self.transport,
            "result_source": self.result_source,
            "endpoint_source": self.endpoint_source,
            "endpoint_scheme": self.endpoint_scheme,
            "endpoint_host_kind": self.endpoint_host_kind,
            "simulated_reason": self.simulated_reason,
            "simulated_reasons": list(self.simulated_reasons),
            "real_model_status": "ready" if ready else "blocked",
            "blocked_reason": (reasons[0] if reasons else ""),
            "blocked_reasons": reasons,
            "price_unknown": bool(price_unknown),
            "max_usd_requires_price": bool(price_unknown),
            "missing_env": sorted(set(missing)),
            "key_present": bool(self.config.api_key),
            "key_ref": self.config.key_ref,
            "base_url_host": _host_of(self.config.base_url),
            "model": self.config.model,
            "prompt_version": self.prompt_version,
            "ledger": self._ledger_status(),
            "budget": {"max_calls": self.config.max_calls,
                        "max_tokens": self.config.max_tokens,
                        "max_usd": self.config.max_usd,
                        "price_known": self.config.price_known},
            "writes": [],
            "note": note,
        }

    def _missing_env(self) -> list[str]:
        missing: list[str] = []
        if not self.config.api_key:
            missing.append(REQUIRED_ENV[0])
        if not self.config.base_url:
            missing.append(REQUIRED_ENV[1])
        if not self.config.model:
            missing.append(REQUIRED_ENV[2])
        return missing

    @property
    def ready(self) -> bool:
        return self.status()["real_model_status"] == "ready"

    def snapshot(self) -> dict:
        return {
            "status": self.status(),
            "transport": self.transport,
            "result_source": self.result_source,
            "endpoint_source": self.endpoint_source,
            "simulated_reason": self.simulated_reason,
            "simulated_reasons": list(self.simulated_reasons),
            "real_model": bool(self.real_model),
            "simulated": bool(self.simulated),
            "calls_seen": self._calls_seen,
            "calls_invoked": self._invoked,
            "calls_ok": self._calls_ok,
            "tokens_in": self._tokens_in,
            "tokens_out": self._tokens_out,
            "usd": self._usd_total,
            "usd_known": self.config.price_known,
            "exhausted": self._exhausted,
            "last_error": self._last_error,
            "prompt_version": self.prompt_version,
            "ledger": self._ledger_status(),
            "log": [dict(item) for item in self.log],
        }

    def _ledger_status(self) -> dict:
        """账本状态（可落盘）：路径、已写条数、写失败原因；路径里没有 key。"""
        return {
            "enabled": self.ledger is not None,
            "path": (str(self.ledger.path)
                     if getattr(self.ledger, "path", None) is not None else ""),
            "written": int(self._ledger_written),
            "errors": list(self._ledger_errors),
        }

    # ------------------------------------------------------------ 预算
    def _usd_of(self, tokens_in: int, tokens_out: int) -> float | None:
        if not self.config.price_known:
            return None
        cost = ((tokens_in / 1000.0) * float(self.config.price_in_per_1k)
                + (tokens_out / 1000.0) * float(self.config.price_out_per_1k))
        return round(cost, 8)

    def _budget_refusal(self, code: str) -> dict:
        return {
            "status": "budget_exhausted", "error": code,
            "error_detail": {"code": "budget_exhausted", "limit": code,
                              "reason": f"provider 本地预算触顶：{code}"},
            "diagnosis": {}, "actions": [], "usage": {}, "usd": None,
            "meta": {"read_only": True, "invoked": False},
        }

    def _precheck(self) -> dict | None:
        # 先判钱：没有单价时任何一次调用都无法结算，连预算账都不必记。
        # 这条必须先于 max_calls：否则“设了 max_usd 但没单价”会被
        # budget_exhausted 盖住，读起来像“跑过并触顶”。
        if self.config.max_usd is not None and not self.config.price_known:
            return {
                "status": "environment_error", "error": "price_unknown",
                "error_detail": {
                    "code": "price_unknown",
                    "reason": (f"max_usd={self.config.max_usd} 已设，但没有单价；"
                               "不谎称成本受控"),
                    "hint": f"设 {ENV_PRICE_IN} / {ENV_PRICE_OUT} 或去掉 max_usd"},
                "diagnosis": {}, "actions": [], "usage": {}, "usd": None,
                "meta": {"read_only": True, "invoked": False},
            }
        if self._exhausted:
            return self._budget_refusal(self._exhausted)
        max_calls = int(self.config.max_calls or 0)
        if max_calls > 0 and self._invoked >= max_calls:
            self._exhausted = "max_calls"
            return self._budget_refusal("max_calls")
        return None

    # ------------------------------------------------------------ 提示词
    def _codes(self) -> tuple[str, ...]:
        if self._diagnosis_codes:
            return self._diagnosis_codes
        try:
            from .session import DIAGNOSIS_CODES
            self._diagnosis_codes = tuple(DIAGNOSIS_CODES)
        except Exception:                 # noqa: BLE001 - 拿不到就只给默认动作
            self._diagnosis_codes = ()
        return self._diagnosis_codes

    def _actions(self) -> list[dict]:
        if self._action_catalog:
            return self._action_catalog
        try:
            from .tools import REGISTRY
            self._action_catalog = [
                {"action": spec.name, "description": spec.summary,
                 "params": dict(spec.schema.get("properties") or {}),
                 "required": list(spec.schema.get("required") or ()),
                 "modes": list(spec.allowed_modes)}
                for spec in REGISTRY.specs()]
        except Exception:                 # noqa: BLE001
            self._action_catalog = [{"action": name, "description": "",
                                      "params": {}, "required": [],
                                      "modes": ["explore"]}
                                     for name in DEFAULT_ACTIONS]
        return self._action_catalog

    def _messages(self, payload: Mapping) -> tuple[str, str]:
        codes = list(self._codes())
        catalog = self._actions()
        rule = {
            "role": "system",
            "content": (
                "你是 vulnmap 研究循环的只读诊断顾问。只输出一个 JSON 对象，"
                "不要 markdown、不要解释。\n"
                f"诊断码只能从以下列表取：{json.dumps(codes, ensure_ascii=False)}\n"
                f"动作只能从以下工具取（参数必须符合 params schema）："
                f"{json.dumps(catalog, ensure_ascii=False)}\n"
                "硬规则：\n"
                "1. 只读：不要声称已验证/已确认；禁止输出 verified/confirmed/"
                "verdict/adjudicated/oracle_result/pass 字段。\n"
                "2. 诊断码必须来自列表；动作必须是列表里的工具名。\n"
                "3. 只有已经发生执行、且不是 input_processed=false 时才建议 "
                "run_epoch；input_processed=false 时应换种子。\n"
                "4. 出现候选（candidates>0）时建议 finish_research，不再重跑。\n"
                "5. 最多 2 个动作。\n"
                "输出格式：{\"diagnosis\":{\"code\":\"...\"},"
                "\"actions\":[{\"action\":\"...\",\"params\":{}}],"
                "\"reason\":\"一句话\"}"
            ),
        }
        user = {
            "task_id": str(payload.get("task_id") or ""),
            "round_no": int(payload.get("round_no") or 0),
            "observation": dict(payload.get("observation") or {}),
        }
        return (rule["content"],
                json.dumps(user, ensure_ascii=False, sort_keys=True))

    # ------------------------------------------------------------ 调用
    def __call__(self, payload: Mapping) -> dict:
        started = float(self.clock())
        self._calls_seen += 1
        call_id = f"call-{self._calls_seen:04d}"
        tid = str(payload.get("task_id") or "")
        round_no = int(payload.get("round_no") or 0)

        missing = self._missing_env()
        if missing:
            detail = {"code": "missing_env", "missing_env": sorted(set(missing)),
                      "hint": "配置环境变量后再跑；不要用 mock 结果冒充真实"}
            self._last_error = "missing_env"
            self._record(call_id=call_id, task_id=tid, round_no=round_no,
                         payload=payload, status="environment_error",
                         error="missing_env", usage={}, usd=None,
                         seconds=float(self.clock()) - started, invoked=False)
            # 没有请求体 = 四个 body 参数全部 missing，绝不拿配置默认值回填
            self._ledger_note(call_id=call_id, task_id=tid, round_no=round_no,
                              status="environment_error", error="missing_env",
                              invoked=False)
            return {"status": "environment_error", "error": "missing_env",
                    "error_detail": detail, "diagnosis": {}, "actions": [],
                    "usage": {}, "usd": None,
                    "meta": {"read_only": True, "invoked": False}}

        refusal = self._precheck()
        if refusal is not None:
            self._record(call_id=call_id, task_id=tid, round_no=round_no,
                         payload=payload, status=refusal["status"],
                         error=str(refusal.get("error") or ""), usage={},
                         usd=None, seconds=float(self.clock()) - started,
                         invoked=False)
            # 预算/单价拒绝同样是一条账：状态有了，参数仍是 missing（没发出去）
            self._ledger_note(call_id=call_id, task_id=tid, round_no=round_no,
                              status=str(refusal.get("status") or ""),
                              error=str(refusal.get("error") or ""),
                              invoked=False)
            return refusal

        system, user = self._messages(payload)
        body = {
            "model": self.config.model,
            "messages": [{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            "temperature": float(self.config.temperature),
            "max_tokens": int(self.config.max_output_tokens),
        }
        if self.config.json_mode:
            body["response_format"] = {"type": "json_object"}
        request = {
            "url": self.config.base_url + "/chat/completions",
            "method": "POST",
            "headers": {"Content-Type": "application/json",
                        "Authorization": f"Bearer {self.config.api_key}"},
            "body": body,
            "timeout": float(self.config.timeout_s),
        }
        header_names = tuple(request["headers"])
        self._invoked += 1
        try:
            raw = self._transport(request)
        except TransportError as exc:
            return self._fail(call_id, tid, round_no, payload, exc.code,
                              exc.reason, started,
                              detail={"code": exc.code, "status": exc.status,
                                      "retryable": exc.retryable},
                              request_body=body, header_names=header_names)
        except Exception as exc:          # noqa: BLE001 - 异常文本可能带 URL，必须脱敏
            return self._fail(call_id, tid, round_no, payload, "network_error",
                              _scrub(f"{type(exc).__name__}", self.config.api_key),
                              started,
                              detail={"code": "network_error", "retryable": True},
                              request_body=body, header_names=header_names)

        if not isinstance(raw, Mapping):
            return self._fail(call_id, tid, round_no, payload, "protocol_error",
                              f"transport 返回 {type(raw).__name__}", started,
                              detail={"code": "protocol_error"},
                              request_body=body, header_names=header_names)
        content = _parse_content(raw)
        if not content.strip():
            return self._fail(call_id, tid, round_no, payload, "empty_response",
                              "choices[0].message.content 为空", started,
                              detail={"code": "empty_response"},
                              request_body=body, response_text=content,
                              response_usage=(raw.get("usage")
                                              if isinstance(raw, Mapping) else None),
                              finish_reason=_finish_reason(raw),
                              header_names=header_names)
        if _contains(content, self.config.api_key):
            return self._fail(call_id, tid, round_no, payload,
                              "secret_in_output",
                              "回包出现 key 原文，已丢弃并脱敏", started,
                              detail={"code": "secret_in_output"},
                              text=_scrub(content, self.config.api_key),
                              request_body=body,
                              response_usage=(raw.get("usage")
                                              if isinstance(raw, Mapping) else None),
                              finish_reason=_finish_reason(raw),
                              header_names=header_names)
        try:
            suggestion = _json_object(content)
        except Exception as exc:          # noqa: BLE001
            return self._fail(call_id, tid, round_no, payload, "invalid_json",
                              f"{type(exc).__name__}: 不是合法 JSON 对象",
                              started,
                              detail={"code": "invalid_json"},
                              text=_scrub(content, self.config.api_key),
                              request_body=body,
                              response_usage=(raw.get("usage")
                                              if isinstance(raw, Mapping) else None),
                              finish_reason=_finish_reason(raw),
                              header_names=header_names)

        usage_doc = raw.get("usage") if isinstance(raw, Mapping) else {}
        usage = dict(usage_doc) if isinstance(usage_doc, Mapping) else {}
        tokens_in = _int(usage.get("prompt_tokens"))
        tokens_out = _int(usage.get("completion_tokens"))
        if tokens_in is None or tokens_out is None:
            tokens_in = tokens_in or 0
            tokens_out = tokens_out or 0
            usage_known = False
        else:
            usage_known = True
        self._tokens_in += int(tokens_in)
        self._tokens_out += int(tokens_out)
        usd = self._usd_of(int(tokens_in), int(tokens_out))
        if usd is not None:
            self._usd_total = float(self._usd_total or 0.0) + float(usd)
        self._calls_ok += 1
        self._last_error = ""
        seconds = float(self.clock()) - started

        normalized = {
            "diagnosis": suggestion.get("diagnosis") or {},
            "actions": suggestion.get("actions") or [],
            "reason": str(suggestion.get("reason") or ""),
            "usage": {"tokens_in": int(tokens_in),
                      "tokens_out": int(tokens_out),
                      "prompt_tokens": int(tokens_in),
                      "completion_tokens": int(tokens_out),
                      "total_tokens": int(tokens_in) + int(tokens_out),
                      "usage_known": usage_known},
            "usd": usd,
            "status": "ok",
            "meta": {"model": self.config.model, "read_only": True,
                     "call_id": call_id},
        }
        # 调用后结算：超 tokens / 超钱只影响“下一次”，本次结果照常返回
        over_tokens = (int(self.config.max_tokens or 0) > 0
                       and self._tokens_in + self._tokens_out
                       > int(self.config.max_tokens))
        over_usd = (self.config.max_usd is not None
                    and self._usd_total is not None
                    and float(self._usd_total) > float(self.config.max_usd))
        if over_tokens or over_usd:
            self._exhausted = "max_tokens" if over_tokens else "max_usd"
        self._record(call_id=call_id, task_id=tid, round_no=round_no,
                     payload=payload, status="ok", error="",
                     usage=normalized["usage"], usd=usd, seconds=seconds,
                     invoked=True,
                     suggestion={"diagnosis": normalized["diagnosis"],
                                 "actions": normalized["actions"]})
        # 逐调用账本：body 哈希 / 响应哈希 / 三态参数 / 原始 usage（缺就 null）
        self._ledger_note(call_id=call_id, task_id=tid, round_no=round_no,
                          status="ok", error="", invoked=True,
                          request_body=body, request_url=str(request["url"]),
                          timeout_s=float(self.config.timeout_s),
                          response_content=content,
                          response_usage=(usage_doc
                                          if isinstance(usage_doc, Mapping)
                                          else None),
                          finish_reason=_finish_reason(raw),
                          header_names=tuple(request["headers"]))
        return normalized

    # ------------------------------------------------------------ 失败/记账
    def _fail(self, call_id: str, task_id: str, round_no: int,
              payload: Mapping, code: str, reason: str, started: float, *,
              detail: Mapping | None = None, text: str = "",
              request_body: Mapping | None = None,
              response_text: str | None = None,
              response_usage: Mapping | None = None,
              finish_reason: str = "",
              header_names: Sequence[str] = ()) -> dict:
        self._last_error = str(code)
        seconds = float(self.clock()) - started
        self._record(call_id=call_id, task_id=task_id, round_no=round_no,
                     payload=payload, status="environment_error", error=code,
                     usage={}, usd=None, seconds=seconds, invoked=True,
                     text=text)
        # 失败也是账：请求发出去了 -> request_sha256 有值；响应没回来 -> null
        self._ledger_note(call_id=call_id, task_id=task_id,
                          round_no=round_no, status="environment_error",
                          error=str(code), invoked=True,
                          request_body=request_body,
                          request_url=(self.config.base_url + "/chat/completions"
                                       if request_body is not None else ""),
                          timeout_s=float(self.config.timeout_s),
                          response_content=(response_text
                                            if response_text is not None
                                            else (text or None)),
                          response_usage=response_usage,
                          finish_reason=finish_reason,
                          header_names=tuple(header_names))
        return {
            "status": "environment_error", "error": str(code),
            "error_detail": dict(detail or {"code": code, "reason": reason}),
            "diagnosis": {}, "actions": [], "usage": {}, "usd": None,
            "meta": {"read_only": True, "invoked": True, "reason": reason},
        }

    def _ledger_note(self, *, call_id: str, task_id: str, round_no: int,
                     status: str, error: str, invoked: bool,
                     request_body: Mapping | None = None,
                     request_url: str = "",
                     timeout_s: float | None = None,
                     response_content: str | None = None,
                     response_usage: Mapping | None = None,
                     finish_reason: str = "",
                     header_names: Sequence[str] = ()) -> None:
        """往逐调用账本追加一条（`ledger=None` 时什么都不做）。

        失败语义：账本写不进去**不改变调用结果**，但错误会进
        `snapshot()["ledger"]["errors"]`（可见、不静默）；出现凭据材料的条目由
        `build_call_record` 自己抛错拦住，那一行不写盘（fail-closed on secret）。

        `header_names` 只传 header 的**名字**，值（含 `Authorization: Bearer …`）
        永远不进账本；账本里只有一个 `request.auth_header_present` 布尔。
        """
        if self.ledger is None:
            return
        try:
            record = build_call_record(
                call_id=call_id, task_id=task_id, round_no=round_no,
                status=status, error=error, invoked=invoked,
                model=self.config.model,
                prompt_version=self.prompt_version,
                endpoint_source=self.endpoint_source,
                transport=self.transport,
                request_body=request_body,
                request_url=request_url,
                timeout_s=timeout_s,
                response_content=response_content,
                response_usage=response_usage,
                finish_reason=finish_reason,
                header_names=tuple(header_names),
                not_sent_overrides=(None if self.config.json_mode
                                    else {"response_format": NOT_SENT_DISABLED}),
                secret=self.config.api_key,
            )
            self.ledger.append(record, secret=self.config.api_key)
            self._ledger_written += 1
        except Exception as exc:          # noqa: BLE001 - 记账失败不改调用语义
            self._ledger_errors.append(
                _scrub(f"{type(exc).__name__}: {exc}", self.config.api_key))

    def _record(self, *, call_id: str, task_id: str, round_no: int,
                payload: Mapping, status: str, error: str,
                usage: Mapping, usd: Any, seconds: float, invoked: bool,
                suggestion: Mapping | None = None, text: str = "") -> None:
        """一条调用摘要（只进内存）：没有 key、没有 Authorization header。"""
        observation = dict(payload.get("observation") or {})
        body = {
            "call_id": call_id, "task_id": task_id, "round_no": int(round_no),
            "status": str(status), "error": str(error), "invoked": bool(invoked),
            "request": {
                "model": self.config.model,
                "url_host": _host_of(self.config.base_url),
                "observation_sha256": _digest(observation)[:16],
                "observation_chars": len(json.dumps(observation,
                                                    ensure_ascii=False)),
                "facts_hash": str(observation.get("facts_hash") or ""),
            },
            "response": {
                "text_chars": len(str(text or "")),
                "sha256": (_digest(suggestion)[:16] if suggestion else ""),
                "diagnosis": ((suggestion or {}).get("diagnosis") or ""),
                "actions": [str((item or {}).get("action") or "")
                            for item in ((suggestion or {}).get("actions") or ())
                            if isinstance(item, Mapping)],
            },
            "usage": dict(usage or {}),
            "usd": usd,
            "usd_known": bool(self.config.price_known),
            "seconds": round(float(seconds), 6),
            "read_only": True,
            "transport": self.transport,
            "result_source": self.result_source,
            "endpoint_source": self.endpoint_source,
            "simulated_reason": self.simulated_reason,
        }
        self.log.append(body)
        if len(self.log) > self.max_log:
            del self.log[:len(self.log) - self.max_log]


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


# ====================================================================== transport
def _urllib_transport(request: Mapping) -> Mapping:
    """默认传输：POST JSON，返回解析后的 JSON；失败抛 `TransportError`。"""
    body = json.dumps(dict(request.get("body") or {}), ensure_ascii=False)
    req = urllib.request.Request(
        str(request["url"]), data=body.encode("utf-8"),
        headers=dict(request.get("headers") or {}), method="POST")
    try:
        with urllib.request.urlopen(req,
                                    timeout=float(request.get("timeout") or 30.0)
                                    ) as resp:
            payload = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read()[:400].decode("utf-8", "replace")
        except Exception:                 # noqa: BLE001
            detail = ""
        code = "http_429" if exc.code == 429 else (
            "http_401" if exc.code == 401 else (
                "http_403" if exc.code == 403 else "http_error"))
        raise TransportError(code, f"HTTP {exc.code}: {detail}",
                             status=exc.code,
                             retryable=exc.code in (408, 429, 500, 502, 503, 504)
                             ) from exc
    except TimeoutError as exc:
        raise TransportError("timeout", "请求超时", retryable=True) from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise TransportError("timeout", "请求超时", retryable=True) from exc
        raise TransportError("network_error", str(exc.reason or exc),
                             retryable=True) from exc
    try:
        parsed = json.loads(payload)
    except Exception as exc:
        raise TransportError("protocol_error", "回包不是 JSON") from exc
    if not isinstance(parsed, Mapping):
        raise TransportError("protocol_error",
                             f"回包是 {type(parsed).__name__}，不是 object")
    return dict(parsed)


def attach_ledger_to_provider(provider: Any,
                              ledger: CallLedger | None) -> Any:
    """把账本接到一个**已构造**的 provider 上（就地设置，返回同一个对象）。

    用途：A/B 入口拿到调用方注入的 provider（本地替身/测试 spy）时，账本仍然要
    按环境打开，否则「入口跑了、账本空着」——那等于没有证据。规则：

    - `ledger=None` → 原样返回，什么都不改（默认不记账）；
    - provider 自己没有 `ledger` 槽位（mock/自定义 provider）→ 原样返回，
      不塞属性、不假装已记账；
    - provider **已有**账本 → 保留它，不覆盖（调用方显式给的优先）。
    """
    if ledger is None or provider is None:
        return provider
    if not hasattr(provider, "ledger"):
        return provider
    if getattr(provider, "ledger", None) is not None:
        return provider
    provider.ledger = ledger
    return provider


def provider_from_env(env: Mapping[str, str] | None = None, *,
                      transport: Callable[[Mapping], Mapping] | None = None,
                      clock: Callable[[], float] | None = None,
                      ledger: CallLedger | None = None,
                      prompt_version: str = PROMPT_VERSION
                      ) -> tuple[RealChatProvider, dict]:
    """按环境建 provider；返回 `(provider, status)`（status 可直接进文档）。

    `ledger=None` 时按 `VULNMAP_CALL_LEDGER`（别名 `VULNMAP_LLM_LEDGER`）决定
    是否记账（没设就不记账）；显式传 `ledger=` 则用它（传一个内存账本即可在
    测试里核对三态）。两个环境变量指向不同文件时直接抛 `CallLedgerError`。
    """
    resolved = resolve_env(env)
    provider = RealChatProvider(
        resolved["config"], transport=transport,
        clock=clock or time.monotonic,
        ledger=(ledger if ledger is not None else ledger_from_env(env)),
        prompt_version=prompt_version)
    return provider, provider.status()


__all__ = [
    "DEFAULT_ACTIONS",
    "ENDPOINT_SOURCES",
    "ENDPOINT_SOURCE_REAL",
    "ENDPOINT_SOURCE_SIMULATED",
    "ENV_BASE_NAMES",
    "ENV_KEY_NAMES",
    "ENV_MODEL_NAMES",
    "ERROR_CODES",
    "KIND",
    "LOCAL_HOSTNAMES",
    "PROMPT_VERSION",
    "READ_ONLY",
    "REAL_MODEL",
    "REDACTED",
    "REQUIRED_ENV",
    "RESULT_SOURCES",
    "RESULT_SOURCE_REAL",
    "RESULT_SOURCE_SIMULATED",
    "SCHEMA",
    "SCHEMA_VERSION",
    "SIMULATED_REASONS",
    "SIMULATED_REASON_INJECTED",
    "SIMULATED_REASON_LOCAL",
    "SIMULATED_REASON_NON_HTTPS",
    "SIMULATED_REASON_PRIVATE",
    "TRANSPORT_INJECTED",
    "TRANSPORT_URLLIB",
    "ProviderConfig",
    "ProviderError",
    "RealChatProvider",
    "TransportError",
    "attach_ledger_to_provider",
    "classify_endpoint",
    "estimate_tokens",
    "provider_from_env",
    "resolve_env",
]
