"""V3-010：模型调用网关 —— 预算、权限、缓存与密钥卫生的唯一出口。

口径（《V3 完整升级方案》§11「预算与进展控制」）：

- **模型调用统一走预算/权限**：`LLMGateway.call()` 是研究侧唯一允许调 provider 的
  地方。`grant` 里没有 `L2`（外部访问）就直接 `rejected`——不预留、不发请求、
  不花钱：拒绝发生在“钱动之前”。
- **调用前以事务预留最大可能用量**：`tokens = 估算 prompt tokens + max_tokens`、
  `turns = 1`，价格表认识该模型时再加 `usd`。原子性由 `BudgetLedger.reserve()`
  的 `BEGIN IMMEDIATE` 事务保证（本模块不自己造锁），所以并发 worker 不会双花。
- **调用后按 provider usage 结算**：`prompt_tokens` 与 `completion_tokens` 都在
  → 按真实值 `settle({tokens, usd})`，`usage_source="provider"`。
- **usage 缺失标 unknown 并按预留保守扣账**：缺任何一个字段就 `settle(None)`
  让账本按预留额扣，`usage_source="unknown"`、`usage_missing=True`——**绝不填 0**
  把成本抹掉（0 的含义是“确实没花”，不是“不知道花多少”）。
- **失败/超时/协议错误也计费**：client 抛异常、返回非 Mapping、usage 结构不认识，
  钱都已经花出去了，一律 `settle(None)` 保守扣账；错误只写进 `ModelCall.error`，
  不向调用方抛（抛出去只会让人重试，重试就是再花一次钱）。
- **缓存命中如实标记**：键含模型/上下正文/工具 schema/采样参数/policy 版本，
  命中则 `cached=True`、`usage_source="cached"`、`charged={}`、
  `reservation_id=""`，不预留也不调用。缓存不冒充“这次调用过”。
- **无 key = 规则回退**：`client is None` 或 `key_provider()` 给不出 key 时返回
  `status="skipped"` / `error.code="no_key"` / `error.fallback="rule"`，零计费。
  这条记录必须存在且清楚：不能既没调模型、又让别人以为调过。
- **没有价格表就不写金额**：scope（含祖先链）设了 `usd` 硬上限而价格表不认识
  该模型 → `rejected` / `error.code="price_unknown"`。设了钱的上限却按未知单价
  放行，就是“谎称成本受控”。
- **API key 绝不进 agent workspace / 结果 / 日志**：对外只有 `key_ref`
  （平台凭据引用）。key 只在 `call()` 真正要调 client 的那一刻取一次，作为局部
  变量传入，随后丢弃；provider 回包里出现 key 原文 → 文本替换为 `[redacted]`、
  该次调用判 `failed`（`secret_in_output`），并且**不写缓存**。

本模块不执行目标、不写裁决字段、不落盘任何明文凭据；它只把“一次模型调用的
账、权限、缓存与密钥卫生”收在一个对象里。
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from .budget import (BudgetError, BudgetLedger, BudgetRefused, BudgetStop,
                     EMPTY_PRICES, PriceTable)
from .contracts import PERMISSIONS, digest_of, permission_allows

SCHEMA = "vulnmap.adaptive.llm_gateway.v1"
SCHEMA_VERSION = 1

#: policy 版本进缓存键：换策略（例如改采样/改提示规范）后旧缓存不能复用
POLICY_VERSION = "v3-p3"

#: 一次调用的五态。`rejected`=没让做（钱没动）、`skipped`=没 key 走规则回退、
#: `failed`=发了但没成（照样计费）、`ok`=有结果（usage 可能仍是 unknown）、
#: `unknown`=不知道有没有发生（本网关自己不产生，留给上层构造）
CALL_STATES = ("ok", "failed", "unknown", "rejected", "skipped")

#: usage 的来源：provider 真值 / unknown（缺字段）/ cached（缓存回放）/
#: estimated（调用方自报估算，网关不产生）
USAGE_SOURCES = ("provider", "unknown", "cached", "estimated")

#: 外部访问权限层级：模型调用是外部访问，必须有 L2
EXTERNAL_LEVEL = "L2"

#: 脱敏替换串
REDACTED = "[redacted]"

#: 短于这个长度的“key”不可能是真凭据，而且拿它做脱敏会把正常文本全打成
#: `[redacted]`：一律按“没有 key”处理（走规则回退，记 no_key）。
MIN_KEY_LENGTH = 8

#: 账本里这类调用记在哪个“工具”名下（审计能看出是模型花费）
TOOL_NAME = "llm"


# ====================================================================== 错误
class GatewayError(RuntimeError):
    """网关层错误：编程/协议错误，或需要被翻成 `ModelCall` 的拒绝。

    `code` 是稳定的机读码（`permission_denied` / `price_unknown` /
    `budget_exceeded` / `no_key` / `client_error` / `protocol_error` /
    `secret_in_output` …），`reason` 给人看，`hint` 说明“下一步该做什么”。
    额外字段（`fallback`、`limit`、`level`）进 `detail`，由 `to_dict()` 摊平。
    """

    def __init__(self, code: str, reason: str, *, hint: str = "",
                 **detail: Any) -> None:
        self.code = str(code or "gateway_error") or "gateway_error"
        self.reason = str(reason or "")
        self.hint = str(hint or "")
        self.detail: dict[str, Any] = dict(detail)
        super().__init__(f"{self.code}: {self.reason}")

    def to_dict(self) -> dict:
        out = {"code": self.code, "reason": self.reason, "hint": self.hint}
        out.update(self.detail)
        return out


class GatewayRefused(GatewayError):
    """权限/价格/预算拒绝：**调用没有发生**，所以不该产生任何花费。

    构造点只有三处（权限闸门、价格闸门、账本预留），`call()` 把它们统一翻成
    `ModelCall(status="rejected")`；想“硬拒绝”的上层可以自己接住这个类型。
    """


class SecretLeak(GatewayError):
    """key 出现在本不该出现的地方（结果/日志/快照）。"""


# ====================================================================== 模型描述
@dataclass(frozen=True)
class ModelSpec:
    """一个模型的可调用描述：名字、provider、单次输出上限、价格表键。

    `price_key` 让“同一模型在价格表里叫别的名字”（别名/自建代理/本地模型）
    也能算钱；空则用 `name` 当价格表键。
    """

    name: str
    provider: str = ""
    max_tokens: int = 1024
    price_key: str = ""

    def __post_init__(self) -> None:
        if not str(self.name or "").strip():
            raise GatewayError("invalid_model", "ModelSpec.name 不能为空")
        try:
            limit = int(self.max_tokens)
        except (TypeError, ValueError) as exc:
            raise GatewayError(
                "invalid_model",
                f"ModelSpec.max_tokens={self.max_tokens!r} 不是整数") from exc
        if limit <= 0:
            raise GatewayError("invalid_model",
                               f"ModelSpec.max_tokens={limit} 必须为正")
        object.__setattr__(self, "name", str(self.name).strip())
        object.__setattr__(self, "provider", str(self.provider or ""))
        object.__setattr__(self, "price_key", str(self.price_key or ""))
        object.__setattr__(self, "max_tokens", limit)

    @property
    def key(self) -> str:
        """价格表键：显式 `price_key` 优先，否则就是模型名。"""
        return self.price_key or self.name

    def to_dict(self) -> dict:
        return {"name": self.name, "provider": self.provider,
                "max_tokens": self.max_tokens, "price_key": self.price_key}


# ====================================================================== 一次调用
@dataclass(frozen=True)
class ModelCall:
    """一次模型调用的完整账目（不可变；`to_dict()` 是给报告/日志的唯一形状）。

    - `status`：五态之一（见 `CALL_STATES`）；`usage_source` 说明 usage 从哪来；
    - `charged`：账本真正扣掉的量（`tokens`/`turns`/`usd`），拒绝与缓存命中为 `{}`；
    - `reservation_id`：这次调用对应的预留（缓存命中/拒绝为空）；
    - `budget`：调用后的账本视图（含 `stop`），让人一眼看到“还剩多少”；
    - `error`：`{code, reason, hint, ...}` 或 `None`；
    - `key_ref`：**只有引用**，key 原文永不进这里；
    - `usage_missing`：usage 缺失、按预留保守扣账（`to_dict()` 里也给出）；
    - `cost_known`：金额是否有价格表支撑（无价格表时金额就是未知，不是 0）。
    """

    call_id: str
    model: str
    purpose: str = ""
    status: str = "unknown"
    text: str = ""
    usage: Mapping = field(default_factory=dict)
    usage_source: str = "unknown"
    cached: bool = False
    charged: Mapping = field(default_factory=dict)
    reservation_id: str = ""
    budget: Mapping = field(default_factory=dict)
    error: Mapping | None = None
    key_ref: str = ""
    created_at: str = ""
    usage_missing: bool = False
    cost_known: bool = False

    def __post_init__(self) -> None:
        status = str(self.status or "")
        if status not in CALL_STATES:
            raise GatewayError("invalid_status",
                               f"status={status!r} 不在 {list(CALL_STATES)} 内")
        source = str(self.usage_source or "")
        if source not in USAGE_SOURCES:
            raise GatewayError("invalid_usage_source",
                               f"usage_source={source!r} 不在 "
                               f"{list(USAGE_SOURCES)} 内")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "usage_source", source)
        object.__setattr__(self, "call_id", str(self.call_id or ""))
        object.__setattr__(self, "model", str(self.model or ""))
        object.__setattr__(self, "text", "" if self.text is None
                           else str(self.text))

    @property
    def ok(self) -> bool:
        """有可用文本（`ok` 且不是 failed）；`cached` 也算可用。"""
        return self.status == "ok"

    @property
    def invoked(self) -> bool:
        """是否真的打到 provider（拒绝/跳过/缓存命中都是 False）。"""
        return self.status in ("ok", "failed") and not self.cached

    def to_dict(self) -> dict:
        return {
            "call_id": self.call_id,
            "model": self.model,
            "purpose": self.purpose,
            "status": self.status,
            "text": self.text,
            "usage": dict(self.usage or {}),
            "usage_source": self.usage_source,
            "usage_missing": bool(self.usage_missing),
            "cached": bool(self.cached),
            "charged": dict(self.charged or {}),
            "reservation_id": self.reservation_id,
            "budget": dict(self.budget or {}),
            "error": dict(self.error) if self.error else None,
            "key_ref": self.key_ref,
            "created_at": self.created_at,
            # 金额是否有价格表支撑：没价格表就不是“花了 0 元”，而是“不知道花了多少”
            "cost_known": bool(self.cost_known),
        }


# ====================================================================== 工具函数
def estimate_tokens(text: str) -> int:
    """**只用于预留**的粗估：(字符数)//4 + 1。

    这个数字永远不会出现在 `usage` 里（那是 provider 的账）；把它当 usage 上报
    等于编造计量，账本会以为“估算值就是真实值”，失败成本就被抹平了。
    """
    return (len(str(text or ""))) // 4 + 1


def contains_secret(text: str, key: str) -> bool:
    """`text` 里是否出现 key 原文（空 key 一律 False）。"""
    secret = str(key or "")
    if not secret:
        return False
    return secret in str(text or "")


def _secret_paths(doc: Any, key: str, path: str = "result") -> list[str]:
    """递归找 key 原文出现的位置，**只返回路径不返回值**（返回内容就又泄漏一次）。"""
    secret = str(key or "")
    if not secret:
        return []
    found: list[str] = []
    if isinstance(doc, Mapping):
        for name, value in doc.items():
            found.extend(_secret_paths(value, secret, f"{path}.{name}"))
    elif isinstance(doc, (list, tuple)):
        for index, value in enumerate(doc):
            found.extend(_secret_paths(value, secret, f"{path}[{index}]"))
    elif isinstance(doc, (bytes, bytearray)):
        # bytes 以前直接漏检：provider 回 `b"..."` 时 key 会原样进结果与缓存
        if secret.encode("utf-8", "replace") in bytes(doc):
            found.append(path)
    elif isinstance(doc, str) and secret in doc:
        found.append(path)
    return found


def _scrub(doc: Any, key: str) -> Any:
    """把 doc 里所有 key 原文换成 `[redacted]`（结构保持，数字不动）。"""
    secret = str(key or "")
    if not secret:
        return doc
    if isinstance(doc, Mapping):
        return {name: _scrub(value, secret) for name, value in doc.items()}
    if isinstance(doc, (list, tuple)):
        return [_scrub(value, secret) for value in doc]
    if isinstance(doc, (bytes, bytearray)):
        # 解码成 str 再打码：保留原结构就会把 key 留在 bytes 里
        return bytes(doc).decode("utf-8", "replace").replace(secret, REDACTED)
    if isinstance(doc, str):
        return doc.replace(secret, REDACTED)
    return doc


def assert_no_secret(doc: Any, key: str, *, where: str = "结果") -> None:
    """断言 doc 的序列化文本里没有 key；有则抛 `SecretLeak`（报告/快照自检用）。"""
    secret = str(key or "")
    if not secret:
        return
    blob = doc if isinstance(doc, str) else repr(doc)
    if secret in blob:
        raise SecretLeak("secret_in_output",
                         f"{where}里出现了 key 原文（长度 {len(secret)}）",
                         hint="key 只能以 key_ref 形式出现；请先 _scrub 再落地")


def _is_number(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _spec_of(model: Any) -> ModelSpec:
    """`call(model=...)` 接受模型名或 `ModelSpec`（别名/上限/价格键都走后者）。"""
    if isinstance(model, ModelSpec):
        return model
    return ModelSpec(name=str(model or ""))


# ====================================================================== 网关
class LLMGateway:
    """一次 campaign 的模型调用出口：预算、权限、缓存、密钥卫生收在一处。

    依赖注入（全部可选，便于离线测试）：

    - `ledger`：`BudgetLedger`（只用到 `reserve/settle/release/snapshot/
      ensure_scope/ensure_chain/exhausted`，不假设 SQLite 细节）；
    - `scope_id`：本网关记账挂在哪一层（通常 `action:<id>`，由 `child()` 建）；
    - `client`：`client(model=..., payload={...}, key=...) -> Mapping`；
    - `prices`：`PriceTable`；`EMPTY_PRICES` 表示**没有价格表**（不编单价）；
    - `grant`：权限集合（`{"L0"}` 起步）；没有 `L2` 就不能做外部模型调用；
    - `allowed_models`：模型白名单（`None` = 不限）；不在表里 → `rejected`；
    - `key_provider`：`() -> str | None`，平台凭据读取器（**只在调用那一刻取一次**）；
    - `key_ref`：凭据引用（可审计、可进日志；这是唯一允许对外出现的“钥匙身份”）；
    - `cache`：任意支持 `in / [] / []=` 的映射（默认进程内 dict，可换持久层）。
    """

    def __init__(self, ledger: BudgetLedger | Any, scope_id: str, *,
                 client: Callable[..., Mapping] | None = None,
                 prices: PriceTable = EMPTY_PRICES,
                 grant: Iterable[str] = frozenset({"L0"}),
                 allowed_models: Iterable[str] | None = None,
                 key_provider: Callable[[], str | None] | None = None,
                 key_ref: str = "platform-credential:llm",
                 max_output_tokens: int = 1024,
                 cache: Any = None,
                 policy_version: str = POLICY_VERSION,
                 clock: Callable[[], float] = time.time) -> None:
        sid = str(scope_id or "")
        if not sid:
            raise GatewayError("invalid_scope", "scope_id 不能为空",
                               hint="先 ledger.ensure_scope/ensure_chain 再建网关")
        if ledger is None:
            raise GatewayError("invalid_ledger", "ledger 不能为空")
        self.ledger = ledger
        self.scope_id = sid
        self.client = client
        self.prices = prices if prices is not None else EMPTY_PRICES
        self.grant = frozenset(str(item) for item in (grant or ()))
        self.allowed_models = (None if allowed_models is None
                               else frozenset(str(item)
                                              for item in allowed_models))
        self.key_provider = key_provider
        self.key_ref = str(key_ref or "")
        self.max_output_tokens = int(max_output_tokens)
        if self.max_output_tokens <= 0:
            raise GatewayError("invalid_max_tokens",
                               f"max_output_tokens={max_output_tokens} 必须为正")
        # 默认缓存是进程内 dict：跨进程复用请传入共享映射（键已经含 policy 版本）
        self.cache: Any = {} if cache is None else cache
        self.policy_version = str(policy_version or POLICY_VERSION)
        self.clock = clock
        # 动作上下文：child() 会带下来，so 深层调用也知道自己在哪个 action 里
        self.action_id = ""
        self.purpose = ""
        # 计数（本网关自己的视角，不含子网关；子调用的花费在共享账本里，不在计数里）
        self._calls = 0
        self._cached = 0
        self._refused = 0

    # ------------------------------------------------------------------ 身份
    # 工具函数也在类上挂一份：调用方 `gw.contains_secret(text, key)` /
    # `LLMGateway.estimate_tokens(text)` 都写得通，不必记它是模块级还是方法
    contains_secret = staticmethod(contains_secret)
    estimate_tokens = staticmethod(estimate_tokens)

    def _stamp(self) -> str:
        return datetime.fromtimestamp(float(self.clock()),
                                      timezone.utc).isoformat(
                                          timespec="seconds")

    @property
    def key_available(self) -> bool:
        """此刻是否**具备**真实调用条件（有 client 且能取到非空 key）。

        这是一次探测性读取（`key_provider` 会被调一次），只回答布尔值；
        取到的 key 不保留、不记录、不进任何返回值。
        """
        if self.client is None:
            return False
        return bool(self._fetch_key())

    def _fetch_key(self) -> str:
        """取一次 key（局部变量语义：调用方用完即弃，绝不存进字段）。"""
        provider = self.key_provider
        if provider is None:
            return ""
        try:
            raw = provider()
        except Exception:              # 凭据后端故障 = 没有 key，走规则回退
            return ""
        # 空白/换行也算没有 key：拿 "  \n" 去调 provider 只会得到 401，白花一次钱
        secret = str(raw or "").strip()
        if len(secret) < MIN_KEY_LENGTH:
            return ""
        return secret

    # ------------------------------------------------------------------ 子网关
    def child(self, *, action_id: str = "", scope_id: str = "",
              purpose: str = "") -> "LLMGateway":
        """建一个挂在 `action:<id>` 上的子网关：子调用**同时**扣祖先链预算。

        这是“子调用计入同一 campaign 预算”的落地方式：账本 `reserve()` 会沿
        `action → finding → task → run` 逐层校验并逐层扣，所以子网关不可能靠
        “换个 scope”绕过上层上限；共享的 client/prices/grant/cache/key_provider
        也保证子网关不会有第二套权限或第二套价格。

        **父网关要挂在 finding/task 层**：`action` 是叶子层，action 不能挂
        action（账本会在预留时判“层级倒挂”）。所以在 action 层建子网关会**当场**
        失败（`scope_order`），而不是等第一次调用时才在预留里炸——失败要花在
        调用之前，不然就是“钱扣了一半才发现层级不对”。
        """
        target_action = str(action_id or self.action_id or "")
        target_scope = str(scope_id or "")
        if not target_scope:
            if not target_action:
                raise GatewayError(
                    "invalid_scope", "child() 需要 action_id 或 scope_id",
                    hint="控制器每一轮都有自己的 action_id，用它建子 scope")
            target_scope = f"action:{target_action}"
        if target_scope == self.scope_id:
            raise GatewayError("scope_cycle",
                               f"child scope 不能等于自己（{target_scope}）")
        if self._scope_level() == "action":
            raise GatewayError(
                "scope_order",
                f"父 scope {self.scope_id} 已经是 action 层，action 不能挂 "
                f"action（{target_scope}）",
                hint="把网关建在 finding/task 层，再用 child(action_id=…) 开 "
                     "action 子 scope；子调用仍会逐层扣祖先预算")
        try:
            self.ledger.ensure_scope(target_scope, level="action",
                                     parent=self.scope_id)
        except BudgetError as exc:
            raise GatewayError("child_scope_failed", exc.reason,
                               hint=exc.hint, parent=self.scope_id) from exc
        child = LLMGateway(
            self.ledger, target_scope, client=self.client, prices=self.prices,
            grant=self.grant, allowed_models=self.allowed_models,
            key_provider=self.key_provider, key_ref=self.key_ref,
            max_output_tokens=self.max_output_tokens, cache=self.cache,
            policy_version=self.policy_version, clock=self.clock)
        child.action_id = target_action
        child.purpose = str(purpose or self.purpose or "")
        return child

    # ------------------------------------------------------------------ 闸门
    def _require_permission(self, model: str) -> None:
        """① 权限闸门：模型调用是外部访问，必须有 L2（否则不预留、不调用）。"""
        if permission_allows(EXTERNAL_LEVEL, self.grant):
            return
        needed = PERMISSIONS[EXTERNAL_LEVEL]
        raise GatewayRefused(
            "permission_denied",
            f"模型调用 {model!r} 需要 {EXTERNAL_LEVEL}"
            f"（{needed['title']}），本次授权={sorted(self.grant)}",
            hint=needed["needs"], level=EXTERNAL_LEVEL,
            grant=sorted(self.grant), model=model)

    def _require_allowed(self, model: str) -> None:
        """模型白名单（`allowed_models=None` 表示不限）。"""
        if self.allowed_models is None:
            return
        if model in self.allowed_models:
            return
        raise GatewayRefused(
            "model_not_allowed",
            f"模型 {model!r} 不在白名单 {sorted(self.allowed_models)} 内",
            hint="模型白名单由 campaign 决定，调用方不能自己加模型",
            model=model, allowed=sorted(self.allowed_models))

    def _scope_level(self) -> str:
        """本 scope 在哪个层级（`action` 是叶子层，不能再挂 action 子 scope）。"""
        try:
            return str(self.ledger.snapshot(self.scope_id).get("level") or "")
        except Exception:              # 只读探测失败就交给账本自己判
            return ""

    def _usd_limit(self) -> tuple[bool, float | None]:
        """本 scope **及其祖先**是否声明了 `usd` 硬上限（任一命中即为 True）。

        只读 `snapshot()`（网关不假设账本的表结构）；账本不可用时按“没有上限”
        处理——这里不能凭空造出一个上限来拒绝，也不能因为读不到就不记账（记账
        在 reserve 里，账本坏了 reserve 自己会报错）。
        """
        try:
            snap = self.ledger.snapshot(self.scope_id)
        except BudgetError:
            return (False, None)
        except Exception:              # 只读探测失败不改变主流程
            return (False, None)
        docs: list[Mapping] = []
        for level in list(snap.get("levels") or ()):
            if isinstance(level, Mapping):
                docs.append(level.get("limits") or {})
        docs.append(snap.get("limits") or {})
        found = False
        limit: float | None = None
        for doc in docs:
            if "usd" not in doc or doc.get("usd") is None:
                continue
            try:
                value = float(doc["usd"])
            except (TypeError, ValueError):
                continue
            found = True
            limit = value if limit is None else min(limit, value)
        return (found, limit)

    def _reserve(self, spec: ModelSpec, *, prompt_tokens: int,
                 want_tokens: int, action: str, idempotency_key: str,
                 purpose: str):
        """③ 事务预留：tokens + turns(+ usd)。价格不认识的付费调用在这里被拒。"""
        amount: dict[str, float] = {
            "tokens": float(prompt_tokens + want_tokens),
            "turns": 1.0,
        }
        price_key = spec.key
        usd: float | None = None
        if getattr(self.prices, "configured", False):
            usd = self.prices.cost(price_key, prompt_tokens=prompt_tokens,
                                   completion_tokens=want_tokens)
        limited, limit = self._usd_limit()
        if limited and usd is None:
            # 设了钱的上限却不知道单价：放行就是“谎称成本受控”（§11）
            raise GatewayRefused(
                "price_unknown",
                f"scope {self.scope_id} 设了 usd 上限（{limit}），但价格表 "
                f"{getattr(self.prices, 'version', '')!r} 不认识模型价格键 "
                f"{price_key!r}",
                hint="补价格表（含该模型的 input/output 每 1k 单价）或去掉 usd 上限",
                key="usd", scope=self.scope_id, limit=limit,
                price_key=price_key,
                price_version=getattr(self.prices, "version", ""))
        if usd is not None:
            amount["usd"] = float(usd)
        note = (f"model:{spec.name};policy:{self.policy_version};"
                f"prompt_tokens_estimate:{prompt_tokens};"
                f"max_tokens:{want_tokens}")
        if purpose:
            note += f";purpose:{purpose}"
        try:
            return self.ledger.reserve(
                self.scope_id, amount, action_id=action, tool=TOOL_NAME,
                note=note, idempotency_key=str(idempotency_key or ""))
        except BudgetRefused as exc:
            # 预算不够是“没让做”，不是“做了没成”：翻成拒绝，钱一分没动
            folded = {name: value for name, value in exc.to_dict().items()
                      if name not in ("code", "reason", "hint")}
            raise GatewayRefused(
                str(getattr(exc, "code", "") or "budget_exceeded"), exc.reason,
                hint="要更多预算必须重新授权（不能由调用方放大）",
                **folded) from exc

    # ------------------------------------------------------------------ 账目
    def _budget_view(self) -> dict:
        """调用后的账本视图（含 `stop`）：报告里“还剩多少/为什么停”由此而来。"""
        try:
            snap = dict(self.ledger.snapshot(self.scope_id))
        except Exception:
            return {"scope_id": self.scope_id, "available": False}
        view = {
            "scope_id": snap.get("scope", self.scope_id),
            "level": snap.get("level", ""),
            "limits": dict(snap.get("limits") or {}),
            "used": dict(snap.get("used") or {}),
            "reserved": dict(snap.get("reserved") or {}),
            "remaining": dict(snap.get("remaining") or {}),
            "bottleneck": dict(snap.get("bottleneck") or {}),
            "available": True,
        }
        try:
            stop: BudgetStop | None = self.ledger.exhausted(self.scope_id)
        except Exception:
            stop = None
        # 预算终止不改结果真假：这里只附带“该停了”，不写任何结论字段
        view["stop"] = stop.to_dict() if stop is not None else None
        return view

    def _settle(self, reservation_id: str, used: Mapping | None, *,
                note: str) -> dict:
        """结算；缺 usage 时 `used=None` 让账本按**预留额**保守扣账。"""
        if not reservation_id:
            return {"charged": {}, "usage_missing": used is None}
        return dict(self.ledger.settle(reservation_id, used, note=note) or {})

    # ------------------------------------------------------------------ 缓存
    @staticmethod
    def cache_key(*, model: str, prompt: str, system: str, tools: Any,
                  temperature: float, max_tokens: int,
                  policy_version: str) -> str:
        """缓存键：模型/上下文/工具 schema/采样参数/policy 版本，逐项进摘要。"""
        return digest_of({
            "model": str(model or ""),
            "prompt": str(prompt or ""),
            "system": str(system or ""),
            "tools": tools,
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
            "policy_version": str(policy_version or ""),
        })

    def _cache_get(self, key_hash: str) -> Mapping | None:
        """命中返回缓存记录（`None` = 未命中）；缓存后端不可用按未命中。"""
        cache = self.cache
        if not key_hash or cache is None:
            return None
        try:
            if key_hash not in cache:
                return None
            record = cache[key_hash]
        except Exception:
            return None
        return record if isinstance(record, Mapping) else None

    def _cache_set(self, key_hash: str, record: Mapping) -> None:
        if not key_hash or self.cache is None:
            return
        try:
            self.cache[key_hash] = dict(record)
        except Exception:
            # 缓存写失败不影响正确性（只是下次多花一次钱），不改变本次结果
            pass

    def _cache_entries(self) -> int | None:
        try:
            return len(self.cache)
        except Exception:
            return None

    def _resolve_max_tokens(self, requested: Any,
                            spec: ModelSpec) -> int:
        candidate = requested if requested is not None else (
            spec.max_tokens or self.max_output_tokens)
        try:
            value = int(candidate)
        except (TypeError, ValueError) as exc:
            raise GatewayError(
                "invalid_max_tokens",
                f"max_tokens={candidate!r} 不是整数") from exc
        if value <= 0:
            raise GatewayError("invalid_max_tokens",
                               f"max_tokens={value} 必须为正")
        # 网关上限是硬顶：任何调用都不能通过传参放大单次输出（成本上界要可算）
        return min(value, self.max_output_tokens)

    # ------------------------------------------------------------------ 调用
    def call(self, model: str, prompt: str, *, system: str = "",
             max_tokens: int | None = None, temperature: float = 0.0,
             purpose: str = "", tools: Any = None, action_id: str = "",
             idempotency_key: str = "") -> ModelCall:
        """唯一出口：权限 → 缓存 → key → 事务预留 → 调用 → 结算。

        永远返回 `ModelCall`（拒绝/跳过/失败都是记录，不靠抛出表达）。
        """
        spec = _spec_of(model)
        prompt_text = str(prompt or "")
        system_text = str(system or "")
        want_tokens = self._resolve_max_tokens(max_tokens, spec)
        try:
            temp = float(temperature)
        except (TypeError, ValueError) as exc:
            raise GatewayError("invalid_temperature",
                               f"temperature={temperature!r} 不是数字") from exc
        tools_doc = tools if tools is None else list(tools)
        purpose_text = str(purpose or self.purpose or "")
        action = str(action_id or self.action_id or "")
        call_id = "call-" + os.urandom(8).hex()
        created_at = self._stamp()
        self._calls += 1

        # ---------------- ① 权限 / 白名单：拒绝时不预留、不取 key、不调 client
        try:
            self._require_permission(spec.name)
            self._require_allowed(spec.name)
        except GatewayRefused as exc:
            self._refused += 1
            return self._record(call_id=call_id, spec=spec,
                                purpose=purpose_text, status="rejected",
                                error=exc.to_dict(), created_at=created_at)

        # ---------------- ② 缓存：命中即回放（零成本、零外部访问）
        key_hash = self.cache_key(
            model=spec.name, prompt=prompt_text, system=system_text,
            tools=tools_doc, temperature=temp, max_tokens=want_tokens,
            policy_version=self.policy_version)
        hit = self._cache_get(key_hash)
        if hit is not None:
            self._cached += 1
            cached_usage = hit.get("usage") if isinstance(hit, Mapping) else {}
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text, status="ok",
                text=hit.get("text", ""),
                usage=dict(cached_usage or {}),
                usage_source="cached", cached=True, charged={},
                reservation_id="", cost_known=False,
                usage_missing=bool(hit.get("usage_missing")),
                created_at=created_at)

        # ---------------- ③ key：真正要调用时才取，且只取一次（局部变量）
        key = self._fetch_key()
        if self.client is None or not key:
            # 无 key = 规则回退：记清楚“没调过”，零计费
            reason = ("没有注入 client（离线/规则模式）" if self.client is None
                      else f"凭据 {self.key_ref} 取不到 key")
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="skipped",
                error=GatewayError(
                    "no_key", reason,
                    hint="走确定性规则路径；不要把这一步当成“模型给过结论”",
                    fallback="rule", key_ref=self.key_ref).to_dict(),
                created_at=created_at)

        # ---------------- ④ 事务预留（最大可能用量 + usd）
        prompt_tokens = estimate_tokens(system_text + prompt_text)
        try:
            reservation = self._reserve(spec, prompt_tokens=prompt_tokens,
                                       want_tokens=want_tokens, action=action,
                                       idempotency_key=idempotency_key,
                                       purpose=purpose_text)
        except GatewayRefused as exc:
            self._refused += 1
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="rejected", error=exc.to_dict(), created_at=created_at,
                extra_budget={"prompt_tokens_estimate": prompt_tokens,
                              "max_tokens": want_tokens})
        rid = str(getattr(reservation, "reservation_id", ""))
        if not getattr(reservation, "open", True):
            # 同一个 idempotency_key 第二次回来时，账本给的是**已经结算过**的那条
            # 预留：此时再调 provider 就是“不花钱的一次真实调用”（漏扣）。
            # 幂等键只用来防止重试重复扣，不能拿来白嫖，所以这里直接停手。
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="rejected",
                error=GatewayError(
                    "idempotent_replay",
                    f"幂等键 {idempotency_key!r} 对应的预留已结算，"
                    "不能再用它发起新的 provider 调用",
                    hint="每次真实调用用新的幂等键；重试要么复用上次结果，"
                         "要么显式重新预留",
                    reservation_id=rid,
                    reservation_state=getattr(reservation, "state", "")).to_dict(),
                created_at=created_at)

        # ---------------- ⑤ 调用（失败也计费）
        payload = {"prompt": prompt_text, "system": system_text,
                   "max_tokens": want_tokens, "temperature": temp,
                   "tools": tools_doc}
        try:
            raw = self.client(model=spec.name, payload=payload, key=key)
        except Exception as exc:       # 超时/网络/协议：钱已经花出去，照样扣
            reason = _scrub(f"{type(exc).__name__}: {exc}", key)
            settled = self._settle(rid, None, note="client_error")
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="failed", reservation_id=rid,
                charged=dict(settled.get("charged") or {}),
                usage_missing=True, usage_source="unknown",
                cost_known=bool((settled.get("charged") or {}).get("usd")
                                is not None),
                error=GatewayError(
                    "client_error", str(reason),
                    hint="按预留保守扣账；重试要重新预留（重试也是花钱）",
                    retryable=True).to_dict(),
                created_at=created_at)

        if not isinstance(raw, Mapping):
            settled = self._settle(rid, None, note="protocol_error")
            conservative = dict(settled.get("charged") or {})
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="failed", reservation_id=rid,
                charged=conservative,
                usage_missing=True, usage_source="unknown",
                cost_known=conservative.get("usd") is not None,
                error=GatewayError(
                    "protocol_error",
                    f"client 返回 {type(raw).__name__}，不是 Mapping",
                    hint="provider 协议错误同样计费；不要重试到预算耗尽"
                ).to_dict(),
                created_at=created_at)

        # ---------------- ⑥ 密钥卫生：回包里出现 key 原文 → 脱敏 + 判失败
        leaked = _secret_paths(raw, key)
        if leaked:
            text = _scrub(raw.get("text", ""), key)
            usage = _scrub(raw.get("usage") or {}, key)
            if not isinstance(usage, Mapping):
                usage = {}
            settled = self._settle(rid, None, note="secret_in_output")
            conservative = dict(settled.get("charged") or {})
            return self._record(
                call_id=call_id, spec=spec, purpose=purpose_text,
                status="failed", text=text, usage=dict(usage),
                usage_source="unknown", reservation_id=rid,
                charged=conservative,
                usage_missing=True,
                cost_known=conservative.get("usd") is not None,
                error=GatewayError(
                    "secret_in_output",
                    "provider 回包里出现 key 原文，已替换为 "
                    f"{REDACTED}（位置：{leaked}）",
                    hint="换凭据注入方式（不要把它拼进 prompt/工具参数）；"
                         "本结果不入缓存",
                    fields=leaked).to_dict(),
                created_at=created_at)

        # ---------------- ⑦ 结算：有 usage 按真值，缺 usage 保守扣账
        text = raw.get("text", "")
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        text = "" if text is None else str(text)
        usage = raw.get("usage") or {}
        if not isinstance(usage, Mapping):
            usage = {}
        prompt_used = usage.get("prompt_tokens")
        completion_used = usage.get("completion_tokens")
        provider_ok = _is_number(prompt_used) and _is_number(completion_used)
        price_key = spec.key
        if provider_ok:
            # turns 也是已知量：一次调用就是 1 个回合，明写出来免得账本把它当缺项
            real: dict[str, float] = {
                "tokens": float(prompt_used) + float(completion_used),
                "turns": 1.0}
            cost: float | None = None
            if getattr(self.prices, "configured", False):
                cost = self.prices.cost(price_key,
                                        prompt_tokens=float(prompt_used),
                                        completion_tokens=float(completion_used))
            if cost is not None:
                real["usd"] = float(cost)
            settled = self._settle(rid, real, note="provider_usage")
            charged = dict(settled.get("charged") or {})
            record = self._record(
                call_id=call_id, spec=spec, purpose=purpose_text, status="ok",
                text=text, usage=dict(usage), usage_source="provider",
                reservation_id=rid, charged=charged, usage_missing=False,
                cost_known=cost is not None, created_at=created_at)
        else:
            # 缺任一字段就标 unknown：既不填 0，也不假装受控
            settled = self._settle(rid, None, note="usage_unknown")
            charged = dict(settled.get("charged") or {})
            record = self._record(
                call_id=call_id, spec=spec, purpose=purpose_text, status="ok",
                text=text, usage=dict(usage), usage_source="unknown",
                reservation_id=rid, charged=charged, usage_missing=True,
                cost_known=bool(charged.get("usd") is not None),
                created_at=created_at)

        # ---------------- ⑧ 只有真实成功的回包才入缓存（失败/未知不缓存）
        if record.status == "ok":
            self._cache_set(key_hash, {
                "text": record.text,
                "usage": dict(record.usage or {}),
                "usage_missing": bool(record.usage_missing),
                "usage_source": record.usage_source,
                "model": spec.name,
                "created_at": created_at,
                "policy_version": self.policy_version,
            })
        return record

    # ------------------------------------------------------------------ 记录
    def _record(self, *, call_id: str, spec: ModelSpec, purpose: str,
                status: str, text: str = "", usage: Mapping | None = None,
                usage_source: str = "unknown", cached: bool = False,
                charged: Mapping | None = None, reservation_id: str = "",
                error: Mapping | None = None, usage_missing: bool = False,
                cost_known: bool = False, created_at: str = "",
                extra_budget: Mapping | None = None) -> ModelCall:
        """拼一条 ModelCall：预算视图现取（拒绝/跳过也给出“账没动”的证据）。"""
        budget = self._budget_view()
        if extra_budget:
            budget.update(dict(extra_budget))
        return ModelCall(
            call_id=call_id, model=spec.name, purpose=str(purpose or ""),
            status=status, text=str(text or ""), usage=dict(usage or {}),
            usage_source=usage_source, cached=bool(cached),
            charged=dict(charged or {}), reservation_id=str(reservation_id or ""),
            budget=budget, error=dict(error) if error else None,
            key_ref=self.key_ref, created_at=created_at or self._stamp(),
            usage_missing=bool(usage_missing), cost_known=bool(cost_known))

    # ------------------------------------------------------------------ 视图
    def snapshot(self) -> dict:
        """网关自述 + 账本视图 + 计数（**不含 key**，只有 `key_ref`）。"""
        prices_doc: dict = {}
        try:
            prices_doc = self.prices.to_dict()
        except Exception:
            prices_doc = {"version": getattr(self.prices, "version", ""),
                          "configured": bool(getattr(self.prices,
                                                     "configured", False))}
        gateway = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "policy_version": self.policy_version,
            "scope_id": self.scope_id,
            "action_id": self.action_id,
            "purpose": self.purpose,
            # 唯一允许对外的“钥匙身份”：引用名 + 是否存在 + 作用域
            "key_ref": self.key_ref,
            "key_present": self.key_available,
            "key_scope": "platform",
            "grant": sorted(self.grant),
            "allowed_models": (None if self.allowed_models is None
                               else sorted(self.allowed_models)),
            "client": self.client is not None,
            "max_output_tokens": self.max_output_tokens,
            "prices": prices_doc,
            "cache": {"enabled": self.cache is not None,
                      "entries": self._cache_entries()},
            "invoked": self._calls - self._cached - self._refused,
        }
        try:
            budget = dict(self.ledger.snapshot(self.scope_id))
        except Exception:
            budget = {"scope_id": self.scope_id, "available": False}
        return {
            "gateway": gateway,
            "budget": budget,
            "calls": self._calls,
            "cached": self._cached,
            "refused": self._refused,
            # 金额是否有价格表支撑：没有价格表时 usd 是未知，不是 0
            "cost_known": bool(getattr(self.prices, "configured", False)),
        }


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "POLICY_VERSION", "CALL_STATES",
    "USAGE_SOURCES", "EXTERNAL_LEVEL", "REDACTED", "TOOL_NAME",
    "GatewayError", "GatewayRefused", "SecretLeak",
    "ModelSpec", "ModelCall", "LLMGateway",
    "estimate_tokens", "contains_secret", "assert_no_secret",
]
