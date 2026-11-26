"""授权声明（metadata.authorized）的严格解析与缺失策略。

背景（验收 F1）：CLI 的 `--meta authorized=false` 以字符串进入元数据，准入门
直接 `bool("false")` → True，把“未授权”读成了“已授权”。字符串真值判断不能
用来判定授权声明：`bool("false")`、`bool("0")`、`bool("no")` 全为真。

本模块只做一件事：把“文本/JSON 里怎么写授权”收敛成唯一口径。

允许的写法（大小写与首尾空白不敏感）：

- 放行：``true`` / ``1`` / ``yes`` / ``on``（以及 JSON 布尔 ``true``、整数 ``1``）
- 阻断：``false`` / ``0`` / ``no`` / ``off``（以及 JSON 布尔 ``false``、整数 ``0``）
- 其余值（``maybe`` / ``enabled`` / ``""`` / ``2`` / ``null`` / 列表 / 字典）
  一律视为**非法**：提交时拒绝（CLI 退出 2 / API 400），准入时按阻断处理
  （fail-closed，不静默放行）。

缺失策略（MISSING_POLICY）：**默认阻断**。
即任务元数据没有 ``authorized`` 字段时，准入门判 BLOCKED，而不是沿用旧的
“缺省即 True”。产品口径写在 ``docs/ACCEPTANCE-FIXES-20261118.md``，
README 与 ``docs/PLATFORM-V2-*.md`` 同步说明。
"""
from __future__ import annotations

TRUE_TOKENS = frozenset({"true", "1", "yes", "on"})
FALSE_TOKENS = frozenset({"false", "0", "no", "off"})

#: 缺失（未声明）授权时的产品策略：``block`` = 默认阻断。
#: 这是显式常量而不是隐式默认值——改口径必须改这里并同步文档与回归。
MISSING_POLICY = "block"

POLICY_TEXT = (
    "metadata.authorized 缺失 → 默认阻断（MISSING_POLICY=block）；"
    "显式声明 authorized=true/1/yes/on 才放行"
)

FIELD = "authorized"


class AuthorizationError(ValueError):
    """授权字段取值非法（不是明确的 true/false 写法）。"""


def parse_authorized(value) -> bool:
    """把一处授权声明解析成布尔；非法值抛 AuthorizationError。

    只接受明确的 true/false 写法，绝不使用 ``bool(value)``：
    非空字符串恒为真，正是 F1 的根因。
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        # JSON 里 1/0 与文本 "1"/"0" 同义；其余整数没有授权语义
        if value == 1:
            return True
        if value == 0:
            return False
        raise AuthorizationError(
            f"{FIELD} must be one of true/1/yes/on or false/0/no/off, got {value!r}")
    if isinstance(value, str):
        token = value.strip().lower()
        if token in TRUE_TOKENS:
            return True
        if token in FALSE_TOKENS:
            return False
        raise AuthorizationError(
            f"{FIELD} must be one of true/1/yes/on or false/0/no/off, "
            f"got {value!r} (empty/typo values are rejected, not treated as true)")
    raise AuthorizationError(
        f"{FIELD} must be a boolean or its text form, got {type(value).__name__}")


def normalize_metadata(metadata: dict | None) -> dict:
    """提交入口的归一化：把文本授权值解析成布尔并写回元数据。

    非法值在这里就拒绝（CLI exit 2 / API 400），不让它落库变成“看起来授权了”。
    """
    out = dict(metadata or {})
    if FIELD in out:
        out[FIELD] = parse_authorized(out[FIELD])
    return out


def resolve(metadata: dict | None) -> dict:
    """准入判定：返回 ``{present, declared, ok, reason, detail, policy}``。

    - 已声明且合法：按声明值 ok；
    - 已声明但非法：ok=False（fail-closed），reason=invalid；
    - 未声明：按 MISSING_POLICY，默认 block → ok=False，reason=missing。
    """
    meta = metadata if isinstance(metadata, dict) else {}
    policy = MISSING_POLICY
    if FIELD not in meta:
        return {"present": False, "declared": None,
                "ok": policy == "allow", "reason": "missing",
                "policy": policy,
                "detail": (f"{FIELD} 未声明；策略={policy}"
                           + ("（默认阻断）" if policy == "block" else "（默认允许）"))}
    raw = meta[FIELD]
    try:
        value = parse_authorized(raw)
    except AuthorizationError as exc:
        return {"present": True, "declared": raw, "ok": False,
                "reason": "invalid", "policy": policy,
                "detail": f"{FIELD} 取值非法，按阻断处理：{exc}"}
    return {"present": True, "declared": value, "ok": value,
            "reason": "true" if value else "false", "policy": policy,
            "detail": f"{FIELD}={'true' if value else 'false'}"}


__all__ = ["TRUE_TOKENS", "FALSE_TOKENS", "MISSING_POLICY", "POLICY_TEXT",
           "FIELD", "AuthorizationError", "parse_authorized",
           "normalize_metadata", "resolve"]
