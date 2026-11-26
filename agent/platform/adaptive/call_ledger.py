"""V3-CALL-LEDGER：逐调用参数账本（append-only JSONL，三态，不回填）。

定位
====

`docs/CG07-CG18-PARAM-FORENSICS.md` 的结论是：历史 run 的模型调用**没有逐调用落盘
采样参数**，因此 D2b 不可通过，且历史 `missing` 永久不可补。本模块就是那条结论的
工程解：从**下一次**调用开始，每发一次（以及每一次没发出去的拒绝）都往 append-only
JSONL 里追加一条记录，把「到底发了什么 / 明确不发送什么 / 该有却没有」拆成三态。

三条硬口径
==========

1. **三态，互不覆盖**（`PARAM_STATES`）：

   - `sent`：本次请求体里**确实出现**的键与值，原样记录（不归一化、不换算）；
   - `not_sent`：客户端**结构性不发送**的参数（`top_p` / `seed` / `stop` / `n` /
     `stream` / `tools` / `user` / `max_retries` …），只记机读理由，**不记值**——
     因为不存在值；
   - `missing`：**应有但未记录**（请求体没构造出来、响应没回来、usage 缺字段），
     值一律 `None`，附机读理由。

   三态两两不交、并集覆盖 `TRACKED_PARAMS`（`validate_record` 硬断言）。

2. **不得用默认值回填**。`temperature=0.0` 只有在它真的进了请求体时才是 `sent`；
   预算拒绝 / 缺 key 的调用一个字段都没发出去，那四个参数全部落 `missing`
   （理由 `no_request_built`），绝不拿 `ProviderConfig` 的默认值冒充「发出去了」。
   同理 `usage` 缺字段时记 `null`，不记 `0`。

3. **key 不落盘**。记录里没有 header 值，只有 `auth_header_present: true/false`
   这个布尔事实；`assert_no_secret_record()` 在**写盘前**扫记录：出现
   `api_key` / `authorization` / `headers` 之类的键名，或出现调用方给的 key 原文、
   `Bearer ` 字面量，就抛 `CallLedgerError`，那一条不写。

append-only 语义
================

- 每条一个 JSON 对象、一行、`\n` 结尾；只以 `"a"` 模式打开，**从不重写/截断**；
- `seq` 从 1 起单调递增；打开已存在的账本时按现有行数续号（不重排、不归并）；
- 打开时逐行解析现有内容，遇到坏行直接抛错——不在可疑账本上继续追加；
- `read_records()` 只读回放，可选 `validate_record()` 逐条复核。

本模块不 import `llm_provider`（避免环），也不写任何其它文件；账本路径由调用方
（或 `VULNMAP_CALL_LEDGER` / `VULNMAP_LLM_LEDGER` 环境变量）显式给出。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

try:                                    # POSIX：追加时加独占锁，seq 不重号
    import fcntl as _fcntl
except ImportError:                     # pragma: no cover - 非 POSIX 平台
    _fcntl = None

SCHEMA = "vulnmap.adaptive.call_ledger.v1"
SCHEMA_VERSION = 1

#: 账本路径环境变量（主名；没有就是「不记账」）
ENV_LEDGER_PATH = "VULNMAP_CALL_LEDGER"

#: 同一开关的别名，按优先级排列（首个非空的生效）。
#:
#: `VULNMAP_LLM_LEDGER` 是 A/B 入口侧更直观的名字；两个都设成**不同路径**时
#: `ledger_path_from_env()` 直接抛错 —— 静悄悄挑一个会让「账本到底在哪」变成
#: 不可核的事实，与「宁缺勿假」冲突。
ENV_LEDGER_PATH_ALIASES = (ENV_LEDGER_PATH, "VULNMAP_LLM_LEDGER")

#: 文件后缀约定（便于 `*.jsonl` 收集与 `wc -l` 核对）
LEDGER_SUFFIX = ".jsonl"

# ================================================================ 三态
PARAM_SENT = "sent"
PARAM_NOT_SENT = "not_sent"
PARAM_MISSING = "missing"
PARAM_STATES = (PARAM_SENT, PARAM_NOT_SENT, PARAM_MISSING)

#: 调用本身是否真的发出去（与三态正交：拒绝的调用也有三态参数）
CALL_SENT = "sent"
CALL_NOT_INVOKED = "not_invoked"
CALL_STATES = (CALL_SENT, CALL_NOT_INVOKED)

# ---- not_sent 的理由码 -------------------------------------------------
#: 客户端从不发送（结构性缺席；不是「这次没发」）
NOT_SENT_ABSENT = "absent_by_design"
#: 客户端结构上不产出（响应里的 id 不被解析，也就没有可绑定的 request_id）
NOT_SENT_NEVER_CAPTURED = "never_captured_by_client"
#: 本次配置下刻意不发送（例：`json_mode=False` 时不发 `response_format`）
NOT_SENT_DISABLED = "disabled_by_config"
NOT_SENT_REASONS = (NOT_SENT_ABSENT, NOT_SENT_NEVER_CAPTURED,
                    NOT_SENT_DISABLED)

# ---- missing 的理由码 --------------------------------------------------
#: 请求体根本没构造出来（缺 key / 预算拒绝 / 单价未知）
MISSING_NO_REQUEST = "no_request_built"
#: 响应没回来（超时 / 网络错误 / HTTP 错误 / 提前拒绝）
MISSING_RESPONSE_ABSENT = "response_absent"
#: 响应回来了但没有可用的 usage 字段
MISSING_USAGE_ABSENT = "usage_absent"
#: 请求体构造了、但该参数不在里面，也没有声明为 not_sent
MISSING_VALUE_NOT_RECORDED = "value_not_recorded"
#: 调用没有发生，因此不存在该值（拒绝类调用的 usage）
MISSING_CALL_NOT_INVOKED = "call_not_invoked"
MISSING_REASONS = (MISSING_NO_REQUEST, MISSING_RESPONSE_ABSENT,
                   MISSING_USAGE_ABSENT, MISSING_VALUE_NOT_RECORDED,
                   MISSING_CALL_NOT_INVOKED)

#: 客户端结构性不发送的参数 → 理由码。
#:
#: 这份表是**代码事实**（`RealChatProvider` 构造请求体时从不写这些键），
#: 与取证文档 `CG07-CG18-PARAM-FORENSICS.md` §2.2 / §3.4 的
#: `absent_by_design` / `never_captured_by_client` 一一对应；`request_id` 归
#: `never_captured_by_client`（客户端不发送，也不解析响应 id）。
NOT_SENT_PARAMS: dict[str, str] = {
    "top_p": NOT_SENT_ABSENT,
    "seed": NOT_SENT_ABSENT,
    "stop": NOT_SENT_ABSENT,
    "presence_penalty": NOT_SENT_ABSENT,
    "frequency_penalty": NOT_SENT_ABSENT,
    "logit_bias": NOT_SENT_ABSENT,
    "logprobs": NOT_SENT_ABSENT,
    "top_logprobs": NOT_SENT_ABSENT,
    "n": NOT_SENT_ABSENT,
    "stream": NOT_SENT_ABSENT,
    "tools": NOT_SENT_ABSENT,
    "tool_choice": NOT_SENT_ABSENT,
    "user": NOT_SENT_ABSENT,
    "max_retries": NOT_SENT_ABSENT,
    "request_id": NOT_SENT_NEVER_CAPTURED,
}

#: 请求体里必须交代清楚的采样/结构参数（缺失即 `missing`，不回填）
BODY_PARAMS = ("model", "temperature", "max_tokens", "response_format")

#: 三态必须覆盖的参数全集
TRACKED_PARAMS = tuple(dict.fromkeys(BODY_PARAMS + tuple(NOT_SENT_PARAMS)))

#: 记录里**禁止出现**的键名（key 不落盘的机读护栏）
FORBIDDEN_KEYS = frozenset({
    "api_key", "apikey", "api-key", "x-api-key", "authorization",
    "auth", "headers", "bearer", "access_token", "secret", "password",
})

#: 写盘前必须存在的顶层字段（缺一即不写：账本宁缺勿假）
REQUIRED_FIELDS = (
    "call_id", "task_id", "round", "model", "prompt_version",
    "endpoint_source", "transport", "request_sha256", "response_sha256",
    "usage", "params_sent", "params_not_sent", "params_missing",
)


class CallLedgerError(ValueError):
    """账本本身的错误（坏行、三态重叠、试图写入凭据材料）。"""


# ================================================================ 哈希/规范化
def canonical_json(value: Any) -> str:
    """确定性 JSON：`sort_keys` + 紧凑分隔符 + 保留非 ASCII。

    账本里所有哈希都基于这个函数，因此「请求体哈希」可以被任何人用同一份
    body 复算出来（测试就是这么验的）。
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def sha256_value(value: Any) -> str:
    return sha256_text(canonical_json(value))


def request_digest(body: Mapping) -> str:
    """请求体哈希：`sha256(canonical_json(body))`（不含 header、不含 URL）。"""
    return sha256_value(dict(body))


def response_digest(content: str) -> str:
    """响应哈希：`sha256(content)`，`content` = `choices[0].message.content`。"""
    return sha256_text(str(content))


def _host_of(url: str) -> str:
    try:
        return str(urllib.parse.urlsplit(str(url or "")).hostname or "")
    except ValueError:
        return ""


def _path_of(url: str) -> str:
    try:
        return str(urllib.parse.urlsplit(str(url or "")).path or "")
    except ValueError:
        return ""


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


# ================================================================ 凭据护栏
def _iter_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _iter_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_keys(item)


def assert_no_secret_record(record: Mapping, *, secret: str = "") -> None:
    """写盘/读回前的凭据自检：有键名或 key 原文就抛错，不写这一条。

    只查真正的凭据材料：`headers` 这一类键名整块禁止（连 header 名都不进账本，
    只有一个 `auth_header_present` 布尔），`Bearer ` / `"api_key"` 字面量同样禁止。
    """
    if not isinstance(record, Mapping):
        raise CallLedgerError("账本条目必须是 mapping")
    bad = sorted({key for key in _iter_keys(record)
                  if key.strip().lower() in FORBIDDEN_KEYS})
    if bad:
        raise CallLedgerError(f"账本条目出现凭据键名：{bad}")
    text = canonical_json(record)
    if secret and secret in text:
        raise CallLedgerError("key 原文出现在账本条目里（拒绝写盘）")
    lowered = text.lower()
    for needle in ("bearer ", '"authorization"', "api_key=", '"api_key"'):
        if needle in lowered:
            raise CallLedgerError(f"账本条目出现凭据材料：{needle!r}")


# ================================================================ 三态装配
def _usage_block(raw: Mapping | None, *, invoked: bool) -> dict:
    """usage 三态：有就记原值，缺就 `None` + 理由，**不记 0**。"""
    block: dict[str, Any] = {
        "prompt_tokens": None, "completion_tokens": None,
        "total_tokens": None, "reasoning_tokens": None,
        "state": PARAM_MISSING, "reason": MISSING_CALL_NOT_INVOKED,
    }
    if not invoked:
        return block
    if not isinstance(raw, Mapping) or not raw:
        block["reason"] = MISSING_USAGE_ABSENT
        return block
    prompt_tokens = _int_or_none(raw.get("prompt_tokens"))
    completion_tokens = _int_or_none(raw.get("completion_tokens"))
    total_tokens = _int_or_none(raw.get("total_tokens"))
    details = raw.get("completion_tokens_details")
    reasoning = (_int_or_none(details.get("reasoning_tokens"))
                 if isinstance(details, Mapping) else None)
    block["prompt_tokens"] = prompt_tokens
    block["completion_tokens"] = completion_tokens
    block["total_tokens"] = total_tokens
    block["reasoning_tokens"] = reasoning
    if prompt_tokens is None or completion_tokens is None:
        block["reason"] = MISSING_USAGE_ABSENT
        return block
    block["state"] = PARAM_SENT
    block["reason"] = ""
    return block


def _assert_partition(sent: Mapping, not_sent: Mapping,
                      missing: Mapping) -> None:
    """三态两两不交、并集覆盖 `TRACKED_PARAMS`；任何一条不成立就抛错。"""
    buckets = {"sent": set(map(str, sent)),
               "not_sent": set(map(str, not_sent)),
               "missing": set(map(str, missing))}
    overlap = ((buckets["sent"] & buckets["not_sent"])
               | (buckets["sent"] & buckets["missing"])
               | (buckets["not_sent"] & buckets["missing"]))
    if overlap:
        raise CallLedgerError(f"三态重叠：{sorted(overlap)}")
    uncovered = set(TRACKED_PARAMS) - set().union(*buckets.values())
    if uncovered:
        raise CallLedgerError(f"三态未覆盖：{sorted(uncovered)}")


def build_call_record(*, call_id: str, status: str, invoked: bool,
                      task_id: str = "", round_no: int = 0,
                      error: str = "", model: str = "",
                      prompt_version: str = "",
                      endpoint_source: str = "", transport: str = "",
                      request_body: Mapping | None = None,
                      request_url: str = "",
                      timeout_s: float | None = None,
                      response_content: str | None = None,
                      response_usage: Mapping | None = None,
                      finish_reason: str = "",
                      header_names: Sequence[str] = (),
                      not_sent_overrides: Mapping[str, str] | None = None,
                      secret: str = "") -> dict:
    """组装一条三态调用记录（纯函数，不写盘；写盘在 `CallLedger.append`）。

    `request_body is None` 表示**这一次调用没有构造出请求体**（缺 key / 预算拒绝 /
    单价未知）：此时四个 body 参数全部 `missing/no_request_built`，`request_sha256`
    与 `response_sha256` 都是 `None`——`invoked` 为 False 的调用也有完整三态。
    """
    sent: dict[str, Any] = {}
    not_sent: dict[str, str] = dict(NOT_SENT_PARAMS)
    for name, reason in dict(not_sent_overrides or {}).items():
        reason_text = str(reason)
        if reason_text not in NOT_SENT_REASONS:
            raise CallLedgerError(f"not_sent 理由非法：{reason_text!r}")
        not_sent[str(name)] = reason_text
    missing: dict[str, str] = {}

    body = dict(request_body) if isinstance(request_body, Mapping) else None
    request_sha: str | None = None
    request_block: dict[str, Any] = {
        "built": body is not None,
        "method": "POST" if body is not None else "",
        "url_host": "",
        "url_path": "",
        "timeout_s": None,
        "body_sha256": None,
        "body_keys": [],
        "messages_sha256": None,
        "messages_count": 0,
        "messages_roles": [],
        "auth_header_present": False,
    }

    if body is not None:
        request_block["url_host"] = _host_of(request_url)
        request_block["url_path"] = _path_of(request_url)
        request_block["timeout_s"] = (None if timeout_s is None
                                      else round(float(timeout_s), 3))
        messages = body.get("messages")
        if isinstance(messages, (list, tuple)):
            request_block["messages_count"] = len(messages)
            request_block["messages_roles"] = [
                str((item or {}).get("role") or "")
                for item in messages if isinstance(item, Mapping)]
            request_block["messages_sha256"] = sha256_value(list(messages))
        for name, value in body.items():
            key = str(name)
            if key == "messages":          # prompt 正文只进绑定哈希，不进属主字段
                continue
            if key in not_sent:
                raise CallLedgerError(
                    f"参数 {key!r} 声明为 not_sent 却出现在请求体里")
            sent[key] = value
        for name in BODY_PARAMS:
            if name not in body and name not in not_sent:
                missing[name] = MISSING_VALUE_NOT_RECORDED
        request_sha = request_digest(body)
        request_block["body_sha256"] = request_sha
        request_block["body_keys"] = sorted(str(k) for k in body)
    else:
        for name in BODY_PARAMS:
            if name not in not_sent:
                missing[name] = MISSING_NO_REQUEST

    request_block["auth_header_present"] = any(
        str(name).strip().lower() == "authorization" for name in header_names)

    response_text = (None if response_content is None
                     else str(response_content))
    response_sha = (None if response_text is None
                    else response_digest(response_text))
    response_block: dict[str, Any] = {
        "present": response_text is not None,
        "chars": len(response_text or ""),
        "sha256": response_sha,
        "finish_reason": str(finish_reason or ""),
        "state": (PARAM_SENT if response_text is not None else PARAM_MISSING),
        "reason": ("" if response_text is not None
                   else (MISSING_RESPONSE_ABSENT if invoked
                         else MISSING_CALL_NOT_INVOKED)),
    }
    if response_text is not None and response_sha is None:  # pragma: no cover
        raise CallLedgerError("响应哈希计算失败")

    usage = _usage_block(response_usage, invoked=invoked)

    _assert_partition(sent, not_sent, missing)

    record = {
        "call_id": str(call_id),
        "task_id": str(task_id or ""),
        "round": int(round_no or 0),
        "call_state": CALL_SENT if invoked else CALL_NOT_INVOKED,
        "status": str(status or ""),
        "error": str(error or ""),
        "invoked": bool(invoked),
        "model": str(model or ""),
        "prompt_version": str(prompt_version or ""),
        "endpoint_source": str(endpoint_source or ""),
        "transport": str(transport or ""),
        "request_sha256": request_sha,
        "response_sha256": response_sha,
        "usage": usage,
        "params_sent": sent,
        "params_not_sent": not_sent,
        "params_missing": missing,
        "request": request_block,
        "response": response_block,
    }
    assert_no_secret_record(record, secret=secret)
    return record


# ================================================================ 读回/校验
def param_states(record: Mapping) -> dict[str, str]:
    """把一条记录翻成 `{参数名: 三态}`（重复键由 `validate_record` 拦掉）。"""
    states: dict[str, str] = {}
    for name in record.get("params_sent") or {}:
        states[str(name)] = PARAM_SENT
    for name in record.get("params_not_sent") or {}:
        states[str(name)] = PARAM_NOT_SENT
    for name in record.get("params_missing") or {}:
        states[str(name)] = PARAM_MISSING
    return dict(sorted(states.items()))


def state_of(record: Mapping, name: str) -> str:
    """单个参数的三态；不在任何一栏里返回空串（不猜）。"""
    return param_states(record).get(str(name), "")


def validate_record(record: Mapping) -> None:
    """读回校验：字段齐全、三态合法、哈希形状正确、无凭据材料。"""
    if not isinstance(record, Mapping):
        raise CallLedgerError("账本条目必须是 mapping")
    absent = [name for name in REQUIRED_FIELDS if name not in record]
    if absent:
        raise CallLedgerError(f"账本条目缺字段：{absent}")
    if not str(record.get("call_id") or "").strip():
        raise CallLedgerError("账本条目 call_id 为空")
    if str(record.get("call_state") or "") not in CALL_STATES:
        raise CallLedgerError(f"call_state 非法：{record.get('call_state')!r}")
    seq = record.get("seq")
    if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool)
                            or seq <= 0):
        raise CallLedgerError(f"seq 非法：{seq!r}")
    for name in ("request_sha256", "response_sha256"):
        value = record.get(name)
        if value is None:
            continue
        if not (isinstance(value, str) and len(value) == 64
                and all(char in "0123456789abcdef" for char in value)):
            raise CallLedgerError(f"{name} 不是 sha256 十六进制：{value!r}")
    for name in ("params_sent", "params_not_sent", "params_missing"):
        if not isinstance(record.get(name), Mapping):
            raise CallLedgerError(f"{name} 必须是 mapping")
    for name, reason in (record.get("params_not_sent") or {}).items():
        if name in TRACKED_PARAMS and str(reason) not in NOT_SENT_REASONS:
            raise CallLedgerError(f"not_sent 理由非法：{name}={reason!r}")
    for name, reason in (record.get("params_missing") or {}).items():
        if name in TRACKED_PARAMS and str(reason) not in MISSING_REASONS:
            raise CallLedgerError(f"missing 理由非法：{name}={reason!r}")
    _assert_partition(record["params_sent"], record["params_not_sent"],
                      record["params_missing"])
    usage = record.get("usage")
    if not isinstance(usage, Mapping):
        raise CallLedgerError("usage 必须是 mapping")
    if str(usage.get("state") or "") not in (PARAM_SENT, PARAM_MISSING):
        raise CallLedgerError(f"usage.state 非法：{usage.get('state')!r}")
    if usage.get("state") == PARAM_SENT:
        if usage.get("prompt_tokens") is None or usage.get("completion_tokens") is None:
            raise CallLedgerError("usage 标成 sent 却没有 token 数（疑似用 0 回填）")
    else:
        if (usage.get("prompt_tokens") == 0
                and usage.get("completion_tokens") == 0):
            raise CallLedgerError("usage 标成 missing 却写了 0/0（疑似用 0 回填）")
    assert_no_secret_record(record)


def read_records(path: str | Path, *, strict: bool = True,
                 validate: bool = True) -> list[dict]:
    """按行读回账本（只读）；坏行在 `strict=True` 下抛错，不跳过。

    `seq` 的严格递增校验**不受 `validate=False` 影响**：它查的是文件结构不变量
    （重号/倒序＝被篡改或多实例撞号），不是条目内容。
    """
    target = Path(path)
    if not target.exists():
        return []
    records: list[dict] = []
    last_seq = 0
    for lineno, line in enumerate(
            target.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError as exc:
            if strict:
                raise CallLedgerError(
                    f"账本第 {lineno} 行不是合法 JSON") from exc
            continue
        if not isinstance(item, dict):
            raise CallLedgerError(f"账本第 {lineno} 行不是 JSON 对象")
        if validate:
            try:
                validate_record(item)
            except CallLedgerError as exc:
                raise CallLedgerError(
                    f"账本第 {lineno} 行校验失败：{exc}") from exc
        seq = item.get("seq")
        if seq is not None:
            if not isinstance(seq, int) or isinstance(seq, bool) or seq <= last_seq:
                raise CallLedgerError(
                    f"账本第 {lineno} 行 seq={seq!r} 未严格递增（上一行 "
                    f"seq={last_seq}）：重号/篡改/多实例并发都会这样")
            last_seq = seq
        records.append(item)
    return records


def ledger_path_from_env(env: Mapping[str, str] | None = None) -> str:
    """解析账本路径：`VULNMAP_CALL_LEDGER` / `VULNMAP_LLM_LEDGER`，首个非空生效。

    传 `env` 就只读这个 mapping（不回落 `os.environ`），这样 A/B runner 拿测试
    环境跑时不会被开发机上的环境变量影响。
    两个环境变量都设成**不同文件**时抛 `CallLedgerError`：这是配置冲突，
    不是可以替调用方二选一的细节。
    """
    source: Mapping[str, str] = env if env is not None else os.environ
    found: list[tuple[str, str, Path]] = []
    for name in ENV_LEDGER_PATH_ALIASES:
        value = str(source.get(name) or "").strip()
        if not value:
            continue
        found.append((name, value, Path(value).expanduser().resolve()))
    if not found:
        return ""
    distinct = {str(item[2]) for item in found}
    if len(distinct) > 1:
        detail = "，".join(f"{name}={value}" for name, value, _ in found)
        raise CallLedgerError(
            f"账本路径环境变量冲突（{detail}）：只能指向同一个文件，"
            "否则无法判断本轮账本落在哪")
    return found[0][1]


def ledger_from_env(env: Mapping[str, str] | None = None) -> CallLedger | None:
    """按环境变量建账本；没设就返回 `None`（= 不记账）。

    认 `VULNMAP_CALL_LEDGER`（主名）与 `VULNMAP_LLM_LEDGER`（别名），
    首个非空的生效；两个都设且不同 → `CallLedgerError`（见
    `ledger_path_from_env()`）。
    """
    value = ledger_path_from_env(env)
    if not value:
        return None
    return CallLedger(value)


# ================================================================ 账本
class CallLedger:
    """append-only JSONL 账本：`append()` 只追加，永不重写。

    - `path=None` → 纯内存账本（只留 `entries()`，方便单元测试与「不落盘」场景）；
    - 打开已有文件时按现有行数续 `seq`，并校验每一行可解析、**尾行必须以换行结尾**
      （写一半崩溃的文件拒绝继续追加，否则新行会拼到旧行上毁掉它）；
    - 追加时以 `O_APPEND` 打开 + POSIX 独占锁（`fcntl.flock`），锁内重算 `seq`：
      多实例写同一账本也不会重号；
    - 条目写盘前先 `validate_record()`（字段/三态/哈希形状）+ 凭据护栏
      （`assert_no_secret_record(secret=…)`），一条坏条目不会让整本账不可读；
    - `fsync=True` 时每行 `os.fsync`（断电级持久化，测试里默认关）。
    """

    def __init__(self, path: str | Path | None = None, *,
                 clock: Any = time.time, fsync: bool = False) -> None:
        self.path: Path | None = Path(path) if path is not None else None
        self.clock = clock
        self.fsync = bool(fsync)
        self._entries: list[dict] = []
        self._seq = 0
        self._size = 0
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._seq = self._count_existing()
            self._size = self.path.stat().st_size if self.path.exists() else 0

    # ------------------------------------------------------------ 内部
    def _read_bytes(self) -> bytes:
        assert self.path is not None
        return self.path.read_bytes()

    def _count_existing(self) -> int:
        """续号起点：`max(行数, 最大 seq)`（无 `seq` 的旧式行只按行数计）。

        坏行 / 缺尾换行 / 编号不递增直接抛错——不在可疑账本上续写。
        """
        if self.path is None or not self.path.exists():
            return 0
        raw = self._read_bytes()
        if not raw:
            return 0
        if not raw.endswith(b"\n"):
            raise CallLedgerError(
                "账本尾行没有换行符（写一半崩溃或被截断）：拒绝在其后追加，"
                "否则新记录会拼到旧行上")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CallLedgerError("账本不是合法 UTF-8：拒绝在其后追加") from exc
        count = 0
        last_seq = 0
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CallLedgerError(
                    f"账本第 {lineno} 行不是合法 JSON：拒绝在其后追加") from exc
            if not isinstance(item, dict):
                raise CallLedgerError(
                    f"账本第 {lineno} 行不是 JSON 对象：拒绝在其后追加")
            seq = item.get("seq")
            if seq is not None:
                # 有 seq 就按它续号（而不是按行数）：中间被拿掉一行时行数会
                # 小于最大 seq，按行数续号会重号
                if (not isinstance(seq, int) or isinstance(seq, bool)
                        or seq <= last_seq):
                    raise CallLedgerError(
                        f"账本第 {lineno} 行 seq={seq!r} 未严格递增"
                        f"（上一行 {last_seq}）：拒绝在其后追加")
                last_seq = seq
            count += 1
        return max(count, last_seq)

    def _next_seq_locked(self, fd: int) -> int:
        """锁内定 `seq`：`max(既有 seq) + 1`，并校验既有行严格递增。

        用「最大 seq + 1」而不是「行数 + 1」：中间被拿掉一行时（`seq` 跳号），
        行数会小于最大 seq，再 +1 就会**重号**，把账本写成自己读不回来的样子。
        既有行不合法（坏 JSON / 非对象 / `seq` 不递增）就拒写，不制造新记录。
        """
        assert self.path is not None
        size = os.fstat(fd).st_size
        if size == self._size:
            return self._seq + 1
        if size == 0:
            return 1
        raw = self._read_bytes()
        if not raw.endswith(b"\n"):
            raise CallLedgerError("账本尾行没有换行符：拒绝在其后追加")
        last_seq = 0
        count = 0
        for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            count += 1
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CallLedgerError(
                    f"账本第 {lineno} 行不是合法 JSON：拒绝在其后追加") from exc
            if not isinstance(item, dict):
                raise CallLedgerError(
                    f"账本第 {lineno} 行不是 JSON 对象：拒绝在其后追加")
            seq = item.get("seq")
            if seq is None:
                # 无 seq 的旧式行：与 `_count_existing` / `read_records` 同口径，
                # 按行数计入，不做编号校验（否则同一文件只有一个实例写得进去）
                continue
            if not isinstance(seq, int) or isinstance(seq, bool):
                raise CallLedgerError(
                    f"账本第 {lineno} 行 seq 不是正整数：{seq!r}（拒绝在其后追加）")
            if seq <= last_seq:
                raise CallLedgerError(
                    f"账本第 {lineno} 行 seq={seq!r} 未严格递增（上一行 "
                    f"{last_seq}）：拒绝在其后追加")
            last_seq = seq
        return max(count, last_seq) + 1

    # ------------------------------------------------------------ 追加
    def append(self, record: Mapping, *, secret: str = "") -> dict:
        """追加一条；返回实际写下的条目（含 `seq` / `recorded_at`）。

        写盘前一律 `validate_record()`：字段齐、三态不交、哈希 64 hex、无凭据。
        """
        if not isinstance(record, Mapping):
            raise CallLedgerError("账本条目必须是 mapping")
        payload = dict(record)
        for name in ("schema", "schema_version", "seq", "recorded_at"):
            payload.pop(name, None)
        if not str(payload.get("call_id") or "").strip():
            raise CallLedgerError("账本条目必须有 call_id")
        assert_no_secret_record(payload, secret=secret)
        validate_record(payload)

        if self.path is None:
            self._seq += 1
            entry = self._envelope(payload, self._seq)
            self._entries.append(entry)
            return dict(entry)

        # O_APPEND + 独占锁：多实例并发追加也不会互相覆盖、不会重号
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        locked = False
        try:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_EX)
                locked = True
            seq = self._next_seq_locked(fd)
            entry = self._envelope(payload, seq)
            data = (canonical_json(entry) + "\n").encode("utf-8")
            view = memoryview(data)
            while view:                 # os.write 可能短写：写完为止
                written = os.write(fd, view)
                view = view[written:]
            if self.fsync:
                os.fsync(fd)
            self._seq = seq
            self._size = os.fstat(fd).st_size
        finally:
            if locked:
                try:                    # 解锁失败不吞掉 close（否则 fd 泄漏）
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
                except Exception:       # noqa: BLE001, S110 - 只为不跳过 close
                    pass
            os.close(fd)
        self._entries.append(entry)
        return dict(entry)

    def _envelope(self, payload: Mapping, seq: int) -> dict:
        entry: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "seq": int(seq),
            "recorded_at": round(float(self.clock()), 6),
        }
        entry.update(dict(payload))
        return entry

    # ------------------------------------------------------------ 读取
    def entries(self) -> list[dict]:
        """本实例写下的条目（副本；读全量请用 `read_records(path)`）。"""
        return [dict(item) for item in self._entries]

    @property
    def written(self) -> int:
        return len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:             # pragma: no cover - 调试用
        where = str(self.path) if self.path is not None else "<memory>"
        return f"CallLedger(path={where!r}, written={self.written})"


__all__ = [
    "BODY_PARAMS",
    "CALL_NOT_INVOKED",
    "CALL_SENT",
    "CALL_STATES",
    "ENV_LEDGER_PATH",
    "ENV_LEDGER_PATH_ALIASES",
    "FORBIDDEN_KEYS",
    "LEDGER_SUFFIX",
    "MISSING_CALL_NOT_INVOKED",
    "MISSING_NO_REQUEST",
    "MISSING_REASONS",
    "MISSING_RESPONSE_ABSENT",
    "MISSING_USAGE_ABSENT",
    "MISSING_VALUE_NOT_RECORDED",
    "NOT_SENT_ABSENT",
    "NOT_SENT_DISABLED",
    "NOT_SENT_NEVER_CAPTURED",
    "NOT_SENT_PARAMS",
    "NOT_SENT_REASONS",
    "PARAM_MISSING",
    "PARAM_NOT_SENT",
    "PARAM_SENT",
    "PARAM_STATES",
    "REQUIRED_FIELDS",
    "SCHEMA",
    "SCHEMA_VERSION",
    "TRACKED_PARAMS",
    "CallLedger",
    "CallLedgerError",
    "assert_no_secret_record",
    "build_call_record",
    "canonical_json",
    "ledger_from_env",
    "ledger_path_from_env",
    "param_states",
    "read_records",
    "request_digest",
    "response_digest",
    "sha256_text",
    "sha256_value",
    "state_of",
    "validate_record",
]
