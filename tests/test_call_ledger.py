r"""逐调用参数账本回归（`tests/test_call_ledger.py`）。

被测实现：

- `agent/platform/adaptive/call_ledger.py`：append-only JSONL 账本 + 三态装配
  （`sent` / `not_sent` / `missing`）+ 哈希绑定 + 凭据护栏；
- `agent/platform/adaptive/llm_provider.py`：`RealChatProvider(ledger=...)` 的接入
  （成功 / 失败 / 预算拒绝都记账，`ledger=None` 时不落盘）；
- `agent/platform/adaptive/real_ab.py`：只有显式设了 `VULNMAP_CALL_LEDGER`
  （或别名 `VULNMAP_LLM_LEDGER`）才落盘；实际入口的端到端验收见
  `tests/test_actual_ab_ledger.py`。

十四组用例（**全部不联网、不调用真实模型**）：

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 append-only | `test_two_calls_append_only_jsonl` | 本地 fixture 两次调用 → 2 行 JSONL、`seq` 单调、第二行不覆盖第一行、逐行可校验 |
| 2 三态 | `test_param_tri_state_is_exact` | `sent` 是请求体原值；`not_sent` 只有理由码（`top_p`/`seed`/`request_id`）；`missing` 为空 |
| 3 不回填 | `test_no_default_backfill_on_refused_calls` | 缺 key / 预算拒绝时四个 body 参数全 `missing/no_request_built`，**不**拿 `temperature=0.0` 冒充已发送 |
| 4 哈希绑定 | `test_request_and_response_hash_bind_fixture_bytes` | 用 fixture 收到的 body / 回的内容独立复算 `request_sha256` / `response_sha256`，逐字节相等 |
| 5 失败也记账 | `test_failed_transport_still_records_request_hash` | 超时：`request_sha256` 有值、`response_sha256=null` + `response_absent`、usage `missing` |
| 6 usage 缺失 | `test_usage_missing_is_null_not_zero` | 响应没有 usage → `null` + `usage_absent`，不是 0（现有 provider 的 `or 0` 不回填进账本） |
| 7 无 key | `test_key_and_bearer_never_persisted` | 账本文件无 key 原文 / `Bearer` / `authorization`；带凭据键名的条目、「`model` 里夹 key」被拒且不写盘 |
| 8 来源字段 | `test_ledger_records_model_prompt_and_source` | `model` / `prompt_version` / `endpoint_source` / `transport` 与 `status()` 一致 |
| 9 续号 | `test_append_only_survives_new_instance` | 新建实例按现有 `max(seq)+1` 续号，前两行字节不变 |
| 9b 失败事实位 | `test_failure_paths_keep_audit_facts_honest` | 超时仍记 `auth_header_present=true`；空 content 记 `present=true/chars=0`；坏 JSON 的响应哈希与 usage 可复算 |
| 9c json_mode | `test_json_mode_off_declares_response_format_not_sent` | `json_mode=False` → `response_format` 是 `not_sent/disabled_by_config`，不是 missing |
| 9d 拒写 | `test_append_refuses_truncated_tail_and_bad_entry` | 尾行缺换行（打开 + 追加两条路径）/ 坏条目一律拒写，文件字节不变 |
| 9e seq 唯一 | `test_seq_is_unique_and_monotonic_on_read` | 两实例**先打开空账本再交叉 append** 不重号；跳号后按 `max(seq)+1` 续；重号读回即报错 |
| 10 只读默认 + 坏账本 | `test_ledger_off_by_default_and_corrupt_file_refused` | 默认不落盘；坏行既不能读也不能续写 |
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive.call_ledger import (
    BODY_PARAMS,
    CALL_NOT_INVOKED,
    CALL_SENT,
    MISSING_CALL_NOT_INVOKED,
    MISSING_NO_REQUEST,
    MISSING_REASONS,
    MISSING_RESPONSE_ABSENT,
    MISSING_USAGE_ABSENT,
    NOT_SENT_ABSENT,
    NOT_SENT_NEVER_CAPTURED,
    NOT_SENT_PARAMS,
    NOT_SENT_REASONS,
    PARAM_MISSING,
    PARAM_NOT_SENT,
    PARAM_SENT,
    TRACKED_PARAMS,
    CallLedger,
    CallLedgerError,
    assert_no_secret_record,
    build_call_record,
    canonical_json,
    ledger_from_env,
    param_states,
    read_records,
    state_of,
    validate_record,
)
from agent.platform.adaptive.compare import FakeClock
from agent.platform.adaptive.llm_provider import (
    PROMPT_VERSION,
    REDACTED,
    ProviderConfig,
    RealChatProvider,
    TransportError,
    provider_from_env,
)

KEY = "sk-ledger-0123456789abcdef"
MODEL = "local-fixture"
FIXTURE_USAGE = {"prompt_tokens": 11, "completion_tokens": 7}


# --------------------------------------------------------------------- fixture
class _FixtureState:
    def __init__(self) -> None:
        self.calls: list[dict] = []        # fixture 收到的请求体（逐字）
        self.contents: list[str] = []      # fixture 回给模型的 content（逐字）
        self.headers: list[dict] = []


@contextmanager
def _chat_fixture(*, include_usage: bool = True):
    """本地 127.0.0.1 HTTP fixture：记录每次 POST，回确定性 chat 响应。

    用默认 `urllib` 传输（不注入 transport），所以这是「HTTP 真发出去了」的通路
    验证；endpoint 是本机，因此来源仍是 `simulated`（不是真实模型）。
    """
    state = _FixtureState()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):                # http.server 约定
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            state.calls.append(body)
            state.headers.append({name: self.headers.get(name)
                                  for name in ("Content-Type", "Authorization")})
            index = len(state.calls)
            content = json.dumps({
                "diagnosis": {"code": "no_execution"},
                "actions": [],
                "reason": f"fixture call {index}",
            }, ensure_ascii=False)
            state.contents.append(content)
            payload = {"choices": [{"message": {"content": content},
                                    "finish_reason": "stop"}]}
            if include_usage:
                payload["usage"] = dict(FIXTURE_USAGE)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):     # 静音测试输出
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/v1", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _local_env(base_url: str) -> dict:
    return {"VULNMAP_LLM_API_KEY": KEY,
            "VULNMAP_LLM_BASE_URL": base_url,
            "VULNMAP_LLM_MODEL": MODEL}


def _payload(task_id: str = "w4-t01", round_no: int = 1) -> dict:
    return {"task_id": task_id, "round_no": round_no,
            "observation": {"trials": 0, "snapshot_status": "unknown"}}


def _ledger(tmp_path: Path) -> CallLedger:
    return CallLedger(tmp_path / "calls.jsonl", clock=FakeClock())


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _chat(suggestion: dict) -> dict:
    return {"choices": [{"message": {"content": json.dumps(suggestion)}}],
            "usage": dict(FIXTURE_USAGE)}


# --------------------------------------------------------------------- 1
def test_two_calls_append_only_jsonl(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        provider, status = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        assert status["real_model_status"] == "ready"

        assert provider(_payload("w4-t01"))["status"] == "ok"
        first_bytes = path.read_bytes()
        assert provider(_payload("w4-t02", round_no=2))["status"] == "ok"
        second_bytes = path.read_bytes()

    assert len(fixture.calls) == 2                       # 真的发了两次 HTTP
    # append-only：第二次写入不碰第一行的任何一个字节
    assert second_bytes.startswith(first_bytes)
    assert first_bytes.count(b"\n") == 1
    assert second_bytes.count(b"\n") == 2

    records = read_records(path)                         # 逐行校验
    assert len(records) == 2
    assert [item["seq"] for item in records] == [1, 2]
    assert [item["call_id"] for item in records] == ["call-0001", "call-0002"]
    assert [item["task_id"] for item in records] == ["w4-t01", "w4-t02"]
    assert [item["round"] for item in records] == [1, 2]
    assert [item["status"] for item in records] == ["ok", "ok"]
    assert [item["call_state"] for item in records] == [CALL_SENT, CALL_SENT]
    assert provider.snapshot()["ledger"] == {
        "enabled": True, "path": str(path), "written": 2, "errors": []}
    # 每行都是独立 JSON 对象（不是数组、不是多行 pretty print）
    for line in _lines(path):
        assert isinstance(json.loads(line), dict)


# --------------------------------------------------------------------- 2
def test_param_tri_state_is_exact(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        provider, _ = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        provider(_payload())

    record = read_records(path)[0]
    # sent = 请求体里确实出现过的键与值（逐字，不归一化）
    assert record["params_sent"] == {
        "model": MODEL,
        "temperature": 0.0,
        "max_tokens": 512,
        "response_format": {"type": "json_object"},
    }
    # 与 fixture 收到的请求体逐键对齐
    received = fixture.calls[0]
    assert record["params_sent"] == {name: received[name]
                                     for name in record["params_sent"]}

    # not_sent = 结构性不发送，只有理由码，没有值
    assert record["params_not_sent"] == NOT_SENT_PARAMS
    assert record["params_not_sent"]["top_p"] == NOT_SENT_ABSENT
    assert record["params_not_sent"]["seed"] == NOT_SENT_ABSENT
    assert record["params_not_sent"]["request_id"] == NOT_SENT_NEVER_CAPTURED
    for name, reason in record["params_not_sent"].items():
        assert reason in NOT_SENT_REASONS
        assert name not in received            # 结构性缺席：请求体里确实没有

    # 成功的调用没有 missing
    assert record["params_missing"] == {}

    # 三态互不相交、并集覆盖全集（validate_record 里也是硬断言）
    states = param_states(record)
    assert set(states) >= set(TRACKED_PARAMS)
    assert state_of(record, "temperature") == PARAM_SENT
    assert state_of(record, "top_p") == PARAM_NOT_SENT
    assert state_of(record, "seed") == PARAM_NOT_SENT
    assert state_of(record, "response_format") == PARAM_SENT
    buckets = {"sent": set(record["params_sent"]),
               "not_sent": set(record["params_not_sent"]),
               "missing": set(record["params_missing"])}
    assert not (buckets["sent"] & buckets["not_sent"])
    assert not (buckets["sent"] & buckets["missing"])
    assert not (buckets["not_sent"] & buckets["missing"])


# --------------------------------------------------------------------- 3
def test_no_default_backfill_on_refused_calls(tmp_path):
    path = tmp_path / "calls.jsonl"
    ledger = _ledger(tmp_path)

    # (a) 缺 key：一个字都没发出去
    provider, status = provider_from_env({}, ledger=ledger, clock=FakeClock())
    assert status["real_model_status"] == "blocked"
    out = provider(_payload())
    assert out["status"] == "environment_error" and out["error"] == "missing_env"
    assert out["meta"]["invoked"] is False

    # (b) 预算拒绝：第一次发、第二次被 max_calls 拦下
    calls: list[dict] = []

    def transport(request: dict) -> dict:
        calls.append(dict(request))
        return _chat({"diagnosis": {"code": "no_execution"}, "actions": []})

    budgeted = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1", model="test-model",
                       api_key=KEY, max_calls=1),
        transport=transport, clock=FakeClock(), ledger=ledger)
    assert budgeted(_payload("t1"))["status"] == "ok"
    refused = budgeted(_payload("t2"))
    assert refused["status"] == "budget_exhausted"
    assert refused["meta"]["invoked"] is False
    assert len(calls) == 1

    records = read_records(path)
    assert len(records) == 3
    assert [item["status"] for item in records] == [
        "environment_error", "ok", "budget_exhausted"]
    assert [item["invoked"] for item in records] == [False, True, False]
    assert [item["call_state"] for item in records] == [
        CALL_NOT_INVOKED, CALL_SENT, CALL_NOT_INVOKED]

    for refused_record in (records[0], records[2]):
        # 没构造请求体 → 四个 body 参数全部 missing，且不是拿默认值回填
        assert refused_record["request_sha256"] is None
        assert refused_record["response_sha256"] is None
        assert refused_record["request"]["built"] is False
        assert refused_record["params_sent"] == {}
        assert set(refused_record["params_missing"]) == set(BODY_PARAMS)
        assert set(refused_record["params_missing"].values()) == {
            MISSING_NO_REQUEST}
        assert "temperature" not in refused_record["params_sent"]   # 不回填 0.0
        assert all(isinstance(value, str) and value in MISSING_REASONS
                   for value in refused_record["params_missing"].values())
        # 没调用就没有 usage：null + 理由，不写 0
        usage = refused_record["usage"]
        assert usage["state"] == PARAM_MISSING
        assert usage["reason"] == MISSING_CALL_NOT_INVOKED
        assert usage["prompt_tokens"] is None
        assert usage["completion_tokens"] is None
        assert all(value is None for value in
                   (usage["prompt_tokens"], usage["completion_tokens"],
                    usage["total_tokens"], usage["reasoning_tokens"]))

    # 成功那条仍然有完整 sent
    ok_record = records[1]
    assert ok_record["params_sent"]["temperature"] == 0.0
    assert ok_record["params_missing"] == {}


# --------------------------------------------------------------------- 4
def test_request_and_response_hash_bind_fixture_bytes(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        provider, _ = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        provider(_payload())

    record = read_records(path)[0]
    sent_body = fixture.calls[0]
    sent_content = fixture.contents[0]

    # 用 fixture 收到的东西独立复算请求哈希（与账本完全一致）
    expected_request = hashlib.sha256(
        canonical_json(sent_body).encode("utf-8")).hexdigest()
    assert record["request_sha256"] == expected_request
    assert record["request"]["body_sha256"] == expected_request
    assert record["request"]["body_keys"] == sorted(sent_body)
    assert record["request"]["messages_sha256"] == hashlib.sha256(
        canonical_json(sent_body["messages"]).encode("utf-8")).hexdigest()
    assert record["request"]["messages_count"] == 2
    assert record["request"]["messages_roles"] == ["system", "user"]
    assert record["request"]["method"] == "POST"
    assert record["request"]["url_path"] == "/v1/chat/completions"
    assert record["request"]["url_host"].startswith("127.0.0.1")
    assert record["request"]["auth_header_present"] is True
    assert fixture.headers[0]["Authorization"] == f"Bearer {KEY}"

    # 响应哈希绑定的就是 fixture 回的那串 content
    assert record["response_sha256"] == hashlib.sha256(
        sent_content.encode("utf-8")).hexdigest()
    assert record["response"]["sha256"] == record["response_sha256"]
    assert record["response"]["chars"] == len(sent_content)
    assert record["response"]["present"] is True
    assert record["response"]["finish_reason"] == "stop"

    # 哈希是 64 位十六进制（validate_record 也查这个）
    validate_record(record)

    # 篡改内容后哈希必然对不上（绑定不是装饰）
    assert hashlib.sha256((sent_content + " ").encode()).hexdigest() != (
        record["response_sha256"])


# --------------------------------------------------------------------- 5
def test_failed_transport_still_records_request_hash(tmp_path):
    path = tmp_path / "calls.jsonl"

    def timeout_transport(request: dict) -> dict:
        raise TransportError("timeout", "请求超时", retryable=True)

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY),
        transport=timeout_transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    out = provider(_payload())
    assert out["status"] == "environment_error" and out["error"] == "timeout"

    record = read_records(path)[0]
    assert record["status"] == "environment_error"
    assert record["error"] == "timeout"
    assert record["invoked"] is True
    assert record["call_state"] == CALL_SENT
    # 请求确实构造并发出了：请求哈希有值、body 参数是 sent
    assert record["request"]["built"] is True
    assert len(record["request_sha256"]) == 64
    assert record["params_sent"]["model"] == "test-model"
    assert record["params_missing"] == {}
    # 响应没回来：哈希 null + 机读理由，不是空串、不是假哈希
    assert record["response_sha256"] is None
    assert record["response"]["present"] is False
    assert record["response"]["reason"] == MISSING_RESPONSE_ABSENT
    assert record["usage"]["state"] == PARAM_MISSING
    assert record["usage"]["reason"] == MISSING_USAGE_ABSENT


# --------------------------------------------------------------------- 6
def test_usage_missing_is_null_not_zero(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture(include_usage=False) as (base_url, fixture):
        provider, _ = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        out = provider(_payload())

    assert out["status"] == "ok"                          # provider 仍算成功
    assert out["usage"]["usage_known"] is False
    record = read_records(path)[0]
    usage = record["usage"]
    assert usage["state"] == PARAM_MISSING
    assert usage["reason"] == MISSING_USAGE_ABSENT
    assert usage["prompt_tokens"] is None
    assert usage["completion_tokens"] is None
    assert usage["total_tokens"] is None
    # 关键：不是 0（现有 provider 的 `tokens_in or 0` 不得回填进账本）
    assert usage["prompt_tokens"] != 0
    assert usage["completion_tokens"] != 0
    assert '"prompt_tokens":0' not in path.read_text(encoding="utf-8")
    assert len(fixture.calls) == 1


# --------------------------------------------------------------------- 7
def test_key_and_bearer_never_persisted(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, _fixture):
        provider, _ = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        provider(_payload("w4-t01"))
        provider(_payload("w4-t02"))

    text = path.read_text(encoding="utf-8")
    assert KEY not in text
    assert "Bearer" not in text
    assert "bearer" not in text.lower()
    assert "authorization" not in text.lower()
    assert "sk-" not in text
    # 只有「有没有带 Authorization」这个布尔事实
    for record in read_records(path):
        assert record["request"]["auth_header_present"] is True
        assert "headers" not in record["request"]

    # 凭据护栏本身：带 key 原文 / 凭据键名的条目写不进去
    ledger = CallLedger(tmp_path / "guard.jsonl", clock=FakeClock())
    ledger.append(_record_for("c1"))
    before = (tmp_path / "guard.jsonl").read_bytes()
    for bad in ({"call_id": "c2", "api_key": KEY},
                {"call_id": "c3", "note": f"Bearer {KEY}"},
                {"call_id": "c4", "headers": {"Authorization": f"Bearer {KEY}"}}):
        try:
            ledger.append(bad)
        except CallLedgerError:
            continue
        raise AssertionError(f"凭据材料漏放进账本：{bad}")
    assert (tmp_path / "guard.jsonl").read_bytes() == before   # 一行都没多

    try:
        assert_no_secret_record({"call_id": "c5", "api_key": KEY})
    except CallLedgerError:
        pass
    else:                                            # pragma: no cover
        raise AssertionError("assert_no_secret_record 漏放 api_key")
    assert_no_secret_record({"call_id": "c6", "model": MODEL})   # 干净条目能过

    # provider 侧真的把 key 传进了护栏（不是只靠「记录里恰好没有 key」）
    try:
        build_call_record(call_id="c7", status="ok", invoked=True,
                          model=f"model-{KEY}", secret=KEY)
    except CallLedgerError:
        pass
    else:                                            # pragma: no cover
        raise AssertionError("build_call_record 没把 secret= 接线到护栏")
    record_ok = build_call_record(call_id="c8", status="ok", invoked=True,
                                 model=MODEL, secret=KEY)
    validate_record(record_ok)
    try:
        CallLedger(tmp_path / "guard2.jsonl", clock=FakeClock()).append(
            {**record_ok, "note": KEY}, secret=KEY)
    except CallLedgerError:
        pass
    else:                                            # pragma: no cover
        raise AssertionError("append(secret=) 没拦住 key 原文")

    # provider 的 ledger 状态里也没有 key
    assert KEY not in json.dumps(provider.snapshot(), ensure_ascii=False)


# --------------------------------------------------------------------- 8
def test_ledger_records_model_prompt_and_source(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, _fixture):
        provider, status = provider_from_env(
            _local_env(base_url), ledger=_ledger(tmp_path), clock=FakeClock())
        provider(_payload())

    record = read_records(path)[0]
    assert record["model"] == MODEL == status["model"]
    assert record["prompt_version"] == PROMPT_VERSION
    assert record["prompt_version"] == status["prompt_version"]
    assert record["endpoint_source"] == "simulated"      # 127.0.0.1 不是 public HTTPS
    assert record["endpoint_source"] == status["endpoint_source"]
    assert record["transport"] == "urllib"               # transport 只说明怎么发
    assert record["transport"] == status["transport"]
    assert record["request"]["timeout_s"] == 30.0
    assert record["status"] == "ok"
    assert record["error"] == ""
    assert record["schema"] == "vulnmap.adaptive.call_ledger.v1"
    assert record["schema_version"] == 1


# --------------------------------------------------------------------- 9
def _record_for(call_id: str, *, round_no: int = 1) -> dict:
    """用同一套装配函数造一条完整记录（测试不手搓三态，避免绕过校验）。"""
    return build_call_record(
        call_id=call_id, task_id="t", round_no=round_no, status="ok",
        invoked=True, model=MODEL, prompt_version=PROMPT_VERSION,
        endpoint_source="simulated", transport="urllib",
        request_body={"model": MODEL, "messages": [], "temperature": 0.0,
                      "max_tokens": 1, "response_format": {"type": "json_object"}},
        request_url="http://127.0.0.1:1/v1/chat/completions",
        timeout_s=30.0, response_content="{}",
        response_usage={"prompt_tokens": 1, "completion_tokens": 1})


def _record_by_task(path: Path, task_id: str) -> dict:
    return next(item for item in read_records(path)
                if item["task_id"] == task_id)


def test_append_only_survives_new_instance(tmp_path):
    path = tmp_path / "calls.jsonl"
    first = CallLedger(path, clock=FakeClock())
    first.append(_record_for("call-0001"))
    snapshot = path.read_bytes()

    # 同一文件的新实例：按现有行数续号，不重写、不截断
    second = CallLedger(path, clock=FakeClock())
    assert second.written == 0
    record = second.append(_record_for("call-0002", round_no=2))
    assert record["seq"] == 2
    text = path.read_bytes()
    assert text.startswith(snapshot)
    assert [item["seq"] for item in read_records(path)] == [1, 2]
    assert [item["call_id"] for item in read_records(path)] == [
        "call-0001", "call-0002"]


# --------------------------------------------------------------------- 9b
def test_failure_paths_keep_audit_facts_honest(tmp_path):
    """失败路径的三个事实位：带 Authorization、空响应与坏 JSON 的响应绑定。"""
    path = tmp_path / "calls.jsonl"

    # (a) 超时：请求确实带 Authorization -> auth_header_present 必须是 True
    seen: list[dict] = []

    def timeout_transport(request: dict) -> dict:
        seen.append(dict(request))
        raise TransportError("timeout", "请求超时", retryable=True)

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY),
        transport=timeout_transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    provider(_payload())
    assert "Authorization" in seen[0]["headers"]
    timeout_record = read_records(path)[0]
    assert timeout_record["request"]["auth_header_present"] is True
    assert timeout_record["response_sha256"] is None
    assert timeout_record["response"]["reason"] == MISSING_RESPONSE_ABSENT

    # (b) 空 content：响应回来了（present=true/chars=0），不是“没回来”
    def empty_transport(request: dict) -> dict:
        return {"choices": [{"message": {"content": ""},
                             "finish_reason": "stop"}]}

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY),
        transport=empty_transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    out = provider(_payload("t-empty"))
    assert out["error"] == "empty_response"
    empty_record = _record_by_task(path, "t-empty")
    assert empty_record["response"]["present"] is True
    assert empty_record["response"]["chars"] == 0
    assert empty_record["response_sha256"] == hashlib.sha256(b"").hexdigest()
    assert empty_record["request"]["auth_header_present"] is True

    # (c) 坏 JSON：回包到了 -> 响应哈希可被原文复算（不是 null）
    raw_bad = "not a json object at all"

    def bad_json_transport(request: dict) -> dict:
        return {"choices": [{"message": {"content": raw_bad},
                             "finish_reason": "length"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 4}}

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY),
        transport=bad_json_transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    assert provider(_payload("t-badjson"))["error"] == "invalid_json"
    bad_record = _record_by_task(path, "t-badjson")
    assert bad_record["response_sha256"] == hashlib.sha256(
        raw_bad.encode("utf-8")).hexdigest()
    assert bad_record["response"]["present"] is True
    assert bad_record["response"]["finish_reason"] == "length"
    # 回包带了 usage 就得记，不能因为"解析失败"把可得事实记成不存在
    assert bad_record["usage"]["state"] == "sent"
    assert bad_record["usage"]["prompt_tokens"] == 7
    assert bad_record["usage"]["completion_tokens"] == 4

    # (d) 回包含 key：文本脱敏后才落盘，但 usage 仍照实记
    leaky = json.dumps({"diagnosis": {"code": "no_execution"},
                        "actions": []}) + KEY

    def leak_transport(request: dict) -> dict:
        return {"choices": [{"message": {"content": leaky},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 2}}

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY),
        transport=leak_transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    assert provider(_payload("t-leak"))["error"] == "secret_in_output"
    leak_record = _record_by_task(path, "t-leak")
    assert leak_record["usage"]["state"] == "sent"
    assert leak_record["usage"]["prompt_tokens"] == 9
    assert leak_record["usage"]["completion_tokens"] == 2
    assert KEY not in json.dumps(leak_record, ensure_ascii=False)
    scrubbed = leaky.replace(KEY, REDACTED)
    assert leak_record["response_sha256"] == hashlib.sha256(
        scrubbed.encode("utf-8")).hexdigest()          # 脱敏后文本的哈希
    assert leak_record["response_sha256"] != hashlib.sha256(
        leaky.encode("utf-8")).hexdigest()             # 不是原文哈希（不可从线路复算）


# --------------------------------------------------------------------- 9c
def test_json_mode_off_declares_response_format_not_sent(tmp_path):
    """`json_mode=False`：`response_format` 是 not_sent/disabled_by_config，不是 missing。"""
    path = tmp_path / "calls.jsonl"
    calls: list[dict] = []

    def transport(request: dict) -> dict:
        calls.append(dict(request))
        return _chat({"diagnosis": {"code": "no_execution"}, "actions": []})

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY, json_mode=False),
        transport=transport, clock=FakeClock(), ledger=_ledger(tmp_path))
    assert provider(_payload())["status"] == "ok"
    assert "response_format" not in calls[0]["body"]
    record = read_records(path)[0]
    assert record["params_not_sent"]["response_format"] == "disabled_by_config"
    assert "response_format" not in record["params_sent"]
    assert record["params_missing"] == {}


# --------------------------------------------------------------------- 9d
def test_append_refuses_truncated_tail_and_bad_entry(tmp_path):
    """末尾无换行 / 坏条目：一律拒写，文件字节不变（新行不得拼到旧行上）。"""
    path = tmp_path / "calls.jsonl"
    ledger = CallLedger(path, clock=FakeClock())
    ledger.append(_record_for("call-0001"))
    before = path.read_bytes()
    assert before.endswith(b"\n")

    # 外部截断掉尾换行（模拟写一半崩溃）
    path.write_bytes(before.rstrip(b"\n"))
    truncated = path.read_bytes()
    # (1) 打开路径：新实例拒绝
    try:
        CallLedger(path, clock=FakeClock())
    except CallLedgerError as exc:
        assert "换行" in str(exc)
    else:                                        # pragma: no cover
        raise AssertionError("尾行缺换行仍被当成可续写账本")
    assert path.read_bytes() == truncated            # 一个字节都没动
    # (2) 追加路径：已打开的实例也不许把新行拼上去
    try:
        ledger.append(_record_for("call-0009"))
    except CallLedgerError as exc:
        assert "换行" in str(exc)
    else:                                        # pragma: no cover
        raise AssertionError("追加路径没检查尾行换行")
    assert path.read_bytes() == truncated

    # 完整但三态不全的条目：写盘前就被 validate_record 拦掉
    good = tmp_path / "good.jsonl"
    ledger = CallLedger(good, clock=FakeClock())
    ledger.append(_record_for("call-0001"))
    snapshot = good.read_bytes()
    for bad in ({"call_id": "c2", "note": "partial"},
                {**_record_for("c3"),
                 "params_missing": {"top_p": "absent_by_design"}}):   # 三态重叠
        try:
            ledger.append(bad)
        except CallLedgerError:
            continue
        raise AssertionError(f"坏条目被写进账本：{bad}")
    assert good.read_bytes() == snapshot


# --------------------------------------------------------------------- 9e
def test_seq_is_unique_and_monotonic_on_read(tmp_path):
    """`seq` 是账本唯一键：重号/篡改在读回时即报错。"""
    path = tmp_path / "calls.jsonl"
    ledger = CallLedger(path, clock=FakeClock())
    ledger.append(_record_for("call-0001"))
    ledger.append(_record_for("call-0002"))
    assert [item["seq"] for item in read_records(path)] == [1, 2]

    # 手改成重号：读回立即报错（不是默默通过）
    lines = _lines(path)
    duplicated = json.loads(lines[1])
    duplicated["seq"] = 1
    again = tmp_path / "dup.jsonl"
    again.write_text(lines[0] + "\n" + json.dumps(duplicated, ensure_ascii=False)
                     + "\n", encoding="utf-8")
    try:
        read_records(again)
    except CallLedgerError as exc:
        assert "seq" in str(exc)
    else:                                            # pragma: no cover
        raise AssertionError("seq 重号未被读回校验拦下")

    # 两个实例**先都打开空账本**，再交叉 append：必须走锁内重算分支
    both = tmp_path / "both.jsonl"
    left = CallLedger(both, clock=FakeClock())
    right = CallLedger(both, clock=FakeClock())
    seqs = []
    for index in range(3):
        seqs.append(left.append(_record_for(f"L{index}"))["seq"])
        seqs.append(right.append(_record_for(f"R{index}"))["seq"])
    assert seqs == [1, 2, 3, 4, 5, 6]
    assert [item["seq"] for item in read_records(both)] == [1, 2, 3, 4, 5, 6]

    # 跳号（中间行被拿掉）：按 max(seq)+1 续，不制造重号
    gapped = tmp_path / "gapped.jsonl"
    gl = CallLedger(gapped, clock=FakeClock())
    gl.append(_record_for("g1"))
    gl.append(_record_for("g2"))
    gl.append(_record_for("g3"))
    lines = _lines(gapped)
    gapped.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    tail = CallLedger(gapped, clock=FakeClock())
    appended = tail.append(_record_for("g4"))
    assert appended["seq"] == 4                       # max(行数2, 最大seq3)+1，不是 2+1
    assert [item["seq"] for item in read_records(gapped)] == [1, 3, 4]

    # 混排：一条有 seq + 一条无 seq 的合法记录（旧式行）——两实例都写得进去，
    # 无 seq 行只按行数计，不做编号校验（三处口径统一，不能"只有一个实例能写"）
    mixed = tmp_path / "mixed.jsonl"
    seeded = CallLedger(mixed, clock=FakeClock())
    seeded.append(_record_for("m1"))
    lines = _lines(mixed)
    mixed.write_text(lines[0] + "\n"
                     + canonical_json(_record_for("legacy")) + "\n",
                     encoding="utf-8")
    one = CallLedger(mixed, clock=FakeClock())
    two = CallLedger(mixed, clock=FakeClock())
    assert one.append(_record_for("m2"))["seq"] == 3   # max(行数2, 最大seq1)+1
    assert two.append(_record_for("m3"))["seq"] == 4   # 走重算分支也不拒写
    # 读回：旧式行没有 seq（None），编号行仍然严格递增 1,3,4
    assert [item.get("seq") for item in read_records(mixed)] == [1, None, 3, 4]


# --------------------------------------------------------------------- 10
def test_ledger_off_by_default_and_corrupt_file_refused(tmp_path):
    # 默认不记账：没有 ledger、没有环境变量 → 不落盘
    assert ledger_from_env({}) is None
    assert ledger_from_env({"VULNMAP_CALL_LEDGER": "  "}) is None
    configured = ledger_from_env({"VULNMAP_CALL_LEDGER": str(tmp_path / "e.jsonl")})
    assert isinstance(configured, CallLedger)

    with _chat_fixture() as (base_url, _fixture):
        provider, status = provider_from_env(_local_env(base_url),
                                             clock=FakeClock())
        assert provider(_payload())["status"] == "ok"
    assert status["ledger"]["enabled"] is False
    assert provider.snapshot()["ledger"] == {
        "enabled": False, "path": "", "written": 0, "errors": []}
    assert list(tmp_path.iterdir()) == []                # 一个文件都没写

    # 坏行：既不能读回，也不能在其后追加（不在可疑账本上续写）
    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text(
        canonical_json(_record_for("call-0001")) + "\nnot-json\n",
        encoding="utf-8")
    try:
        read_records(corrupt)
    except CallLedgerError as exc:
        assert "第 2 行" in str(exc)
    else:                                            # pragma: no cover
        raise AssertionError("坏行被静默跳过")
    try:
        CallLedger(corrupt, clock=FakeClock())
    except CallLedgerError:
        pass
    else:                                            # pragma: no cover
        raise AssertionError("坏账本被当成空账本续写")

    # 三态重叠/缺字段的记录读回即判错
    bad = {"call_id": "c1", "task_id": "t", "round": 1, "model": MODEL,
           "prompt_version": "", "endpoint_source": "", "transport": "",
           "request_sha256": None, "response_sha256": None,
           "usage": {"state": PARAM_SENT, "prompt_tokens": 1,
                     "completion_tokens": 1},
           "params_sent": {"model": MODEL},
           "params_not_sent": {"model": NOT_SENT_ABSENT},   # 同时 sent 又 not_sent
           "params_missing": {}}
    try:
        validate_record(bad)
    except CallLedgerError:
        pass
    else:                                            # pragma: no cover
        raise AssertionError("三态重叠未被拦下")
