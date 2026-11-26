r"""A/B 实际入口的逐调用账本验收（`tests/test_actual_ab_ledger.py`）。

被测链路（**真实入口，不是直接构造 provider**）：

```
run_real_ab(tasks=..., env=..., budget=...)
  -> _provider_with_budget(env, budget, ledger=...)
     -> ledger_from_env(env)          # VULNMAP_CALL_LEDGER / VULNMAP_LLM_LEDGER
     -> RealChatProvider(config, ledger=...)
        -> urllib POST http://127.0.0.1:PORT/v1/chat/completions
        -> CallLedger.append(record)   # append-only JSONL
```

十一组用例（**全部不联网、不调用真实模型、不使用真实 key**）：

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 入口落盘 | `test_run_real_ab_writes_ledger_via_llm_env` | 本地 HTTP fixture + `VULNMAP_LLM_LEDGER` → 账本行数 == 真发出去的调用数；顶层 `call_ledger` 块与文件一致 |
| 2 字段齐全 | `test_every_record_carries_required_audit_fields` | 每条都有 `call_id/task_id/round/model/prompt_version/endpoint_source/transport/request_sha256/response_sha256/usage/params_sent/params_not_sent/params_missing`，且值对得上 |
| 3 字节绑定 | `test_hashes_bind_to_fixture_bytes` | 用 fixture 真收到的 body / 真回的 content 独立复算两个 sha256，逐字节相等 |
| 4 来源 | `test_result_source_is_simulated_not_real` | `real_model_status/summary_scope/result_source` 全是 `simulated`，`real_model=False`；账本 `endpoint_source=simulated`、`transport=urllib` |
| 5 无凭据 | `test_ledger_never_stores_key_or_bearer` | 文件里没有 key 原文 / `Bearer` / `authorization`；但 `request.auth_header_present=true`（证明确实带了 header，只是没落盘） |
| 6 append-only | `test_append_only_across_two_entry_runs` | 两次入口运行：第二次写入不碰第一次的任何字节，`seq` 连续、`call_id` 续号 |
| 7 默认关闭 | `test_ledger_off_by_default_at_entry` | 两个环境变量都不设 → 不建文件、`call_ledger.enabled=false` |
| 8 注入 provider | `test_injected_provider_still_gets_ledger` | `run_real_ab(provider=RealChatProvider(transport=spy), env=...)` 也接账本（入口接线，不是 provider 自建） |
| 9 显式优先 | `test_explicit_ledger_argument_wins` | 同时给 `ledger=` 与 `VULNMAP_LLM_LEDGER` → 只写显式账本，环境路径不落盘 |
| 10 冲突 | `test_conflicting_env_names_refused` | 两个环境变量指向不同文件 → `CallLedgerError`，且一次 HTTP 都没发 |
| 11 拒绝也记账 | `test_budget_refusal_is_recorded_as_not_invoked` | `max_calls` 触顶的调用也有条目：`call_state=not_invoked` + 四个 body 参数 `missing/no_request_built`（不回填） |

口径：账本只证明「这一次发了什么 / 明确不发送什么 / 该有却没有」，**不**证明响应
来自真实模型；`127.0.0.1` 的响应一律 `simulated`，不进入真实统计。
"""
from __future__ import annotations

import json
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive.call_ledger import (
    CALL_NOT_INVOKED,
    CALL_SENT,
    FORBIDDEN_KEYS,
    MISSING_NO_REQUEST,
    PARAM_SENT,
    REQUIRED_FIELDS,
    CallLedger,
    CallLedgerError,
    ledger_from_env,
    read_records,
    request_digest,
    response_digest,
    validate_record,
)
from agent.platform.adaptive.llm_provider import (
    PROMPT_VERSION,
    RealChatProvider,
    provider_from_env,
    resolve_env,
)
from agent.platform.adaptive.real_ab import run_real_ab, small_ab_tasks

#: 假 key：形状像 key，但只在本文件的 fixture 环境里存在（不联网、不落盘）
KEY = "sk-actual-ab-fixture-0123456789abcdef"
MODEL = "fixture-model"
USAGE = {"prompt_tokens": 11, "completion_tokens": 7}


# --------------------------------------------------------------------- fixture
class _FixtureState:
    def __init__(self) -> None:
        self.calls: list[dict] = []       # fixture 真收到的请求体（逐字）
        self.contents: list[str] = []     # fixture 真回给客户端的 content
        self.auth_headers: list[str] = []


@contextmanager
def _chat_fixture():
    """本地 `127.0.0.1` HTTP fixture：确定性 chat 响应，记录收到的 body。

    走默认 `urllib`（不注入 transport）：请求真的发了出去，但 endpoint 是本机，
    因此来源仍是 `simulated`——这正是本文件要验收的「入口 + 账本」通路。
    """
    state = _FixtureState()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):                # http.server 约定
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            state.calls.append(body)
            state.auth_headers.append(str(self.headers.get("Authorization") or ""))
            content = json.dumps({
                "diagnosis": {"code": "no_execution"},
                "actions": ["finish_research"],
                "reason": f"fixture call {len(state.calls)}",
            }, ensure_ascii=False)
            state.contents.append(content)
            payload = {"choices": [{"message": {"content": content},
                                    "finish_reason": "stop"}],
                       "usage": dict(USAGE)}
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):     # 静音
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _env(base_url: str, ledger_path: Path | None) -> dict:
    env = {"VULNMAP_LLM_API_KEY": KEY,
           "VULNMAP_LLM_BASE_URL": base_url,
           "VULNMAP_LLM_MODEL": MODEL}
    if ledger_path is not None:
        env["VULNMAP_LLM_LEDGER"] = str(ledger_path)
    return env


def _budget(calls: int = 4) -> dict:
    return {"max_rounds": 1, "max_calls": calls,
            "max_tokens": 16000, "max_usd": None}


def _tasks(count: int = 3) -> list[dict]:
    return small_ab_tasks()[:count]


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _records(path: Path) -> list[dict]:
    records = read_records(path)          # 逐行 validate_record + seq 严格递增
    for item in records:
        validate_record(item)
    return records


# --------------------------------------------------------------------- 1
def test_run_real_ab_writes_ledger_via_llm_env(tmp_path):
    path = tmp_path / "actual-ab" / "calls.jsonl"
    tasks = _tasks(3)
    with _chat_fixture() as (base_url, fixture):
        doc = run_real_ab(tasks=tasks, env=_env(base_url, path),
                          budget=_budget(4))
    # 入口真的发了 HTTP（不是本地假 provider）
    assert len(fixture.calls) == len(tasks)
    assert doc["provider_budget"]["calls_ok"] == len(tasks)
    # 一次调用一行，且文件与文档块一致
    assert path.exists()
    records = _records(path)
    assert len(records) == len(fixture.calls) == doc["provider_budget"]["calls_ok"]
    assert doc["call_ledger"] == {
        "enabled": True,
        "path": str(path),
        "written": len(records),
        "errors": [],
        "note": doc["call_ledger"]["note"],
    }
    assert doc["call_ledger"]["note"]
    # 任务顺序与账本顺序一致（同一初始条件下逐条可对）
    assert [item["task_id"] for item in records] == \
        [task["task_id"] for task in tasks]
    assert [item["seq"] for item in records] == list(range(1, len(records) + 1))


# --------------------------------------------------------------------- 2
def test_every_record_carries_required_audit_fields(tmp_path):
    path = tmp_path / "calls.jsonl"
    tasks = _tasks(2)
    with _chat_fixture() as (base_url, _fixture):
        run_real_ab(tasks=tasks, env=_env(base_url, path), budget=_budget(2))
    records = _records(path)
    assert records
    seen_call_ids: list[str] = []
    for index, record in enumerate(records):
        absent = [name for name in REQUIRED_FIELDS if name not in record]
        assert not absent, f"第 {index + 1} 条缺字段：{absent}"
        assert record["call_id"].strip() and record["call_id"] not in seen_call_ids
        seen_call_ids.append(record["call_id"])
        assert record["task_id"] == fixtures_task_id(tasks, index)
        assert record["round"] == 1
        assert record["model"] == MODEL
        assert record["prompt_version"] == PROMPT_VERSION
        assert record["endpoint_source"] == "simulated"      # 本机 HTTP
        assert record["transport"] == "urllib"               # 默认传输
        assert record["call_state"] == CALL_SENT
        assert record["status"] == "ok"
        # 哈希：64 位小写十六进制
        for name in ("request_sha256", "response_sha256"):
            value = record[name]
            assert isinstance(value, str) and len(value) == 64
            assert all(char in "0123456789abcdef" for char in value)
        # usage：真值，不是 0 回填
        usage = record["usage"]
        assert usage["state"] == PARAM_SENT
        assert usage["prompt_tokens"] == USAGE["prompt_tokens"]
        assert usage["completion_tokens"] == USAGE["completion_tokens"]
        # 三态：sent 是请求体原值；not_sent 只有理由码；missing 为空
        sent = record["params_sent"]
        assert sent["model"] == MODEL
        assert sent["temperature"] == 0.0
        assert sent["response_format"] == {"type": "json_object"}
        assert isinstance(sent["max_tokens"], int)
        for name in ("top_p", "seed", "request_id"):
            assert isinstance(record["params_not_sent"][name], str)
            assert record["params_not_sent"][name]
        assert record["params_missing"] == {}


def fixtures_task_id(tasks: list[dict], index: int) -> str:
    """账本第 `index` 条应对应的任务（1 轮时按任务顺序一一对应）。"""
    return str(tasks[index]["task_id"])


# --------------------------------------------------------------------- 3
def test_hashes_bind_to_fixture_bytes(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        run_real_ab(tasks=_tasks(2), env=_env(base_url, path), budget=_budget(2))
    records = _records(path)
    assert len(records) == len(fixture.calls) == 2
    for record, body, content in zip(records, fixture.calls,
                                     fixture.contents):
        assert record["request_sha256"] == request_digest(body)
        assert record["response_sha256"] == response_digest(content)
        # 请求体块里的哈希与顶层一致（同一份 body，两个可核位置）
        assert record["request"]["body_sha256"] == record["request_sha256"]
        assert record["request"]["built"] is True
        assert record["request"]["url_path"].endswith("/chat/completions")
        assert record["request"]["url_host"] == "127.0.0.1"


# --------------------------------------------------------------------- 4
def test_result_source_is_simulated_not_real(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, _fixture):
        doc = run_real_ab(tasks=_tasks(2), env=_env(base_url, path),
                          budget=_budget(2))
    assert doc["real_model_status"] == "simulated"
    assert doc["summary_scope"] == "simulated"
    assert doc["result_source"] == "simulated"
    assert doc["real_model"] is False
    assert doc["mocked"] is False
    assert doc["simulated"] is True
    assert doc["transport"] == "urllib"
    assert doc["endpoint_source"] == "simulated"
    assert doc["simulated_reason"] == "local_endpoint"
    assert doc["auto_apply_allowed"] is False
    # 账本里的来源字段必须与运行时一致（不能账本说 real、结果说 simulated）
    for record in _records(path):
        assert record["endpoint_source"] == doc["endpoint_source"]
        assert record["transport"] == doc["transport"]
        assert record["call_state"] == CALL_SENT


# --------------------------------------------------------------------- 5
def test_ledger_never_stores_key_or_bearer(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        run_real_ab(tasks=_tasks(2), env=_env(base_url, path), budget=_budget(2))
    text = path.read_text(encoding="utf-8")
    assert KEY not in text                      # key 原文不落盘
    lowered = text.lower()
    for needle in ("bearer", "authorization", "api_key", "x-api-key"):
        assert needle not in lowered
    # 客户端确实带了 Authorization（通路是真的），账本只留布尔事实
    assert all(auth.lower().startswith("bearer ") for auth in fixture.auth_headers)
    for record in _records(path):
        assert record["request"]["auth_header_present"] is True
        keys = _all_keys(record)
        assert not {key.lower() for key in keys} & FORBIDDEN_KEYS


def _all_keys(value, out: list[str] | None = None) -> list[str]:
    out = [] if out is None else out
    if isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _all_keys(item, out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _all_keys(item, out)
    return out


# --------------------------------------------------------------------- 6
def test_append_only_across_two_entry_runs(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        first = run_real_ab(tasks=_tasks(2), env=_env(base_url, path),
                            budget=_budget(2))
        first_bytes = path.read_bytes()
        first_records = _records(path)
        second = run_real_ab(tasks=_tasks(2), env=_env(base_url, path),
                             budget=_budget(2))
        second_bytes = path.read_bytes()

    assert first["call_ledger"]["written"] == 2
    assert second["call_ledger"]["written"] == 2      # 本次写入条数，不是总数
    # 第二次写入完全没有碰第一次的任何字节
    assert second_bytes.startswith(first_bytes)
    assert first_bytes.count(b"\n") == 2
    assert second_bytes.count(b"\n") == 4
    records = _records(path)
    assert [item["seq"] for item in records] == [1, 2, 3, 4]
    assert [item["call_id"] for item in records] == [
        "call-0001", "call-0002", "call-0001", "call-0002"]
    assert records[:2] == first_records
    assert len(records) == len(fixture.calls) == 4


# --------------------------------------------------------------------- 7
def test_ledger_off_by_default_at_entry(tmp_path):
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, _fixture):
        doc = run_real_ab(tasks=_tasks(2), env=_env(base_url, None),
                          budget=_budget(2))
    assert doc["real_model_status"] == "simulated"
    assert doc["call_ledger"]["enabled"] is False
    assert doc["call_ledger"]["path"] == ""
    assert doc["call_ledger"]["written"] == 0
    assert not path.exists()
    assert ledger_from_env({"VULNMAP_LLM_LEDGER": "  "}) is None
    assert ledger_from_env({"VULNMAP_CALL_LEDGER": ""}) is None


# --------------------------------------------------------------------- 8
def test_injected_provider_still_gets_ledger(tmp_path):
    path = tmp_path / "calls.jsonl"
    received: list[dict] = []

    def spy(request):
        received.append(dict(request["body"]))
        return {"choices": [{"message": {"content": json.dumps(
            {"diagnosis": {}, "actions": [], "reason": "spy"})}}],
            "usage": dict(USAGE)}

    env = {"VULNMAP_LLM_API_KEY": KEY,
           "VULNMAP_LLM_BASE_URL": "https://api.example.invalid/v1",
           "VULNMAP_LLM_MODEL": MODEL,
           "VULNMAP_LLM_LEDGER": str(path)}
    provider = RealChatProvider(resolve_env(env)["config"], transport=spy)
    assert provider.ledger is None                 # 构造时没有账本
    doc = run_real_ab(tasks=_tasks(2), provider=provider, env=env,
                      budget=_budget(2))
    # 入口把环境里的账本接到了注入 provider 上
    assert provider.ledger is not None
    assert doc["call_ledger"]["enabled"] is True
    assert doc["call_ledger"]["written"] == 2
    assert len(received) == 2
    records = _records(path)
    assert len(records) == 2
    assert [item["transport"] for item in records] == ["injected", "injected"]
    # 注入 transport 仍是模拟来源，即使 endpoint 是 public HTTPS
    assert doc["result_source"] == "simulated"
    assert doc["real_model"] is False
    assert doc["real_model_status"] == "simulated"
    # 每条都能对回 spy 真收到的 body
    for record, body in zip(records, received):
        assert record["request_sha256"] == request_digest(body)


# --------------------------------------------------------------------- 9
def test_explicit_ledger_argument_wins(tmp_path):
    env_path = tmp_path / "from-env.jsonl"
    memory = CallLedger(None)
    with _chat_fixture() as (base_url, _fixture):
        doc = run_real_ab(tasks=_tasks(1), env=_env(base_url, env_path),
                          budget=_budget(1), ledger=memory)
    assert len(memory.entries()) == 1
    assert not env_path.exists()                  # 环境路径被显式参数压掉
    assert doc["call_ledger"]["enabled"] is True
    assert doc["call_ledger"]["path"] == ""       # 内存账本没有路径
    assert doc["call_ledger"]["written"] == 1
    assert scope_task(memory.entries()[0]) == _tasks(1)[0]["task_id"]


def scope_task(record: dict) -> str:
    return str(record.get("task_id") or "")


# --------------------------------------------------------------------- 10
def test_conflicting_env_names_refused(tmp_path):
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    env = {"VULNMAP_CALL_LEDGER": str(first),
           "VULNMAP_LLM_LEDGER": str(second)}
    try:
        ledger_from_env(env)
    except CallLedgerError as exc:
        assert "冲突" in str(exc)
    else:                                          # pragma: no cover - 防御
        raise AssertionError("两个不同路径必须报错，不能静默二选一")
    # 同一个文件用两种写法（相对/绝对）不算冲突
    same = ledger_from_env({"VULNMAP_CALL_LEDGER": str(tmp_path / "same.jsonl"),
                            "VULNMAP_LLM_LEDGER": str(tmp_path / "same.jsonl")})
    assert same is not None and same.path == tmp_path / "same.jsonl"

    with _chat_fixture() as (base_url, fixture):
        try:
            run_real_ab(tasks=_tasks(1), env={**_env(base_url, None), **env},
                        budget=_budget(1))
        except CallLedgerError:
            pass
    assert fixture.calls == []                     # 冲突在传输前就拦住


# --------------------------------------------------------------------- 11
def test_budget_refusal_is_recorded_as_not_invoked(tmp_path):
    """预算拒绝也是「一次调用」：必须记账，且不能拿配置默认值冒充已发送。

    入口侧的 `budget` 是 runner 的软预算；provider 自己的 `max_calls` 是硬顶。
    这里让 provider 硬顶 = 1、runner 软预算 = 3，于是后两次调用**没发出去**
    但仍是 provider 的一次处理 → 账本必须有 `not_invoked` 条目。
    """
    path = tmp_path / "calls.jsonl"
    with _chat_fixture() as (base_url, fixture):
        env = _env(base_url, path)
        env["VULNMAP_LLM_MAX_CALLS"] = "1"          # 只在构造 provider 时用
        provider = RealChatProvider(resolve_env(env)["config"])
        doc = run_real_ab(tasks=_tasks(3), provider=provider, env=env,
                          budget=_budget(3))
    assert len(fixture.calls) == 1                 # 只真发了一次
    records = _records(path)
    # 每次“调用”（含被预算拒绝的后两次）都有账，且账本不冒充「发过了」
    assert len(records) == doc["provider_budget"]["calls_seen"] == 3
    assert [item["call_state"] for item in records] == [
        CALL_SENT, CALL_NOT_INVOKED, CALL_NOT_INVOKED]
    for refused in records[1:]:
        assert refused["invoked"] is False
        assert refused["status"] == "budget_exhausted"
        assert refused["request_sha256"] is None
        assert refused["response_sha256"] is None
        for name in ("model", "temperature", "max_tokens", "response_format"):
            assert refused["params_missing"][name] == MISSING_NO_REQUEST
        assert refused["params_sent"] == {}
        assert refused["usage"]["state"] == "missing"
        assert refused["usage"]["prompt_tokens"] is None
    assert doc["real_model_status"] == "simulated"


# --------------------------------------------------------------------- 12
def test_provider_from_env_honours_llm_ledger_name(tmp_path):
    path = tmp_path / "provider.jsonl"
    with _chat_fixture() as (base_url, fixture):
        provider, status = provider_from_env(_env(base_url, path))
        assert status["ledger"] == {"enabled": True, "path": str(path),
                                    "written": 0, "errors": []}
        assert provider({"task_id": "w4-t01", "round_no": 1})["status"] == "ok"
    assert len(fixture.calls) == 1
    records = _records(path)
    assert len(records) == 1
    assert records[0]["task_id"] == "w4-t01"
    assert provider.snapshot()["ledger"]["written"] == 1
