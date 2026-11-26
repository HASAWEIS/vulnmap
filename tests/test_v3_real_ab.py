r"""V3 真实模型只读 A/B 回归（`tests/test_v3_real_ab.py`）。

被测实现：

- `agent/platform/adaptive/llm_provider.py`：真实 OpenAI-compatible 只读 provider
  （`transport` 怎么发 / `endpoint_source` 发给谁 / `result_source` 能否进真实统计）；
- `agent/platform/adaptive/real_ab.py`：A/B runner（blocked/mocked/simulated/ran/failed）；
- `agent/platform/adaptive/compare.py`：`provider_kind="real"` / `"simulated"` 分支
  （默认 `offline` 口径未改）。

十组用例（全部不联网）：

| 组 | 用例 | 断言什么 |
|---|---|---|
| 1 无 key blocked | `test_blocked_without_key_never_fabricates_results` | `real_model_status="blocked"`、`missing_env` 精确、`summary=None`、没有 0 调用/0 费用冒充 |
| 2 mock 隔离 | `test_mock_is_tagged_and_never_mixed_with_real` | `mocked=True`、`real_model_status="mocked"`、`result_source="mock"`、`cost_is_fake`，与 `ran` 互斥 |
| 3 只读不写 | `test_simulated_provider_is_read_only_and_strips_verdict_fields` | 全程无文件写入；夹带 `verified` 的动作被拒；注入 transport → `simulated` 且文档无裁决字段 |
| 4 错误采纳门禁 | `test_wrong_adoption_blocks_simulated_gate` | 替身提 gold 禁止的 `run_epoch` → `no_model_wrong_adoption` 一票否决、`auto_apply=False` |
| 5 密钥卫生 | `test_key_never_reaches_doc_log_or_artifacts` | key 不进 doc / provider log / 落盘 JSON；artifact 带 `result_source`/`transport` |
| 6 结构化失败/预算 | `test_structured_errors_and_budget_stop` | 注入传输超时 → `simulated` + `calls_ok=0`；`max_calls=1` → 其余 `budget_exhausted`；默认 urllib 槽位仍记 `failed`；无价格时 `usd=None` 不是 0 |
| 7 预算门禁（显式 max_usd） | `test_provider_transport_never_called_when_price_unknown`、`test_real_ab_budget_max_usd_without_price_blocks_before_transport`、`test_mock_result_never_impersonates_real` | 显式 `max_usd` 必须下发；无单价 → `blocked/price_unknown`、传输 0 次、不记 `ran`；mock 不能标成 `ran/real` |
| 8 真实 HTTP 通路 | `test_urllib_transport_really_posts_chat_completions_locally` | 默认 `urllib` 真发 `POST /v1/chat/completions`（本地 fixture），header/usage 正确；本地 endpoint 的来源是 `simulated` |
| 9 来源口径 | `test_status_reports_transport_and_result_source`、`test_injected_transport_never_reports_ran_or_real`、`test_default_urllib_real_branch_is_not_harmed`、`test_result_source_exclusive_selfcheck_rejects_impersonation` | public HTTPS 默认=`urllib/real`；注入=`injected/simulated`；注入 transport 有调用也只报 `simulated`；真实分支不被误伤；来源篡改被互斥自检判错 |
| 10 endpoint 来源（本轮） | `test_endpoint_source_classification_is_machine_readable`、`test_local_http_status_is_simulated_but_transport_still_sends`、`test_local_http_default_urllib_real_ab_end_to_end_is_simulated`、`test_public_https_status_is_real_without_network_request` | 只有 public HTTPS 算 `real`；本地 HTTP 默认 urllib 端到端是 `simulated`（不是 `ran/real`）；status 给机读 reason；public HTTPS status 为 real 且不发请求 |
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

import agent.platform.adaptive.llm_provider as llm_provider_mod
from agent.platform.adaptive.compare import FakeClock, FakeProvider
from agent.platform.adaptive.llm_provider import (
    ProviderConfig,
    RealChatProvider,
    TransportError,
    classify_endpoint,
    provider_from_env,
    resolve_env,
)
from agent.platform.adaptive.real_ab import (
    SMALL_BUDGET,
    RealABError,
    _check_status_exclusive,
    render_real_ab_markdown,
    run_real_ab,
    small_ab_tasks,
)

KEY = "sk-test-0123456789abcdef"
ENV_READY = {
    "VULNMAP_LLM_API_KEY": KEY,
    "VULNMAP_LLM_BASE_URL": "https://api.example.test/v1",
    "VULNMAP_LLM_MODEL": "test-model",
}


def _params(action: str) -> dict:
    if action == "finish_research":
        return {"reason": "candidate observed in execution feedback"}
    return {}


def _user_of(request: dict) -> dict:
    messages = request["body"]["messages"]
    return json.loads(messages[-1]["content"])


def _chat(suggestion: dict, *, tokens_in: int = 120,
          tokens_out: int = 40) -> dict:
    return {
        "choices": [{"message": {"content": json.dumps(suggestion,
                                                       ensure_ascii=False)}}],
        "usage": {"prompt_tokens": tokens_in, "completion_tokens": tokens_out},
    }


def _gold_transport(tasks: list[dict], *, action_override: str = ""):
    """理想的真实模型：按人工 gold 回诊断与动作（传输层是内存假实现）。"""
    index = {task["task_id"]: task for task in tasks}

    def transport(request: dict) -> dict:
        user = _user_of(request)
        task = index[str(user["task_id"])]
        gold = task["gold"]
        actions = ([action_override] if action_override
                   else list(gold["actions"]))
        suggestion = {
            "diagnosis": {"code": gold["diagnosis"]},
            "actions": [{"action": name, "params": _params(name)}
                        for name in actions],
            "reason": "gold replay for test",
        }
        return _chat(suggestion)
    return transport


def _provider(transport, *, env: dict | None = None) -> RealChatProvider:
    provider, _ = provider_from_env(env or ENV_READY, transport=transport,
                                    clock=FakeClock(0.01))
    return provider


@contextmanager
def _local_chat_fixture():
    """本地 127.0.0.1 HTTP fixture：记录每次 POST，回固定 chat 响应。"""
    calls: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):                # http.server 约定
            length = int(self.headers.get("Content-Length") or 0)
            calls.append(json.loads(self.rfile.read(length).decode("utf-8")))
            content = json.dumps({"diagnosis": {"code": "no_execution"},
                                  "actions": [], "reason": "local fixture"})
            data = json.dumps({
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            }).encode("utf-8")
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
        yield f"http://127.0.0.1:{port}/v1", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _local_env(base_url: str) -> dict:
    return {"VULNMAP_LLM_API_KEY": KEY,
            "VULNMAP_LLM_BASE_URL": base_url,
            "VULNMAP_LLM_MODEL": "local-fixture"}


def _model_records(doc: dict) -> list[dict]:
    return [item["model"] for item in doc.get("tasks") or ()]


# --------------------------------------------------------------------- 1 blocked
def test_blocked_without_key_never_fabricates_results():
    tasks = small_ab_tasks()
    env = {"VULNMAP_LLM_BASE_URL": "https://api.example.test/v1",
           "VULNMAP_LLM_MODEL": "test-model"}
    doc = run_real_ab(tasks=tasks, env=env)

    assert doc["real_model_status"] == "blocked"
    assert doc["mocked"] is False and doc["real_model"] is False
    assert "VULNMAP_LLM_API_KEY" in doc["missing_env"]
    assert doc["summary"] is None                 # 没有指标，不是 0 指标
    assert doc["provider_trace"] == []
    assert doc["gate"]["default_arm"] == "rules"
    assert doc["gate"]["auto_apply"] is False
    assert doc["verdict"] == "not_evaluated"
    assert doc["tasks_total"] == len(tasks)
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert '"model_calls": 0' not in body          # 不编造“0 次调用”
    assert "mocked" in body and '"mocked": false' in body

    # 三个必要件都缺时，missing_env 逐项列出（统一逻辑名）
    empty = run_real_ab(tasks=tasks, env={})
    assert empty["real_model_status"] == "blocked"
    assert sorted(empty["missing_env"]) == [
        "VULNMAP_LLM_API_KEY", "VULNMAP_LLM_BASE_URL", "VULNMAP_LLM_MODEL"]

    markdown = render_real_ab_markdown(doc)
    assert "real_model_status" in markdown and "blocked" in markdown
    assert "是否可开放自动应用：**否**" in markdown
    assert "不是 0" in markdown


# --------------------------------------------------------------------- 2 mocked
def test_mock_is_tagged_and_never_mixed_with_real():
    tasks = small_ab_tasks()
    script = {}
    for task in tasks:
        gold = task["gold"]
        script[task["task_id"]] = {
            "diagnosis": {"code": gold["diagnosis"]},
            "actions": [{"action": name, "params": _params(name)}
                        for name in gold["actions"]],
        }
    provider = FakeProvider(script)
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock())

    assert doc["mocked"] is True
    assert doc["real_model_status"] == "mocked"
    assert doc["real_model"] is False
    assert doc["simulated"] is False
    assert doc["result_source"] == "mock"
    assert doc["summary_scope"] == "mock"
    assert doc["provider_status"]["cost_is_fake"] is True
    assert doc["summary"] is not None
    assert doc["summary"]["correct"]["model"] == len(tasks)
    assert doc["summary"]["cost"]["calls"]["model"] == sum(
        len(task["rounds"]) for task in tasks)
    assert doc["gate"]["auto_apply"] is False
    assert doc["gate"]["default_arm"] in ("rules", "model")
    # mocked 与 ran 互斥：不能既标 mock 又标真实跑过
    assert doc["real_model_status"] != "ran"
    assert "mocked=true" in doc["note"]


# --------------------------------------------------------------------- 3 只读
def test_simulated_provider_is_read_only_and_strips_verdict_fields(monkeypatch):
    tasks = small_ab_tasks()
    index = {task["task_id"]: task for task in tasks}

    def transport(request: dict) -> dict:
        user = _user_of(request)
        gold = index[str(user["task_id"])]["gold"]
        return _chat({
            "diagnosis": {"code": gold["diagnosis"]},
            "actions": [{"action": "run_epoch",
                         "params": {"verified": True, "confirmed": True}}],
            "reason": "try to smuggle a verdict",
        })

    provider = _provider(transport)

    # 运行期禁止任何文件写入（provider 只读；runner 未给 artifacts_dir）
    def _boom(*args, **kwargs):
        raise AssertionError("只读 A/B 不应写文件")

    monkeypatch.setattr(Path, "write_text", _boom)
    monkeypatch.setattr(Path, "write_bytes", _boom)
    monkeypatch.setattr(Path, "mkdir", _boom)
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock())

    # 注入 transport：有调用，但来源是 simulated，绝不记 ran/real
    assert doc["real_model_status"] == "simulated"
    assert doc["summary_scope"] == "simulated"
    assert doc["real_model"] is False and doc["mocked"] is False
    assert doc["simulated"] is True
    assert doc["transport"] == "injected"
    assert doc["result_source"] == "simulated"
    assert doc["provider_budget"]["calls_ok"] > 0        # 确实发生过调用
    assert doc["provider_status"]["read_only"] is True
    assert doc["provider_status"]["writes"] == []
    for record in _model_records(doc):
        assert record["adopted"] == 0
        assert any("verdict_fields" in reason for reason in record["rejected"])
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert '"verified": true' not in body
    assert '"confirmed": true' not in body
    # 只允许“被剥掉的字段名”出现在 rejected 原因里，不允许作为建议字段透传
    for record in _model_records(doc):
        assert "verified" not in record and "confirmed" not in record
    # provider 自己的调用摘要也没有裁决字段
    assert all("verified" not in json.dumps(entry, ensure_ascii=False)
               for entry in doc["provider_trace"])


# --------------------------------------------------------------------- 4 门禁
def test_wrong_adoption_blocks_simulated_gate():
    tasks = small_ab_tasks()
    provider = _provider(_gold_transport(tasks, action_override="run_epoch"))
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock())

    assert doc["real_model_status"] == "simulated"
    assert doc["summary_scope"] == "simulated"
    summary = doc["summary"]
    assert summary["wrong_adoptions"]["model"] > 0
    assert "forbidden_action:run_epoch" in " ".join(
        str(item) for record in _model_records(doc)
        for item in record["wrong_reasons"])
    gate = doc["gate"]
    assert gate["default_arm"] == "rules"
    assert gate["model_advisory_allowed"] is False
    assert gate["auto_apply"] is False
    checks = {item["name"]: item["ok"] for item in gate["checks"]}
    assert checks["read_only_simulated_provider"] is True
    assert "no_model_wrong_adoption" in gate["reasons"]
    assert any("allow_auto_apply" in item or "proposal_gate" in item
               for item in gate["auto_apply_blockers"])
    assert doc["auto_apply_allowed"] is False


# --------------------------------------------------------------------- 5 密钥
def test_key_never_reaches_doc_log_or_artifacts(tmp_path):
    tasks = small_ab_tasks()
    provider = _provider(_gold_transport(tasks))
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock(), artifacts_dir=tmp_path)

    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert KEY not in body
    assert "Bearer" not in body
    trace = json.dumps(doc["provider_trace"], ensure_ascii=False)
    assert KEY not in trace and "Authorization" not in trace
    assert doc["provider_status"]["key_ref"] == "env:VULNMAP_LLM_API_KEY"

    for path in tmp_path.iterdir():
        text = path.read_text(encoding="utf-8")
        assert KEY not in text
        assert "Bearer" not in text
    payload = json.loads((tmp_path / "real-ab.json").read_text(encoding="utf-8"))
    assert payload["real_model_status"] == "simulated"     # 注入 transport，不是真跑
    assert payload["mocked"] is False
    assert payload["result_source"] == "simulated"
    assert payload["transport"] == "injected"
    assert payload["summary_scope"] == "simulated"

    # 配置对象自己的 repr/to_dict 也不能带 key
    cfg = resolve_env(ENV_READY)["config"]
    assert KEY not in repr(cfg)
    assert KEY not in json.dumps(cfg.to_dict(), ensure_ascii=False)


# --------------------------------------------------------------------- 6 失败/预算
def test_structured_errors_and_budget_stop(monkeypatch):
    tasks = small_ab_tasks()

    def timeout_transport(request: dict) -> dict:
        raise TransportError("timeout", "请求超时", retryable=True)

    provider = _provider(timeout_transport)
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock())
    # 注入 transport：即使全部超时也只是 simulated（不进真实统计）
    assert doc["real_model_status"] == "simulated"
    assert doc["provider_budget"]["calls_ok"] == 0
    assert doc["provider_budget"]["calls_invoked"] == len(tasks)
    assert len(doc["summary"]["retained"]["environment_error"]) == len(tasks)
    assert all(record["error"] == "timeout" for record in _model_records(doc))
    assert doc["summary"]["cost"]["calls"]["model"] == len(tasks)
    assert doc["gate"]["default_arm"] == "rules"

    provider = _provider(_gold_transport(tasks))
    doc = run_real_ab(tasks=tasks, provider=provider,
                      budget={"max_calls": 1, "max_rounds": 2,
                              "max_tokens": 16000, "max_usd": None},
                      clock=FakeClock())
    status_counts = doc["summary"]["status_counts"]["model"]
    assert status_counts["ok"] == 1
    assert status_counts["budget_exhausted"] == len(tasks) - 1
    assert doc["summary"]["cost"]["calls"]["model"] == 1
    assert doc["provider_budget"]["calls_invoked"] == 1

    # 没有价格表：金额是未知，不是 0
    assert doc["summary"]["cost"]["usd"]["model"] is None
    assert doc["summary"]["cost"]["usd_known"] is False
    metric = next(row for row in doc["summary"]["metrics"]
                  if row["metric"] == "model_usd")
    assert metric["known"] is False and metric["reason"] == "model_unknown"

    # 真实通路（默认 urllib 槽位 + provider=None）仍然会记 failed：
    # 换成超时传输后，real 分支的失败语义没有被 simulated 改动误伤
    monkeypatch.setattr(llm_provider_mod, "_urllib_transport", timeout_transport)
    real_doc = run_real_ab(tasks=tasks, env=ENV_READY, budget=SMALL_BUDGET,
                           clock=FakeClock())
    assert real_doc["real_model_status"] == "failed"
    assert real_doc["summary_scope"] == "real"
    assert real_doc["transport"] == "urllib"
    assert real_doc["result_source"] == "real"
    assert real_doc["mocked"] is False and real_doc["simulated"] is False
    assert real_doc["provider_budget"]["calls_ok"] == 0


def test_provider_budget_and_price_guard_are_structured():
    cfg = ProviderConfig(base_url="https://api.example.test/v1",
                          model="test-model", api_key=KEY,
                          max_calls=1, max_usd=0.01)
    provider = RealChatProvider(cfg, transport=lambda request: _chat(
        {"diagnosis": {"code": "no_execution"}, "actions": []}))
    # 设了 max_usd 却没有单价：status 直接 blocked（不谎称成本受控）
    status = provider.status()
    assert status["real_model_status"] == "blocked"
    assert "VULNMAP_LLM_PRICE_IN_PER_1K" in status["missing_env"]
    first = provider({"task_id": "t1", "round_no": 1, "observation": {}})
    assert first["error"] == "price_unknown"
    assert first["status"] == "environment_error"

    provider = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY, max_calls=1),
        transport=lambda request: _chat({"diagnosis": {"code": "no_execution"},
                                          "actions": []}))
    assert provider.status()["real_model_status"] == "ready"
    assert provider({"task_id": "t1", "round_no": 1,
                     "observation": {}})["status"] == "ok"
    second = provider({"task_id": "t2", "round_no": 1, "observation": {}})
    assert second["status"] == "budget_exhausted"
    assert second["error"] == "max_calls"
    assert provider.snapshot()["calls_invoked"] == 1


# --------------------------------------------------------------------- 7 真实 HTTP 通路
def test_urllib_transport_really_posts_chat_completions_locally():
    """用本地 HTTP fixture 验证默认 `urllib` 通路（本地假模型，不是真实模型）。"""
    seen: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):                # http.server 约定
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization")
            seen["model"] = body.get("model")
            content = json.dumps({"diagnosis": {"code": "no_execution"},
                                  "actions": [], "reason": "local fixture"})
            data = json.dumps({
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            }).encode("utf-8")
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
        env = {
            "VULNMAP_LLM_API_KEY": KEY,
            "VULNMAP_LLM_BASE_URL": f"http://127.0.0.1:{port}/v1",
            "VULNMAP_LLM_MODEL": "local-fixture",
        }
        provider, status = provider_from_env(env)
        assert status["real_model_status"] == "ready"
        out = provider({"task_id": "w4-t01", "round_no": 1,
                        "observation": {"trials": 0,
                                        "snapshot_status": "unknown"}})
        assert out["status"] == "ok"
        assert out["diagnosis"]["code"] == "no_execution"
        assert out["usage"]["tokens_in"] == 11
        assert out["usage"]["tokens_out"] == 7
        assert seen["path"] == "/v1/chat/completions"
        assert seen["model"] == "local-fixture"
        assert seen["auth"] == f"Bearer {KEY}"
        assert provider.snapshot()["calls_ok"] == 1
        assert KEY not in json.dumps(provider.snapshot(), ensure_ascii=False)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# --------------------------------------------------------------------- 8 预算门禁
def test_provider_transport_never_called_when_price_unknown():
    """直接打 provider：显式 max_usd + 无单价 → 传输 0 次，不记成功调用。"""
    calls: list[dict] = []

    def spy(request: dict) -> dict:
        calls.append(dict(request))
        return _chat({"diagnosis": {"code": "no_execution"}, "actions": []})

    cfg = ProviderConfig(base_url="https://api.example.test/v1",
                          model="test-model", api_key=KEY,
                          max_calls=4, max_usd=0.01)
    provider = RealChatProvider(cfg, transport=spy)

    status = provider.status()
    assert status["real_model_status"] == "blocked"          # 不是 ready
    assert status["blocked_reason"] == "price_unknown"       # 机读理由
    assert status["blocked_reasons"] == ["price_unknown"]
    assert status["price_unknown"] is True
    assert status["budget"]["max_usd"] == 0.01               # 上限确实在配置里
    assert status["budget"]["price_known"] is False

    result = provider({"task_id": "t1", "round_no": 1, "observation": {}})
    assert calls == []                                       # 传输 0 次
    assert result["status"] == "environment_error"
    assert result["error"] == "price_unknown"
    assert result["meta"]["invoked"] is False

    snapshot = provider.snapshot()
    assert snapshot["calls_invoked"] == 0
    assert snapshot["calls_ok"] == 0
    assert snapshot["usd"] is None and snapshot["usd_known"] is False
    assert all(entry["invoked"] is False for entry in snapshot["log"])

    # 再调一次也一样被拒（不是“第一次放行、后面才拦”）
    assert provider({"task_id": "t2", "round_no": 1,
                     "observation": {}})["error"] == "price_unknown"
    assert calls == [] and provider.snapshot()["calls_invoked"] == 0

    # 补上单价后同一份 max_usd 才允许调用
    priced = RealChatProvider(
        ProviderConfig(base_url="https://api.example.test/v1",
                       model="test-model", api_key=KEY, max_usd=0.01,
                       price_in_per_1k=0.1, price_out_per_1k=0.2),
        transport=spy)
    assert priced.status()["real_model_status"] == "ready"
    assert priced({"task_id": "t1", "round_no": 1,
                   "observation": {}})["status"] == "ok"
    assert len(calls) == 1


def test_real_ab_budget_max_usd_without_price_blocks_before_transport(
        monkeypatch):
    """跑 run_real_ab：budget 里的 max_usd 必须下发；无单价 → blocked/0 次。"""
    calls: list[dict] = []

    def spy(request: dict) -> dict:
        calls.append(dict(request))
        return _chat({"diagnosis": {"code": "no_execution"}, "actions": []})

    # 默认 urllib 通路在 provider 构造时解析模块全局，这里换成内存 spy
    monkeypatch.setattr(llm_provider_mod, "_urllib_transport", spy)
    # 环境里有 key/base/model，但刻意没有单价
    budget = {"max_rounds": 2, "max_calls": 12, "max_tokens": 16000,
              "max_usd": 0.01}
    doc = run_real_ab(tasks=small_ab_tasks(), env=ENV_READY, budget=budget,
                      clock=FakeClock())

    assert calls == []                                   # 传输 0 次
    assert doc["real_model_status"] == "blocked"         # 不是 ran
    assert doc["real_model_status"] != "ran"
    assert doc["mocked"] is False and doc["real_model"] is False
    assert doc["blocked_reason"] == "price_unknown"
    assert doc["summary"] is None                        # 没有指标
    assert doc["provider_trace"] == []
    assert doc["provider_budget"] == {
        "calls_seen": 0, "calls_invoked": 0, "calls_ok": 0,
        "tokens_in": 0, "tokens_out": 0,
        "usd": None, "usd_known": False, "exhausted": "",
    }
    assert doc["provider_status"]["real_model_status"] == "blocked"
    assert doc["provider_status"]["price_unknown"] is True
    assert doc["provider_status"]["budget"]["max_usd"] == 0.01
    assert "price_unknown" in doc["gate"]["reasons"]
    assert doc["gate"]["default_arm"] == "rules"
    assert doc["gate"]["auto_apply"] is False
    assert doc["auto_apply_allowed"] is False
    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert '"real_model_status": "ran"' not in body
    assert '"model_calls": 0' not in body                # 不编“跑过 0 次”

    markdown = render_real_ab_markdown(doc)
    assert "price_unknown" in markdown and "0 次" in markdown


def test_mock_result_never_impersonates_real():
    """mock 只能是 mocked；自称真实但带 mock 标记的对象不得进真实通路。"""
    tasks = small_ab_tasks()
    script = {task["task_id"]: {
        "diagnosis": {"code": task["gold"]["diagnosis"]},
        "actions": [{"action": name, "params": _params(name)}
                    for name in task["gold"]["actions"]],
    } for task in tasks}
    doc = run_real_ab(tasks=tasks, provider=FakeProvider(script),
                      budget=SMALL_BUDGET, clock=FakeClock())
    assert doc["mocked"] is True
    assert doc["real_model_status"] == "mocked"
    assert doc["summary_scope"] == "mock"
    assert doc["result_source"] == "mock"
    assert doc["real_model"] is False
    assert doc["provider_status"]["real_model"] is False
    assert doc["provider_status"]["mocked"] is True
    assert doc["provider_status"]["real_model_status"] == "mocked"
    assert doc["provider_status"]["cost_is_fake"] is True
    assert doc["auto_apply_allowed"] is False
    assert doc["real_model_status"] != "ran"

    class _Impersonator:
        """自称 real_model=True，却又带 mocked=True：必须被拒，不能记 ran。"""

        offline = False
        real_model = True
        read_only = True
        mocked = True

        def status(self) -> dict:
            return {"real_model_status": "ready", "missing_env": []}

        def snapshot(self) -> dict:
            return {"calls_ok": 1}

        def __call__(self, payload):  # pragma: no cover - 不该被调用
            raise AssertionError("冒充真实的 mock 不应被调用")

    try:
        run_real_ab(tasks=tasks, provider=_Impersonator(), clock=FakeClock())
    except RealABError as exc:
        assert "offline=True" in str(exc)
    else:                                             # pragma: no cover
        raise AssertionError("冒充真实的 mock 必须被拒")

    # 互斥自检本身：手改成 ran+mocked 的文档直接判错
    for bad in ({"real_model_status": "ran", "mocked": True,
                 "real_model": True},
                {"real_model_status": "ran", "mocked": False,
                 "real_model": False},
                {"real_model_status": "mocked", "mocked": False,
                 "real_model": False}):
        try:
            _check_status_exclusive(bad)
        except RealABError:
            continue
        raise AssertionError(f"互斥自检漏放：{bad}")


# --------------------------------------------------------------------- 9 来源口径
def test_status_reports_transport_and_result_source():
    """默认 urllib=real；注入 transport=injected/simulated（机读、可落盘）。"""
    _, default_status = provider_from_env(ENV_READY, clock=FakeClock(0.01))
    assert default_status["transport"] == "urllib"
    assert default_status["result_source"] == "real"
    assert default_status["real_model"] is True
    assert default_status["simulated"] is False
    assert default_status["mocked"] is False

    spy = _gold_transport(small_ab_tasks())
    injected, injected_status = provider_from_env(
        ENV_READY, transport=spy, clock=FakeClock(0.01))
    assert injected_status["transport"] == "injected"
    assert injected_status["result_source"] == "simulated"
    assert injected_status["endpoint_source"] == "real"      # endpoint 是 public HTTPS
    assert injected_status["simulated_reason"] == "injected_transport"
    assert injected_status["real_model"] is False
    assert injected_status["simulated"] is True
    assert injected_status["mocked"] is False
    assert injected_status["real_model_status"] == "ready"   # 能跑，但不是真实来源

    snapshot = injected.snapshot()
    assert snapshot["transport"] == "injected"
    assert snapshot["result_source"] == "simulated"
    assert snapshot["endpoint_source"] == "real"
    assert snapshot["simulated_reason"] == "injected_transport"
    assert snapshot["real_model"] is False
    assert snapshot["simulated"] is True
    assert KEY not in json.dumps(snapshot, ensure_ascii=False)

    # 来源字段只在 host 级别、不带 endpoint 全文与 key
    body = json.dumps(injected_status, ensure_ascii=False)
    assert "api.example.test/v1" not in body
    assert KEY not in body


def test_injected_transport_never_reports_ran_or_real(tmp_path):
    """注入 transport spy：有调用，但报告是 simulated，不是 ran/real。"""
    tasks = small_ab_tasks()
    calls: list[dict] = []
    gold = _gold_transport(tasks)

    def spy(request: dict) -> dict:
        calls.append(dict(request))
        return gold(request)

    provider = _provider(spy)
    doc = run_real_ab(tasks=tasks, provider=provider, budget=SMALL_BUDGET,
                      clock=FakeClock(), artifacts_dir=tmp_path)

    assert calls                                           # 确实发生了调用
    assert doc["provider_budget"]["calls_ok"] > 0          # 且调用成功
    assert doc["real_model_status"] == "simulated"
    assert doc["real_model_status"] != "ran"
    assert doc["summary_scope"] == "simulated"
    assert doc["real_model"] is False
    assert doc["mocked"] is False and doc["simulated"] is True
    assert doc["transport"] == "injected"
    assert doc["result_source"] == "simulated"
    assert doc["auto_apply_allowed"] is False
    assert doc["gate"]["auto_apply"] is False
    # 门禁里认的是“模拟来源”，不是真实只读
    checks = {item["name"]: item["ok"] for item in doc["gate"]["checks"]}
    assert checks["read_only_simulated_provider"] is True
    assert "read_only_real_provider" not in checks

    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert '"real_model_status": "ran"' not in body
    assert '"summary_scope": "real"' not in body

    # 报告与 artifact 都要写来源，读者一眼能看出这不是真实模型结果
    markdown = (tmp_path / "real-ab.md").read_text(encoding="utf-8")
    assert "result_source=simulated" in markdown or "`simulated`" in markdown
    assert "transport=injected" in markdown
    payload = json.loads((tmp_path / "real-ab.json").read_text(encoding="utf-8"))
    assert payload["real_model_status"] == "simulated"
    assert payload["summary_scope"] == "simulated"
    assert payload["result_source"] == "simulated"
    assert payload["transport"] == "injected"
    assert payload["simulated"] is True
    assert payload["mocked"] is False
    assert payload["doc"]["result_source"] == "simulated"


def test_default_urllib_real_branch_is_not_harmed(monkeypatch):
    """provider=None + 默认 urllib 槽位 → 仍是 real/ran，不被 simulated 误伤。"""
    tasks = small_ab_tasks()
    calls: list[dict] = []
    gold = _gold_transport(tasks)

    def spy(request: dict) -> dict:
        calls.append(dict(request))
        return gold(request)

    # 只替换“默认传输槽位”，不注入 provider：来源仍是 urllib/real
    monkeypatch.setattr(llm_provider_mod, "_urllib_transport", spy)
    doc = run_real_ab(tasks=tasks, env=ENV_READY, budget=SMALL_BUDGET,
                      clock=FakeClock())

    assert calls
    assert doc["real_model_status"] == "ran"
    assert doc["summary_scope"] == "real"
    assert doc["transport"] == "urllib"
    assert doc["result_source"] == "real"
    assert doc["real_model"] is True
    assert doc["mocked"] is False and doc["simulated"] is False
    assert doc["provider_status"]["transport"] == "urllib"
    assert doc["provider_status"]["result_source"] == "real"
    assert doc["provider_status"]["real_model"] is True
    assert doc["auto_apply_allowed"] is False
    checks = {item["name"]: item["ok"] for item in doc["gate"]["checks"]}
    assert checks["read_only_real_provider"] is True
    assert "read_only_simulated_provider" not in checks


def test_result_source_exclusive_selfcheck_rejects_impersonation():
    """`result_source` 与 `real_model_status` 必须自洽，篡改即判错。"""
    bad_docs = (
        {"real_model_status": "ran", "mocked": False, "real_model": True,
         "result_source": "simulated"},
        {"real_model_status": "simulated", "mocked": False, "real_model": False,
         "simulated": False, "result_source": "simulated"},
        {"real_model_status": "simulated", "mocked": False, "real_model": True,
         "simulated": True, "result_source": "simulated"},
        {"real_model_status": "blocked", "mocked": False, "real_model": False,
         "result_source": "real"},
        {"real_model_status": "ran", "mocked": False, "real_model": True,
         "result_source": "unknown"},
        {"real_model_status": "ran", "mocked": False, "real_model": True,
         "result_source": "real", "endpoint_source": "simulated"},
        {"real_model_status": "ran", "mocked": False, "real_model": True,
         "result_source": "real", "endpoint_source": "real",
         "transport": "injected"},
        {"real_model_status": "ran", "mocked": False, "real_model": True,
         "result_source": "real", "endpoint_source": "unknown"},
    )
    for bad in bad_docs:
        try:
            _check_status_exclusive(bad)
        except RealABError:
            continue
        raise AssertionError(f"来源互斥自检漏放：{bad}")

    # 合法形状不能被误判
    _check_status_exclusive({"real_model_status": "ran", "mocked": False,
                             "real_model": True, "result_source": "real",
                             "endpoint_source": "real",
                             "transport": "urllib"})
    _check_status_exclusive({"real_model_status": "simulated", "mocked": False,
                             "real_model": False, "simulated": True,
                             "result_source": "simulated"})
    _check_status_exclusive({"real_model_status": "blocked", "mocked": False,
                             "real_model": False, "result_source": "none"})


# --------------------------------------------------------- 10 endpoint 来源
def test_endpoint_source_classification_is_machine_readable():
    """只有 public HTTPS 算 real；本机/私网/link-local/非 HTTPS 的 reason 可机读。"""
    matrix = (
        ("https://api.example.test/v1", "real", ""),
        ("https://api.example.test/v1/chat/completions", "real", ""),
        ("http://api.example.test/v1", "simulated", "non_https_endpoint"),
        ("http://127.0.0.1:8000/v1", "simulated", "local_endpoint"),
        ("https://127.0.0.1/v1", "simulated", "local_endpoint"),
        ("http://localhost:8000/v1", "simulated", "local_endpoint"),
        ("https://localhost/v1", "simulated", "local_endpoint"),
        ("https://[::1]/v1", "simulated", "local_endpoint"),
        ("http://0.0.0.0:8000/v1", "simulated", "local_endpoint"),
        ("https://10.1.2.3/v1", "simulated", "private_endpoint"),
        ("https://192.168.1.10/v1", "simulated", "private_endpoint"),
        ("https://172.16.0.5/v1", "simulated", "private_endpoint"),
        ("https://169.254.10.10/v1", "simulated", "private_endpoint"),
        ("http://[fe80::1]/v1", "simulated", "private_endpoint"),
        ("https://8.8.8.8/v1", "real", ""),
    )
    for url, source, reason in matrix:
        got = classify_endpoint(url)
        assert got["endpoint_source"] == source, (url, got)
        assert got["simulated_reason"] == reason, (url, got)
    # local 优先于 non-HTTPS、private 优先于 non-HTTPS，reason 才能“最具体”
    assert classify_endpoint("http://127.0.0.1/v1")["simulated_reason"] == (
        "local_endpoint")
    assert classify_endpoint("http://10.0.0.5/v1")["simulated_reason"] == (
        "private_endpoint")


def test_local_http_status_is_simulated_but_transport_still_sends():
    """本地 HTTP：real_model=false/simulated=true，但默认 urllib 仍真发请求。"""
    with _local_chat_fixture() as (base_url, calls):
        provider, status = provider_from_env(_local_env(base_url),
                                             clock=FakeClock(0.01))
        assert status["transport"] == "urllib"
        assert status["endpoint_source"] == "simulated"
        assert status["simulated_reason"] == "local_endpoint"
        assert status["result_source"] == "simulated"
        assert status["real_model"] is False
        assert status["simulated"] is True
        assert status["mocked"] is False
        assert status["real_model_status"] == "ready"   # 能跑，但不是真实来源
        assert status["base_url_host"].startswith("127.0.0.1")

        out = provider({"task_id": "w4-t01", "round_no": 1,
                        "observation": {"trials": 0}})
        assert out["status"] == "ok"                    # 通路确实可用
        assert len(calls) == 1

        snapshot = provider.snapshot()
        assert snapshot["transport"] == "urllib"
        assert snapshot["endpoint_source"] == "simulated"
        assert snapshot["simulated_reason"] == "local_endpoint"
        assert snapshot["result_source"] == "simulated"
        assert snapshot["real_model"] is False
        assert snapshot["simulated"] is True
        assert snapshot["calls_ok"] == 1


def test_local_http_default_urllib_real_ab_end_to_end_is_simulated(tmp_path):
    """默认 urllib 打本地 fixture：端到端报告必须是 simulated，不是 ran/real。"""
    with _local_chat_fixture() as (base_url, calls):
        doc = run_real_ab(tasks=small_ab_tasks(), env=_local_env(base_url),
                          budget=SMALL_BUDGET, clock=FakeClock(),
                          artifacts_dir=tmp_path)

    assert calls                                   # HTTP 请求确实发出去了
    assert doc["provider_budget"]["calls_ok"] > 0  # 且调用成功
    assert doc["real_model_status"] == "simulated"
    assert doc["real_model_status"] != "ran"
    assert doc["summary_scope"] == "simulated"
    assert doc["result_source"] == "simulated"
    assert doc["transport"] == "urllib"            # transport 只说明怎么发
    assert doc["endpoint_source"] == "simulated"   # endpoint 才说明来源
    assert doc["simulated_reason"] == "local_endpoint"
    assert doc["real_model"] is False
    assert doc["simulated"] is True
    assert doc["mocked"] is False
    assert doc["summary"] is not None
    assert doc["provider_status"]["endpoint_source"] == "simulated"
    assert doc["provider_status"]["simulated_reason"] == "local_endpoint"
    assert doc["provider_status"]["result_source"] == "simulated"
    assert doc["auto_apply_allowed"] is False
    checks = {item["name"]: item["ok"] for item in doc["gate"]["checks"]}
    assert checks["read_only_simulated_provider"] is True
    assert "read_only_real_provider" not in checks

    body = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    assert '"real_model_status": "ran"' not in body
    assert '"summary_scope": "real"' not in body
    assert '"result_source": "real"' not in body

    payload = json.loads((tmp_path / "real-ab.json").read_text(encoding="utf-8"))
    assert payload["real_model_status"] == "simulated"
    assert payload["summary_scope"] == "simulated"
    assert payload["transport"] == "urllib"
    assert payload["endpoint_source"] == "simulated"
    assert payload["simulated_reason"] == "local_endpoint"
    assert payload["result_source"] == "simulated"
    markdown = (tmp_path / "real-ab.md").read_text(encoding="utf-8")
    assert "endpoint_source=simulated" in markdown
    assert "simulated_reason=local_endpoint" in markdown


def test_public_https_status_is_real_without_network_request(monkeypatch):
    """公网 HTTPS：status 直接给 real，且 status() 自身不发任何请求。"""
    def _boom(request):  # pragma: no cover - status 不应触达传输层
        raise AssertionError("status() 不应发请求")

    monkeypatch.setattr(llm_provider_mod, "_urllib_transport", _boom)
    provider, status = provider_from_env(ENV_READY, clock=FakeClock(0.01))

    assert status["transport"] == "urllib"
    assert status["endpoint_source"] == "real"
    assert status["simulated_reason"] == ""
    assert status["simulated_reasons"] == []
    assert status["result_source"] == "real"
    assert status["real_model"] is True
    assert status["simulated"] is False
    assert status["mocked"] is False
    assert status["real_model_status"] == "ready"
    assert provider.snapshot()["calls_seen"] == 0
    assert provider.snapshot()["calls_invoked"] == 0
