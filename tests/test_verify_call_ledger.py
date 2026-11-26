"""课程验证入口的逐调用账本：四个验收场景。

被测对象是**真实入口**：agent/llm.py 的 call_json —— VerifyStage 的模型闭环
（run_diverse_loop 里的 call_llm）就是调它。这里不构造旁路，而是用
本地 HTTP fixture 当"模型服务"，验证记录链本身：

1. 正常调用能按 (run_id, call_id) 关联，且 sent 值与 mock 服务捕获的请求体一致；
2. 预算拒绝不产生网络请求，账本落 refused_before_send；
3. 同一任务连续两次运行不串账（call_id 各自从 0001 起，run_id 不同）；
4. 账本不可写时，完整性判定必须是 incomplete，不能被当成证据齐全。
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import llm as llm_mod                       # noqa: E402
from agent.budget import BudgetExhausted, GlobalModelBudget  # noqa: E402


class _Mock:
    """本地 chat/completions 替身；记录每次真实到达的请求体。"""

    def __init__(self, body: dict | None = None):
        self.requests: list = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                outer.requests.append({"headers": dict(self.headers),
                                       "raw": raw,
                                       "body": json.loads(raw)})
                payload = dict(body or {
                    "model": "mock-model",
                    "choices": [{"message": {"content": '{"ok":true}'},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                              "total_tokens": 18},
                })
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d/v1" % self.server.server_address[1]


def _config(url: str):
    return llm_mod.LlmConfig(base_url=url, model="mock-model",
                             api_key="sk-test-not-real", temperature=0.0,
                             max_tokens=321, max_retries=0)


def _read_ledger(path: Path) -> list:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


@pytest.fixture()
def ledger_env(tmp_path, monkeypatch):
    path = tmp_path / "calls.jsonl"
    monkeypatch.setenv("VULNMAP_LLM_LEDGER", str(path))
    monkeypatch.delenv("VULNMAP_CALL_LEDGER", raising=False)
    return path


# ---------------------------------------------------------------- 场景 1
def test_normal_call_records_sent_values_and_links_by_run_id(ledger_env):
    with _Mock() as mock:
        token = llm_mod.set_run_context("r-test-0001", "verify", workspace="/tmp/ws")
        try:
            res = llm_mod.call_json(_config(mock.url), system="s", user="u",
                                    prompt_version="verify-llm-loop-p5")
        finally:
            llm_mod.reset_run_context(token)

    assert res.ok and res.status == "ok"
    assert len(mock.requests) == 1

    rows = _read_ledger(ledger_env)
    assert len(rows) == 1
    row = rows[0]
    assert row["run_id"] == "r-test-0001"
    assert row["stage"] == "verify"
    assert row["call_id"] == "call-0001"
    assert row["call_key"] == "r-test-0001::call-0001"
    assert row["call_state"] == "sent"
    assert row["prompt_version"] == "verify-llm-loop-p5"

    received = mock.requests[0]["body"]
    assert row["params_sent"]["model"] == received["model"]
    assert row["params_sent"]["temperature"] == received["temperature"]
    assert row["params_sent"]["max_tokens"] == received["max_tokens"]
    assert row["params_sent"]["response_format"] == received["response_format"]

    assert row["params_not_sent"]["top_p"] == "absent_by_design"
    assert row["params_not_sent"]["seed"] == "absent_by_design"
    assert row["params_missing"] == {}

    assert row["request_sha256"] == hashlib.sha256(
        mock.requests[0]["raw"]).hexdigest()
    assert row["response_sha256"] and len(row["response_sha256"]) == 64
    assert row["usage"]["state"] == "sent"
    assert row["usage"]["total_tokens"] == 18

    text = ledger_env.read_text(encoding="utf-8")
    assert "sk-test-not-real" not in text
    assert "authorization" not in text.lower()
    assert "bearer" not in text.lower()

    summary = llm_mod.ledger_summary("r-test-0001", "verify")
    assert summary["status"] == "complete"
    assert summary["sent"] == 1 and summary["with_request_hash"] == 1


# ---------------------------------------------------------------- 场景 2
def test_budget_refusal_writes_no_request(ledger_env):
    guard = GlobalModelBudget(max_requests=0)
    llm_mod.set_global_budget(guard)
    try:
        with _Mock() as mock:
            token = llm_mod.set_run_context("r-budget", "verify")
            try:
                with pytest.raises(BudgetExhausted):
                    llm_mod.call_json(_config(mock.url), system="s", user="u",
                                      prompt_version="verify-llm-loop-p5")
            finally:
                llm_mod.reset_run_context(token)
            assert mock.requests == [], "预算拒绝不得产生任何网络请求"

        rows = _read_ledger(ledger_env)
        assert len(rows) == 1
        row = rows[0]
        assert row["call_state"] == "refused_before_send"
        assert row["refusal"] == "BudgetExhausted"
        assert row["request_sha256"] == ""
        assert row["params_missing"]["model"] == "request_not_built"

        summary = llm_mod.ledger_summary("r-budget", "verify")
        assert summary["refused"] == 1 and summary["sent"] == 0
    finally:
        llm_mod.set_global_budget(None)


# ---------------------------------------------------------------- 场景 3
def test_two_runs_do_not_mix(ledger_env):
    with _Mock() as mock:
        for run_id in ("r-run-a", "r-run-b"):
            token = llm_mod.set_run_context(run_id, "verify")
            try:
                llm_mod.call_json(_config(mock.url), system="s", user="u",
                                  prompt_version="p5")
                llm_mod.call_json(_config(mock.url), system="s", user="u",
                                  prompt_version="p5")
            finally:
                llm_mod.reset_run_context(token)

    rows = _read_ledger(ledger_env)
    assert len(rows) == 4
    a = [r for r in rows if r["run_id"] == "r-run-a"]
    b = [r for r in rows if r["run_id"] == "r-run-b"]
    assert [r["call_id"] for r in a] == ["call-0001", "call-0002"]
    assert [r["call_id"] for r in b] == ["call-0001", "call-0002"]

    assert llm_mod.ledger_summary("r-run-a", "verify")["sent"] == 2
    assert llm_mod.ledger_summary("r-run-b", "verify")["sent"] == 2
    assert llm_mod.ledger_summary("r-missing", "verify")["status"] == "incomplete"


# ---------------------------------------------------------------- 场景 4
def test_unwritable_ledger_is_incomplete_not_complete(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("VULNMAP_LLM_LEDGER", str(blocker / "calls.jsonl"))
    monkeypatch.delenv("VULNMAP_CALL_LEDGER", raising=False)

    with _Mock() as mock:
        token = llm_mod.set_run_context("r-unwritable", "verify")
        try:
            res = llm_mod.call_json(_config(mock.url), system="s", user="u",
                                    prompt_version="p5")
        finally:
            llm_mod.reset_run_context(token)

    assert res.ok
    assert res.ledger["written"] is False
    assert res.ledger["error"]

    summary = llm_mod.ledger_summary("r-unwritable", "verify")
    assert summary["status"] in ("incomplete", "not_recorded")
    assert summary["status"] != "complete"

# ---------------------------------------------------------------- 场景 4b
def test_param_evidence_never_reports_complete_without_rows(tmp_path, monkeypatch):
    """VerifyStage 的参数证据判定：没行/写失败都不能报 complete。"""
    from agent.stages.verify import VerifyStage

    class Shim:
        run_id = "r-evidence"
        name = "verify"

    monkeypatch.delenv("VULNMAP_LLM_LEDGER", raising=False)
    monkeypatch.delenv("VULNMAP_CALL_LEDGER", raising=False)
    disabled = VerifyStage._param_evidence(Shim(), 2)
    assert disabled["status"] == "not_recorded"
    assert disabled["reason"] == "ledger_disabled"

    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("VULNMAP_LLM_LEDGER", str(blocker / "x.jsonl"))
    unwritable = VerifyStage._param_evidence(Shim(), 2)
    assert unwritable["status"] != "complete"

    good = tmp_path / "good.jsonl"
    monkeypatch.setenv("VULNMAP_LLM_LEDGER", str(good))
    with _Mock() as mock:
        token = llm_mod.set_run_context("r-evidence", "verify")
        try:
            llm_mod.call_json(_config(mock.url), system="s", user="u",
                              prompt_version="p5")
        finally:
            llm_mod.reset_run_context(token)
    complete = VerifyStage._param_evidence(Shim(), 1)
    assert complete["status"] == "complete"
    assert complete["sent"] == 1
    assert complete["call_key_prefix"] == "r-evidence::"

    # 有闭环轮次但账本里没有本 run 的行 -> 不能算齐全
    monkeypatch.setenv("VULNMAP_LLM_LEDGER", str(tmp_path / "empty.jsonl"))
    no_rows = VerifyStage._param_evidence(Shim(), 3)
    assert no_rows["status"] == "incomplete"
    assert no_rows["reason"] == "no_rows_for_run"
