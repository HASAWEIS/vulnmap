"""LLM 客户端：参数可审计、三种"未完成"必须判失败、模型输出必须校验。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import agent.llm as llm


def test_params_are_recorded_without_key():
    cfg = llm.LlmConfig(api_key="sk-secret", model="m1")
    p = cfg.public_params()
    assert "api_key" not in p
    assert p["model"] == "m1" and p["response_format"] == "json_object"


def test_request_body_disables_thinking_by_default():
    cfg = llm.LlmConfig(api_key="k")
    body = cfg.request_body("s", "u")
    assert body["thinking"] == {"type": "disabled"}
    assert body["response_format"] == {"type": "json_object"}


def test_missing_key_fails_without_network():
    r = llm.call_json(llm.LlmConfig(api_key=""), system="s", user="u",
                      prompt_version="pv1")
    assert r.status == "failed" and r.error == "no_api_key"


def test_record_has_structured_fields():
    r = llm.LlmResult(status="ok", model="m", prompt_version="pv", tokens=10,
                      prompt_tokens=6, completion_tokens=4, finish_reason="stop")
    rec = r.to_record(role="locate", params={"model": "m"}, accepted=True, added=["f"])
    for key in ("role", "status", "model", "prompt_version", "tokens",
                "prompt_tokens", "completion_tokens", "finish_reason",
                "params", "accepted", "added"):
        assert key in rec
    assert rec["tokens"] == 10 and rec["added"] == ["f"]
