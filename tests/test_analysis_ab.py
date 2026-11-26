"""LLM vs 规则 A/B：无 key 可重复、有 key 只记真实 token、不伪造 LLM 数据。

这些测试全部离线：有 key 的路径用 monkeypatch 顶掉 transport，
既不会发网络请求，也不会把测试用的假 key 写进任何文件。
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

from agent.discovery import agents  # noqa: E402

import analysis_ab  # noqa: E402

FIXTURE = ROOT / "fixtures" / "discovery"
KEY_ENVS = ("DISCOVERY_LLM_API_KEY", "BDVE_LLM_API_KEY", "DEEPSEEK_API_KEY",
            "LLM_API_KEY", "OPENAI_API_KEY")
LLM_ENV_KEYS = set(agents.USAGE_TOKEN_FIELDS)


@pytest.fixture(autouse=True)
def _no_key_env(monkeypatch):
    """默认无 key：任何测试都不该意外读到宿主机的 key。"""
    for name in KEY_ENVS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)
    agents.usage_reset()
    yield
    agents.usage_reset()


def _sites(n: int = 2):
    return analysis_ab.select_sites(FIXTURE, n)["sites"]


# ---------------------------------------------------------------- 无 key
def test_no_key_llm_side_is_skipped_not_faked(tmp_path):
    payload = analysis_ab.run_ab({"fixture": FIXTURE}, out_dir=tmp_path)
    llm = payload["sides"]["fixture"]["llm"]
    heur = payload["sides"]["fixture"]["heuristic"]

    assert llm["skipped"] is True
    assert llm["skip_reason"] == "no_key"
    assert llm["llm_status"] == "no_key"
    assert llm["hypotheses"] == 0 and llm["llm_hypotheses"] == 0
    assert llm["valid_hypotheses"] == 0
    # 没有 token 就没有 token 字段，没有单价就不估算成本
    assert llm["tokens"] is None
    assert llm["cost"] is None and llm["cost_estimated"] is False

    # 规则侧照常输出，且每一条 citations 都能解析
    assert heur["hypotheses"] >= 3
    assert heur["valid_hypotheses"] == heur["hypotheses"]
    assert heur["valid_rate"] == 1.0
    assert heur["seed_count"]["total"] > 0

    assert payload["comparison"]["overall"]["verdict"] == "llm_not_run"
    assert payload["comparison"]["per_target"]["fixture"]["verdict"] == "llm_not_run"
    assert payload["environment"]["key_source_env"] is None


def test_no_key_outputs_json_and_markdown(tmp_path):
    payload = analysis_ab.run_ab({"fixture": FIXTURE}, out_dir=tmp_path)
    paths = analysis_ab.write_outputs(payload, tmp_path)
    json_path, md_path = Path(paths["json"]), Path(paths["markdown"])
    assert json_path.is_file() and md_path.is_file()

    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["schema"] == analysis_ab.SCHEMA
    assert loaded["fingerprint"] == payload["fingerprint"]

    md = md_path.read_text(encoding="utf-8")
    assert "skipped" in md and "no_key" in md
    assert "不写任何 LLM 优劣结论" in md
    assert "LLM 有优势" not in md


def test_no_key_run_is_repeatable(tmp_path):
    first = analysis_ab.run_ab({"fixture": FIXTURE}, out_dir=tmp_path / "a")
    second = analysis_ab.run_ab({"fixture": FIXTURE}, out_dir=tmp_path / "b")
    # 指纹剔除了耗时/时间戳：同样输入必须同指纹
    assert first["fingerprint"] == second["fingerprint"]
    for key in ("hypotheses", "valid_hypotheses"):
        assert (first["sides"]["fixture"]["heuristic"][key]
                == second["sides"]["fixture"]["heuristic"][key])
    assert (first["sides"]["fixture"]["heuristic"]["seed_count"]
            == second["sides"]["fixture"]["heuristic"]["seed_count"])


def test_cli_engine_without_key_does_not_run_subprocess(tmp_path):
    side = analysis_ab.run_side_cli("fixture", FIXTURE, "llm", tmp_path,
                                    max_sites=2)
    assert side["skipped"] is True and side["skip_reason"] == "no_key"
    assert side["tokens"] is None
    # 没 key 就不该启动子进程：不产生 llm 运行目录
    assert not (tmp_path / "fixture" / "llm").exists()


# ---------------------------------------------------------------- 有 key（transport 被打桩）
def _fake_post_factory(usage: dict, calls: list):
    def fake_post(prompt, cfg, timeout):
        calls.append({"key_present": bool(cfg.get("key"))})
        return {"hypothesis": "memcpy 的长度参数来自输入，可能越界写",
                "confidence": 0.8,
                "citations": ["vuln_parser.c:16"],
                "_usage": dict(usage)}
    return fake_post


def test_llm_usage_tokens_costs_recorded_without_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "sk-test-secret")
    calls = []
    usage = {"prompt_tokens": 1200, "completion_tokens": 80, "total_tokens": 1280}
    monkeypatch.setattr(agents, "_llm_post", _fake_post_factory(usage, calls))

    side = analysis_ab.run_side_inproc("fixture", FIXTURE, "llm", _sites(2),
                                       "unknown", price_input=1.0,
                                       price_output=2.0)
    assert len(calls) == 2 and all(c["key_present"] for c in calls)
    assert side["llm_hypotheses"] == 2 and side["fallback_hypotheses"] == 0
    assert side["llm_valid_hypotheses"] == 2
    assert side["tokens"] == {"prompt_tokens": 2400, "completion_tokens": 160,
                              "total_tokens": 2560}
    expected = 2400 / 1_000_000 * 1.0 + 160 / 1_000_000 * 2.0
    assert side["cost"]["total"] == pytest.approx(expected)
    assert side["cost_estimated"] is True
    assert side["cost_per_valid_hypothesis"] == pytest.approx(expected / 2)

    blob = json.dumps(side, ensure_ascii=False)
    assert "sk-test-secret" not in blob
    # prompt 原文（task 说明/源码窗口）不进指标
    assert "只读源码给出可验证的漏洞假设" not in blob
    assert "source_window" not in blob

    # 台账只保留白名单字段，且不含 key
    log = agents.usage_log()
    assert len(log) == 2
    allowed = {"kind", "ok", "attempts", "seconds", "usage", "error"}
    for entry in log:
        assert set(entry) <= allowed
        assert set(entry["usage"]) <= LLM_ENV_KEYS
        assert entry["kind"] == "analysis" and entry["ok"] is True
    assert "sk-test-secret" not in json.dumps(log, ensure_ascii=False)


def test_markdown_states_cost_when_price_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "sk-test-secret")
    monkeypatch.setattr(agents, "_llm_post",
                        _fake_post_factory({"prompt_tokens": 1000,
                                            "completion_tokens": 100,
                                            "total_tokens": 1100}, []))
    payload = analysis_ab.run_ab({"fixture": FIXTURE},
                                 out_dir=tmp_path, modes=("heuristic", "llm"),
                                 max_sites=2, price_input=1.0, price_output=1.0)
    md = analysis_ab.render_markdown(payload)
    assert "已启用成本估算" in md
    assert "sk-test-secret" not in md
    assert "sk-test-secret" not in json.dumps(payload, ensure_ascii=False)


def test_llm_failure_falls_back_and_counts_as_zero_llm_hypotheses(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "sk-test-secret")

    def boom(prompt, cfg, timeout):
        raise TimeoutError("simulated")

    monkeypatch.setattr(agents, "_llm_post", boom)
    side = analysis_ab.run_side_inproc("fixture", FIXTURE, "llm", _sites(2),
                                       "unknown")
    assert side["llm_hypotheses"] == 0
    assert side["llm_valid_hypotheses"] == 0
    assert side["fallback_hypotheses"] == 2      # 回退到规则，但不冒充 LLM 产出
    assert side["llm_status"] == "invalid_or_timeout"
    assert side["tokens"] is None                # 失败没有 token，不补零
    assert side["cost"] is None

    verdict = analysis_ab._target_verdict(
        {"mode": "heuristic", "valid_hypotheses": 2, "valid_rate": 1.0,
         "seed_count": {"total": 20}, "sites": 2}, side)
    assert verdict["verdict"] == "llm_no_output"


# ---------------------------------------------------------------- 口径函数
def test_cost_estimate_zero_price_means_not_estimated():
    tokens = {"prompt_tokens": 1_000_000, "completion_tokens": 500_000,
              "total_tokens": 1_500_000}
    assert analysis_ab.cost_estimate(tokens, 0.0, 0.0) is None
    assert analysis_ab.cost_estimate(None, 1.0, 1.0) is None
    assert analysis_ab.cost_estimate({}, 1.0, 1.0) is None
    cost = analysis_ab.cost_estimate(tokens, 1.0, 0.5)
    assert cost["input"] == pytest.approx(1.0)
    assert cost["output"] == pytest.approx(0.25)
    assert cost["total"] == pytest.approx(1.25)
    assert cost["currency"] == "USD" and cost["unit"] == "per_1m_tokens"


def test_token_fields_do_not_fabricate_zeros():
    assert analysis_ab._token_fields({"prompt_tokens": 0, "completion_tokens": 0,
                                      "total_tokens": 0}) is None
    assert analysis_ab._token_fields({}) is None
    assert analysis_ab._token_fields(None) is None


def test_validate_citations_rejects_unresolvable_refs():
    assert agents.validate_citations(["vuln_parser.c:16"], FIXTURE) is True
    assert agents.validate_citations(["vuln_parser.c:99999"], FIXTURE) is False
    assert agents.validate_citations(["../outside.c:1"], FIXTURE) is False
    assert agents.validate_citations(["vuln_parser.c"], FIXTURE) is False
    assert agents.validate_citations([], FIXTURE) is False


def test_verdict_does_not_claim_advantage_on_noise():
    heur = {"mode": "heuristic", "valid_hypotheses": 5, "valid_rate": 1.0,
            "seed_count": {"total": 50}, "sites": 5}
    llm_close = {"mode": "llm", "skipped": False, "hypotheses": 5,
                 "llm_valid_hypotheses": 5, "valid_hypotheses": 5,
                 "valid_rate": 1.0, "seed_count": {"total": 52}, "sites": 5}
    verdict = analysis_ab._target_verdict(heur, llm_close)
    assert verdict["verdict"] == "no_significant_difference"
    assert "不主张任何一侧有优势" in verdict["reason"]

    # 只有差值达到门槛、且有效率不下降时才允许写“初步信号”
    llm_higher = dict(llm_close, llm_valid_hypotheses=7, hypotheses=7,
                      sites=7, seed_count={"total": 70})
    stronger = analysis_ab._target_verdict(
        {"mode": "heuristic", "valid_hypotheses": 5, "valid_rate": 1.0,
         "seed_count": {"total": 50}, "sites": 5}, llm_higher)
    assert stronger["verdict"] == "llm_advantage"
    assert "样本量小" in stronger["reason"]


def test_usage_totals_and_delta_are_additive():
    agents.usage_reset()
    before = agents.usage_totals()
    agents.record_usage(kind="analysis", ok=True, attempts=1,
                        usage={"prompt_tokens": 10, "completion_tokens": 5},
                        seconds=0.1)
    agents.record_usage(kind="analysis", ok=False, attempts=2, seconds=0.2,
                        error="llm_call_failed")
    after = agents.usage_totals()
    delta = agents.usage_delta(before, after)
    assert delta["calls"] == 2 and delta["ok"] == 1 and delta["failed"] == 1
    assert delta["attempts"] == 3
    assert delta["prompt_tokens"] == 10 and delta["completion_tokens"] == 5
    # total 缺失时用 prompt+completion 补齐，不臆造额外字段
    assert delta["total_tokens"] == 15
