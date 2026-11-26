"""验收整改 F1–F4 回归（依据 2026-11-18 平台验收报告）。

F1 授权：文本/JSON 授权值严格解析。false/0/no/off 阻断，true/1/yes/on 放行，
  非法值拒绝（不再 `bool("false")`）；缺失声明按显式策略默认阻断。
F2 LLM：V2 假设集默认优先 LLM、无配置明确回退规则、`--no-llm` 显式关闭，
  与 Discovery 默认一致；用 mock 验证调用/回退/不调用，不花真实 token。
F3 主页统计：通过数取 benchmark_verified，按赛道分列（CG 双端 / EG flag /
  VG 行为），CG 双端单列保留，撤回案例分母明示。
F4 恢复：preflight 接受 BLOCKED 重试，保留旧事件，重跑检查再决定 READY/BLOCKED。

所有测试只用临时库/临时目录；LLM 场景一律 monkeypatch，不联网。
"""
from __future__ import annotations

import json
import shutil
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.discovery import agents as discovery_agents
from agent.platform import (EventBus, PlatformStore, TaskSpec, run_hypotheses,
                            run_preflight, run_understand)
from agent.platform import authorization, hypotheses as hyp_mod
from agent.platform.hypotheses import propose, resolve_llm_mode
from agent.platform.program import ProgramIndex

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "platform.py"
FIXTURE = ROOT / "fixtures" / "discovery"
PAGE = ROOT / "vulnmap_platform" / "static" / "index.html"
LEDGER = ROOT / "experiments" / "LEDGER.json"

LLM_ENV_KEYS = ("DISCOVERY_LLM_API_KEY", "BDVE_LLM_API_KEY", "DEEPSEEK_API_KEY",
                "LLM_API_KEY", "OPENAI_API_KEY")


# ------------------------------------------------------------------ helpers
def _run(*args: str, db: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), "--db", str(db), *args],
                          cwd=str(ROOT), capture_output=True, text=True)


def _task(benchmark: str = "target_yaml", target: Path | None = None,
          task_id: str = "acc-1", metadata: dict | None = None,
          state: str = "RECEIVED") -> dict:
    return {"task_id": task_id, "benchmark": benchmark,
            "target": str(target or FIXTURE), "metadata": metadata or {},
            "state": state}


def _store_with(tmp_path: Path, metadata: dict | None = None,
                target: Path | None = None, task_id: str = "acc-1",
                name: str = "acc.db") -> tuple[PlatformStore, EventBus]:
    store = PlatformStore(tmp_path / name)
    spec = TaskSpec(task_id=task_id, benchmark="target_yaml",
                    target=str(target or FIXTURE), metadata=dict(metadata or {}))
    store.create_task(spec)
    bus = EventBus(store)
    bus.emit(task_id, "task.created", stage="RECEIVED", payload=spec.to_dict())
    return store, bus


@pytest.fixture()
def client(monkeypatch, tmp_path):
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    root = tmp_path / "platform"
    root.mkdir()
    monkeypatch.setenv("PLATFORM_ROOT", str(root))
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


# ================================================================== F1 授权
@pytest.mark.parametrize("value", ["true", "TRUE", "True", " 1 ", "yes", "YES",
                                   "on", "On", " true "])
def test_f1_true_text_forms_allow(value):
    assert authorization.parse_authorized(value) is True


@pytest.mark.parametrize("value", ["false", "FALSE", "False", " 0 ", "no", "NO",
                                   "off", "Off", " false "])
def test_f1_false_text_forms_block(value):
    assert authorization.parse_authorized(value) is False


@pytest.mark.parametrize("value", ["maybe", "enabled", "", "  ", "2", "-1",
                                   "tru", "nope", "yes please"])
def test_f1_illegal_text_rejected(value):
    with pytest.raises(authorization.AuthorizationError):
        authorization.parse_authorized(value)


@pytest.mark.parametrize("value", [None, 2, -1, 1.0, [], {}, ["true"]])
def test_f1_illegal_types_rejected(value):
    with pytest.raises(authorization.AuthorizationError):
        authorization.parse_authorized(value)


def test_f1_bool_of_string_is_never_used():
    """根因回归：非空字符串恒为真，`bool("false")` 不能再被当成授权判据。"""
    assert bool("false") is True
    assert authorization.parse_authorized("false") is False


def test_f1_missing_policy_is_explicit_block():
    assert authorization.MISSING_POLICY == "block"
    res = authorization.resolve({})
    assert res["present"] is False and res["ok"] is False
    assert res["reason"] == "missing" and res["policy"] == "block"


def test_f1_task_spec_normalizes_text_metadata():
    spec = TaskSpec("norm-1", "target_yaml", str(FIXTURE),
                    metadata={"authorized": "false", "image_vul": "x"})
    assert spec.metadata["authorized"] is False, "字符串 false 不能原样落库"
    spec = TaskSpec("norm-2", "target_yaml", str(FIXTURE),
                    metadata={"authorized": " YES "})
    assert spec.metadata["authorized"] is True
    with pytest.raises(Exception):
        TaskSpec("norm-3", "target_yaml", str(FIXTURE),
                 metadata={"authorized": "maybe"})


def test_f1_preflight_blocks_string_false(tmp_path):
    store, bus = _store_with(tmp_path)  # 无授权声明
    with pytest.raises(Exception):
        # 非法值在提交层就被拒；这里直接改库模拟历史脏数据
        TaskSpec("acc-1", "target_yaml", str(FIXTURE),
                 metadata={"authorized": "maybe"})
    con = sqlite3.connect(tmp_path / "acc.db")
    con.execute("update tasks set metadata_json=? where task_id=?",
                (json.dumps({"authorized": "false"}), "acc-1"))
    con.commit()
    con.close()
    out = run_preflight("acc-1", store, bus)
    assert out["state"] == "BLOCKED"
    assert "authorized" in out["blockers"]
    check = next(c for c in out["checks"] if c["name"] == "authorized")
    assert check["declared"] is False and check["reason"] == "false"
    assert store.get_task("acc-1")["state"] == "BLOCKED"


def test_f1_preflight_blocks_missing_authorization(tmp_path):
    store, bus = _store_with(tmp_path)
    out = run_preflight("acc-1", store, bus)
    assert out["state"] == "BLOCKED"
    check = next(c for c in out["checks"] if c["name"] == "authorized")
    assert check["reason"] == "missing" and check["policy"] == "block"


def test_f1_preflight_allows_declared_true(tmp_path):
    store, bus = _store_with(tmp_path, metadata={"authorized": "true"})
    out = run_preflight("acc-1", store, bus)
    assert out["state"] == "READY", out


# ------------------------------------------------------- F1 CLI / API 回归
def test_f1_cli_string_false_is_blocked(tmp_path):
    db = tmp_path / "cli.db"
    target = tmp_path / "target"
    target.mkdir()
    p = _run("submit", "--benchmark", "target_yaml", "--target", str(target),
             "--task-id", "cli-false", "--meta", "authorized=false", db=db)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["metadata"]["authorized"] is False

    p = _run("preflight", "cli-false", db=db)
    assert p.returncode == 1, p.stdout + p.stderr
    out = json.loads(p.stdout)
    assert out["state"] == "BLOCKED" and "authorized" in out["blockers"]


@pytest.mark.parametrize("text", ["true", "1", "yes", "on"])
def test_f1_cli_text_true_is_ready(tmp_path, text):
    db = tmp_path / "cli.db"
    target = tmp_path / "target"
    target.mkdir()
    assert _run("submit", "--benchmark", "target_yaml", "--target", str(target),
                "--task-id", "cli-t", "--meta", f"authorized={text}",
                db=db).returncode == 0
    p = _run("preflight", "cli-t", db=db)
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(p.stdout)["state"] == "READY"


@pytest.mark.parametrize("text", ["maybe", "enabled", "2"])
def test_f1_cli_illegal_value_rejected_at_submit(tmp_path, text):
    db = tmp_path / "cli.db"
    target = tmp_path / "target"
    target.mkdir()
    p = _run("submit", "--benchmark", "target_yaml", "--target", str(target),
             "--task-id", "cli-bad", "--meta", f"authorized={text}", db=db)
    assert p.returncode == 2, p.stdout
    assert "authorized" in p.stderr
    # 被拒的提交不落库：preflight 找不到任务
    assert _run("preflight", "cli-bad", db=db).returncode == 2


def test_f1_cli_missing_authorization_blocks(tmp_path):
    db = tmp_path / "cli.db"
    target = tmp_path / "target"
    target.mkdir()
    assert _run("submit", "--benchmark", "target_yaml", "--target", str(target),
                "--task-id", "cli-none", "--meta", "note=none", db=db).returncode == 0
    p = _run("preflight", "cli-none", db=db)
    assert p.returncode == 1
    out = json.loads(p.stdout)
    assert out["state"] == "BLOCKED" and out["policy"] == "block"


def test_f1_api_text_metadata_is_strict(client, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    body = {"benchmark": "target_yaml", "target": str(target),
            "task_id": "api-false", "metadata": ["authorized=false"]}
    r = client.post("/api/platform/tasks", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["task"]["metadata"]["authorized"] is False
    out = client.post("/api/platform/tasks/api-false/preflight").json()
    assert out["state"] == "BLOCKED" and "authorized" in out["blockers"]

    ok = {"benchmark": "target_yaml", "target": str(target),
          "task_id": "api-true", "metadata": {"authorized": "on"}}
    assert client.post("/api/platform/tasks", json=ok).status_code == 201
    assert client.post("/api/platform/tasks/api-true/preflight").json()["state"] == "READY"

    bad = {"benchmark": "target_yaml", "target": str(target),
           "task_id": "api-bad", "metadata": {"authorized": "maybe"}}
    r = client.post("/api/platform/tasks", json=bad)
    assert r.status_code == 400 and "authorized" in r.json()["detail"]

    missing = {"benchmark": "target_yaml", "target": str(target),
               "task_id": "api-missing", "metadata": {"note": "n/a"}}
    assert client.post("/api/platform/tasks", json=missing).status_code == 201
    out = client.post("/api/platform/tasks/api-missing/preflight").json()
    assert out["state"] == "BLOCKED"
    check = next(c for c in out["checks"] if c["name"] == "authorized")
    assert check["reason"] == "missing"


# ================================================================== F2 LLM
def _index() -> ProgramIndex:
    return ProgramIndex.build(_task())


def _configure_mock_llm(monkeypatch, calls: list) -> None:
    """有配置 + mock 调用点分析：只记录调用，不联网、不花 token。"""
    for name in LLM_ENV_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "unit-test-key")
    monkeypatch.setenv("DISCOVERY_LLM_MODEL", "mock-model")

    def fake_analyze(site, source_root, timeout=None):  # noqa: ANN001
        calls.append({"file": site.get("file"), "line": site.get("line"),
                      "callee": site.get("callee")})
        return {"hypothesis": f"{site.get('callee')} 的参数长度可能未校验（mock）",
                "confidence": 0.66,
                "citations": [f"{site.get('file')}:{site.get('line')}"]}

    monkeypatch.setattr(hyp_mod.agents, "llm_analyze", fake_analyze)


def _drop_llm_config(monkeypatch) -> None:
    for name in LLM_ENV_KEYS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)


def test_f2_default_is_auto_and_matches_discovery():
    """V2 默认(auto)必须与 Discovery/D1.5 的默认(use_llm=True)同向。"""
    assert resolve_llm_mode(None) == (True, "auto")
    default = discovery_agents.analyze_site.__defaults__
    assert default is not None and default[0] is True, (
        "Discovery analyze_site 默认应启用 LLM；V2 默认必须与之一致")


def test_f2_configured_default_calls_llm(monkeypatch):
    calls: list = []
    _configure_mock_llm(monkeypatch, calls)
    index = _index()
    assert hyp_mod.agents.llm_configured() is True
    items = propose(index, root=index.root)  # 不传 use_llm = 默认 auto
    assert calls, "有配置时默认必须调用 LLM"
    assert any(h["source"].startswith("llm:mock-model") for h in items)
    assert any(h.get("llm") is True for h in items)


def test_f2_no_config_falls_back_to_rule(monkeypatch):
    _drop_llm_config(monkeypatch)
    hits: list = []

    real_connect = socket.socket.connect

    def no_network(self, address):  # noqa: ANN001
        hits.append(address)
        raise AssertionError("无 key 时不得发起任何网络连接")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    index = _index()
    assert hyp_mod.agents.llm_configured() is False
    items = propose(index, root=index.root)
    monkeypatch.setattr(socket.socket, "connect", real_connect)
    assert hits == [], "无配置不得联网"
    assert items and all(h["source"].startswith("rule:") for h in items)
    assert all(h["llm"] is False for h in items)
    assert all(h["llm_status"] == "no_key" for h in items), (
        "无配置要明确回退：记录 no_key 而不是假装 disabled")


def test_f2_explicit_off_never_calls(monkeypatch):
    calls: list = []
    _configure_mock_llm(monkeypatch, calls)
    index = _index()
    items = propose(index, root=index.root, use_llm=False)
    assert calls == [], "use_llm=False 必须一次都不调用"
    assert all(h["source"].startswith("rule:") for h in items)


def test_f2_run_hypotheses_records_mode(monkeypatch, tmp_path):
    calls: list = []
    _configure_mock_llm(monkeypatch, calls)
    store, bus = _store_with(tmp_path, metadata={"authorized": True},
                             task_id="f2-auto", name="f2.db")
    assert run_preflight("f2-auto", store, bus)["state"] == "READY"
    assert run_understand("f2-auto", store, bus)["state"] == "UNDERSTANDING"
    out = run_hypotheses("f2-auto", store, bus)
    assert calls and out["llm"] is True and out["llm_mode"] == "auto"
    payload = [e for e in bus.list("f2-auto")
               if e["event_type"] == "hypothesis.proposed"][0]["payload"]
    assert payload["llm_mode"] == "auto" and payload["llm"] is True


def test_f2_cli_default_auto_and_no_llm_flag(tmp_path):
    db = tmp_path / "cli.db"
    env_backup = {}
    for name in LLM_ENV_KEYS + ("DISCOVERY_LLM_DISABLED", "VULNMAP_DISABLE_LLM"):
        env_backup[name] = None
    base = {k: v for k, v in __import__("os").environ.items()
            if k not in LLM_ENV_KEYS}
    for name in ("DISCOVERY_LLM_DISABLED", "VULNMAP_DISABLE_LLM"):
        base.pop(name, None)

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(BIN), "--db", str(db), *args],
                              cwd=str(ROOT), capture_output=True, text=True,
                              env=base)

    for task_id in ("cli-auto", "cli-off"):
        assert run("submit", "--benchmark", "target_yaml",
                   "--target", str(FIXTURE), "--task-id", task_id,
                   "--meta", "authorized=true").returncode == 0
        assert run("preflight", task_id).returncode == 0
        assert run("understand", task_id).returncode == 0

    p = run("hypotheses", "cli-auto")
    assert p.returncode == 0, p.stderr
    auto = json.loads(p.stdout)
    assert auto["llm_mode"] == "auto" and auto["llm"] is True
    assert all(h["source"].startswith("rule:") for h in auto["hypotheses"]), (
        "无 key 时 auto 必须回退规则")
    assert all(h["llm_status"] == "no_key" for h in auto["hypotheses"])

    p = run("hypotheses", "cli-off", "--no-llm")
    assert p.returncode == 0, p.stderr
    off = json.loads(p.stdout)
    assert off["llm_mode"] == "off" and off["llm"] is False
    assert all(h["llm_status"] == "disabled" for h in off["hypotheses"])

    # --llm 与 --no-llm 互斥（参数层拒绝，不静默挑一个）
    both = run("hypotheses", "cli-off", "--llm", "--no-llm")
    assert both.returncode != 0


# ================================================================== F3 主页
def test_f3_cases_api_exposes_per_benchmark_verdict(client):
    items = client.get("/api/cases").json()["items"]
    for item in items:
        assert {"benchmark_verified", "benchmark_criterion",
                "exploit_flag_issued", "local_verified"} <= set(item)
    led = json.loads(LEDGER.read_text(encoding="utf-8"))
    expect = sum(1 for r in led["rows"] if r.get("benchmark_verified"))
    assert sum(1 for i in items if i["benchmark_verified"]) == expect, (
        "benchmark_verified 统计必须与台账逐例一致")


def test_f3_criteria_are_per_benchmark(client):
    items = client.get("/api/cases").json()["items"]
    kinds = {i["benchmark"]: i["benchmark_criterion"] for i in items}
    assert kinds["cybergym"] == "vuln_fix_diff"
    assert kinds["exploitgym"] == "exploit_flag"
    assert kinds["vulngym"] == "behavior_diff"
    eg = [i for i in items if i["benchmark"] == "exploitgym"]
    assert any(i["benchmark_verified"] and not i["local_verified"] for i in eg), (
        "ExploitGym 的通过不能依赖 CG 的双端字段")


def test_f3_page_uses_benchmark_verified():
    text = PAGE.read_text(encoding="utf-8")
    assert "benchmark_verified" in text
    assert "local_verified)" not in text.split("function benchTable")[0].split(
        "function benchStats")[1], "benchStats 不能再用 local_verified 当通过判据"
    for label in ("CG 双端", "EG flag", "VG 行为"):
        assert label in text, f"缺少分赛道列：{label}"
    assert "撤回" in text and "分母" in text, "撤回案例的分母口径必须写明"


def test_f3_stat_keys_use_benchmark_verified():
    import re
    text = PAGE.read_text(encoding="utf-8")
    m = re.search(r'<script id="stat-keys" type="application/json">(.+?)</script>',
                  text, re.S)
    assert m
    spec = json.loads(m.group(1))
    keys = {(g, k) for _, g, k in spec}
    assert ("ledger_totals", "benchmark_verified") in keys
    assert ("ledger_totals", "local_dual_run_pass") in keys, "CG 双端必须单列保留"
    assert ("stats", "ledger_cases") in keys


NODE_BENCH_ITEMS = [
    {"benchmark": "cybergym", "local_verified": True, "benchmark_verified": True,
     "exploit_flag_issued": False, "verdict": "pass",
     "causal_chain_verified": True, "high_severity_confirmed": True},
    {"benchmark": "cybergym", "local_verified": False, "benchmark_verified": False,
     "exploit_flag_issued": False, "verdict": "generated_but_unverified",
     "causal_chain_verified": False, "high_severity_confirmed": False},
    # 关键样例：local_verified=false 但按 EG 判据 benchmark_verified=true（旧口径会漏算）
    {"benchmark": "exploitgym", "local_verified": False, "benchmark_verified": True,
     "exploit_flag_issued": True, "verdict": "pass",
     "causal_chain_verified": False, "high_severity_confirmed": True},
    {"benchmark": "exploitgym", "local_verified": False, "benchmark_verified": False,
     "exploit_flag_issued": False, "verdict": "withdrawn",
     "causal_chain_verified": False, "high_severity_confirmed": False},
    {"benchmark": "vulngym", "local_verified": True, "benchmark_verified": True,
     "exploit_flag_issued": False, "verdict": "pass",
     "causal_chain_verified": False, "high_severity_confirmed": True},
]


@pytest.mark.skipif(shutil.which("node") is None, reason="node 不在 PATH")
def test_f3_benchstats_behaviour_in_node(tmp_path):
    """把页面里的 benchStats 抽出来在 node 里跑：通过数按 benchmark_verified 计。"""
    text = PAGE.read_text(encoding="utf-8")
    start = text.index("const BENCH_CRITERION")
    end = text.index("const cell =")
    chunk = text[start:end]
    harness = tmp_path / "benchstats.js"
    harness.write_text(
        "const BENCH_LABEL={cybergym:'CyberGym',exploitgym:'ExploitGym',"
        "vulngym:'VulnGym'};\n"
        "const pct=(n,d)=>d?Math.round(n/d*100):0;\n" + chunk +
        "const items=" + json.dumps(NODE_BENCH_ITEMS, ensure_ascii=False) + ";\n"
        "console.log(JSON.stringify(benchStats(items)));\n", encoding="utf-8")
    out = subprocess.run(["node", str(harness)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    stats = {b["key"]: b for b in json.loads(out.stdout)}

    cg, eg, vg = stats["cybergym"], stats["exploitgym"], stats["vulngym"]
    assert (cg["n"], cg["verified"], cg["dual"]) == (2, 1, 1)
    assert (cg["flag"], cg["behavior"]) == (None, None), "非本赛道指标必须留空"
    assert (eg["n"], eg["verified"], eg["flag"], eg["withdrawn"]) == (2, 1, 1, 1)
    assert eg["dual"] is None
    assert (vg["n"], vg["verified"], vg["behavior"]) == (1, 1, 1)
    assert cg["verified"] + eg["verified"] + vg["verified"] == 3
    assert cg["failed"] + eg["failed"] + vg["failed"] == 2


# =============================================================== F4 恢复入口
def test_f4_preflight_retry_after_material_provided(tmp_path):
    target = tmp_path / "late-target"  # 先不存在
    store, bus = _store_with(tmp_path, metadata={"authorized": True},
                             target=target, task_id="f4-1", name="f4.db")

    first = run_preflight("f4-1", store, bus)
    assert first["state"] == "BLOCKED" and first["retry"] is False
    assert "target_path" in first["blockers"]
    events_before = bus.list("f4-1")
    failed = [e for e in events_before if e["event_type"] == "preflight.failed"]
    assert failed and failed[0]["stage"] == "BLOCKED"

    target.mkdir()  # 补齐材料
    second = run_preflight("f4-1", store, bus)
    assert second["state"] == "READY", second
    assert second["retry"] is True and second["previous_state"] == "BLOCKED"

    events = bus.list("f4-1")
    assert len(events) > len(events_before), "重试必须追加事件"
    assert [e["seq"] for e in events] == [e["seq"] for e in events_before] + [
        e["seq"] for e in events[len(events_before):]], "旧事件不得被改写/删除"
    types = [e["event_type"] for e in events]
    assert types[0] == "task.created"
    assert "preflight.failed" in types and "preflight.passed" in types

    replay = bus.replay("f4-1")
    assert replay["state"] == "READY"
    assert [t["to"] for t in replay["transitions"]] == [
        "PREFLIGHT", "BLOCKED", "PREFLIGHT", "READY"]
    assert bus.replay("f4-1") == replay, "事件重放在重试后必须稳定"


def test_f4_retry_while_still_blocked_keeps_appending(tmp_path):
    store, bus = _store_with(tmp_path, metadata={"authorized": True},
                             target=tmp_path / "still-missing",
                             task_id="f4-2", name="f4b.db")
    assert run_preflight("f4-2", store, bus)["state"] == "BLOCKED"
    again = run_preflight("f4-2", store, bus)
    assert again["state"] == "BLOCKED" and again["retry"] is True
    replay = bus.replay("f4-2")
    assert [t["to"] for t in replay["transitions"]] == [
        "PREFLIGHT", "BLOCKED", "PREFLIGHT", "BLOCKED"]


def test_f4_retry_rejects_ready_state(tmp_path):
    store, bus = _store_with(tmp_path, metadata={"authorized": True},
                             task_id="f4-3", name="f4c.db")
    assert run_preflight("f4-3", store, bus)["state"] == "READY"
    with pytest.raises(ValueError):
        run_preflight("f4-3", store, bus)


def test_f4_cli_retry_end_to_end(tmp_path):
    db = tmp_path / "cli.db"
    target = tmp_path / "cli-target"
    assert _run("submit", "--benchmark", "target_yaml", "--target", str(target),
                "--task-id", "cli-retry", "--meta", "authorized=true",
                db=db).returncode == 0
    first = _run("preflight", "cli-retry", db=db)
    assert first.returncode == 1
    assert json.loads(first.stdout)["state"] == "BLOCKED"

    target.mkdir()
    second = _run("preflight", "cli-retry", db=db)
    assert second.returncode == 0, second.stdout + second.stderr
    assert json.loads(second.stdout)["state"] == "READY"

    status = json.loads(_run("status", "cli-retry", db=db).stdout)
    assert status["task"]["state"] == "READY"
    assert [t["to"] for t in status["replay"]["transitions"]] == [
        "PREFLIGHT", "BLOCKED", "PREFLIGHT", "READY"]
    assert status["events"] >= 5


def test_f4_api_retry_end_to_end(client, tmp_path):
    target = tmp_path / "api-target"
    body = {"benchmark": "target_yaml", "target": str(target),
            "task_id": "api-retry", "metadata": {"authorized": True}}
    assert client.post("/api/platform/tasks", json=body).status_code == 201
    first = client.post("/api/platform/tasks/api-retry/preflight")
    assert first.status_code == 200
    assert first.json()["state"] == "BLOCKED"

    target.mkdir()
    second = client.post("/api/platform/tasks/api-retry/preflight")
    assert second.status_code == 200
    out = second.json()
    assert out["state"] == "READY" and out["retry"] is True

    detail = client.get("/api/platform/tasks/api-retry").json()
    assert detail["state"] == "READY"
    assert [t["to"] for t in detail["timeline"]] == [
        "PREFLIGHT", "BLOCKED", "PREFLIGHT", "READY"]
    types = [e["event_type"] for e in client.get(
        "/api/platform/tasks/api-retry/events").json()["items"]]
    assert types.count("preflight.failed") == 1
    assert types.count("preflight.passed") == 1
