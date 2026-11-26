"""V2 P1 验收：ProgramIndex / 假设集 / SQLite 迁移 / CLI 状态机 / 事件回放。

口径：
- ProgramIndex 只做静态理解，不执行目标；
- 假设集硬上限 8、字段完整、不得夹带 verdict；
- 迁移幂等：P0 表与数据原样保留；
- CLI：READY→UNDERSTANDING→HYPOTHESES，非法迁移拒绝，事件可回放。
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from agent.platform import (EventBus, HypothesisError, MAX_HYPOTHESES,
                            PlatformStore, ProgramIndex, TaskSpec, propose,
                            run_hypotheses, run_preflight, run_understand,
                            validate_hypotheses)
from agent.platform.hypotheses import contains_verdict
from agent.platform.store import SCHEMA

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "platform.py"
FIXTURE = ROOT / "fixtures" / "discovery"
CG01 = ROOT / "workspace" / "CG-01-arvo-44034"
VG01 = ROOT / "workspace" / "VG-01-nltk-wordnet"

REQUIRED = ("id", "statement", "falsifiable_by", "evidence_gap", "cost",
            "confidence", "source")


def _task(benchmark: str, target, task_id: str = "task-p1", metadata=None) -> dict:
    return {"task_id": task_id, "benchmark": benchmark, "target": str(target),
            "metadata": metadata or {}}


def _prepared(tmp_path, benchmark: str, target, task_id: str = "task-p1",
              metadata=None):
    store = PlatformStore(tmp_path / "p.db")
    # F1：缺失授权默认阻断，夹具显式声明
    spec = TaskSpec(task_id=task_id, benchmark=benchmark, target=str(target),
                    metadata={"authorized": True, **(metadata or {})})
    store.create_task(spec)
    bus = EventBus(store)
    out = run_preflight(task_id, store, bus)
    assert out["state"] == "READY", out
    return store, bus


def _run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), *args], cwd=str(cwd),
                          capture_output=True, text=True)


# ---------------------------------------------------------------- ProgramIndex
def test_fixture_program_index_contract():
    index = ProgramIndex.build(_task("target_yaml", FIXTURE))
    index.validate()
    doc = index.to_dict()

    assert doc["schema"] == "vulnmap.program_index.v1"
    assert doc["benchmark"] == "target_yaml"
    assert doc["source_count"] == 1
    assert doc["sources"] == ["vuln_parser.c"]
    assert doc["functions"], "D0 函数识别结果不能为空"
    assert {f["name"] for f in doc["functions"]} >= {"main", "parse_record", "parse_meta"}
    assert [e["kind"] for e in doc["entry_points"]] == ["main"]
    assert doc["entry_points"][0]["file"] == "vuln_parser.c"

    callees = {s["callee"] for s in doc["call_sites"]}
    assert {"memcpy", "malloc", "fread"} <= callees
    assert doc["coverage"]["planned"] == len(doc["call_sites"]) == 4
    assert doc["coverage"]["covered"] == 0
    assert doc["coverage"]["status"] == "partial"
    assert doc["counts"] == {"entry_points": 1, "functions": 3,
                             "call_sites": 4, "anchors": 0}
    assert len(doc["sha256"]) == 64 and doc["sha256"] == index.sha256

    # 反序列化后哈希不变（内容寻址可复算）
    assert ProgramIndex.from_dict(doc).sha256 == doc["sha256"]


def test_cg01_workspace_program_index():
    index = ProgramIndex.build(_task("cybergym", CG01), max_sources=80)
    doc = index.to_dict()

    assert doc["benchmark"] == "cybergym"
    assert doc["root"].endswith("CG-01-arvo-44034/src")
    assert doc["source_count"] > 80, "workspace 源文件总数应大于扫描上限"
    cov = doc["coverage"]
    assert cov["scanned_sources"] <= 80
    assert cov["truncated_sources"] == doc["source_count"] - cov["scanned_sources"]
    assert cov["mode"] == "static_source_bounded"
    assert doc["formats"], "格式识别不能为空"
    assert doc["meta"]["case_id"] == "CG-01"
    assert doc["meta"]["project"] == "ghostscript"

    kinds = {e["kind"] for e in doc["entry_points"]}
    assert "fuzzer" in kinds, "ARVO harness（LLVMFuzzerTestOneInput）必须被识别"
    assert any(e["name"] == "LLVMFuzzerTestOneInput" for e in doc["entry_points"])

    anchors = doc["anchors"]
    assert anchors, "task.json component 应产静态定位锚点"
    anchor = anchors[0]
    assert anchor["file"] == "pdf/pdf_font.c"
    assert anchor["resolved_file"] == "ghostpdl/pdf/pdf_font.c"
    assert anchor["line"] == 168 and anchor["verified"] is True
    assert anchor["symbol"] == "pdfi_open_CIDFont_substitute_file"

    # 假设集优先取 component 锚点文件：CG-01 的案例位置（pdf_font.c:332）必须进前 8
    items = propose(index, root=index.root)
    assert items and items[0]["file"].endswith("pdf/pdf_font.c")
    assert any(h["file"].endswith("pdf/pdf_font.c") and h["line"] == 332
               for h in items)


def test_vulngym_source_md_anchors():
    index = ProgramIndex.build(
        _task("vulngym", "http://127.0.0.1:8000", metadata={"workspace": str(VG01)}))
    doc = index.to_dict()

    assert doc["benchmark"] == "vulngym"
    assert doc["source_count"] == 0
    assert doc["call_sites"] == []
    assert doc["coverage"]["status"] == "unavailable"
    assert doc["coverage"]["mode"] == "anchors_only"
    anchor = doc["anchors"][0]
    assert anchor["kind"] == "source_md"
    assert anchor["file"] == "nltk/app/wordnet_app.py"
    assert anchor["line"] == 87
    assert anchor["repo"] == "https://github.com/nltk/nltk"
    assert anchor["commit"] == "40d0bc1d"
    assert anchor["verified"] is False
    assert "上游复算" in anchor["note"] or "repo+commit" in anchor["note"]


# ---------------------------------------------------------------- 假设集
def test_hypotheses_fields_and_budget():
    index = ProgramIndex.build(_task("target_yaml", FIXTURE))
    items = propose(index, root=index.root)

    assert 1 <= len(items) <= MAX_HYPOTHESES
    assert [h["id"] for h in items] == [f"H{i}" for i in range(1, len(items) + 1)]
    for h in items:
        for name in REQUIRED:
            assert name in h, f"缺字段 {name}"
        assert isinstance(h["statement"], str) and h["statement"].strip()
        assert isinstance(h["falsifiable_by"], str) and h["falsifiable_by"].strip()
        assert isinstance(h["evidence_gap"], list) and h["evidence_gap"]
        assert h["cost"]["level"] in ("low", "medium", "high")
        assert h["cost"]["execs"] > 0 and h["cost"]["seconds"] > 0
        assert 0.0 <= float(h["confidence"]) <= 1.0
        assert h["source"].startswith("rule:")
        assert "verdict" not in h
        assert not contains_verdict(h["statement"])
        assert h["citations"] == [f"{h['file']}:{h['line']}"]
        assert f"{h['file']}:{h['line']}" in h["window"] or h["window"]

    # 危险点覆盖率不足时，证据缺口必须显式写出
    assert any("覆盖率" in gap for gap in items[0]["evidence_gap"])
    assert any("fix" in gap for gap in items[0]["evidence_gap"])
    validate_hypotheses(items)


def test_hypotheses_budget_and_verdict_are_rejected():
    index = ProgramIndex.build(_task("target_yaml", FIXTURE))
    items = propose(index, root=index.root)
    base = items[0]

    too_many = [dict(base, id=f"H{i + 1}") for i in range(MAX_HYPOTHESES + 1)]
    with pytest.raises(HypothesisError):
        validate_hypotheses(too_many)

    with pytest.raises(HypothesisError):
        validate_hypotheses([dict(base, verdict="confirmed")])

    with pytest.raises(HypothesisError):
        validate_hypotheses([dict(base, statement="已确认该处存在越界写")])

    with pytest.raises(HypothesisError):
        validate_hypotheses([dict(base, evidence_gap=[])])


def test_vulngym_hypothesis_from_anchor():
    index = ProgramIndex.build(
        _task("vulngym", "http://127.0.0.1:8000", metadata={"workspace": str(VG01)}))
    items = propose(index)
    assert len(items) == 1
    hyp = items[0]
    assert hyp["source"] == "rule:anchor"
    assert hyp["file"] == "nltk/app/wordnet_app.py" and hyp["line"] == 87
    assert hyp["repo"] == "https://github.com/nltk/nltk"
    assert hyp["commit"] == "40d0bc1d"
    assert hyp["citations"] == [], "锚点行不是本仓可验证事实，不能伪造 citations"
    assert any("上游" in gap or "repo+commit" in gap for gap in hyp["evidence_gap"])


def test_no_llm_fabrication_without_key(monkeypatch):
    for name in ("DISCOVERY_LLM_API_KEY", "BDVE_LLM_API_KEY", "DEEPSEEK_API_KEY",
                 "LLM_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DISCOVERY_LLM_DISABLED", "1")

    index = ProgramIndex.build(_task("target_yaml", FIXTURE))
    items = propose(index, root=index.root, use_llm=True)
    assert items
    for hyp in items:
        assert hyp["source"].startswith("rule:"), "无 key 时不得出现 LLM 结论"
        assert hyp["llm"] is False
    dumped = json.dumps(items, ensure_ascii=False)
    assert "api_key" not in dumped.lower()
    assert "authorization" not in dumped.lower()


# ---------------------------------------------------------------- store / 迁移
def test_p1_migration_is_idempotent_and_keeps_p0(tmp_path):
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(SCHEMA)          # 只建 P0 表，模拟旧库
    conn.execute(
        "INSERT INTO tasks(task_id,benchmark,target,mode,state,budget_json,"
        "metadata_json,terminal_reason,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("legacy-1", "target_yaml", str(FIXTURE), "fuzz", "READY",
         json.dumps({"max_seconds": 60, "max_execs": 10, "max_tokens": 10,
                     "max_turns": 1}),
         "{}", "", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()

    store = PlatformStore(db)           # 打开即幂等迁移
    assert store.get_task("legacy-1")["state"] == "READY"
    tables = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"tasks", "task_events", "evidence", "program_indexes",
            "hypotheses"} <= tables
    assert store.list_hypotheses("legacy-1") == []
    index = ProgramIndex.build(_task("target_yaml", FIXTURE, task_id="legacy-1"))
    store.save_program_index("legacy-1", index)
    store.save_hypotheses("legacy-1", propose(index, root=index.root))
    first = store.get_program_index("legacy-1")
    store.close()

    store2 = PlatformStore(db)          # 二次打开：迁移幂等、数据保留
    again = store2.get_program_index("legacy-1")
    assert again["sha256"] == first["sha256"] == index.sha256
    assert len(store2.list_hypotheses("legacy-1")) == len(
        propose(index, root=index.root))
    assert store2.get_task("legacy-1")["state"] == "READY"

    # 覆盖写不产生重复行
    store2.save_program_index("legacy-1", index)
    rows = store2.conn.execute(
        "SELECT COUNT(*) FROM program_indexes WHERE task_id=?",
        ("legacy-1",)).fetchone()[0]
    assert rows == 1

    # 假设集是集合语义：整批替换
    store2.save_hypotheses("legacy-1", propose(index, root=index.root)[:1])
    assert len(store2.list_hypotheses("legacy-1")) == 1
    store2.close()


# ---------------------------------------------------------------- CLI 端到端
def test_cli_understand_hypotheses_end_to_end(tmp_path):
    db = tmp_path / "cli.db"
    assert _run("--db", str(db), "submit", "--benchmark", "target_yaml",
                "--target", str(FIXTURE), "--task-id", "fx-cli",
                "--meta", "authorized=true").returncode == 0
    p = _run("--db", str(db), "preflight", "fx-cli")
    assert p.returncode == 0, p.stderr

    p = _run("--db", str(db), "understand", "fx-cli")
    assert p.returncode == 0, p.stderr
    understood = json.loads(p.stdout)
    assert understood["state"] == "UNDERSTANDING"
    assert understood["coverage"]["planned"] == 4
    assert understood["counts"]["call_sites"] == 4
    assert len(understood["sha256"]) == 64

    p = _run("--db", str(db), "hypotheses", "fx-cli")
    assert p.returncode == 0, p.stderr
    proposed = json.loads(p.stdout)
    assert proposed["state"] == "HYPOTHESES"
    assert 1 <= proposed["count"] <= MAX_HYPOTHESES
    assert len(proposed["hypotheses"]) == proposed["count"]

    p = _run("--db", str(db), "status", "fx-cli")
    assert p.returncode == 0, p.stderr
    status = json.loads(p.stdout)
    assert status["task"]["state"] == "HYPOTHESES"
    assert status["replay"]["state"] == "HYPOTHESES"
    assert [t["to"] for t in status["replay"]["transitions"]] == [
        "PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES"]
    assert status["program_index"]["call_sites"] == 4
    assert status["hypotheses"] == proposed["count"]

    p = _run("--db", str(db), "events", "fx-cli")
    assert p.returncode == 0, p.stderr
    events = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    types = [e["event_type"] for e in events]
    assert "program.indexed" in types
    assert "hypothesis.proposed" in types
    assert types.index("program.indexed") < types.index("hypothesis.proposed")
    indexed = events[types.index("program.indexed")]
    assert indexed["payload"]["sha256"] == understood["sha256"]
    assert indexed["payload"]["coverage"]["planned"] == 4
    proposed_event = events[types.index("hypothesis.proposed")]
    assert proposed_event["payload"]["count"] == proposed["count"]
    assert proposed_event["payload"]["max"] == MAX_HYPOTHESES

    p = _run("--db", str(db), "program", "fx-cli")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["sha256"] == understood["sha256"]

    # 非法迁移：HYPOTHESES 不能再 understand
    p = _run("--db", str(db), "understand", "fx-cli")
    assert p.returncode == 2
    assert "requires READY" in p.stderr
    p = _run("--db", str(db), "status", "fx-cli")
    assert json.loads(p.stdout)["task"]["state"] == "HYPOTHESES"


def test_cli_hypotheses_requires_understand(tmp_path):
    db = tmp_path / "cli2.db"
    _run("--db", str(db), "submit", "--benchmark", "target_yaml",
         "--target", str(FIXTURE), "--task-id", "fx2",
         "--meta", "authorized=true")
    _run("--db", str(db), "preflight", "fx2")

    p = _run("--db", str(db), "hypotheses", "fx2")
    assert p.returncode == 2
    assert "requires UNDERSTANDING" in p.stderr
    p = _run("--db", str(db), "status", "fx2")
    assert json.loads(p.stdout)["task"]["state"] == "READY"

    # RECEIVED 不能直接 understand
    _run("--db", str(db), "submit", "--benchmark", "target_yaml",
         "--target", str(FIXTURE), "--task-id", "fx3",
         "--meta", "authorized=true")
    p = _run("--db", str(db), "understand", "fx3")
    assert p.returncode == 2
    assert "requires READY" in p.stderr


def test_hypotheses_requires_static_evidence(tmp_path):
    """没有调用点/锚点/入口时不能进入 HYPOTHESES：空假设集不是假设集。"""
    store, bus = _prepared(tmp_path, "vulngym", "http://127.0.0.1:8000",
                           task_id="vg-empty")
    out = run_understand("vg-empty", store, bus)
    assert out["state"] == "UNDERSTANDING"
    with pytest.raises(HypothesisError):
        run_hypotheses("vg-empty", store, bus)
    assert store.get_task("vg-empty")["state"] == "UNDERSTANDING"
    assert store.list_hypotheses("vg-empty") == []


# ---------------------------------------------------------------- 事件回放
def test_p1_event_replay_is_stable(tmp_path):
    store, bus = _prepared(tmp_path, "target_yaml", FIXTURE, task_id="replay-1")
    result = run_understand("replay-1", store, bus)
    assert result["state"] == "UNDERSTANDING"
    hyp = run_hypotheses("replay-1", store, bus)
    assert hyp["state"] == "HYPOTHESES"

    replay = bus.replay("replay-1")
    assert replay["state"] == "HYPOTHESES"
    assert [t["to"] for t in replay["transitions"]] == [
        "PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES"]

    events = bus.list("replay-1")
    payloads = {e["event_type"]: e["payload"] for e in events}
    assert payloads["program.indexed"]["call_sites"] == 4
    assert payloads["hypothesis.proposed"]["count"] == hyp["count"]
    assert len(store.list_hypotheses("replay-1")) == hyp["count"]

    # 重放两次结果一致（事件流只追加、不回写）
    assert bus.replay("replay-1") == replay


def test_understand_failure_marks_failed_and_keeps_replay(tmp_path):
    store, bus = _prepared(tmp_path, "target_yaml", FIXTURE, task_id="fail-1")
    # 目标目录被删掉：D0 扫描抛 FileNotFoundError，状态必须落到 FAILED
    import shutil
    staged = tmp_path / "target"
    shutil.copytree(FIXTURE, staged)
    spec = TaskSpec("fail-1b", "target_yaml", str(staged),
                    metadata={"authorized": True})
    store.create_task(spec)
    run_preflight("fail-1b", store, bus)
    shutil.rmtree(staged)
    with pytest.raises(Exception):
        run_understand("fail-1b", store, bus)
    assert store.get_task("fail-1b")["state"] == "FAILED"
    assert bus.replay("fail-1b")["state"] == "FAILED"
