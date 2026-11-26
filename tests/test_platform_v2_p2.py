"""V2 P2 验收：Plan 选择 / D2 执行器 / Candidate / 状态机与事件 / 证据。

口径：
- Plan 只做确定性选择（static/dynamic/fuzz/replay），不产结论；
- 执行器只包 Discovery D2（构建 harness + run_parallel + 覆盖率），不重写 Discovery；
- 单端 fuzz 只产 Candidate(state=new)：不伪造 confirmed/verified；
- 失败（构建失败/执行器缺失）落 FAILED；预算内无崩溃落 NO_REPRO；
- 崩溃输入与日志都能按 sha256 在 EvidenceStore 里校验。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from agent.platform import (CANDIDATE_STATES, Candidate, CandidateError,
                            EventBus, PlatformStore, TaskSpec, run_hypotheses,
                            run_execution, run_plan, run_preflight,
                            run_understand, validate_candidate)
from agent.platform.candidates import from_crash, sha256_hex
from agent.platform.hypotheses import contains_verdict
from agent.platform.planner import (KINDS, PlanError, select as select_plan,
                                   validate as validate_plan)
from agent.platform.program import ProgramIndex
from agent.platform.store import SCHEMA

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "platform.py"
FIXTURE = ROOT / "fixtures" / "discovery"
VG01 = ROOT / "workspace" / "VG-01-nltk-wordnet"

CANDIDATE_FIELDS = ("id", "task", "input_sha256", "crash_type",
                    "stack_hash", "evidence_sha256", "state")


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), *args],
                          capture_output=True, text=True)


def _prepared(tmp_path, *, task_id="task-p2", benchmark="target_yaml",
              target=FIXTURE, metadata=None, db_name="p.db"):
    store = PlatformStore(tmp_path / db_name)
    # F1：缺失授权默认阻断，夹具显式声明
    spec = TaskSpec(task_id=task_id, benchmark=benchmark, target=str(target),
                    metadata={"authorized": True, **(metadata or {})})
    store.create_task(spec)
    bus = EventBus(store)
    assert run_preflight(task_id, store, bus)["state"] == "READY"
    assert run_understand(task_id, store, bus)["state"] == "UNDERSTANDING"
    assert run_hypotheses(task_id, store, bus)["state"] == "HYPOTHESES"
    return store, bus


def _submit_through_hypotheses(db: Path, target: Path, task_id: str) -> None:
    steps = (
        ("submit", "--benchmark", "target_yaml", "--target", str(target),
         "--task-id", task_id, "--meta", "authorized=true"),
        ("preflight", task_id),
        ("understand", task_id),
        ("hypotheses", task_id),
    )
    for step in steps:
        proc = _run("--db", str(db), *step)
        assert proc.returncode == 0, proc.stderr


def _clean_target(root: Path) -> Path:
    """不会崩溃的受控目标：只有格式检查与校验和。"""
    root.mkdir(parents=True, exist_ok=True)
    (root / "clean.c").write_text(
        "#include <stdio.h>\n#include <stdint.h>\n\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc < 2) return 2;\n"
        "    FILE *f = fopen(argv[1], \"rb\");\n"
        "    if (!f) return 2;\n"
        "    uint8_t buf[256];\n"
        "    size_t n = fread(buf, 1, sizeof(buf), f);\n"
        "    fclose(f);\n"
        "    uint32_t sum = 0;\n"
        "    for (size_t i = 0; i < n; i++) sum = sum * 31u + buf[i];\n"
        "    return sum == 0xdeadbeefu ? 3 : 0;\n"
        "}\n")
    (root / "target.yaml").write_text(
        "name: clean-fixture\nformat: unknown\nsources:\n  - clean.c\n"
        "includes:\n  - .\nbuild:\n  mode: main\n"
        "fuzz:\n  seconds: 1\n  workers: 1\n")
    return root


# ---------------------------------------------------------------- Plan
def test_plan_from_fixture_selects_fuzz(tmp_path):
    store, bus = _prepared(tmp_path)
    out = run_plan("task-p2", store, bus)
    assert out["state"] == "PLANNED"
    plan = out["plan"]

    assert plan["schema"] == "vulnmap.plan.v1"
    assert plan["kind"] == "fuzz"
    assert plan["benchmark"] == "target_yaml"
    assert plan["target"].endswith("fixtures/discovery")
    assert plan["budget"]["seconds"] > 0
    assert plan["budget"]["workers"] >= 1
    assert plan["budget"]["timeout"] > 0
    assert len(plan["hypothesis_ids"]) >= 1
    assert all(h.startswith("H") for h in plan["hypothesis_ids"])
    assert plan["reason"].strip() and "fuzz" in plan["reason"]
    assert "P3" in plan["reason"], "规划必须说明确认结论留给独立验证"
    assert len(plan["sha256"]) == 64
    validate_plan(plan)

    stored = store.get_plan("task-p2")
    assert stored["kind"] == "fuzz" and stored["sha256"] == plan["sha256"]
    assert stored["doc"] == plan

    events = bus.list("task-p2")
    selected = [e for e in events if e["event_type"] == "plan.selected"]
    assert len(selected) == 1
    payload = selected[0]["payload"]
    assert payload["kind"] == "fuzz"
    assert payload["sha256"] == plan["sha256"]
    assert payload["budget"] == plan["budget"]
    assert payload["hypothesis_ids"] == plan["hypothesis_ids"]
    assert bus.replay("task-p2")["state"] == "PLANNED"

    # 规划阶段不得夹带结论字段/文本
    assert not any(k in plan for k in ("verdict", "confirmed", "exploitable"))
    assert not contains_verdict(plan["reason"])


def test_plan_budget_and_kind_validation():
    with pytest.raises(PlanError):
        validate_plan({"task_id": "t", "benchmark": "target_yaml",
                       "kind": "magic", "target": "/tmp",
                       "reason": "x", "budget": {"seconds": 1, "execs": 1,
                                                "workers": 1, "timeout": 1}})
    with pytest.raises(PlanError):
        validate_plan({"task_id": "t", "benchmark": "target_yaml",
                       "kind": "fuzz", "target": "/tmp",
                       "reason": "x", "budget": {"seconds": 1, "execs": 1,
                                                "workers": 0, "timeout": 1}})
    with pytest.raises(PlanError):
        validate_plan({"task_id": "t", "benchmark": "target_yaml",
                       "kind": "fuzz", "target": "/tmp", "reason": "已确认漏洞",
                       "budget": {"seconds": 1, "execs": 1, "workers": 1,
                                  "timeout": 1}})
    assert set(KINDS) == {"static", "dynamic", "fuzz", "replay"}


def test_plan_kind_rules_cover_static_and_replay(tmp_path):
    """四种 kind 都有确定性入口：无入口/无调用点 → static；CG 无源码 → replay。"""
    static_task = {"task_id": "s1", "benchmark": "target_yaml",
                   "target": str(tmp_path / "empty")}
    empty = ProgramIndex(benchmark="target_yaml", root=str(tmp_path / "empty"))
    p_static = select_plan(static_task, empty, [])
    assert p_static.kind == "static"
    assert "静态" in p_static.reason

    replay_task = {"task_id": "r1", "benchmark": "cybergym",
                   "target": str(tmp_path / "ws")}
    no_src = ProgramIndex(benchmark="cybergym", root=str(tmp_path / "ws"),
                          source_count=0)
    p_replay = select_plan(replay_task, no_src, [])
    assert p_replay.kind == "replay"
    assert "工作区" in p_replay.reason

    # 有入口无调用点的 target_yaml 走 fuzz（静态不充分）
    entry = ProgramIndex(
        benchmark="target_yaml", root=str(tmp_path / "entry"),
        entry_points=[{"kind": "main", "name": "main", "file": "a.c", "line": 1}],
        source_count=1)
    p_fuzz = select_plan({"task_id": "f1", "benchmark": "target_yaml",
                          "target": str(tmp_path / "entry")}, entry, [])
    assert p_fuzz.kind == "fuzz"


@pytest.mark.skipif(not VG01.exists(), reason="VG-01 workspace missing")
def test_plan_vulngym_selects_dynamic_without_execution(tmp_path):
    store, bus = _prepared(tmp_path, task_id="vg-p2", benchmark="vulngym",
                           target="http://127.0.0.1:8000",
                           metadata={"workspace": str(VG01)})
    out = run_plan("vg-p2", store, bus)
    plan = out["plan"]
    assert out["state"] == "PLANNED"
    assert plan["kind"] == "dynamic"
    assert plan["target"] == "http://127.0.0.1:8000"
    assert "动态" in plan["reason"]
    # 规划只写事件，不执行：没有 exec.started，也没有候选
    types = [e["event_type"] for e in bus.list("vg-p2")]
    assert "plan.selected" in types and "exec.started" not in types
    assert store.list_candidates("vg-p2") == []


# ---------------------------------------------------------------- Candidate
def _crash() -> dict:
    data = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    return {
        "input_bytes": data,
        "input_sha256": sha256_hex(data),
        "log": "ERROR: AddressSanitizer: heap-buffer-overflow\n"
               "WRITE of size 64\n#0 0x1 in parse_record a.c:16\n",
        "parsed": {"crash_type": "heap-buffer-overflow", "access": "WRITE",
                   "access_size": 64, "function": "parse_record",
                   "file": "a.c", "line": 16, "frames": []},
        "stack_hash": "0123456789abcdef",
    }


def test_candidate_contract_and_rejects_verdict():
    cand = from_crash(_crash(), task_id="t1", candidate_id="C1",
                      exec_id="exec-1", plan_sha256="p" * 64,
                      build_sha256="b" * 64)
    doc = cand.to_dict()
    for name in CANDIDATE_FIELDS:
        assert name in doc, f"缺字段 {name}"
    assert doc["state"] == "new"
    assert len(doc["input_sha256"]) == 64
    assert len(doc["evidence_sha256"]) == 64
    assert doc["crash_type"] == "heap-buffer-overflow"
    assert doc["stack_hash"] == "0123456789abcdef"
    assert doc["detail"]["scope"] == "single_build_only"
    assert "confirmed" not in json.dumps(doc, ensure_ascii=False).lower()
    validate_candidate(doc)

    assert "confirmed" not in CANDIDATE_STATES
    assert "verified" not in CANDIDATE_STATES

    with pytest.raises(CandidateError):
        validate_candidate(dict(doc, state="confirmed"))
    with pytest.raises(CandidateError):
        validate_candidate(dict(doc, verdict="confirmed"))
    with pytest.raises(CandidateError):
        validate_candidate(dict(doc, input_sha256="short"))

    # 诊断无效（无根因帧/未知类型）的崩溃只作为线索，不升为正常候选
    weak = from_crash(dict(_crash(), diagnostic_valid=False),
                      task_id="t1", candidate_id="C2")
    assert weak.state == "needs_evidence"
    assert weak.detail["diagnostic_valid"] is False
    validate_candidate(weak)


def test_candidate_table_migration_and_roundtrip(tmp_path):
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(SCHEMA)      # 模拟 P0 旧库：candidates 没有 state/exec_id/detail_json
    conn.execute(
        "INSERT INTO candidates(candidate_id,task_id,input_sha256,crash_type,"
        "stack_hash,evidence_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
        ("C0", "legacy-1", "a" * 64, "unknown-crash", "f" * 16, "b" * 64,
         "2026-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()

    store = PlatformStore(db)       # 打开即幂等补列 + 建 plans
    store.create_task(TaskSpec("t1", "target_yaml", str(tmp_path)))
    columns = {row[1] for row in store.conn.execute("PRAGMA table_info(candidates)")}
    assert {"state", "exec_id", "detail_json"} <= columns
    tables = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"candidates", "plans", "tasks", "task_events"} <= tables

    legacy = store.get_candidate("legacy-1", "C0")
    assert legacy["state"] == "new"
    assert legacy["task"] == "legacy-1"

    cand = from_crash(_crash(), task_id="t1", candidate_id="C1",
                      exec_id="exec-1")
    saved = store.save_candidate(cand)
    assert saved["id"] == "C1" and saved["state"] == "new"
    rows = store.list_candidates("t1")
    assert len(rows) == 1 and rows[0]["input_sha256"] == cand.input_sha256
    assert store.list_candidates("t1", state="new") == rows
    assert store.list_candidates("t1", state="rejected") == []
    assert store.summary("t1")["candidates"] == 1
    assert store.summary("t1")["candidate_states"] == {"new": 1}

    # 任务内编号 C1 会重复：落库必须按任务隔离，不能撞 P0 的单列主键
    store.create_task(TaskSpec("t2", "target_yaml", str(tmp_path)))
    store.save_candidate(from_crash(_crash(), task_id="t2", candidate_id="C1"))
    assert store.get_candidate("t1", "C1")["task"] == "t1"
    assert store.get_candidate("t2", "C1")["task"] == "t2"
    assert [c["id"] for c in store.list_candidates("t2")] == ["C1"]
    assert store.conn.execute(
        "SELECT COUNT(*) FROM candidates").fetchone()[0] == 3
    store.close()

    store2 = PlatformStore(db)      # 二次打开：迁移幂等、旧行仍可读
    assert store2.get_candidate("legacy-1", "C0")["state"] == "new"
    assert len(store2.list_candidates("t1")) == 1
    store2.close()


# ---------------------------------------------------------------- CLI 端到端
def test_cli_plan_run_candidates_fixture(tmp_path):
    db = tmp_path / "cli.db"
    work = tmp_path / "work"
    evidence = tmp_path / "evidence"
    _submit_through_hypotheses(db, FIXTURE, "fx-p2")

    proc = _run("--db", str(db), "plan", "fx-p2")
    assert proc.returncode == 0, proc.stderr
    planned = json.loads(proc.stdout)
    assert planned["state"] == "PLANNED"
    assert planned["plan"]["kind"] == "fuzz"

    proc = _run("--db", str(db), "run", "fx-p2", "--seconds", "1",
                "--workers", "1", "--timeout", "2",
                "--workdir", str(work), "--evidence-root", str(evidence))
    assert proc.returncode == 0, proc.stderr
    ran = json.loads(proc.stdout)
    assert ran["state"] == "CANDIDATE"
    assert ran["exec_id"].startswith("exec-")
    assert ran["build"]["sha256"] and len(ran["build"]["sha256"]) == 64
    assert ran["fuzz"]["crashes"] >= 1
    assert ran["candidates"], "fixture 必须在 1s 内产出候选"

    cand = ran["candidates"][0]
    for name in CANDIDATE_FIELDS:
        assert name in cand, f"候选缺字段 {name}"
    assert cand["task"] == "fx-p2"
    assert cand["state"] == "new"
    assert cand["crash_type"] and cand["crash_type"] != "unknown"
    assert len(cand["input_sha256"]) == 64
    assert len(cand["evidence_sha256"]) == 64
    assert cand["detail"]["access"] in ("WRITE", "READ")
    assert cand["detail"]["function"] == "parse_record"
    assert cand["detail"]["scope"] == "single_build_only"

    # CLI candidates 与 run 结果一致
    proc = _run("--db", str(db), "candidates", "fx-p2")
    assert proc.returncode == 0, proc.stderr
    listed = json.loads(proc.stdout)
    assert listed == ran["candidates"]
    assert [c["id"] for c in listed] == [c["id"] for c in ran["candidates"]]

    # 事件时间线：plan.selected → exec.started → candidate.created → exec.finished
    proc = _run("--db", str(db), "events", "fx-p2")
    assert proc.returncode == 0, proc.stderr
    events = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    types = [e["event_type"] for e in events]
    for name in ("plan.selected", "exec.started", "candidate.created",
                 "exec.finished"):
        assert name in types, f"缺事件 {name}"
    assert types.index("plan.selected") < types.index("exec.started")
    assert types.index("exec.started") < types.index("candidate.created")
    assert types.index("candidate.created") < types.index("exec.finished")
    started = events[types.index("exec.started")]["payload"]
    assert started["plan_sha256"] == planned["plan"]["sha256"]
    assert started["overrides"] == {"seconds": 1.0, "workers": 1, "timeout": 2.0}
    assert started["budget"]["seconds"] == 1.0

    finished = events[types.index("exec.finished")]["payload"]
    assert finished["outcome"] == "candidate"
    assert finished["candidates"] == len(ran["candidates"])
    assert finished["budget_used"]["seconds"] == 1.0
    assert finished["error"] is None
    created = events[types.index("candidate.created")]["payload"]
    assert created["state"] == "new"
    assert created["evidence_sha256"] == cand["evidence_sha256"]

    # 状态机与回放
    proc = _run("--db", str(db), "status", "fx-p2")
    assert proc.returncode == 0, proc.stderr
    status = json.loads(proc.stdout)
    assert status["task"]["state"] == "CANDIDATE"
    assert status["replay"]["state"] == "CANDIDATE"
    assert [t["to"] for t in status["replay"]["transitions"]] == [
        "PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED",
        "RUNNING", "CANDIDATE"]
    assert status["plan"]["kind"] == "fuzz"
    assert status["candidates"] == len(ran["candidates"])
    assert status["candidate_states"] == {"new": len(ran["candidates"])}

    # 证据可校验：每条证据文件内容哈希 == sha256；候选引用主证据
    rows = json.loads(_run("--db", str(db), "evidence", "fx-p2").stdout)
    kinds = {row["kind"] for row in rows}
    assert {"crash_input", "crash_log"} <= kinds
    for row in rows:
        path = Path(row["path"])
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    shas = {row["sha256"] for row in rows}
    assert cand["evidence_sha256"] in shas
    assert cand["detail"]["input_evidence_sha256"] in shas
    assert cand["detail"]["log_evidence_sha256"] == cand["evidence_sha256"]

    # 不允许伪造确认结论
    dumped = json.dumps(listed, ensure_ascii=False).lower()
    assert "confirmed" not in dumped
    assert "verdict" not in dumped


def test_run_no_crash_enters_no_repro(tmp_path):
    target = _clean_target(tmp_path / "clean")
    db = tmp_path / "clean.db"
    _submit_through_hypotheses(db, target, "clean-p2")

    proc = _run("--db", str(db), "plan", "clean-p2")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["plan"]["kind"] == "fuzz"

    proc = _run("--db", str(db), "run", "clean-p2", "--seconds", "1",
                "--workers", "1", "--workdir", str(tmp_path / "work"),
                "--evidence-root", str(tmp_path / "evidence"))
    assert proc.returncode == 0, proc.stderr
    ran = json.loads(proc.stdout)
    assert ran["state"] == "NO_REPRO"
    assert ran["candidates"] == []
    assert ran["fuzz"]["execs"] > 0
    assert ran["fuzz"]["crashes"] == 0

    status = json.loads(_run("--db", str(db), "status", "clean-p2").stdout)
    assert status["task"]["state"] == "NO_REPRO"
    assert status["replay"]["state"] == "NO_REPRO"
    assert status["candidates"] == 0
    assert status["candidate_states"] == {}
    assert [t["to"] for t in status["replay"]["transitions"]][-3:] == [
        "PLANNED", "RUNNING", "NO_REPRO"]
    assert json.loads(_run("--db", str(db), "candidates", "clean-p2").stdout) == []

    events = [json.loads(line) for line in
              _run("--db", str(db), "events", "clean-p2").stdout.splitlines()
              if line.strip()]
    finished = [e for e in events if e["event_type"] == "exec.finished"]
    assert finished and finished[-1]["payload"]["outcome"] == "no_repro"
    assert not [e for e in events if e["event_type"] == "candidate.created"]


def test_run_requires_plan_and_plan_requires_hypotheses(tmp_path):
    db = tmp_path / "order.db"
    _submit_through_hypotheses(db, FIXTURE, "order1")

    proc = _run("--db", str(db), "run", "order1", "--seconds", "1")
    assert proc.returncode == 2
    assert "requires PLANNED" in proc.stderr
    assert json.loads(_run("--db", str(db), "status", "order1").stdout)[
        "task"]["state"] == "HYPOTHESES"

    # READY 阶段不能直接 plan
    _run("--db", str(db), "submit", "--benchmark", "target_yaml",
         "--target", str(FIXTURE), "--task-id", "order2",
         "--meta", "authorized=true")
    _run("--db", str(db), "preflight", "order2")
    proc = _run("--db", str(db), "plan", "order2")
    assert proc.returncode == 2
    assert "requires HYPOTHESES" in proc.stderr
    assert json.loads(_run("--db", str(db), "status", "order2").stdout)[
        "task"]["state"] == "READY"


def test_build_failure_marks_failed_and_keeps_state(tmp_path):
    target = tmp_path / "broken"
    target.mkdir()
    (target / "broken.c").write_text(
        "int main(int argc, char **argv) { this is not valid C; return 0; }\n")
    (target / "target.yaml").write_text(
        "name: broken\nformat: unknown\nsources:\n  - broken.c\n"
        "includes:\n  - .\nbuild:\n  mode: main\n"
        "fuzz:\n  seconds: 1\n  workers: 1\n")
    db = tmp_path / "broken.db"
    _submit_through_hypotheses(db, target, "bad-p2")
    assert _run("--db", str(db), "plan", "bad-p2").returncode == 0

    proc = _run("--db", str(db), "run", "bad-p2", "--seconds", "1",
                "--workers", "1", "--workdir", str(tmp_path / "work"),
                "--evidence-root", str(tmp_path / "evidence"))
    assert proc.returncode == 2
    assert "build failed" in proc.stderr

    status = json.loads(_run("--db", str(db), "status", "bad-p2").stdout)
    assert status["task"]["state"] == "FAILED"
    assert status["replay"]["state"] == "FAILED"
    assert status["candidates"] == 0
    events = [json.loads(line) for line in
              _run("--db", str(db), "events", "bad-p2").stdout.splitlines()
              if line.strip()]
    finished = [e for e in events if e["event_type"] == "exec.finished"]
    assert finished and finished[-1]["payload"]["outcome"] == "failed"
    assert "build failed" in finished[-1]["payload"]["error"]
    assert [t["to"] for t in status["replay"]["transitions"]][-3:] == [
        "PLANNED", "RUNNING", "FAILED"]


@pytest.mark.skipif(not VG01.exists(), reason="VG-01 workspace missing")
def test_dynamic_without_service_config_fails_closed(tmp_path):
    """P3.9 起 dynamic 有执行器，但没声明服务地址时必须落 FAILED 并留证据。

    （本轮改口径：原来是“dynamic 没有执行器”，现在执行器存在、配置缺口是
    `runner_not_configured:*`——仍然不能假装跑过，也不许把缺口写成 NO_REPRO。）
    """
    from agent.platform.executors import DynamicExecError

    store, bus = _prepared(tmp_path, task_id="vg-run", benchmark="vulngym",
                           target="http://127.0.0.1:8000",
                           metadata={"workspace": str(VG01)})
    plan = run_plan("vg-run", store, bus)["plan"]
    assert plan["kind"] == "dynamic"
    with pytest.raises(DynamicExecError):
        run_execution("vg-run", store, bus, workdir=tmp_path / "work",
                      evidence_root=tmp_path / "evidence")
    assert store.get_task("vg-run")["state"] == "FAILED"
    events = [e for e in bus.list("vg-run") if e["event_type"] == "exec.finished"]
    assert events and events[-1]["payload"]["outcome"] == "failed"
    assert "runner_not_configured" in events[-1]["payload"]["error"]
    # 失败前的 spec 也必须落库（失败可复核）
    kinds = {row["kind"] for row in store.list_evidence("vg-run")}
    assert {"dynamic_spec", "exec_error"} <= kinds
    assert bus.replay("vg-run")["state"] == "FAILED"
