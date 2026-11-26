from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent.platform import (Budget, EventBus, EvidenceStore, PlatformStore,
                            TaskSpec, TaskError, run_preflight)

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "platform.py"


def _spec(tmp_path, **kw):
    target = kw.pop("target", tmp_path / "target")
    Path(target).mkdir(parents=True, exist_ok=True)
    # F1：授权声明必须显式（缺失默认阻断），测试夹具照流程声明 authorized=true
    kw.setdefault("metadata", {"authorized": True})
    return TaskSpec(task_id=kw.pop("task_id", "task-test-1"),
                    benchmark=kw.pop("benchmark", "target_yaml"),
                    target=str(target), **kw)


def test_submit_preflight_ready_and_replay(tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = _spec(tmp_path)
    task = store.create_task(spec)
    assert task["state"] == "RECEIVED"
    bus = EventBus(store)
    bus.emit(spec.task_id, "task.created", payload=spec.to_dict())
    out = run_preflight(spec.task_id, store, bus)
    assert out["state"] == "READY"
    task = store.get_task(spec.task_id)
    assert task["state"] == "READY"
    replay = bus.replay(spec.task_id)
    assert replay["state"] == "READY"
    assert [t["to"] for t in replay["transitions"]] == ["PREFLIGHT", "READY"]
    events = bus.list(spec.task_id)
    assert events[0]["event_type"] == "task.created"
    assert events[-1]["event_type"] == "preflight.passed"


def test_missing_target_blocks(tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = TaskSpec("task-missing", "target_yaml", str(tmp_path / "nope"))
    store.create_task(spec)
    bus = EventBus(store)
    out = run_preflight(spec.task_id, store, bus)
    assert out["state"] == "BLOCKED"
    assert "target_path" in out["blockers"]
    assert bus.replay(spec.task_id)["state"] == "BLOCKED"


def test_unauthorized_blocks(tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = _spec(tmp_path, task_id="task-noauth", metadata={"authorized": False})
    store.create_task(spec)
    out = run_preflight(spec.task_id, store, EventBus(store))
    assert out["state"] == "BLOCKED"
    assert "authorized" in out["blockers"]


def test_vulngym_url_target(monkeypatch, tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = TaskSpec("task-url", "vulngym", "http://127.0.0.1:8000",
                    metadata={"authorized": True})
    store.create_task(spec)
    out = run_preflight(spec.task_id, store, EventBus(store))
    assert out["state"] == "READY"


def test_illegal_transition_rejected(tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = _spec(tmp_path, task_id="task-illegal")
    store.create_task(spec)
    with pytest.raises(TaskError):
        store.transition(spec.task_id, "RUNNING")


def test_evidence_content_addressed(tmp_path):
    store = PlatformStore(tmp_path / "p.db")
    spec = _spec(tmp_path, task_id="task-ev")
    store.create_task(spec)
    ev = EvidenceStore(store, tmp_path / "evidence")
    ref = ev.put_bytes(spec.task_id, "log", b"hello", source_stage="PREFLIGHT")
    assert len(ref.sha256) == 64
    assert Path(ref.path).read_bytes() == b"hello"
    assert ev.verify(ref)
    assert store.list_evidence(spec.task_id)[0]["kind"] == "log"


def test_cli_end_to_end(tmp_path):
    db = tmp_path / "cli.db"
    target = tmp_path / "src"
    target.mkdir()
    p = subprocess.run([sys.executable, str(BIN), "--db", str(db), "submit",
                        "--benchmark", "target_yaml", "--target", str(target),
                        "--task-id", "task-cli",
                        "--meta", "authorized=true"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["state"] == "RECEIVED"
    p = subprocess.run([sys.executable, str(BIN), "--db", str(db), "preflight",
                        "task-cli"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["state"] == "READY"
    p = subprocess.run([sys.executable, str(BIN), "--db", str(db), "status",
                        "task-cli"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    data = json.loads(p.stdout)
    assert data["task"]["state"] == "READY"
    assert data["replay"]["state"] == "READY"
    assert data["events"] >= 3
