"""team_worker CLI：入队→领取→开始→完成 / 失败路径。"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "experiments" / "team_worker.py"


def run(tmp_path, *args):
    return subprocess.run([sys.executable, str(CLI), "--db", str(tmp_path / "t.db"), *args],
                          capture_output=True, text=True)


def test_enqueue_claim_complete(tmp_path):
    r = run(tmp_path, "enqueue", "--id", "t1", "--role", "builder",
            "--subject", "x", "--scope", "a.py", "--acceptance", "true")
    assert r.returncode == 0, r.stderr
    r = run(tmp_path, "claim", "--worker", "w1", "--role", "builder")
    assert r.returncode == 0 and json.loads(r.stdout)["id"] == "t1"
    assert run(tmp_path, "start", "--id", "t1", "--worker", "w1").returncode == 0
    r = run(tmp_path, "complete", "--id", "t1", "--worker", "w1", "--artifact-sha", "abc")
    assert r.returncode == 0
    r = run(tmp_path, "list", "--status", "done")
    assert len(json.loads(r.stdout)) == 1


def test_fail_requeues(tmp_path):
    run(tmp_path, "enqueue", "--id", "t1", "--role", "auditor", "--subject", "x", "--scope", "a.py")
    run(tmp_path, "claim", "--worker", "w1")
    r = run(tmp_path, "fail", "--id", "t1", "--worker", "w1", "--reason", "boom")
    assert "queued" in r.stdout
    r = run(tmp_path, "stats")
    assert json.loads(r.stdout).get("queued") == 1


def test_no_task_returns_1(tmp_path):
    assert run(tmp_path, "claim", "--worker", "w1").returncode == 1
