"""团队队列：领取、lease 过期接管、写域互斥、验收产物。"""
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.team import TeamQueue


def q(tmp_path):
    return TeamQueue(tmp_path / "team.db")


def test_claim_once(tmp_path):
    tq = q(tmp_path)
    tq.enqueue(task_id="t1", role="builder", subject="x", scope="a.py")
    t1 = tq.claim("w1")
    assert t1 and t1.id == "t1" and t1.status == "leased"
    assert tq.claim("w2") is None


def test_scope_conflict_blocks_second_claim(tmp_path):
    tq = q(tmp_path)
    tq.enqueue(task_id="t1", role="builder", subject="x", scope="agent/stages/verify.py")
    tq.enqueue(task_id="t2", role="builder", subject="y", scope="agent/stages/verify.py,tests/a.py")
    assert tq.claim("w1").id == "t1"
    assert tq.claim("w2") is None          # 写域冲突


def test_lease_expiry_takeover(tmp_path):
    tq = q(tmp_path)
    tq.enqueue(task_id="t1", role="builder", subject="x", scope="a.py")
    assert tq.claim("w1", lease_seconds=0).id == "t1"
    time.sleep(0.01)
    t2 = tq.claim("w2")
    assert t2 and t2.id == "t1" and t2.owner == "w2" and t2.attempts == 2


def test_complete_requires_artifact(tmp_path):
    tq = q(tmp_path)
    tq.enqueue(task_id="t1", role="builder", subject="x", scope="a.py")
    tq.claim("w1")
    try:
        tq.complete("t1", "w1", artifact_sha="")
        assert False
    except ValueError:
        pass
    assert tq.complete("t1", "w1", artifact_sha="abc", result="ok")
    assert tq.get("t1").status == "done"


def test_fail_retries_then_terminal(tmp_path):
    tq = q(tmp_path)
    tq.enqueue(task_id="t1", role="builder", subject="x", scope="a.py", max_attempts=2)
    tq.claim("w1"); assert tq.fail("t1", "w1", reason="boom") == "queued"
    tq.claim("w1"); assert tq.fail("t1", "w1", reason="boom") == "failed"
