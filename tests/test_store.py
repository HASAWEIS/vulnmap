"""存储层：claim 修订、工件、检查点、上下文预算。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.store import Store


def test_claim_revision_increments(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "arvo:1", "cybergym", str(tmp_path))
    cid = st.upsert_claim("r1", {"claim_id": "c-1", "subject": "f", "confidence": 0.4})
    st.upsert_claim("r1", {"claim_id": "c-1", "subject": "f", "confidence": 0.9})
    rows = st.claims("r1")
    assert len(rows) == 1
    assert rows[0]["revision"] == 2
    assert rows[0]["confidence"] == 0.9


def test_artifact_and_checkpoint(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "arvo:1", "cybergym", str(tmp_path))
    st.add_artifact("r1", "verify", "poc", "artifacts/verify/poc.bin", "a" * 64, 10, "v1", "verify-v1")
    binding = {"schema": "vulnmap.checkpoint.v1", "run_id": "r1", "stage": "verify", "artifacts": {"poc": "a" * 64}}
    key = st.save_checkpoint("r1", "verify", binding)
    assert st.find_checkpoint("r1", "verify", binding)["key"] == key


def test_blackboard_context_trims_artifacts(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "arvo:1", "cybergym", str(tmp_path))
    for i in range(10):
        st.add_artifact("r1", "recon", f"k{i}", f"artifacts/{i}.json", str(i) * 64, 1, "v1", "recon-v1")
    st.add_blackboard("r1", "hypothesis", "u1", "unknown-x")
    ctx = st.blackboard_context("r1", max_tokens=50)
    assert len(ctx["artifacts"]) <= 6
    assert ctx["unknowns"]
