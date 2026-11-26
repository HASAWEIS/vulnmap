"""检查点：真复用、输入/镜像/版本变化必须失效。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent import checkpoint as ck
from agent.store import Store

BASE = dict(run_id="r1", stage="verify", attempt=0, image_digest="sha256:" + "a" * 64,
            inputs={"repo-vul.tar.gz": "b" * 64},
            artifacts={"artifacts/verify/result.json": "c" * 64},
            role_version="verify-v1", prompt_version="verify-p1",
            schema_version="vulnmap.verify.v1", tool_version="vulnmap-1.0")


def _store(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "arvo:10400", "cybergym", str(tmp_path))
    return st


def test_binding_requires_image_digest(tmp_path):
    with pytest.raises(ValueError):
        ck.build_binding(**{**BASE, "image_digest": ""})


@pytest.mark.parametrize("override", [
    {"image_digest": "sha256:" + "d" * 64},
    {"inputs": {"repo-vul.tar.gz": "e" * 64}},
    {"prompt_version": "verify-p2"},
    {"role_version": "verify-v2"},
    {"tool_version": "vulnmap-2.0"},
    {"artifacts": {"artifacts/verify/result.json": "f" * 64}},
])
def test_any_binding_change_misses(tmp_path, override):
    st = _store(tmp_path)
    ck.save(st, "r1", "verify", ck.build_binding(**BASE))
    changed = ck.build_binding(**{**BASE, **override})
    assert ck.load_or_none(st, "r1", "verify", changed) is None


def test_identical_binding_hits(tmp_path):
    st = _store(tmp_path)
    key = ck.save(st, "r1", "verify", ck.build_binding(**BASE))
    row = ck.load_or_none(st, "r1", "verify", ck.build_binding(**BASE))
    assert row is not None and row["key"] == key
    assert json.loads(row["binding"])["image_digest"] == BASE["image_digest"]


def test_latest_checkpoint_is_per_stage(tmp_path):
    st = _store(tmp_path)
    ck.save(st, "r1", "verify", ck.build_binding(**BASE))
    assert st.latest_checkpoint("r1", "verify") is not None
    assert st.latest_checkpoint("r1", "recon") is None
