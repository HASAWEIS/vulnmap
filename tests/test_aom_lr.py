"""CG-24（arvo:10252 / aom AV1）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import aom_lr  # noqa: E402


def test_seeds_discovered():
    seeds = aom_lr.discover_seeds()
    assert seeds, "experiments/s11/seeds 下应有 IVF 种子"
    assert all(p.suffix == ".ivf" for p in seeds)


def test_ivf_structure_preserved():
    r = aom_lr.build({"seed_index": 0, "seed": 1})
    assert r.ok, r.reason
    header, frames = aom_lr.parse_ivf(r.data)
    assert header[:4] == b"DKIF"
    assert len(frames) >= 1
    # 帧头（size/timestamp）必须还能解析出来，否则解码器根本进不去
    assert all(sz > 0 for _, sz, _ in frames)


def test_mutation_is_reproducible_and_changes_bytes():
    a = aom_lr.build({"seed_index": 0, "seed": 7})
    b = aom_lr.build({"seed_index": 0, "seed": 7})
    c = aom_lr.build({"seed_index": 0, "seed": 8})
    assert a.data == b.data
    assert a.data != c.data
    seed = Path(a.fields_used["seed_file"]).read_bytes()
    assert a.data != seed, "必须真的改动了字节"


def test_biggest_frame_is_default_target():
    r = aom_lr.build({"seed_index": 0, "seed": 3})
    assert r.ok
    assert r.fields_used["frame"] == "biggest"
    _, frames = aom_lr.parse_ivf(r.data)
    biggest = max(sz for _, sz, _ in frames)
    assert r.fields_used["frame_size"] == biggest


def test_field_validation():
    assert not aom_lr.build({"seed_index": 99999}).ok
    assert not aom_lr.build({"flips": 0}).ok
    assert not aom_lr.build({"flips": 999}).ok
    assert not aom_lr.build({"frame": "middle"}).ok
    assert not aom_lr.build({"seed": "x"}).ok


def test_unknown_fields_dropped():
    r = aom_lr.build({"seed_index": 0, "magic": 1})
    assert r.ok and any(d["field"] == "magic" for d in r.dropped)


def test_claim_shape():
    c = aom_lr.declared_claim()
    assert c["subject"] == "enqueue_lr_jobs"
    assert c["sink"]["file"] == "av1/common/thread_common.c"
    assert c["cwe"] == "CWE-122"
    assert c["test_plan"]["format"] == "aom_lr"


def test_parse_ivf_rejects_non_ivf():
    try:
        aom_lr.parse_ivf(b"not an ivf stream at all........")
    except ValueError:
        return
    raise AssertionError("应当抛 ValueError")
