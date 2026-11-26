"""CG-32（arvo:58262 / matio + HDF5）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import hdf5_memcpy  # noqa: E402


def test_mat73_header():
    """MAT v7.3 = "MATLAB 7" 头 + HDF5 user block。"""
    r = hdf5_memcpy.build({})
    assert r.ok, r.reason
    assert r.data[:8] == b"MATLAB 7"
    assert b"\x89HDF\r\n\x1a\n" in r.data[:2048], "文件里应有 HDF5 signature"


def test_size_and_variant_guard():
    r = hdf5_memcpy.build({})
    assert r.size == r.fields_used["bytes"] == 37240
    assert not hdf5_memcpy.build({"variant": "orig"}).ok
    assert not hdf5_memcpy.build({"variant": "x"}).ok


def test_unknown_fields_dropped():
    r = hdf5_memcpy.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = hdf5_memcpy.declared_claim()
    assert c["subject"] == "Mat_H5ReadFieldNames"
    assert c["sink"]["file"] == "src/mat73.c"
    assert c["sink"]["line"] == 625
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = hdf5_memcpy.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
