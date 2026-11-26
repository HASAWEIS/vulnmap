"""CG-28（arvo:16445 / zstd legacy v0.3）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import zstd_legacy  # noqa: E402


def test_header_layout():
    r = zstd_legacy.build({})
    assert r.ok, r.reason
    assert r.data[4:8] == b"\x23\xb5\x2f\xfd", "v0.3 magic 0xFD2FB523 (LE)"
    csize = r.fields_used["csize"]
    h0, h1, h2 = r.data[8], r.data[9], r.data[10]
    assert (h0 >> 6) == zstd_legacy.BT_COMPRESSED
    assert ((h0 & 7) << 16 | (h1 << 8) | h2) == csize
    assert r.size == 4 + 7 + csize


def test_literals_header_is_raw_with_big_size():
    r = zstd_legacy.build({"lit_size": 131082})
    lit = int.from_bytes(r.data[11:14], "little")
    assert (lit & 3) == zstd_legacy.IS_RAW
    assert (lit >> 2) == 131082
    assert 131082 > zstd_legacy.BLOCKSIZE


def test_harness_seed_prefix_present():
    """simple_decompress 先用 4 字节做种子，frame 前必须有它。"""
    r = zstd_legacy.build({"seed_prefix": 0x41414141})
    assert r.data[:4] == b"\x41\x41\x41\x41"
    assert r.data[4:8] == b"\x23\xb5\x2f\xfd"


def test_slack_window():
    """memcpy 分支要求 litSize <= cSize-3 且 litSize > cSize-11。"""
    for slack in (3, 4, 10):
        r = zstd_legacy.build({"slack": slack})
        assert r.ok
        lit = r.fields_used["lit_size"]
        cs = r.fields_used["csize"]
        assert cs - 10 <= lit <= cs - 3
    assert not zstd_legacy.build({"slack": 2}).ok


def test_small_lit_warns():
    r = zstd_legacy.build({"lit_size": 4096})
    assert r.ok and "warning" in r.fields_used


def test_bounds_and_types():
    assert not zstd_legacy.build({"lit_size": 0}).ok
    assert not zstd_legacy.build({"lit_size": 1 << 24}).ok
    assert not zstd_legacy.build({"fill": 300}).ok
    assert not zstd_legacy.build({"lit_size": "big"}).ok


def test_claim_shape():
    c = zstd_legacy.declared_claim()
    assert c["subject"] == "ZSTD_decodeLiteralsBlock"
    assert c["sink"]["file"] == "lib/legacy/zstd_v03.c"
    assert c["sink"]["line"] == 2529
    assert c["cwe"] == "CWE-121"


def test_record_shape():
    rec = zstd_legacy.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
