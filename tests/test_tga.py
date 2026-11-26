"""CG-27（arvo:12818 / kimageformats TGA）构造器契约测试。"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import tga  # noqa: E402


def test_default_header_layout():
    r = tga.build({})
    assert r.ok, r.reason
    assert r.size == 18 + r.fields_used["payload"]
    hdr = r.data[:18]
    assert len(hdr) == 18
    id_len, cmap_type, img_type = hdr[0], hdr[1], hdr[2]
    assert (id_len, cmap_type, img_type) == (0, 0, 3)
    w, h = struct.unpack("<HH", hdr[12:16])
    assert (w, h) == (65535, 65535)
    assert hdr[16] == 8      # pixel depth


def test_size_exceeds_int_max():
    """关键：declared_size 必须 > INT_MAX，readRawData 才会返回 -1。"""
    r = tga.build({})
    assert r.fields_used["declared_size"] == 65535 * 65535
    assert r.fields_used["declared_size"] > 0x7FFFFFFF
    small = tga.build({"width": 4, "height": 4})
    assert small.ok and "warning" in small.fields_used


def test_pixel_size_variants():
    for ps, bpp in ((1, 8), (2, 16), (3, 24), (4, 32)):
        r = tga.build({"pixel_size": ps, "image_type": 2})
        assert r.ok and r.data[16] == bpp
        assert r.fields_used["declared_size"] == 65535 * 65535 * ps


def test_rle_flag():
    r = tga.build({"rle": 1})
    assert r.ok and (r.data[17] & 0x20)


def test_bounds_and_types():
    assert not tga.build({"width": 0}).ok
    assert not tga.build({"height": 70000}).ok
    assert not tga.build({"pixel_size": 5}).ok
    assert not tga.build({"image_type": 9}).ok
    assert not tga.build({"payload": 999}).ok
    assert not tga.build({"width": "wide"}).ok


def test_unknown_fields_dropped():
    r = tga.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_points_at_tga_cpp():
    c = tga.declared_claim()
    assert c["subject"] == "LoadTGA"
    assert c["sink"]["file"] == "src/imageformats/tga.cpp"
    assert c["sink"]["line"] == 264
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = tga.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
