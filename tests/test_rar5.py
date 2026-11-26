"""CG-29（arvo:11011 / libarchive rar5）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import rar5  # noqa: E402


def test_archive_signature():
    r = rar5.build({})
    assert r.ok, r.reason
    assert r.data[:8] == bytes.fromhex("526172211a070100"), "RAR5 签名 Rar!\\x1a\\x07\\x01\\x00"
    assert r.size == 642


def test_variant_guard():
    assert rar5.build({"variant": "dir"}).ok
    assert not rar5.build({"variant": "orig"}).ok
    assert not rar5.build({"variant": "x"}).ok


def test_unknown_fields_dropped():
    r = rar5.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = rar5.declared_claim()
    assert c["subject"] == "do_uncompress_block"
    assert c["sink"]["file"] == "libarchive/archive_read_support_format_rar5.c"
    assert c["sink"]["line"] == 2424
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = rar5.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
