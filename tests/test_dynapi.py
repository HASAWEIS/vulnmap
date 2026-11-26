"""CG-35（arvo:49613 / libredwg dynapi TFv）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import dynapi  # noqa: E402


def test_default_dxf_shape():
    r = dynapi.build({})
    assert r.ok, r.reason
    text = r.data.decode()
    assert text.startswith("0\nSECTION\n2\nHEADER\n9\n$ACADVER\n1\nAC1015\n")
    assert text.rstrip().endswith("EOF")
    assert "3\n" + "A" * 200 in text


def test_field_caps():
    assert dynapi.build({"kind": "ltype"}).fields_used["field_cap"] == 48
    assert dynapi.build({"kind": "style"}).fields_used["field_cap"] == 64


def test_tables_vs_blocks():
    t = dynapi.build({"where": "tables"}).data.decode()
    b = dynapi.build({"where": "blocks"}).data.decode()
    assert "ENDTAB" in t and "TABLE\n2\nLTYPE" in t
    assert "ENDTAB" not in b and "BLOCKS" in b


def test_bounds_and_types():
    assert not dynapi.build({"size": 8}).ok
    assert not dynapi.build({"size": 4096}).ok
    assert not dynapi.build({"kind": "nope"}).ok
    assert not dynapi.build({"where": "nowhere"}).ok
    assert not dynapi.build({"size": "big"}).ok


def test_unknown_fields_dropped():
    r = dynapi.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = dynapi.declared_claim()
    assert c["subject"] == "dynapi_set_helper"
    assert c["sink"]["file"] == "src/dynapi.c"
    assert c["sink"]["line"] == 3112
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = dynapi.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
