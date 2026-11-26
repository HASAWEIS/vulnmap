"""CG-21（arvo:10710 / OVN lexer）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import ovn_lex  # noqa: E402


def test_default_build_shape():
    r = ovn_lex.build({})
    assert r.ok, r.reason
    assert r.format == "ovn_lex"
    assert r.data.startswith(b"1 == 0x")
    assert r.data.count(b"0") >= 300
    assert r.size == r.fields_used["bytes"]


def test_zeros_scan_values_scaling():
    sizes = [ovn_lex.build({"zeros": z}).size for z in (300, 600, 1200)]
    assert sizes[0] < sizes[1] < sizes[2]


def test_below_minimum_rejected():
    """i/2 没过 sizeof(u8) 时不算缺陷，构造器直接拒，避免造无效输入。"""
    r = ovn_lex.build({"zeros": 32})
    assert not r.ok and "zeros" in r.reason


def test_upper_bound_rejected():
    assert not ovn_lex.build({"zeros": 99999}).ok


def test_bad_type_rejected():
    assert not ovn_lex.build({"zeros": "many"}).ok


def test_prefix_must_be_hex():
    assert ovn_lex.build({"prefix": "0x"}).ok
    assert not ovn_lex.build({"prefix": "0b"}).ok


def test_operands_are_used():
    r = ovn_lex.build({"lhs": "7", "op": "!=", "zeros": 40})
    assert r.ok and r.data.startswith(b"7 != 0x")
    assert r.fields_used["lhs"] == "7" and r.fields_used["op"] == "!="


def test_unknown_fields_dropped():
    r = ovn_lex.build({"zeros": 40, "magic": 1})
    assert r.ok and any(d["field"] == "magic" for d in r.dropped)


def test_claim_points_at_lex_c():
    c = ovn_lex.declared_claim()
    assert c["subject"] == "lex_parse_hex_integer"
    assert c["sink"]["file"] == "ovn/lib/lex.c" and c["sink"]["line"] == 341
    assert c["test_plan"]["format"] == "ovn_lex"


def test_record_shape():
    rec = ovn_lex.build({"zeros": 40}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}