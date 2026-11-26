"""CG-34（arvo:49259 / mruby）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import codegen_args as cb  # noqa: E402


def test_default_shape():
    r = cb.build({})
    assert r.ok, r.reason
    text = r.data.decode()
    assert "o.m = f(1, k: 2) { }" in text
    assert text.endswith("\n")
    assert r.fields_used["shape"] == 3


def test_prelude_toggle():
    with_pre = cb.build({"prelude": 1}).data.decode()
    without = cb.build({"prelude": 0}).data.decode()
    assert "class C" in with_pre
    assert "class C" not in without
    assert without.strip() == cb.SHAPES[3]


def test_locals_padding():
    r = cb.build({"locals": 120})
    text = r.data.decode()
    assert "v0 = 0" in text and "v119 = 119" in text


def test_bounds_and_types():
    assert not cb.build({"shape": 99}).ok
    assert not cb.build({"locals": 999}).ok
    assert not cb.build({"shape": "x"}).ok
    assert cb.build({"shape": len(cb.SHAPES) - 1}).ok


def test_unknown_fields_dropped():
    r = cb.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = cb.declared_claim()
    assert c["subject"] == "mrb_vm_exec"
    assert c["sink"]["file"] == "mrbgems/mruby-compiler/core/codegen.c"
    assert c["sink"]["line"] == 1809
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = cb.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
