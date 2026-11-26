"""CG-23（arvo:10653 / GraphicsMagick MagickGetToken）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import gm_token  # noqa: E402


def test_default_build_ok():
    r = gm_token.build({})
    assert r.ok, r.reason
    assert r.format == "gm_token"
    body = r.data.decode("latin-1")
    assert body.startswith("push graphic-context")
    assert "url(#" in body and body.rstrip().endswith("pop graphic-context")


def test_token_length_window():
    """只有 2049..2052 才在"读越界 4 字节"的窗口里。"""
    for tl in (2049, 2050, 2051, 2052):
        r = gm_token.build({"token_len": tl})
        assert r.ok, r.reason
        tok = [ln for ln in r.data.decode("latin-1").splitlines() if ln.startswith("url(#")][0]
        assert len(tok) == tl
    assert not gm_token.build({"token_len": 2048}).ok
    assert not gm_token.build({"token_len": 2053}).ok


def test_token_is_keyword_position():
    """url(#…) 必须在图元关键字位置（每行第一个 token），不能在 fill 参数里。"""
    lines = gm_token.build({}).data.decode("latin-1").splitlines()
    kw = [ln for ln in lines if "url(#" in ln]
    assert len(kw) == 1
    assert kw[0].startswith("url(#"), kw[0][:20]


def test_fill_char_and_tail():
    r = gm_token.build({"token_len": 2049, "fill": "B", "tail": " 0,0"})
    assert r.ok
    assert "url(#BBBB" in r.data.decode("latin-1")
    assert r.fields_used["fill"] == "B"


def test_bad_type_rejected():
    assert not gm_token.build({"token_len": "long"}).ok


def test_unknown_fields_dropped():
    r = gm_token.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_points_at_utility_c():
    c = gm_token.declared_claim()
    assert c["subject"] == "MagickGetToken"
    assert c["sink"]["file"] == "magick/utility.c" and c["sink"]["line"] == 3830
    assert c["cwe"] == "CWE-125", "这是读越界，不是写溢出"
    assert c["test_plan"]["format"] == "gm_token"


def test_record_shape():
    rec = gm_token.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
