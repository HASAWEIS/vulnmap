"""CG-25（arvo:14821 / OpenThread Ip6::Address::FromString）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import ot_ip6  # noqa: E402


def test_default_build_shape():
    r = ot_ip6.build({})
    assert r.ok, r.reason
    assert r.format == "ot_ip6"
    text = r.data.decode()
    assert text.startswith("coap get ")
    assert text.endswith("\n"), "CLI 靠换行触发 ProcessCommand"
    assert "." in text, "必须带内嵌 IPv4 才会走到那条分支"


def test_default_address_is_the_crashing_one():
    """实测命中形：:: + 7 段 + 内嵌 IPv4（压缩移位时 endp 越过缓冲区下界）。"""
    assert ot_ip6.DEFAULT_ADDR == "::1:2:3:4:5:6:7:1.2.3.4"
    assert ot_ip6.build({}).data.decode().startswith("coap get ::1:2:3:4:5:6:7:1.2.3.4 ")


def test_address_without_ipv4_rejected():
    r = ot_ip6.build({"addr": "2001:db8::1"})
    assert not r.ok and "IPv4" in r.reason


def test_bad_verb_rejected():
    assert not ot_ip6.build({"verb": "patch"}).ok
    for v in ("get", "post", "put", "delete"):
        assert ot_ip6.build({"verb": v}).ok


def test_custom_uri_and_newline():
    r = ot_ip6.build({"uri": "/x", "newline": "\r\n"})
    assert r.ok and r.data.endswith(b"/x\r\n")
    r2 = ot_ip6.build({"newline": ""})
    assert r2.ok and not r2.data.endswith(b"\n")


def test_unknown_fields_dropped():
    r = ot_ip6.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_points_at_fromstring():
    c = ot_ip6.declared_claim()
    assert c["subject"] == "Ip6::Address::FromString"
    assert c["sink"]["file"] == "src/core/net/ip6_address.cpp"
    assert c["sink"]["line"] == 333
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = ot_ip6.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
