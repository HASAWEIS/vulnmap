"""CG-38（arvo:52465 / net-snmp）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import snmp_oid  # noqa: E402


def test_agentx_header_shape():
    r = snmp_oid.build({})
    assert r.ok, r.reason
    assert r.data[0] == 1 and r.data[1] == 1        # version=1, command=OPEN
    payload_len = int.from_bytes(r.data[16:20], "little")
    assert payload_len == len(r.data) - 20


def test_oid_starts_with_2_ffffffff():
    r = snmp_oid.build({})
    n_subid = r.data[24]
    assert n_subid == 21
    import struct
    first = struct.unpack("<I", r.data[28:32])[0]
    second = struct.unpack("<I", r.data[32:36])[0]
    assert first == 2 and second == 0xFFFFFFFF


def test_outbuf_region_nonzero():
    r = snmp_oid.build({})
    assert r.fields_used["outbuf_len"] == 75
    assert 0 not in r.data[37:112]


def test_subid0_constraint():
    """asn_build_objid 要求 objid[0] <= 2，否则直接报错返回。"""
    assert snmp_oid.build({"subid0": 2}).ok
    assert snmp_oid.build({"subid0": 0}).ok
    assert not snmp_oid.build({"subid0": 3}).ok
    assert not snmp_oid.build({"n_tail": 99}).ok
    assert not snmp_oid.build({"cmd": 99}).ok


def test_unknown_fields_dropped():
    r = snmp_oid.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = snmp_oid.declared_claim()
    assert c["subject"] == "asn_build_objid"
    assert c["sink"]["file"] == "snmplib/asn1.c"
    assert c["cwe"] == "CWE-122"


def test_record_shape():
    rec = snmp_oid.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
