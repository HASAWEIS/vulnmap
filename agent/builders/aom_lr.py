"""CG-24（arvo:10252 / aom AV1）loop restoration 线程化路径构造器。

**缺陷**（av1/common/thread_common.c）：foreach_rest_unit_in_planes_mt() 用
seq_params.sb_size 推 unit_size（128/64），但每个 plane 的
rst_info[plane].restoration_unit_size 可能不同；且 RESTORE_NONE 的 plane 也被计入。
于是 num_rows_lr 偏小 -> lr_sync->sync_range 按偏小的行数分配 -> enqueue_lr_jobs 里
写 lr_job 时 4 字节越界。官方栈：

    enqueue_lr_jobs thread_common.c:599 <- foreach_rest_unit_in_planes_mt:743
    <- av1_loop_restoration_filter_frame_mt:780 <- ... <- aom_codec_decode

patch：跳过 RESTORE_NONE 的 plane，并改用 rst_info[plane].restoration_unit_size。

**输入格式**：IVF（"DKIF" 32 字节头 + 每帧 [size(4) LE][timestamp(8)][payload]），
fuzz 目标 /out/av1_dec_fuzzer_threaded 逐帧喂 aom_codec_decode。

**本构造器做什么**：读真实 IVF 种子，保持头部/帧头结构，只改帧 payload
（默认最后一帧的 tile 区），做确定性变异；批量跑容器找 4 字节堆写。
"""
from __future__ import annotations

import random
import struct
from pathlib import Path

SEED_ROOT = "experiments/s11/seeds"
IVF_SIG = b"DKIF"
DEFAULT_FLIPS = 12

FIELDS = {
    "seed_index": "int, 选哪个 IVF 种子（按 discover_seeds() 顺序）",
    "seed": "int, 变异随机种子（同参数同结果）",
    "flips": "int(1..256), 目标帧 payload 里改写的字节数（默认 12）",
    "frame": "'last'(默认) | 'first' | 'rand'，改哪一帧",
    "skip": "int(0..64), 帧 payload 开头保留多少字节不动（默认 8）",
    "splice": "int, 若非 0，把另一路种子的同位置字节拼进来（取该值作种子下标）",
}

DECLARED_SINK = {
    "file": "av1/common/thread_common.c",
    "line": 599,
    "symbol": "enqueue_lr_jobs",
    "note": "lr_job 队列按偏小的 num_rows_lr 分配，写 4 字节越界",
}


class AomLrResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "aom_lr"
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


def seed_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent / SEED_ROOT


def discover_seeds(root: Path | None = None) -> list[Path]:
    base = Path(root) if root else seed_root()
    if not base.exists():
        return []
    return sorted(p for p in base.rglob("*.ivf") if p.is_file())


def parse_ivf(data: bytes) -> tuple[bytes, list[tuple[int, int, bytes]]]:
    """返回 (32 字节头, [(payload_off, payload_len, payload)])。"""
    if len(data) < 32 or data[:4] != IVF_SIG:
        raise ValueError("not an IVF stream")
    frames = []
    off = 32
    while off + 12 <= len(data):
        (sz,) = struct.unpack("<I", data[off:off + 4])
        if sz == 0 or off + 12 + sz > len(data):
            break
        frames.append((off + 12, sz, data[off + 12:off + 12 + sz]))
        off += 12 + sz
    return data[:32], frames


def build(fields: dict, *, root: Path | None = None) -> AomLrResult:
    fields = dict(fields or {})
    seeds = discover_seeds(root)
    if not seeds:
        return AomLrResult(False, reason=f"没有 IVF 种子（{seed_root()}）")
    try:
        idx = int(fields.get("seed_index", 0))
        rng_seed = int(fields.get("seed", 0))
        flips = int(fields.get("flips", DEFAULT_FLIPS))
        skip = int(fields.get("skip", 8))
        splice = int(fields.get("splice", 0) or 0)
    except (TypeError, ValueError):
        return AomLrResult(False, reason="seed_index/seed/flips/skip/splice 必须是整数")
    if not 0 <= idx < len(seeds):
        return AomLrResult(False, reason=f"seed_index 越界（0..{len(seeds)-1}）: {idx}")
    if not 1 <= flips <= 256:
        return AomLrResult(False, reason=f"flips 越界（1..256）: {flips}")
    frame_sel = str(fields.get("frame") or "biggest")
    if frame_sel not in ("biggest", "last", "first", "rand"):
        return AomLrResult(False, reason=f"frame 只认 biggest/last/first/rand: {frame_sel}")

    src = seeds[idx]
    try:
        raw = src.read_bytes()
        header, frames = parse_ivf(raw)
    except (OSError, ValueError) as exc:
        return AomLrResult(False, reason=f"读/解析种子失败: {exc}")
    if not frames:
        return AomLrResult(False, reason="种子里没有可用的 IVF 帧")

    rng = random.Random(rng_seed)
    if frame_sel == "first":
        fi = 0
    elif frame_sel == "last":
        fi = len(frames) - 1
    elif frame_sel == "rand":
        fi = rng.randrange(len(frames))
    else:  # biggest：tile 数据最多，最可能走到 loop restoration
        fi = max(range(len(frames)), key=lambda k: frames[k][1])
    off, sz, payload = frames[fi]
    buf = bytearray(raw)

    lo = off + min(skip, max(sz - 1, 0))
    hi = off + sz
    if hi - lo < 1:
        return AomLrResult(False, reason="目标帧太小，没有可变异空间")
    for _ in range(flips):
        pos = rng.randrange(lo, hi)
        buf[pos] = rng.randrange(0, 256)

    if splice and 0 <= splice < len(seeds) and splice != idx:
        try:
            _, other_frames = parse_ivf(seeds[splice].read_bytes())
        except (OSError, ValueError):
            other_frames = []
        if other_frames:
            _, _, other = other_frames[min(fi, len(other_frames) - 1)]
            take = min(len(other), hi - lo)
            if take > 0:
                buf[lo:lo + take] = other[:take]

    used = {"seed_index": idx, "seed_file": str(src), "seed": rng_seed,
            "flips": flips, "frame": frame_sel, "frame_index": fi,
            "frame_size": sz, "skip": skip, "splice": splice,
            "bytes": len(buf)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "aom_lr 构造器不识别该字段"}
               for k in fields if k not in known]
    return AomLrResult(True, bytes(buf), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：loop restoration 线程化的 lr_job 队列 4 字节越界写。"""
    return {
        "claim_id": "cg24-aom-lr-job",
        "subject": "enqueue_lr_jobs",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/aom_lr.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "aom_lr"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    seeds = discover_seeds()
    print("IVF seeds:", len(seeds))
    r = build({"seed_index": 0, "seed": 1})
    assert r.ok, r.reason
    header, frames = parse_ivf(r.data)
    assert header[:4] == IVF_SIG
    assert len(frames) >= 1
    assert build({"seed_index": 0, "seed": 1}).data == r.data   # 可复现
    assert not build({"seed_index": 99999}).ok
    assert not build({"flips": 0}).ok
    assert not build({"frame": "middle"}).ok
    assert build({"unknown": 1}).dropped
    print("aom_lr builder self-check OK:", r.to_record())
