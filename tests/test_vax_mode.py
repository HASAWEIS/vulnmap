"""CG-26（arvo:19414 / binutils vax-dis）构造器契约测试。"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import vax_mode  # noqa: E402


def test_default_layout():
    """fuzz_disassemble 的布局：[insn][flavour(1)][mach(8 LE)][arch(1)]。"""
    r = vax_mode.build({})
    assert r.ok, r.reason
    data = r.data
    assert data[-1] == vax_mode.BFD_ARCH_VAX, "最后 1 字节是 arch"
    assert len(data) >= 10, "目标要求 Size >= 10"
    assert data[-10] == 0, "倒数第 10 字节是 flavour"
    mach = struct.unpack("<Q", data[-9:-1])[0]
    assert mach == 0


def test_index_bytes_dominate():
    r = vax_mode.build({"depth": 400})
    assert r.ok and r.data[:400] == b"\x40" * 400
    assert r.size == 410


def test_depth_bounds():
    assert not vax_mode.build({"depth": 5}).ok
    assert not vax_mode.build({"depth": 99999}).ok


def test_mode_byte_must_be_index_mode():
    """高半字节必须是 0x4（index 模式），否则不会递归。"""
    assert vax_mode.build({"mode_byte": 0x40}).ok
    assert vax_mode.build({"mode_byte": 0x4F}).ok
    assert not vax_mode.build({"mode_byte": 0x50}).ok


def test_arch_and_flavour_bounds():
    assert not vax_mode.build({"arch": 999}).ok
    assert not vax_mode.build({"flavour": 300}).ok
    assert vax_mode.build({"arch": 34}).data[-1] == 34


def test_bad_type_rejected():
    assert not vax_mode.build({"depth": "deep"}).ok


def test_unknown_fields_dropped():
    r = vax_mode.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = vax_mode.declared_claim()
    assert c["subject"] == "print_insn_mode"
    assert c["sink"]["file"] == "opcodes/vax-dis.c"
    assert c["sink"]["line"] == 260
    assert c["test_plan"]["format"] == "vax_mode"
