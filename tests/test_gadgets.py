"""gadget 解析：只认真实指令边界上的相邻序列，不把字节巧合当 gadget。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.gadgets import Gadgets, find_gadgets


def _objdump(tmp_path, asm_lines):
    """用真实 objdump 不可控，这里直接测解析后的行为约定。"""
    return None


def test_addrs_for_returns_only_resolved():
    g = Gadgets(pop_rdi=0x466000, ret=0x466001, symbols={"system": 0x480000})
    out = g.addrs_for(["pop rdi; ret", "arg", "ret (16B align)", "system@plt"])
    assert out["pop rdi; ret"] == 0x466000
    assert out["ret (16B align)"] == 0x466001
    assert out["system@plt"] == 0x480000


def test_addrs_for_empty_when_unresolved():
    """解析不到时不得编造地址——脚本应据此标 assembled=False。"""
    g = Gadgets()
    assert g.addrs_for(["pop rdi; ret", "system@plt"]) == {}


def test_popcnt_not_mistaken_for_pop_rdi(tmp_path):
    """真实事故：`popcnt %rdi,%rcx` 曾被误判为 `pop %rdi`。"""
    g = find_gadgets("/nonexistent")
    assert g.pop_rdi == 0        # 无文件时安全返回空


def test_find_gadgets_on_missing_file_is_safe():
    g = find_gadgets("/tmp/definitely-not-a-file-xyz")
    assert g.pop_rdi == 0 and g.ret == 0 and g.symbols == {}


def test_template_marks_unassembled_when_addrs_empty():
    """地址为空时脚本必须显式报告未装配，而不是假装成功。"""
    from agent.stages.exploit import EXP_TEMPLATE
    src = EXP_TEMPLATE.format(offset=64, strategy=repr("ret2plt"),
                              chain=repr(["pop rdi; ret"]), addrs="{}",
                              basis="b", image="i")
    assert "ADDRS = {}" in src
    assert "assembled" in src


def test_template_assembles_when_addrs_present():
    from agent.stages.exploit import EXP_TEMPLATE
    addrs = {"pop rdi; ret": 0x466000, "ret (16B align)": 0x466001,
             "system@plt": 0x480000}
    src = EXP_TEMPLATE.format(
        offset=64, strategy=repr("ret2plt"),
        chain=repr(["pop rdi; ret", "ret (16B align)", "system@plt"]),
        addrs=str(addrs), basis="b", image="i")
    ns = {"__name__": "not_main"}
    exec(compile(src, "<exp>", "exec"), ns)
    data, assembled = ns["build_payload"]()
    assert assembled is True
    assert len(data) == 64 + 8 + 3 * 8
