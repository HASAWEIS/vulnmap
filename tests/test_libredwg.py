"""CG-10（arvo:54625 / libredwg）构造器单元测试。

只测构造器的**契约**（字段校验、字节落位、结果结构），
不测"能不能触发漏洞"——那是 e2e 的事，见 experiments/s5g/EVIDENCE.md。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import libredwg  # noqa: E402


def test_build_default_template_ok():
    r = libredwg.build({})
    assert r.ok, r.reason
    assert r.format == "dwg"
    assert r.size == len(libredwg_path_bytes())
    assert r.fields_used == {"base": "template"}


def libredwg_path_bytes() -> bytes:
    p = ROOT / "agent" / "templates" / libredwg.DEFAULT_TEMPLATE
    return p.read_bytes()


def test_version_written_at_0x4b():
    for ver in (1, 4, 5):
        r = libredwg.build({"version": ver})
        assert r.ok, r.reason
        assert r.data[libredwg.VERSION_OFFSET] == ver
        assert r.fields_used["version"] == ver


def test_version_out_of_range_rejected():
    for bad in (0, 6, -1):
        r = libredwg.build({"version": bad})
        assert not r.ok and "version" in r.reason


def test_version_not_int_rejected():
    r = libredwg.build({"version": "five"})
    assert not r.ok


def test_entities_end_lands_little_endian_at_0x18():
    r = libredwg.build({"entities_end": 0x7FFFFFFF})
    assert r.ok, r.reason
    assert r.data[0x18:0x1C] == b"\xff\xff\xff\x7f"
    assert r.fields_used["entities_end"] == 0x7FFFFFFF


def test_entities_start_and_blocks_start_offsets():
    r = libredwg.build({"entities_start": 0, "blocks_start": 0x40})
    assert r.ok, r.reason
    assert r.data[0x14:0x18] == b"\x00\x00\x00\x00"
    assert r.data[0x1C:0x20] == b"\x40\x00\x00\x00"


def test_entities_end_out_of_u32_rejected():
    r = libredwg.build({"entities_end": 0x1_0000_0000})
    assert not r.ok and "entities_end" in r.reason


def test_tail_repeat_multiplies():
    one = libredwg.build({})
    two = libredwg.build({"tail_repeat": 2})
    assert two.ok and two.size == one.size * 2


def test_tail_repeat_bounds():
    assert not libredwg.build({"tail_repeat": 0}).ok
    assert not libredwg.build({"tail_repeat": 65}).ok


def test_unknown_fields_are_dropped_not_silent():
    r = libredwg.build({"magic": 1})
    assert r.ok
    assert any(d["field"] == "magic" for d in r.dropped)


def test_base_r11_requires_src_root():
    r = libredwg.build({"base": "r11"})
    assert not r.ok and "r11" in r.reason


def test_base_r11_uses_repo_sample():
    src = ROOT / "workspace" / "S5G-CG10" / "src"
    if not (src / "libredwg" / libredwg.R11_DIR / libredwg.R11_SAMPLE).exists():
        return
    r = libredwg.build({"base": "r11", "entities_end": 0x7FFFFFFF}, src_root=src)
    assert r.ok, r.reason
    assert r.data[:6] == b"AC1009"
    assert r.data[0x18:0x1C] == b"\xff\xff\xff\x7f"


def test_unknown_base_rejected():
    r = libredwg.build({"base": "png"})
    assert not r.ok


def test_result_record_shape():
    rec = libredwg.build({"version": 5}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
    assert rec["ok"] is True


def test_declared_claim_separates_sink_from_observed_crash():
    c = libredwg.declared_claim()
    assert c["subject"] == "decode_r11"
    assert c["sink"]["file"] == "src/decode_r11.c"
    assert c["observed_crash"]["file"] == "src/out_json.c"
    assert c["verified"] is False


def test_fields_spec_lists_all_known_fields():
    spec = libredwg.fields_spec()
    assert set(spec) == {"base", "version", "entities_start", "entities_end",
                         "blocks_start", "tail_repeat"}
