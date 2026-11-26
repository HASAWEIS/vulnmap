"""CG-16（arvo:368 / freetype2）CFF 变异构造器的契约测试。

只测构造器本身（种子发现、表格完整性、变异可复现、字段校验），
不测"能不能触发 blend UAF"——那是实验结论，见 experiments/s8c/EVIDENCE.md。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import freetype_cff as fc  # noqa: E402


def test_has_cff_seeds_locally():
    seeds = fc.cff_seeds()
    assert seeds, "本机应至少有一个带 CFF 表的字体"
    assert all(isinstance(p, Path) for p in seeds)


def test_build_default_ok_and_keeps_sfnt_tables():
    r = fc.build({"seed_index": 0, "seed": 1})
    assert r.ok, r.reason
    assert r.format == "freetype_cff"
    tables = fc.sfnt_tables(r.data)
    assert "CFF " in tables or "CFF2" in tables, tables.keys()
    # 表目录必须仍然可解析（说明没破坏 sfnt 骨架）
    assert len(tables) >= 3


def test_mutation_is_reproducible():
    a = fc.build({"seed_index": 0, "seed": 7, "flips": 8})
    b = fc.build({"seed_index": 0, "seed": 7, "flips": 8})
    c = fc.build({"seed_index": 0, "seed": 8, "flips": 8})
    assert a.data == b.data
    assert a.data != c.data


def test_blend_sequence_is_injected():
    base = fc.build({"seed_index": 0, "seed": 1, "blend_runs": 0, "flips": 0})
    mut = fc.build({"seed_index": 0, "seed": 1, "blend_runs": 3, "flips": 0})
    assert base.ok and mut.ok
    assert mut.data != base.data
    assert mut.fields_used["blend_runs"] == 3


def test_tag_flip_modes():
    r = fc.build({"seed_index": 0, "seed": 1, "mode": "tag_flip"})
    assert r.ok and r.fields_used["tag_patch"] == "tag_flipped"
    tables = fc.sfnt_tables(r.data)
    assert "CFF2" in tables and "CFF " not in tables
    h = fc.build({"seed_index": 0, "seed": 1, "mode": "tag_flip_header"})
    assert h.ok and h.fields_used.get("cff_major") == 2
    toff, _ = fc.sfnt_tables(h.data)["CFF2"]
    assert h.data[toff] == 2          # CFF2 header major


def test_seed_index_out_of_range_rejected():
    r = fc.build({"seed_index": 99999})
    assert not r.ok and "seed_index" in r.reason


def test_bad_field_types_rejected():
    assert not fc.build({"seed": "x"}).ok
    assert not fc.build({"flips": -1}).ok
    assert not fc.build({"blend_runs": 99}).ok


def test_unknown_fields_are_dropped():
    r = fc.build({"seed": 1, "magic": 1})
    assert r.ok
    assert any(d["field"] == "magic" for d in r.dropped)


def test_record_shape():
    rec = fc.build({"seed": 1}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}


def test_sfnt_tables_rejects_non_sfnt():
    assert fc.sfnt_tables(b"not a font at all") == {}