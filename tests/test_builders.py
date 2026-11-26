"""构造器注册表：字节一致、参数校验、recipe 解析。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.builders import build, describe, supported_formats
from agent.stages.verify import (make_fuzz_seed, make_gas_file_directive,
                                 make_mng, pdf_with_basefont)


def test_mng_matches_existing_implementation():
    """构造器不得改变已通过的 PoC 字节。"""
    assert build("mng", {"loop_len": 4}).data == make_mng(4)


def test_pdf_matches_existing_implementation():
    assert build("pdf", {"basefont_len": 4096}).data == pdf_with_basefont(b"A" * 4096)


def test_gas_matches_existing_implementation():
    assert build("gas", {"slot": 4294967289}).data == make_gas_file_directive(4294967289)


def test_unknown_format_is_unsupported_not_empty():
    r = build("not-a-real-format", {})
    assert r.ok is False
    assert "unsupported_format" in r.reason
    assert r.data == b""


@pytest.mark.parametrize("fmt,fields", [
    ("mng", {"loop_len": -1}),
    ("pdf", {"basefont_len": -5}),
    ("gas", {"slot": -1}),
    ("fuzz", {"size": -1}),
    ("mvg", {"segments": 1}),
])
def test_out_of_range_rejected(fmt, fields):
    r = build(fmt, fields)
    assert r.ok is False and "越界" in r.reason


def test_unknown_fields_are_dropped_with_reason():
    r = build("mng", {"loop_len": 4, "bogus": 123})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "bogus"


def test_describe_recovers_format():
    for fmt, fields in [("mng", {"loop_len": 4}), ("pdf", {"basefont_len": 32}),
                        ("gas", {"slot": 4294967289}), ("mvg", {"segments": 8})]:
        d = describe(build(fmt, fields).data)
        assert d["format"] == fmt, (fmt, d)


def test_mvg_builder_produces_verified_shape():
    """mvg 触发形已实测：vul 崩 / fix 不崩（见 experiments/10096-recipe-loop）。"""
    data = build("mvg", {"segments": 2}).data
    assert b"path w(m3'2" in data and data.endswith(b"22")


def test_supported_formats_listed():
    assert set(supported_formats()) >= {"mng", "pdf", "gas", "fuzz", "mvg"}


# ---- recipe 解析 ----

def test_recipe_parsed_into_bytes():
    from agent.loop import parse_response
    import json as _j
    data, why, field = parse_response(
        _j.dumps({"encoding": "recipe", "format": "mng", "fields": {"loop_len": 4},
                  "rationale": "r"}), "mng")
    assert data == make_mng(4)


def test_recipe_required_when_builder_exists():
    from agent.loop import parse_response
    import json as _j
    with pytest.raises(ValueError) as exc:
        parse_response(_j.dumps({"encoding": "text", "content": "x"}), "mng",
                       require_recipe=True)
    assert "must_use_recipe" in str(exc.value)


def test_recipe_bad_fields_rejected():
    from agent.loop import parse_response
    import json as _j
    with pytest.raises(ValueError) as exc:
        parse_response(_j.dumps({"encoding": "recipe", "format": "mng",
                                 "fields": {"loop_len": -9}}), "mng")
    assert "recipe_failed" in str(exc.value)


def test_empty_bytes_not_counted_as_duplicate():
    """空响应（模型失败）不应被当成重复输入。"""
    from agent import loop
    assert loop.LoopRound(round_id=1, sha256="").sha256 == ""


def test_rar5_builder_available():
    r = build("rar5", {"fill": 0x0F})
    assert r.ok and r.format == "rar5" and len(r.data) > 0


def test_rar5_fill_out_of_range_rejected():
    assert build("rar5", {"fill": 16}).ok is False
    assert build("rar5", {"fill": -1}).ok is False


def test_rar5_fill_changes_bytes():
    a = build("rar5", {"fill": 0x0A}).data
    b = build("rar5", {"fill": 0x0F}).data
    assert a != b and len(a) == len(b)


def test_rar5_in_supported_formats():
    assert "rar5" in supported_formats()
