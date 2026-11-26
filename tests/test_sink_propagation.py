"""报告层 sink 传播：verify 实测位置优先，locate/模型指认退居兜底。

对应 S5K：CG-12 的 case.sink 曾写成模型指认的 dump-emoji.cc:210，
真实崩溃点在 hb-ot-layout-common.hh:289；CG-10 的 sink 直接为空。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.stages.report import ReportStage  # noqa: E402


def _stage():
    """只测纯函数：不碰 store / 工作区，绕开 __init__ 的重依赖。"""
    return object.__new__(ReportStage)


class _R:
    def fetchall(self):
        return []

    def fetchone(self):
        return None


class _FakeCon:
    def execute(self, *a, **k):
        return _R()


class _FakeStore:
    _con = _FakeCon()


def _stage_with_store():
    """_checks 里会查 attempts 表判 model_recorded，这里给个空库替身。"""
    st = _stage()
    st.store = _FakeStore()
    st.run_id = "test-run"
    return st


def _verify(evidence_sink=None, text_hit=None, cand_sink=None, cand_verdict="pass"):
    ev = {}
    if evidence_sink is not None:
        ev["sink"] = evidence_sink
    if text_hit is not None:
        ev["text_hit"] = text_hit
    cand = {"candidate": "c1", "verdict": cand_verdict, "claim": {"sink": cand_sink} if cand_sink else None}
    return {"verdict": "pass", "root_cause": {"evidence": ev}, "candidates": [cand]}


def test_verify_evidence_sink_wins_over_locate_claim():
    """verify 有 sink、locate claim 指向别处 -> 采用 verify，并记录被覆盖的 claim。"""
    s = _stage()
    verify = _verify(evidence_sink={"file": "src/header_variables_r11.spec", "line": 145,
                                    "symbol": "json_cquote"})
    claim = {"sink": {"file": "src/decode_r11.c", "line": 697}}
    sink, source = s._resolve_sink(verify, claim)
    assert source == "verify.root_cause.evidence.sink"
    assert sink["file"] == "src/header_variables_r11.spec"
    assert sink["line"] == 145
    assert sink["overrode_claim_sink"]["file"] == "src/decode_r11.c"


def test_text_hit_used_when_parser_found_no_stack_sink():
    """CG-12 的情形：解析器没拆出栈帧，只有裸文本命中。"""
    s = _stage()
    verify = _verify(text_hit={"file": "hb-ot-layout-common.hh", "line": 289,
                               "delta": 0, "source": "raw_trace_text"})
    claim = {"sink": {"file": "harfbuzz/src/dump-emoji.cc", "line": 210}}
    sink, source = s._resolve_sink(verify, claim)
    assert source == "verify.root_cause.evidence.text_hit"
    assert "hb-ot-layout-common.hh" in sink["file"]
    assert sink["line"] == 289
    assert "dump-emoji" not in sink["file"]
    assert sink["overrode_claim_sink"]["file"].endswith("dump-emoji.cc")


def test_candidate_claim_sink_has_highest_priority():
    s = _stage()
    verify = _verify(cand_sink={"file": "src/out_json.c", "line": 1865, "symbol": "json_cquote"},
                     evidence_sink={"file": "src/other.c", "line": 1})
    sink, source = s._resolve_sink(verify, {})
    assert source == "verify.candidate.claim.sink"
    assert sink["file"] == "src/out_json.c"


def test_only_failed_candidates_are_ignored():
    s = _stage()
    verify = _verify(cand_sink={"file": "src/nope.c", "line": 7}, cand_verdict="not_triggered",
                     evidence_sink={"file": "src/header_variables_r11.spec", "line": 145})
    sink, source = s._resolve_sink(verify, {})
    assert source == "verify.root_cause.evidence.sink"
    assert sink["file"] == "src/header_variables_r11.spec"


def test_fallback_to_locate_claim_when_verify_has_nothing():
    """verify 完全没给崩溃位置 -> 回退 locate claim（不是伪造，标明来源）。"""
    s = _stage()
    sink, source = s._resolve_sink({"root_cause": {}, "candidates": []},
                                   {"sink": {"file": "src/a.c", "line": 12}})
    assert source == "locate.claim.sink"
    assert sink == {"file": "src/a.c", "line": 12}


def test_empty_everything_returns_empty_sink():
    s = _stage()
    sink, source = s._resolve_sink({"root_cause": {}, "candidates": []}, {})
    assert sink == {} and source == "none"


def test_sink_line_exists_resolves_header_basename(tmp_path):
    """崩溃点常是头文件 basename；src 下直接拼不上时要能按 basename 找到。"""
    s = _stage()
    src = tmp_path / "src"
    (src / "harfbuzz" / "src").mkdir(parents=True)
    target = src / "harfbuzz" / "src" / "hb-ot-layout-common.hh"
    target.write_text("\n" * 400, encoding="utf-8")
    assert s._sink_line_ok(src, {"file": "hb-ot-layout-common.hh", "line": 289}) is True


def test_sink_line_out_of_range_is_false(tmp_path):
    s = _stage()
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("x\n" * 10, encoding="utf-8")
    assert s._sink_line_ok(src, {"file": "a.c", "line": 999}) is False
    assert s._sink_line_ok(src, {"file": "a.c", "line": 0}) is False
    assert s._sink_line_ok(src, {"file": "missing.c", "line": 3}) is False
    assert s._sink_line_ok(src, {}) is False
