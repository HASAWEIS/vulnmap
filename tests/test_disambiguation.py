"""同名函数消歧：不许静默取首项，并列必须报 ambiguous。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.tools import binscan

ROOT = Path(__file__).resolve().parent.parent / "workspace"


def _cands(files, sig="int foo(void)", branches=None):
    return [{"file": f, "line": 10 + i, "signature": sig,
             "conditions": [], "branches": (branches[i] if branches else [])}
            for i, f in enumerate(files)]


def test_single_candidate_is_unique():
    r = binscan.disambiguate("foo", _cands(["a.c"]))
    assert r["status"] == "unique" and r["picked"]["file"] == "a.c"


def test_no_candidates():
    r = binscan.disambiguate("foo", [])
    assert r["status"] == "none" and r["picked"] is None


def test_file_hint_only_ranks_not_confirms():
    """启发式领先只能得到 ranked_candidate，不能当成"确认选对"。"""
    c = _cands(["x/elf_fuzzer.cc", "x/rules_fuzzer.cc"])
    r = binscan.disambiguate("foo", c, file_hint="x/rules_fuzzer.cc")
    assert r["status"] == "ranked_candidate"
    assert r["needs_confirmation"] is True
    assert r["confidence"] == "heuristic_only"
    assert r["picked"]["file"] == "x/rules_fuzzer.cc"


def test_tie_without_evidence_is_ambiguous():
    """并列且无线索：绝不静默选第一个。"""
    c = _cands(["x/a.cc", "x/b.cc"])
    r = binscan.disambiguate("foo", c)
    assert r["status"] == "ambiguous"
    assert r["picked"] is None
    assert len(r["candidates"]) == 2


def test_description_mention_breaks_tie():
    c = _cands(["x/elf_fuzzer.cc", "x/rules_fuzzer.cc"])
    r = binscan.disambiguate("foo", c, descr="the rules fuzzer leaks")
    assert r["status"] == "ranked_candidate"
    assert r["picked"]["file"] == "x/rules_fuzzer.cc"


def test_conditional_branches_are_not_a_tie():
    """同文件同签名的 #if/#else 两支只编译一份，不算歧义。"""
    c = _cands(["x/png.c", "x/png.c"],
               branches=[["if:HasPNG", "if:VER>10011"], ["if:HasPNG", "else:VER>10011"]])
    r = binscan.disambiguate("foo", c)
    # 互斥已知，但"哪一支是活动的"未确认：不给 picked，只给 provisional
    assert r["status"] == "conditional_unresolved"
    assert r["picked"] is None
    assert r["provisional"]["line"] == 10
    assert r["needs_confirmation"] is True


@pytest.mark.skipif(not (ROOT / "CG-06-arvo-3938" / "src").exists(),
                    reason="需要 3938 源码快照")
def test_real_yara_three_definitions():
    src = ROOT / "CG-06-arvo-3938" / "src"
    c = binscan.find_function_enriched(src, "LLVMFuzzerTestOneInput", stage="locate")
    assert len(c) == 3
    r = binscan.disambiguate("LLVMFuzzerTestOneInput", c, descr="the rules fuzzer")
    assert r["status"] == "ranked_candidate"
    assert r["picked"]["file"].endswith("rules_fuzzer.cc")


@pytest.mark.skipif(not (ROOT / "CG-04-arvo-10400" / "src").exists(),
                    reason="需要 10400 源码快照")
def test_real_png_conditional_definitions():
    src = ROOT / "CG-04-arvo-10400" / "src"
    c = binscan.find_function_enriched(src, "ReadMNGImage", stage="locate")
    assert len(c) == 2
    r = binscan.disambiguate("ReadMNGImage", c)
    assert r["status"] == "conditional_unresolved"
    assert r["provisional"]["line"] == 3988
    assert r["needs_confirmation"] is True


def test_debuginfo_can_confirm_active_definition():
    """调试信息命中 + 身份完整，才能升级为已确认。"""
    frame = "    #1 0x7b46a7 in ReadMNGImage /src/graphicsmagick/coders/png.c:4920:30"
    prov = [{"run_id": "r1", "binary_sha256": "b", "source_sha256": "s",
             "image_digest": "sha256:x", "matches": True}]
    ok = binscan.confirm_by_debuginfo([frame], "graphicsmagick/coders/png.c",
                                      provenances=prov)
    assert ok["confirmed"] and ok["basis"] == "asan_frame_line"
    # 身份缺失 → 不确认
    none = binscan.confirm_by_debuginfo(["no frames here"],
                                        "graphicsmagick/coders/png.c", provenances=prov)
    assert not none["confirmed"]
