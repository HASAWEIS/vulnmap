"""locate 的路径归一化 + 缩进式定义兜底（S7 / arvo:368 现场）。

现场：模型给出 cff_blend_doBlend @ src/cff/cffload.c，
但仓库根在 src/freetype2/ 下，且定义行是 GNU 缩进排版，
旧实现判 function_not_found -> claims_llm=0。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.stages.locate import LocateStage  # noqa: E402


def _stage():
    """只测纯函数，绕开 Stage.__init__ 的 store/布局依赖。"""
    return object.__new__(LocateStage)


def _mk(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------- 路径归一化：唯一前缀命中 ----------

def test_unique_subdir_prefix_resolves(tmp_path):
    """src/freetype2/src/cff/cffload.c 存在，hint 是 src/cff/cffload.c -> 补前缀命中。"""
    src = tmp_path / "src"
    _mk(src, "freetype2/src/cff/cffload.c", "int x;\n")
    s = _stage()
    rel, tier, cands = s.resolve_repo_path(src, "src/cff/cffload.c")
    assert tier == "subdir_prefix"
    assert rel == "freetype2/src/cff/cffload.c"
    assert cands == [rel]


def test_direct_path_still_wins(tmp_path):
    """原路径就存在时不做任何改写（回归保护）。"""
    src = tmp_path / "src"
    _mk(src, "src/cff/cffload.c", "int x;\n")
    s = _stage()
    rel, tier, _ = s.resolve_repo_path(src, "src/cff/cffload.c")
    assert (rel, tier) == ("src/cff/cffload.c", "direct")


def test_unique_basename_fallback(tmp_path):
    """只有 basename 能对上、且唯一时接受，并给出 basename 级别。"""
    src = tmp_path / "src"
    _mk(src, "some/deep/dir/only.c", "int x;\n")
    s = _stage()
    rel, tier, _ = s.resolve_repo_path(src, "src/whatever/only.c")
    assert tier == "basename" and rel == "some/deep/dir/only.c"


def test_ambiguous_prefix_is_rejected(tmp_path):
    """两个子目录都能前缀命中 -> 歧义，必须返回 None，不许猜一个。"""
    src = tmp_path / "src"
    _mk(src, "projA/src/x.c", "int x;\n")
    _mk(src, "projB/src/x.c", "int x;\n")
    s = _stage()
    rel, tier, cands = s.resolve_repo_path(src, "src/x.c")
    assert rel is None and tier == "ambiguous"
    assert len(cands) == 2


def test_ambiguous_basename_is_rejected(tmp_path):
    src = tmp_path / "src"
    _mk(src, "a/foo.c", "int x;\n")
    _mk(src, "b/foo.c", "int x;\n")
    s = _stage()
    rel, tier, cands = s.resolve_repo_path(src, "src/not/there/foo.c")
    assert rel is None and tier == "ambiguous" and len(cands) == 2


def test_no_match_reports_not_found(tmp_path):
    src = tmp_path / "src"
    _mk(src, "a/foo.c", "int x;\n")
    s = _stage()
    rel, tier, cands = s.resolve_repo_path(src, "src/cff/nothing.c")
    assert (rel, tier, cands) == (None, "not_found", [])


def test_empty_hint_is_empty_tier(tmp_path):
    s = _stage()
    assert s.resolve_repo_path(tmp_path, "") == (None, "empty", [])


# ---------- 缩进式定义兜底 ----------

FREETYPE_LIKE = """#include <stdio.h>

  static void
  cff_blend_doBlend( int  numBlends,
                     int  parser )
  {
    int i;

    for ( i = 0; i < numBlends; i++ )
      cff_blend_doBlend( i, parser );
  }

  static int
  cff_parse_num( int  x )
  {
    return x;
  }
"""


def test_indented_definition_is_found(tmp_path):
    """GNU 缩进的定义（名字不顶格）也要能定位到，且行号是定义行。"""
    src = tmp_path / "src"
    _mk(src, "freetype2/src/cff/cffload.c", FREETYPE_LIKE)
    s = _stage()
    defs = s.find_definitions(src, "cff_blend_doBlend")
    assert len(defs) == 1, defs
    assert defs[0]["file"] == "freetype2/src/cff/cffload.c"
    assert defs[0]["line"] == 4
    assert defs[0]["source"] == "indent_tolerant_scan"


def test_call_site_is_not_mistaken_for_definition(tmp_path):
    """同名调用点（以 ); 结尾）不能被当成定义。"""
    src = tmp_path / "src"
    _mk(src, "a.c", "  int f( int n, int m )\n  {\n    return 0;\n  }\n\n"
                    "  void g( void )\n  {\n    f( 1, 2 );\n  }\n")
    s = _stage()
    defs = s.find_definitions(src, "f")
    assert [d["line"] for d in defs] == [1]


def test_prototype_is_skipped(tmp_path):
    src = tmp_path / "src"
    _mk(src, "a.c", "  int f( int n );\n")
    s = _stage()
    assert s.find_definitions(src, "f") == []


def test_missing_function_returns_empty(tmp_path):
    src = tmp_path / "src"
    _mk(src, "a.c", "int g( void ) { return 0; }\n")
    s = _stage()
    assert s.find_definitions(src, "cff_blend_doBlend") == []
