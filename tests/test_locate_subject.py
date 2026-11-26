"""locate 口径：subject=责任方，ASAN 首帧只是受害者。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.tools import binscan


def test_read_lines_ignores_formfeed():
    """\\x0c 不是换行：splitlines() 会让 png.c 行号漂移 10 行。"""
    import tempfile
    with tempfile.NamedTemporaryFile("wb", suffix=".c", delete=False) as fh:
        fh.write(b"a\nb\x0cc\nd\n")
        p = Path(fh.name)
    assert binscan.read_lines(p) == ["a", "b\x0cc", "d"]
    p.unlink()


def test_read_lines_strips_only_trailing_newline():
    import tempfile
    with tempfile.NamedTemporaryFile("wb", suffix=".c", delete=False) as fh:
        fh.write(b"x\ny\n")
        p = Path(fh.name)
    lines = binscan.read_lines(p)
    assert lines == ["x", "y"], lines
    p.unlink()


def test_find_function_multiline_signature(tmp_path):
    f = tmp_path / "a.c"
    f.write_text("static int\nfoo(pdf_context *c,\n    int b)\n{\n  return 0;\n}\n")
    hits = binscan.find_function(tmp_path, "foo", stage="locate")
    assert hits and hits[0]["line"] == 2


def test_find_function_skips_prototype(tmp_path):
    f = tmp_path / "a.c"
    f.write_text("int foo(int a);\n")
    assert binscan.find_function(tmp_path, "foo", stage="locate") == []


def test_function_body_bounds(tmp_path):
    f = tmp_path / "a.c"
    f.write_text("int foo(int a)\n{\n  x();\n  return 0;\n}\n\nint bar(void)\n{\n}\n")
    body = binscan.function_body(f, 1, stage="locate")
    assert body[0] == 1 and body[-1] == 5


def test_symbol_at_returns_call_name(tmp_path):
    """有行号时 symbol 必须非空（审查方 ① 条）。"""
    from agent.stages.locate import LocateStage
    f = tmp_path / "a.c"
    f.write_text("int foo(int a)\n{\n  memcpy(dst, src, n);\n}\n")
    st = LocateStage.__new__(LocateStage)
    assert st._symbol_at(f, 3) == "memcpy"
