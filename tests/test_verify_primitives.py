"""容器构造与判定相关的单测。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.stages.verify import make_mng, pdf_with_basefont
from agent.tools.binscan import detect_magic


def test_mng_magic_and_size():
    data = make_mng(4)
    assert detect_magic(data) == "mng"
    assert len(data) == 143


def test_mng_without_filler_is_not_valid_container():
    assert len(make_mng(4, filler=False)) < len(make_mng(4, filler=True))


def test_pdf_magic():
    data = pdf_with_basefont(b"A" * 32)
    assert detect_magic(data) == "pdf"
    assert b"/BaseFont /" in data
