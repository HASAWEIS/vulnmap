"""因果链证据自证：两案例、引用行真实存在、每例 3-5 步、confirmed/inferred 不混。

背景：sink 只写「哪一行」不足以支撑根因。CG-10D / CG-12D 的说明书要求补
「输入字段 → 长度 → 写偏移」链条，且 inferred 不得冒充 confirmed。
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "CAUSAL-CG10D-CG12D.md"

CASE_A = "CG-10D"
CASE_B = "CG-12D"

# 关键锚点：行号 + 该行必须含的片段（防文档漂移后行号指到别处）
ANCHORS = [
    ("workspace/S5G-CG10/src/libredwg/src/header_variables_r11.spec", 145, "FIELD_TFF"),
    ("workspace/S5G-CG10/src/libredwg/src/out_json.c", 1323, "json_cquote"),
    ("workspace/S5G-CG10/src/libredwg/src/out_json.c", 1380, "*dest = 0"),
    ("workspace/S5G-CG10/src/libredwg/src/bits.c", 1459, "memcpy"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-ot-layout-common.hh", 289, "serialize_subset"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-machinery.hh", 649, "v[0]"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-machinery.hh", 650, "v[1]"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-subset.cc", 74, "alloc"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-open-type.hh", 251, "serialize_subset"),
    ("workspace/S5H-CG12/src/harfbuzz/src/hb-open-type.hh", 259, "src.subset"),
]

CITE = re.compile(r"(workspace/[A-Za-z0-9_./\-]+\.(?:c|cc|h|hh|spec)):(\d+)")
STEP_ROW = re.compile(r"^\|\s*(\d+)\s*\|(.+)$")


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.is_file(), "缺少 docs/CAUSAL-CG10D-CG12D.md"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def sections(text) -> dict:
    """按「## 案例 …」切段，返回 {case_id: 段落文本}。"""
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith("## 案例"):
            if cur:
                out[cur] = "\n".join(buf)
            m = re.search(r"(CG-\d+D)", line)
            cur = m.group(1) if m else line
            buf = [line]
        else:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf)
    return out


def _line(path: str, n: int) -> str:
    f = ROOT / path
    assert f.is_file(), f"{path} 不存在"
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert 1 <= n <= len(lines), f"{path}:{n} 越界（文件只有 {len(lines)} 行）"
    return lines[n - 1]


# --------------------------------------------------------------------------- #
# A. 覆盖与结构
# --------------------------------------------------------------------------- #
def test_doc_covers_both_cases(text, sections):
    assert CASE_A in text and CASE_B in text
    assert CASE_A in sections and CASE_B in sections, f"缺少案例小节：{list(sections)}"
    assert "harfbuzz" in text and "libredwg" in text


def test_each_case_has_three_to_five_steps(sections):
    for cid in (CASE_A, CASE_B):
        rows = [STEP_ROW.match(ln) for ln in sections[cid].splitlines()]
        steps = [r for r in rows if r and "confirmed" in r.group(2) or (r and "inferred" in r.group(2))]
        numbered = [int(r.group(1)) for r in steps]
        assert len(numbered) >= 3, f"{cid} 只有 {len(numbered)} 步，要求至少 3 步"
        assert len(numbered) <= 5, f"{cid} 有 {len(numbered)} 步，超过 5 步上限"
        assert numbered == list(range(1, len(numbered) + 1)), f"{cid} 步骤编号不连续：{numbered}"


def test_status_only_confirmed_or_inferred(sections):
    for cid in (CASE_A, CASE_B):
        for ln in sections[cid].splitlines():
            r = STEP_ROW.match(ln)
            if not r:
                continue
            cell = r.group(2)
            has_conf = "confirmed" in cell
            has_inf = "inferred" in cell
            assert has_conf or has_inf, f"{cid} 步骤缺状态标记：{ln[:60]}"
            assert not (has_conf and has_inf), f"{cid} 一步同时标 confirmed 与 inferred：{ln[:60]}"


# --------------------------------------------------------------------------- #
# B. 引用行必须真实存在
# --------------------------------------------------------------------------- #
def test_every_citation_resolves(text):
    cites = CITE.findall(text)
    assert len(cites) >= 12, f"引用太少（{len(cites)}），不足以支撑 2×3 步"
    for path, n in cites:
        _line(path, int(n))  # 内部断言：存在、不越界


def test_cited_lines_are_not_blank(text):
    for path, n in CITE.findall(text):
        assert _line(path, int(n)).strip(), f"{path}:{n} 是空行，引用无效"


def test_each_step_cites_at_least_one_line(sections):
    for cid in (CASE_A, CASE_B):
        for ln in sections[cid].splitlines():
            r = STEP_ROW.match(ln)
            if not r or not ("confirmed" in r.group(2) or "inferred" in r.group(2)):
                continue
            assert CITE.search(ln), f"{cid} 第 {r.group(1)} 步没有 workspace/…:行号 引用"


def test_anchor_lines_still_contain_expected_code():
    for path, n, needle in ANCHORS:
        line = _line(path, n)
        assert needle in line, f"{path}:{n} 期望含 {needle!r}，实际：{line.strip()[:80]}"


# --------------------------------------------------------------------------- #
# C. confirmed / inferred 不许混说
# --------------------------------------------------------------------------- #
def test_inferred_is_declared_not_laundered(text, sections):
    """inferred 必须显式列出并带翻案条件，不能悄悄写成结论。"""
    assert "inferred" in text
    assert "翻案条件" in text, "inferred 必须写翻案条件"
    for cid in (CASE_A, CASE_B):
        assert "inferred" in sections[cid], f"{cid} 没有标注任何 inferred（要么真没有，要么漏标）"


def test_confirmed_steps_are_frame_backed(sections):
    """confirmed 步骤必须能落到源码行；CG-10D 第 5 步这类只有函数级证据的必须是 inferred。"""
    a = sections[CASE_A]
    row5 = [ln for ln in a.splitlines() if STEP_ROW.match(ln) and STEP_ROW.match(ln).group(1) == "5"]
    assert row5, "CG-10D 缺第 5 步"
    assert "inferred" in row5[0], "CG-10D 第 5 步（终止符具体行号无 ASAN 行号）必须标 inferred"


def test_doc_does_not_claim_scores_changed(text):
    """只补证据：文档必须写明不改 case.json / LEDGER。"""
    assert "不改" in text and "case.json" in text
