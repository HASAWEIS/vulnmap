"""closeout 自证：4 份因果链文档合格、引用行真实、MATERIALS 覆盖 9 个高危。

背景：closeout 阶段最怕「文档写得漂亮但行号是编的」和「清单漏案例」。
本测试只做可复算的机械核对，不评价论证质量。
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
WS = ROOT / "workspace"

CAUSAL_DOCS = {
    "CG-29": DOCS / "CAUSAL-CG29.md",
    "CG-30": DOCS / "CAUSAL-CG30.md",
    "CG-31": DOCS / "CAUSAL-CG31.md",
    "CG-36": DOCS / "CAUSAL-CG36.md",
}
MATERIALS = DOCS / "MATERIALS.md"

CITE = re.compile(r"(workspace/[A-Za-z0-9_./\-]+\.(?:c|cc|cpp|h|hh|in|spec|diff)):(\d+)")
STEP_ROW = re.compile(r"^\|\s*(\d+)\s*\|(.+)$")

# 每份文档至少要有这些「真正的写点」引用，且该行内容要对得上
ANCHORS = {
    "CG-29": [
        ("workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c", 2424, "window_buf["),
        ("workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c", 1826, "window_mask"),
        ("workspace/S14-CG29-arvo-11011/src/libarchive/libarchive/archive_read_support_format_rar5.c", 1834, "calloc"),
    ],
    "CG-30": [
        ("workspace/S15-CG30-arvo-29633/src/fio/filesetup.c", 1656, "sprintf"),
        ("workspace/S15-CG30-arvo-29633/src/fio/filesetup.c", 1646, "file_name[PATH_MAX]"),
        ("workspace/S15-CG30-arvo-29633/src/fio/options.c", 1320, "add_file"),
    ],
    "CG-31": [
        ("workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp", 208, "BrotliDecoderDecompressStream"),
        ("workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp", 205, "available_out"),
        ("workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp", 204, "alloc"),
        ("workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp", 212, "uncompressedLen *= 2"),
        ("workspace/S16-CG31-arvo-61675/src/exiv2/src/bmffimage.cpp", 217, "131072"),
    ],
    "CG-36": [
        ("workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c", 275, "tbl->size"),
        ("workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c", 274, "section[id]"),
        ("workspace/S19-CG36-arvo-54839/src/libredwg/src/decode.c", 729, "calloc"),
    ],
}


def _line(path: str, n: int) -> str:
    f = ROOT / path
    assert f.is_file(), f"{path} 不存在"
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert 1 <= n <= len(lines), f"{path}:{n} 越界（文件只有 {len(lines)} 行）"
    return lines[n - 1]


def _chain(text: str) -> str:
    m = re.search(r"## 传播链.*?\n(.*?)(?=\n## )", text, re.S)
    assert m, "缺「## 传播链」小节"
    return m.group(1)


def _high_cases() -> list[dict]:
    """按 workspace 实况算 9 个高危（不写死列表，anti-rot）。"""
    out = []
    for d in sorted(WS.iterdir()):
        cp = d / "artifacts" / "report" / "case.json"
        if not cp.is_file():
            continue
        c = json.loads(cp.read_text(encoding="utf-8"))
        if (c.get("acceptance") or {}).get("high_severity_confirmed"):
            out.append({"case_id": c.get("case_id"), "task_id": c.get("task_id"), "dir": d.name})
    return out


# --------------------------------------------------------------------------- #
# A. 4 份因果链文档
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cid", sorted(CAUSAL_DOCS))
def test_causal_doc_exists(cid):
    p = CAUSAL_DOCS[cid]
    assert p.is_file(), f"缺少 {p.relative_to(ROOT)}"
    assert cid in p.read_text(encoding="utf-8"), f"{p.name} 里没提 {cid}"


@pytest.mark.parametrize("cid", sorted(CAUSAL_DOCS))
def test_causal_doc_has_3_to_5_steps(cid):
    text = CAUSAL_DOCS[cid].read_text(encoding="utf-8")
    rows = [STEP_ROW.match(ln) for ln in _chain(text).splitlines()]
    nums = [int(r.group(1)) for r in rows
            if r and ("confirmed" in r.group(2) or "inferred" in r.group(2))]
    assert len(nums) >= 3, f"{cid} 只有 {len(nums)} 步"
    assert len(nums) <= 5, f"{cid} 有 {len(nums)} 步，超过 5 步上限"
    assert nums == list(range(1, len(nums) + 1)), f"{cid} 步骤编号不连续：{nums}"


@pytest.mark.parametrize("cid", sorted(CAUSAL_DOCS))
def test_causal_doc_status_discipline(cid):
    text = CAUSAL_DOCS[cid].read_text(encoding="utf-8")
    for ln in _chain(text).splitlines():
        m = STEP_ROW.match(ln)
        if not m:
            continue
        has_c, has_i = "confirmed" in m.group(2), "inferred" in m.group(2)
        assert has_c != has_i, f"{cid} 第 {m.group(1)} 步状态标记异常：{ln[:60]}"
    assert "inferred" in text, f"{cid} 没有 inferred 小节（要么真没有，要么漏标）"


@pytest.mark.parametrize("cid", sorted(CAUSAL_DOCS))
def test_causal_doc_citations_resolve(cid):
    text = CAUSAL_DOCS[cid].read_text(encoding="utf-8")
    cites = CITE.findall(text)
    assert len(cites) >= 3, f"{cid} 引用太少（{len(cites)}）"
    for path, n in cites:
        assert _line(path, int(n)).strip(), f"{cid}: {path}:{n} 是空行"


@pytest.mark.parametrize("cid", sorted(CAUSAL_DOCS))
def test_causal_doc_anchor_lines(cid):
    """锚点：文档引用的关键行必须真的是那段代码，不能指到别处。"""
    for path, n, needle in ANCHORS[cid]:
        line = _line(path, n)
        assert needle in line, f"{cid}: {path}:{n} 期望含 {needle!r}，实际 {line.strip()[:60]}"


def test_causal_docs_claim_no_score_change():
    for cid, p in CAUSAL_DOCS.items():
        text = p.read_text(encoding="utf-8")
        assert "case.json" in text and ("不改" in text or "不动" in text), f"{cid} 没写明不改成绩"


# --------------------------------------------------------------------------- #
# B. MATERIALS 覆盖 9 个高危
# --------------------------------------------------------------------------- #
def test_materials_exists_with_headers():
    assert MATERIALS.is_file(), "缺少 docs/MATERIALS.md"
    text = MATERIALS.read_text(encoding="utf-8")
    for col in ("日志", "PoC", "报告", "CWE", "危害", "模型参数"):
        assert col in text, f"MATERIALS 缺列：{col}"


def test_materials_covers_nine_high_cases():
    text = MATERIALS.read_text(encoding="utf-8")
    high = _high_cases()
    assert len(high) == 9, f"高危案例数为 {len(high)}，与台账 9 不符：{[h['case_id'] for h in high]}"
    missing = [h["case_id"] for h in high if h["case_id"] not in text]
    assert not missing, f"MATERIALS 漏了这些高危案例：{missing}"


def test_materials_lists_each_workspace():
    text = MATERIALS.read_text(encoding="utf-8")
    missing = [h["dir"] for h in _high_cases() if h["dir"] not in text]
    assert not missing, f"MATERIALS 没写这些 workspace：{missing}"


def test_materials_names_real_gaps():
    """缺口必须点名，而不是一句「部分齐备」带过。

    注：VG-01 的 日志/PoC/报告 四项已在 s23b 补齐（poc/request.sh + logs + report.md），
    因此这里校验的是「补了之后仍缺什么」——逐例采样参数与源码树，而不是旧的缺日志。
    """
    text = MATERIALS.read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines() if ln.startswith("| VG-01 |")]
    assert rows, "MATERIALS 没有 VG-01 行"
    row = rows[0]
    assert "poc/request.sh" in row, "VG-01 行没写真实 PoC 实体"
    assert "采样参数" in row, "VG-01 行没标出仍缺的逐例采样参数"
    assert "MODEL-PARAMS" in text or "FREEZE.json" in text, "模型参数缺口要指向明细/全局记录"


def test_materials_has_summary_and_bottom_line():
    text = MATERIALS.read_text(encoding="utf-8")
    assert "## 汇总" in text
    assert "## 逐例缺口" in text
