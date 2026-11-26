"""CG-18（libidn2 arvo:12420）因果链自证：文档齐全、引用行真实、confirmed/inferred 不混。

背景：sink 写 lookup.c:621 只说「哪一行爆」，说不出「输入怎么变成 66 字节写」。
本测试把文档里的每条引用回算到源码树，并把 PoC 解析结果与文档的数字对齐。
"""
import re
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "CAUSAL-CG18.md"
POC = ROOT / "workspace" / "S7-CG18-arvo-12420" / "artifacts" / "verify" / "libidn2-4i-65.bin"

# 关键锚点：行号 + 该行必须含的片段（防文档漂移后行号指到别处）
ANCHORS = [
    ("workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c", 67, "malloc(64)"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/fuzz/libidn2_to_ascii_8z_fuzzer.c", 73, "idn2_to_ascii_4i"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 602, "u32_to_u8"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 611, "idn2_lookup_u8"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 620, "if (output)"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 621, "strcpy"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 452, "lookupnamelen"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 453, "IDN2_DOMAIN_MAX_LENGTH"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/lookup.c", 83, "IDN2_LABEL_MAX_LENGTH"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/idn2.h.in", 137, "IDN2_LABEL_MAX_LENGTH 63"),
    ("workspace/S7-CG18-arvo-12420/src/libidn2/lib/idn2.h.in", 148, "IDN2_DOMAIN_MAX_LENGTH 255"),
]

CITE = re.compile(r"(workspace/[A-Za-z0-9_./\-]+\.(?:c|cc|h|hh|in|spec)):(\d+)")
STEP_ROW = re.compile(r"^\|\s*(\d+)\s*\|(.+)$")


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.is_file(), "缺少 docs/CAUSAL-CG18.md"
    return DOC.read_text(encoding="utf-8")


def _line(path: str, n: int) -> str:
    f = ROOT / path
    assert f.is_file(), f"{path} 不存在"
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert 1 <= n <= len(lines), f"{path}:{n} 越界（文件只有 {len(lines)} 行）"
    return lines[n - 1]


def _chain_section(text: str) -> str:
    """取「## 传播链」到下一个二级标题之间的正文。"""
    m = re.search(r"## 传播链.*?\n(.*?)(?=\n## )", text, re.S)
    assert m, "文档缺少「## 传播链」小节"
    return m.group(1)


# --------------------------------------------------------------------------- #
# A. 覆盖与结构
# --------------------------------------------------------------------------- #
def test_doc_mentions_cg18_and_case(text):
    assert "CG-18" in text
    assert "arvo:12420" in text and "libidn2" in text
    assert "idn2_to_ascii_4i" in text


def test_chain_has_at_least_three_steps(text):
    steps = [STEP_ROW.match(ln) for ln in _chain_section(text).splitlines()]
    nums = [int(m.group(1)) for m in steps if m and ("confirmed" in m.group(2) or "inferred" in m.group(2))]
    assert len(nums) >= 3, f"传播链只有 {len(nums)} 步，要求至少 3 步"
    assert len(nums) <= 5, f"传播链 {len(nums)} 步，超过 5 步上限"
    assert nums == list(range(1, len(nums) + 1)), f"步骤编号不连续：{nums}"


def test_status_only_confirmed_or_inferred(text):
    for ln in _chain_section(text).splitlines():
        m = STEP_ROW.match(ln)
        if not m:
            continue
        cell = m.group(2)
        assert ("confirmed" in cell) != ("inferred" in cell), f"状态标记缺失或重复：{ln[:70]}"


# --------------------------------------------------------------------------- #
# B. 引用行必须真实存在
# --------------------------------------------------------------------------- #
def test_every_citation_resolves(text):
    cites = CITE.findall(text)
    assert len(cites) >= 6, f"引用太少（{len(cites)}），不足以支撑一条数据流链"
    for path, n in cites:
        _line(path, int(n))
        assert _line(path, int(n)).strip(), f"{path}:{n} 是空行，引用无效"


def test_each_step_cites_a_source_line(text):
    for ln in _chain_section(text).splitlines():
        m = STEP_ROW.match(ln)
        if not m or not ("confirmed" in m.group(2) or "inferred" in m.group(2)):
            continue
        assert CITE.search(ln), f"第 {m.group(1)} 步没有 workspace/…:行号 引用"


def test_anchor_lines_still_contain_expected_code():
    for path, n, needle in ANCHORS:
        line = _line(path, n)
        assert needle in line, f"{path}:{n} 期望含 {needle!r}，实际：{line.strip()[:70]}"


# --------------------------------------------------------------------------- #
# C. 数字必须与 PoC 实测一致
# --------------------------------------------------------------------------- #
def test_poc_is_two_labels_of_32_codepoints():
    """文档说「两个 label 各 32 字符 → 65 码点」，必须能被 PoC 逐字节复算。"""
    blob = POC.read_bytes()
    assert len(blob) % 4 == 0
    cps = struct.unpack("<%dI" % (len(blob) // 4), blob)
    assert len(cps) == 65, f"码点数 {len(cps)} ≠ 文档的 65"
    labels, cur = [], []
    for c in cps:
        if c == 0x2E:
            labels.append(cur)
            cur = []
        else:
            cur.append(c)
    labels.append(cur)
    assert [len(l) for l in labels] == [32, 32], f"label 长度 {[len(l) for l in labels]} ≠ [32, 32]"


def test_doc_states_66_bytes_into_64(text):
    assert "66" in text and "64" in text
    assert "65" in text
    # 75+1 = 66 与 65 字符的算术关系必须写出来，不能只丢数字
    assert re.search(r"65\s*\+\s*1\s*=\s*66", text) or "65 字符 + NUL" in text, "缺少 65+1=66 的算术说明"


def test_doc_declares_deployment_gap_as_inferred(text):
    """lead 明确要求：deployment 调用点未知必须写成 inferred。"""
    assert "inferred" in text
    assert "deployment" in text or "调用点" in text
    seg = text.split("## inferred", 1)
    assert len(seg) == 2, "缺少 inferred 清单小节"
    assert "调用点" in seg[1] or "deployment" in seg[1]


def test_doc_claims_no_score_change(text):
    assert "case.json" in text and "LEDGER" in text
    assert "不改" in text or "不动" in text
