"""口径回归：人工验证包不得被当成严格 V2 提交包。

背景：AR6/AR7 是"源码分析 + 手工 PoC + docker 双端"的人工验证包，包内自写复算器
通过；但冻结包判据要求 Agent 事件流（JSONL + seq 连续）、源数据库导出、
judgments/、review.layers、MANIFEST.json / SHA256SUMS。用冻结实现复核两份包
在完整性门即被拒。

本测试锁三件事：
1. 若两份包存在，冻结实现 verify() 必须返回 strict_submittable=False；
2. 口径文档必须写明严格数 5、人工验证包 2；
3. 仓库台账/处置不得把 AR6/AR7 记成严格提交。
"""
from __future__ import annotations

import importlib.util
import re
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKS = {
    "AR6": Path("/home/root_bupt/桌面/file/课程提交包_20261127/AR6"),
    "AR7": Path("/home/root_bupt/桌面/file/课程提交包_20261127/AR7"),
}
RECHECK = ROOT / "experiments" / "strict-v2-recheck-ar6-ar7.json"
DOC = ROOT / "docs" / "STRICT-V2-RECHECK-20261127.md"


def _verifier():
    pv = ROOT / "experiments" / "submission-pack" / "pack_verify.py"
    spec = importlib.util.spec_from_file_location("pack_verify_scope", pv)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pack_verify_scope"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", sorted(PACKS))
def test_manual_packs_are_not_strict_v2(name):
    pack = PACKS[name]
    if not pack.is_dir():
        pytest.skip(f"{name} 包不在本机，跳过")
    res = _verifier().verify(pack)
    assert res.get("strict_submittable") is False, (
        f"{name} 被冻结判据判为 strict=True，口径需重新审定，不能默认放行")
    assert res.get("errors"), f"{name} 应有明确拒收原因"


def test_recheck_record_says_five_strict():
    assert RECHECK.is_file(), "缺严格复核机读记录"
    data = json.loads(RECHECK.read_text(encoding="utf-8"))
    assert data["strict_count"] == 0, "复核记录里这两份包不应为 strict"
    for name in PACKS:
        case = data["cases"].get(name)
        assert case and case.get("strict") is False, f"{name} 复核结论被改写"


def test_doc_states_strict_five_and_two_manual():
    assert DOC.is_file()
    text = DOC.read_text(encoding="utf-8")
    assert "**5**" in text, "文档必须写明严格 V2 提交包为 5"
    assert "人工验证包" in text
    assert "未通过严格 V2" in text or "未通过严格 V2 复核" in text


def test_disposition_counts_do_not_inflate():
    d = json.loads((ROOT / "experiments" / "gap-disposition.json").read_text(encoding="utf-8"))
    counts = d.get("counts") or {}
    assert counts.get("strict_v2_packs") == 5, counts
    assert counts.get("materials_recompute_ok") == 7, counts
    assert sorted(counts.get("manual_packs_reference_only") or []) == ["AR6", "AR7"]


# ---------------------------------------------------------------- 案例文档口径
CASE_DOCS = [
    ROOT / "docs" / "CASE6-AR6-20261127.md",
    ROOT / "docs" / "CASE7-AR7-20261127.md",
    ROOT / "docs" / "COURSE-GAP-DISPOSITION.md",
]

#: 旧结论的书面形式；出现即必须同时带撤销标记（或删除线）
STALE_PATTERNS = [
    r"严格可提交（V2 内部）\s*\|\s*\*\*true\*\*",
    r"可提交\s*[67]/10",
    r"（[67]/10）",
    r"（[67] / 10）",
    r"下一轮[^\n]*7/10",
    r"5\s*→\s*[67]",
    r"6\s*已可提交",
]


@pytest.mark.parametrize("doc", CASE_DOCS, ids=lambda p: p.name)
def test_no_unrevoked_stale_counts(doc):
    """旧结论允许保留作历史，但必须就地标为已撤销。"""
    if not doc.is_file():
        pytest.skip(f"{doc.name} 不存在")
    lines = doc.read_text(encoding="utf-8").splitlines()
    offenders = []
    for i, line in enumerate(lines):
        for pat in STALE_PATTERNS:
            if not re.search(pat, line):
                continue
            window = "\n".join(lines[max(0, i - 2): i + 3])
            if "撤销" in window or "~~" in line:
                continue
            offenders.append(f"{doc.name}:{i + 1}: {line.strip()[:80]}")
    assert not offenders, "存在未标注撤销的旧口径：" + "; ".join(offenders)


@pytest.mark.parametrize("doc", CASE_DOCS, ids=lambda p: p.name)
def test_case_doc_mentions_strict_five(doc):
    """每份案例/处置文档都必须能把人引到「严格 5」这个当前结论。"""
    if not doc.is_file():
        pytest.skip(f"{doc.name} 不存在")
    text = doc.read_text(encoding="utf-8")
    assert ("严格可提交仍为 **5**" in text
            or "严格可提交为 **5/10**" in text
            or "严格 V2 提交包" in text
            or "STRICT-V2-RECHECK-20261127.md" in text), \
        f"{doc.name} 没有指向当前严格口径（5）"
