"""CG-17 / arvo:1065 严重性草案校验：六维证据 + 引用可解析 + CVSS 自洽。

重点不是"有文件"，而是：
1) 向量必须落在 AV:L（本地文件输入），不能出现 AV:N；
2) I:H 无实测就不得出现；
3) 六维 evidence 里的每条 文件:行 都必须真实存在；
4) cvss_base_score 与向量、以及敏感性表里的备选分数都要能复算。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S7-CG17-arvo-1065"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-1065.md"

DIMS = ("attack_vector", "privileges_required", "user_interaction",
        "observed_impact", "reachability_evidence", "deployment_conditions")

_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "PR": {"N": .85, "L": .62, "H": .27}, "UI": {"N": .85, "R": .62},
      "CIA": {"H": .56, "L": .22, "N": 0.0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss_base(vector):
    parts = dict(p.split(":") for p in vector.split("/")[1:])
    iss = 1 - ((1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]])
               * (1 - _W["CIA"][parts["A"]]))
    impact = 6.42 * iss if parts["S"] == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploit = (8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]]
               * _W["PR"][parts["PR"]] * _W["UI"][parts["UI"]])
    raw = impact + exploit
    return _roundup(min(raw, 10) if parts["S"] == "U" else min(1.08 * raw, 10))


def _sev():
    assert SEV.is_file(), f"缺少 {SEV}"
    return json.loads(SEV.read_text(encoding="utf-8"))


CITE = re.compile(r"([\w./-]+\.(?:log|c|cc|cpp|hh|hpp|json|txt)):(\d+)(?:-(\d+))?")


def test_draft_flags():
    d = _sev()
    assert d["final"] is False, "不得签 final=true"
    assert d["human_signoff_required"] is True
    assert d["reviewed_by"] == "agent"
    assert str(d.get("reviewed_at") or "").strip(), "reviewed_at 必填"
    # _status=DRAFT / _warning 会让 report 阶段判成未评估，任务明确禁止
    assert "_status" not in d and "_warning" not in d


def test_six_dimensions_have_value_and_evidence():
    d = _sev()
    assert set(d["dimensions"]) == set(DIMS)
    for name in DIMS:
        dim = d["dimensions"][name]
        assert str(dim.get("value") or "").strip(), f"{name} 缺 value"
        assert len(str(dim.get("evidence") or "")) >= 20, f"{name} evidence 过于空泛"


def test_vector_is_local_and_has_no_i_h():
    d = _sev()
    vec = d["cvss_vector"]
    assert vec.startswith("CVSS:3.1/")
    assert "/AV:L/" in vec, "本地文件输入必须是 AV:L（不得照抄 CG-12D 的 AV:N）"
    assert "/AV:N" not in vec
    assert "/I:H" not in vec, "I:H 无实测证据，不得出现"
    assert "/I:L/" in vec
    assert "/S:U" in vec


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 3.3) < 1e-9


def test_severity_label_matches_score():
    d = _sev()
    score = d["cvss_base_score"]
    label = d["severity"]
    expect = "low" if score < 4.0 else ("medium" if score < 7.0 else "high")
    assert label == expect, f"severity={label} 与分数 {score} 不一致（应为 {expect}）"


def test_every_dimension_citation_resolves():
    """核心：每条 文件:行 必须真实存在（不许空泛引用）。"""
    d = _sev()
    cites = []
    for name in DIMS:
        for path, start, end in CITE.findall(d["dimensions"][name]["evidence"]):
            cites.append((name, path, int(start), int(end) if end else int(start)))
    assert len(cites) >= 6, f"可解析引用过少：{cites}"
    for name, path, start, end in cites:
        f = ROOT / path
        assert f.is_file(), f"{name} 引用文件不存在: {path}"
        total = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
        assert 1 <= start <= end <= total, f"{name} 引用越界: {path}:{start}-{end}（共 {total} 行）"


def test_missing_dimensions_are_consistent():
    d = _sev()
    entries = d["missing_dimensions"]
    assert entries, "至少要列一条缺证据项"
    for entry in entries:
        dim, _, reason = entry.partition(":")
        assert dim in DIMS, f"非法维度 {dim}"
        assert len(reason) >= 10, f"{dim} 缺证据理由过短"
        assert d["dimensions"][dim]["value"] == "unproven", f"{dim} 列入缺失却不是 unproven"


def test_sensitivity_scores_recompute():
    """敏感性表里的备选分数必须同样可复算，不能手写数字。"""
    d = _sev()
    sens = d["sensitivity"]
    assert len(sens) >= 4
    for key, text in sens.items():
        m = re.search(r"(CVSS:3\.1/[^\s]+?)\s*=\s*(\d+(?:\.\d+)?)", text)
        assert m, f"{key} 缺向量或分数: {text}"
        vec, claimed = m.group(1), float(m.group(2))
        assert abs(cvss_base(vec) - claimed) < 1e-9, f"{key} 复算 {cvss_base(vec)} ≠ {claimed}"


def test_case_json_not_rewritten_by_draft():
    """草案不得回写 case.json（本轮只新增 severity.json）。"""
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    blob = json.dumps(case, ensure_ascii=False)
    assert "CVSS:3.1/AV:L" not in blob, "case.json 里出现了本草案的向量，说明被回写"
    assert (case.get("severity") or {}).get("state") == "unassessed"


def test_doc_covers_key_points():
    text = DOC.read_text(encoding="utf-8")
    for token in ("AV:L", "I:L", "3.3", "CG-12D", "CWE-457", "arvo:1065",
                  "final=false", "human_signoff_required"):
        assert token in text, f"文档缺 {token}"
    assert "softmagic.c:365" in text
    assert "pmatch" in text
