"""CG-18 / arvo:12420 严重性草案校验：六维证据 + 引用可解析 + CVSS 自洽 + 禁 AV:N。

本案例的定级要点：输入是本地文件 → 必须 AV:L；越界写有实测 → I:H 成立；
因此测试同时钉住"不许出现 AV:N"与"必须有 I:H/A:H"，并复算敏感性表里的每个备选分数。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S7-CG18-arvo-12420"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-12420.md"

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
NETWORK_MARKERS = ("socat", "listen(", "bind(", "0.0.0.0", "tcp:", "http://", "https://")


def test_draft_flags():
    d = _sev()
    assert d["final"] is False
    assert d["human_signoff_required"] is True
    assert d["reviewed_by"] == "agent"
    assert str(d.get("reviewed_at") or "").strip()
    assert "_status" not in d and "_warning" not in d


def test_six_dimensions_have_value_and_evidence():
    d = _sev()
    assert set(d["dimensions"]) == set(DIMS)
    for name in DIMS:
        dim = d["dimensions"][name]
        assert str(dim.get("value") or "").strip(), f"{name} 缺 value"
        assert len(str(dim.get("evidence") or "")) >= 20, f"{name} evidence 过于空泛"


def test_vector_is_local_and_impact_is_high():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec, "本地文件输入必须是 AV:L"
    assert "/AV:N" not in vec, "无网络入口证据时禁止 AV:N"
    assert "/I:H/" in vec, "越界写有实测，I:H 应成立"
    assert vec.endswith("/A:H"), "ASAN 下 exit=1 终止，A:H 应成立"
    assert "/C:N/" in vec


def test_no_network_evidence_in_logs():
    """禁 AV:N 的前提要能被检查：证据日志里不该出现网络入口标记。"""
    d = _sev()
    head = d["dimensions"]["attack_vector"]["evidence"].split(" —— ")[0]
    log = ROOT / head.split(":")[0]
    assert log.is_file(), log
    text = log.read_text(encoding="utf-8", errors="ignore").lower()
    for marker in NETWORK_MARKERS:
        assert marker not in text, f"日志里出现网络标记 {marker}，AV:N 假设需重新评估"
    assert "/tmp/poc" in text


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 7.1) < 1e-9


def test_severity_label_matches_score():
    d = _sev()
    score = d["cvss_base_score"]
    expect = "low" if score < 4.0 else ("medium" if score < 7.0 else "high")
    assert d["severity"] == expect


def test_every_dimension_citation_resolves():
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
    assert entries
    for entry in entries:
        dim, _, reason = entry.partition(":")
        assert dim in DIMS
        assert len(reason) >= 10
        assert d["dimensions"][dim]["value"] == "unproven", f"{dim} 列入缺失却不是 unproven"


def test_sensitivity_scores_recompute_and_av_n_is_flagged_forbidden():
    d = _sev()
    sens = d["sensitivity"]
    assert len(sens) >= 5
    for key, text in sens.items():
        m = re.search(r"(CVSS:3\.1/[^\s]+?)\s*=\s*(\d+(?:\.\d+)?)", text)
        assert m, f"{key} 缺向量或分数: {text}"
        vec, claimed = m.group(1), float(m.group(2))
        assert abs(cvss_base(vec) - claimed) < 1e-9, f"{key} 复算 {cvss_base(vec)} ≠ {claimed}"
    av_n = [v for k, v in sens.items() if "/AV:N/" in v]
    assert av_n, "敏感性表应显式列出被禁止的 AV:N 对照"
    assert any("禁止" in v for v in av_n), "AV:N 备选必须标注为禁止"


def test_case_json_not_rewritten_by_draft():
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        # 允许“显式 severity.json 合并”，但必须有签署记录，且不是草案自动写入
        rec = json.loads((WS / "severity.json").read_text(encoding="utf-8"))
        assert rec.get("reviewed_by") and rec.get("reviewed_at")
        assert rec.get("cvss_vector") == sev.get("cvss_vector")
    else:
        assert sev.get("state") == "unassessed"


def test_doc_covers_key_points():
    text = DOC.read_text(encoding="utf-8")
    for token in ("AV:L", "I:H", "A:H", "7.1", "CWE-122", "arvo:12420",
                  "strcpy", "63", "final=false", "human_signoff_required"):
        assert token in text, f"文档缺 {token}"
    assert "lookup.c:621" in text
    assert "禁止" in text or "AV:N" in text
