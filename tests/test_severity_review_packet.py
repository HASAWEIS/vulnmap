"""严重性人工复核包（review_v2）结构校验：三问判断 + 引用可解析 + CVSS 自洽。

复核包的核心不是"写得多"，而是每条判断都能回到日志行；
因此本测试会**逐条解析 evidence 里的 path:line 并检查该行确实存在**。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKET = ROOT / "experiments" / "severity" / "review_v2.json"
DOC = ROOT / "docs" / "SEVERITY-REVIEW-PACKET.md"

CASES = {"CG-10D": "workspace/S5G-CG10", "CG-12D": "workspace/S5H-CG12",
         "CG-07": "workspace/CG-07-arvo-10096", "CG-14": "workspace/CG-14-arvo-11253"}
SEV_FILES = {k: Path(v) / "severity.json" for k, v in CASES.items()}

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


def _packet():
    assert PACKET.is_file(), f"missing {PACKET}"
    return json.loads(PACKET.read_text(encoding="utf-8"))


def _evidence_texts(case):
    out = []
    for check in (case.get("checks") or {}).values():
        out.extend(check.get("evidence") or [])
    return out


CITE = re.compile(r"([\w./-]+\.(?:log|c|cc|cpp|hh|hpp|json|txt)):(\d+)(?:-(\d+))?")


def test_packet_and_doc_exist():
    assert PACKET.is_file()
    assert DOC.is_file(), "验收要求 docs/SEVERITY-REVIEW-PACKET.md 存在"


def test_never_signed_final():
    d = _packet()
    assert d["schema"] == "vulnmap.severity_review.v2"
    assert d["final"] is False
    assert d["human_signoff_required"] is True
    for name, case in d["cases"].items():
        assert case.get("final") is False, f"{name} 不得签 final=true"


def test_four_cases_with_required_fields():
    d = _packet()
    assert set(d["cases"]) == set(CASES)
    for name, case in d["cases"].items():
        assert case["workspace"] == CASES[name]
        assert case["task_id"].startswith("arvo:")
        assert Path(ROOT / case["severity_json"]).is_file(), case["severity_json"]
        for check in ("attack_vector_network", "user_interaction_required", "integrity_high"):
            assert check in case["checks"], f"{name} 缺 {check}"
        assert case["missing_evidence"], f"{name} 缺 missing_evidence"
        assert case["verdict"] in ("keep", "downgrade")


def test_recommended_score_matches_vector():
    for name, case in _packet()["cases"].items():
        score = cvss_base(case["recommended_vector"])
        assert abs(score - case["recommended_score"]) < 1e-9, (
            f"{name} 建议向量 {case['recommended_vector']} 复算 {score} ≠ {case['recommended_score']}")
        assert cvss_base(case["claimed"]["cvss_vector"]) == case["claimed"]["score"]


def test_verdict_matches_threshold():
    for name, case in _packet()["cases"].items():
        score = case["recommended_score"]
        if case["verdict"] == "downgrade":
            assert score < 7.0, f"{name} 判 downgrade 但分数 {score} 已过门槛"
        else:
            assert score >= 7.0, f"{name} 判 keep 但分数 {score} 低于门槛"


def test_av_network_always_rejected_and_recommended_local():
    """四例都判 AV:N 不成立；建议向量必须落在 AV:L。"""
    for name, case in _packet()["cases"].items():
        assert case["claimed"]["cvss_vector"].split("/")[1] == "AV:N"
        chk = case["checks"]["attack_vector_network"]
        assert chk["supported"] is False, f"{name} 不应判 AV:N 成立"
        assert chk["recommended"] == "local"
        assert "/AV:L/" in case["recommended_vector"]


def test_ui_r_is_labelled_assumption():
    for name, case in _packet()["cases"].items():
        chk = case["checks"]["user_interaction_required"]
        assert chk["supported"] == "assumption_only", f"{name} UI:R 应标为假设"
        assert chk["recommended"] == "keep_required_conservative"


def test_i_h_judgement_consistent_with_evidence():
    d = _packet()["cases"]
    assert d["CG-10D"]["checks"]["integrity_high"]["supported"] is False
    assert d["CG-12D"]["checks"]["integrity_high"]["supported"] is False
    assert d["CG-07"]["checks"]["integrity_high"]["supported"] is True
    assert d["CG-14"]["checks"]["integrity_high"]["supported"] is True
    # I:H 不成立的例子必须把建议向量写成 I:L
    for name in ("CG-10D", "CG-12D"):
        assert d[name]["checks"]["integrity_high"]["recommended"] == "I:L"
        assert "/I:L/" in d[name]["recommended_vector"]


def test_every_citation_resolves_to_a_real_line():
    """核心测试：evidence 里每条 path:line 必须真的存在（不许空泛引用）。"""
    for name, case in _packet()["cases"].items():
        cites = []
        for text in _evidence_texts(case):
            for path, line, line2 in CITE.findall(text):
                cites.append((path, int(line), int(line2) if line2 else int(line)))
        assert len(cites) >= 3, f"{name} 可解析引用过少：{cites}"
        for path, start, end in cites:
            f = ROOT / path
            assert f.is_file(), f"{name} 引用文件不存在: {path}"
            total = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            assert start >= 1 and end <= total, f"{name} 引用越界: {path}:{start}-{end}（共 {total} 行）"


def test_missing_evidence_is_specific():
    for name, case in _packet()["cases"].items():
        items = case["missing_evidence"]
        assert len(items) >= 3, f"{name} 缺证据条目过少"
        for item in items:
            assert len(item) >= 8, f"{name} 缺证据描述过短: {item}"


def test_severity_files_reflect_review_recommendation():
    """复核后：降级案例必须是 medium，保留案例必须是 high，且署名仍标 pending。"""
    d = _packet()
    for name, path in SEV_FILES.items():
        rec = d["cases"][name]
        sev = json.loads(path.read_text(encoding="utf-8"))
        if rec["verdict"] == "downgrade":
            assert sev["severity"] == "medium", f"{name} 未按复核降级"
        else:
            assert sev["severity"] == "high", f"{name} 不应被降级"
        assert sev["cvss_vector"] == rec["recommended_vector"], f"{name} 向量未对齐复核建议"
        assert "human review pending" in sev["reviewed_by"], f"{name} 署名被改动"


def test_doc_covers_all_cases_and_is_not_a_signoff():
    text = DOC.read_text(encoding="utf-8")
    for name, ws in CASES.items():
        assert name in text, f"文档缺 {name}"
        assert ws in text, f"文档缺 {ws}"
    assert "final=false" in text or "final`=false" in text or "`final=false`" in text
    assert "human_signoff_required" in text
    assert "6.1" in text and "7.1" in text
