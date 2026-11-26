"""CG-27 / arvo:12818 严重性草案校验。

任务的关键约束：
1) 图片解析入口、无网络证据 → 必须 AV:L，禁止 AV:N；
2) 不能因为"写 4.29e9"直接给 I:H/A:H —— 那 4.29e9 里只有 1 字节越界；
3) 也不能因为"值是 0"直接给 I:N —— 越界字节落在分配区之外；
4) 每条 evidence 的 文件:行 必须真实存在，向量与敏感性分数可复算。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S13-CG27-arvo-12818"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-12818.md"

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


def _vul_log_text():
    d = _sev()
    head = d["dimensions"]["attack_vector"]["evidence"].split(" —— ")[0]
    return (ROOT / head.split(":")[0]).read_text(encoding="utf-8", errors="ignore")


CITE = re.compile(r"([\w./-]+\.(?:log|c|cc|cpp|hh|hpp|json|txt)):(\d+)(?:-(\d+))?")


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


def test_log_shows_only_one_byte_out_of_bounds():
    """定级的地基：日志必须能证明越界只有 1 字节。"""
    log = _vul_log_text()
    assert "WRITE of size 4294836226" in log
    assert "1 bytes to the left of 4294836225-byte region" in log
    assert 4294836226 - 4294836225 == 1
    assert "Called with maxSize < 0" in log, "int 截断证据缺失"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "图片解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}，AV:N 需重新评估"
    assert "tga" in log or "kimgio" in log


def test_no_inflation_and_no_zero_washing():
    """既不能因写大给 I:H，也不能因值是 0 给 I:N。"""
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H" not in vec, "4.29e9 里只有 1 字节越界，不支持 I:H"
    assert "/A:H" not in vec, "无非 ASAN 的 OOM/崩溃实测，不支持 A:H"
    assert "/I:N" not in vec, "越界字节真实存在，不得判无完整性影响"
    assert "/I:L/" in vec and vec.endswith("/A:L")
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "1byte" in impact or "1_byte" in impact, f"observed_impact 应点明单字节越界，实际 {impact}"
    assert "zero" in impact or "zero_fill" in impact


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 4.4) < 1e-9
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


def test_sensitivity_scores_recompute():
    d = _sev()
    sens = d["sensitivity"]
    assert len(sens) >= 5
    for key, text in sens.items():
        m = re.search(r"(CVSS:3\.1/[^\s]+?)\s*=\s*(\d+(?:\.\d+)?)", text)
        assert m, f"{key} 缺向量或分数: {text}"
        vec, claimed = m.group(1), float(m.group(2))
        assert abs(cvss_base(vec) - claimed) < 1e-9, f"{key} 复算 {cvss_base(vec)} ≠ {claimed}"
    av_n = [v for k, v in sens.items() if "/AV:N/" in v]
    assert av_n and any("禁止" in v for v in av_n), "敏感性表须把 AV:N 标为禁止"
    assert any("/I:H/" in v for v in sens.values()), "应给出 I:H/A:H 对照分供人工取舍"


def test_case_json_only_merged_from_this_draft():
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 向量不是本草案的"
        assert (case.get("acceptance") or {}).get("high_severity_confirmed") is False
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_documents_the_one_byte_split():
    text = DOC.read_text(encoding="utf-8")
    for token in ("4.29e9", "1 bytes to the left", "4294836226", "4294836225",
                  "AV:L", "I:L", "A:L", "4.4", "final=false", "human_signoff_required", "7.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text
