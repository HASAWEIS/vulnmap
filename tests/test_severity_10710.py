"""CG-21 / arvo:10710 严重性草案校验。

钉子（按任务要求）：
1) 文本本地输入 → 必须 AV:L，禁止 AV:N；
2) 评分方向要与日志一致：日志写 READ of size 1 / stack-buffer-underflow 时，
   不得给 I:H/A:H（那是"栈写破坏"的前提，本例没有）；
3) 六维 evidence 的每条 文件:行 必须真实存在；
4) 向量、敏感性表分数都要能复算。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S9-CG21-arvo-10710"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-10710.md"

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
    head = d["dimensions"]["observed_impact"]["evidence"].split(" —— ")[0]
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


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec, "文本本地输入必须是 AV:L"
    assert "/AV:N" not in vec, "无网络入口证据，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}，AV:N 需重新评估"


def test_rating_matches_observed_access_type():
    """日志是 READ 就不能按"栈写破坏"给 I:H/A:H。"""
    d = _sev()
    log = _vul_log_text()
    assert "READ of size 1" in log
    assert "stack-buffer-underflow" in log
    assert "WRITE of size" not in log, "日志若出现 WRITE，说明前提变了，本草案需重写"
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "read" in impact, f"observed_impact 应体现读类访问，实际 {impact}"
    vec = d["cvss_vector"]
    assert "/I:H" not in vec and "/A:H" not in vec, "读下溢 + |=0 空操作，不支持 I:H/A:H"
    assert "/I:L/" in vec and vec.endswith("/A:N")


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 3.3) < 1e-9
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
    assert av_n and any("禁止" in v for v in av_n), "敏感性表应把 AV:N 标为禁止"


def test_case_json_only_merged_from_this_draft():
    """case.json 可以由 pipeline 消费 severity.json 合并，但不能是手写/与草案不一致。

    背景：S9 的 report 阶段会读 workspace 下的 severity.json 并写回 case.json，
    这是既有流程；本测试只保证"合并的值来自本草案"，并保证草案本身仍是 final=false。
    """
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 的向量不是本草案的（疑似手写）"
        assert (case.get("acceptance") or {}).get("high_severity_confirmed") is False, (
            "low 定级不应被记成 high")
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False and draft["human_signoff_required"] is True


def test_doc_covers_key_points():
    text = DOC.read_text(encoding="utf-8")
    for token in ("AV:L", "I:L", "A:N", "3.3", "stack-buffer-underflow",
                  "READ of size 1", "lex.c:336", "lex.c:341", "final=false",
                  "human_signoff_required", "7.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁" in text or "禁止" in text
