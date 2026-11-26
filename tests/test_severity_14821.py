"""CG-25 / arvo:14821 严重性草案校验。

钉子（按任务要求"只按证据打分，不为进高危抬分"）：
1) 入口只有 CLI/UART → 必须 AV:L，禁止 AV:N；
2) 1 字节栈写、规模结构性受限 → 不得给 I:H / A:H，须为 I:L / A:L；
3) 六维 evidence 的每条 文件:行 必须真实存在；
4) 向量与敏感性表分数都要能复算。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S12-CG25-arvo-14821"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-14821.md"

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


def test_av_local_and_no_network_claim():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec, "CLI/UART 入口应为 AV:L"
    assert "/AV:N" not in vec, "仅 CLI/UART 路径，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://", "socket"):
        assert marker not in log, f"日志出现网络标记 {marker}，AV:N 结论需重新评估"
    assert "uart" in log


def test_no_inflation_to_high():
    """1 字节写 + 结构性上限 → 不允许 I:H/A:H。"""
    d = _sev()
    log = _vul_log_text()
    assert "WRITE of size 1" in log
    assert "stack-buffer-overflow" in log
    vec = d["cvss_vector"]
    assert "/I:H" not in vec, "1 字节写且规模有上限，不支持 I:H"
    assert "/A:H" not in vec, "无非 ASAN 崩溃证据，不支持 A:H"
    assert "/I:L/" in vec and vec.endswith("/A:L")
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "1byte" in impact or "1_byte" in impact, f"observed_impact 应写明单字节，实际 {impact}"
    assert d["severity"] != "high", "不得为进高危抬分"


def test_underflow_bound_is_documented():
    """文档必须写出"越界量结构性受限"的推导，否则 I:L 就成了空口保守。"""
    text = DOC.read_text(encoding="utf-8")
    for token in ("dst", "colonp", "endp", "VerifyOrExit", "≤ 2", "m8"):
        assert token in text, f"文档缺上界推导要素: {token}"


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 5.1) < 1e-9
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
    assert len(entries) >= 2, "PR 与 deployment 都应列为缺口"
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
    assert any("/I:H/" in v for v in sens.values()), "应给出 I:H/A:H 的对照分以供人工取舍"


def test_case_json_only_merged_from_this_draft():
    """case.json 可由 pipeline 消费 severity.json 合并，但值必须来自本草案。"""
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 的向量不是本草案的"
        assert (case.get("acceptance") or {}).get("high_severity_confirmed") is False
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_covers_key_points():
    text = DOC.read_text(encoding="utf-8")
    for token in ("AV:L", "I:L", "A:L", "5.1", "CWE-121", "arvo:14821",
                  "ip6_address.cpp:333", "final=false", "human_signoff_required", "7.7"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text or "禁" in text
