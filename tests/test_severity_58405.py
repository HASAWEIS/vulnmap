"""CG-39 / arvo:58405 严重性草案校验。

争议点：0xCC 会写 "E-" 是否意味着内容可控 → I:H。测试直接读日志与源码确认：
  - 越界的是 `*txt = 0`（NUL，固定值），"E-" 全在缓冲区内；
  - 守卫 -3 与单次最多 +4 字符的差恒为 1 字节，无放大路径；
  - 该字节落在 buf[32,97) 与 args[144,528) 之间的 47 字节空隙。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S21-CG39-arvo-58405"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-58405.md"
SRC = WS / "src" / "ghostpdl" / "pdf" / "pdf_font1C.c"

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


CITE = re.compile(r"([\w./-]+\.(?:log|c|cc|cpp|hh|hpp|json|txt|diff)):(\d+)(?:-(\d+))?")


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


def test_log_shows_one_byte_overflow_and_layout_gap():
    log = _vul_log_text()
    assert "WRITE of size 1" in log
    assert "offset 97 in frame" in log
    assert "[32, 97) 'buf.i'" in log
    assert "[144, 528) 'args'" in log
    assert 144 - 97 == 47, "buf 与 args 之间有 47 字节空隙"


def test_source_guard_diff_is_exactly_one_byte():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert "char buf[65];" in src[690], src[690]
    guard = src[695]
    assert "while (txt < buf + (sizeof buf) - 3" in guard, guard
    # 守卫留 3，单次最多 +4（0xCC 两个半字节各 2 字符）→ 差 1 字节
    assert 65 - 3 == 62
    assert 62 - 1 == 61, "能进入循环的最大 txt = buf+61"
    assert 61 + 4 == 65, "单次迭代最多 +4 → txt 到 buf+65"
    assert 65 - 65 + 1 == 1, "buf[65] 即越界 1 字节（合法下标 0..64）"
    whole = "\n".join(src)
    assert "*txt++ = 'E';" in whole and "*txt++ = '-';" in whole
    term = [ln for ln in src if ln.strip() == "*txt = 0;"]
    assert len(term) == 1, "NUL 终止符写入必须唯一（越界点）"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "PDF 解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_not_inflated_to_high():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H" not in vec, "越界字节是固定 NUL，不支持 I:H"
    assert "/A:N" in vec, "无非 ASAN 崩溃实测"
    assert "/I:L/" in vec
    assert d["severity"] == "low"
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "1byte" in impact and "nul" in impact.lower(), impact
    joined = " ".join(d["limitations"])
    assert "NUL" in joined, "必须写明越界的是 NUL"
    assert "47" in joined, "必须写明 47 字节空隙"


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
    assert av_n and any("禁止" in v for v in av_n)
    assert any("/I:H/" in v for v in sens.values()), "应给出 I:H 对照分供人工取舍"


def test_case_json_only_merged_from_this_draft():
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 向量不是本草案的"
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_documents_nul_and_gap():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:L", "A:N", "AV:L", "3.3", "NUL", "47", "buf[65]", "*txt = 0",
                  "final=false", "human_signoff_required", "7.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text