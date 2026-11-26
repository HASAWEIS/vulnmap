"""CG-29 / arvo:11011 严重性草案校验。

本题的争议点是"I:H 是否有据"，所以测试除了常规项（引用行存在、分数复算、禁 AV:N），
还会**直接读源码与上游补丁**验证结构性依据：
  - rar5.c:1826 必须是 `window_mask = window_size - 1`（目录 window_size=0 → mask=SIZE_MAX）
  - rar5.c:2424 必须是把 literal 写进 `window_buf[write_idx & cmask]`
  - patch.diff 必须把 size==0 时的 mask 置 0
只要这三条不成立，就不该给 I:H。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S14-CG29-arvo-11011"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-11011.md"
SRC = WS / "src" / "libarchive" / "libarchive" / "archive_read_support_format_rar5.c"
PATCH = WS / "patch.diff"

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


def test_measured_facts_are_what_log_says():
    log = _vul_log_text()
    assert "WRITE of size 1" in log, "实测是 1 字节写"
    assert "1-byte region" in log, "目标缓冲只有 1 字节"
    assert "do_uncompress_block" in log


def test_structural_evidence_for_i_h_exists_in_source():
    """I:H 的两块基石：mask 失效 + literal 写入，必须能在源码里指到。"""
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert "window_mask = rar->cstate.window_size - 1" in src[1825], src[1825]
    assert "window_buf[write_idx & cmask] = (uint8_t) num" in src[2423], src[2423]
    assert "const int cmask = rar->cstate.window_mask" in src[2373], src[2373]
    joined = "\n".join(src[1358:1370])
    assert "is_dir ?" in joined and "0 :" in joined, "目录 window_size=0 的证据缺失"


def test_upstream_patch_confirms_root_cause():
    patch = PATCH.read_text(encoding="utf-8")
    assert "window_mask = rar->cstate.window_size - 1" in patch
    assert "window_mask = 0" in patch, "上游补丁应把 size==0 时的 mask 置 0"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "档案解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_i_h_and_a_h_with_reasons():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H/" in vec, "受控 literal + mask 失效 → I:H"
    assert vec.endswith("/A:H")
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "overwrite" in impact and "controlled" in impact, impact
    assert len(d["limitations"]) >= 4
    assert any("放大" in x or "amplif" in x.lower() for x in d["limitations"]), "应写明未做放大 PoC"


def test_score_matches_vector():
    d = _sev()
    assert abs(cvss_base(d["cvss_vector"]) - d["cvss_base_score"]) < 1e-9
    assert abs(cvss_base(d["cvss_vector"]) - 7.1) < 1e-9
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
    assert any("/I:L/" in v for v in sens.values()), "应给出 I:L 的对照分（实测优先口径）"


def test_case_json_only_merged_from_this_draft():
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 向量不是本草案的"
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_documents_why_one_byte_supports_high():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:H", "AV:L", "7.1", "SIZE_MAX", "cmask", "write_idx",
                  "Huffman literal", "1 字节", "final=false", "human_signoff_required", "6.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text
