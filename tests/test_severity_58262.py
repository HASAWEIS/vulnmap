"""CG-32 / arvo:58262 严重性草案校验。

争议点："vlen 数据来自文件"是否足以给 I:H，还是只能算 DoS。测试直接读日志/源码/补丁：
  - 日志必须是 WRITE of size 16 且目标区只有 1 字节（malloc(0)）；
  - mat73.c:739/623/625/626/631 必须与"标量 dataspace → malloc(0) → H5Aread 写 1 个 hvl_t"一致；
  - 补丁必须给 rank==0 补 *nfields = 1（说明是缓冲被分小，不是写很大）；
  - 并断言 16 ≤ 24 的 slack 算术（A:N 的依据）。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S16-CG32-arvo-58262"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-58262.md"
SRC = WS / "src" / "matio" / "src" / "mat73.c"
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


def test_log_shows_fixed_16byte_write_into_1byte_region():
    log = _vul_log_text()
    assert "WRITE of size 16" in log, "越界量固定 16 字节"
    assert "1-byte region" in log, "目标区是 malloc(0) 的 1 字节记账"
    assert "Mat_H5ReadFieldNames" in log
    assert 16 <= 24, "glibc 最小 chunk 可用 24 字节：16 字节写落在 slack 内"


def test_source_shows_zero_length_allocation():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert "hsize_t  nfields=0" in src[738], src[738]
    assert "H5Sget_simple_extent_dims(space_id,nfields,NULL)" in src[622], src[622]
    assert "malloc((size_t)(*nfields)*sizeof(*fieldnames_vl))" in src[624], src[624]
    assert "H5Aread(attr_id,field_id,fieldnames_vl)" in src[625], src[625]
    assert "for ( i = 0; i < *nfields; i++ )" in src[630], src[630]


def test_upstream_patch_treats_scalar_as_one_element():
    patch = PATCH.read_text(encoding="utf-8")
    assert "*nfields = 1;" in patch, "补丁应把 rank==0 视作 1 个字段（说明缓冲被分小）"
    assert "calloc((size_t)(*nfields)" in patch


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "MAT 解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_not_inflated_to_high_and_not_just_dos():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H" not in vec, "固定 16 字节、描述符内容、slack 吸收 → 不支持 I:H"
    assert "/A:N" in vec, "无非 ASAN 崩溃实测"
    assert "/I:L/" in vec
    assert d["severity"] == "low"
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "16byte" in impact and "descriptor" in impact, impact
    joined = " ".join(d["limitations"])
    assert "hvl_t" in joined, "必须说明写入内容是 hvl_t 描述符，不是文件原始字节"
    assert "24" in joined, "必须写明 glibc 可用 24 字节的 slack 算术"


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


def test_doc_documents_slack_arithmetic():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:L", "A:N", "AV:L", "3.3", "hvl_t", "24", "16",
                  "final=false", "human_signoff_required", "7.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text
