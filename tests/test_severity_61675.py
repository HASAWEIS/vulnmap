"""CG-31 / arvo:61675 严重性草案校验。

争议点是"I:H 是否有据、是否只算 DoS"，所以测试直接读日志/源码/补丁：
  - 日志必须是 WRITE of size 201672 且起点在 196606 字节 region 右边界（container-overflow 也要成立）；
  - bmffimage.cpp:194/204/205/206/214-215 必须与"两轮迭代 + size_t 下溢"一致；
  - 补丁必须包含 total_out > 131072（上游封掉下溢的方式）。
只要这些不成立，就不该给 I:H。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S16-CG31-arvo-61675"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-61675.md"
SRC = WS / "src" / "exiv2" / "src" / "bmffimage.cpp"
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


def test_log_shows_overflow_past_196606_bytes():
    log = _vul_log_text()
    assert "WRITE of size 201672" in log
    assert "196606-byte region" in log
    assert "0 bytes to the right" in log
    assert "container-overflow" in log, "本跑的 ASAN 分类"
    assert 201672 > 196606, "写长必须大于缓冲，才算越出分配"


def test_source_has_two_pass_underflow():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert "compressedBufSize * 2" in src[193], src[193]
    assert "arr.alloc(uncompressedLen)" in src[203], src[203]
    assert "available_out = uncompressedLen - total_out" in src[204], src[204]
    assert "next_out = arr.data() + total_out" in src[205], src[205]
    assert "uncompressedLen > 131072" in src[213], src[213]
    assert "++dos > 1" in src[214], src[214]
    # 下溢可复算：131072 - 196606 在 size_t 下是天文数字
    underflow = (131072 - 196606) % (2 ** 64)
    assert underflow > 2 ** 63, "131072 - 196606 必须下溢成巨大无符号数"


def test_upstream_patch_caps_by_total_out():
    patch = PATCH.read_text(encoding="utf-8")
    assert "total_out > 131072" in patch, "补丁应封掉 total_out 已超上限时的第二轮"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "图片解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_i_h_not_just_dos():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H/" in vec, "内容可控 + 长度可控 + 越出分配 → I:H"
    assert vec.endswith("/A:H")
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "overwrite" in impact and "controlled" in impact, impact
    joined = " ".join(d["limitations"])
    assert "container-overflow" in joined, "必须说明 ASAN 分类与 slack 的关系"
    assert "slack" in joined or "16" in joined


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
    assert any("只算 DoS" in v or "/I:N/" in v for v in sens.values()), "应给出只算 DoS 的对照分"


def test_case_json_only_merged_from_this_draft():
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 向量不是本草案的"
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_documents_underflow_and_dos_dissent():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:H", "AV:L", "7.1", "131072", "196606", "201672", "available_out",
                  "5.5", "final=false", "human_signoff_required"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text
    assert "只算 DoS" in text
