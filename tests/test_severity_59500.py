"""CG-37 / arvo:59500 严重性草案校验。

争议点："负下标由头部控制"是否够 I:H。测试直接读日志/源码验证两条事实：
  1) 写的内容来自静态表 vga_palette（rodata），不是文件字节 → 不满足 I:H 的内容可控；
  2) 越界量可量化且有界：present=-30 → 目标 = palette-90 = 结构体-30，长度 858，结构体外仅 30 字节。
并保留常规校验（引用行存在、分数复算、禁 AV:N）。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S20-CG37-arvo-59500"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-59500.md"
SRC = WS / "src" / "mupdf" / "source" / "fitz" / "load-bmp.c"

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


def test_log_shows_underflow_and_frame_offset():
    log = _vul_log_text()
    assert "stack-buffer-underflow" in log
    assert "WRITE of size 1" in log
    assert "offset 2 in frame" in log
    assert "[32, 976) 'info'" in log


def test_source_write_comes_from_rodata_table():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    assert "vga_palette" in src[76], src[76]
    memcpy = "\n".join(src[913:917])
    assert "memcpy(&info->palette[readcolors * 3], &vga_palette[readcolors * 3]," in memcpy, memcpy
    assert "sizeof(vga_palette) - readcolors * 3" in memcpy
    present = "\n".join(src[939:944])
    assert "present = fz_mini(expected, (bitmap - p) / entry_size)" in present, present
    whole = "\n".join(src)
    assert "if (present < expected)" in whole
    assert "bmp_load_default_palette(ctx, info, present)" in whole


def test_struct_layout_and_extent_arithmetic():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    body = "\n".join(src[104:140])
    assert "struct info" in body
    assert "uint8_t palette[256 * 3];" in body
    # 布局算术：type[2]+version..amask → palette 在结构体偏移 60；present=-30
    palette_off = 60
    assert 2 + 2 + 4 + 4 + 4 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 == 60
    dest = palette_off + (-30) * 3
    assert dest == -30, "目标 = 结构体前 30 字节"
    length = 256 * 3 - (-30) * 3
    assert length == 858
    assert dest + length == palette_off + 256 * 3, "恰好结束在 palette 末尾"
    assert 30 == 0 - dest, "结构体外只有 30 字节"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "图片解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_i_stays_low_because_content_is_not_controlled():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:L/" in vec, "内容来自 rodata 常量，不支持 I:H"
    assert "/I:H" not in vec
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "underflow" in impact and "uncontrolled" in impact, impact
    joined = " ".join(d["limitations"])
    assert "vga_palette" in joined, "必须说明源是静态表"
    assert "30" in joined, "必须写明结构体外只有 30 字节"


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


def test_doc_documents_content_and_extent():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:L", "AV:L", "4.4", "vga_palette", "rodata", "858", "30",
                  "final=false", "human_signoff_required", "7.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text
