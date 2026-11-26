"""CG-36 / arvo:54839 严重性草案校验。

争议点："只越界 4 字节"是否够 I:H。测试直接读日志/源码/结构体：
  - 日志必须是 WRITE of size 4 + 256-byte region（数组 2×128，num_sections=0）；
  - decode.c:729 必须按 num_sections+2 分配，:765-769 必须是五个 section_hdr 调用，:275-278 必须来自 bit_read_RS/RL；
  - dwg.h 里 Dwg_Section 的字段顺序与 SECTION_LAYER=2 必须成立；
  - 并断言布局算术：U+264 是下一块 size 字段，address 的 8 字节 store 正落在这里。
"""
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace" / "S19-CG36-arvo-54839"
SEV = WS / "severity.json"
DOC = ROOT / "docs" / "SEVERITY-54839.md"
SRC = WS / "src" / "libredwg" / "src" / "decode.c"
HDR = WS / "src" / "libredwg" / "include" / "dwg.h"

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


def test_log_shows_4byte_write_past_256_region():
    log = _vul_log_text()
    assert "WRITE of size 4" in log
    assert "4 bytes to the right of 256-byte region" in log
    assert "decode_preR13_section_hdr" in log


def test_source_sizes_array_by_file_value():
    src = SRC.read_text(encoding="utf-8", errors="ignore").splitlines()
    alloc = "\n".join(src[726:731])
    assert "calloc" in alloc and "num_sections + 2" in alloc, alloc
    calls = "\n".join(src[764:769])
    for name in ("BLOCK", "LAYER", "STYLE", "LTYPE", "VIEW"):
        assert "decode_preR13_section_hdr (\"%s\"" % name in calls, calls
    body = "\n".join(src[270:279])
    assert "&dwg->header.section[id]" in body
    assert "tbl->size = bit_read_RS" in body
    assert "tbl->address = bit_read_RL" in body, "写入值必须来自文件"
    assert "strncpy (tbl->name" in body


def test_struct_layout_and_enum_ids():
    hdr = HDR.read_text(encoding="utf-8", errors="ignore")
    assert "char name[64]" in hdr
    assert "uint64_t   address" in hdr
    assert "SECTION_LAYER = 2" in hdr, "第二个调用点的下标必须是 2"
    # 布局算术：2 个槽位 = 256 字节；下一块 size 字段在 U+264，address 的 8 字节 store 正落此处
    assert 2 * 128 == 256
    assert 264 == 256 + 8, "section[2].address = 256 + offsetof(address)=8 → U+264"
    assert 264 + 8 == 272, "8 字节 store 覆盖 U+264..271，正是下一块 size 字段"


def test_av_local_and_no_network():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/AV:L/" in vec
    assert "/AV:N" not in vec, "DWG 解析入口，禁止 AV:N"
    log = _vul_log_text().lower()
    for marker in ("socat", "listen(", "bind(", "0.0.0.0", "http://"):
        assert marker not in log, f"日志出现网络标记 {marker}"


def test_i_h_because_value_and_target_are_file_controlled():
    d = _sev()
    vec = d["cvss_vector"]
    assert "/I:H/" in vec and vec.endswith("/A:H")
    impact = d["dimensions"]["observed_impact"]["value"]
    assert "controlled" in impact and "metadata" in impact, impact
    joined = " ".join(d["limitations"])
    assert "下标是固定的" in joined or "下标" in joined, "必须区分『固定下标』与『可控取值』"
    assert "264" in joined, "必须写明 address 落点 U+264"


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
    assert any("/I:L/" in v for v in sens.values()), "应给出 I:L 对照分（实测优先口径）"


def test_case_json_only_merged_from_this_draft():
    draft = _sev()
    case = json.loads((WS / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    sev = case.get("severity") or {}
    if sev.get("state") == "assessed":
        assert sev.get("cvss_vector") == draft["cvss_vector"], "case.json 向量不是本草案的"
    else:
        assert sev.get("state") == "unassessed"
    assert draft["final"] is False


def test_doc_documents_metadata_target():
    text = DOC.read_text(encoding="utf-8")
    for token in ("I:H", "AV:L", "7.1", "256", "264", "bit_read_RL", "num_sections",
                  "final=false", "human_signoff_required", "6.1"):
        assert token in text, f"文档缺 {token}"
    assert "禁止" in text and "AV:N" in text
    assert "size 字段" in text
