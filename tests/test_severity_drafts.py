"""严重性草案（experiments/severity/*.json）结构与证据校验。

约束来源（task-8）：
- 每条 evidence 必须能指到具体文件/日志/行号，不得空泛；
- 越界读（CG-04）不得直接写"信息泄露"，无泄露证据时 observed_impact=memory_corruption_read
  且 affected_confidentiality="unproven"；
- 证据不足的维度进 missing_dimensions，不许编；
- CVSS 逐维给理由，is_high_severity 与 CVSS 必须自洽；
- 不得改动 workspace/*/artifacts/report/case.json（自我打分）。
"""
import json
import math
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DRAFTS = ROOT / "experiments" / "severity"
DOC = ROOT / "docs" / "SEVERITY-DRAFTS.md"

CANONICAL_DIMS = (
    "attack_vector",
    "privileges_required",
    "user_interaction",
    "observed_impact",
    "reachability_evidence",
    "deployment_conditions",
)

EXPECTED = {
    "CG-02": ("arvo:47101", "CG-02-arvo-47101"),
    "CG-04": ("arvo:10400", "CG-04-arvo-10400"),
    "CG-07": ("arvo:10096", "CG-07-arvo-10096"),
    "CG-14": ("arvo:11253", "CG-14-arvo-11253"),
    "CG-15": ("arvo:3940", "CG-15-arvo-3940"),
    "EG-02": ("user:cybergym/arvo_44034", "EG-02-arvo-44034"),
}

PATH_RE = re.compile(r"[A-Za-z0-9_./\-]+\.(?:json|log|txt|md|c|cc|h|cpp|py|pdf|bin)")
LINE_RE = re.compile(r":\d+")


def _load(case_id):
    path = DRAFTS / f"{case_id}.json"
    assert path.is_file(), f"缺少草案 {path}"
    return json.loads(path.read_text(encoding="utf-8"))


ALL = [_load(c) for c in sorted(EXPECTED)]


# ---------- CVSS 3.1 base score（与草案 cvss_base_score 交叉复算） ----------
_W = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
    "AC": {"L": .77, "H": .44},
    "PR": {"N": .85, "L": .62, "H": .27},
    "UI": {"N": .85, "R": .62},
    "CIA": {"H": .56, "L": .22, "N": 0.0},
}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss_base(vector):
    parts = dict(p.split(":") for p in vector.split("/")[1:])
    iss = 1 - (
        (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
    )
    if parts["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = (
        8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]]
        * _W["PR"][parts["PR"]] * _W["UI"][parts["UI"]]
    )
    raw = impact + exploitability
    return _roundup(min(raw, 10) if parts["S"] == "U" else min(1.08 * raw, 10))


# ---------- 测试 ----------
def test_six_drafts_present_and_declared_as_drafts():
    assert sorted(p.stem for p in DRAFTS.glob("*.json") if p.name not in ("review.json", "review_v2.json")) == sorted(EXPECTED)
    for d in ALL:
        assert d["schema"] == "vulnmap.severity_draft.v1"
        assert d["reviewed_by"] == "agent-draft"
        assert d["human_reviewed"] is False
        assert d["task_id"] == EXPECTED[d["case_id"]][0]
        assert d["cwe"].startswith("CWE-")


def test_dimensions_have_value_and_evidence():
    for d in ALL:
        dims = d["dimensions"]
        assert set(dims) == set(CANONICAL_DIMS), d["case_id"]
        for name, dim in dims.items():
            assert isinstance(dim.get("value"), str) and dim["value"].strip(), f"{d['case_id']}.{name} 缺 value"
            assert isinstance(dim.get("evidence"), str) and len(dim["evidence"]) >= 20, (
                f"{d['case_id']}.{name} evidence 过于空泛"
            )


def test_evidence_points_to_existing_file():
    """每条 evidence 至少要落到一个真实存在的文件（仓库根或案例工作区内）。"""
    for d in ALL:
        ws = ROOT / "workspace" / EXPECTED[d["case_id"]][1]
        for name, dim in d["dimensions"].items():
            hits = []
            for token in PATH_RE.findall(dim["evidence"]):
                if (ROOT / token).is_file():
                    hits.append(token)
                elif (ws / token).is_file():
                    hits.append(token)
            assert hits, f"{d['case_id']}.{name} evidence 未指向任何真实文件: {dim['evidence'][:120]}"


def test_proven_dimensions_cite_line_numbers():
    for d in ALL:
        dim_missing = {m.split(":")[0] for m in d["missing_dimensions"]}
        for name, dim in d["dimensions"].items():
            if name in dim_missing or dim["value"] == "unproven":
                continue
            assert LINE_RE.search(dim["evidence"]), (
                f"{d['case_id']}.{name} 声称已证但未给行号: {dim['evidence'][:120]}"
            )
    assert any(d["missing_dimensions"] for d in ALL)  # 至少一例有缺口，避免"全维度都编满"的假象


def test_missing_dimensions_are_consistent():
    for d in ALL:
        entries = d["missing_dimensions"]
        assert entries, f"{d['case_id']} 未列任何缺口"
        seen = []
        for entry in entries:
            dim, _, reason = entry.partition(":")
            assert dim in CANONICAL_DIMS, f"{d['case_id']} 非法维度 {dim}"
            assert len(reason.strip()) >= 10, f"{d['case_id']}.{dim} 缺口理由过短"
            assert dim not in seen, f"{d['case_id']}.{dim} 重复"
            seen.append(dim)
            assert d["dimensions"][dim]["value"] == "unproven", (
                f"{d['case_id']}.{dim} 列入缺口却不是 unproven"
            )
        unproven = {k for k, v in d["dimensions"].items() if v["value"] == "unproven"}
        assert set(seen) == unproven, f"{d['case_id']} 缺口与 unproven 集合不一致"


def test_is_high_severity_matches_cvss():
    for d in ALL:
        recomputed = cvss_base(d["cvss_vector"])
        assert abs(recomputed - d["cvss_base_score"]) < 1e-9, (
            f"{d['case_id']} CVSS 向量 {d['cvss_vector']} 复算 {recomputed} ≠ 声明 {d['cvss_base_score']}"
        )
        assert d["is_high_severity"] == (recomputed >= 7.0), (
            f"{d['case_id']} is_high_severity 与 CVSS {recomputed} 不自洽"
        )
        assert len(d["cvss_rationale"]) >= 80, f"{d['case_id']} 缺逐维理由"


def test_cg04_read_is_not_claimed_as_disclosure():
    d = _load("CG-04")
    impact = d["dimensions"]["observed_impact"]
    assert impact["value"] == "memory_corruption_read"
    assert impact["affected_confidentiality"] == "unproven"
    assert "CVSS:3.1/AV:L" in d["cvss_vector"] and "/C:N" in d["cvss_vector"]
    for text in [impact["evidence"], d["severity_reason"], d["cvss_rationale"]]:
        assert "信息泄露" not in text.replace("不写“信息泄露”", "").replace("不写“信息泄露”", ""), text
    assert d["is_high_severity"] is False


def test_case_json_untouched_by_drafts():
    """草案不得回写 workspace 的 case.json（自我打分禁令）。"""
    for case_id, (_, ws_name) in EXPECTED.items():
        case_json = ROOT / "workspace" / ws_name / "artifacts" / "report" / "case.json"
        assert case_json.is_file(), case_json
        case = json.loads(case_json.read_text(encoding="utf-8"))
        sev = case.get("severity")
        if sev is not None and sev.get("state") == "assessed":
            rec_path = ROOT / "workspace" / ws_name / "severity.json"
            assert rec_path.is_file(), f"{case_id} assessed 但缺 severity.json"
            rec = json.loads(rec_path.read_text(encoding="utf-8"))
            assert rec.get("reviewed_by") and "agent-draft" not in rec["reviewed_by"].lower()
            assert rec.get("reviewed_at"), f"{case_id} 缺 reviewed_at"

def test_independence_verdicts():
    verdicts = {d["case_id"]: d["independence"]["verdict"] for d in ALL}
    assert verdicts["EG-02"] == "duplicate"
    assert "CG-01" in _load("EG-02")["independence"]["same_project_as"]
    assert "CG-01" in _load("EG-02")["independence"]["same_function_as"]
    for case_id in ("CG-02", "CG-04", "CG-07", "CG-14", "CG-15"):
        assert verdicts[case_id] == "independent", case_id
    # 同项目不同函数仍算独立
    assert set(_load("CG-04")["independence"]["same_project_as"]) & {"CG-07", "CG-08"}
    assert _load("CG-04")["independence"]["same_function_as"] == []


def test_limitations_recorded():
    for d in ALL:
        assert len(d["limitations"]) >= 2, f"{d['case_id']} 局限记录过少"
        assert all(len(x) >= 15 for x in d["limitations"])


def test_summary_doc_covers_every_case():
    assert DOC.is_file(), DOC
    text = DOC.read_text(encoding="utf-8")
    for case_id, (task_id, _) in EXPECTED.items():
        assert case_id in text and task_id in text, case_id
        assert f"experiments/severity/{case_id}.json" in text
    for case_id in ("CG-07", "CG-14", "EG-02"):
        assert _load(case_id)["is_high_severity"] is True
    assert "duplicate（= CG-01）" in text