"""污染边界：模板污染必须被如实记录，不能淡化成"独立实现"。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def prov():
    return json.loads((ROOT / "experiments" / "PROVENANCE.json").read_text(encoding="utf-8"))


def test_provenance_lists_every_case(prov):
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    dev_rows = sum(1 for r in led["rows"] if r.get("dev_rerun"))
    vg_rows = sum(1 for r in led["rows"] if str(r.get("case_id", "")).startswith("VG-"))
    assert len(prov["rows"]) == led["totals"]["cases"] - dev_rows - vg_rows


def test_poc_derived_templates_are_flagged(prov):
    """与官方 PoC 字节相同的模板，必须出现在 contamination 里。"""
    flagged = [r for r in prov["rows"] if r["contamination"]]
    for r in flagged:
        assert any("PoC" in c for c in r["contamination"]), r


def test_template_dir_declares_origin():
    """模板目录必须自带来源声明，明确"等同 PoC 则不算自主生成"。"""
    p = ROOT / "agent" / "templates" / "PROVENANCE.json"
    assert p.exists(), "模板目录缺少 PROVENANCE.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    assert "_warning" in d and "不能" in d["_warning"]
    for t in d["templates"]:
        assert "identical_to_poc" in t


def test_dev_set_tasks_not_counted_as_clean(prov):
    for r in prov["rows"]:
        if r["in_dev_set"]:
            assert r["clean"] is False, r["case_id"]


def test_poc_template_cases_not_clean(prov):
    for r in prov["rows"]:
        if any("PoC" in c for c in r["contamination"]):
            assert r["clean"] is False, r["case_id"]


def test_summary_consistent(prov):
    s = prov["summary"]
    assert s["clean"] == sum(1 for r in prov["rows"] if r["clean"])
    assert s["in_dev_set"] == sum(1 for r in prov["rows"] if r["in_dev_set"])
    assert s["model_verified_contribution"] == sum(
        1 for r in prov["rows"] if r["model_verified_contribution"])
