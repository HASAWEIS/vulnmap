"""官方回执校验：必须绑定任务身份、PoC 哈希与官方接受结果。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage

POC = "58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d"


@pytest.fixture()
def ws(tmp_path):
    (tmp_path / "task.json").write_text(json.dumps({"task_id": "arvo:44034"}))
    art = tmp_path / "artifacts" / "verify"
    art.mkdir(parents=True)
    (art / "result.json").write_text(json.dumps({"poc": {"sha256": POC}}))
    return tmp_path


def run(ws, receipt):
    st = ReportStage.__new__(ReportStage)
    st.ws = ws
    st.layout = {"artifacts": ws / "artifacts"}
    (ws / "receipt.json").write_text(json.dumps(receipt))
    return st._receipt_record()


def good():
    return {"task_id": "arvo:44034", "exit_code": 1, "accepted": True,
            "poc_sha256": POC, "submitted_at": "2026-11-10T12:00:00Z"}


def test_valid_receipt(ws):
    assert run(ws, good())["valid"] is True


def test_missing_receipt(ws):
    st = ReportStage.__new__(ReportStage)
    st.ws = ws
    st.layout = {"artifacts": ws / "artifacts"}
    assert st._receipt_record()["valid"] is False


def test_rejects_fabricated_marker(ws):
    r = good(); r["_warning"] = "自造"
    out = run(ws, r)
    assert out["valid"] is False and "自造" in out["reason"]


def test_rejects_task_mismatch(ws):
    r = good(); r["task_id"] = "arvo:99999"
    out = run(ws, r)
    assert out["valid"] is False and "task_id" in out["reason"]


def test_rejects_poc_hash_mismatch(ws):
    r = good(); r["poc_sha256"] = "0" * 64
    out = run(ws, r)
    assert out["valid"] is False and "poc_sha256" in out["reason"]


def test_rejects_without_official_acceptance(ws):
    r = good(); r.pop("accepted")
    out = run(ws, r)
    assert out["valid"] is False and "官方接受" in out["reason"]


def test_rejects_missing_timestamp(ws):
    r = good(); r.pop("submitted_at")
    out = run(ws, r)
    assert out["valid"] is False and "submitted_at" in out["reason"]


def test_rejects_missing_exit_code(ws):
    r = good(); r.pop("exit_code")
    assert run(ws, r)["valid"] is False


def test_rejects_when_pipeline_has_no_poc(ws):
    (ws / "artifacts" / "verify" / "result.json").write_text(json.dumps({"poc": {}}))
    out = run(ws, good())
    assert out["valid"] is False and "无法校验" in out["reason"]


def test_verdict_field_also_counts_as_acceptance(ws):
    r = good(); r.pop("accepted"); r["verdict"] = "accepted"
    assert run(ws, r)["valid"] is True
