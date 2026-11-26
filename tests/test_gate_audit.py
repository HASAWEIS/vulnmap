"""门禁审计：同类缺陷（该查却没查）的回归测试。

已发现的历史同类问题：
  1. is_high_severity 未纳入 accept 判据
  2. LLM 重试未计入预算
  3. LINE_SLACK 把"指错行"当"行号漂移"
本文件覆盖后续审计发现。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.stages.report import ReportStage

DIMS = {d: {"value": "v", "evidence": "e"} for d in
        ("attack_vector", "privileges_required", "user_interaction",
         "observed_impact", "reachability_evidence", "deployment_conditions")}


def _st(tmp_path):
    st = ReportStage.__new__(ReportStage)
    st.ws = tmp_path
    st.layout = {"artifacts": tmp_path / "artifacts"}
    (tmp_path / "artifacts" / "verify").mkdir(parents=True, exist_ok=True)
    return st


def _sev(**over):
    base = {"severity": "high", "dimensions": dict(DIMS),
            "reviewed_by": "reviewer-a", "reviewed_at": "2026-11-10"}
    base.update(over)
    return base


# ---- 审计发现 1：severity 未签署也被判 assessed ----

def test_severity_without_reviewer_is_not_assessed(tmp_path):
    """六维齐全但没写 reviewed_by/at：说明没人签，不能算已论证。"""
    st = _st(tmp_path)
    out = st._validate_severity(_sev(reviewed_by="", reviewed_at=""), "CWE-121")
    assert out["state"] != "assessed", "未签署的论证不得判 assessed"
    assert out["is_high_severity"] is False


def test_severity_with_reviewer_is_assessed(tmp_path):
    st = _st(tmp_path)
    out = st._validate_severity(_sev(), "CWE-121")
    assert out["state"] == "assessed"


def test_draft_marker_is_not_assessed(tmp_path):
    """带 DRAFT 标记的文件即使字段齐全也不得采信。"""
    st = _st(tmp_path)
    out = st._validate_severity(_sev(_status="DRAFT_PENDING_HUMAN_REVIEW"), "CWE-121")
    assert out["state"] != "assessed"


# ---- 审计发现 2：material 只查存在不查身份 ----

def test_material_check_requires_poc_not_empty(tmp_path):
    st = _st(tmp_path)
    art = tmp_path / "artifacts"
    (art / "verify" / "result.json").write_text(json.dumps({"poc": {"path": "artifacts/verify/x.bin"}}))
    (art / "verify" / "x.bin").write_bytes(b"")
    (art / "locate").mkdir(); (art / "locate" / "findings.json").write_text("{}")
    (art / "recon").mkdir(); (art / "recon" / "repo_map.json").write_text("{}")
    out = st._material_check()
    assert out["complete"] is False, "空 PoC 不应算材料齐全"


# ---- 审计发现 3：dual_run 不能只看 verdict 字符串 ----

def test_dual_run_requires_both_exit_codes(tmp_path):
    """verdict=pass 但没有 fix_exit 记录时，不能算双端通过。"""
    st = _st(tmp_path)
    status = st._stage_status({"sink": {}}, {"verdict": "pass",
                                            "vul": {"exit_code": 1}, "fix": {}})
    assert status["local_dual_run"]["ok"] is False
