"""证据完整性：身份采集不崩、新增贡献判定不放水、台账自动生成。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.contracts import Budget
from agent.runtime.orchestrator import Orchestrator
from agent.stages.report import ReportStage
from agent.stages.verify import VerifyStage

WS = Path(__file__).resolve().parent.parent / "workspace" / "CG-04-arvo-10400"


def test_run_identity_available_before_use(monkeypatch):
    """回归：原实现先用了未赋值的 image，导致身份永远为空。"""
    orch = Orchestrator(WS, budget=Budget(max_turns=40, timeout_seconds=900))
    st = VerifyStage(orch.store, orch.task["run_id"], WS, orch._request("verify"))
    monkeypatch.setattr(st, "_run_identity",
                        lambda img: {"image": img, "image_digest": "sha256:d",
                                     "target_sha256": "t", "source_sha256": "s"})
    ident = st._run_identity(st._images()["vul"])
    assert ident["target_sha256"] == "t"
    assert "error" not in ident


def _stage():
    orch = Orchestrator(WS, budget=Budget(max_turns=40, timeout_seconds=900))
    return ReportStage(orch.store, orch.task["run_id"], WS, orch._request("report"))


def test_new_contribution_requires_execution_and_pass():
    st = _stage()
    locate = {"llm": {"status": "ok", "accepted": True},
              "agreement": {"added_by_llm": ["Foo"]},
              "claims_llm": [{"subject": "Foo"}]}
    # 没有执行记录
    assert st._model_contribution(locate, {"candidates": [], "verdict": "pass"})[
        "verified_new_contribution"] is False
    # 执行了但没通过
    assert st._model_contribution(
        locate, {"candidates": [{"proposed_by": "llm"}], "verdict": "not_triggered"})[
        "verified_new_contribution"] is False
    # 执行通过、根因成立、且绑定到同一个模型候选 → 才算贡献
    ok = st._model_contribution(
        locate, {"candidates": [{"proposed_by": "llm", "subject": "Foo",
                                 "claim_id": "llm-1", "sha256": "abc",
                                 "verdict": "pass"}],
                 "verdict": "pass",
                 "claim_used": {"id": "llm-1", "subject": "Foo"},
                 "root_cause": {"matched": True, "confidence": "strong"}})
    assert ok["verified_new_contribution"] is True


def test_model_candidate_pass_requires_own_verdict():
    """规则候选通过、模型候选失败 → 全局也是 pass，但不算模型贡献。"""
    st = _stage()
    locate = {"llm": {"status": "ok", "accepted": True},
              "agreement": {"added_by_llm": ["Foo"]},
              "claims_llm": [{"subject": "Foo"}]}
    verify = {"candidates": [
                  {"proposed_by": "rule", "verdict": "pass", "sha256": "r1"},
                  {"proposed_by": "llm", "verdict": "not_triggered", "sha256": "l1"}],
              "verdict": "pass",
              "claim_used": {"id": "c-1", "subject": "Bar"},
              "root_cause": {"matched": True, "confidence": "strong"}}
    assert st._model_contribution(locate, verify)["verified_new_contribution"] is False


def test_model_contribution_requires_claim_binding():
    """模型候选通过了，但根因绑定在别的 claim 上 → 不算。"""
    st = _stage()
    locate = {"llm": {"status": "ok", "accepted": True},
              "agreement": {"added_by_llm": ["Foo"]},
              "claims_llm": [{"subject": "Foo"}]}
    verify = {"candidates": [{"proposed_by": "llm", "verdict": "pass",
                              "subject": "Foo", "claim_id": "llm-1", "sha256": "x"}],
              "verdict": "pass",
              "claim_used": {"id": "c-1", "subject": "Other"},
              "root_cause": {"matched": True, "confidence": "strong"}}
    assert st._model_contribution(locate, verify)["verified_new_contribution"] is False


def test_generation_unsupported_is_not_model_contribution():
    """10096 的真实形态：模型给了候选，但没执行、没通过 → 不算贡献。"""
    st = _stage()
    locate = {"llm": {"status": "ok", "accepted": True},
              "agreement": {"added_by_llm": ["ConvertPrimitiveToPath"]},
              "claims_llm": [{"subject": "ConvertPrimitiveToPath"}]}
    verify = {"verdict": "generation_unsupported", "candidates": []}
    assert st._model_contribution(locate, verify)["verified_new_contribution"] is False
