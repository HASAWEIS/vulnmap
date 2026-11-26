"""report 判据：必须读表/读检查点，且结构化判断不许字符串包含。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent import checkpoint as ckpt
from agent.stages.report import ReportStage


def _binding(**kw):
    base = dict(run_id="r1", stage="verify", attempt=0, image_digest="sha256:" + "a" * 64,
                inputs={"x": "y"}, artifacts={"artifacts/verify/result.json": "c" * 64},
                role_version="verify-v1", prompt_version="verify-p1",
                schema_version="vulnmap.verify.v1", tool_version="v1")
    base.update(kw)
    return ckpt.build_binding(**base)


# ---- _model_recorded：结构化 ----
class _FakeStore:
    def __init__(self, details):
        self._details = details

    def _con(self):
        raise NotImplementedError


def _stage_with_details(details):
    st = ReportStage.__new__(ReportStage)
    st.run_id = "r1"

    class Con:
        def execute(self, *a, **k):
            class R:
                def fetchall(self_inner):
                    return [{"detail": d} for d in details]
            return R()

    class Store:
        _con = Con()
    st.store = Store()
    return st


@pytest.mark.parametrize("detail,expected", [
    ({"prompt_version": "locate-p1"}, False),                      # 只出现字样 → 不算
    ({"llm": {"model": "m", "prompt_version": "p"}}, False),       # 缺 tokens
    ({"llm": {"model": "gpt-4", "prompt_version": "p", "tokens": 1}}, False),  # model 不符
    # 必须显式 status=ok；缺省成功不再接受（审查方 2025-11-09）
    ({"llm": {"model": "deepseek-flash", "prompt_version": "p", "tokens": 9}}, False),
    ({"llm": {"model": "deepseek-flash", "prompt_version": "p", "tokens": 9,
              "status": "ok"}}, True),
    ({"llm": {"model": "deepseek-flash", "prompt_version": "p", "tokens": 9,
              "status": "failed"}}, False),
    ({"llm": {"model": "deepseek-flash", "prompt_version": "p", "tokens": 0,
              "status": "ok"}}, False),
    ("not-json", False),
    ({}, False),
])
def test_model_recorded_is_structural(detail, expected):
    st = _stage_with_details([json.dumps(detail) if not isinstance(detail, str) else detail])
    assert st._model_recorded({"model": "deepseek-flash"}) is expected


# ---- verify_binding_images：必须与真实镜像对账 ----
def test_verify_binding_images_rejects_unresolved():
    with pytest.raises(ValueError):
        ckpt.verify_binding_images(_binding(image_digest="sha256:unresolved-abc"))


def test_verify_binding_images_rejects_empty():
    with pytest.raises(ValueError):
        ckpt.verify_binding_images({"stage": "verify", "image_digest": "", "images": {}})


def test_verify_binding_images_rejects_composite_for_multi_image():
    b = _binding(image_digest="sha256:" + "b" * 64,
                 images={"n132/arvo:1-vul": "sha256:" + "b" * 64})
    # images 非空时主字段必须为空；组合摘要混进来应被识别（这里主字段被当作 images 的旁证）
    assert ckpt.binding_image_digests(b)


# ---- discovery 溯源 ----
def test_discovery_is_rule_without_llm_evidence():
    from agent.stages.report import ReportStage
    st = ReportStage.__new__(ReportStage)
    st.store = type("S", (), {"_con": type("C", (), {
        "execute": lambda self, *a, **k: type("R", (), {
            "fetchall": lambda s2: []})()})()})()
    st.run_id = "r1"
    d = st._discovery({"subject": "f", "subject_source": "description"}, {})
    assert d["discovery_source"] == "rule"
    assert d["agent_discovered"] is False
    assert d["evidence"] == []
    assert "尚无模型提出" in d["note"]


def test_discovery_hybrid_when_rule_and_llm_agree():
    from agent.stages.report import ReportStage
    st = ReportStage.__new__(ReportStage)
    st.run_id = "r1"
    st._llm_records = lambda: [{"role": "locate", "accepted": True,
                                "model": "deepseek-flash", "prompt_version": "locate-p1"}]
    d = st._discovery({"subject": "f", "subject_source": "description"}, {})
    assert d["discovery_source"] == "hybrid"
    assert d["agent_discovered"] is False   # 规则已有结论，模型只是补充
    assert d["evidence"]


def test_discovery_llm_only_counts_as_agent_discovered():
    from agent.stages.report import ReportStage
    st = ReportStage.__new__(ReportStage)
    st.run_id = "r1"
    st._llm_records = lambda: [{"role": "locate", "accepted": True,
                                "model": "deepseek-flash", "prompt_version": "locate-p1"}]
    d = st._discovery({"subject": "f", "subject_source": "llm"}, {})
    assert d["discovery_source"] == "llm"
    assert d["agent_discovered"] is True
