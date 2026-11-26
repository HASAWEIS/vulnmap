"""编排器：迁移表与降级路径。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.runtime.orchestrator import TRANSITIONS, STAGE_ORDER


def test_transitions_cover_every_stage():
    for stage in STAGE_ORDER:
        assert stage in TRANSITIONS
        assert TRANSITIONS[stage]["ok"] in STAGE_ORDER + ("done",)


def test_verify_failure_falls_back_to_report():
    assert TRANSITIONS["verify"]["fail"] in ("locate", "blocked")
