"""策略闸门与预算结算：审查方 2025-11-09 的两条阻断项。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.budget import BudgetLease
from agent.contracts import Budget
from agent.errors import BudgetExhausted
from agent.policy import ToolDenied, check_tool, classify
from agent.store import Store
from agent.tools import shell


def _store(tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.create_run("r1", "arvo:10400", "cybergym", str(tmp_path))
    return st


# ---- 策略闸门 ----
def test_web_fetch_is_denied_in_every_stage():
    for stage in ("recon", "locate", "verify", "exploit", "report"):
        with pytest.raises(ToolDenied):
            check_tool(stage, "WebFetch")


def test_docker_allowed_only_downstream():
    check_tool("verify", classify("shell.run", argv=["docker", "run", "img"]))
    with pytest.raises(ToolDenied):
        check_tool("recon", classify("shell.run", argv=["docker", "run", "img"]))


def test_shell_run_without_stage_is_denied():
    with pytest.raises(PermissionError):
        shell.run(["true"])


def test_shell_run_rejects_denied_tool_before_exec(tmp_path):
    marker = tmp_path / "should_not_exist"
    with pytest.raises(ToolDenied):
        shell.run(["touch", str(marker)], stage="recon", tool="WebFetch")
    assert not marker.exists()


def test_binscan_requires_stage(tmp_path):
    from agent.tools import binscan
    with pytest.raises(PermissionError):
        binscan.grep(tmp_path, "x")


# ---- 预算结算 ----
def test_enter_consumes_a_turn_immediately(tmp_path):
    st = _store(tmp_path)
    with BudgetLease(st, "r1", "recon", Budget(max_turns=5)) as lease:
        assert lease.turns == 1
        assert st.budget_row("r1", "recon", 5)["turns_used"] == 1
    assert st.budget_row("r1", "recon", 5)["turns_used"] == 1


def test_exhaustion_blocks_the_extra_enter(tmp_path):
    st = _store(tmp_path)
    for _ in range(4):
        with BudgetLease(st, "r1", "recon", Budget(max_turns=4)):
            pass
    with pytest.raises(BudgetExhausted):
        BudgetLease(st, "r1", "recon", Budget(max_turns=4)).__enter__()
    assert st.budget_row("r1", "recon", 4)["turns_used"] == 4


def test_timeout_turn_is_still_counted(tmp_path):
    st = _store(tmp_path)
    with pytest.raises(BudgetExhausted):
        with BudgetLease(st, "r1", "recon", Budget(max_turns=5, timeout_seconds=0)) as lease:
            import time
            time.sleep(0.01)
            lease.check_time()
    assert st.budget_row("r1", "recon", 5)["turns_used"] == 1


def test_seconds_accumulate_across_leases(tmp_path):
    st = _store(tmp_path)
    for _ in range(3):
        with BudgetLease(st, "r1", "verify", Budget(max_turns=5)):
            pass
    row = st.budget_row("r1", "verify", 5)
    assert row["turns_used"] == 3
    assert row["seconds_used"] >= 0
