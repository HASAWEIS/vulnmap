"""契约层单测：构造期校验必须失败。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.contracts import Budget, ContractError, OutputContract, StageRequest, ToolPolicy


def test_finalization_must_be_smaller():
    with pytest.raises(ContractError):
        Budget(max_turns=5, finalization_turns=5)


def test_contracts_subset_of_outputs():
    with pytest.raises(ContractError):
        StageRequest(run_id="r", stage="recon", role_version="v", prompt_version="p", prompt="x",
                     required_outputs=("a.json",),
                     output_contracts=(OutputContract("b.json", "s"),))


def test_unsafe_relative_name():
    with pytest.raises(ContractError):
        StageRequest(run_id="r", stage="recon", role_version="v", prompt_version="p", prompt="x",
                     required_outputs=("../escape.json",))


def test_tool_policy_denies_by_default():
    pol = ToolPolicy(allowed=("Read",))
    assert pol.permits("Read")
    assert not pol.permits("WebFetch")
    assert not pol.permits("Write")
