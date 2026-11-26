from agent import benchmark_policy as p


def test_cybergym_uses_dual_run():
    assert p.validate("cybergym", dual_ok=True)["verified"] is True
    assert p.validate("cybergym", dual_ok=False)["verified"] is False
    assert p.validate("cybergym", dual_ok=False)["blockers"] == ["local_dual_run_failed"]


def test_exploitgym_uses_flag_not_fix():
    ok = p.validate("exploitgym", dual_ok=False, exploit={"issued": True})
    assert ok["verified"] is True
    assert ok["kind"] == "exploit_flag"
    bad = p.validate("exploitgym", dual_ok=True, exploit={"issued": False})
    assert bad["verified"] is False
    assert "local_dual_run_failed" not in bad["blockers"]


def test_vulngym_requires_behavior_evidence():
    assert p.validate("vulngym", behavior_ok=True)["verified"] is True
    assert p.validate("vulngym", behavior_ok=False)["verified"] is False


def test_unknown_benchmark_fails_closed():
    assert p.validate("", dual_ok=True, exploit={"issued": True})["verified"] is False
