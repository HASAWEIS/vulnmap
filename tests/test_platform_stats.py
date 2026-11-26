"""平台统计口径：运行量（workspaces/runs）与案例量（ledger_cases/independent_high）必须分开。

背景：workspace/ 下既有正式案例目录，也有 S2-/S4-/S5* 实验复跑目录。
平台若只给一个 totals.cases，界面就会把复跑目录当案例（25 vs 台账 17）。
本文件锁死四个口径的对应关系，防止再次被合并。
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture(scope="module")
def ledger():
    return json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))


def _stats(client) -> dict:
    return client.get("/api/overview").json()["stats"]


def test_overview_exposes_stats_block(client):
    ov = client.get("/api/overview").json()
    assert "stats" in ov, "overview 必须给出分离口径 stats"
    assert set(_stats(client)) >= {"workspaces", "runs", "ledger_cases",
                                   "independent_high"}


def test_ledger_cases_equals_ledger_totals(client, ledger):
    assert _stats(client)["ledger_cases"] == ledger["totals"]["cases"]


def test_workspaces_exceed_ledger_cases(client):
    s = _stats(client)
    assert s["workspaces"] > s["ledger_cases"], (
        "workspace 目录数应大于台账案例数（多出的是实验复跑目录）；"
        f"workspaces={s['workspaces']}, ledger_cases={s['ledger_cases']}")


def test_independent_high_equals_ledger_high(client, ledger):
    assert _stats(client)["independent_high"] == \
        ledger["totals"]["high_severity_confirmed"]


def test_stats_values_are_ints(client):
    s = _stats(client)
    for k in ("workspaces", "runs", "ledger_cases", "independent_high"):
        assert isinstance(s[k], int), k
        assert s[k] >= 0, k


def test_workspaces_count_matches_filesystem(client):
    dirs = [d for d in (ROOT / "workspace").iterdir() if d.is_dir()]
    assert _stats(client)["workspaces"] == len(dirs)


def test_runs_at_least_ledger_cases(client):
    s = _stats(client)
    assert s["runs"] >= s["ledger_cases"], (
        f"runs={s['runs']} 至少应覆盖台账案例数 {s['ledger_cases']}")


def test_totals_kept_for_backward_compat_but_deprecated(client):
    ov = client.get("/api/overview").json()
    assert "totals" in ov, "totals 不能删（向后兼容）"
    assert ov["totals"].get("_deprecated") is True
    assert ov["totals"].get("_replaced_by") == "stats"
    assert ov.get("totals_deprecated") is True


def test_totals_still_counts_workspaces_not_cases(client, ledger):
    """totals.cases 仍是"有报告的工作区"口径（含复跑），故允许不等于台账。

    不变式：ledger_cases <= totals.cases <= workspaces（后者含无 task.json 的目录）。
    """
    ov = client.get("/api/overview").json()
    s = _stats(client)
    assert ledger["totals"]["cases"] <= ov["totals"]["cases"] <= s["workspaces"]
def test_four_metrics_are_not_collapsed(client):
    s = _stats(client)
    assert s["workspaces"] != s["ledger_cases"], "运行量与案例量被合并了"
    assert s["independent_high"] <= s["ledger_cases"]
    assert s["note"], "四个口径必须带一句不可合并的说明"


def test_stats_doc_exists_and_names_all_four():
    p = ROOT / "docs" / "STATS.md"
    assert p.is_file(), "缺少 docs/STATS.md"
    text = p.read_text(encoding="utf-8")
    for key in ("workspaces", "runs", "ledger_cases", "independent_high"):
        assert key in text, f"docs/STATS.md 未说明 {key}"
