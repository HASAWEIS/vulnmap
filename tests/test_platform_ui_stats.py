"""首屏口径：页面必须显示台账案例（17）与独立高危（3），且不得再显示工作区数（25）。

首屏是客户端渲染的（app.js + /api/overview），所以这里断言**页面声明的口径 + 渲染出来的数字**：
页面把指标口径写在 <script id="stat-keys"> 里，测试解析它、按 /api/overview 求值，
就等于断言"首屏会显示什么"。数字不写死在 HTML 里，避免下次台账一变页面就骗人。
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PAGE = ROOT / "vulnmap_platform" / "static" / "index.html"
LEDGER = ROOT / "experiments" / "LEDGER.json"


@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture(scope="module")
def ledger():
    return json.loads(LEDGER.read_text(encoding="utf-8"))


def page_text() -> str:
    return PAGE.read_text(encoding="utf-8")


def stat_spec() -> list:
    m = re.search(r'<script id="stat-keys" type="application/json">(.+?)</script>',
                  page_text(), re.S)
    assert m, "页面缺少口径声明块 <script id=stat-keys>"
    return json.loads(m.group(1))


def rendered(client) -> dict:
    """按页面声明的口径求值：{标签: 首屏会显示的数字}。"""
    ov = client.get("/api/overview").json()
    out = {}
    for label, group, key in stat_spec():
        assert group in ov, f"页面引用了不存在的分组 {group}"
        assert key in ov[group], f"页面引用了不存在的字段 {group}.{key}"
        out[label] = ov[group][key]
    return out


# ---------------------------------------------------------------- 页面口径
def test_first_screen_does_not_show_workspace_count():
    assert "25" not in page_text(), "页面仍出现工作区总数 25（应改为台账口径）"


def test_page_declares_ledger_stats():
    keys = {(g, k) for _, g, k in stat_spec()}
    assert ("stats", "ledger_cases") in keys, "首屏案例数应取 stats.ledger_cases"
    assert ("stats", "independent_high") in keys, "首屏高危应取 stats.independent_high"


def test_page_no_longer_uses_totals_cases():
    t = page_text()
    assert "t.cases" not in t, "页面仍用 totals.cases 显示案例总数"
    assert "totals.cases" not in t


def test_first_screen_shows_17_cases(client, ledger):
    vals = rendered(client)
    assert vals["台账案例"] == len(ledger["rows"])


def test_first_screen_shows_3_independent_high(client, ledger):
    vals = rendered(client)
    n = sum(1 for r in ledger["rows"] if r.get("high_severity_confirmed"))
    assert vals["独立高危"] == n


def test_first_screen_values_contain_17_and_3_but_not_25(client):
    led = json.loads(LEDGER.read_text(encoding="utf-8"))
    expect_cases = len(led["rows"])
    expect_high = sum(1 for r in led["rows"] if r.get("high_severity_confirmed"))
    vals = set(rendered(client).values())
    assert expect_cases in vals, f"首屏未出现台账案例数 {expect_cases}：{vals}"
    assert expect_high in vals, f"首屏未出现独立高危 {expect_high}：{vals}"


def test_runs_and_workspaces_not_in_case_cards(client):
    labels = {label for label, g, k in stat_spec() if g == "stats"}
    assert labels == {"台账案例", "独立高危"}, (
        "stats 分组只放案例量；运行量（workspaces/runs）不得混进案例卡片")


# ---------------------------------------------------------------- 案例列表
def test_cases_endpoint_defaults_to_ledger(client, ledger):
    r = client.get("/api/cases").json()
    ledger_dirs = [Path(row["source"]).parts[1] for row in ledger["rows"]]
    assert r["scope"] == "ledger"
    assert len(r["items"]) == len(ledger["rows"])
    assert sorted(i["dir"] for i in r["items"]) == sorted(ledger_dirs)
    n_ws = sum(1 for d in (ROOT / "workspace").iterdir()
               if d.is_dir() and (d / "task.json").exists())
    assert r["hidden_experiments"] == n_ws - len(ledger["rows"])


def test_cases_endpoint_include_experiments(client, ledger):
    r = client.get("/api/cases?include_experiments=1").json()
    assert r["scope"] == "experiments"
    assert r["hidden_experiments"] == 0
    assert len(r["items"]) > len(ledger["rows"])


def test_default_list_hides_pure_experiment_dirs(client):
    dirs = {i["dir"] for i in client.get("/api/cases").json()["items"]}
    for d in ("S2-CG09-rule", "S2-CG09-llm", "S4-CG07-10096", "S5B-CG09",
              "S5C-CG09", "S5D-CG09", "S5E-CG08"):
        assert d not in dirs, f"实验复跑目录 {d} 出现在默认案例列表里"


def test_ledger_backed_s_dirs_are_kept(client, ledger):
    """台账里确实收录的 S5G/S5H 属于案例，不能被"以 S 开头"一刀切掉。"""
    dirs = {i["dir"] for i in client.get("/api/cases").json()["items"]}
    for row in ledger["rows"]:
        d = Path(row["source"]).parts[1]
        assert d in dirs, f"台账条目 {d} 不在默认列表里"
