"""平台层：API 与前端必须与验收台账一致。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLAT = ROOT / "vulnmap_platform"


@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    sys.path.insert(0, str(ROOT))
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


def test_overview_totals_match_ledger(client):
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    ov = client.get("/api/overview").json()
    # 旧 totals 是合并口径（含复跑目录），台账口径看 stats.ledger_cases
    assert ov["stats"]["ledger_cases"] == led["totals"]["cases"]
    assert ov["stats"]["independent_high"] == led["totals"]["high_severity_confirmed"]
    t = ov["totals"]
    assert t["cases"] >= led["totals"]["cases"]
    assert t["high_severity_confirmed"] == led["totals"]["high_severity_confirmed"]


def test_funnel_is_monotonic(client):
    """层级门禁必须单调：高危 ⊆ 双端，因果链 ⊆ 双端。"""
    t = client.get("/api/overview").json()["totals"]
    # 高危要求“双端 + 严重性”，不要求数据流因果链；因果链是另一条独立门槛
    assert t["high_severity_confirmed"] <= t["local_dual_run_pass"]
    assert t["causal_chain_verified"] <= t["local_dual_run_pass"]
    assert t["local_dual_run_pass"] <= t["with_report"] <= t["cases"]


def test_every_workspace_case_listed(client):
    n = sum(1 for d in (ROOT / "workspace").iterdir()
            if d.is_dir() and (d / "task.json").exists())
    assert len(client.get("/api/cases?include_experiments=1").json()["items"]) == n


def test_case_detail_404_for_unknown(client):
    assert client.get("/api/cases/no-such-case").status_code == 404


def test_case_detail_has_required_blocks(client):
    items = client.get("/api/cases?include_experiments=1").json()["items"]
    d = client.get(f"/api/cases/{items[0]['dir']}").json()
    for k in ("summary", "task", "case", "verify", "locate", "artifacts"):
        assert k in d, k


def test_static_pages_exist_and_self_contained():
    for f in ("index.html", "cases.html", "packages.html", "lab.html"):
        p = PLAT / "static" / f
        assert p.exists(), f
        html = p.read_text(encoding="utf-8")
        import re
        assert not re.findall(r'(?:src|href)="https?://', html), f"{f} 依赖外部资源"


def test_page_theme_is_light():
    """需求：不要大规模暗色。

    允许局部使用品牌深蓝（如 hero 区块），但**页面底色与主体面**必须是亮色，
    否则就成了暗色主题。
    """
    import re
    css = (PLAT / "static" / "style.css").read_text(encoding="utf-8")

    def lum(hexv):
        v = hexv.lstrip("#")
        if len(v) == 3:            # #fff 简写
            v = "".join(c * 2 for c in v)
        r, g, b = int(v[0:2], 16), int(v[2:4], 16), int(v[4:6], 16)
        return (r + g + b) / 3

    for var, name in (("--page", "页面底色"), ("--surface", "卡片面"), ("--soft", "次级面")):
        m = re.search(rf"{var}:\s*(#(?:[0-9a-fA-F]{{3}}|[0-9a-fA-F]{{6}}))", css)
        assert m, f"未定义 {var}"
        assert lum(m.group(1)) > 200, f"{name}过暗：{m.group(1)}"


def test_dark_usage_is_localized():
    """深色只允许出现在 hero 等局部区块，不能铺满页面。"""
    import re
    css = (PLAT / "static" / "style.css").read_text(encoding="utf-8")
    # 找所有 background: 声明里亮度 < 90 的颜色
    dark = []
    for m in re.finditer(r"background(?:-color)?:\s*(#[0-9a-fA-F]{6})", css):
        v = m.group(1).lstrip("#")
        lum = (int(v[0:2],16) + int(v[2:4],16) + int(v[4:6],16)) / 3
        if lum < 90:
            start = css.rfind("}", 0, m.start())
            dark.append(css[start+1:m.start()].strip().split("{")[0].strip()[:40])
    # hero 与顶栏允许深色；其余不应出现大面积深底
    assert len(dark) <= 3, f"深色背景使用过多：{dark}"


def test_packages_api_has_hash_lists(client):
    for p in client.get("/api/packages").json()["items"]:
        assert p["files_detail"], f"{p['case']} 无材料哈希清单"
        for f in p["files_detail"]:
            assert len(f["sha256"]) == 64


def test_platform_is_read_only():
    """展示层不得写入验收状态。"""
    import re
    src = (PLAT / "api" / "app.py").read_text(encoding="utf-8")
    forbidden = re.findall(r"\b(write_text|write_bytes|unlink|rmtree|mkdir)\b", src)
    assert not forbidden, f"后端出现写操作：{set(forbidden)}"


def test_sidebar_has_no_checkbox_like_icons():
    """历史问题：侧栏每项前有一个空心方框，看起来像复选框。

    那是 `.ic` 的 border 装饰，用户误读为可勾选控件——已移除。
    """
    css = (PLAT / "static" / "style.css").read_text(encoding="utf-8")
    assert ".sb-item .ic" not in css, "侧栏方框装饰应已移除"
    app = (PLAT / "static" / "app.js").read_text(encoding="utf-8")
    assert '<span class="ic">' not in app, "侧栏不应再渲染方框图标"


def test_no_theme_switch_placeholder():
    """主题切换曾是禁用占位，已按要求删除。"""
    for f in ("app.js", "style.css"):
        text = (PLAT / "static" / f).read_text(encoding="utf-8")
        assert "theme-switch" not in text, f"{f} 仍残留主题开关"


def test_projects_grouped_by_benchmark():
    """案例必须按 benchmark 分组作为「项目」，而不是平铺。"""
    app = (PLAT / "static" / "app.js").read_text(encoding="utf-8")
    assert "groupByBench" in app
    assert "BENCH_LABEL" in app


def test_case_links_navigate_to_detail_anchor():
    """侧栏案例链接必须带 hash，才能触发详情展开。"""
    app = (PLAT / "static" / "app.js").read_text(encoding="utf-8")
    assert 'cases.html#${esc(c.dir)}' in app
    cases = (PLAT / "static" / "cases.html").read_text(encoding="utf-8")
    assert "location.hash" in cases, "cases 页需读取 hash 自动展开"


def test_cases_page_uses_route_not_inline_expand():
    """案例详情改为纯路由：不依赖行内展开的 JS 状态。"""
    s = (PLAT / "static" / "cases.html").read_text(encoding="utf-8")
    assert "renderDetail" in s and "renderList" in s
    assert "hashchange" in s, "需监听 hash 变化"
    assert "data-detail" not in s, "不应再有行内展开实现"


def test_cases_page_renders_shell():
    """历史 bug：重写 cases.html 时漏了 renderShell，侧栏与顶栏全空。"""
    for f in ("index.html", "cases.html", "packages.html", "lab.html"):
        s = (PLAT / "static" / f).read_text(encoding="utf-8")
        assert "renderShell(" in s, f"{f} 必须调用 renderShell 渲染骨架"


def test_static_assets_are_versioned():
    """静态资源必须带版本号，否则改完浏览器仍用缓存。"""
    import re
    for f in ("index.html", "cases.html", "packages.html", "lab.html"):
        s = (PLAT / "static" / f).read_text(encoding="utf-8")
        assert re.search(r'style\.css\?v=\d+', s), f"{f} 的 css 未带版本号"
        assert re.search(r'app\.js\?v=\d+', s), f"{f} 的 js 未带版本号"


def test_backend_disables_cache_for_assets():
    s = (PLAT / "api" / "app.py").read_text(encoding="utf-8")
    assert "no-store" in s, "静态资源应禁用缓存"
