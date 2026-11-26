"""Discovery 平台只读 API 与前端页面。

约束：不依赖运行中的 8102/8900 服务；用 TestClient 直接打 app，证据来自
仓库内 discovery/ 的真实目录（fixture / real-cjson / eval-fixture 复跑副本）。
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DISCOVERY = ROOT / "discovery"
FIXTURE = DISCOVERY / "fixture"
STATIC = ROOT / "vulnmap_platform" / "static"
PAGES = ("index.html", "discovery-campaigns.html", "discovery-campaign.html",
         "discovery-findings.html", "discovery-reports.html")
READER = "discovery-report.html"


@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture(autouse=True)
def _default_discovery_root(monkeypatch):
    monkeypatch.delenv("DISCOVERY_ROOT", raising=False)


# ---------- API: 列表 ----------

def test_campaign_list_scans_all_evidence_dirs(client):
    data = client.get("/api/discovery/campaigns").json()
    assert Path(data["root"]).resolve() == DISCOVERY.resolve()
    assert data["exists"] is True
    # 仓库可能正在被其它 discovery 运行追加证据目录；只要求非空且路径真实，
    # 精确计数由 DISCOVERY_ROOT 覆盖测试在受控目录里验证。
    assert len(data["items"]) >= 2
    assert all(Path(i["campaign_path"]).is_file() for i in data["items"])
    ids = {item["id"] for item in data["items"]}
    assert {"discovery-83fddbcf", "cJSON-81da812d"} <= ids
    keys = {item["key"] for item in data["items"]}
    assert {"fixture", "real-cjson", "eval-fixture/eval-ranked"} <= keys


def test_campaign_list_required_fields_and_paths(client):
    items = client.get("/api/discovery/campaigns").json()["items"]
    for item in items:
        for key in ("id", "target", "risk", "coverage", "analysis",
                    "isolation", "report"):
            assert key in item, key
        assert Path(item["campaign_path"]).is_file()
        assert Path(item["campaign_path"]).name == "campaign.json"
        if item["report"]["available"]:
            assert Path(item["report"]["md"]).is_file()
            assert item["report"]["rel_md"] == "report.md"


def test_campaign_list_keeps_duplicate_ids_as_separate_evidence(client):
    items = client.get("/api/discovery/campaigns").json()["items"]
    same_id = [i for i in items if i["id"] == "discovery-83fddbcf"]
    assert len(same_id) >= 3, "eval-fixture 复跑副本不应被合并"
    assert len({i["key"] for i in same_id}) == len(same_id)


def test_campaign_totals_match_items(client):
    data = client.get("/api/discovery/campaigns").json()
    t = data["totals"]
    assert t["campaigns"] == len(data["items"])
    assert t["with_report"] == sum(1 for i in data["items"] if i["report"]["available"])
    assert t["confirmed"] == sum(int(i["risk"].get("confirmed") or 0) for i in data["items"])
    assert t["crashes"] == sum(int(i["crashes"]) for i in data["items"])


# ---------- API: 详情 ----------

def test_campaign_detail_combines_evidence(client):
    d = client.get("/api/discovery/campaigns/discovery-83fddbcf").json()
    # 重复 id 的确定性选择：最浅、最短的原始目录（fixture），不是 eval 副本
    assert d["key"] == "fixture"
    assert d["campaign"]["campaign"] == "discovery-83fddbcf"
    assert d["target"]["target"] == "discovery"
    assert d["callsites"]["planned"] == 4
    assert d["callsites"]["covered"] == 4
    assert len(d["callsites"]["sites"]) == 4
    assert len(d["hypotheses"]) == 3
    assert d["hypotheses"][0]["site_id"].startswith("vuln_parser.c:")
    assert d["triage"][0]["stack_hash"] == "d33104e0a3d79e44"
    assert d["reviews"][0]["verdict"] == "confirmed"
    assert d["report"]["findings"][0]["stack_hash"] == "d33104e0a3d79e44"
    assert d["evidence"]["report_md"] is True
    for key in ("campaign", "target", "callsites", "triage", "hypotheses",
                "reviews", "report", "crashes"):
        assert key in d


def test_campaign_detail_dir_disambiguates_duplicates(client):
    d = client.get("/api/discovery/campaigns/cJSON-81da812d?dir=real-cjson").json()
    assert d["key"] == "real-cjson"
    assert d["target"]["target"] == "cJSON"
    assert d["callsites"]["planned"] == 80
    assert d["triage"][0]["verdict"] == "weakened"
    assert d["crashes_count"] == 1


def test_campaign_detail_accepts_evidence_key(client):
    d = client.get("/api/discovery/campaigns/fixture").json()
    assert d["id"] == "discovery-83fddbcf"
    assert d["key"] == "fixture"


def test_campaign_detail_404(client):
    assert client.get("/api/discovery/campaigns/no-such-campaign").status_code == 404
    assert client.get("/api/discovery/campaigns/discovery-83fddbcf?dir=nope").status_code == 404


# ---------- API: 报告 ----------

def test_report_markdown_is_served_from_evidence(client):
    r = client.get("/api/discovery/campaigns/discovery-83fddbcf/report")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert r.text.startswith("# Discovery 报告：discovery")
    assert "## 1. 分析完整性" in r.text


def test_report_markdown_for_real_cjson(client):
    r = client.get("/api/discovery/campaigns/cJSON-81da812d/report?dir=real-cjson")
    assert r.status_code == 200
    assert "# Discovery 报告：cJSON" in r.text


def test_report_404(client):
    assert client.get("/api/discovery/campaigns/no-such/report").status_code == 404
    assert client.get("/api/discovery/campaigns/discovery-83fddbcf/report?dir=nope").status_code == 404


# ---------- API: 崩溃 ----------

def test_crashes_map_to_triage_stack_hash_and_verdict(client):
    data = client.get("/api/discovery/campaigns/discovery-83fddbcf/crashes").json()
    assert data["key"] == "fixture"
    assert data["count"] == 1 == len(data["crashes"])
    crash = data["crashes"][0]
    on_disk = FIXTURE / "crashes" / crash["name"]
    assert on_disk.is_file()
    assert crash["size"] == on_disk.stat().st_size
    assert crash["triage"]["stack_hash"] == "d33104e0a3d79e44"
    assert crash["triage"]["verdict"] == "confirmed"
    assert crash["triage"]["access"] == "WRITE"
    assert crash["log"]["name"] == crash["name"].replace(".bin", ".log")
    assert (FIXTURE / "crashes" / crash["log"]["name"]).is_file()


def test_crashes_empty_campaign(client):
    d = client.get("/api/discovery/campaigns/libpng-1.6.37-914c87e9/crashes").json()
    assert d["count"] == 0
    assert d["crashes"] == []


def test_crashes_404(client):
    assert client.get("/api/discovery/campaigns/no-such/crashes").status_code == 404


# ---------- DISCOVERY_ROOT ----------

def test_discovery_root_env_override(client, tmp_path, monkeypatch):
    root = tmp_path / "campaigns"
    shutil.copytree(FIXTURE, root / "copy")
    campaign = json.loads((root / "copy" / "campaign.json").read_text(encoding="utf-8"))
    campaign["campaign"] = "fixture-copy"
    (root / "copy" / "campaign.json").write_text(
        json.dumps(campaign, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setenv("DISCOVERY_ROOT", str(root))
    data = client.get("/api/discovery/campaigns").json()
    assert Path(data["root"]).resolve() == root.resolve()
    assert [i["id"] for i in data["items"]] == ["fixture-copy"]
    assert data["items"][0]["key"] == "copy"

    detail = client.get("/api/discovery/campaigns/fixture-copy").json()
    assert detail["key"] == "copy"
    assert detail["crashes_count"] == 1

    # 原仓库目录不在覆盖后的根内
    assert client.get("/api/discovery/campaigns/discovery-83fddbcf").status_code == 404


def test_discovery_root_missing_is_empty_not_500(client, tmp_path, monkeypatch):
    monkeypatch.setenv("DISCOVERY_ROOT", str(tmp_path / "nope"))
    data = client.get("/api/discovery/campaigns")
    assert data.status_code == 200
    assert data.json()["exists"] is False
    assert data.json()["items"] == []
    assert client.get("/api/discovery/campaigns/anything").status_code == 404


# ---------- 前端 ----------

def test_discovery_pages_exist_and_are_self_contained():
    for name in PAGES:
        page = STATIC / name
        assert page.is_file(), name
        html = page.read_text(encoding="utf-8")
        assert "renderShell(" in html, f"{name} 必须复用 app.js 骨架"
        api_hint = "/api/benchmark-reports" if name == "discovery-reports.html" else "/api/discovery/campaigns"
        assert api_hint in html, f"{name} 未接 {api_hint}"
        assert not re.findall(r'(?:src|href)="https?://', html), f"{name} 依赖外部资源"
        assert re.search(r'style\.css\?v=\d+', html), f"{name} css 没版本号"
        assert re.search(r'app\.js\?v=\d+', html), f"{name} js 没版本号"


def test_index_defaults_to_discovery():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "renderShell(DEFAULT_VIEW" in html
    assert "Discovery 总览" in html
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "DEFAULT_VIEW='discovery'" in js
    assert "['index.html','discovery'" in js


def test_index_shows_benchmark_pass_rate():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "Benchmark 通过性" in html
    assert "通过率" in html
    assert "双端通过" in html
    assert "progress-track" in html
    assert "验收台账" in html, "总览必须标明数据来自验收台账，而非 Discovery 实时结果"
    # 总览不再平铺 campaign 证据表；明细留给 Campaign 列表
    assert "Campaign / 目录" not in html


def test_overview_keeps_three_diagrams():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    for asset in ("assets/architecture-v1.png", "assets/roadmap-v1.png",
                  "assets/mining-v1.svg"):
        assert asset in html, f"总览底部缺少图示 {asset}"
    assert "diagram-grid" in html and "diagram-dialog" in html


def test_legacy_pages_remain_accessible():
    for name in ("cases.html", "report.html", "overview.html",
                 "packages.html", "lab.html"):
        page = STATIC / name
        assert page.is_file(), name
        assert "renderShell(" in page.read_text(encoding="utf-8"), name


def test_discovery_pages_cover_required_views():
    campaigns = (STATIC / "discovery-campaigns.html").read_text(encoding="utf-8")
    detail = (STATIC / "discovery-campaign.html").read_text(encoding="utf-8")
    findings = (STATIC / "discovery-findings.html").read_text(encoding="utf-8")
    reports = (STATIC / "discovery-reports.html").read_text(encoding="utf-8")
    assert "campaign.json" in campaigns
    assert "triage" in detail and "callsites" in detail and "report.md" in detail
    assert "crash-*.bin" in findings or "crashes" in findings
    # Reports 页按 benchmark 分组，再按样例分节（复用 /api/benchmark-reports）
    assert "buildBenchmarkReports" in reports
    assert "/api/benchmark-reports" in reports
    assert "report-selector" in reports
    assert "样例" in reports
    # 单个 Discovery campaign 的 report.md 阅读器单独成页
    reader = (STATIC / READER).read_text(encoding="utf-8")
    assert "report.md" in reader and "/report?dir=" in reader


# ---------- 只读约束 ----------

def test_discovery_api_is_read_only():
    src = (ROOT / "vulnmap_platform" / "api" / "app.py").read_text(encoding="utf-8")
    start = src.index("# ---------- Discovery（只读证据视图）----------")
    end = src.index("SHOTS = ROOT / \"screenshots\"")
    block = src[start:end]
    forbidden = re.findall(r"\b(write_text|write_bytes|unlink|rmtree|mkdir)\b", block)
    assert not forbidden, f"Discovery 读路径出现写操作：{set(forbidden)}"


def test_discovery_frontend_has_no_api_key():
    for name in (*PAGES, READER):
        html = (STATIC / name).read_text(encoding="utf-8")
        assert "DISCOVERY_LLM_API_KEY" not in html
        assert not re.search(r"sk-[A-Za-z0-9]{8,}", html), name


# ---------- 浏览器视觉验收回归（见 docs/UI-ACCEPTANCE.md）----------

ALL_PAGES = (*PAGES, READER, "cases.html", "report.html", "overview.html",
             "packages.html", "lab.html")


def _css_version(name: str) -> str:
    html = (STATIC / name).read_text(encoding="utf-8")
    match = re.search(r"style\.css\?v=(\d+)", html)
    assert match, f"{name} 缺 style.css 版本号"
    return match.group(1)


def test_favicon_is_served_not_404(client):
    """验收时 /favicon.ico 404 是唯一的控制台报错，落成静态图标后归零。"""
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.content[:4] == b"\x00\x00\x01\x00", "不是 ICO 容器"


def test_every_page_pins_the_same_css_version():
    versions = {_css_version(name) for name in ALL_PAGES}
    assert len(versions) == 1, f"css 版本不一致：{sorted(versions)}"


def test_local_static_assets_referenced_by_pages_exist():
    for name in ALL_PAGES:
        html = (STATIC / name).read_text(encoding="utf-8")
        refs = re.findall(r'(?:src|href)="([^":#?]+\.(?:png|svg|js|css|ico))(?:[?#][^"]*)?"', html)
        for ref in refs:
            assert (STATIC / ref).is_file(), f"{name} 引用了不存在的静态资源 {ref}"


def test_odd_metric_card_spans_full_width_on_narrow_screen():
    """窄屏 2 列网格下，第 5 张 KPI 卡会孤零零占半格；用 last-child:odd 铺满。"""
    css = (STATIC / "style.css").read_text(encoding="utf-8")
    assert ".metrics-grid>.metric:last-child:nth-child(odd){grid-column:1/-1}" in css


def test_ui_acceptance_screenshots_referenced_in_doc_exist():
    doc = ROOT / "docs" / "UI-ACCEPTANCE.md"
    if not doc.is_file():
        pytest.skip("未产出 docs/UI-ACCEPTANCE.md")
    shots = set(re.findall(r"discovery/ui-acceptance/[\w.-]+\.png",
                           doc.read_text(encoding="utf-8")))
    assert shots, "验收文档没有引用任何截图"
    for shot in shots:
        assert (ROOT / shot).is_file(), f"文档引用的截图缺失：{shot}"
