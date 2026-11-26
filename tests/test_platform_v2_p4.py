"""V2 P4 验收：任务 Web/API + 五个只读页面。

口径（与需求逐条对应）：

1. **提交/准入**：`POST /api/platform/tasks` 只建 RECEIVED 任务并发 `task.created`，
   不执行目标；`POST /{id}/preflight` 是显式准入门，READY/BLOCKED 由 preflight 判定；
   重复提交 409、非法 benchmark 400、非 RECEIVED 准入 409；
2. **只读查询**：`/tasks`、`/{id}`、`/{id}/events`、`/{id}/evidence`、`/{id}/casepack`
   只读；GET 前后 tasks/事件数不变；库不存在时 GET 不建库；
3. **证据**：清单带 present/hash_ok（现场重算），blob 只允许该任务登记过的 sha256；
4. **CasePack**：有 `reports` 台账才返回；content_sha256 与包内文件重算一致；
   文件下载只允许包清单里的名字（`..` / 未知名字 404），未出包 404；
5. **页面**：五个页面 200 且复用 app.js/style.css，只读消费；提交/准入按钮打 API；
6. **导航**：index 与 app.js 的 VIEWS 都有 V2 任务入口。

所有测试都用临时 `PLATFORM_ROOT`，不依赖运行中的 8102/8900 服务，也不碰仓库 `.platform`。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (EventBus, EvidenceStore, PlatformStore, TaskSpec,
                            build_casepack)
from agent.platform.casepack import FILES

STATIC = ROOT / "vulnmap_platform" / "static"
PAGES = {
    "platform-tasks.html": "提交任务",
    "platform-task.html": "任务详情",
    "platform-events.html": "事件流",
    "platform-evidence.html": "证据浏览器",
    "platform-casepack.html": "CasePack",
}
CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED",
         "RUNNING", "CANDIDATE", "VERIFYING", "REVIEW")


@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture()
def platform_root(tmp_path, monkeypatch):
    """每个测试一个独立 PLATFORM_ROOT；端点按请求重新读取环境变量。"""
    root = tmp_path / "platform"
    root.mkdir()
    monkeypatch.setenv("PLATFORM_ROOT", str(root))
    return root


def _target(root: Path, name: str = "ws") -> str:
    path = root / name
    path.mkdir(exist_ok=True)
    return str(path)


def _submit(client, root: Path, *, task_id: str = "p4-demo",
            benchmark: str = "target_yaml", target: str | None = None) -> dict:
    r = client.post("/api/platform/tasks", json={
        "task_id": task_id, "benchmark": benchmark,
        "target": target if target is not None else _target(root),
        # F1：缺失授权默认阻断，API 夹具显式声明
        "metadata": {"authorized": True},
    })
    assert r.status_code == 201, r.text
    return r.json()


def _db(root: Path) -> Path:
    return root / "platform.db"


def _seed_evidence(root: Path, task_id: str, *, kind="crash_log",
                   data=b"AddressSanitizer: heap-buffer-overflow\n") -> str:
    """用运行时接口写一条证据（页面/只读端点不写证据，测试自己造数据）。"""
    store = PlatformStore(_db(root))
    try:
        ref = EvidenceStore(store, root / "evidence").put_bytes(
            task_id, kind, data, source_stage="RUNNING")
        return ref.sha256
    finally:
        store.close()


def _json_bytes(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
                       default=str) + "\n").encode("utf-8")


# ------------------------------------------------------------------ 提交 / 准入
def test_submit_creates_received_task_without_executing(client, platform_root):
    body = _submit(client, platform_root, task_id="submit-1")
    task = body["task"]
    assert task["state"] == "RECEIVED"
    assert task["benchmark"] == "target_yaml"
    assert task["budget"]["max_seconds"] == 3600
    assert body["links"]["events"].endswith("/submit-1/events")

    detail = client.get("/api/platform/tasks/submit-1").json()
    assert detail["state"] == "RECEIVED"
    assert detail["timeline"] == []          # 还没有状态迁移
    assert detail["summary"]["events"] == 1  # 只有 task.created
    assert detail["summary"]["candidates"] == 0
    assert detail["summary"]["evidence"] == 0

    events = client.get("/api/platform/tasks/submit-1/events").json()
    assert events["count"] == 1
    assert events["items"][0]["event_type"] == "task.created"
    assert events["items"][0]["stage"] == "RECEIVED"


def test_preflight_gate_to_ready_and_timeline(client, platform_root):
    _submit(client, platform_root, task_id="gate-1")
    r = client.post("/api/platform/tasks/gate-1/preflight")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["state"] == "READY"
    assert out["blockers"] == []
    names = {c["name"] for c in out["checks"]}
    assert {"target_path", "authorized"} <= names

    detail = client.get("/api/platform/tasks/gate-1").json()
    assert detail["state"] == "READY"
    assert [t["to"] for t in detail["timeline"]] == ["PREFLIGHT", "READY"]
    assert detail["replay"]["state"] == "READY"
    types = [e["event_type"] for e in client.get(
        "/api/platform/tasks/gate-1/events").json()["items"]]
    assert "preflight.passed" in types


def test_preflight_blocks_missing_target(client, platform_root):
    missing = str(platform_root / "no-such-dir")
    _submit(client, platform_root, task_id="gate-2", target=missing)
    out = client.post("/api/platform/tasks/gate-2/preflight").json()
    assert out["state"] == "BLOCKED"
    assert "target_path" in out["blockers"]
    assert client.get("/api/platform/tasks/gate-2").json()["state"] == "BLOCKED"


def test_preflight_rejects_wrong_state(client, platform_root):
    _submit(client, platform_root, task_id="gate-3")
    assert client.post("/api/platform/tasks/gate-3/preflight").status_code == 200
    again = client.post("/api/platform/tasks/gate-3/preflight")
    assert again.status_code == 409
    assert "RECEIVED" in again.json()["detail"]


def test_submit_validation_and_duplicate(client, platform_root):
    assert client.post("/api/platform/tasks", json={
        "benchmark": "nope", "target": _target(platform_root)}).status_code == 400
    assert client.post("/api/platform/tasks", json={
        "benchmark": "target_yaml"}).status_code == 400
    assert client.post("/api/platform/tasks", json={
        "benchmark": "target_yaml", "target": _target(platform_root),
        "budget": {"max_seconds": 0}}).status_code == 400
    _submit(client, platform_root, task_id="dup-1")
    again = client.post("/api/platform/tasks", json={
        "benchmark": "target_yaml", "target": _target(platform_root),
        "task_id": "dup-1"})
    assert again.status_code == 409


def test_run_endpoint_requires_planned(client, platform_root):
    """执行只能由显式接口触发，且只受理 PLANNED；RECEIVED 直接 409。"""
    _submit(client, platform_root, task_id="run-1")
    r = client.post("/api/platform/tasks/run-1/run", json={})
    assert r.status_code == 409
    assert "PLANNED" in r.json()["detail"]


# ------------------------------------------------------------------ 查询 / 只读
def test_list_filters_and_totals(client, platform_root):
    _submit(client, platform_root, task_id="list-1", benchmark="target_yaml")
    _submit(client, platform_root, task_id="list-2", benchmark="vulngym",
            target="http://127.0.0.1:8000")
    data = client.get("/api/platform/tasks").json()
    assert {i["task_id"] for i in data["items"]} == {"list-1", "list-2"}
    assert data["totals"]["tasks"] == 2
    assert data["totals"]["by_benchmark"] == {"target_yaml": 1, "vulngym": 1}

    only = client.get("/api/platform/tasks?benchmark=vulngym").json()
    assert [i["task_id"] for i in only["items"]] == ["list-2"]
    assert only["totals"]["filtered"] == 1

    limited = client.get("/api/platform/tasks?limit=1").json()
    assert len(limited["items"]) == 1
    assert limited["totals"]["tasks"] == 2

    assert client.get("/api/platform/tasks?state=NOPE").status_code == 400
    assert client.get("/api/platform/tasks?benchmark=nope").status_code == 400


def test_events_after_pagination(client, platform_root):
    _submit(client, platform_root, task_id="ev-1")
    client.post("/api/platform/tasks/ev-1/preflight")
    all_events = client.get("/api/platform/tasks/ev-1/events?after=0").json()
    assert all_events["count"] == len(all_events["items"]) == 4
    last = all_events["next_after"]
    assert last == all_events["items"][-1]["seq"]

    rest = client.get(f"/api/platform/tasks/ev-1/events?after={last}").json()
    assert rest["items"] == []
    assert rest["next_after"] == last


def test_read_endpoints_do_not_mutate_state(client, platform_root):
    _submit(client, platform_root, task_id="ro-1")
    _seed_evidence(platform_root, "ro-1")

    def snapshot():
        store = PlatformStore(_db(platform_root))
        try:
            task = store.get_task("ro-1")
            return (task["state"], task["updated_at"],
                    len(store.list_events("ro-1")),
                    len(store.list_evidence("ro-1")),
                    len(store.list_candidates("ro-1")))
        finally:
            store.close()

    before = snapshot()
    client.get("/api/platform/tasks")
    client.get("/api/platform/tasks/ro-1")
    client.get("/api/platform/tasks/ro-1/events")
    client.get("/api/platform/tasks/ro-1/evidence")
    assert client.get("/api/platform/tasks/ro-1/casepack").status_code == 404
    assert snapshot() == before


def test_list_does_not_create_database(tmp_path, monkeypatch, client):
    fresh = tmp_path / "fresh-platform"
    monkeypatch.setenv("PLATFORM_ROOT", str(fresh))
    data = client.get("/api/platform/tasks").json()
    assert data["exists"] is False
    assert data["items"] == []
    assert not (fresh / "platform.db").exists(), "只读列表不应建库"


def test_unknown_task_is_404_everywhere(client, platform_root):
    assert client.get("/api/platform/tasks/nope").status_code == 404
    assert client.get("/api/platform/tasks/nope/events").status_code == 404
    assert client.get("/api/platform/tasks/nope/evidence").status_code == 404
    assert client.get("/api/platform/tasks/nope/casepack").status_code == 404
    assert client.get(
        "/api/platform/tasks/nope/evidence/" + "0" * 64).status_code == 404


# ------------------------------------------------------------------ 证据
def test_evidence_list_and_blob_download(client, platform_root):
    _submit(client, platform_root, task_id="evd-1")
    sha = _seed_evidence(platform_root, "evd-1", data=b"crash log\n")

    data = client.get("/api/platform/tasks/evd-1/evidence").json()
    assert data["count"] == 1
    item = data["items"][0]
    assert item["sha256"] == sha
    assert item["kind"] == "crash_log"
    assert item["present"] is True and item["hash_ok"] is True
    assert item["download"].endswith("/evidence/" + sha)

    blob = client.get(item["download"])
    assert blob.status_code == 200
    assert blob.content == b"crash log\n"

    # 未登记的哈希 / 非法哈希都不提供 blob
    assert client.get("/api/platform/tasks/evd-1/evidence/" + "a" * 64).status_code == 404
    assert client.get("/api/platform/tasks/evd-1/evidence/not-a-sha").status_code == 404


def test_evidence_hash_ok_false_when_blob_tampered(client, platform_root):
    _submit(client, platform_root, task_id="evd-2")
    sha = _seed_evidence(platform_root, "evd-2", data=b"original\n")
    (platform_root / "evidence" / sha).write_bytes(b"tampered\n")
    item = client.get("/api/platform/tasks/evd-2/evidence").json()["items"][0]
    assert item["present"] is True
    assert item["hash_ok"] is False


# ------------------------------------------------------------------ CasePack
def test_casepack_404_before_pack(client, platform_root):
    _submit(client, platform_root, task_id="pack-0")
    r = client.get("/api/platform/tasks/pack-0/casepack")
    assert r.status_code == 404
    assert "casepack" in r.json()["detail"]
    assert client.get(
        "/api/platform/tasks/pack-0/casepack/file?name=report.md").status_code == 404


def test_casepack_path_hash_and_downloads(client, platform_root):
    store = PlatformStore(_db(platform_root))
    try:
        spec = TaskSpec(task_id="pack-1", benchmark="target_yaml",
                        target=_target(platform_root))
        store.create_task(spec)
        EventBus(store).emit("pack-1", "task.created", payload=spec.to_dict())
        for state in CHAIN:
            store.transition("pack-1", state, reason="p4 fixture")
        EvidenceStore(store, platform_root / "evidence").put_bytes(
            "pack-1", "crash_log", b"asan: heap-buffer-overflow\n")
        pack = build_casepack("pack-1", store)
    finally:
        store.close()

    data = client.get("/api/platform/tasks/pack-1/casepack").json()
    assert data["report_id"] == pack["report_id"]
    assert data["exists"] is True
    pack_dir = Path(data["path"])
    assert pack_dir == Path(pack["path"])
    assert {f["path"] for f in data["files"]} == set(FILES)

    # content_sha256 必须能由包内文件现场重算
    expected_files = []
    for rel in FILES:
        p = pack_dir / rel
        expected_files.append({"path": rel,
                               "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                               "size": p.stat().st_size})
    expected_files.sort(key=lambda x: x["path"])
    expected = hashlib.sha256(_json_bytes(expected_files)).hexdigest()
    assert data["content_sha256"] == expected
    assert data["recomputed_sha256"] == expected
    assert data["hash_ok"] is True
    assert data["reports"][0]["report_id"] == pack["report_id"]

    manifest = client.get(
        "/api/platform/tasks/pack-1/casepack/file?name=casepack.json")
    assert manifest.status_code == 200
    assert json.loads(manifest.text)["content_sha256"] == expected

    report = client.get(
        "/api/platform/tasks/pack-1/casepack/file?name=report.md")
    assert report.status_code == 200
    assert "Case Pack: pack-1" in report.text

    # 只允许包清单里的名字
    assert client.get(
        "/api/platform/tasks/pack-1/casepack/file?name=../platform.db").status_code == 404
    assert client.get(
        "/api/platform/tasks/pack-1/casepack/file?name=../../etc/passwd").status_code == 404
    assert client.get(
        "/api/platform/tasks/pack-1/casepack/file?name=nope.json").status_code == 404

    detail = client.get("/api/platform/tasks/pack-1").json()
    assert detail["casepack"]["content_sha256"] == expected
    assert detail["summary"]["reports"] == 1


# ------------------------------------------------------------------ 页面
def test_pages_exist_and_serve_200(client):
    for name, marker in PAGES.items():
        assert (STATIC / name).is_file(), f"缺少页面 {name}"
        r = client.get("/" + name)
        assert r.status_code == 200, name
        assert "text/html" in r.headers["content-type"]
        text = r.text
        assert marker in text, f"{name} 缺少标记 {marker}"
        assert "app.js" in text and "style.css" in text, f"{name} 未复用共用外壳"


def test_pages_are_read_only_consumers():
    """页面不允许绕过 API 改状态：除提交/准入外不得有写请求，也不碰 SQLite。"""
    for name in PAGES:
        text = (STATIC / name).read_text(encoding="utf-8")
        assert "sqlite" not in text.lower(), f"{name} 不应直接读库"
        if name != "platform-tasks.html":
            assert "postJSON(" not in text, f"{name} 不应有写动作"
        for verb in ("DELETE", "PUT", "PATCH"):
            assert verb not in text, f"{name} 出现 {verb} 请求"
    tasks_page = (STATIC / "platform-tasks.html").read_text(encoding="utf-8")
    posts = {line.strip() for line in tasks_page.splitlines() if "postJSON(" in line}
    assert posts, "提交页应通过 postJSON 调用 API"
    assert all("/api/platform/tasks" in line for line in posts)


def test_index_navigation_has_v2_entry():
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "platform-tasks.html" in index
    assert "platform-tasks.html" in app_js
    assert "V2 任务" in app_js


def test_pages_reference_existing_api_routes(client):
    """页面调用的 V2 路由必须真实存在（打开 API 文档清单做交叉检查）。"""
    paths = {r.path for r in client.app.routes if getattr(r, "path", "").startswith("/api/platform")}
    for expected in ("/api/platform/tasks",
                     "/api/platform/tasks/{task_id}",
                     "/api/platform/tasks/{task_id}/events",
                     "/api/platform/tasks/{task_id}/evidence",
                     "/api/platform/tasks/{task_id}/evidence/{sha256_value}",
                     "/api/platform/tasks/{task_id}/casepack",
                     "/api/platform/tasks/{task_id}/casepack/file",
                     "/api/platform/tasks/{task_id}/preflight",
                     "/api/platform/tasks/{task_id}/run"):
        assert expected in paths, f"缺少路由 {expected}"
