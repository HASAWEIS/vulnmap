"""V2 P4.6 验收：CasePack 网页报告（report.html）+ 写操作默认只开本机。

口径（与需求逐条对应）：

1. **report.html**：CasePack 在保留 `report.md` 的同时多渲染一份 `report.html`
   ——确定性（同一批台账重算字节相同）、样式内联、无脚本、零外部资源；
   它进 `FILES`，因此进 `content_sha256`；`reports` 台账额外记
   `report_html_sha256`（单文件哈希），可与盘上文件逐字对齐。
2. **HTML 内容**：任务/状态/候选/验证/复核/证据清单/口径声明齐备，
   所有台账字段转义（候选/复核里塞 `<script>` 只会变成文本）。
3. **写操作默认回环**：`PLATFORM_API_TOKEN` 未设置时，远端写请求 403 且提示设置
   token；本机回环（127.0.0.1 / ::1 / localhost）照旧受理并标注 `auth.mode=open`、
   `X-Platform-Auth: open`；带转发头的回环按远端处理（除非 `PLATFORM_TRUST_PROXY=1`）；
   GET 始终开放；设置 token 后与本机/远端无关，只认 Bearer。

全部测试用临时 `PLATFORM_ROOT`，不碰仓库 `.platform`。
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (EventBus, EvidenceStore, PlatformStore, TaskSpec,
                            build_casepack, run_review, run_verification)
from agent.platform.candidates import from_crash, sha256_hex
from agent.platform.casepack import (FILES, SELF_FILE, CasePackError,
                                     render_report_html)

CANDIDATE_CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES",
                   "PLANNED", "RUNNING", "CANDIDATE")

#: 外部资源特征：出现任何一条都说明 HTML 不是自包含的
EXTERNAL_REF_PATTERNS = (
    r"(?i)https?://",
    r"(?i)<[a-z][^>]*\b(?:src|href)\s*=",   # 标签内的外链属性（值里的文本已被转义）
    r"(?i)<link\b",
    r"(?i)<script\b",
    r"(?i)<iframe\b",
    r"(?i)<img\b",
    r"(?i)@import",
    r"(?i)url\(",
)


# ------------------------------------------------------------------ fixtures
def _task(tmp_path, *, task_id="pack-html", db_name="p.db"):
    store = PlatformStore(tmp_path / db_name)
    bus = EventBus(store)
    spec = TaskSpec(task_id=task_id, benchmark="cybergym",
                    target=str(tmp_path / "ws"))
    store.create_task(spec)
    bus.emit(task_id, "task.created", payload=spec.to_dict())
    for state in CANDIDATE_CHAIN:
        store.transition(task_id, state, reason="casepack fixture")
    return store, bus


def _candidate(store, task_id, *, data=b"CRASH" + b"A" * 48,
               candidate_id="C1", crash_type="heap-buffer-overflow"):
    log = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
           "#0 0x1 in parse_record a.c:16\n")
    evidence = EvidenceStore(store, store.path.parent / "evidence")
    input_ref = evidence.put_bytes(task_id, "crash_input", data,
                                   source_stage="RUNNING")
    log_ref = evidence.put_bytes(task_id, "crash_log", log.encode("utf-8"),
                                 source_stage="RUNNING")
    parsed = {"crash_type": crash_type, "access": "WRITE",
              "function": "parse_record", "file": "a.c", "line": 16,
              "frames": [{"func": "parse_record", "file": "a.c", "line": 16}]}
    cand = from_crash(
        {"input_bytes": data, "input_sha256": sha256_hex(data), "log": log,
         "stack_hash": "0123456789abcdef", "crash_type": crash_type,
         "parsed": parsed, "diagnostic_valid": True},
        task_id=task_id, candidate_id=candidate_id, exec_id="exec-pack",
        plan_sha256="p" * 64, build_sha256="b" * 64)
    cand.detail["input_evidence_sha256"] = input_ref.sha256
    cand.detail["log_evidence_sha256"] = log_ref.sha256
    cand.evidence_sha256 = log_ref.sha256
    store.save_candidate(cand)
    return cand


def _log(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _verified_reviewed(tmp_path, *, task_id="pack-html", db_name="p.db"):
    store, bus = _task(tmp_path, task_id=task_id, db_name=db_name)
    _candidate(store, task_id)
    vul_log = _log(tmp_path, "vul.log", "AddressSanitizer: heap-buffer-overflow\n")
    fix_log = _log(tmp_path, "fix.log", "program exited cleanly\n")
    run_verification(task_id, store, bus, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    run_review(task_id, store, bus)
    return store, bus


def _canonical_sha(files: list[dict]) -> str:
    listed = sorted(files, key=lambda x: x["path"])
    canonical = json.dumps(listed, ensure_ascii=False, indent=2,
                           sort_keys=True) + "\n"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _assert_no_external_refs(text: str) -> None:
    hits = [pat for pat in EXTERNAL_REF_PATTERNS if re.search(pat, text)]
    assert not hits, f"report.html 含外部资源特征：{hits}"


# ------------------------------------------------------------------ 1. HTML
def test_report_html_added_hashed_and_recorded(tmp_path):
    store, bus = _verified_reviewed(tmp_path)
    pack = build_casepack("pack-html", store, bus=bus)
    out = Path(pack["path"])

    # 1) 文件齐备：report.md 保留，report.html 新增且进 FILES / 内容哈希
    assert "report.html" in FILES and "report.md" in FILES
    for rel in FILES:
        assert (out / rel).is_file(), f"缺文件 {rel}"
    assert (out / SELF_FILE).is_file()
    listed = {f["path"]: f for f in pack["files"]}
    assert set(listed) == set(FILES)
    html_bytes = (out / "report.html").read_bytes()
    html_sha = hashlib.sha256(html_bytes).hexdigest()
    assert listed["report.html"]["sha256"] == html_sha
    assert listed["report.html"]["size"] == len(html_bytes)
    assert pack["report"]["html"] == "report.html"
    assert pack["report"]["html_sha256"] == html_sha
    assert pack["report"]["html_external_refs"] == 0
    assert pack["content_sha256"] == _canonical_sha(pack["files"])

    # 2) 台账：整包哈希不变口径，额外一列记网页单文件哈希
    reports = store.list_reports("pack-html")
    assert len(reports) == 1
    assert reports[0]["report_id"] == pack["report_id"] == "PACK1"
    assert reports[0]["sha256"] == pack["content_sha256"]
    assert reports[0]["path"] == str(out)
    assert reports[0]["report_html_sha256"] == html_sha

    # 3) 内容：任务/候选/验证/复核/证据/口径声明都在，且中文不乱码
    text = html_bytes.decode("utf-8")
    assert text.startswith("<!doctype html>")
    assert "Case Pack: pack-html" in text
    assert "<style>" in text and "</style>" in text
    for needle in ("heap-buffer-overflow", "vuln_fix_diff", "accept",
                   "证据清单", "口径声明", "benchmark_verified"):
        assert needle in text, f"report.html 缺内容：{needle}"
    assert "C1" in text and "V1" in text and "R1" in text
    manifest = json.loads((out / "evidence" / "manifest.json").read_text(
        encoding="utf-8"))
    for item in manifest["items"]:
        assert item["sha256"] in text

    # 4) 自包含：无脚本、无外部链接、无 @import / url()
    _assert_no_external_refs(text)

    # 5) report.ready 事件带网页哈希，且 report.md 仍在（三种消费者各取所需）
    ready = [e for e in bus.list("pack-html") if e["event_type"] == "report.ready"]
    assert ready and ready[-1]["payload"]["report_html_sha256"] == html_sha
    assert ready[-1]["payload"]["content_sha256"] == pack["content_sha256"]
    assert (out / "report.md").is_file()
    assert "Case Pack: pack-html" in (out / "report.md").read_text(encoding="utf-8")


def test_report_html_is_deterministic_and_escapes_ledger_fields():
    task = {"task_id": "det-1", "benchmark": "cybergym",
            "target": "/ws/<script>alert(1)</script>", "mode": "fuzz"}
    state = {"state": "REPORTED", "terminal_reason": "",
             "events": 7, "replayed_state": "REPORTED",
             "transitions": [{"to": "REVIEW"}, {"to": "REPORTED"}]}
    candidates = [{"id": "C1", "crash_type": "<script>alert(1)</script>",
                   "state": "new", "stack_hash": "a" * 40,
                   "evidence_sha256": "b" * 64}]
    verifications = [{"verification_id": "V1", "kind": "vuln_fix_diff",
                      "status": "verified", "verified": True,
                      "detail": {"blockers": []}}]
    reviews = [{"review_id": "R1", "verdict": "accept",
                "verification_id": "V1", "reason": "<img src=x onerror=1>"}]
    manifest = {"count": 1, "all_present": True, "all_hash_ok": True,
                "manifest_sha256": "c" * 64,
                "items": [{"kind": "crash_log", "sha256": "d" * 64,
                           "size": 12, "present": True, "hash_ok": True,
                           "path": "/ws/a.c"}]}

    first = render_report_html(task, state, candidates, verifications, reviews,
                               manifest)
    second = render_report_html(task, state, candidates, verifications, reviews,
                                manifest)
    assert first == second, "同一批输入必须渲染出同一份字节（否则哈希不可复算）"
    assert hashlib.sha256(first.encode("utf-8")).hexdigest() == \
        hashlib.sha256(second.encode("utf-8")).hexdigest()

    # 台账字段里的标签只能是文本，不能变成可执行标记
    assert "<script>alert(1)</script>" not in first
    assert "<img src=x" not in first
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in first
    _assert_no_external_refs(first)


def test_report_html_covers_negative_results(tmp_path):
    """负结果也进 HTML：验证未通过 / 复核 none 一样有行，不做“只报喜”的网页。"""
    store, bus = _task(tmp_path, task_id="pack-neg", db_name="neg.db")
    _candidate(store, "pack-neg")
    vul_log = _log(tmp_path, "vul-neg.log", "boom\n")
    run_verification("pack-neg", store, bus, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 1, "log_path": str(vul_log)},
    })
    pack = build_casepack("pack-neg", store, bus=bus)
    assert pack["state"] == "NO_REPRO"
    assert pack["verdict"]["verified"] == 0
    text = (Path(pack["path"]) / "report.html").read_text(encoding="utf-8")
    assert "no_repro" in text
    assert "未通过" in text
    assert "confirmed" not in text.lower()


# ------------------------------------------------------- 2. API 下载与哈希
def test_api_exposes_report_html_hash_and_download(tmp_path, monkeypatch):
    store, bus = _verified_reviewed(tmp_path, task_id="pack-api",
                                    db_name="platform.db")
    pack = build_casepack("pack-api", store, bus=bus)
    store.close()
    monkeypatch.setenv("PLATFORM_ROOT", str(tmp_path))

    from fastapi.testclient import TestClient

    from vulnmap_platform.api.app import app
    client = TestClient(app, client=("127.0.0.1", 50000))

    data = client.get("/api/platform/tasks/pack-api/casepack").json()
    html_sha = hashlib.sha256(
        (Path(pack["path"]) / "report.html").read_bytes()).hexdigest()
    assert data["report_html"] == "report.html"
    assert data["report_html_sha256"] == html_sha
    assert data["report_html_sha256_recorded"] == html_sha
    assert data["report_html_ok"] is True
    assert "report.html" in {f["path"] for f in data["files"]}
    assert data["hash_ok"] is True

    download = client.get(
        "/api/platform/tasks/pack-api/casepack/file?name=report.html")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/html")
    assert "Case Pack: pack-api" in download.text

    detail = client.get("/api/platform/tasks/pack-api").json()
    assert detail["casepack"]["report_html_sha256"] == html_sha
    assert detail["casepack"]["download_html"].endswith("name=report.html")


# ------------------------------------------------------- 3. 写操作默认回环
@pytest.fixture()
def platform_root(tmp_path, monkeypatch):
    root = tmp_path / "platform"
    root.mkdir()
    monkeypatch.setenv("PLATFORM_ROOT", str(root))
    monkeypatch.delenv("PLATFORM_API_TOKEN", raising=False)
    monkeypatch.delenv("PLATFORM_TRUST_PROXY", raising=False)
    return root


def _client(peer=("testclient", 50000)):
    from fastapi.testclient import TestClient

    from vulnmap_platform.api.app import app
    return TestClient(app, client=peer)


def _submit_body(platform_root, task_id):
    return {"benchmark": "target_yaml",
            "target": str(platform_root / "ws"),
            "task_id": task_id}


def test_write_default_rejects_remote_client(platform_root):
    remote = _client(("203.0.113.9", 40000))
    r = remote.post("/api/platform/tasks", json=_submit_body(platform_root, "remote-1"))
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "PLATFORM_API_TOKEN" in detail and "Bearer" in detail
    assert r.headers.get("x-platform-auth") == "denied"
    # 读端点不受影响：远端也能看，鉴权只管写
    listing = remote.get("/api/platform/tasks")
    assert listing.status_code == 200
    assert listing.json()["exists"] is False
    assert listing.json()["auth"]["write_scope"] == "loopback"
    assert listing.json()["auth"]["remote_writes"] == "denied"
    # 被拒的写请求没有落库（不建库）
    assert not (platform_root / "platform.db").exists()


def test_write_default_allows_loopback_peers(platform_root):
    for idx, peer in enumerate((("127.0.0.1", 50000), ("::1", 50001),
                                ("localhost", 50002))):
        client = _client(peer)
        r = client.post("/api/platform/tasks",
                        json=_submit_body(platform_root, f"local-{idx}"))
        assert r.status_code == 201, (peer, r.text)
        body = r.json()
        assert body["auth"]["mode"] == "open"
        assert body["auth"]["token_required"] is False
        assert body["auth"]["write_scope"] == "loopback"
        assert body["auth"]["loopback_only"] is True
        assert r.headers["x-platform-auth"] == "open"
        assert r.headers["x-platform-write-scope"] == "loopback"
        # P4.5 口径保留：未设 token 的说明里必须明说“未设置”
        assert "未设置" in body["auth"]["note"]


def test_write_from_loopback_with_forward_headers_is_remote(platform_root,
                                                            monkeypatch):
    proxied = _client(("127.0.0.1", 50000))
    body = _submit_body(platform_root, "proxied-1")
    r = proxied.post("/api/platform/tasks", json=body,
                     headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 403
    assert "PLATFORM_API_TOKEN" in r.json()["detail"]

    # 显式信任代理时才回到本机判定（运维自己开的口子）
    monkeypatch.setenv("PLATFORM_TRUST_PROXY", "1")
    ok = proxied.post("/api/platform/tasks", json=body,
                      headers={"X-Forwarded-For": "198.51.100.7"})
    assert ok.status_code == 201
    assert ok.json()["auth"]["write_scope"] == "loopback"


def test_token_governs_writes_regardless_of_peer(platform_root, monkeypatch):
    remote = _client(("203.0.113.9", 40000))
    local = _client(("127.0.0.1", 50000))
    payload = _submit_body(platform_root, "tok-1")

    assert local.post("/api/platform/tasks", json=payload).status_code == 201

    monkeypatch.setenv("PLATFORM_API_TOKEN", "token-abc")
    assert local.post("/api/platform/tasks",
                      json=_submit_body(platform_root, "tok-2")).status_code == 401
    assert remote.post("/api/platform/tasks",
                       json=_submit_body(platform_root, "tok-3"),
                       headers={"Authorization": "Bearer token-abc"}).status_code == 201
    assert remote.post("/api/platform/tasks",
                       json=_submit_body(platform_root, "tok-4"),
                       headers={"Authorization": "Bearer wrong"}).status_code == 403
    info = local.get("/api/platform/tasks").json()["auth"]
    assert info["mode"] == "bearer" and info["write_scope"] == "token"


def test_casepack_still_requires_review_before_html(tmp_path):
    """打包门槛不受本轮影响：REVIEW 之前不能出包，也就没有 report.html。"""
    store, bus = _task(tmp_path, task_id="pack-early", db_name="early.db")
    _candidate(store, "pack-early")
    with pytest.raises(CasePackError, match="casepack requires"):
        build_casepack("pack-early", store, bus=bus)
    assert not (tmp_path / "casepacks" / "pack-early" / "report.html").exists()
