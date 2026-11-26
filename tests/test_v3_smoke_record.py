r"""V3 验收：`smoke --record` 把结论落成 `verifications`（不写 confirmed）。

口径（逐条对应需求）：

1. **只有判据成立才 verified**：`status=would_verify` 且 `criterion.criterion_ok`
   才写 `verified=True`；缺口（`needs_evidence`）与负结果（`no_repro`）原样落，
   `error/unknown_case` 落 `rejected`。默认（不加 `--record`）一条都不写；
2. **编号稳定 + detail 可审计**：`SMOKE-<case>-<run>`，`run_id` 省略时按
   案例/任务/benchmark/证据清单哈希/spec/checks 派生；detail 带
   case/task/benchmark/spec/evidence/criterion/run_id；`evidence_sha256`
   是 runner 证据清单（kind/sha256/size，排序）的哈希；
3. **任务必须存在**：不存在时明确报错（exit 2），不自动建假任务；
   `--ensure-task` 才按 `task.json` 登记一条 `RECEIVED` 任务；
4. **幂等**：同一 `--run-id` 重复 record → 一条记录、逐字一致、事件不翻倍；
5. **API 可查**：`GET /api/platform/tasks/{id}` 的 `verifications` 能读到；
6. **不写 confirmed**：库里任何一行都不出现该字段/标签。

全部离线：本地 HTTP 服务 + 临时 SQLite，不碰 docker、不访问 benchmark 网络。
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import Budget, PlatformStore, TaskError, TaskSpec  # noqa: E402

BIN = ROOT / "bin" / "platform.py"
CASE = "VG-01"
TASK_ID = "vg-smoke-rec"


# ------------------------------------------------------------------ fixtures
class _Handler(BaseHTTPRequestHandler):
    """基线 200/A、修补 403/B：稳定的 behavior_diff，不跟随跳转。"""

    def do_GET(self):                              # noqa: N802 - http.server 协议
        routes = {"/base": (200, b"A"), "/patched": (403, b"B")}
        status, body = routes.get(self.path, (404, b"?"))
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):                  # 测试里不要噪声
        pass


@pytest.fixture()
def http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        thread.join(timeout=5)


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _workspace(tmp_path: Path, *, base_url: str, patched_url: str,
               task_id: str = TASK_ID, benchmark: str = "vulngym") -> Path:
    root = tmp_path / "workspace"
    case = root / f"{CASE}-fake"
    case.mkdir(parents=True)
    doc = {
        "case_id": CASE,
        "task_id": task_id,
        "benchmark": benchmark,
        "baseline_url": base_url,
        "patched_url": patched_url,
        "expect": {"baseline_status": 200, "patched_status_in": [403]},
    }
    (case / "task.json").write_text(json.dumps(doc, ensure_ascii=False),
                                    encoding="utf-8")
    return root


def _run(args, *, cwd=ROOT):
    return subprocess.run([sys.executable, str(BIN), *args],
                          capture_output=True, text=True, cwd=str(cwd),
                          env=dict(os.environ))


def _smoke_args(tmp_path: Path, root: Path, *extra: str) -> list[str]:
    db = tmp_path / "platform.db"
    return ["--db", str(db), "smoke", CASE,
            "--workspace-root", str(root),
            "--execute", "--isolation", "none", "--timeout", "10",
            "--workdir", str(tmp_path / "smoke"), *extra]


def _store(tmp_path: Path) -> PlatformStore:
    return PlatformStore(tmp_path / "platform.db")


def _manifest_sha(evidence) -> str:
    """与 bin/platform.py `_smoke_manifest()` 同一口径（测试独立重算）。"""
    items = [{"kind": str(item.get("kind") or ""),
              "sha256": str(item.get("sha256") or ""),
              "size": int(item.get("size") or 0)} for item in evidence]
    items.sort(key=lambda x: (x["kind"], x["sha256"], x["size"]))
    blob = json.dumps(items, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _dumps(row) -> str:
    return json.dumps(row, ensure_ascii=False, default=str)


# ------------------------------------------------------- 1. verified 落库
def test_record_verified_persists_with_auditable_detail(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")

    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "run-001"))
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    entry = doc["cases"][0]
    assert entry["status"] == "would_verify" and entry["persisted"] is True
    assert doc["persisted"] is True
    summary = entry["verification"]
    assert summary["verification_id"] == f"SMOKE-{CASE}-run-001"
    assert summary["verified"] is True and summary["status"] == "verified"

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1
        row = rows[0]
        assert row["verification_id"] == f"SMOKE-{CASE}-run-001"
        assert row["benchmark"] == "vulngym" and row["kind"] == "behavior_diff"
        assert row["verified"] is True and row["status"] == "verified"
        assert row["evidence_sha256"] == _manifest_sha(entry["evidence"])
        assert row["evidence_sha256"] == summary["evidence_sha256"]

        detail = row["detail"]
        for key in ("case", "task", "benchmark", "spec", "evidence",
                    "criterion", "run_id"):
            assert key in detail, key
        assert detail["case"] == CASE
        assert detail["run_id"] == "run-001"
        assert detail["task"]["task_id"] == TASK_ID
        assert detail["task"]["task_json"].endswith("task.json")
        assert detail["task"]["state"] == "RECEIVED"
        assert detail["benchmark"] == "vulngym"
        assert detail["spec"]["baseline_url"].endswith("/base")
        assert detail["criterion"]["criterion_ok"] is True
        assert detail["checks"]["behavior_differs"] is True
        assert detail["evidence"] and all(
            set(item) == {"kind", "sha256", "size"} for item in detail["evidence"])
        assert detail["mode"] == "execute"
        assert detail["record_schema"] == "vulnmap.smoke_record.v1"
        # 不伪造候选：smoke 没有候选链
        assert row["candidate_id"] == ""
        assert "confirmed" not in _dumps(rows)
    finally:
        store.close()


# ------------------------------------------------------- 2. 缺口不落 verified
def test_record_needs_evidence_never_verified(tmp_path):
    port = _closed_port()
    root = _workspace(tmp_path, base_url=f"http://127.0.0.1:{port}/base",
                      patched_url=f"http://127.0.0.1:{port}/patched")

    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "gap-001"))
    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)["cases"][0]
    assert entry["status"] == "needs_evidence"
    assert entry["executed"] is False
    assert entry["verification"]["verified"] is False
    assert entry["verification"]["status"] == "needs_evidence"

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1
        assert rows[0]["verified"] is False
        assert rows[0]["status"] == "needs_evidence"
        assert rows[0]["evidence_sha256"] == _manifest_sha([])  # 空清单仍有确定哈希
        assert any(str(b).startswith("connection_failed:")
                   for b in rows[0]["detail"]["blockers"])
        assert "confirmed" not in _dumps(rows)
        # 任务仍是 RECEIVED：smoke 不改任务状态
        assert store.get_task(TASK_ID)["state"] == "RECEIVED"
    finally:
        store.close()


def test_dry_run_record_is_needs_evidence(tmp_path, http_server):
    """`--record` 不隐含 `--execute`：没跑就只有配方，不能写 verified。"""
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    db = tmp_path / "platform.db"
    proc = _run(["--db", str(db), "smoke", CASE, "--workspace-root", str(root),
                 "--record", "--ensure-task", "--run-id", "dry-001"])
    assert proc.returncode == 0, proc.stderr
    entry = json.loads(proc.stdout)["cases"][0]
    assert entry["status"] == "ready" and entry["executed"] is False
    assert entry["verification"]["verified"] is False
    assert entry["verification"]["status"] == "needs_evidence"

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1 and rows[0]["verified"] is False
        assert rows[0]["detail"]["mode"] == "dry-run"
    finally:
        store.close()


def test_negative_criterion_lands_no_repro(tmp_path, http_server):
    """判据不成立（两侧行为一致）→ no_repro，不是 needs_evidence。"""
    port = http_server.rsplit(":", 1)[1]
    root = _workspace(tmp_path, base_url=f"http://127.0.0.1:{port}/base",
                      patched_url=f"http://127.0.0.1:{port}/base")
    # expect 仍要求修补侧 403，实际两侧都是 200 → direction/behavior 不成立
    task_json = json.loads((next(root.iterdir()) / "task.json").read_text("utf-8"))
    task_json["baseline_url"] = f"http://127.0.0.1:{port}/base"
    task_json["patched_url"] = f"http://127.0.0.1:{port}/patched"
    task_json["expect"] = {"baseline_status": 200, "patched_status_in": [201]}
    (next(root.iterdir()) / "task.json").write_text(
        json.dumps(task_json), encoding="utf-8")

    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "neg-001"))
    assert proc.returncode == 0, proc.stderr
    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1
        assert rows[0]["verified"] is False
        assert rows[0]["status"] == "no_repro"
    finally:
        store.close()


# ------------------------------------------------------- 3. 幂等
def test_repeat_record_is_idempotent(tmp_path, http_server):
    """同一个 run 重复 record：一条记录、同一编号、首次时间戳不刷新。"""
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    args = _smoke_args(tmp_path, root, "--record", "--ensure-task",
                       "--run-id", "same-run")

    first = _run(args)
    assert first.returncode == 0, first.stderr
    second = _run(args)
    assert second.returncode == 0, second.stderr
    doc = json.loads(second.stdout)
    summary = doc["cases"][0]["verification"]
    assert summary["idempotent_overwrite"] is True

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1, rows
        assert rows[0]["verification_id"] == f"SMOKE-{CASE}-same-run"
        # 时间戳保留首次值：重复 record 不刷出一条“新”记录
        first_summary = json.loads(first.stdout)["cases"][0]["verification"]
        assert rows[0]["created_at"] == first_summary["created_at"]
        events = [e for e in store.list_events(TASK_ID)
                  if e["event_type"] == "verification.recorded"]
        assert len(events) >= 1        # 记录被修正时留痕，但行数不增长
    finally:
        store.close()


def test_repeat_record_without_new_evidence_is_byte_identical(tmp_path,
                                                              http_server):
    """内容完全没变（dry-run 无 runner 快照）→ 不写新事件，行逐字一致。"""
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    db = tmp_path / "platform.db"
    args = ["--db", str(db), "smoke", CASE, "--workspace-root", str(root),
            "--record", "--ensure-task", "--run-id", "stable-001"]
    assert _run(args).returncode == 0

    store = _store(tmp_path)
    try:
        first_row = store.list_verifications(TASK_ID)[0]
    finally:
        store.close()

    second = _run(args)
    assert second.returncode == 0, second.stderr
    summary = json.loads(second.stdout)["cases"][0]["verification"]
    assert summary["changed"] is False

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1
        assert rows[0] == first_row
        events = [e for e in store.list_events(TASK_ID)
                  if e["event_type"] == "verification.recorded"]
        assert len(events) == 1        # 内容没变就不补同义事件
    finally:
        store.close()


def test_default_run_id_is_stable_and_reuses_one_row(tmp_path, http_server):
    """不给 --run-id：同一配方重复跑只覆盖同一条记录，不会一次一行。"""
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    args = _smoke_args(tmp_path, root, "--record", "--ensure-task")
    assert _run(args).returncode == 0
    first = json.loads(_run(args).stdout)["cases"][0]["verification"]
    assert first["verification_id"].startswith(f"SMOKE-{CASE}-r")
    assert first["idempotent_overwrite"] is True

    store = _store(tmp_path)
    try:
        rows = store.list_verifications(TASK_ID)
        assert len(rows) == 1
        assert rows[0]["verification_id"] == first["verification_id"]
    finally:
        store.close()


def test_default_smoke_still_does_not_persist(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    proc = _run(_smoke_args(tmp_path, root))
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["persisted"] is False
    assert doc["cases"][0]["status"] == "would_verify"
    store = _store(tmp_path)
    try:
        with pytest.raises(TaskError):
            store.get_task(TASK_ID)                 # 没 --record 就不建任务
        assert store.list_verifications(TASK_ID) == []
    finally:
        store.close()


# ------------------------------------------------------- 4. 任务存在性
def test_record_without_task_errors_and_creates_nothing(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    proc = _run(_smoke_args(tmp_path, root, "--record", "--run-id", "no-task"))
    assert proc.returncode == 2
    doc = json.loads(proc.stdout)
    assert doc["persisted"] is False
    assert doc["errors"] and doc["errors"][0]["case"] == CASE
    assert "task not found" in doc["errors"][0]["error"]
    assert "--ensure-task" in doc["errors"][0]["error"]
    store = _store(tmp_path)
    try:
        with pytest.raises(TaskError):
            store.get_task(TASK_ID)                 # 不自动建假任务
        assert store.list_verifications(TASK_ID) == []
    finally:
        store.close()


def test_ensure_task_registers_received_from_task_json(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    task_json = next(root.iterdir()) / "task.json"
    before = task_json.read_bytes()

    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "ensure-001"))
    assert proc.returncode == 0, proc.stderr
    store = _store(tmp_path)
    try:
        task = store.get_task(TASK_ID)
        assert task["state"] == "RECEIVED"
        assert task["benchmark"] == "vulngym"
        events = store.list_events(TASK_ID)
        created = [e for e in events if e["event_type"] == "task.created"]
        assert len(created) == 1
        assert created[0]["payload"]["source"] == "smoke:record"
        assert created[0]["payload"]["task_json"].endswith("task.json")
        assert [e["event_type"] for e in events].count("verification.recorded") == 1
    finally:
        store.close()
    # task.json 只读：登记任务不回写工作区
    assert task_json.read_bytes() == before


def test_existing_task_is_reused_not_overwritten(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    store = _store(tmp_path)
    try:
        store.create_task(TaskSpec(task_id=TASK_ID, benchmark="vulngym",
                                   target=str(root), mode="fuzz"))
    finally:
        store.close()

    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "reuse-001"))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["cases"][0]["verification"]["task_created"] is False
    store = _store(tmp_path)
    try:
        task = store.get_task(TASK_ID)
        assert task["mode"] == "fuzz"               # 不被 smoke 覆盖
        assert len([e for e in store.list_events(TASK_ID)
                    if e["event_type"] == "task.created"]) == 0
    finally:
        store.close()


def test_benchmark_mismatch_is_refused(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    store = _store(tmp_path)
    try:
        store.create_task(TaskSpec(task_id=TASK_ID, benchmark="cybergym",
                                   target=str(root), mode="fuzz"))
    finally:
        store.close()

    proc = _run(_smoke_args(tmp_path, root, "--record", "--run-id", "mix-001"))
    assert proc.returncode == 2
    doc = json.loads(proc.stdout)
    assert "benchmark mismatch" in doc["errors"][0]["error"]
    store = _store(tmp_path)
    try:
        assert store.list_verifications(TASK_ID) == []
    finally:
        store.close()


def test_task_id_flag_rejects_multiple_cases(tmp_path):
    proc = _run(["--db", str(tmp_path / "platform.db"), "smoke",
                 "VG-01", "CG-01", "--workspace-root", str(tmp_path),
                 "--record", "--task-id", TASK_ID])
    assert proc.returncode == 2
    doc = json.loads(proc.stdout)
    assert "--task-id" in doc["errors"][0]["error"]
    assert doc["persisted"] is False


# ------------------------------------------------------- 5. API 可查
def test_api_exposes_recorded_verification(tmp_path, http_server, monkeypatch):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "api-001"))
    assert proc.returncode == 0, proc.stderr
    monkeypatch.setenv("PLATFORM_ROOT", str(tmp_path))

    from fastapi.testclient import TestClient

    from vulnmap_platform.api.app import app
    client = TestClient(app, client=("127.0.0.1", 50000))
    detail = client.get(f"/api/platform/tasks/{TASK_ID}")
    assert detail.status_code == 200
    body = detail.json()
    vids = [row["verification_id"] for row in body["verifications"]]
    assert vids == [f"SMOKE-{CASE}-api-001"]
    row = body["verifications"][0]
    assert row["verified"] is True and row["status"] == "verified"
    assert row["detail"]["run_id"] == "api-001"
    assert row["detail"]["criterion"]["criterion_ok"] is True
    assert body["summary"]["verifications"] == 1
    assert body["summary"]["verification_statuses"] == {"verified": 1}

    assert "confirmed" not in json.dumps(body["verifications"], ensure_ascii=False)

    listing = client.get("/api/platform/tasks")
    assert listing.status_code == 200
    assert any(item["task_id"] == TASK_ID for item in listing.json()["items"])


def test_cli_verifications_lists_record(tmp_path, http_server):
    root = _workspace(tmp_path, base_url=f"{http_server}/base",
                      patched_url=f"{http_server}/patched")
    proc = _run(_smoke_args(tmp_path, root, "--record", "--ensure-task",
                            "--run-id", "cli-001"))
    assert proc.returncode == 0, proc.stderr

    listed = _run(["--db", str(tmp_path / "platform.db"), "verifications", TASK_ID])
    assert listed.returncode == 0, listed.stderr
    rows = json.loads(listed.stdout)
    assert [row["verification_id"] for row in rows] == [f"SMOKE-{CASE}-cli-001"]
    assert rows[0]["verified"] is True
