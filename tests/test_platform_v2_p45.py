"""V2 P4.5 验收：执行作业化（jobs 表 / cancel / SSE）+ 可选 token 认证。

口径（与需求逐条对应）：

1. **run 不再 fire-and-forget**：`POST /api/platform/tasks/{id}/run` 在 `platform.db`
   的 `jobs` 表留一行（`job_id/task_id/pid/status/started/finished/log` 五列齐全），
   `GET /api/platform/jobs/{id}` 能查到 pid / 启动时间 / 日志 tail / 退出码，
   `GET /api/platform/jobs?task_id=` 能列；同一任务在有活作业时再 run → 409。
2. **状态以事件流为准**：job 的 `status` 是启动器视角（PENDING/RUNNING/EXITED/FAILED/
   CANCELLED），`state` 永远是 `task_events` 重放结果；两者不一致时以 `state` 为准，
   响应里带 `status_source="event_stream"`。
3. **cancel 是双动作**：先走状态机 `cancel_task()`（事件流写 `task.cancel_requested`，
   任务落 CANCELLED），再对进程组发 SIGTERM；重复取消 409，未知 job 404，
   进程已结束的 job 只取消任务状态（不把进程事实改写成 CANCELLED）。
4. **SSE**：`GET /api/platform/tasks/{id}/stream` 是 `text/event-stream`，
   帧序 `retry` → `hello` → `task_event`（带 id=seq）→ `state` → `end`；
   `after=` 续传、`once=1` 单趟、`max_events` 截断、终态 `reason=terminal`、未知任务 404。
5. **认证开关**：`PLATFORM_API_TOKEN` 未设置 → 写操作本地开放，响应 `auth.mode=open`
   且 HTTP 头 `X-Platform-Auth: open`；设置后写操作必须 `Authorization: Bearer`，
   缺失 401（带 `WWW-Authenticate`）、错误 403；GET 一律开放；token 每请求重读。
6. **页面**：`platform-task.html` / `platform-events.html` 用 `EventSource` 跟随
   `/stream`；页面仍然只读（不碰 SQLite、除提交页外无 `postJSON`）。

全部测试用临时 `PLATFORM_ROOT`：不碰仓库 `.platform`，也不依赖运行中的 8102 服务。
执行器命令被换成本机小脚本（`python -c`），但 **spawn/task/finished 都是真进程**，
所以 pid、退出码、SIGTERM 都是真的。
"""
from __future__ import annotations

import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import EventBus, PlatformStore, TaskSpec
from vulnmap_platform.api import platform_jobs

STATIC = ROOT / "vulnmap_platform" / "static"
CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED")
JOB_COLUMNS = ("job_id", "task_id", "pid", "status", "started", "finished", "log")

#: 换成执行器命令的本机小脚本：长睡（活作业）/ 正常退出 / 非零退出
CODE_SLEEP = "import time; time.sleep(60)"
CODE_OK = "import sys; sys.exit(0)"
CODE_BAD = "import sys; sys.exit(7)"


# ------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def client():
    fastapi_testclient = pytest.importorskip("fastapi.testclient")
    from vulnmap_platform.api.app import app
    return fastapi_testclient.TestClient(app)


@pytest.fixture()
def platform_root(tmp_path, monkeypatch):
    """每个测试一个独立 PLATFORM_ROOT；token 默认不设置（本地开放）。"""
    root = tmp_path / "platform"
    root.mkdir()
    monkeypatch.setenv("PLATFORM_ROOT", str(root))
    monkeypatch.delenv("PLATFORM_API_TOKEN", raising=False)
    return root


@pytest.fixture()
def spawner(monkeypatch):
    """把执行器命令换成本机脚本，但保留真实 spawn / 真进程 / 真信号。"""
    real_spawn = platform_jobs._spawn_process
    state: dict = {"code": CODE_SLEEP, "argv": [], "pids": [], "logs": []}

    def fake(argv, log_path, cwd=None):
        state["argv"].append([str(a) for a in argv])
        state["logs"].append(str(log_path))
        return real_spawn([sys.executable, "-c", state["code"]], log_path, cwd)

    monkeypatch.setattr(platform_jobs, "_spawn_process", fake)
    monkeypatch.setattr(sys, "_vulnmap_p45_state", state, raising=False)
    yield state
    for pid in state["pids"]:
        try:
            os.kill(int(pid), signal.SIGKILL)
        except OSError:
            pass


def _target(root: Path, name: str = "ws") -> str:
    path = root / name
    path.mkdir(exist_ok=True)
    return str(path)


def _db(root: Path) -> Path:
    return root / "platform.db"


def _submit(client, root: Path, *, task_id: str = "p45-demo",
            benchmark: str = "target_yaml", target: str | None = None) -> dict:
    r = client.post("/api/platform/tasks", json={
        "task_id": task_id, "benchmark": benchmark,
        "target": target if target is not None else _target(root),
        # F1：缺失授权默认阻断，API 夹具显式声明
        "metadata": {"authorized": True}})
    assert r.status_code == 201, r.text
    return r.json()


def _planned(client, root: Path, *, task_id: str = "p45-run") -> dict:
    """建任务并推到 PLANNED（run 的唯一合法入口状态）。"""
    body = _submit(client, root, task_id=task_id)
    store = PlatformStore(_db(root))
    try:
        for state in CHAIN:
            store.transition(task_id, state, reason="p45 fixture")
    finally:
        store.close()
    return body


def _run_job(client, root: Path, *, task_id: str = "p45-run",
             body: dict | None = None) -> dict:
    r = client.post(f"/api/platform/tasks/{task_id}/run", json=body or {})
    assert r.status_code == 200, r.text
    return r.json()


def _job(client, job_id: str) -> dict:
    r = client.get(f"/api/platform/jobs/{job_id}")
    assert r.status_code == 200, r.text
    return r.json()


def _wait_status(client, job_id: str, want, timeout: float = 15.0) -> dict:
    want = {want} if isinstance(want, str) else set(want)
    deadline = time.monotonic() + timeout
    data = _job(client, job_id)
    while time.monotonic() < deadline:
        if data["status"] in want:
            return data
        time.sleep(0.05)
        data = _job(client, job_id)
    return data


def _wait_pid_gone(pid: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not platform_jobs.pid_alive(pid):
            return True
        time.sleep(0.05)
    return not platform_jobs.pid_alive(pid)


def _frames(text: str) -> list[dict]:
    """把 SSE 原文切成帧：{retry|event|id|data}。"""
    out = []
    for block in text.split("\n\n"):
        frame: dict = {}
        for line in block.splitlines():
            if line.startswith("retry: "):
                frame["retry"] = int(line[len("retry: "):])
            elif line.startswith("event: "):
                frame["event"] = line[len("event: "):]
            elif line.startswith("id: "):
                frame["id"] = int(line[len("id: "):])
            elif line.startswith("data: "):
                frame["data"] = json.loads(line[len("data: "):])
        if frame:
            out.append(frame)
    return out


def _ev(frames: list[dict], name: str) -> list[dict]:
    """按帧名筛（`retry` 帧没有 event 字段，不能直接下标）。"""
    return [f for f in frames if f.get("event") == name]


def _stream(client, task_id: str, **params) -> tuple[object, list[dict]]:
    r = client.get(f"/api/platform/tasks/{task_id}/stream", params=params)
    return r, _frames(r.text) if r.status_code == 200 else []


def _row(root: Path, job_id: str) -> dict:
    conn = sqlite3.connect(str(_db(root)))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    finally:
        conn.close()
    assert row is not None, f"jobs 表里没有 {job_id}"
    return dict(row)


def _events(client, task_id: str) -> list[dict]:
    return client.get(f"/api/platform/tasks/{task_id}/events").json()["items"]


# ------------------------------------------------------------ 1. 作业生命周期
def test_run_creates_job_row_with_pid_and_log(client, platform_root, spawner):
    _planned(client, platform_root, task_id="life-1")
    body = _run_job(client, platform_root, task_id="life-1")
    job = body["job"]
    assert job["task_id"] == "life-1"
    assert job["job_id"].startswith("job-")
    assert job["status"] == "RUNNING"
    assert job["pid"] and job["pid"] > 0
    assert body["pid"] == job["pid"]
    assert Path(job["log"]["path"]) == platform_root / "runs" / "life-1.log"
    assert body["state"] == "PLANNED"          # 触发本身不改任务状态

    row = _row(platform_root, job["job_id"])
    for column in JOB_COLUMNS:                 # 需求点名的五列 + log 全在
        assert column in row
    assert row["task_id"] == "life-1"
    assert row["pid"] == job["pid"]
    assert row["started"]
    assert row["finished"] == ""
    assert row["log"].endswith("life-1.log")

    detail = _job(client, job["job_id"])
    assert detail["status"] == "RUNNING"
    assert detail["state"] == "PLANNED"
    assert detail["status_source"] == "event_stream"
    assert detail["finished"] is False
    assert detail["job_finished"] is False
    assert detail["task"]["task_id"] == "life-1"
    assert detail["links"]["cancel"].endswith(f"/jobs/{job['job_id']}/cancel")
    assert detail["links"]["stream"].endswith("/tasks/life-1/stream")

    # 列表 + 任务详情都能看到这条作业
    listed = client.get("/api/platform/jobs", params={"task_id": "life-1"}).json()
    assert [j["job_id"] for j in listed["jobs"]] == [job["job_id"]]
    assert client.get("/api/platform/tasks/life-1").json()["jobs"][0]["job_id"] == job["job_id"]


def test_run_rejects_wrong_state_and_second_live_job(client, platform_root, spawner):
    _submit(client, platform_root, task_id="life-2")          # RECEIVED
    r = client.post("/api/platform/tasks/life-2/run", json={})
    assert r.status_code == 409 and "PLANNED" in r.json()["detail"]

    store = PlatformStore(_db(platform_root))
    try:
        for state in CHAIN:
            store.transition("life-2", state, reason="p45 fixture")
    finally:
        store.close()
    job = _run_job(client, platform_root, task_id="life-2")["job"]
    again = client.post("/api/platform/tasks/life-2/run", json={})
    assert again.status_code == 409
    assert job["job_id"] in again.json()["detail"]     # 指出是哪条活作业
    client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={"reason": "done"})


def test_job_records_exit_code_for_success_and_failure(client, platform_root, spawner):
    spawner["code"] = CODE_OK
    _planned(client, platform_root, task_id="exit-ok")
    ok = _run_job(client, platform_root, task_id="exit-ok")["job"]
    done = _wait_status(client, ok["job_id"], {"EXITED", "FAILED"})
    assert done["status"] == "EXITED"
    assert done["job"]["exit_code"] == 0
    assert done["job"]["finished"]
    assert done["job"]["alive"] is False

    spawner["code"] = CODE_BAD
    _planned(client, platform_root, task_id="exit-bad")
    bad = _run_job(client, platform_root, task_id="exit-bad")["job"]
    failed = _wait_status(client, bad["job_id"], {"EXITED", "FAILED"})
    assert failed["status"] == "FAILED"
    assert failed["job"]["exit_code"] == 7
    assert "exited 7" in (failed["job"]["note"] or "")


def test_job_log_tail_is_visible(client, platform_root, spawner):
    spawner["code"] = "print('executor says hi')"
    _planned(client, platform_root, task_id="log-1")
    job = _run_job(client, platform_root, task_id="log-1")["job"]
    done = _wait_status(client, job["job_id"], {"EXITED", "FAILED"})
    tail = done["job"]["log"]["tail"]
    assert done["job"]["log"]["exists"] is True
    assert "executor says hi" in tail
    assert done["job"]["log"]["size"] > 0


def test_state_comes_from_event_stream_not_launcher(client, platform_root, spawner):
    """job 进程退出（EXITED）但任务状态还在事件流里往前走：以 state 为准。"""
    spawner["code"] = CODE_OK
    _planned(client, platform_root, task_id="auth-1")
    job = _run_job(client, platform_root, task_id="auth-1")["job"]
    _wait_status(client, job["job_id"], {"EXITED", "FAILED"})

    store = PlatformStore(_db(platform_root))
    try:
        store.transition("auth-1", "RUNNING", reason="p45 fixture")
    finally:
        store.close()
    detail = _job(client, job["job_id"])
    assert detail["status"] == "EXITED"        # 启动器视角：进程已退出
    assert detail["state"] == "RUNNING"        # 事件流视角：任务在跑
    assert detail["finished"] is False          # 任务还没到终态
    assert detail["job_finished"] is True       # 进程这一侧已经结束
    assert detail["timeline"][-1]["to"] == "RUNNING"
    assert [t["to"] for t in detail["timeline"]] == list(CHAIN) + ["RUNNING"]


def test_jobs_reads_do_not_create_database_or_touch_schema(client, platform_root):
    """没库时读 job 端点不建库；有库时 jobs 表不影响 PlatformStore 的 schema 版本。"""
    assert _db(platform_root).exists() is False
    assert client.get("/api/platform/jobs").json()["count"] == 0
    assert client.get("/api/platform/jobs/job-nope").status_code == 404
    assert _db(platform_root).exists() is False          # 读路径没建库

    _submit(client, platform_root, task_id="schema-1")
    assert _db(platform_root).is_file()
    from agent.platform.store import SCHEMA_VERSION as STORE_SCHEMA_VERSION
    conn = sqlite3.connect(str(_db(platform_root)))
    try:
        # 启动器 jobs 表（API 侧自建 + V3 P3 的两个关联列）不改变 PlatformStore
        # 的 schema 版本：这里跟常量比，不写死数字（V3 P3 起是 5）
        assert conn.execute("PRAGMA user_version").fetchone()[0] \
            == STORE_SCHEMA_VERSION
    finally:
        conn.close()
    store = PlatformStore(_db(platform_root))            # 加了 jobs 表仍能正常打开
    try:
        assert store.get_task("schema-1")["state"] == "RECEIVED"
    finally:
        store.close()


# ------------------------------------------------------------------ 2. cancel
def test_cancel_live_job_cancels_task_and_signals_process(client, platform_root, spawner):
    _planned(client, platform_root, task_id="cancel-1")
    job = _run_job(client, platform_root, task_id="cancel-1")["job"]
    assert job["status"] == "RUNNING"

    r = client.post(f"/api/platform/jobs/{job['job_id']}/cancel",
                    json={"reason": "p45 test"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] is True
    assert out["state"] == "CANCELLED"
    assert out["task"]["from"] == "PLANNED"
    assert out["job_cancelled"] is True
    assert out["signal"] == "SIGTERM"
    assert out["job"]["status"] == "CANCELLED"
    assert out["job"]["finished"]

    # 事件流先落痕：task.cancel_requested → state.changed→CANCELLED → task.cancelled
    events = _events(client, "cancel-1")
    types = [e["event_type"] for e in events]
    assert "task.cancel_requested" in types
    assert types[-1] == "task.cancelled"
    assert [e["payload"].get("to") for e in events
            if e["event_type"] == "state.changed"][-1] == "CANCELLED"
    assert events[-1]["seq"] == out["event_seq"]

    # 进程真的被信号打掉了（真进程、真 SIGTERM）
    assert _wait_pid_gone(job["pid"]) is True
    assert _job(client, job["job_id"])["job"]["alive"] is False
    # watcher 不会把已取消的作业改写成 EXITED/FAILED
    time.sleep(0.3)
    assert _job(client, job["job_id"])["status"] == "CANCELLED"

    again = client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={})
    assert again.status_code == 409
    assert "terminal" in again.json()["detail"]


def test_cancel_finished_job_only_cancels_task(client, platform_root, spawner):
    """进程已结束的作业不把进程事实改写成 CANCELLED，但任务取消照样受理。"""
    spawner["code"] = CODE_OK
    _planned(client, platform_root, task_id="cancel-2")
    job = _run_job(client, platform_root, task_id="cancel-2")["job"]
    _wait_status(client, job["job_id"], {"EXITED", "FAILED"})

    r = client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={"reason": "late"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["job_cancelled"] is False
    assert out["status"] == "EXITED"
    assert out["state"] == "CANCELLED"
    assert "只取消任务状态" in out["note"]


def test_cancel_errors(client, platform_root, spawner):
    assert client.post("/api/platform/jobs/job-missing/cancel", json={}).status_code == 404

    _planned(client, platform_root, task_id="cancel-3")
    job = _run_job(client, platform_root, task_id="cancel-3")["job"]
    client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={})
    # 任务已终态：再取消任何 job 都 409（state 是唯一裁判）
    later = client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={})
    assert later.status_code == 409


# -------------------------------------------------------------------- 3. SSE
def test_stream_once_replays_events_then_ends(client, platform_root, spawner):
    spawner["code"] = CODE_OK
    _planned(client, platform_root, task_id="sse-1")
    job = _run_job(client, platform_root, task_id="sse-1")["job"]
    _wait_status(client, job["job_id"], {"EXITED", "FAILED"})

    r, frames = _stream(client, "sse-1", once=1)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert frames[0] == {"retry": 1000}
    assert frames[1]["event"] == "hello"
    assert frames[1]["data"]["task_id"] == "sse-1"
    assert frames[1]["data"]["state"] == "PLANNED"

    events = _ev(frames, "task_event")
    server = _events(client, "sse-1")
    assert len(events) == len(server)
    assert [f["id"] for f in events] == [e["seq"] for e in server]
    assert events[0]["data"]["event_type"] == "task.created"
    assert any(f["event"] == "state" and f["data"]["state"] == "PLANNED"
               for f in _ev(frames, "state"))
    assert frames[-1]["event"] == "end"
    assert frames[-1]["data"]["reason"] == "once"
    assert any(f["data"].get("jobs") for f in _ev(frames, "state"))


def test_stream_after_is_incremental(client, platform_root, spawner):
    _planned(client, platform_root, task_id="sse-2")
    events = _events(client, "sse-2")
    last = events[-1]["seq"]
    r, frames = _stream(client, "sse-2", after=last, once=1)
    assert r.status_code == 200
    assert _ev(frames, "task_event") == []
    assert frames[-1]["data"] == {"reason": "once", "after": last, "emitted": 0}

    tail_from_middle = _stream(client, "sse-2", after=last - 1, once=1)[1]
    got = [f["id"] for f in _ev(tail_from_middle, "task_event")]
    assert got == [last]


def test_stream_ends_on_terminal_state(client, platform_root, spawner):
    _planned(client, platform_root, task_id="sse-3")
    job = _run_job(client, platform_root, task_id="sse-3")["job"]
    client.post(f"/api/platform/jobs/{job['job_id']}/cancel", json={"reason": "sse"})

    r, frames = _stream(client, "sse-3", once=1)
    assert r.status_code == 200
    assert frames[-1]["event"] == "end"
    assert frames[-1]["data"]["reason"] == "terminal"
    assert frames[-1]["data"]["state"] == "CANCELLED"
    assert any(f["event"] == "state" and f["data"]["terminal"] is True
               for f in _ev(frames, "state"))


def test_stream_max_events_and_timeout_and_404(client, platform_root, spawner):
    _planned(client, platform_root, task_id="sse-4")
    r, frames = _stream(client, "sse-4", once=0, max_events=2, timeout=5)
    assert r.status_code == 200
    assert len(_ev(frames, "task_event")) == 2
    assert frames[-1]["event"] == "end"
    assert frames[-1]["data"]["reason"] == "max_events"
    assert frames[-1]["data"]["emitted"] == 2

    started = time.monotonic()
    r2, frames2 = _stream(client, "sse-4", timeout=0.3, poll=0.05)
    assert time.monotonic() - started < 10
    assert r2.status_code == 200
    assert frames2[-1]["event"] == "end"
    assert frames2[-1]["data"]["reason"] == "timeout"

    assert client.get("/api/platform/tasks/nope/stream?once=1").status_code == 404


def test_stream_head_has_no_cache_headers(client, platform_root):
    _submit(client, platform_root, task_id="sse-5")
    r, frames = _stream(client, "sse-5", once=1)
    assert r.status_code == 200
    assert r.headers["cache-control"].startswith("no-cache")
    assert r.headers["x-accel-buffering"] == "no"
    assert r.headers["x-platform-auth"] == "open"
    assert frames[0]["retry"] == 1000


# ------------------------------------------------------------------- 4. 认证
def test_writes_are_open_and_annotated_without_token(client, platform_root, spawner):
    body = _submit(client, platform_root, task_id="auth-open")
    assert body["auth"]["mode"] == "open"
    assert body["auth"]["token_required"] is False
    assert "未设置" in body["auth"]["note"]

    r = client.post("/api/platform/tasks/auth-open/preflight")
    assert r.status_code == 200
    assert r.json()["auth"]["mode"] == "open"
    assert r.headers["x-platform-auth"] == "open"

    store = PlatformStore(_db(platform_root))
    try:
        for state in ("UNDERSTANDING", "HYPOTHESES", "PLANNED"):
            store.transition("auth-open", state, reason="p45 fixture")
    finally:
        store.close()
    run = _run_job(client, platform_root, task_id="auth-open")
    assert run["auth"]["mode"] == "open"
    cancel = client.post(f"/api/platform/jobs/{run['job']['job_id']}/cancel", json={})
    assert cancel.status_code == 200
    assert cancel.json()["auth"]["mode"] == "open"
    # 读端点也标注（不含 token 本身）
    assert client.get("/api/platform/tasks").json() != {}
    assert client.get(f"/api/platform/jobs/{run['job']['job_id']}").json()["auth"]["mode"] == "open"


def test_token_requires_bearer_on_writes(client, platform_root, spawner, monkeypatch):
    _planned(client, platform_root, task_id="auth-tok")
    monkeypatch.setenv("PLATFORM_API_TOKEN", "s3cret-token")

    payload = {"benchmark": "target_yaml", "target": _target(platform_root, "ws2")}
    missing = client.post("/api/platform/tasks", json=payload)
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"].lower().startswith("bearer")
    assert "PLATFORM_API_TOKEN" in missing.json()["detail"]

    wrong = client.post("/api/platform/tasks", json=payload,
                        headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 403

    bad_scheme = client.post("/api/platform/tasks", json=payload,
                             headers={"Authorization": "Basic s3cret-token"})
    assert bad_scheme.status_code == 401

    ok = client.post("/api/platform/tasks", json={**payload, "task_id": "auth-tok-2"},
                     headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 201
    assert ok.json()["auth"]["mode"] == "bearer"
    assert ok.json()["auth"]["token_required"] is True
    assert ok.headers["x-platform-auth"] == "bearer"

    gate = client.post("/api/platform/tasks",
                       json={**payload, "task_id": "auth-gate"},
                       headers={"Authorization": "Bearer s3cret-token"})
    assert gate.status_code == 201
    assert client.post("/api/platform/tasks/auth-gate/preflight").status_code == 401
    assert client.post("/api/platform/tasks/auth-gate/preflight",
                       headers={"Authorization": "Bearer s3cret-token"}).status_code == 200

    assert client.post("/api/platform/tasks/auth-tok/run", json={}).status_code == 401
    run = client.post("/api/platform/tasks/auth-tok/run", json={},
                      headers={"Authorization": "Bearer s3cret-token"})
    assert run.status_code == 200
    job_id = run.json()["job"]["job_id"]

    assert client.post(f"/api/platform/jobs/{job_id}/cancel", json={}).status_code == 401
    cancelled = client.post(f"/api/platform/jobs/{job_id}/cancel", json={},
                            headers={"Authorization": "Bearer s3cret-token"})
    assert cancelled.status_code == 200

    # 读端点不受影响
    assert client.get("/api/platform/tasks").status_code == 200
    assert client.get(f"/api/platform/jobs/{job_id}").status_code == 200
    assert client.get("/api/platform/tasks/auth-tok/stream?once=1").status_code == 200


def test_token_is_read_per_request_not_cached(client, platform_root, monkeypatch):
    payload = {"benchmark": "target_yaml", "target": _target(platform_root, "ws3")}
    monkeypatch.setenv("PLATFORM_API_TOKEN", "one-shot")
    assert client.post("/api/platform/tasks", json=payload).status_code == 401
    monkeypatch.delenv("PLATFORM_API_TOKEN")
    assert client.post("/api/platform/tasks",
                       json={**payload, "task_id": "auth-flip"}).status_code == 201


# -------------------------------------------------------------------- 5. 页面
def test_pages_use_eventsource_for_live_updates(client, platform_root):
    for name in ("platform-task.html", "platform-events.html"):
        text = (STATIC / name).read_text(encoding="utf-8")
        assert "EventSource(" in text, f"{name} 应使用 EventSource"
        assert "/stream" in text, f"{name} 应订阅 /stream"
        r = client.get("/" + name)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "app.js" in r.text and "style.css" in r.text
    task_page = (STATIC / "platform-task.html").read_text(encoding="utf-8")
    assert "/api/platform/jobs/" in task_page        # 作业面板读 job 端点
    assert "es.close()" in task_page or ".close()" in task_page
    events_page = (STATIC / "platform-events.html").read_text(encoding="utf-8")
    assert "after=" in events_page


def test_pages_stay_read_only_consumers():
    """页面仍然不碰 SQLite、不在提交页之外发写请求（P4 的硬约束继续有效）。"""
    pages = ("platform-tasks.html", "platform-task.html", "platform-events.html",
             "platform-evidence.html", "platform-casepack.html")
    for name in pages:
        text = (STATIC / name).read_text(encoding="utf-8")
        assert "sqlite" not in text.lower(), f"{name} 不应直接读库"
        for verb in ("DELETE", "PUT", "PATCH"):
            assert verb not in text, f"{name} 出现 {verb} 请求"
        if name != "platform-tasks.html":
            assert "postJSON(" not in text, f"{name} 写请求应走 writeJSON"
    tasks_page = (STATIC / "platform-tasks.html").read_text(encoding="utf-8")
    posts = {line.strip() for line in tasks_page.splitlines() if "postJSON(" in line}
    assert posts and all("/api/platform/tasks" in line for line in posts)

    app_js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "writeJSON" in app_js
    assert "platform_token" in app_js
    assert "Bearer" in app_js


def test_new_routes_registered(client, platform_root):
    paths = {r.path for r in client.app.routes if getattr(r, "path", "")}
    for expected in ("/api/platform/jobs",
                     "/api/platform/jobs/{job_id}",
                     "/api/platform/jobs/{job_id}/cancel",
                     "/api/platform/tasks/{task_id}/stream"):
        assert expected in paths, f"缺少路由 {expected}"


def test_jobs_endpoint_reports_auth_note(client, platform_root):
    data = client.get("/api/platform/jobs").json()
    assert data["count"] == 0
    assert data["auth"]["mode"] == "open"
    assert "事件流" in data["note"]
