"""V2 P4/P4.5：任务运行时的 Web/API 面（只读查询 + 提交/准入/执行作业）。

设计边界（与 P0–P3 的运行时一致）：

- **读端点不改状态**：只调用 `PlatformStore` 的 get/list/summary 与 `EventBus.replay`，
  不写任务、不写事件、不改候选/验证/复核记录；库不存在时直接返回空列表或 404，
  不会为了“看一眼”而建库。
- **写端点只有四类**：任务提交（`POST /api/platform/tasks`）、准入门
  （`POST /api/platform/tasks/{id}/preflight`）、显式执行触发
  （`POST /api/platform/tasks/{id}/run`，P4.5 起落成 **Job**）、作业取消
  （`POST /api/platform/jobs/{id}/cancel`）。执行本身交给 `bin/platform.py run`
  子进程，HTTP 请求不跑目标、不伪造状态。
- **P4.5 执行不再是 fire-and-forget**：`/run` 在 `platform.db` 的 `jobs` 表留一行
  （job_id/task_id/pid/status/started/finished/log），后台线程监视退出码，
  `GET /api/platform/jobs/{id}` 能查、`POST /api/platform/jobs/{id}/cancel` 能停。
  **job.status 只是启动器视角**；任务状态永远以 `task_events` 事件流重放为准
  （响应里 `state` 与 `status` 分开给）。
- **SSE**：`GET /api/platform/tasks/{id}/stream` 把事件流推给页面（`text/event-stream`），
  页面用 `EventSource` 更新，不再靠定时轮询。
- **写操作默认只开本机**（P4.6）：`PLATFORM_API_TOKEN` 未设置时，写操作只受理
  回环客户端（`127.0.0.1` / `::1` / `localhost`）；远端一律 403 并提示设置 token。
  设置 token 后写操作要求 `Authorization: Bearer`，与本机/远端无关。响应体 `auth`
  字段与 `X-Platform-Auth` / `X-Platform-Write-Scope` 头都如实标注当前口径。
- **页面只读消费**：页面全部通过本模块的 API 取数，不碰 SQLite；
  按钮只提交/准入/触发/取消，状态只能由运行时写。
- **V3 P4a 研究轮次只读面**：`/research`、`/research/events`、
  `/research/evidence` 三个 GET 只读 `research.json` 与事件流，404=没有这个
  研究记录，409=记录存在但不可用（坏 JSON / 串任务 / 与 `research.mapped`
  登记的哈希不一致）；解释器在 `platform_research.py`，CLI 共用同一份。

数据源：`<PLATFORM_ROOT>/platform.db`（默认 `<repo>/.platform/platform.db`）、
证据 `<PLATFORM_ROOT>/evidence`、CasePack `<PLATFORM_ROOT>/casepacks/<task_id>`、
执行日志 `<PLATFORM_ROOT>/runs/<task_id>.log`。
`PLATFORM_ROOT` 与 `PLATFORM_API_TOKEN` 每次请求重新读取，便于测试用临时目录覆盖。
"""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import sys
import time
from contextlib import contextmanager
from hashlib import sha256
from typing import Any, Iterator

from fastapi import Body, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse

from agent.platform import (Budget, EventBus, PlatformStore, STATES, TaskError,
                            TaskSpec, cancel_task, new_task_id, run_preflight)
from agent.platform.task import BENCHMARKS, TERMINAL

from . import platform_jobs
from . import platform_research as research_view
from .platform_auth import MODE_HEADER, SCOPE_HEADER, auth_info, write_guard

PLATFORM_ROOT_ENV = "PLATFORM_ROOT"
MAX_LIST = 200
MAX_ROWS = 200
DL_MEDIA = {".md": "text/markdown; charset=utf-8",
            ".html": "text/html; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jsonl": "application/x-ndjson; charset=utf-8"}


def _json_bytes(doc: Any) -> bytes:
    """与 agent/platform/casepack.py 完全一致的内容哈希口径。"""
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
                       default=str) + "\n").encode("utf-8")


def register_routes(app, root) -> None:
    repo_root = pathlib.Path(root).resolve()

    def _root() -> pathlib.Path:
        raw = (os.environ.get(PLATFORM_ROOT_ENV) or "").strip()
        if raw:
            return pathlib.Path(raw).expanduser().resolve()
        return (repo_root / ".platform").resolve()

    @contextmanager
    def _open(create: bool = False):
        db = _root() / "platform.db"
        if not create and not db.is_file():
            yield None
            return
        try:
            store = PlatformStore(db)
        except (sqlite3.Error, OSError) as exc:
            raise HTTPException(503, f"platform db unavailable: {exc}") from exc
        try:
            yield store
        finally:
            store.close()

    def _count(store: PlatformStore, table: str, task_id: str) -> int:
        row = store.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE task_id=?", (task_id,)).fetchone()
        return int(row[0]) if row else 0

    def _counts(store: PlatformStore, task_id: str) -> dict:
        return {
            "events": _count(store, "task_events", task_id),
            "evidence": _count(store, "task_evidence", task_id),
            "candidates": _count(store, "candidates", task_id),
            "verifications": _count(store, "verifications", task_id),
            "reviews": _count(store, "reviews", task_id),
            "reports": _count(store, "reports", task_id),
        }

    def _row(store: PlatformStore, row: sqlite3.Row) -> dict:
        item = dict(row)
        item["budget"] = json.loads(item.pop("budget_json") or "{}")
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        item["counts"] = _counts(store, item["task_id"])
        return item

    def _task_or_404(store: PlatformStore | None, task_id: str) -> dict:
        if store is None:
            raise HTTPException(404, "task not found")
        try:
            return store.get_task(task_id)
        except TaskError as exc:
            raise HTTPException(404, "task not found") from exc

    def _db_path() -> pathlib.Path:
        return _root() / "platform.db"

    def _links(task_id: str) -> dict:
        base = f"/api/platform/tasks/{task_id}"
        return {"self": base, "events": f"{base}/events",
                "stream": f"{base}/stream",
                "evidence": f"{base}/evidence",
                "casepack": f"{base}/casepack",
                "research": f"{base}/research",
                "research_events": f"{base}/research/events",
                "research_evidence": f"{base}/research/evidence",
                "jobs": f"/api/platform/jobs?task_id={task_id}",
                "preflight": f"{base}/preflight", "run": f"{base}/run"}

    def _job_links(job_id: str, task_id: str) -> dict:
        base = f"/api/platform/jobs/{job_id}"
        return {"self": base, "cancel": f"{base}/cancel",
                "task": f"/api/platform/tasks/{task_id}",
                "stream": f"/api/platform/tasks/{task_id}/stream"}

    def _mark(response: Response | None, auth: dict) -> None:
        if response is None:
            return
        try:
            response.headers[MODE_HEADER] = str(auth.get("mode") or "open")
            response.headers[SCOPE_HEADER] = str(
                auth.get("write_scope") or "loopback")
        except Exception:      # pragma: no cover
            pass

    def _latest_report(store: PlatformStore, task_id: str) -> dict | None:
        reports = store.list_reports(task_id)
        return reports[-1] if reports else None

    def _pack_files(pack_dir: pathlib.Path) -> list[dict]:
        """盘上文件清单：优先读包内 casepack.json，读不到就扫目录。"""

        def safe(path: pathlib.Path) -> dict:
            return {"path": path.relative_to(pack_dir).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256(path.read_bytes()).hexdigest()}

        manifest = pack_dir / "casepack.json"
        if manifest.is_file():
            try:
                doc = json.loads(manifest.read_text(encoding="utf-8"))
                files = [f for f in (doc.get("files") or [])
                         if isinstance(f, dict) and f.get("path")]
                if files:
                    return [{"path": str(f["path"]),
                             "size": int(f.get("size") or 0),
                             "sha256": str(f.get("sha256") or "")}
                            for f in files]
            except (ValueError, OSError):
                pass
        return [safe(p) for p in sorted(pack_dir.rglob("*"))
                if p.is_file() and p.name != "casepack.json"]

    def _recompute(pack_dir: pathlib.Path) -> dict:
        """按 casepack 的口径重算 content_sha256，用于展示“哈希可复算”。"""
        try:
            files = _pack_files(pack_dir)
        except OSError:
            return {"content_sha256": "", "hash_ok": False,
                    "reason": "pack dir unreadable"}
        listed = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"]}
                  for f in files]
        listed.sort(key=lambda x: x["path"])
        digest = sha256(_json_bytes(listed)).hexdigest()
        return {"content_sha256": digest, "hash_ok": bool(files)}

    # ------------------------------------------------------------ 提交 / 列表
    @app.get("/api/platform/tasks")
    def platform_tasks(state: str = "", benchmark: str = "", limit: int = 50):
        """任务列表：只读。库不存在时给空列表 + exists=false，不建库。"""
        if state and state not in STATES:
            raise HTTPException(400, f"unknown state: {state}")
        if benchmark and benchmark not in BENCHMARKS:
            raise HTTPException(400, f"unknown benchmark: {benchmark}")
        limit = max(1, min(int(limit or 50), MAX_LIST))
        root_dir = _root()
        db = root_dir / "platform.db"
        with _open() as store:
            if store is None:
                return {"root": str(root_dir), "db": str(db), "exists": False,
                        "items": [], "auth": auth_info(),
                        "totals": {"tasks": 0, "by_state": {},
                                   "by_benchmark": {}, "filtered": 0}}
            sql = "SELECT * FROM tasks"
            args: list = []
            where = []
            if state:
                where.append("state=?")
                args.append(state)
            if benchmark:
                where.append("benchmark=?")
                args.append(benchmark)
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY created_at DESC, task_id DESC"
            rows = store.conn.execute(sql, args).fetchall()
            all_rows = store.conn.execute("SELECT * FROM tasks").fetchall()
            items = [_row(store, r) for r in rows[:limit]]
        by_state: dict[str, int] = {}
        by_bench: dict[str, int] = {}
        for r in all_rows:
            by_state[r["state"]] = by_state.get(r["state"], 0) + 1
            by_bench[r["benchmark"]] = by_bench.get(r["benchmark"], 0) + 1
        return {"root": str(root_dir), "db": str(db), "exists": True,
                "items": items,
                "auth": auth_info(),
                "totals": {"tasks": len(all_rows), "by_state": by_state,
                           "by_benchmark": by_bench, "filtered": len(rows)}}

    @app.post("/api/platform/tasks", status_code=201)
    def platform_submit(payload: dict = Body(...),
                        auth: dict = Depends(write_guard),
                        response: Response = None):
        """任务提交（RECEIVED）。只建任务 + task.created 事件，不执行目标。"""
        _mark(response, auth)
        if not isinstance(payload, dict):
            raise HTTPException(400, "body must be a JSON object")
        benchmark = str(payload.get("benchmark") or "").strip()
        if benchmark not in BENCHMARKS:
            raise HTTPException(
                400, f"benchmark must be one of {list(BENCHMARKS)}")
        target = str(payload.get("target") or "").strip()
        if not target:
            raise HTTPException(400, "target is required")
        if not target.startswith(("http://", "https://")):
            # 与 CLI 一致：本地路径一律解析成绝对路径（相对路径按仓库根算）
            p = pathlib.Path(target)
            target = str(p if p.is_absolute() else (repo_root / p).resolve())
        metadata = payload.get("metadata") or {}
        if isinstance(metadata, list):
            parsed = {}
            for item in metadata:
                if not isinstance(item, str) or "=" not in item:
                    raise HTTPException(400, f"metadata must be key=value: {item!r}")
                k, v = item.split("=", 1)
                parsed[k] = v
            metadata = parsed
        if not isinstance(metadata, dict):
            raise HTTPException(400, "metadata must be an object")
        budget_src = payload.get("budget") or {}
        if not isinstance(budget_src, dict):
            raise HTTPException(400, "budget must be an object")
        budget_args = {}
        for key in ("max_seconds", "max_execs", "max_tokens", "max_turns"):
            if budget_src.get(key) in (None, ""):
                continue
            try:
                budget_args[key] = int(budget_src[key])
            except (TypeError, ValueError) as exc:
                raise HTTPException(400, f"budget.{key} must be an integer") from exc
        task_id = str(payload.get("task_id") or "").strip() or new_task_id(
            str(payload.get("prefix") or "task"))
        with _open(create=True) as store:
            try:
                spec = TaskSpec(task_id=task_id, benchmark=benchmark,
                                target=target, mode=str(payload.get("mode") or "fuzz"),
                                budget=Budget(**budget_args), metadata=metadata)
            except TaskError as exc:
                raise HTTPException(400, str(exc)) from exc
            try:
                store.get_task(task_id)
            except TaskError:
                pass
            else:
                raise HTTPException(409, f"task already exists: {task_id}")
            try:
                task = store.create_task(spec)
            except TaskError as exc:
                raise HTTPException(400, str(exc)) from exc
            seq = EventBus(store).emit(task_id, "task.created", stage="RECEIVED",
                                       payload=spec.to_dict())
        return {"task": task, "event_seq": seq, "links": _links(task_id),
                "auth": auth}

    # ------------------------------------------------------------ 详情 / 时间线
    @app.get("/api/platform/tasks/{task_id}")
    def platform_task(task_id: str):
        """任务详情：状态 + 预算 + 时间线（事件重放得到的状态迁移）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            task = store.get_task(task_id)
            bus = EventBus(store)
            events = bus.list(task_id)
            replay = bus.replay(task_id)
            summary = store.summary(task_id)
            plan = store.get_plan(task_id)
            program = store.get_program_index(task_id)
            hypotheses = store.list_hypotheses(task_id)
            candidates = store.list_candidates(task_id)[:MAX_ROWS]
            verifications = store.list_verifications(task_id)[:MAX_ROWS]
            reviews = store.list_reviews(task_id)[:MAX_ROWS]
            reports = store.list_reports(task_id)
            pack = _latest_report(store, task_id)
        return {
            "task": task,
            "state": task["state"],
            "budget": task["budget"],
            "terminal_reason": task["terminal_reason"],
            "summary": summary,
            "timeline": replay.get("transitions") or [],
            "replay": {k: replay.get(k) for k in ("state", "events")},
            "events": {"count": len(events), "tail": events[-20:]},
            "plan": (plan or {}).get("doc"),
            "program_index": (program or {}).get("doc"),
            "hypotheses": hypotheses[:MAX_ROWS],
            "candidates": candidates,
            "verifications": verifications,
            "reviews": reviews,
            "reports": reports,
            "casepack": None if pack is None else {
                "report_id": pack["report_id"], "path": pack["path"],
                "content_sha256": pack["sha256"], "created_at": pack["created_at"],
                "report_html": "report.html",
                "report_html_sha256": pack.get("report_html_sha256") or "",
                "download_html": (f"/api/platform/tasks/{task_id}/casepack/file"
                                  "?name=report.html"),
            },
            "jobs": platform_jobs.list_jobs(_db_path(), task_id, limit=10),
            "auth": auth_info(),
            "links": _links(task_id),
        }

    # ------------------------------------------------------------ 事件流
    @app.get("/api/platform/tasks/{task_id}/events")
    def platform_events(task_id: str, after: int = 0, limit: int = 500):
        """事件流（append-only）：after=seq 支持增量拉取。"""
        after = max(0, int(after or 0))
        limit = max(1, min(int(limit or 500), MAX_ROWS * 5))
        with _open() as store:
            _task_or_404(store, task_id)
            items = EventBus(store).list(task_id, after_seq=after)
        visible = items[:limit]
        return {
            "task_id": task_id,
            "after": after,
            "count": len(visible),
            "total_after": len(items),
            "next_after": visible[-1]["seq"] if visible else after,
            "items": visible,
        }

    # ------------------------------------------------------------ 证据浏览器
    @app.get("/api/platform/tasks/{task_id}/evidence")
    def platform_evidence(task_id: str):
        """证据清单：sha256/size/kind/present/hash_ok + 下载地址（只读）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            rows = store.list_evidence(task_id)
            root_dir = _root()
        items = []
        for row in rows:
            path = pathlib.Path(str(row.get("path") or ""))
            if not path.is_absolute():
                path = root_dir / "evidence" / path.name
            present = path.is_file()
            digest = ""
            if present:
                try:
                    digest = sha256(path.read_bytes()).hexdigest()
                except OSError:
                    present = False
            items.append({
                "sha256": row["sha256"], "size": int(row.get("size") or 0),
                "kind": row["kind"], "source_stage": row.get("source_stage", ""),
                "created_at": row.get("created_at", ""), "path": str(path),
                "present": present,
                "hash_ok": bool(present and digest == row["sha256"]),
                "download": f"/api/platform/tasks/{task_id}/evidence/{row['sha256']}",
            })
        return {
            "task_id": task_id,
            "count": len(items),
            "all_present": all(i["present"] for i in items) if items else True,
            "all_hash_ok": all(i["hash_ok"] for i in items) if items else True,
            "items": items,
        }

    @app.get("/api/platform/tasks/{task_id}/evidence/{sha256_value}")
    def platform_evidence_blob(task_id: str, sha256_value: str):
        """按内容哈希取回证据 blob；只允许该任务登记过的哈希。"""
        digest = (sha256_value or "").strip().lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise HTTPException(404, "evidence not found")
        with _open() as store:
            _task_or_404(store, task_id)
            rows = {r["sha256"]: r for r in store.list_evidence(task_id)}
            root_dir = _root()
        row = rows.get(digest)
        if row is None:
            raise HTTPException(404, "evidence not found")
        path = pathlib.Path(str(row.get("path") or ""))
        if not path.is_absolute():
            path = root_dir / "evidence" / path.name
        if not path.is_file():
            raise HTTPException(404, "evidence blob missing on disk")
        return FileResponse(path, media_type="application/octet-stream",
                            filename=digest)

    # ------------------------------------------------------------ 研究轮次（V3 P4a）
    def _research_call(fn):
        """只读层的两类错误 → 404/409（记录不存在 vs 记录存在但不可用）。"""
        try:
            return fn()
        except research_view.ResearchUnavailable as exc:
            raise HTTPException(404, str(exc)) from exc
        except research_view.ResearchConflict as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/platform/tasks/{task_id}/research")
    def platform_research_status(task_id: str):
        """研究轮次：轮次 / 阶段 / 动作 / 结果 / 证据引用（只读，不写裁决）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            events = EventBus(store).list(task_id)
            root_dir = _root()
        return _research_call(
            lambda: research_view.status_view(root_dir, task_id, events))

    @app.get("/api/platform/tasks/{task_id}/research/events")
    def platform_research_events(task_id: str, after: int = 0, limit: int = 200,
                                 kind: str = ""):
        """研究 session 的事件流（`after=seq` 增量；`kind` = 事件前缀或全名）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            events = EventBus(store).list(task_id)
            root_dir = _root()
        return _research_call(
            lambda: research_view.events_view(root_dir, task_id, events,
                                              after=after, limit=limit,
                                              kind=kind))

    @app.get("/api/platform/tasks/{task_id}/research/evidence")
    def platform_research_evidence(task_id: str):
        """研究证据：报告引用 × 本任务台账（跨任务哈希不算命中）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            events = EventBus(store).list(task_id)
            rows = store.list_evidence(task_id)
            root_dir = _root()
        return _research_call(
            lambda: research_view.evidence_view(
                root_dir, task_id,
                research_view.load_report(root_dir, task_id, events), rows))

    # ------------------------------------------------------------ CasePack
    @app.get("/api/platform/tasks/{task_id}/casepack")
    def platform_casepack(task_id: str):
        """CasePack 台账：路径 + 文件清单 + 内容哈希（重算校验，不写盘）。"""
        with _open() as store:
            _task_or_404(store, task_id)
            pack = _latest_report(store, task_id)
            reports = store.list_reports(task_id)
        if pack is None:
            raise HTTPException(404, "casepack not found")
        pack_dir = pathlib.Path(str(pack["path"]))
        exists = pack_dir.is_dir()
        files = []
        recomputed = {"content_sha256": "", "hash_ok": False}
        if exists:
            try:
                files = _pack_files(pack_dir)
                recomputed = _recompute(pack_dir)
            except OSError as exc:
                raise HTTPException(503, f"casepack unreadable: {exc}") from exc
        stored = str(pack.get("sha256") or "")
        recorded_html = str(pack.get("report_html_sha256") or "")
        html_file = next((f for f in files if f["path"] == "report.html"), None)
        html_sha = str((html_file or {}).get("sha256") or "")
        return {
            "task_id": task_id,
            "report_id": pack["report_id"],
            "path": str(pack_dir),
            "exists": exists,
            "content_sha256": stored,
            "recomputed_sha256": recomputed["content_sha256"],
            "hash_ok": bool(exists and recomputed["content_sha256"] == stored),
            "created_at": pack["created_at"],
            "report_html": "report.html",
            "report_html_sha256": html_sha,
            "report_html_sha256_recorded": recorded_html,
            "report_html_ok": bool(html_sha and html_sha == recorded_html),
            "files": files,
            "reports": reports,
            "links": {
                "self": f"/api/platform/tasks/{task_id}/casepack",
                "download": (f"/api/platform/tasks/{task_id}/casepack/file"
                             "?name=casepack.json"),
                "report_md": (f"/api/platform/tasks/{task_id}/casepack/file"
                              "?name=report.md"),
                "report_html": (f"/api/platform/tasks/{task_id}/casepack/file"
                                "?name=report.html"),
            },
        }

    @app.get("/api/platform/tasks/{task_id}/casepack/file")
    def platform_casepack_file(task_id: str, name: str):
        """下载包内单个文件；只允许包清单里的名字，禁止跳出包目录。"""
        with _open() as store:
            _task_or_404(store, task_id)
            pack = _latest_report(store, task_id)
        if pack is None:
            raise HTTPException(404, "casepack not found")
        pack_dir = pathlib.Path(str(pack["path"])).resolve()
        if not pack_dir.is_dir():
            raise HTTPException(404, "casepack dir missing")
        wanted = (name or "").strip().replace("\\", "/")
        if not wanted or wanted.startswith("/") or ".." in pathlib.PurePosixPath(wanted).parts:
            raise HTTPException(404, "file not in casepack")
        allowed = {f["path"] for f in _pack_files(pack_dir)}
        # casepack.json 是包自身的清单（不参与 content_sha256），允许下载
        if (pack_dir / "casepack.json").is_file():
            allowed.add("casepack.json")
        if wanted not in allowed:
            raise HTTPException(404, "file not in casepack")
        path = (pack_dir / wanted).resolve()
        if pack_dir not in path.parents or not path.is_file():
            raise HTTPException(404, "file not in casepack")
        return FileResponse(path, filename=wanted,
                            media_type=DL_MEDIA.get(path.suffix,
                                                    "application/octet-stream"))

    # ------------------------------------------------------------ 准入 / 执行
    @app.post("/api/platform/tasks/{task_id}/preflight")
    def platform_preflight(task_id: str, auth: dict = Depends(write_guard),
                           response: Response = None):
        """准入门：RECEIVED → PREFLIGHT → READY/BLOCKED；BLOCKED 可重试（F4）。

        重试只追加事件、不删旧事件：补齐材料后重跑检查，再决定 READY/BLOCKED。
        """
        _mark(response, auth)
        with _open() as store:
            task = _task_or_404(store, task_id)
            if task["state"] not in ("RECEIVED", "BLOCKED"):
                raise HTTPException(
                    409, f"preflight requires RECEIVED or BLOCKED (retry), "
                         f"got {task['state']}")
            bus = EventBus(store)
            try:
                out = run_preflight(task_id, store, bus)
            except (TaskError, ValueError) as exc:
                raise HTTPException(409, str(exc)) from exc
            state = store.get_task(task_id)
            events = bus.list(task_id)
        return {"task_id": task_id, "state": out["state"],
                "checks": out["checks"], "blockers": out["blockers"],
                "retry": out.get("retry", False),
                "previous_state": out.get("previous_state", "RECEIVED"),
                "task": state, "event_seq": events[-1]["seq"] if events else 0,
                "links": _links(task_id), "auth": auth}

    # ------------------------------------------------------------ 作业 / 执行
    @app.get("/api/platform/jobs")
    def platform_jobs_list(task_id: str = "", limit: int = 50):
        """作业台账（只读）：jobs 表只是启动器视角，任务状态看事件流。"""
        jobs = platform_jobs.list_jobs(_db_path(), task_id=task_id, limit=limit)
        return {"jobs": jobs, "count": len(jobs), "task_id": task_id,
                "root": str(_root()), "auth": auth_info(),
                "note": ("job.status 是启动器视角；任务状态以 task_events 事件流为准"
                         "（GET /api/platform/tasks/{id} 的 state 字段）")}

    @app.get("/api/platform/jobs/{job_id}")
    def platform_job(job_id: str):
        """单作业详情：进程事实 + 事件流派生的任务状态 + 日志 tail。"""
        job = platform_jobs.get_job(_db_path(), job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        task_id = str(job.get("task_id") or "")
        state, terminal_reason, events, transitions = "", "", 0, []
        with _open() as store:
            if store is not None:
                try:
                    task = store.get_task(task_id)
                except TaskError:
                    task = None
                if task is not None:
                    bus = EventBus(store)
                    replay = bus.replay(task_id)
                    state = replay.get("state") or task["state"]
                    terminal_reason = task.get("terminal_reason") or ""
                    events = replay.get("events") or 0
                    transitions = replay.get("transitions") or []
        return {
            "job": job,
            "task": {"task_id": task_id, "state": state,
                     "terminal_reason": terminal_reason,
                     "exists": bool(state)},
            "state": state,
            "status": job["status"],
            "finished": state in TERMINAL,
            "job_finished": job["status"] in platform_jobs.TERMINAL_JOB_STATES,
            "events": events,
            "timeline": transitions[-10:],
            "status_source": "event_stream",
            "links": _job_links(job_id, task_id),
            "auth": auth_info(),
            "note": ("status=启动器视角（pid/退出码）；state=事件流重放，二者不一致时"
                     "以 state 为准"),
        }

    @app.post("/api/platform/jobs/{job_id}/cancel")
    def platform_job_cancel(job_id: str, payload: dict | None = Body(None),
                            auth: dict = Depends(write_guard),
                            response: Response = None):
        """取消作业：先走状态机 `cancel_task()`（事件流留痕），再对进程组发信号。"""
        _mark(response, auth)
        body = payload or {}
        reason = str(body.get("reason") or "").strip() or "api cancel"
        job = platform_jobs.get_job(_db_path(), job_id)
        if job is None:
            raise HTTPException(404, "job not found")
        task_id = str(job.get("task_id") or "")
        task_state = ""
        with _open() as store:
            task = _task_or_404(store, task_id)
            task_state = task["state"]
            if task_state in TERMINAL:
                raise HTTPException(
                    409, f"task {task_id} is already terminal: {task_state}")
            bus = EventBus(store)
            try:
                cancel_task(task_id, store, bus, reason=reason, actor="api")
            except (TaskError, ValueError) as exc:
                raise HTTPException(409, str(exc)) from exc
            task_after = store.get_task(task_id)
            events = bus.list(task_id)
        job_live = job["status"] in platform_jobs.LIVE_STATES
        if job_live:
            out = platform_jobs.cancel_job(_db_path(), job_id, reason=reason)
            job_after, signal = out["job"], out["signal"]
            note = ("状态已按事件流落 CANCELLED；进程收到信号后会自行退出，"
                    "watcher 不再改写已取消的作业")
        else:
            # 进程早就结束了（EXITED/FAILED）但任务还停在非终态：仍然受理任务取消，
            # 作业行不动（它记录的是进程事实，不该被改写成 CANCELLED）。
            job_after, signal = job, ""
            note = (f"作业进程已结束（status={job['status']}, "
                    f"exit_code={job.get('exit_code')}）：只取消任务状态，"
                    "作业行保留进程事实")
        return {"ok": True, "job": job_after, "signal": signal,
                "task": {"task_id": task_id, "state": task_after["state"],
                         "from": task_state},
                "state": task_after["state"], "status": job_after["status"],
                "job_cancelled": bool(job_live),
                "events": len(events),
                "event_seq": events[-1]["seq"] if events else 0,
                "links": _job_links(job_id, task_id), "auth": auth,
                "note": note}

    @app.post("/api/platform/tasks/{task_id}/run")
    def platform_run(task_id: str, payload: dict | None = Body(None),
                     auth: dict = Depends(write_guard),
                     response: Response = None):
        """显式执行触发：只受理 PLANNED，执行落成 jobs 表的一行（P4.5）。"""
        _mark(response, auth)
        body = payload or {}
        with _open() as store:
            task = _task_or_404(store, task_id)
            if task["state"] != "PLANNED":
                raise HTTPException(
                    409, f"run requires PLANNED, got {task['state']}")
            db = str(_db_path())
        live = [j for j in platform_jobs.list_jobs(_db_path(), task_id, limit=10)
                if j["status"] in platform_jobs.LIVE_STATES]
        if live:
            raise HTTPException(
                409, f"task {task_id} already has live job: {live[0]['job_id']}")
        root_dir = _root()
        args = [sys.executable, str(repo_root / "bin" / "platform.py"),
                "--db", db, "run", task_id]
        for key, flag in (("seconds", "--seconds"), ("workers", "--workers"),
                          ("timeout", "--timeout")):
            if body.get(key) not in (None, ""):
                try:
                    args += [flag, str(float(body[key]) if key != "workers"
                                       else int(body[key]))]
                except (TypeError, ValueError) as exc:
                    raise HTTPException(400, f"{key} must be numeric") from exc
        if body.get("isolation"):
            args += ["--isolation", str(body["isolation"])]
        if body.get("require_isolation"):
            args.append("--require-isolation")
        log_dir = root_dir / "runs"
        log_path = log_dir / f"{task_id}.log"
        try:
            job = platform_jobs.create_job(_db_path(), task_id, args, log_path,
                                           cwd=str(repo_root),
                                           note="run via POST /api/platform/tasks/{id}/run")
        except platform_jobs.JobError as exc:
            status = 503 if exc.kind == "unavailable" else 409
            raise HTTPException(status, str(exc)) from exc
        links = _links(task_id)
        links["job"] = _job_links(job["job_id"], task_id)["self"]
        links["jobs"] = f"/api/platform/jobs?task_id={task_id}"
        return {"ok": True, "task_id": task_id, "pid": job.get("pid"),
                "log": str(log_path), "state": "PLANNED", "job": job,
                "links": links, "auth": auth,
                "note": ("执行由 CLI 子进程完成，作业落在 jobs 表；"
                         "状态变化以事件流为准（GET /api/platform/jobs/{job_id} 的 state）")}


    # ------------------------------------------------------------ SSE 事件流
    def _sse_frame(event: str, data: Any, *, event_id: int | None = None) -> str:
        """一条 SSE 帧：可选 id + event + 单行 JSON data + 空行结尾。"""
        out = ""
        if event_id is not None:
            out += f"id: {int(event_id)}\n"
        out += f"event: {event}\n"
        body = json.dumps(data, ensure_ascii=False, default=str)
        out += f"data: {body}\n\n"
        return out

    def _job_brief(job: dict) -> dict:
        return {"job_id": job.get("job_id"), "status": job.get("status"),
                "pid": job.get("pid"),
                "log": (job.get("log") or {}).get("path", "")}

    def _state_frame(task_id: str, db: pathlib.Path) -> dict:
        """任务状态（事件流重放）+ 作业摘要；状态不存在时给空态。"""
        state, events, reason = "", 0, ""
        with _open() as store:
            if store is not None:
                try:
                    task = store.get_task(task_id)
                except TaskError:
                    task = None
                if task is not None:
                    bus = EventBus(store)
                    replay = bus.replay(task_id)
                    state = replay.get("state") or task["state"]
                    events = replay.get("events") or 0
                    reason = task.get("terminal_reason") or ""
        jobs = [_job_brief(j) for j in platform_jobs.list_jobs(db, task_id, limit=5)]
        return {"task_id": task_id, "state": state,
                "terminal": state in TERMINAL, "terminal_reason": reason,
                "events": events, "jobs": jobs,
                "status": jobs[0]["status"] if jobs else ""}

    @app.get("/api/platform/tasks/{task_id}/stream")
    def platform_stream(task_id: str, request: Request, after: int = 0,
                        once: int = 0, timeout: float = 300.0,
                        max_events: int = 0, poll: float = 0.2):
        """SSE：把 `task_events` 推给页面（`after=seq` 续传，`once=1` 单趟便于脚本）。

        帧：`retry` / `event: hello` / `event: task_event`（带 id=seq）/
        `event: state`（事件流派生状态 + 作业摘要）/ `event: ping` / `event: end`。
        结束条件：任务到达终态、`once=1`、`max_events` 上限、`timeout` 到期
        （`timeout=0` 表示不设上限，只由终态或客户端断开结束）。
        """
        after = max(0, int(after or 0))
        once = 1 if int(once or 0) else 0
        max_events = max(0, min(int(max_events or 0), 5000))
        timeout = max(0.0, min(float(timeout or 0), 3600.0))
        poll = max(0.05, min(float(poll or 0.2), 5.0))
        with _open() as store:                 # 前置 404：任务不存在别开流
            _task_or_404(store, task_id)
        db = _db_path()
        auth = auth_info()

        def gen() -> Iterator[str]:
            cursor = after
            emitted = 0
            deadline = None if timeout <= 0 else time.monotonic() + timeout
            yield "retry: 1000\n\n"
            first_state = _state_frame(task_id, db)
            yield _sse_frame("hello", {"task_id": task_id,
                                       "state": first_state.get("state"),
                                       "after": cursor,
                                       "events": first_state.get("events"),
                                       "timeout": timeout, "once": bool(once),
                                       "auth": auth})
            last_state = first_state.get("state")
            ticks = 0
            while True:
                with _open() as store:
                    if store is None:
                        yield _sse_frame("end", {"reason": "db missing"})
                        return
                    events = EventBus(store).list(task_id, after_seq=cursor)
                for ev in events:
                    if max_events and emitted >= max_events:
                        break
                    cursor = int(ev["seq"])
                    emitted += 1
                    yield _sse_frame("task_event", ev, event_id=cursor)
                state = _state_frame(task_id, db)
                if ticks == 0 or state.get("state") != last_state:
                    yield _sse_frame("state", state)
                    last_state = state.get("state")
                if state.get("terminal"):
                    yield _sse_frame("end", {"reason": "terminal",
                                             "state": state.get("state")})
                    return
                if once:
                    yield _sse_frame("end", {"reason": "once", "after": cursor,
                                             "emitted": emitted})
                    return
                if max_events and emitted >= max_events:
                    yield _sse_frame("end", {"reason": "max_events",
                                             "after": cursor,
                                             "emitted": emitted})
                    return
                if deadline is not None and time.monotonic() >= deadline:
                    yield _sse_frame("end", {"reason": "timeout",
                                             "after": cursor})
                    return
                ticks += 1
                if ticks % 50 == 0:
                    yield _sse_frame("ping", {"after": cursor,
                                              "ts": int(time.time())})
                time.sleep(poll)

        headers = {"Cache-Control": "no-cache, no-transform",
                   "Connection": "keep-alive",
                   "X-Accel-Buffering": "no",
                   MODE_HEADER: str(auth.get("mode") or "open"),
                   SCOPE_HEADER: str(auth.get("write_scope") or "loopback")}
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers=headers)
