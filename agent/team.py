"""团队任务队列：照 BinSight 的 TaskRunner/lease 模型做的轻量实现。

关键约束（与 BinSight 对齐）：
- 任务先入队，Worker 用 lease 领取；lease 过期可被接管；
- 写域（write scope）重叠的任务不能被两个 Worker 同时持有；
- 每次尝试单独记账，失败可重试，但同一任务最多 max_attempts 次；
- 完成必须带验收命令与产物哈希，缺一不算 done。
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS team_tasks(
  id TEXT PRIMARY KEY, role TEXT NOT NULL, subject TEXT NOT NULL,
  scope TEXT NOT NULL, acceptance TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued', owner TEXT, lease_until REAL,
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
  artifact_sha TEXT, result TEXT, revision INTEGER NOT NULL DEFAULT 1,
  created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS team_attempts(
  id TEXT PRIMARY KEY, task_id TEXT, worker TEXT, n INTEGER,
  started_at REAL, finished_at REAL, outcome TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_team_status ON team_tasks(status, role);
"""

TERMINAL = ("done", "failed", "cancelled")


@dataclass
class Task:
    id: str
    role: str
    subject: str
    scope: str
    acceptance: str
    status: str
    owner: str | None
    lease_until: float | None
    attempts: int
    max_attempts: int
    artifact_sha: str | None
    result: str | None
    revision: int
    created_at: float = 0.0
    updated_at: float = 0.0


class TeamQueue:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)

    # ---- 入队 ----
    def enqueue(self, *, task_id: str, role: str, subject: str, scope: str,
                acceptance: str = "", max_attempts: int = 3) -> Task:
        now = time.time()
        self._con.execute(
            "INSERT INTO team_tasks(id,role,subject,scope,acceptance,status,attempts,max_attempts,created_at,updated_at)"
            " VALUES(?,?,?,?,?, 'queued',0,?,?,?)",
            (task_id, role, subject, scope, acceptance, max_attempts, now, now))
        return self.get(task_id)

    # ---- 领取（原子） ----
    def claim(self, worker: str, *, lease_seconds: int = 900, role: str | None = None) -> Task | None:
        now = time.time()
        self._con.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(now)
            q = "SELECT * FROM team_tasks WHERE status='queued'"
            args: list = []
            if role:
                q += " AND role=?"
                args.append(role)
            q += " ORDER BY attempts ASC, created_at ASC LIMIT 1"
            row = self._con.execute(q, args).fetchone()
            if row is None:
                self._con.execute("COMMIT")
                return None
            if self._scope_conflict(row["scope"], row["id"]):
                self._con.execute("COMMIT")
                return None
            self._con.execute(
                "UPDATE team_tasks SET status='leased', owner=?, lease_until=?, revision=revision+1, updated_at=?"
                " WHERE id=? AND status='queued'",
                (worker, now + lease_seconds, now, row["id"]))
            self._con.execute(
                "INSERT INTO team_attempts(id,task_id,worker,n,started_at,outcome,detail)"
                " VALUES(?,?,?,?,?, 'running','')",
                (f"{row['id']}:{row['attempts']+1}:{uuid.uuid4().hex[:8]}", row["id"], worker, row["attempts"] + 1, now))
            self._con.execute("UPDATE team_tasks SET attempts=attempts+1 WHERE id=?", (row["id"],))
            self._con.execute("COMMIT")
            return self.get(row["id"])
        except Exception:
            self._con.execute("ROLLBACK")
            raise

    def _scope_conflict(self, scope: str, task_id: str) -> bool:
        """同一写域不能同时被两个活动任务持有。"""
        rows = self._con.execute(
            "SELECT scope,id FROM team_tasks WHERE status IN ('leased','running') AND id<>?", (task_id,)).fetchall()
        want = set(_split_scope(scope))
        for r in rows:
            if want & set(_split_scope(r["scope"])):
                return True
        return False

    def _expire_locked(self, now: float) -> None:
        self._con.execute(
            "UPDATE team_tasks SET status='queued', owner=NULL, lease_until=NULL, revision=revision+1, updated_at=?"
            " WHERE status IN ('leased','running') AND lease_until IS NOT NULL AND lease_until < ?",
            (now, now))

    # ---- 心跳 / 状态 ----
    def heartbeat(self, task_id: str, worker: str, *, lease_seconds: int = 900) -> bool:
        cur = self._con.execute(
            "UPDATE team_tasks SET lease_until=?, updated_at=? WHERE id=? AND owner=? AND status IN ('leased','running')",
            (time.time() + lease_seconds, time.time(), task_id, worker))
        return cur.rowcount == 1

    def start(self, task_id: str, worker: str) -> bool:
        cur = self._con.execute(
            "UPDATE team_tasks SET status='running', updated_at=? WHERE id=? AND owner=? AND status='leased'",
            (time.time(), task_id, worker))
        return cur.rowcount == 1

    def release(self, task_id: str, worker: str) -> bool:
        """主动释放租约：回到 queued，且不消耗 attempts（用于 claim 错任务）。"""
        cur = self._con.execute(
            "UPDATE team_tasks SET status='queued', owner=NULL, lease_until=NULL, attempts=MAX(attempts-1,0),"
            " revision=revision+1, updated_at=? WHERE id=? AND owner=? AND status IN ('leased','running')",
            (time.time(), task_id, worker))
        if cur.rowcount:
            self._con.execute(
                "UPDATE team_attempts SET outcome='released', finished_at=?"
                " WHERE task_id=? AND worker=? AND outcome='running'",
                (time.time(), task_id, worker))
        return cur.rowcount == 1

    def complete(self, task_id: str, worker: str, *, artifact_sha: str, result: str = "") -> bool:
        if not artifact_sha:
            raise ValueError("complete requires artifact_sha")
        now = time.time()
        cur = self._con.execute(
            "UPDATE team_tasks SET status='done', artifact_sha=?, result=?, lease_until=NULL, updated_at=?,"
            " revision=revision+1 WHERE id=? AND owner=? AND status IN ('leased','running')",
            (artifact_sha, result, now, task_id, worker))
        if cur.rowcount != 1:
            return False
        self._close_attempt(task_id, worker, "done", result)
        return True

    def fail(self, task_id: str, worker: str, *, reason: str) -> str:
        row = self.get(task_id)
        final = row.attempts >= row.max_attempts
        status = "failed" if final else "queued"
        self._con.execute(
            "UPDATE team_tasks SET status=?, owner=NULL, lease_until=NULL, result=?, updated_at=?, revision=revision+1"
            " WHERE id=? AND owner=?",
            (status, reason, time.time(), task_id, worker))
        self._close_attempt(task_id, worker, "failed", reason)
        return status

    def _close_attempt(self, task_id: str, worker: str, outcome: str, detail: str) -> None:
        self._con.execute(
            "UPDATE team_attempts SET finished_at=?, outcome=?, detail=?"
            " WHERE task_id=? AND worker=? AND outcome='running'",
            (time.time(), outcome, detail[:1000], task_id, worker))

    # ---- 查询 ----
    def cancel(self, task_id: str, reason: str = "") -> bool:
        cur = self._con.execute(
            "UPDATE team_tasks SET status='cancelled', result=?, updated_at=?, revision=revision+1"
            " WHERE id=? AND status='queued'", (reason, time.time(), task_id))
        return cur.rowcount == 1

    def get(self, task_id: str) -> Task | None:
        row = self._con.execute("SELECT * FROM team_tasks WHERE id=?", (task_id,)).fetchone()
        return Task(**dict(row)) if row else None

    def list(self, status: str | None = None) -> list[Task]:
        q = "SELECT * FROM team_tasks"
        args: list = []
        if status:
            q += " WHERE status=?"
            args.append(status)
        q += " ORDER BY created_at"
        return [Task(**dict(r)) for r in self._con.execute(q, args).fetchall()]

    def stats(self) -> dict:
        out = {}
        for r in self._con.execute("SELECT status, COUNT(*) n FROM team_tasks GROUP BY status"):
            out[r["status"]] = r["n"]
        return out


def _split_scope(scope: str) -> list[str]:
    return [s.strip() for s in scope.split(",") if s.strip()]
