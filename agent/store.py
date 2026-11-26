"""SQLite 持久层：runs / stages / attempts / artifacts / evidence / claims / blackboard / checkpoints。"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .util import canonical_json, short_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, task_id TEXT, benchmark TEXT, workspace TEXT,
  status TEXT DEFAULT 'running', created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS stages(
  id TEXT PRIMARY KEY, run_id TEXT, stage TEXT, status TEXT DEFAULT 'planned',
  attempt INTEGER DEFAULT 0, reason TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS attempts(
  id TEXT PRIMARY KEY, run_id TEXT, stage TEXT, n INTEGER, action_key TEXT,
  outcome TEXT, seconds REAL, detail TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS artifacts(
  id TEXT PRIMARY KEY, run_id TEXT, stage TEXT, kind TEXT, uri TEXT,
  sha256 TEXT, size INTEGER, schema_version TEXT, produced_by TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, run_id TEXT, stage TEXT, kind TEXT, summary TEXT,
  artifact_id TEXT, location TEXT, observed_by TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS claims(
  id TEXT PRIMARY KEY, run_id TEXT, subject TEXT, predicate TEXT, value TEXT,
  status TEXT, confidence REAL, cwe TEXT, entry TEXT, sink TEXT, dataflow TEXT,
  assumptions TEXT, test_plan TEXT, evidence_refs TEXT, revision INTEGER, created_at REAL);
CREATE TABLE IF NOT EXISTS blackboard(
  id TEXT PRIMARY KEY, run_id TEXT, kind TEXT, title TEXT, content TEXT,
  status TEXT, evidence_refs TEXT, claim_id TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS checkpoints(
  key TEXT PRIMARY KEY, run_id TEXT, stage TEXT, binding TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS budgets(
  run_id TEXT, stage TEXT, turns_used INTEGER DEFAULT 0, turns_max INTEGER,
  seconds_used REAL DEFAULT 0, PRIMARY KEY(run_id, stage));
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(str(self.path), check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.executescript(SCHEMA)
        self._con.commit()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self._con
            self._con.commit()
        except Exception:
            self._con.rollback()
            raise

    # ---- runs / stages ----
    def create_run(self, run_id: str, task_id: str, benchmark: str, workspace: str) -> None:
        now = time.time()
        with self.tx() as con:
            con.execute(
                "INSERT OR REPLACE INTO runs(id,task_id,benchmark,workspace,status,created_at,updated_at)"
                " VALUES(?,?,?,?, 'running', ?, ?)", (run_id, task_id, benchmark, workspace, now, now))

    def set_stage(self, run_id: str, stage: str, status: str, attempt: int = 0, reason: str = "") -> None:
        now = time.time()
        with self.tx() as con:
            con.execute(
                "INSERT INTO stages(id,run_id,stage,status,attempt,reason,updated_at)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET"
                " status=excluded.status, attempt=excluded.attempt, reason=excluded.reason, updated_at=excluded.updated_at",
                (f"{run_id}:{stage}", run_id, stage, status, attempt, reason, now))

    def stage_row(self, run_id: str, stage: str) -> dict | None:
        row = self._con.execute("SELECT * FROM stages WHERE id=?", (f"{run_id}:{stage}",)).fetchone()
        return dict(row) if row else None

    # ---- attempts ----
    def record_attempt(self, run_id: str, stage: str, n: int, action_key: str,
                       outcome: str, seconds: float, detail: str = "") -> None:
        aid = short_hash([run_id, stage, n, action_key], 20)
        with self.tx() as con:
            con.execute("INSERT OR REPLACE INTO attempts(id,run_id,stage,n,action_key,outcome,seconds,detail,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?)", (aid, run_id, stage, n, action_key, outcome, seconds, detail, time.time()))

    def action_seen(self, run_id: str, stage: str, action_key: str) -> bool:
        row = self._con.execute("SELECT 1 FROM attempts WHERE run_id=? AND stage=? AND action_key=? LIMIT 1",
                                (run_id, stage, action_key)).fetchone()
        return row is not None

    # ---- artifacts ----
    def add_artifact(self, run_id: str, stage: str, kind: str, uri: str, sha: str,
                     size: int, schema_version: str, produced_by: str) -> str:
        aid = short_hash([run_id, stage, kind, sha], 20)
        with self.tx() as con:
            con.execute("INSERT OR REPLACE INTO artifacts(id,run_id,stage,kind,uri,sha256,size,schema_version,produced_by,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (aid, run_id, stage, kind, uri, sha, size, schema_version, produced_by, time.time()))
        return aid

    def artifacts(self, run_id: str, stage: str | None = None) -> list[dict]:
        if stage:
            rows = self._con.execute("SELECT * FROM artifacts WHERE run_id=? AND stage=? ORDER BY created_at DESC",
                                     (run_id, stage)).fetchall()
        else:
            rows = self._con.execute("SELECT * FROM artifacts WHERE run_id=? ORDER BY created_at DESC",
                                     (run_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- evidence / claims / blackboard ----
    def add_evidence(self, run_id: str, stage: str, kind: str, summary: str,
                     location: dict | None = None, observed_by: str = "", artifact_id: str | None = None) -> str:
        eid = short_hash([run_id, stage, kind, summary], 20)
        with self.tx() as con:
            con.execute("INSERT OR REPLACE INTO evidence(id,run_id,stage,kind,summary,artifact_id,location,observed_by,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?)",
                        (eid, run_id, stage, kind, summary, artifact_id,
                         canonical_json(location or {}), observed_by, time.time()))
        return eid

    def upsert_claim(self, run_id: str, claim: dict) -> str:
        cid = claim.get("claim_id") or short_hash(
            [run_id, claim.get("subject"), (claim.get("sink") or {}).get("file"), (claim.get("sink") or {}).get("line")], 20)
        old = self._con.execute("SELECT revision FROM claims WHERE id=?", (cid,)).fetchone()
        revision = (old["revision"] + 1) if old else 1
        with self.tx() as con:
            con.execute(
                "INSERT INTO claims(id,run_id,subject,predicate,value,status,confidence,cwe,entry,sink,dataflow,"
                "assumptions,test_plan,evidence_refs,revision,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET status=excluded.status, confidence=excluded.confidence,"
                " entry=excluded.entry, sink=excluded.sink, dataflow=excluded.dataflow, evidence_refs=excluded.evidence_refs,"
                " revision=excluded.revision",
                (cid, run_id, claim.get("subject", ""), claim.get("predicate", ""), str(claim.get("value", "")),
                 claim.get("status", "proposed"), float(claim.get("confidence", 0.0)), claim.get("cwe", ""),
                 canonical_json(claim.get("entry") or {}), canonical_json(claim.get("sink") or {}),
                 canonical_json(claim.get("dataflow") or []), canonical_json(claim.get("assumptions") or []),
                 canonical_json(claim.get("test_plan") or {}), canonical_json(claim.get("evidence_refs") or []),
                 revision, time.time()))
        return cid

    def claims(self, run_id: str) -> list[dict]:
        rows = self._con.execute("SELECT * FROM claims WHERE run_id=? ORDER BY confidence DESC", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_blackboard(self, run_id: str, kind: str, title: str, content: str,
                       status: str = "", claim_id: str | None = None, evidence_refs: list[str] | None = None) -> str:
        bid = short_hash([run_id, kind, title, content], 20)
        with self.tx() as con:
            con.execute("INSERT OR REPLACE INTO blackboard(id,run_id,kind,title,content,status,evidence_refs,claim_id,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?)",
                        (bid, run_id, kind, title, content, status,
                         canonical_json(evidence_refs or []), claim_id, time.time()))
        return bid

    def blackboard(self, run_id: str, kind: str | None = None) -> list[dict]:
        if kind:
            rows = self._con.execute("SELECT * FROM blackboard WHERE run_id=? AND kind=? ORDER BY created_at DESC",
                                     (run_id, kind)).fetchall()
        else:
            rows = self._con.execute("SELECT * FROM blackboard WHERE run_id=? ORDER BY created_at DESC",
                                     (run_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- checkpoints ----
    def save_checkpoint(self, run_id: str, stage: str, binding: dict) -> str:
        key = short_hash(canonical_json(binding), 32)
        with self.tx() as con:
            con.execute("INSERT OR REPLACE INTO checkpoints(key,run_id,stage,binding,created_at) VALUES(?,?,?,?,?)",
                        (key, run_id, stage, canonical_json(binding), time.time()))
        return key

    def find_checkpoint(self, run_id: str, stage: str, binding: dict) -> dict | None:
        key = short_hash(canonical_json(binding), 32)
        row = self._con.execute("SELECT * FROM checkpoints WHERE key=?", (key,)).fetchone()
        return dict(row) if row else None

    def latest_checkpoint(self, run_id: str, stage: str) -> dict | None:
        row = self._con.execute(
            "SELECT * FROM checkpoints WHERE run_id=? AND stage=? ORDER BY created_at DESC LIMIT 1",
            (run_id, stage)).fetchone()
        return dict(row) if row else None

    def checkpoints(self, run_id: str | None = None) -> list[dict]:
        if run_id:
            rows = self._con.execute(
                "SELECT * FROM checkpoints WHERE run_id=? ORDER BY created_at DESC", (run_id,)).fetchall()
        else:
            rows = self._con.execute("SELECT * FROM checkpoints ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ---- budgets ----
    def budget_row(self, run_id: str, stage: str, max_turns: int) -> dict:
        with self.tx() as con:
            con.execute("INSERT OR IGNORE INTO budgets(run_id,stage,turns_used,seconds_used,turns_max) VALUES(?,?,0,0,?)",
                        (run_id, stage, max_turns))
        row = self._con.execute("SELECT * FROM budgets WHERE run_id=? AND stage=?", (run_id, stage)).fetchone()
        return dict(row)

    def set_turns_used(self, run_id: str, stage: str, turns: int, seconds: float) -> None:
        with self.tx() as con:
            con.execute("UPDATE budgets SET turns_used=?, seconds_used=? WHERE run_id=? AND stage=?",
                        (turns, seconds, run_id, stage))

    # ---- context for next stage ----
    def blackboard_context(self, run_id: str, *, max_tokens: int = 8000) -> dict:
        arts = self.artifacts(run_id)[:6]
        claims = [c for c in self.claims(run_id) if c["status"] in ("proposed", "supported")][:8]
        unknown = self.blackboard(run_id, "hypothesis")[:10]
        ctx = {
            "artifacts": [{"kind": a["kind"], "uri": a["uri"], "sha256": a["sha256"]} for a in arts],
            "claims": [{"id": c["id"], "cwe": c["cwe"], "status": c["status"], "confidence": c["confidence"]} for c in claims],
            "unknowns": [{"title": u["title"], "content": u["content"][:200]} for u in unknown],
        }
        # 简单预算：超限先砍 artifacts 摘要，不砍 unknown
        while len(canonical_json(ctx)) > max_tokens * 4 and ctx["artifacts"]:
            ctx["artifacts"].pop()
        return ctx
