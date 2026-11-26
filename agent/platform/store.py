"""V2 证据/状态存储：SQLite 单一事实源。

表：
  tasks / task_events / evidence / task_evidence
  candidates / verifications / reviews / reports        （P0 预留，P2 起写 candidates）
  program_indexes / hypotheses                          （P1）
  plans                                                 （P2）

迁移策略：P0 的 SCHEMA 原样保留；P1/P2 只在 SCHEMA_P1/SCHEMA_P2 里新增
`CREATE TABLE/INDEX IF NOT EXISTS`，每次 open 都幂等执行，老库打开后自动补齐
新表且不触碰旧数据。P2 另需给 P0 的 candidates 补 `state/exec_id/detail_json`
三列：SQLite 的 ADD COLUMN 不支持 IF NOT EXISTS，先读 PRAGMA table_info 再补。
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from pathlib import Path

from .budget import usage_from_events, violations as budget_violations
from .task import Budget, TaskError, TaskSpec, assert_transition, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks(
  task_id TEXT PRIMARY KEY,
  benchmark TEXT NOT NULL,
  target TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'fuzz',
  state TEXT NOT NULL,
  budget_json TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  terminal_reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  event_type TEXT NOT NULL,
  stage TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_task ON task_events(task_id, seq);
CREATE TABLE IF NOT EXISTS evidence(
  sha256 TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_evidence(
  task_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  kind TEXT NOT NULL,
  source_stage TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  PRIMARY KEY(task_id, sha256, kind)
);
CREATE TABLE IF NOT EXISTS candidates(
  candidate_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  input_sha256 TEXT NOT NULL DEFAULT '',
  crash_type TEXT NOT NULL DEFAULT '',
  stack_hash TEXT NOT NULL DEFAULT '',
  evidence_sha256 TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications(
  verification_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  benchmark TEXT NOT NULL,
  kind TEXT NOT NULL,
  verified INTEGER NOT NULL,
  evidence_sha256 TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews(
  review_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  verification_id TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  evidence_sha256 TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports(
  report_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
"""

SCHEMA_P1 = """
CREATE TABLE IF NOT EXISTS program_indexes(
  task_id TEXT PRIMARY KEY,
  benchmark TEXT NOT NULL,
  root TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_count INTEGER NOT NULL DEFAULT 0,
  call_site_count INTEGER NOT NULL DEFAULT 0,
  entry_count INTEGER NOT NULL DEFAULT 0,
  doc_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hypotheses(
  task_id TEXT NOT NULL,
  hypothesis_id TEXT NOT NULL,
  statement TEXT NOT NULL,
  falsifiable_by TEXT NOT NULL,
  evidence_gap_json TEXT NOT NULL DEFAULT '[]',
  cost_json TEXT NOT NULL DEFAULT '{}',
  confidence REAL NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT '',
  doc_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(task_id, hypothesis_id)
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_task ON hypotheses(task_id);
"""

SCHEMA_P2 = """
CREATE TABLE IF NOT EXISTS plans(
  task_id TEXT PRIMARY KEY,
  benchmark TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  seconds REAL NOT NULL DEFAULT 0,
  execs INTEGER NOT NULL DEFAULT 0,
  workers INTEGER NOT NULL DEFAULT 0,
  timeout REAL NOT NULL DEFAULT 0,
  sha256 TEXT NOT NULL DEFAULT '',
  doc_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_task ON candidates(task_id);
CREATE INDEX IF NOT EXISTS idx_candidates_stack ON candidates(task_id, stack_hash);
"""

# P0 的 candidates 表缺 P2 需要的列：打开库时按 PRAGMA 幂等补齐
CANDIDATE_COLUMNS = {
    "state": "TEXT NOT NULL DEFAULT 'new'",
    "exec_id": "TEXT NOT NULL DEFAULT ''",
    "detail_json": "TEXT NOT NULL DEFAULT '{}'",
}

# P0 的 candidates 主键只有 candidate_id，而候选编号 C1..Cn 是任务内编号：
# 落库时加 `<task_id>::` 前缀保证跨任务不撞主键，读回时仍暴露任务内 id。
CANDIDATE_ID_SEP = "::"

# P3：verifications / reviews / reports 的主键同样是任务内编号（V1/R1/PACK1），
# 复用同一命名空间规则；旧库里的裸 id 仍按原值可读。
SCHEMA_P3 = """
CREATE INDEX IF NOT EXISTS idx_verifications_task
  ON verifications(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reviews_task ON reviews(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id, created_at);
"""

# P0 的 reviews 表只有 reason，复核的结构化 checks/root_cause 需要一列 JSON
REVIEW_COLUMNS = {"detail_json": "TEXT NOT NULL DEFAULT '{}'"}

# V3 P3（V3-011）：campaign 子 Job 与 lease/fencing。
# 口径（§10「执行可靠性、取消与恢复」）：
# - `campaign_jobs` 是 **campaign 层**的子 Job 台账，与 `vulnmap_platform` 的
#   `jobs` 表（启动器视角：pid/exit_code/log）不是一回事：这里记的是
#   “谁拥有这次执行、租约到什么时候、第几次 fencing generation”。
# - 认领 = 单条 `UPDATE … WHERE status='PENDING' AND (lease 过期)`，靠
#   `BEGIN IMMEDIATE` 串行化；每次认领 `fence+1`，**旧 owner 的写入条件里带
#   owner+fence**，所以迟到的 worker 覆盖不了新 owner 的结果（只进 late 表）。
# - `UNKNOWN` 不是终态：所有权不明时先落地 `UNKNOWN`，由 `recovery` 对账外部
#   副作用后再决定复用/重派/保持（绝不盲目重放）。
# - 相同规范化请求（request_hash）已成功过 → 直接复用，不重复执行。
CAMPAIGN_JOB_STATES = ("PENDING", "RUNNING", "SUCCEEDED", "FAILED", "UNKNOWN",
                       "CANCELLED")
TERMINAL_CAMPAIGN_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
CAMPAIGN_EFFECTS = ("none", "possible", "external")


class CampaignJobError(TaskError):
    """campaign 子 Job 契约错误：未知 job / 状态不允许 / 身份不对 / 终态不可改写。

    `CODES` 是稳定词表（API、测试、文档都按它断言），不认识的码直接算编程错误。
    """

    CODES = ("unknown_job", "invalid_status", "invalid_verdict",
             "terminal_override", "not_unknown", "forged_identity",
             "external_effect_unresolved")

    def __init__(self, code: str, reason: str, *, job_key: str = "") -> None:
        if code not in self.CODES:
            raise TaskError(f"unknown campaign job code: {code!r}")
        self.code = str(code)
        self.reason = str(reason)
        self.job_key = str(job_key)
        super().__init__(f"{self.code}: {self.reason}")

    def to_dict(self) -> dict:
        return {"code": self.code, "reason": self.reason,
                "job_key": self.job_key}

SCHEMA_P4 = """
CREATE TABLE IF NOT EXISTS campaign_jobs(
  job_key TEXT PRIMARY KEY,
  campaign TEXT NOT NULL,
  task_id TEXT NOT NULL,
  epoch INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  request_hash TEXT NOT NULL DEFAULT '',
  request_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}',
  result_sha256 TEXT NOT NULL DEFAULT '',
  execution_id TEXT NOT NULL DEFAULT '',
  launcher_job_id TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  boot_id TEXT NOT NULL DEFAULT '',
  pid INTEGER,
  attempt INTEGER NOT NULL DEFAULT 0,
  fence INTEGER NOT NULL DEFAULT 0,
  lease_expires_at REAL NOT NULL DEFAULT 0,
  external_effect TEXT NOT NULL DEFAULT 'none',
  reconciled_at TEXT NOT NULL DEFAULT '',
  reconcile_note TEXT NOT NULL DEFAULT '',
  cancel_requested_at TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT '',
  finished_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_campaign_jobs_request
  ON campaign_jobs(campaign, task_id, request_hash);
CREATE INDEX IF NOT EXISTS idx_campaign_jobs_campaign
  ON campaign_jobs(campaign, status);
CREATE INDEX IF NOT EXISTS idx_campaign_jobs_task
  ON campaign_jobs(task_id, status);
CREATE INDEX IF NOT EXISTS idx_campaign_jobs_lease
  ON campaign_jobs(status, lease_expires_at);
CREATE TABLE IF NOT EXISTS campaign_job_late(
  late_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_key TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  fence INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_campaign_job_late
  ON campaign_job_late(job_key, created_at);
"""

# V3 第 3 周（V3-019）：原始执行证据 → 待复核项 → 独立复核者的交接台账。
# 口径（`docs/V3-W3-HANDOFF.md`）：
# - `review_items` 是**待复核队列**：一条项只有三方身份
#   （run_id / execution_id / evidence_sha256）与状态，没有结论字段；
# - `handoff_verdicts` 是独立复核者（只读原始记录）给出的定性，只能让项从
#   `pending` 走到 `accepted/rejected/needs_evidence`，不写 verified/confirmed；
# - 状态词表与 `adaptive.handoff.STATUSES` 必须一致（有测试对账），但不在这里
#   import adaptive：store 被 adaptive 依赖，反向 import 会成环。
REVIEW_ITEM_STATUSES = ("pending", "accepted", "rejected", "needs_evidence")
HANDOFF_VERDICT_STATUSES = ("accepted", "rejected", "needs_evidence")

SCHEMA_W3 = """
CREATE TABLE IF NOT EXISTS review_items(
  item_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  revision_id TEXT NOT NULL DEFAULT '',
  build_id TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  verdict_id TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_review_items_triple
  ON review_items(task_id, run_id, execution_id, evidence_sha256);
CREATE INDEX IF NOT EXISTS idx_review_items_status
  ON review_items(task_id, status);
CREATE TABLE IF NOT EXISTS handoff_verdicts(
  verdict_id TEXT PRIMARY KEY,
  item_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  verifier TEXT NOT NULL DEFAULT '',
  checks_json TEXT NOT NULL DEFAULT '{}',
  blockers_json TEXT NOT NULL DEFAULT '[]',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_handoff_verdicts_task
  ON handoff_verdicts(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_handoff_verdicts_item
  ON handoff_verdicts(item_id);
"""

# V3 隔离验收（口径见 `docs/V3-ISOLATION-ACCEPTANCE.md`）：
# - `isolation_acceptance` 是**平台侧**的隔离验收记录：谁的、什么检查项、
#   证据哈希、什么时候验收；记录只增不改，同 id 同内容幂等，不同内容拒绝。
# - 任务提交者自填的 `metadata.isolation_accepted` **不在这张表里**：自报是
#   advisory，进不了平台台账（放行只读这张表，见 `adaptive.handoff`）。
ISOLATION_ACCEPTANCE_STATUSES = ("accepted", "rejected")

SCHEMA_W5 = """
CREATE TABLE IF NOT EXISTS isolation_acceptance(
  acceptance_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  status TEXT NOT NULL,
  isolation TEXT NOT NULL DEFAULT '',
  network TEXT NOT NULL DEFAULT '',
  cap_drop INTEGER NOT NULL DEFAULT 0,
  ro_root INTEGER NOT NULL DEFAULT 0,
  executed_isolated INTEGER NOT NULL DEFAULT 0,
  checks_json TEXT NOT NULL DEFAULT '{}',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  evidence_sha256 TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_isolation_acceptance_task
  ON isolation_acceptance(task_id, created_at);
"""

SCHEMA_VERSION = 7


def _candidate_db_id(task_id: str, candidate_id: str) -> str:
    prefix = f"{task_id}{CANDIDATE_ID_SEP}"
    return candidate_id if candidate_id.startswith(prefix) else prefix + candidate_id


def _strip_ns(task_id: str, value: str) -> str:
    """把 `<task_id>::X` 还原成任务内编号 X。"""
    prefix = f"{task_id}{CANDIDATE_ID_SEP}"
    return value[len(prefix):] if value.startswith(prefix) else value


def _ensure_columns(conn: sqlite3.Connection, table: str,
                    columns: dict[str, str]) -> list[str]:
    """SQLite 无 ADD COLUMN IF NOT EXISTS：按 PRAGMA table_info 逐列补齐。"""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    added: list[str] = []
    for name, ddl in columns.items():
        if name in existing:
            continue
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        added.append(name)
    return added


class PlatformStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.executescript(SCHEMA_P1)   # 幂等迁移：P0 表不动，只补 P1 表
        self.conn.executescript(SCHEMA_P2)   # P2：plans + candidates 索引
        self.conn.executescript(SCHEMA_P3)   # P3：verifications/reviews/reports 索引
        self.conn.executescript(SCHEMA_P4)   # V3 P3：campaign_jobs + late 归档
        self.conn.executescript(SCHEMA_W3)   # V3 W3：review_items + 交接定性
        self.conn.executescript(SCHEMA_W5)   # 隔离验收：平台侧记录（只增不改）
        _ensure_columns(self.conn, "candidates", CANDIDATE_COLUMNS)
        _ensure_columns(self.conn, "reviews", REVIEW_COLUMNS)
        self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- tasks ----
    def create_task(self, spec: TaskSpec) -> dict:
        ts = now()
        try:
            self.conn.execute(
                "INSERT INTO tasks(task_id,benchmark,target,mode,state,budget_json,"
                "metadata_json,terminal_reason,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (spec.task_id, spec.benchmark, spec.target, spec.mode, "RECEIVED",
                 json.dumps(spec.budget.to_dict()), json.dumps(spec.metadata, ensure_ascii=False),
                 "", ts, ts))
        except sqlite3.IntegrityError as exc:
            raise TaskError(f"task already exists: {spec.task_id}") from exc
        self.conn.commit()
        return self.get_task(spec.task_id)

    def get_task(self, task_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise TaskError(f"task not found: {task_id}")
        out = dict(row)
        out["budget"] = json.loads(out.pop("budget_json"))
        out["metadata"] = json.loads(out.pop("metadata_json"))
        return out

    def ensure_task_from_task_json(self, task_json: dict, *,
                                   task_json_path: str = "",
                                   workspace: str = "",
                                   task_id: str = "",
                                   benchmark: str = "",
                                   mode: str = "smoke",
                                   target: str = "") -> tuple[dict, bool]:
        """从 workspace `task.json` 幂等登记任务；返回 `(task, created)`。

        `smoke --record --ensure-task` 用这条路径把“案例工作区”变成**已存在**的任务：
        只在 `tasks` 表插一行 `state=RECEIVED` 并补一条 `task.created` 事件，
        没有任何执行结论、不写候选/验证记录。已存在则原样返回（`created=False`），
        不会覆盖既有任务的 benchmark/target/metadata。

        与 `submit` 的区别只有一个：字段来源是 `task.json`，不是命令行参数；
        因此 `task_id` / `benchmark` 的口径校验与 `TaskSpec` 完全一致（不合法就抛
        `TaskError`，绝不落一个“看起来像任务”的半成品）。
        """
        from .events import EventBus

        doc = dict(task_json or {})
        tid = str(task_id or doc.get("task_id") or doc.get("case_id") or "").strip()
        bench = str(benchmark or doc.get("benchmark") or "").strip().lower()
        if not tid:
            raise TaskError("task.json 缺少 task_id/case_id，无法登记任务")
        if not bench:
            raise TaskError(f"task.json 缺少 benchmark，无法登记任务 {tid}")
        try:
            existing = self.get_task(tid)
        except TaskError:
            existing = None
        if existing is not None:
            return existing, False

        workspace_path = str(workspace or "").strip()
        if not workspace_path and task_json_path:
            workspace_path = str(Path(task_json_path).expanduser().parent)
        target_value = str(target or workspace_path or task_json_path or "").strip()
        if not target_value:
            raise TaskError(f"{tid}: task.json 未给出 workspace，无法确定 target")
        metadata = {
            "source": "smoke:record",
            "registered_by": "ensure_task_from_task_json",
            "case_id": str(doc.get("case_id") or ""),
            "task_json": str(task_json_path or ""),
            "workspace": workspace_path,
        }
        spec = TaskSpec(task_id=tid, benchmark=bench, target=target_value,
                        mode=mode or "smoke", metadata=metadata)
        try:
            task = self.create_task(spec)
            created = True
        except TaskError as exc:
            # 并发登记：另一条路径已经建好，按“已存在”返回；其它错误原样抛出
            if "already exists" not in str(exc):
                raise
            task, created = self.get_task(tid), False
        if created:
            EventBus(self).emit(
                tid, "task.created", stage="RECEIVED",
                payload={**spec.to_dict(), "source": "smoke:record",
                         "task_json": str(task_json_path or ""),
                         "workspace": workspace_path})
        return task, created

    def transition(self, task_id: str, dst: str, reason: str = "") -> dict:
        task = self.get_task(task_id)
        src = task["state"]
        assert_transition(src, dst)
        ts = now()
        self.conn.execute(
            "UPDATE tasks SET state=?, terminal_reason=?, updated_at=? WHERE task_id=?",
            (dst, reason, ts, task_id))
        self.conn.commit()
        self.append_event(task_id, "state.changed", stage=dst,
                          payload={"from": src, "to": dst, "reason": reason})
        return self.get_task(task_id)

    # ---- events ----
    def append_event(self, task_id: str, event_type: str, stage: str = "",
                     payload: dict | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO task_events(task_id,ts,event_type,stage,payload_json) "
            "VALUES(?,?,?,?,?)",
            (task_id, now(), event_type, stage,
             json.dumps(payload or {}, ensure_ascii=False)))
        self.conn.commit()
        return int(cur.lastrowid)

    def list_events(self, task_id: str, after_seq: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM task_events WHERE task_id=? AND seq>? ORDER BY seq",
            (task_id, after_seq)).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["payload"] = json.loads(d.pop("payload_json") or "{}")
            out.append(d)
        return out

    # ---- evidence refs ----
    def add_evidence(self, task_id: str, sha256: str, size: int, path: str,
                     kind: str, source_stage: str = "") -> None:
        ts = now()
        self.conn.execute(
            "INSERT OR IGNORE INTO evidence(sha256,size,path,created_at) VALUES(?,?,?,?)",
            (sha256, size, path, ts))
        self.conn.execute(
            "INSERT OR IGNORE INTO task_evidence(task_id,sha256,kind,source_stage,created_at) "
            "VALUES(?,?,?,?,?)", (task_id, sha256, kind, source_stage, ts))
        self.conn.commit()

    def list_evidence(self, task_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT e.sha256,e.size,e.path,te.kind,te.source_stage,te.created_at "
            "FROM task_evidence te JOIN evidence e ON e.sha256=te.sha256 "
            "WHERE te.task_id=? ORDER BY te.created_at, te.kind", (task_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- P1：ProgramIndex ----
    def save_program_index(self, task_id: str, index) -> dict:
        """写入/覆盖一个任务的 ProgramIndex；同一任务只保留最新版本。"""
        doc = index.to_dict() if hasattr(index, "to_dict") else dict(index or {})
        if not isinstance(doc, dict) or not doc:
            raise TaskError("program index doc must be a non-empty dict")
        benchmark = str(doc.get("benchmark") or "")
        root = str(doc.get("root") or "")
        counts = doc.get("counts") or {}
        sha = str(doc.get("sha256") or "")
        if not sha:
            from hashlib import sha256 as _sha256
            canonical = json.dumps({k: v for k, v in doc.items() if k != "sha256"},
                                   ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":"), default=str)
            sha = _sha256(canonical.encode("utf-8")).hexdigest()
            doc["sha256"] = sha
        ts = now()
        values = (benchmark, root, sha,
                  int(doc.get("source_count") or 0),
                  int(counts.get("call_sites") or len(doc.get("call_sites") or [])),
                  int(counts.get("entry_points") or len(doc.get("entry_points") or [])),
                  json.dumps(doc, ensure_ascii=False), ts)
        cur = self.conn.execute(
            "UPDATE program_indexes SET benchmark=?,root=?,sha256=?,source_count=?,"
            "call_site_count=?,entry_count=?,doc_json=?,updated_at=? WHERE task_id=?",
            values + (task_id,))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO program_indexes(task_id,benchmark,root,sha256,source_count,"
                "call_site_count,entry_count,doc_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (task_id,) + values[:7] + (ts, ts))
        self.conn.commit()
        return self.get_program_index(task_id) or {}

    def get_program_index(self, task_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM program_indexes WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["doc"] = json.loads(out.pop("doc_json") or "{}")
        return out

    # ---- P1：hypotheses ----
    def save_hypotheses(self, task_id: str, items: list[dict]) -> int:
        """整批替换某任务的假设集（假设集是集合语义，不做增量合并）。"""
        if not isinstance(items, list):
            raise TaskError("hypotheses must be a list")
        ts = now()
        self.conn.execute("DELETE FROM hypotheses WHERE task_id=?", (task_id,))
        for item in items:
            if not isinstance(item, dict):
                raise TaskError("hypothesis must be a dict")
            hid = str(item.get("id") or "")
            if not hid:
                raise TaskError("hypothesis.id is required")
            self.conn.execute(
                "INSERT OR REPLACE INTO hypotheses(task_id,hypothesis_id,statement,"
                "falsifiable_by,evidence_gap_json,cost_json,confidence,source,doc_json,"
                "created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (task_id, hid, str(item.get("statement") or ""),
                 str(item.get("falsifiable_by") or ""),
                 json.dumps(item.get("evidence_gap") or [], ensure_ascii=False),
                 json.dumps(item.get("cost") or {}, ensure_ascii=False),
                 float(item.get("confidence") or 0.0),
                 str(item.get("source") or ""),
                 json.dumps(item, ensure_ascii=False), ts))
        self.conn.commit()
        return len(items)

    def list_hypotheses(self, task_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM hypotheses WHERE task_id=? ORDER BY hypothesis_id",
            (task_id,)).fetchall()
        out = []
        for row in rows:
            item = json.loads(row["doc_json"] or "{}")
            item["created_at"] = row["created_at"]
            out.append(item)
        return out

    def get_hypothesis(self, task_id: str, hypothesis_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM hypotheses WHERE task_id=? AND hypothesis_id=?",
            (task_id, hypothesis_id)).fetchone()
        if not row:
            return None
        item = json.loads(row["doc_json"] or "{}")
        item["created_at"] = row["created_at"]
        return item

    # ---- P2：plans ----
    def save_plan(self, task_id: str, plan) -> dict:
        """写入/覆盖一个任务的 Plan；同一任务只保留最新版本（PLANNED 单值）。"""
        from .planner import validate as validate_plan

        doc = plan.to_dict() if hasattr(plan, "to_dict") else dict(plan or {})
        validate_plan(doc)
        if str(doc.get("task_id") or "") != task_id:
            raise TaskError(
                f"plan.task_id {doc.get('task_id')!r} != {task_id!r}")
        budget = doc.get("budget") or {}
        from .planner import digest as _digest
        sha = str(doc.get("sha256") or "")
        if not sha:
            sha = _digest(doc)
            doc["sha256"] = sha
        ts = now()
        values = (str(doc.get("benchmark") or ""), str(doc.get("kind") or ""),
                  str(doc.get("target") or ""),
                  float(budget.get("seconds") or 0.0),
                  int(budget.get("execs") or 0),
                  int(budget.get("workers") or 0),
                  float(budget.get("timeout") or 0.0),
                  sha, json.dumps(doc, ensure_ascii=False), ts)
        cur = self.conn.execute(
            "UPDATE plans SET benchmark=?,kind=?,target=?,seconds=?,execs=?,"
            "workers=?,timeout=?,sha256=?,doc_json=?,updated_at=? WHERE task_id=?",
            values + (task_id,))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO plans(task_id,benchmark,kind,target,seconds,execs,"
                "workers,timeout,sha256,doc_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (task_id,) + values[:9] + (ts, ts))
        self.conn.commit()
        return self.get_plan(task_id) or {}

    def get_plan(self, task_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM plans WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["doc"] = json.loads(out.pop("doc_json") or "{}")
        return out

    # ---- P2：candidates ----
    def save_candidate(self, candidate) -> dict:
        """写入/覆盖一个 Candidate；候选是“单端执行证据”，state 默认 new。"""
        from .candidates import validate_candidate

        doc = (candidate.to_dict() if hasattr(candidate, "to_dict")
               else dict(candidate or {}))
        validate_candidate(doc)
        task_id = str(doc.get("task_id") or doc.get("task") or "")
        cid = str(doc.get("id") or "")
        db_id = _candidate_db_id(task_id, cid)
        ts = now()
        values = (
            task_id, str(doc.get("input_sha256") or ""),
            str(doc.get("crash_type") or ""), str(doc.get("stack_hash") or ""),
            str(doc.get("evidence_sha256") or ""), str(doc.get("state") or "new"),
            str(doc.get("exec_id") or ""),
            json.dumps(doc, ensure_ascii=False))
        cur = self.conn.execute(
            "UPDATE candidates SET task_id=?,input_sha256=?,crash_type=?,"
            "stack_hash=?,evidence_sha256=?,state=?,exec_id=?,detail_json=? "
            "WHERE candidate_id=? AND task_id=?",
            values + (db_id, task_id))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO candidates(candidate_id,task_id,input_sha256,"
                "crash_type,stack_hash,evidence_sha256,state,exec_id,"
                "detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (db_id,) + values + (ts,))
        self.conn.commit()
        return self.get_candidate(task_id, cid) or {}

    def list_candidates(self, task_id: str, state: str = "") -> list[dict]:
        if state:
            rows = self.conn.execute(
                "SELECT * FROM candidates WHERE task_id=? AND state=? "
                "ORDER BY rowid", (task_id, state)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM candidates WHERE task_id=? ORDER BY rowid",
                (task_id,)).fetchall()
        out = []
        for row in rows:
            item = json.loads(row["detail_json"] or "{}")
            stored_id = row["candidate_id"]
            prefix = f"{row['task_id']}{CANDIDATE_ID_SEP}"
            if stored_id.startswith(prefix):
                stored_id = stored_id[len(prefix):]
            item.setdefault("id", stored_id)
            item.setdefault("task_id", row["task_id"])
            item["task"] = row["task_id"]
            item["state"] = row["state"]
            item["created_at"] = row["created_at"]
            out.append(item)
        return out

    def get_candidate(self, task_id: str, candidate_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM candidates WHERE task_id=? "
            "AND candidate_id IN (?,?)",
            (task_id, candidate_id,
             _candidate_db_id(task_id, candidate_id))).fetchone()
        if not row:
            return None
        item = json.loads(row["detail_json"] or "{}")
        stored_id = row["candidate_id"]
        prefix = f"{task_id}{CANDIDATE_ID_SEP}"
        if stored_id.startswith(prefix):
            stored_id = stored_id[len(prefix):]
        item.setdefault("id", stored_id)
        item.setdefault("task_id", row["task_id"])
        item["task"] = row["task_id"]
        item["state"] = row["state"]
        item["created_at"] = row["created_at"]
        return item

    # ---- P3：verifications ----
    def save_verification(self, verification) -> dict:
        """写入一条独立验证记录（同一 verification_id 覆盖写）。"""
        from .verify import Verification

        doc = (verification.to_dict() if hasattr(verification, "to_dict")
               else dict(verification or {}))
        Verification.from_dict(doc).validate()
        task_id = str(doc.get("task_id") or "")
        vid = str(doc.get("verification_id") or "")
        if not task_id or not vid:
            raise TaskError("verification requires task_id and verification_id")
        db_id = _candidate_db_id(task_id, vid)
        detail = doc.get("detail") or {}
        ts = str(doc.get("created_at") or now())
        values = (task_id, str(doc.get("candidate_id") or ""),
                  str(doc.get("benchmark") or ""), str(doc.get("kind") or ""),
                  1 if doc.get("verified") else 0,
                  str(doc.get("evidence_sha256") or ""),
                  json.dumps(doc, ensure_ascii=False), ts)
        cur = self.conn.execute(
            "UPDATE verifications SET task_id=?,candidate_id=?,benchmark=?,kind=?,"
            "verified=?,evidence_sha256=?,detail_json=?,created_at=? "
            "WHERE verification_id=? AND task_id=?",
            values + (db_id, task_id))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO verifications(verification_id,task_id,candidate_id,"
                "benchmark,kind,verified,evidence_sha256,detail_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)", (db_id,) + values)
        self.conn.commit()
        return self.get_verification(task_id, vid) or {}

    def _verification_row(self, task_id: str, row) -> dict:
        doc = json.loads(row["detail_json"] or "{}")
        doc["verification_id"] = _strip_ns(task_id, row["verification_id"])
        doc.setdefault("task_id", row["task_id"])
        doc.setdefault("candidate_id", row["candidate_id"])
        doc.setdefault("benchmark", row["benchmark"])
        doc.setdefault("kind", row["kind"])
        doc["verified"] = bool(row["verified"])
        doc.setdefault("status", "verified" if row["verified"] else "no_repro")
        doc["evidence_sha256"] = row["evidence_sha256"]
        doc.setdefault("detail", {})
        doc["created_at"] = row["created_at"]
        return doc

    def get_verification(self, task_id: str, verification_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM verifications WHERE task_id=? "
            "AND verification_id IN (?,?)",
            (task_id, verification_id,
             _candidate_db_id(task_id, verification_id))).fetchone()
        return self._verification_row(task_id, row) if row else None

    def list_verifications(self, task_id: str, verified: bool | None = None) -> list[dict]:
        sql = "SELECT * FROM verifications WHERE task_id=?"
        args: list = [task_id]
        if verified is not None:
            sql += " AND verified=?"
            args.append(1 if verified else 0)
        sql += " ORDER BY rowid"
        rows = self.conn.execute(sql, args).fetchall()
        return [self._verification_row(task_id, r) for r in rows]

    # ---- P3：reviews ----
    def save_review(self, review) -> dict:
        """写入一条复核记录；复核只能引用已有验证，不产生新证据。"""
        from .review import Review

        doc = (review.to_dict() if hasattr(review, "to_dict")
               else dict(review or {}))
        Review.from_dict(doc).validate()
        task_id = str(doc.get("task_id") or "")
        rid = str(doc.get("review_id") or "")
        if not task_id or not rid:
            raise TaskError("review requires task_id and review_id")
        db_id = _candidate_db_id(task_id, rid)
        ts = str(doc.get("created_at") or now())
        values = (task_id, str(doc.get("verification_id") or ""),
                  str(doc.get("verdict") or ""), str(doc.get("reason") or ""),
                  str(doc.get("evidence_sha256") or ""),
                  json.dumps(doc, ensure_ascii=False), ts)
        cur = self.conn.execute(
            "UPDATE reviews SET task_id=?,verification_id=?,verdict=?,reason=?,"
            "evidence_sha256=?,detail_json=?,created_at=? "
            "WHERE review_id=? AND task_id=?", values + (db_id, task_id))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO reviews(review_id,task_id,verification_id,verdict,"
                "reason,evidence_sha256,detail_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)", (db_id,) + values)
        self.conn.commit()
        return self.get_review(task_id, rid) or {}

    def _review_row(self, task_id: str, row) -> dict:
        doc = json.loads(row["detail_json"] or "{}")
        doc["review_id"] = _strip_ns(task_id, row["review_id"])
        doc.setdefault("task_id", row["task_id"])
        doc["verification_id"] = row["verification_id"]
        doc["verdict"] = row["verdict"]
        doc["reason"] = row["reason"]
        doc["evidence_sha256"] = row["evidence_sha256"]
        doc.setdefault("checks", {})
        doc.setdefault("blockers", [])
        doc.setdefault("detail", {})
        doc["created_at"] = row["created_at"]
        return doc

    def get_review(self, task_id: str, review_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM reviews WHERE task_id=? AND review_id IN (?,?)",
            (task_id, review_id, _candidate_db_id(task_id, review_id))).fetchone()
        return self._review_row(task_id, row) if row else None

    def list_reviews(self, task_id: str, verdict: str = "") -> list[dict]:
        if verdict:
            rows = self.conn.execute(
                "SELECT * FROM reviews WHERE task_id=? AND verdict=? ORDER BY rowid",
                (task_id, verdict)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM reviews WHERE task_id=? ORDER BY rowid",
                (task_id,)).fetchall()
        return [self._review_row(task_id, r) for r in rows]

    # ---- V3 W3：交接（待复核项 + 独立复核定性）----
    def save_review_item(self, item) -> dict:
        """写入一条待复核项（同 item_id 覆盖写；三方身份唯一索引防重复开项）。"""
        doc = item.to_dict() if hasattr(item, "to_dict") else dict(item or {})
        task_id = str(doc.get("task_id") or "")
        item_id = str(doc.get("item_id") or "")
        if not task_id or not item_id:
            raise TaskError("review item requires task_id and item_id")
        status = str(doc.get("status") or "pending")
        if status not in REVIEW_ITEM_STATUSES:
            raise TaskError(
                f"review item status must be one of {REVIEW_ITEM_STATUSES}, "
                f"got {status!r}")
        for name in ("run_id", "execution_id", "evidence_sha256"):
            if not str(doc.get(name) or ""):
                raise TaskError(f"review item requires {name}")
        db_id = _candidate_db_id(task_id, item_id)
        ts = str(doc.get("created_at") or now())
        updated = str(doc.get("updated_at") or ts)
        values = (task_id, str(doc.get("run_id") or ""),
                  str(doc.get("execution_id") or ""),
                  str(doc.get("evidence_sha256") or "").lower(),
                  str(doc.get("kind") or ""), status,
                  str(doc.get("revision_id") or ""),
                  str(doc.get("build_id") or ""),
                  str(doc.get("source") or ""),
                  str(doc.get("verdict_id") or ""),
                  json.dumps(doc, ensure_ascii=False), ts, updated)
        cur = self.conn.execute(
            "UPDATE review_items SET task_id=?,run_id=?,execution_id=?,"
            "evidence_sha256=?,kind=?,status=?,revision_id=?,build_id=?,"
            "source=?,verdict_id=?,detail_json=?,created_at=?,updated_at=? "
            "WHERE item_id=? AND task_id=?", values + (db_id, task_id))
        if cur.rowcount == 0:
            try:
                self.conn.execute(
                    "INSERT INTO review_items(item_id,task_id,run_id,"
                    "execution_id,evidence_sha256,kind,status,revision_id,"
                    "build_id,source,verdict_id,detail_json,created_at,"
                    "updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (db_id,) + values)
            except sqlite3.IntegrityError as exc:
                # 三方身份唯一：同一次执行不能开第二条待复核项（不静默合并）
                raise TaskError(
                    f"duplicate_review_item:{task_id}/{item_id} "
                    f"run_id/execution_id/evidence 已存在") from exc
        self.conn.commit()
        return self.get_review_item(task_id, item_id) or {}

    def _review_item_row(self, task_id: str, row) -> dict:
        doc = json.loads(row["detail_json"] or "{}")
        doc["item_id"] = _strip_ns(task_id, row["item_id"])
        doc["task_id"] = row["task_id"]
        doc["run_id"] = row["run_id"]
        doc["execution_id"] = row["execution_id"]
        doc["evidence_sha256"] = row["evidence_sha256"]
        doc["kind"] = row["kind"]
        doc["status"] = row["status"]
        doc["revision_id"] = row["revision_id"]
        doc["build_id"] = row["build_id"]
        doc["source"] = row["source"]
        doc["verdict_id"] = row["verdict_id"]
        doc.setdefault("detail", {})
        doc["created_at"] = row["created_at"]
        doc["updated_at"] = row["updated_at"]
        return doc

    def get_review_item(self, task_id: str, item_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM review_items WHERE task_id=? "
            "AND item_id IN (?,?)",
            (task_id, item_id,
             _candidate_db_id(task_id, item_id))).fetchone()
        return self._review_item_row(task_id, row) if row else None

    def list_review_items(self, task_id: str, status: str = "") -> list[dict]:
        sql = "SELECT * FROM review_items WHERE task_id=?"
        args: list = [task_id]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY rowid"
        rows = self.conn.execute(sql, args).fetchall()
        return [self._review_item_row(task_id, r) for r in rows]

    # ---- 隔离验收记录（平台侧；自报字段永远不进这里） ----
    def save_isolation_acceptance(self, record) -> dict:
        """写入一条平台侧隔离验收记录。

        只增不改：同 `acceptance_id` 同内容 → 幂等返回既有行；同 id 不同内容
        → `TaskError`（改写验收记录等于伪造放行依据，直接拒绝）。
        """
        doc = (record.to_dict() if hasattr(record, "to_dict")
               else dict(record or {}))
        task_id = str(doc.get("task_id") or "")
        acceptance_id = str(doc.get("acceptance_id") or "")
        if not task_id or not acceptance_id:
            raise TaskError("isolation acceptance requires task_id and acceptance_id")
        status = str(doc.get("status") or "")
        if status not in ISOLATION_ACCEPTANCE_STATUSES:
            raise TaskError(
                f"isolation acceptance status must be one of "
                f"{ISOLATION_ACCEPTANCE_STATUSES}, got {status!r}")
        checks = dict(doc.get("checks") or {})
        evidence = [dict(item) for item in (doc.get("evidence") or ())]
        values = (task_id, status, str(doc.get("isolation") or ""),
                  str(doc.get("network") or ""),
                  int(bool(doc.get("cap_drop"))),
                  int(bool(doc.get("ro_root"))),
                  int(bool(doc.get("executed_isolated"))),
                  json.dumps(checks, ensure_ascii=False, sort_keys=True),
                  json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                  str(doc.get("evidence_sha256") or ""),
                  str(doc.get("reason") or ""),
                  str(doc.get("checked_at") or ""),
                  str(doc.get("created_at") or now()))
        existing = self.get_isolation_acceptance(task_id, acceptance_id)
        if existing is not None:
            same = {key: existing.get(key) for key in (
                "status", "isolation", "network", "cap_drop", "ro_root",
                "executed_isolated", "checks", "evidence", "evidence_sha256",
                "reason", "checked_at")}
            incoming = {
                "status": status, "isolation": values[2], "network": values[3],
                "cap_drop": bool(values[4]), "ro_root": bool(values[5]),
                "executed_isolated": bool(values[6]), "checks": checks,
                "evidence": evidence, "evidence_sha256": values[9],
                "reason": values[10], "checked_at": values[11]}
            if same != incoming:
                raise TaskError(
                    f"isolation_acceptance_immutable:{acceptance_id}")
            return existing
        self.conn.execute(
            "INSERT INTO isolation_acceptance(acceptance_id,task_id,status,"
            "isolation,network,cap_drop,ro_root,executed_isolated,checks_json,"
            "evidence_json,evidence_sha256,reason,checked_at,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (acceptance_id,) + values)
        self.conn.commit()
        return self.get_isolation_acceptance(task_id, acceptance_id) or {}

    def _isolation_acceptance_row(self, row) -> dict:
        return {
            "acceptance_id": row["acceptance_id"], "task_id": row["task_id"],
            "status": row["status"], "isolation": row["isolation"],
            "network": row["network"], "cap_drop": bool(row["cap_drop"]),
            "ro_root": bool(row["ro_root"]),
            "executed_isolated": bool(row["executed_isolated"]),
            "checks": json.loads(row["checks_json"] or "{}"),
            "evidence": json.loads(row["evidence_json"] or "[]"),
            "evidence_sha256": row["evidence_sha256"],
            "reason": row["reason"], "checked_at": row["checked_at"],
            "created_at": row["created_at"],
        }

    def get_isolation_acceptance(self, task_id: str,
                                 acceptance_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM isolation_acceptance WHERE task_id=? AND "
            "acceptance_id=?", (task_id, acceptance_id)).fetchone()
        return self._isolation_acceptance_row(row) if row else None

    def list_isolation_acceptances(self, task_id: str,
                                   status: str = "") -> list[dict]:
        sql = "SELECT * FROM isolation_acceptance WHERE task_id=?"
        args: list = [task_id]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY rowid"
        rows = self.conn.execute(sql, args).fetchall()
        return [self._isolation_acceptance_row(r) for r in rows]

    def latest_isolation_acceptance(self, task_id: str) -> dict | None:
        """最近一条记录（按写入顺序；验收记录只增不改）。"""
        rows = self.list_isolation_acceptances(task_id)
        return rows[-1] if rows else None

    def save_handoff_verdict(self, verdict) -> dict:
        """写入一条独立复核定性（review_items 之外单独留账，不改原始证据）。"""
        doc = (verdict.to_dict() if hasattr(verdict, "to_dict")
               else dict(verdict or {}))
        task_id = str(doc.get("task_id") or "")
        verdict_id = str(doc.get("verdict_id") or "")
        if not task_id or not verdict_id:
            raise TaskError("handoff verdict requires task_id and verdict_id")
        status = str(doc.get("status") or "")
        if status not in HANDOFF_VERDICT_STATUSES:
            raise TaskError(
                f"handoff verdict status must be one of "
                f"{HANDOFF_VERDICT_STATUSES}, got {status!r}")
        db_id = _candidate_db_id(task_id, verdict_id)
        ts = str(doc.get("created_at") or now())
        values = (str(doc.get("item_id") or ""), task_id,
                  str(doc.get("run_id") or ""),
                  str(doc.get("execution_id") or ""),
                  str(doc.get("evidence_sha256") or "").lower(), status,
                  str(doc.get("reason") or ""),
                  str(doc.get("verifier") or ""),
                  json.dumps(dict(doc.get("checks") or {}), ensure_ascii=False),
                  json.dumps(list(doc.get("blockers") or []), ensure_ascii=False),
                  json.dumps(doc, ensure_ascii=False), ts)
        cur = self.conn.execute(
            "UPDATE handoff_verdicts SET item_id=?,task_id=?,run_id=?,"
            "execution_id=?,evidence_sha256=?,status=?,reason=?,verifier=?,"
            "checks_json=?,blockers_json=?,detail_json=?,created_at=? "
            "WHERE verdict_id=? AND task_id=?", values + (db_id, task_id))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO handoff_verdicts(verdict_id,item_id,task_id,run_id,"
                "execution_id,evidence_sha256,status,reason,verifier,"
                "checks_json,blockers_json,detail_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (db_id,) + values)
        self.conn.commit()
        return self.get_handoff_verdict(task_id, verdict_id) or {}

    def _handoff_verdict_row(self, task_id: str, row) -> dict:
        doc = json.loads(row["detail_json"] or "{}")
        doc["verdict_id"] = _strip_ns(task_id, row["verdict_id"])
        doc["item_id"] = row["item_id"]
        doc["task_id"] = row["task_id"]
        doc["run_id"] = row["run_id"]
        doc["execution_id"] = row["execution_id"]
        doc["evidence_sha256"] = row["evidence_sha256"]
        doc["status"] = row["status"]
        doc["reason"] = row["reason"]
        doc["verifier"] = row["verifier"]
        doc["checks"] = json.loads(row["checks_json"] or "{}")
        doc["blockers"] = json.loads(row["blockers_json"] or "[]")
        doc["created_at"] = row["created_at"]
        return doc

    def get_handoff_verdict(self, task_id: str, verdict_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM handoff_verdicts WHERE task_id=? "
            "AND verdict_id IN (?,?)",
            (task_id, verdict_id,
             _candidate_db_id(task_id, verdict_id))).fetchone()
        return self._handoff_verdict_row(task_id, row) if row else None

    def list_handoff_verdicts(self, task_id: str,
                              status: str = "") -> list[dict]:
        sql = "SELECT * FROM handoff_verdicts WHERE task_id=?"
        args: list = [task_id]
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY rowid"
        rows = self.conn.execute(sql, args).fetchall()
        return [self._handoff_verdict_row(task_id, r) for r in rows]

    def handoff_summary(self, task_id: str) -> dict:
        """交接台账摘要（只数状态，不下结论）。"""
        items = self.list_review_items(task_id)
        verdicts = self.list_handoff_verdicts(task_id)
        return {
            "items": len(items),
            "pending": sum(1 for i in items if i.get("status") == "pending"),
            "accepted": sum(1 for i in items if i.get("status") == "accepted"),
            "rejected": sum(1 for i in items if i.get("status") == "rejected"),
            "needs_evidence": sum(1 for i in items
                                  if i.get("status") == "needs_evidence"),
            "verdicts": len(verdicts),
            "last_item": items[-1]["item_id"] if items else "",
            "last_verdict": verdicts[-1]["verdict_id"] if verdicts else "",
        }

    # ---- P3：reports（Case Pack 台账）----
    def save_report(self, report_id: str, task_id: str, path: str,
                    sha256_value: str) -> dict:
        """记一条 Case Pack：path=打包目录，sha256=内容哈希（可复算）。"""
        if not str(report_id or "").strip():
            raise TaskError("report_id is required")
        if not str(task_id or "").strip():
            raise TaskError("report task_id is required")
        if not str(path or "").strip():
            raise TaskError("report path is required")
        if sha256_value and len(sha256_value) != 64:
            raise TaskError("report sha256 must be 64 hex chars")
        db_id = _candidate_db_id(task_id, report_id)
        ts = now()
        cur = self.conn.execute(
            "UPDATE reports SET path=?,sha256=?,created_at=? WHERE report_id=?",
            (str(path), str(sha256_value), ts, db_id))
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO reports(report_id,task_id,path,sha256,created_at) "
                "VALUES(?,?,?,?,?)",
                (db_id, task_id, str(path), str(sha256_value), ts))
        self.conn.commit()
        return self.get_report(task_id, report_id) or {}

    def get_report(self, task_id: str, report_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM reports WHERE task_id=? AND report_id IN (?,?)",
            (task_id, report_id, _candidate_db_id(task_id, report_id))).fetchone()
        if not row:
            return None
        out = dict(row)
        out["report_id"] = _strip_ns(task_id, out["report_id"])
        return out

    def list_reports(self, task_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM reports WHERE task_id=? ORDER BY rowid",
            (task_id,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["report_id"] = _strip_ns(task_id, item["report_id"])
            out.append(item)
        return out

    # ---- V3 P3：campaign_jobs（campaign 层子 Job + lease/fencing）----
    @contextlib.contextmanager
    def _immediate(self):
        """显式 `BEGIN IMMEDIATE`：认领/结算期间持有写锁，两个 worker 抢不到同一行。"""
        if self.conn.in_transaction:
            self.conn.commit()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()

    @staticmethod
    def _campaign_row(row) -> dict:
        item = dict(row)
        for key in ("request_json", "result_json"):
            name = key[:-5]
            item[name] = json.loads(item.pop(key) or "{}")
        item["lease_expires_at"] = float(item.get("lease_expires_at") or 0.0)
        item["fence"] = int(item.get("fence") or 0)
        item["attempt"] = int(item.get("attempt") or 0)
        item["epoch"] = int(item.get("epoch") or 0)
        item["terminal"] = item["status"] in TERMINAL_CAMPAIGN_STATES
        return item

    @staticmethod
    def _request_hash(request) -> str:
        import hashlib
        canonical = json.dumps(dict(request or {}), ensure_ascii=False,
                               sort_keys=True, separators=(",", ":"),
                               default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def create_campaign_job(self, *, campaign: str, task_id: str, kind: str,
                            request=None, epoch: int = 0, job_key: str = "",
                            external_effect: str = "none",
                            note: str = "") -> dict:
        """登记一个 campaign 子 Job（PENDING）；相同规范化请求不新建也不重复跑。"""
        campaign = str(campaign or "").strip()
        task_id = str(task_id or "").strip()
        kind = str(kind or "").strip()
        if not campaign or not task_id or not kind:
            raise TaskError("campaign job requires campaign/task_id/kind")
        if str(external_effect) not in CAMPAIGN_EFFECTS:
            raise TaskError(
                f"external_effect must be one of {CAMPAIGN_EFFECTS}")
        payload = dict(request or {})
        req_hash = self._request_hash(payload)
        jk = str(job_key or "").strip()
        ts = now()
        with self._immediate() as conn:
            if jk:
                row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                                  (jk,)).fetchone()
                if row is not None:
                    return self._campaign_row(row)
            existing = conn.execute(
                "SELECT * FROM campaign_jobs WHERE campaign=? AND task_id=? "
                "AND request_hash=? AND status='SUCCEEDED' "
                "ORDER BY created_at DESC LIMIT 1",
                (campaign, task_id, req_hash)).fetchone()
            if existing is not None:
                out = self._campaign_row(existing)
                out["reused"] = True
                return out
            jk = jk or f"cj-{req_hash[:12]}-{int(time.time() * 1000) % 100000:05d}"
            conn.execute(
                "INSERT INTO campaign_jobs(job_key,campaign,task_id,epoch,kind,"
                "status,request_hash,request_json,result_json,result_sha256,"
                "execution_id,launcher_job_id,owner,boot_id,pid,attempt,fence,"
                "lease_expires_at,external_effect,reconciled_at,reconcile_note,"
                "cancel_requested_at,note,created_at,started_at,finished_at,"
                "updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?,?)",
                (jk, campaign, task_id, int(epoch or 0), kind, "PENDING",
                 req_hash, json.dumps(payload, ensure_ascii=False), "{}", "",
                 "", "", "", "", None, 0, 0, 0.0, str(external_effect), "", "",
                 "", str(note or ""), ts, "", "", ts))
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (jk,)).fetchone()
            out = self._campaign_row(row)
        out["reused"] = False
        return out

    def get_campaign_job(self, job_key: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                                (str(job_key),)).fetchone()
        return self._campaign_row(row) if row else None

    def find_campaign_job(self, *, campaign: str, task_id: str,
                          request=None, status: str = "SUCCEEDED") -> dict | None:
        req_hash = self._request_hash(request or {})
        row = self.conn.execute(
            "SELECT * FROM campaign_jobs WHERE campaign=? AND task_id=? "
            "AND request_hash=? AND status=? ORDER BY created_at LIMIT 1",
            (str(campaign), str(task_id), req_hash, str(status))).fetchone()
        return self._campaign_row(row) if row else None

    def list_campaign_jobs(self, *, campaign: str = "", task_id: str = "",
                           status: str = "", limit: int = 200) -> list[dict]:
        sql = "SELECT * FROM campaign_jobs"
        clauses: list[str] = []
        args: list = []
        if campaign:
            clauses.append("campaign=?")
            args.append(str(campaign))
        if task_id:
            clauses.append("task_id=?")
            args.append(str(task_id))
        if status:
            clauses.append("status=?")
            args.append(str(status))
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at, job_key LIMIT ?"
        args.append(max(1, min(int(limit or 200), 5000)))
        rows = self.conn.execute(sql, args).fetchall()
        return [self._campaign_row(row) for row in rows]

    def claim_campaign_job(self, job_key: str, *, owner: str, boot_id: str,
                           ttl: float = 60.0, pid: int | None = None,
                           clock=None) -> dict | None:
        """原子认领一个 PENDING job；拿不到（别人在跑/已是终态/所有权不明）→ None。

        认领成功：`fence+1`、`attempt+1`、`RUNNING`、写 owner/boot/pid/租约。
        **只从 PENDING 认领**：RUNNING 的租约过期是“所有权不明”，先走
        `mark_campaign_job_unknown` + `recovery` 对账，不在这里抢。
        """
        owner_text = str(owner or "").strip()
        if not owner_text:
            raise TaskError("claim requires owner")
        now_ts = float(clock() if clock is not None else time.time())
        ts = now()
        with self._immediate() as conn:
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            if row is None:
                return None
            if row["status"] in TERMINAL_CAMPAIGN_STATES:
                return None
            if row["status"] != "PENDING":
                return None
            fence = int(row["fence"] or 0) + 1
            attempt = int(row["attempt"] or 0) + 1
            cur = conn.execute(
                "UPDATE campaign_jobs SET status='RUNNING',owner=?,boot_id=?,"
                "pid=?,attempt=?,fence=?,lease_expires_at=?,started_at=?,"
                "updated_at=? WHERE job_key=? AND status='PENDING' AND fence=?",
                (owner_text, str(boot_id or ""), None if pid is None else int(pid),
                 attempt, fence, now_ts + float(ttl), ts, ts, str(job_key),
                 int(row["fence"] or 0)))
            if cur.rowcount != 1:              # pragma: no cover - 写锁内不会输
                return None
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            return self._campaign_row(row)

    def renew_campaign_job_lease(self, job_key: str, *, owner: str, fence: int,
                                 ttl: float = 60.0, clock=None) -> bool:
        """续租：只有当前 owner + 同一 fence 才能续；旧 owner 续不上就得停手。"""
        now_ts = float(clock() if clock is not None else time.time())
        with self._immediate() as conn:
            cur = conn.execute(
                "UPDATE campaign_jobs SET lease_expires_at=?,updated_at=? "
                "WHERE job_key=? AND owner=? AND fence=? AND status='RUNNING'",
                (now_ts + float(ttl), now(), str(job_key), str(owner),
                 int(fence)))
            return cur.rowcount == 1

    def finish_campaign_job(self, job_key: str, *, owner: str, fence: int,
                            status: str, result=None, execution_id: str = "",
                            note: str = "") -> dict:
        """提交结果：owner+fence+execution 全对才落库；否则归档 late、终态不动。

        返回 `{accepted, late, reason, job}`；非法状态/未知 job 抛 `CampaignJobError`。
        """
        status = str(status or "")
        if status not in ("SUCCEEDED", "FAILED"):
            raise CampaignJobError(
                "invalid_status", f"finish 只接受 SUCCEEDED/FAILED，实际 {status!r}")
        ts = now()
        with self._immediate() as conn:
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            if row is None:
                raise CampaignJobError("unknown_job", f"没有 campaign job {job_key!r}")
            reason = ""
            if row["status"] in TERMINAL_CAMPAIGN_STATES:
                reason = "terminal_already_set"
            elif row["status"] != "RUNNING":
                reason = "not_running"
            elif str(row["owner"] or "") != str(owner or ""):
                reason = "stale_owner"
            elif int(row["fence"] or 0) != int(fence):
                reason = "stale_fence"
            elif str(row["execution_id"] or "") and not str(execution_id or ""):
                # 已绑定执行身份却提交时不声明：等于想绕过“结果必须属于同一 execution”
                reason = "cross_execution"
            elif execution_id and str(row["execution_id"] or "") \
                    and str(row["execution_id"]) != str(execution_id):
                reason = "cross_execution"
            if reason:
                self._archive_late(conn, row, status=status, result=result,
                                   reason=reason, owner=owner, fence=fence)
                return {"accepted": False, "late": True, "reason": reason,
                        "job": self._campaign_row(row)}
            result_doc = dict(result or {})
            result_hash = (self._request_hash(result_doc) if result_doc else "")
            conn.execute(
                "UPDATE campaign_jobs SET status=?,result_json=?,result_sha256=?,"
                "execution_id=?,lease_expires_at=0,finished_at=?,updated_at=?,"
                "note=? WHERE job_key=? AND owner=? AND fence=? AND status='RUNNING'",
                (status, json.dumps(result_doc, ensure_ascii=False), result_hash,
                 str(execution_id or row["execution_id"] or ""), ts, ts,
                 str(note or row["note"] or ""), str(job_key), str(owner),
                 int(fence)))
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            return {"accepted": True, "late": False, "reason": "",
                    "job": self._campaign_row(row)}

    def set_campaign_job_execution(self, job_key: str, execution_id: str, *,
                                   owner: str, fence: int) -> bool:
        """绑定执行身份（T09）；**必须**带当前 owner+fence，否则等于谁都能改绑定。"""
        if not str(owner or "").strip():
            raise CampaignJobError(
                "forged_identity", "绑定 execution 必须声明 owner")
        cur = self.conn.execute(
            "UPDATE campaign_jobs SET execution_id=?,updated_at=? "
            "WHERE job_key=? AND owner=? AND fence=? AND status='RUNNING'",
            (str(execution_id or ""), now(), str(job_key), str(owner),
             int(fence)))
        self.conn.commit()
        return cur.rowcount == 1

    def mark_campaign_job_unknown(self, job_key: str, *, reason: str,
                                  owner: str = "", fence: int = 0) -> dict | None:
        """所有权不明 → UNKNOWN（非终态）：清租约、`fence+1` 让旧 owner 失效。"""
        ts = now()
        with self._immediate() as conn:
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            if row is None:
                return None
            if row["status"] in TERMINAL_CAMPAIGN_STATES:
                return self._campaign_row(row)
            if owner and str(row["owner"] or "") not in ("", str(owner)):
                return self._campaign_row(row)       # 不是自己的 job：不改
            if fence and int(row["fence"] or 0) != int(fence):
                # 拿着旧 generation 来说“我不知道成没成”：不许动新 owner 的 RUNNING
                return self._campaign_row(row)
            conn.execute(
                "UPDATE campaign_jobs SET status='UNKNOWN',owner='',boot_id='',"
                "pid=NULL,fence=fence+1,lease_expires_at=0,reconciled_at='',"
                "reconcile_note=?,note=?,updated_at=? WHERE job_key=?",
                (str(reason or "")[:400], str(row["note"] or "") or str(reason or ""),
                 ts, str(job_key)))
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            return self._campaign_row(row)

    def expire_campaign_job_leases(self, *, clock=None,
                                   max_grace: float = 0.0) -> list[dict]:
        """把租约过期的 RUNNING 标 UNKNOWN（所有权不明），返回被标记的 job。"""
        now_ts = float(clock() if clock is not None else time.time())
        rows = self.conn.execute(
            "SELECT job_key,lease_expires_at FROM campaign_jobs "
            "WHERE status='RUNNING'").fetchall()
        stale = [str(row["job_key"]) for row in rows
                 if float(row["lease_expires_at"] or 0) + float(max_grace) < now_ts]
        out: list[dict] = []
        for job_key in stale:
            job = self.mark_campaign_job_unknown(
                job_key, reason="lease_expired:ownership_unknown")
            if job is not None:
                out.append(job)
        return out

    def reconcile_campaign_job(self, job_key: str, *, verdict: str,
                               result=None, note: str = "",
                               execution_id: str = "", force: bool = False) -> dict:
        """UNKNOWN 对账结论：SUCCEEDED/FAILED 复用或落败；PENDING 才允许重派。

        `verdict="UNKNOWN"` 表示证据不足：保持 UNKNOWN（不重放、不假装完成）。
        """
        verdict = str(verdict or "").upper()
        if verdict not in ("SUCCEEDED", "FAILED", "PENDING", "UNKNOWN"):
            raise CampaignJobError(
                "invalid_verdict", f"未知对账结论 {verdict!r}")
        ts = now()
        with self._immediate() as conn:
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            if row is None:
                raise CampaignJobError("unknown_job", f"没有 campaign job {job_key!r}")
            status = str(row["status"])
            if status in TERMINAL_CAMPAIGN_STATES:
                if status == verdict:
                    return self._campaign_row(row)
                raise CampaignJobError(
                    "terminal_override",
                    f"{job_key} 已是 {status}，不能改成 {verdict}")
            if status != "UNKNOWN":
                raise CampaignJobError(
                    "not_unknown", f"{job_key} 状态是 {status}，只有 UNKNOWN 需要对账")
            if verdict == "PENDING" and str(row["external_effect"] or "none") \
                    not in ("none", "") and not force:
                # 外部副作用（网络提交/外部写）还没对账清楚就重派 = 盲目重放（§10）
                raise CampaignJobError(
                    "external_effect_unresolved",
                    f"{job_key} 登记的副作用是 {row['external_effect']!r}，"
                    "未确认前禁止重派（人工确认后传 force=True）")
            if verdict == "PENDING":
                conn.execute(
                    "UPDATE campaign_jobs SET status='PENDING',fence=fence+1,"
                    "owner='',boot_id='',pid=NULL,lease_expires_at=0,"
                    "reconciled_at=?,reconcile_note=?,updated_at=? WHERE job_key=?",
                    (ts, str(note or "reconciled:no_external_effect"), ts,
                     str(job_key)))
            else:
                result_doc = dict(result or {})
                result_hash = (self._request_hash(result_doc) if result_doc else "")
                finished = ts if verdict != "UNKNOWN" else ""
                conn.execute(
                    "UPDATE campaign_jobs SET status=?,result_json=?,"
                    "result_sha256=?,execution_id=?,reconciled_at=?,"
                    "reconcile_note=?,finished_at=?,updated_at=?,"
                    "lease_expires_at=0 WHERE job_key=?",
                    (verdict, json.dumps(result_doc, ensure_ascii=False),
                     result_hash, str(execution_id or row["execution_id"] or ""),
                     ts, str(note or ""), finished, ts, str(job_key)))
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            return self._campaign_row(row)

    def cancel_campaign_job(self, job_key: str, *, reason: str = "",
                            actor: str = "api") -> dict:
        """取消：终态 CANCELLED、清租约、`fence+1`——迟到结果从此写不进来。"""
        ts = now()
        with self._immediate() as conn:
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            if row is None:
                raise CampaignJobError("unknown_job", f"没有 campaign job {job_key!r}")
            if row["status"] in TERMINAL_CAMPAIGN_STATES:
                out = self._campaign_row(row)
                out["already"] = True
                return out
            note = f"cancelled: {reason}".strip() if reason else "cancelled"
            conn.execute(
                "UPDATE campaign_jobs SET status='CANCELLED',owner='',boot_id='',"
                "pid=NULL,fence=fence+1,lease_expires_at=0,cancel_requested_at=?,"
                "finished_at=?,updated_at=?,note=? WHERE job_key=?",
                (ts, ts, ts, f"{note} (actor={actor})", str(job_key)))
            row = conn.execute("SELECT * FROM campaign_jobs WHERE job_key=?",
                               (str(job_key),)).fetchone()
            out = self._campaign_row(row)
            out["already"] = False
            return out

    def attach_campaign_launcher(self, job_key: str, launcher_job_id: str, *,
                                 owner: str, fence: int) -> bool:
        """关联既有启动器 `jobs.job_id`；**必须**是当前 owner+fence。

        否则谁都能把 job 的 launcher 指针改到别人的进程上，取消时就会杀错人。
        """
        if not str(owner or "").strip():
            raise CampaignJobError(
                "forged_identity", "关联启动器必须声明 owner")
        cur = self.conn.execute(
            "UPDATE campaign_jobs SET launcher_job_id=?,updated_at=? "
            "WHERE job_key=? AND owner=? AND fence=? AND status='RUNNING'",
            (str(launcher_job_id or ""), now(), str(job_key), str(owner),
             int(fence)))
        self.conn.commit()
        return cur.rowcount == 1

    def _archive_late(self, conn, row, *, status: str, result, reason: str,
                      owner: str, fence: int) -> None:
        """迟到结果只归档，不改终态（§10）。"""
        conn.execute(
            "INSERT INTO campaign_job_late(job_key,owner,fence,status,"
            "payload_json,reason,created_at) VALUES(?,?,?,?,?,?,?)",
            (str(row["job_key"]), str(owner or ""), int(fence or 0), str(status),
             json.dumps(dict(result or {}), ensure_ascii=False), str(reason),
             now()))

    def list_campaign_late(self, job_key: str = "",
                           limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM campaign_job_late"
        args: list = []
        if job_key:
            sql += " WHERE job_key=?"
            args.append(str(job_key))
        sql += " ORDER BY late_id DESC LIMIT ?"
        args.append(max(1, min(int(limit or 50), 500)))
        out = []
        for row in self.conn.execute(sql, args).fetchall():
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json") or "{}")
            out.append(item)
        return out

    def campaign_job_summary(self, task_id: str) -> dict:
        jobs = self.list_campaign_jobs(task_id=task_id, limit=5000)
        by_status: dict[str, int] = {}
        for job in jobs:
            by_status[job["status"]] = by_status.get(job["status"], 0) + 1
        return {
            "total": len(jobs),
            "states": by_status,
            "unknown": [job["job_key"] for job in jobs
                        if job["status"] == "UNKNOWN"],
            "running": [job["job_key"] for job in jobs
                        if job["status"] == "RUNNING"],
            "with_external_effect": [job["job_key"] for job in jobs
                                     if job["external_effect"] != "none"],
        }

    def summary(self, task_id: str) -> dict:
        task = self.get_task(task_id)
        events = self.list_events(task_id)
        index = self.get_program_index(task_id)
        plan = self.get_plan(task_id)
        candidates = self.list_candidates(task_id)
        verifications = self.list_verifications(task_id)
        reviews = self.list_reviews(task_id)
        reports = self.list_reports(task_id)
        usage = usage_from_events(events)
        return {
            "task": task,
            "events": len(events),
            "last_event": events[-1] if events else None,
            "evidence": len(self.list_evidence(task_id)),
            "program_index": None if index is None else {
                "sha256": index["sha256"],
                "benchmark": index["benchmark"],
                "source_count": index["source_count"],
                "call_sites": index["call_site_count"],
                "entry_points": index["entry_count"],
                "updated_at": index["updated_at"],
            },
            "hypotheses": len(self.list_hypotheses(task_id)),
            "plan": None if plan is None else {
                "kind": plan["kind"],
                "benchmark": plan["benchmark"],
                "seconds": plan["seconds"],
                "execs": plan["execs"],
                "workers": plan["workers"],
                "sha256": plan["sha256"],
                "updated_at": plan["updated_at"],
            },
            "candidates": len(candidates),
            "candidate_states": {
                state: sum(1 for c in candidates if c["state"] == state)
                for state in sorted({c["state"] for c in candidates})
            },
            "verifications": len(verifications),
            "verification_statuses": {
                status: sum(1 for v in verifications if v.get("status") == status)
                for status in sorted({str(v.get("status")) for v in verifications})
            },
            "reviews": len(reviews),
            "review_verdicts": {
                verdict: sum(1 for r in reviews if r.get("verdict") == verdict)
                for verdict in sorted({str(r.get("verdict")) for r in reviews})
            },
            "budget_usage": {
                **task["budget"],
                "used": usage,
                "exceeded": [v["reason"] for v in
                             budget_violations(task["budget"], usage,
                                               strict=True)],
                "at_limit": [v["reason"] for v in
                             budget_violations(task["budget"], usage)],
            },
            # V3 W3：交接台账摘要（未核验/缺证据在这里就能看见，不靠报告口径）
            "handoff": self.handoff_summary(task_id),
            "reports": len(reports),
            "casepack": None if not reports else {
                "report_id": reports[-1]["report_id"],
                "path": reports[-1]["path"],
                "sha256": reports[-1]["sha256"],
                "created_at": reports[-1]["created_at"],
            },
        }
