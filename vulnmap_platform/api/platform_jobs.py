"""V2 P4.5：执行从 fire-and-forget 改成 Job（`jobs` 表 + 进程监视 + 取消）。

P4 的 `POST /{id}/run` 只 `Popen` 一次就把 pid 扔掉：进程死没死、退出码多少、日志在
哪儿、能不能停，全都没有台账。P4.5 补上这一层，但**刻意只做"启动器视角"**：

- `jobs` 表只记**进程事实**：`job_id / task_id / pid / status / started / finished / log`
  （外加 `exit_code / argv_json / note / created_at / updated_at`）。它**不是**第二套任务
  状态机：任务状态永远以 `task_events` 事件流重放为准（`EventBus.replay`），响应里
  `state`（事件派生）与 `status`（启动器）分开给，谁都不覆盖谁。
- **表在 API 侧自建**：`CREATE TABLE IF NOT EXISTS jobs(...)`，与 `agent/platform/store.py`
  的 `SCHEMA_VERSION=4` 并存不冲突（SQLite 允许额外表）；`agent/platform` 核心不改。
  只在**写路径**（创建/取消 job）建表，读路径用 `mode=ro` 打开，库不存在就 404——
  维持 P4"GET 不建库"的硬约束。
- **状态机判定收在这里**：`pid` 活着 → `RUNNING`；进程退出 → `EXITED/FAILED`（按退出码）；
  被取消 → `CANCELLED`（终态，watcher 不再回写）。取消先走 `agent/platform` 的
  `cancel_task()`（事件流先记 `task.cancel_requested`），再对**进程组**发 SIGTERM。
- **可注入 spawn**：进程启动收在模块级 `_spawn_process()`，测试 monkeypatch 它即可在被
  测进程内跑真实小脚本或假进程，不必真的执行 `bin/platform.py run`。

`PLATFORM_ROOT`/库路径由调用方（`platform_tasks.py`）按请求解析后传入，本模块不读环境变量。
"""
from __future__ import annotations

import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import threading
import uuid
from datetime import datetime

JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  pid INTEGER,
  status TEXT NOT NULL,
  started TEXT NOT NULL DEFAULT '',
  finished TEXT NOT NULL DEFAULT '',
  log TEXT NOT NULL DEFAULT '',
  exit_code INTEGER,
  argv_json TEXT NOT NULL DEFAULT '[]',
  note TEXT NOT NULL DEFAULT '',
  campaign TEXT NOT NULL DEFAULT '',
  job_key TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_task ON jobs(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_campaign ON jobs(campaign, created_at);
"""

#: V3 P3（V3-011）：老库的 jobs 表没有 campaign/job_key —— 启动器 job 要能被
#: `campaign_jobs.launcher_job_id` 反查。SQLite 的 ADD COLUMN 不支持
#: IF NOT EXISTS，按 PRAGMA 幂等补齐；缺省值让旧行保持“不属于任何 campaign”。
JOB_COLUMNS = {
    "campaign": "TEXT NOT NULL DEFAULT ''",
    "job_key": "TEXT NOT NULL DEFAULT ''",
}


def _ensure_job_columns(conn: sqlite3.Connection) -> list[str]:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
    added: list[str] = []
    for name, ddl in JOB_COLUMNS.items():
        if name in existing:
            continue
        conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {ddl}")
        added.append(name)
    return added

#: 启动器状态（与任务状态机 `agent/platform/task.py` 的 STATES 不是一回事）
JOB_STATES = ("PENDING", "RUNNING", "EXITED", "FAILED", "CANCELLED")
LIVE_STATES = ("PENDING", "RUNNING")
TERMINAL_JOB_STATES = ("EXITED", "FAILED", "CANCELLED")
LOG_TAIL_BYTES = 4096
MAX_JOBS = 200


class JobError(Exception):
    """job 层错误：not_found / conflict 由 API 层翻成 404 / 409。"""

    def __init__(self, message: str, kind: str = "conflict"):
        super().__init__(message)
        self.kind = kind


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def new_job_id() -> str:
    return f"job-{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------- 连接
def _write_conn(db_path: pathlib.Path) -> sqlite3.Connection:
    """写路径：确保父目录与 jobs 表存在（幂等）。"""
    db_path = pathlib.Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(JOBS_SCHEMA)
    _ensure_job_columns(conn)
    return conn


def _read_conn(db_path: pathlib.Path) -> sqlite3.Connection | None:
    """读路径：库不存在 → None；只读打开，绝不建库建表。"""
    db_path = pathlib.Path(db_path)
    if not db_path.is_file():
        return None
    conn = sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True,
                           timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def jobs_available(db_path: pathlib.Path) -> bool:
    conn = _read_conn(db_path)
    if conn is None:
        return False
    try:
        conn.execute("SELECT 1 FROM jobs LIMIT 1")
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


# --------------------------------------------------------------------- 视图
def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:      # 存在但属别的用户：算活着
        return True
    except (OSError, ValueError, TypeError):
        return False
    return True


def _log_view(row: dict) -> dict:
    raw = str(row.get("log") or "")
    view = {"path": raw, "exists": False, "size": 0, "tail": ""}
    if not raw:
        return view
    path = pathlib.Path(raw)
    try:
        if path.is_file():
            size = path.stat().st_size
            view["exists"] = True
            view["size"] = int(size)
            with path.open("rb") as fh:
                if size > LOG_TAIL_BYTES:
                    fh.seek(size - LOG_TAIL_BYTES)
                view["tail"] = fh.read().decode("utf-8", "replace")
    except OSError:
        pass
    return view


def job_dict(row: dict | sqlite3.Row, *, tail: bool = True) -> dict:
    out = dict(row)
    try:
        out["argv"] = json.loads(out.pop("argv_json", "[]") or "[]")
    except ValueError:
        out["argv"] = []
    log_path = str(out.get("log") or "")
    view = _log_view({"log": log_path})
    if not tail:
        view["tail"] = ""
    out["log_path"] = log_path
    out["log"] = view
    out["alive"] = pid_alive(out.get("pid"))
    out["live"] = out.get("status") in LIVE_STATES
    return out


def _fetch(conn: sqlite3.Connection, job_id: str) -> dict | None:
    for row in conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)):
        return dict(row)
    return None


def get_job(db_path: pathlib.Path, job_id: str, *, tail: bool = True) -> dict | None:
    conn = _read_conn(db_path)
    if conn is None:
        return None
    try:
        row = _fetch(conn, job_id)
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    return None if row is None else job_dict(row, tail=tail)


def list_jobs(db_path: pathlib.Path, task_id: str = "",
              limit: int = 50, campaign: str = "") -> list[dict]:
    conn = _read_conn(db_path)
    if conn is None:
        return []
    limit = max(1, min(int(limit or 50), MAX_JOBS))
    sql = "SELECT * FROM jobs"
    clauses: list[str] = []
    args: list = []
    if task_id:
        clauses.append("task_id=?")
        args.append(task_id)
    if campaign:
        clauses.append("campaign=?")
        args.append(campaign)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC, job_id DESC LIMIT ?"
    args.append(limit)
    try:
        rows = [dict(r) for r in conn.execute(sql, args)]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [job_dict(r) for r in rows]


# --------------------------------------------------------------------- 启动
def _spawn_process(argv: list[str], log_path: pathlib.Path,
                   cwd: str | None = None):
    """默认启动器：独立进程组 + 输出落日志。测试可 monkeypatch 本函数。"""
    log_path = pathlib.Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=fh,
                                stderr=subprocess.STDOUT,
                                start_new_session=True)
    except OSError:
        fh.close()
        raise
    proc._vulnmap_log_fh = fh       # 由 watcher 在进程结束后关闭
    return proc


def _close_log(proc) -> None:
    fh = getattr(proc, "_vulnmap_log_fh", None)
    if fh is not None:
        try:
            fh.close()
        except OSError:
            pass


def _watch(db_path: pathlib.Path, job_id: str, proc) -> None:
    """后台线程：等进程结束 → 写退出码与终态（已被取消则不回写）。"""
    try:
        code = proc.wait()
    except Exception:               # pragma: no cover - wait 极少抛错
        code = None
    finally:
        _close_log(proc)
    try:
        conn = _write_conn(db_path)
    except (sqlite3.Error, OSError):
        return
    try:
        row = _fetch(conn, job_id)
        if row is None or row.get("status") not in LIVE_STATES:
            return
        status = "EXITED" if code == 0 else "FAILED"
        note = row.get("note") or ""
        if code == 0:
            note = note or "executor exited 0"
        else:
            note = f"executor exited {code}"
        conn.execute(
            "UPDATE jobs SET status=?, exit_code=?, finished=?, note=?, updated_at=? "
            "WHERE job_id=?", (status, None if code is None else int(code),
                               now(), note, now(), job_id))
        conn.commit()
    except sqlite3.Error:
        pass
    finally:
        conn.close()


def create_job(db_path: pathlib.Path, task_id: str, argv: list[str],
               log_path: pathlib.Path, *, cwd: str | None = None,
               note: str = "", spawn=None, campaign: str = "",
               job_key: str = "") -> dict:
    """建 jobs 行 → 启动进程 → 标 RUNNING → 起 watcher。启动失败抛 JobError。"""
    db_path = pathlib.Path(db_path)
    log_path = pathlib.Path(log_path)
    job_id = new_job_id()
    ts = now()
    spawner = spawn or _spawn_process
    try:
        proc = spawner([str(a) for a in argv], log_path, cwd)
    except OSError as exc:
        # 进程没起来也要留痕：FAILED 行 + 备注，便于前端看到"启动失败"
        try:
            conn = _write_conn(db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO jobs(job_id,task_id,pid,status,started,"
                    "finished,log,exit_code,argv_json,note,campaign,job_key,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job_id, task_id, None, "FAILED", "", ts, str(log_path),
                     None, json.dumps([str(a) for a in argv]),
                     f"spawn failed: {exc}", str(campaign or ""),
                     str(job_key or ""), ts, ts))
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            pass
        raise JobError(f"cannot start executor: {exc}", kind="unavailable") from exc

    pid = getattr(proc, "pid", None)
    conn = _write_conn(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO jobs(job_id,task_id,pid,status,started,finished,"
            "log,exit_code,argv_json,note,campaign,job_key,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, task_id, None if pid is None else int(pid), "RUNNING", ts,
             "", str(log_path), None, json.dumps([str(a) for a in argv]),
             note, str(campaign or ""), str(job_key or ""), ts, ts))
        conn.commit()
    finally:
        conn.close()
    threading.Thread(target=_watch, args=(db_path, job_id, proc),
                     name=f"job-watch-{job_id}", daemon=True).start()
    job = get_job(db_path, job_id)
    assert job is not None                     # 刚写完，读不到就是磁盘异常
    return job


# --------------------------------------------------------------------- 取消
def _signal_process(pid: int, *, sig=signal.SIGTERM) -> str:
    """对进程组发信号（spawn 用 start_new_session，pid 即组长）。

    **台账 pid 不可信**：pid 等于调度进程自己时绝不发信号（否则 cancel 会把
    API 进程组整个带走）。这种情况返回 `skipped:self_pid`，状态照样落 CANCELLED。
    """
    if int(pid) == os.getpid():
        return "skipped:self_pid"
    try:
        pgid = os.getpgid(int(pid))
    except (ProcessLookupError, PermissionError, OSError):
        pgid = None
    if pgid:
        try:
            os.killpg(pgid, sig)
            return sig.name
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        os.kill(int(pid), sig)
        return sig.name
    except (ProcessLookupError, PermissionError, OSError):
        return ""                               # 进程已不在：状态照样落 CANCELLED


def cancel_job(db_path: pathlib.Path, job_id: str, *, reason: str = "",
               actor: str = "api", kill: bool = True) -> dict:
    """把 job 打成 CANCELLED 并（可选）对进程组发 SIGTERM。

    只改 jobs 行；任务状态由调用方走 `agent/platform` 的 `cancel_task()`。
    """
    db_path = pathlib.Path(db_path)
    if not db_path.is_file():
        raise JobError(f"job not found: {job_id}", kind="not_found")
    conn = _write_conn(db_path)
    try:
        row = _fetch(conn, job_id)
        if row is None:
            raise JobError(f"job not found: {job_id}", kind="not_found")
        if row["status"] in TERMINAL_JOB_STATES:
            raise JobError(
                f"job {job_id} already {row['status']}", kind="conflict")
        sent = ""
        pid = row.get("pid")
        if kill and pid and pid_alive(pid):
            sent = _signal_process(int(pid))
        note = (f"cancel requested: {reason}".strip() if reason
                else "cancel requested")
        if sent:
            note += f" (sent {sent})"
        conn.execute(
            "UPDATE jobs SET status='CANCELLED', finished=?, note=?, updated_at=? "
            "WHERE job_id=?", (now(), note, now(), job_id))
        conn.commit()
        updated = _fetch(conn, job_id) or row
    finally:
        conn.close()
    return {"job": job_dict(updated), "signal": sent}


# --------------------------------------------------------------------- 关联
def jobs_for_campaign(db_path: pathlib.Path, campaign: str,
                      limit: int = 50) -> list[dict]:
    """V3 P3：按 campaign 过滤启动器 job（`campaign_jobs.launcher_job_id` 的反查面）。"""
    return list_jobs(db_path, limit=limit, campaign=campaign)


def link_campaign_job(db_path: pathlib.Path, job_id: str, job_key: str) -> bool:
    """把一条启动器 job 标到某个 campaign job 上（幂等；只写这一个字段）。"""
    if not str(job_key or "").strip():
        raise JobError("job_key is required")
    if not pathlib.Path(db_path).is_file():
        return False
    conn = _write_conn(db_path)
    try:
        cur = conn.execute(
            "UPDATE jobs SET job_key=?, updated_at=? WHERE job_id=?",
            (str(job_key), now(), str(job_id)))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()
