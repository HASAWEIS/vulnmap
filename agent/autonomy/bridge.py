"""把自主运行包接到平台 run_id / 事件流，让课程判据能直接引用。

只读平台库，不改平台事实；把关联写进运行包 run.json 的 platform 段。
"""
from __future__ import annotations

import json
import pathlib
import sqlite3

from .pack import RunPack


def attach_platform(pack: RunPack, *, db_path, task_id) -> dict:
    db = pathlib.Path(db_path)
    if not db.is_file():
        return {"attached": False, "reason": "db_missing", "db": str(db)}
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        row = con.execute(
            "select id, task_id, status from tasks where task_id=? "
            "order by rowid desc limit 1", (task_id,)).fetchone()
        if row is None:
            return {"attached": False, "reason": "task_not_found", "task_id": task_id}
        events = con.execute(
            "select count(*) from task_events where task_id=?", (row["id"],)).fetchone()[0]
    finally:
        con.close()

    run = pack.run()
    run["platform"] = {"db": str(db), "task_id": task_id,
                       "platform_run_id": row["id"],
                       "platform_status": row["status"],
                       "event_count": int(events)}
    (pack.root / "run.json").write_text(
        json.dumps(run, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")
    return {"attached": True, "platform_run_id": row["id"], "events": int(events)}
