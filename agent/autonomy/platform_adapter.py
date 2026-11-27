"""从平台事实（tasks / task_events / evidence / reports）生成自主运行包。

只读平台库；不改平台任何记录。生成的包可用于 agent/autonomy/verify.py 的独立校验。
平台的运行身份就是 task_id，因此包内 run_id = task_id。
"""
from __future__ import annotations

import json
import pathlib
import sqlite3

from .pack import RunPack, sha_file


def _tables(con) -> set:
    return {r[0] for r in con.execute("select name from sqlite_master where type='table'")}


def _ts(value):
    """平台 ts 可能是 epoch 秒或 ISO8601；统一成 epoch 秒。"""
    import datetime
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.datetime.fromisoformat(str(value)).timestamp()
    except ValueError:
        return 0.0


def _json(text, default):
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default


def pack_from_platform(db_path, task_id, pack_root, *, event_cap=200) -> dict:
    db = pathlib.Path(db_path)
    if not db.is_file():
        return {"ok": False, "reason": "db_missing"}
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        tables = _tables(con)
        task = con.execute("select * from tasks where task_id=?", (task_id,)).fetchone()
        if task is None:
            return {"ok": False, "reason": "task_not_found", "task_id": task_id}
        budget = _json(task["budget_json"], {}) or {}
        events = con.execute(
            "select seq, ts, event_type, stage from task_events where task_id=? "
            "order by seq limit ?", (task_id, event_cap)).fetchall()
        total_events = con.execute(
            "select count(*) from task_events where task_id=?", (task_id,)).fetchone()[0]

        evid = []
        if "task_evidence" in tables:
            # evidence 是内容寻址：同一 sha256 可能对应多个路径。
            # 用 in 子查询按 path 取全部实体，避免 join 把同内容文件乘开。
            evid = con.execute(
                "select sha256, size, path from evidence "
                "where sha256 in (select sha256 from task_evidence where task_id=?) "
                "group by path", (task_id,)).fetchall()
        elif "evidence" in tables:
            evid = con.execute("select sha256, size, path from evidence").fetchall()

        report = None
        if "reports" in tables:
            cols = {d[1] for d in con.execute("pragma table_info(reports)")}
            json_col = next((c for c in ("payload_json", "report_json", "body_json", "content")
                             if c in cols), None)
            if json_col:
                row = con.execute(
                    "select %s from reports where task_id=? "
                    "order by rowid desc limit 1" % json_col, (task_id,)).fetchone()
                if row is not None:
                    report = _json(row[0], None)
            else:                        # 报告只有路径时，读文件
                row = con.execute(
                    "select path from reports where task_id=? order by rowid desc limit 1",
                    (task_id,)).fetchone()
                if row is not None and row["path"] and pathlib.Path(row["path"]).is_file():
                    report = _json(pathlib.Path(row["path"]).read_text(
                        encoding="utf-8", errors="ignore"), None)
    finally:
        con.close()

    pack = RunPack(pack_root)
    pack.root.mkdir(parents=True, exist_ok=True)
    started = _ts(events[0]["ts"]) if events else 0.0
    (pack.root / "run.json").write_text(json.dumps({
        "schema": "vulnmap.autonomy.runpack.v1",
        "run_id": task_id, "task_id": task_id,
        "started_at": started, "budget": {
            "max_observations": int(budget.get("max_turns") or event_cap),
            "max_seconds": int(budget.get("max_seconds") or 0) or None,
        },
        "state": "finished",
        "finished_at": _ts(events[-1]["ts"]) if events else started,
        "base_dir": str(pathlib.Path(pack_root).parent),
        "source": "platform",
    }, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")

    (pack.root / "frozen_inputs.json").write_text(json.dumps({
        "schema": "vulnmap.autonomy.runpack.v1.frozen", "run_id": task_id,
        "files": {},
        "note": "平台任务的目标与预算在 tasks 行内冻结；本包不复制目标源码。",
        "target": task["target"], "benchmark": task["benchmark"],
    }, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")

    (pack.root / "interventions.jsonl").write_text("", encoding="utf-8")

    with open(pack.root / "observations.jsonl", "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps({"ts": _ts(e["ts"]), "kind": e["event_type"],
                                 "detail": {"seq": e["seq"], "stage": e["stage"]}},
                                ensure_ascii=False) + chr(10))

    (pack.root / "artifacts").mkdir(parents=True, exist_ok=True)
    with open(pack.root / "artifacts.jsonl", "w", encoding="utf-8") as fh:
        for e in evid:
            src = pathlib.Path(e["path"])
            rel = "artifacts/" + src.name
            dst = pack.root / rel
            if src.is_file():
                dst.write_bytes(src.read_bytes())
            fh.write(json.dumps({
                "ts": _ts(events[-1]["ts"]) if events else 0.0,
                "name": src.name, "path": rel,
                "producer": "agent", "sha256": e["sha256"], "size": e["size"],
                "present": dst.is_file(),
                "actual_sha256": sha_file(dst) if dst.is_file() else None,
            }, ensure_ascii=False) + chr(10))

    result = None
    if isinstance(report, dict) and report.get("findings"):
        result = {"schema": "vulnmap.autonomy.result.v1", "run_id": task_id,
                  "task_id": task_id, "findings": report["findings"]}
        (pack.root / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")

    return {"ok": True, "run_id": task_id, "events": total_events,
            "events_recorded": len(events), "evidence": len(evid),
            "result_from_report": bool(result), "pack": str(pack.root)}
