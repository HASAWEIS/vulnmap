"""平台事实 -> 自主运行包：适配器与校验的回归。"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agent.autonomy.pack import sha_file
from agent.autonomy.platform_adapter import pack_from_platform
from agent.autonomy.verify import verify

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "experiments" / "autonomy" / "holdout" / "expected.json"


def _db(tmp_path, *, findings=None, evidence_files=(), tamper=False):
    db = tmp_path / "platform.db"
    con = sqlite3.connect(db)
    con.execute("create table tasks (task_id text, benchmark text, target text, mode text,"
                " state text, budget_json text, metadata_json text, terminal_reason text,"
                " created_at text, updated_at text)")
    con.execute("create table task_events (seq integer, task_id text, ts text,"
                " event_type text, stage text, payload_json text)")
    con.execute("create table evidence (sha256 text, size integer, path text, created_at text)")
    con.execute("create table task_evidence (task_id text, sha256 text, kind text,"
                " source_stage text, created_at text)")
    con.execute("create table reports (report_id text, task_id text, path text,"
                " sha256 text, created_at text)")
    con.execute("insert into tasks values (?,?,?,?,?,?,?,?,?,?)",
                ("t-auto", "target_yaml", "fixtures/autonomy/kvparse", "fuzz", "REPORTED",
                 json.dumps({"max_turns": 40, "max_seconds": 600}), "{}", "", "2026-11-27T00:00:00+00:00",
                 "2026-11-27T00:05:00+00:00"))
    for i in range(1, 6):
        con.execute("insert into task_events values (?,?,?,?,?,?)",
                    (i, "t-auto", "2026-11-27T00:00:0%d+00:00" % i, "state.changed",
                     "run", "{}"))
    for p in evidence_files:
        p = Path(p)
        h = sha_file(p)
        con.execute("insert into evidence values (?,?,?,?)", (h, p.stat().st_size, str(p), "now"))
        con.execute("insert into task_evidence values (?,?,?,?,?)", ("t-auto", h, "artifact", "run", "now"))
    if findings is not None:
        rep = tmp_path / "report.json"
        rep.write_text(json.dumps({"findings": findings}), encoding="utf-8")
        con.execute("insert into reports values (?,?,?,?,?)",
                    ("rep-1", "t-auto", str(rep), sha_file(rep), "now"))
    con.commit()
    con.close()
    return db


def _findings_and_files(tmp_path):
    """用 fixture 生成与保留答案一致的 findings 和 evidence 文件。"""
    exp = json.loads(EXPECTED.read_text(encoding="utf-8"))["items"]
    findings, files = {}, []
    for key, v in exp.items():
        if not v.get("observable"):
            findings[key] = {"status": "unknown", "reason": "file_missing"}
            continue
        art = tmp_path / ("art-%s.json" % key)
        art.write_text(json.dumps({"entries": v["entries"]}), encoding="utf-8")
        files.append(art)
        findings[key] = {"status": "ok", "entries": v["entries"],
                         "errors": v["errors"], "artifact": "artifacts/" + art.name}
    return findings, files


def test_adapter_builds_autonomous_pack_and_passes(tmp_path):
    findings, files = _findings_and_files(tmp_path)
    db = _db(tmp_path, findings=findings, evidence_files=files)
    pack_root = tmp_path / "packs" / "t-auto"
    out = pack_from_platform(db, "t-auto", pack_root)
    assert out["ok"] and out["events"] == 5 and out["evidence"] == len(files)
    assert out["result_from_report"] is True

    res = verify(pack_root, expected_path=EXPECTED)
    assert res["class"] == "agent_autonomous", res["class_reasons"]
    assert res["checks"]["artifact_provenance"] is True
    assert res["verdict"] == "pass", res["reasons"]


def test_adapter_without_evidence_is_manual_baseline(tmp_path):
    findings, _ = _findings_and_files(tmp_path)
    db = _db(tmp_path, findings=findings)
    pack_root = tmp_path / "packs" / "t-auto"
    pack_from_platform(db, "t-auto", pack_root)
    res = verify(pack_root, expected_path=EXPECTED)
    assert res["class"] == "manual_baseline"
    assert any("无工件记录" in r for r in res["class_reasons"])


def test_adapter_missing_task(tmp_path):
    db = _db(tmp_path, findings={"a.kv": {"status": "ok"}})
    out = pack_from_platform(db, "nope", tmp_path / "packs" / "x")
    assert out["ok"] is False and out["reason"] == "task_not_found"


def test_tampered_evidence_fails_provenance(tmp_path):
    findings, files = _findings_and_files(tmp_path)
    db = _db(tmp_path, findings=findings, evidence_files=files)
    pack_root = tmp_path / "packs" / "t-auto"
    pack_from_platform(db, "t-auto", pack_root)
    victim = sorted((pack_root / "artifacts").glob("*.json"))[0]
    victim.write_text("{}", encoding="utf-8")
    res = verify(pack_root, expected_path=EXPECTED)
    assert res["checks"]["artifact_provenance"] is False
    assert res["verdict"] == "fail"
