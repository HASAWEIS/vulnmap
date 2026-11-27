"""自主闭环运行包：分类与独立校验的回归。

覆盖用户要求的判定面：人工介入降级、缺证据、跨运行、哈希不符、超预算、
搬运既有文件、失败样例如实报 unknown。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.autonomy.classify import ASSISTED, AUTONOMOUS, MANUAL, classify
from agent.autonomy.pack import RunPack, sha_file
from agent.autonomy.verify import verify

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "autonomy" / "kvparse"
VISIBLE = [str(p.relative_to(ROOT)) for p in sorted((FIX / "inputs").glob("*.kv"))]
EXPECTED = ROOT / "experiments" / "autonomy" / "holdout" / "expected.json"


def _pack(tmp_path, name="run", budget=None):
    pack = RunPack(tmp_path / name)
    pack.init(run_id="r-test", task_id="t", budget=budget or {"max_observations": 99, "max_seconds": 600},
              agent_visible=VISIBLE, base_dir=ROOT)
    return pack


def _emit(pack, key, entries, errors, *, status="ok", artifact=True):
    art_rel = None
    if artifact:
        art = pack.root / "artifacts" / f"{key}.json"
        art.parent.mkdir(parents=True, exist_ok=True)
        art.write_text(json.dumps({"entries": entries}), encoding="utf-8")
        pack.artifact(name=key, path=art, producer="agent")
        art_rel = f"artifacts/{key}.json"
    return {"status": status, "entries": entries, "errors": errors,
            "artifact": art_rel}


def _finish(pack, findings):
    pack.result({"schema": "vulnmap.autonomy.result.v1", "run_id": pack.run()["run_id"],
                 "findings": findings})
    pack.finish()


def test_autonomous_run_passes(tmp_path):
    pack = _pack(tmp_path)
    findings = {}
    for key in ("a.kv", "b.kv", "c.kv", "d.kv", "e.kv", "f.kv"):
        findings[key] = _emit(pack, key, 1, 0)
    findings["missing.kv"] = {"status": "unknown", "reason": "file_missing"}
    pack.observe(kind="run_parser", detail={"n": 1})
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["class"] == AUTONOMOUS
    assert res["checks"]["artifact_provenance"] is True
    assert res["class_reasons"] == []


def test_human_supplied_input_is_assisted(tmp_path):
    pack = _pack(tmp_path)
    pack.intervention(kind="provided_input", detail={"file": "e.kv"})
    findings = {"a.kv": _emit(pack, "a.kv", 1, 0)}
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["class"] == ASSISTED
    assert res["verdict"] == "fail"
    assert any("关键输入类人工介入" in r for r in res["class_reasons"])


def test_missing_evidence_fails(tmp_path):
    pack = _pack(tmp_path)
    _finish(pack, {"a.kv": _emit(pack, "a.kv", 1, 0)})
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["verdict"] == "fail"
    assert res["counts"]["missing"] > 0
    assert any("缺少条目" in r for r in res["reasons"])


def test_cross_run_reference_fails(tmp_path):
    pack = _pack(tmp_path)
    findings = {"a.kv": _emit(pack, "a.kv", 1, 0)}
    pack.result({"schema": "vulnmap.autonomy.result.v1", "run_id": "r-other",
                 "findings": findings})
    pack.finish()
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["result_belongs_to_run"] is False
    assert res["verdict"] == "fail"


def test_tampered_artifact_fails_provenance(tmp_path):
    pack = _pack(tmp_path)
    findings = {"a.kv": _emit(pack, "a.kv", 1, 0)}
    (pack.root / "artifacts" / "a.kv.json").write_text("{}", encoding="utf-8")
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["artifact_provenance"] is False
    assert res["verdict"] == "fail"


def test_over_budget_fails(tmp_path):
    pack = _pack(tmp_path, budget={"max_observations": 1, "max_seconds": 600})
    for i in range(3):
        pack.observe(kind="run_parser", detail={"n": i})
    _finish(pack, {"a.kv": _emit(pack, "a.kv", 1, 0)})
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["budget_observations"] is False
    assert res["verdict"] == "fail"


def test_artifact_copied_from_visible_input_is_manual(tmp_path):
    pack = _pack(tmp_path)
    src = ROOT / "fixtures/autonomy/kvparse/inputs/a.kv"       # 可见材料
    art = pack.root / "artifacts" / "copy.json"
    art.parent.mkdir(parents=True, exist_ok=True)
    art.write_bytes(src.read_bytes())
    pack.artifact(name="copy", path=art, producer="agent")
    _finish(pack, {"a.kv": {"status": "ok", "entries": 3, "errors": 0,
                            "artifact": "artifacts/copy.json"}})
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["class"] == MANUAL
    assert any("搬运既有文件" in r for r in res["class_reasons"])


def test_honest_unknown_on_unobservable_passes(tmp_path):
    """失败样例的正确姿态：观测不到就报 unknown，不猜。"""
    pack = _pack(tmp_path)
    exp = json.loads(EXPECTED.read_text(encoding="utf-8"))["items"]
    findings = {}
    for k, v in exp.items():
        if v.get("observable"):
            findings[k] = _emit(pack, k, v["entries"], v["errors"])
    findings["missing.kv"] = {"status": "unknown", "reason": "file_missing"}
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["counts"]["unknown_honest"] == 1
    assert res["checks"]["expected_matched"] is True


def test_guessing_on_unobservable_fails(tmp_path):
    pack = _pack(tmp_path)
    findings = {k: _emit(pack, k, 1, 0) for k in ("a.kv", "b.kv", "c.kv", "d.kv", "e.kv", "f.kv")}
    findings["missing.kv"] = {"status": "ok", "entries": 0, "errors": 0}
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["expected_matched"] is False
    assert res["verdict"] == "fail"


# ---------------------------------------------------------------- 平台 run_id 关联
def _platform_db(tmp_path, run_id="r-test", task_id="t"):
    import sqlite3
    db = tmp_path / "platform.db"
    con = sqlite3.connect(db)
    con.execute("create table tasks (id text, task_id text, status text)")
    con.execute("create table task_events (task_id text, seq integer)")
    con.execute("insert into tasks values (?,?,?)", (run_id, task_id, "closed"))
    for i in range(1, 4):
        con.execute("insert into task_events values (?,?)", (run_id, i))
    con.commit()
    con.close()
    return db


def test_platform_link_matches(tmp_path):
    from agent.autonomy.bridge import attach_platform
    pack = _pack(tmp_path)
    db = _platform_db(tmp_path)
    out = attach_platform(pack, db_path=db, task_id="t")
    assert out["attached"] is True and out["events"] == 3
    findings = {"a.kv": _emit(pack, "a.kv", 1, 0)}
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["platform_run_linked"] is True


def test_platform_link_mismatch_fails(tmp_path):
    from agent.autonomy.bridge import attach_platform
    pack = _pack(tmp_path)
    db = _platform_db(tmp_path, run_id="r-other")
    attach_platform(pack, db_path=db, task_id="t")
    findings = {"a.kv": _emit(pack, "a.kv", 1, 0)}
    _finish(pack, findings)
    res = verify(pack.root, expected_path=EXPECTED)
    assert res["checks"]["platform_run_linked"] is False
    assert res["verdict"] == "fail"
    assert any("不一致" in r for r in res["reasons"])


def test_stability_summary_is_stable():
    """保留样例多轮结果必须稳定（自主恒自主、介入恒降级）。"""
    import json as _json
    p = ROOT / "experiments" / "autonomy" / "stability" / "summary.json"
    if not p.is_file():
        pytest.skip("未跑稳定性脚本")
    s = _json.loads(p.read_text(encoding="utf-8"))
    assert s["auto_rounds"] >= 3 and s["auto_stable"] is True, s
    assert s["auto_classes"] == ["agent_autonomous"], s
    assert s["auto_verdicts"] == ["pass"], s
    assert s["assisted_stable"] is True and s["assisted_classes"] == ["agent_assisted"], s
