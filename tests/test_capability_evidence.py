"""能力证据不进交付计数；裁决校验脚本可判非法。"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_capability_evidence_excluded():
    cap = json.loads((ROOT / "experiments" / "capability-evidence.json").read_text())
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text())
    ids = {r.get("case_id") for r in led["rows"]}
    by_id = {r["case_id"]: r for r in led["rows"]}
    for item in cap["items"]:
        if item["counts_in_delivery"]:
            assert item["case"] in ids, f"{item['case']} 已准入但台账缺失"
            assert by_id[item["case"]].get("dev_rerun") is True
            assert by_id[item["case"]].get("first_run") is False
        else:
            assert item["case"] not in ids, f"{item['case']} 不应进台账"


def test_severity_review_rejects_empty(tmp_path):
    p = ROOT / "experiments" / "severity" / "review.json"
    backup = p.read_bytes() if p.exists() else None
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"decisions": {"CG-02": {"integrity_impact": "I:H"}}}))
        r = subprocess.run([sys.executable, str(ROOT / "experiments" / "check_severity_review.py")],
                           capture_output=True, text=True)
        assert r.returncode == 1 and "missing decision" in r.stdout
    finally:
        if backup is not None:
            p.write_bytes(backup)
        elif p.exists():
            p.unlink()
