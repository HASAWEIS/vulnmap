"""前端数据与台账一致：展示的数字不能和验收状态脱节。"""
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"


@pytest.fixture(scope="module")
def data():
    r = subprocess.run([sys.executable, str(ROOT / "experiments" / "build_dashboard.py")],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    return json.loads((WEB / "data.json").read_text(encoding="utf-8"))


def test_dashboard_totals_match_ledger(data):
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    assert data["totals"] == led["totals"]


def test_every_case_has_detail(data):
    missing = [c["ledger"].get("case_id") or c["ledger"].get("case_dir")
               for c in data["cases"] if not c.get("detail")]
    assert not missing, f"这些案例没有 case.json，前端无法展示明细：{missing}"


def test_case_count_matches_workspace(data):
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    n = led["totals"]["cases"]
    with_detail = sum(1 for c in data["cases"] if c.get("detail"))
    assert with_detail == n


def test_index_html_is_self_contained():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    import re
    ext = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    assert not ext, f"页面不应依赖外部资源（离线可用）：{ext}"


def test_index_html_has_no_unbalanced_script():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert html.count("<script") == html.count("</script>")
    assert html.startswith("<!doctype html>")


def test_high_severity_shown_matches_gate(data):
    """前端展示的"高危"必须与门禁口径一致，不能自己另算一套。"""
    for c in data["cases"]:
        d = c.get("detail")
        if not d:
            continue
        acc = d["acceptance"]
        # 高危显示必须同时满足"已论证"与"属目标缺陷"
        if acc["high_severity_confirmed"]:
            assert acc["severity_assessed"], f"{d['case_id']}: 高危但严重性未论证"
            assert acc["counts_as_target_defect"], f"{d['case_id']}: 高危但非目标缺陷"


def test_project_field_is_not_a_path(data):
    """历史数据问题：case.json 的 project 曾被写成源码绝对路径，直接展示无意义。"""
    bad = [(c["detail"]["case_id"], c["detail"]["project"])
           for c in data["cases"]
           if c.get("detail") and str(c["detail"].get("project") or "").startswith("/")]
    assert not bad, f"project 不应是路径：{bad}"


def test_dashboard_json_is_serializable(data):
    """前端 data.json 必须可被 json 解析且无 NaN/Infinity。"""
    text = (WEB / "data.json").read_text(encoding="utf-8")
    assert "NaN" not in text and "Infinity" not in text
    json.loads(text)
