"""模型定位贡献：候选枚举 + 选择校验 + 执行裁判。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.tools.binscan import read_lines, write_candidates


SRC = """static int f(int *in, int n)
{
  out = alloc(2*n+3);
  out[n].code = A;
  out[n].point = in[0];
  if (n > 2) {
    out[start].code = B;
    out[n].code = C;
    n++;
    out[n].code = D;
  }
  out[n].code = E;
  return 0;
}
"""


def _lines(tmp_path):
    p = tmp_path / "t.c"
    p.write_text(SRC, encoding="utf-8")
    return read_lines(p)


def test_enumerates_array_and_struct_writes(tmp_path):
    lines = _lines(tmp_path)
    got = [c["line"] for c in write_candidates(lines, 1, len(lines), stage="locate")]
    # out[...].field = 形式全部应被枚举，共 6 处
    assert len(got) == 6, got


def test_assignment_comparison_not_counted(tmp_path):
    p = tmp_path / "t.c"
    p.write_text("void f(){\n  if (a[i] == 0) {}\n  a[i] = 1;\n}\n", encoding="utf-8")
    lines = read_lines(p)
    got = write_candidates(lines, 1, len(lines), stage="locate")
    assert [c["line"] for c in got] == [3]


def test_requires_stage(tmp_path):
    lines = _lines(tmp_path)
    with pytest.raises(PermissionError):
        write_candidates(lines, 1, 5)


def test_candidates_carry_text_for_audit(tmp_path):
    lines = _lines(tmp_path)
    got = write_candidates(lines, 1, len(lines), stage="locate")
    assert all(c["text"] and c["base"] for c in got)


# ---- 贡献校验 ----

def _report():
    from agent.stages.report import ReportStage
    return ReportStage.__new__(ReportStage)


def test_pinpoint_verified_when_pick_matches_crash():
    r = _report()
    locate = {"pinpoint": {"attempted": True, "validated": True, "picked": 942,
                           "candidates": 10}}
    verify = {"model_loop": {"rounds": [{"crash_line": 942}]}}
    out = r._pinpoint_verified(locate, verify)
    assert out["verified"] is True


def test_pinpoint_rejected_when_pick_differs():
    r = _report()
    locate = {"pinpoint": {"attempted": True, "validated": True, "picked": 949,
                           "candidates": 10}}
    verify = {"model_loop": {"rounds": [{"crash_line": 942}]}}
    out = r._pinpoint_verified(locate, verify)
    assert out["verified"] is False
    assert "949" in out["reason"] and "942" in out["reason"]


def test_pinpoint_rejected_without_selection_space():
    r = _report()
    locate = {"pinpoint": {"attempted": True, "validated": True, "picked": 5,
                           "candidates": 1}}
    verify = {"model_loop": {"rounds": [{"crash_line": 5}]}}
    assert r._pinpoint_verified(locate, verify)["verified"] is False


def test_pinpoint_rejected_without_executed_crash():
    r = _report()
    locate = {"pinpoint": {"attempted": True, "validated": True, "picked": 5,
                           "candidates": 4}}
    out = r._pinpoint_verified(locate, {"model_loop": {"rounds": []}})
    assert out["verified"] is False
    assert out["reason"] == "no_executed_crash_line"


def test_pinpoint_rejected_when_not_attempted():
    r = _report()
    out = r._pinpoint_verified({"pinpoint": {"attempted": False}}, {})
    assert out["verified"] is False
