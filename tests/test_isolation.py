"""工作区隔离：权限约束 + 泄漏自检。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.isolation import (assert_workspace_reads_confined, check_permissions,
                             sealed_paths)


def test_sealed_dir_not_world_readable():
    problems = check_permissions()
    assert not problems, problems


def test_sealed_paths_discovered():
    assert sealed_paths(), "封存目录应当可枚举"


def test_workspace_leak_detector_finds_identical_copy(tmp_path):
    """把封存文件复制进工作区必须被检出。"""
    sealed = sealed_paths()
    if not sealed:
        return
    src = sorted(sealed)[0]
    (tmp_path / "copied.bin").write_bytes(src.read_bytes())
    hits = assert_workspace_reads_confined(tmp_path)
    assert hits and "identical to sealed" in hits[0]


def test_auditor_does_not_claim_no_read_during_run():
    """读后关闭检测不到：报告必须明确不声称 stronger 结论。"""
    from agent.isolation import ReadAuditor
    a = ReadAuditor()
    if not a.sealed:
        return
    fh = open(sorted(a.sealed)[0])
    hits = a.scan_process_open_files()
    assert hits                    # 打开时能检出
    rep = a.report()
    assert rep["no_open_handle_at_scan"] is False
    assert rep["proves_no_read_during_run"] is False
    fh.close()
    b = ReadAuditor()
    b.scan_process_open_files()
    assert b.report()["no_open_handle_at_scan"] is True
    assert b.report()["proves_no_read_during_run"] is False   # 读后关闭 → 不声称
