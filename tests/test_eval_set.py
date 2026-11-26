"""正式集冻结与泄漏扫描：口径必须可复算，交集为空，泄漏能抓到。"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import eval_set  # noqa: E402
import leak_scan  # noqa: E402

PROV = json.loads((ROOT / "experiments" / "PROVENANCE.json").read_text(encoding="utf-8"))
FREEZE = json.loads((ROOT / "experiments" / "FREEZE.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# A. 正式集冻结
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def doc():
    """不探测 docker，保证测试可复现（离线也能跑）。"""
    return eval_set.build(probe_docker=False, generated_at="2026-11-10T00:00:00")


def test_clean_and_dev_disjoint(doc):
    """正式集与开发集交集必须为空 —— 这是正式集的合法性前提。"""
    eval_ids = {e["task_id"] for e in doc["eval_set"]}
    dev_ids = {r["task_id"] for r in PROV["rows"] if r["in_dev_set"]}
    assert eval_ids, "正式集不能为空"
    assert eval_ids & dev_ids == set(), f"交集非空：{eval_ids & dev_ids}"
    assert doc["exclusion"]["intersection"] == []
    assert "∅" in doc["exclusion"]["conclusion"]


def test_eval_set_equals_provenance_clean_rows(doc):
    """入选名单必须逐条等于 PROVENANCE 里 clean=true 且非开发集的行。"""
    expect = {r["task_id"] for r in PROV["rows"]
              if r.get("clean") is True and not r.get("in_dev_set")}
    got = {e["task_id"] for e in doc["eval_set"]}
    assert got == expect
    assert doc["counts"]["eval"] == len(expect) == len(doc["eval_set"])


def test_eval_entries_carry_required_fields(doc):
    required = {"task_id", "case_id", "repo_sha256", "image_digest",
                "allowed_inputs", "sealed_paths", "frozen_at"}
    for e in doc["eval_set"]:
        assert required <= set(e), f"{e.get('task_id')} 缺字段：{required - set(e)}"
        assert e["frozen_at"] == FREEZE["frozen_at"], "frozen_at 必须取自 FREEZE.json"
        assert set(e["allowed_inputs"]) <= {"description.txt", "error.txt"}, e["allowed_inputs"]
        assert isinstance(e["sealed_paths"], list)
        # 解析不了的指针必须显式标记 unresolved，不能静默写成 null
        key = {"repo_sha256": "repo_sha256", "image_digest": "image_digest"}
        for field, tag in key.items():
            if e[field] is None:
                assert any(t.startswith(tag) for t in e["unresolved"]), (e["task_id"], field)
        if e["repo_sha256"]:
            assert len(e["repo_sha256"]) == 64


def test_disk_eval_set_matches_generator(doc):
    """仓库里的 EVAL_SET.json 必须与脚本现在能算出的口径一致（防手改漂移）。"""
    disk = json.loads((ROOT / "experiments" / "EVAL_SET.json").read_text(encoding="utf-8"))
    assert disk["schema"] == eval_set.SCHEMA
    assert [e["task_id"] for e in disk["eval_set"]] == [e["task_id"] for e in doc["eval_set"]]
    assert disk["exclusion"]["intersection"] == []


def test_overlap_is_rejected(tmp_path, monkeypatch):
    """同一 task_id 同时落在正式集与开发集时，必须抛错而不是静默少放一条。"""
    prov = json.loads(json.dumps(PROV))
    clean_row = next(r for r in prov["rows"]
                     if r.get("clean") is True and not r.get("in_dev_set"))
    prov["rows"].append({**clean_row, "in_dev_set": True, "clean": False,
                         "dev_note": "人为制造的开发集重复行"})
    (tmp_path / "PROVENANCE.json").write_text(json.dumps(prov, ensure_ascii=False), encoding="utf-8")
    (tmp_path / "FREEZE.json").write_text(json.dumps(FREEZE, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(eval_set, "EXP", tmp_path)
    monkeypatch.setattr(eval_set, "WS", tmp_path / "workspace")
    with pytest.raises(AssertionError):
        eval_set.build(probe_docker=False)


# --------------------------------------------------------------------------- #
# B. 泄漏扫描
# --------------------------------------------------------------------------- #
def _make_sealed(root: Path, task_id: str = "arvo:1111") -> Path:
    sd = root / "sealed-1111"
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "ANSWER.json").write_text(json.dumps({
        "defect_location": "src/parser/vuln_engine.c:512 (stack overflow)",
        "defect_file": "src/parser/vuln_engine.c",
        "reason": "递归下降解析器未限制嵌套深度，深层嵌套导致栈溢出",
        "required_elements": ["depth_limit_missing"],
        "sealed_files": {"error.txt": "0" * 64, "patch.diff": "1" * 64},
    }, ensure_ascii=False), encoding="utf-8")
    (sd / "patch.diff").write_text("--- a\n+++ b\n", encoding="utf-8")
    (sd / "ARCHIVE.json").write_text(json.dumps({"task_id": task_id}), encoding="utf-8")
    return sd


def _make_workspace(root: Path) -> Path:
    ws = root / "workspace"
    other = ws / "CG-99-arvo-9999"
    (other / "artifacts").mkdir(parents=True)
    (other / "logs").mkdir(parents=True)
    (other / "task.json").write_text(json.dumps({"task_id": "arvo:9999"}), encoding="utf-8")
    (other / "artifacts" / "run_summary.json").write_text('{"ok": true}\n', encoding="utf-8")
    (other / "logs" / "build.log").write_text("compile ok\n", encoding="utf-8")
    return ws


def test_leak_scan_detects_planted_leak(tmp_path):
    """人造泄漏必须命中，且退出码为 1。"""
    sealed_root = tmp_path / "experiments"
    sd = _make_sealed(sealed_root)
    ws = _make_workspace(tmp_path)
    leaky = ws / "CG-99-arvo-9999" / "artifacts" / "report.md"
    leaky.write_text("根因：递归下降解析器未限制嵌套深度，深层嵌套导致栈溢出\n", encoding="utf-8")

    secrets = leak_scan.build_secret_index([sd])
    report = leak_scan.scan(ws, secrets)
    assert report["hits"], "人造泄漏没被抓到"
    assert report["hits"][0]["kind"] == "cross_task"
    assert report["leak_count"] >= 1
    assert not report["clean"]

    rc = leak_scan.main(["--workspace", str(ws), "--sealed", str(sd)])
    assert rc == 1


def test_leak_scan_sha256_hit(tmp_path):
    """泄漏的也可能只是封存文件的 sha256 副本。"""
    sealed_root = tmp_path / "experiments"
    sd = _make_sealed(sealed_root)
    ws = _make_workspace(tmp_path)
    digest = leak_scan.sha256_file(sd / "patch.diff")
    (ws / "CG-99-arvo-9999" / "artifacts" / "manifest.json").write_text(
        json.dumps({"patch": digest}), encoding="utf-8")

    report = leak_scan.scan(ws, leak_scan.build_secret_index([sd]))
    assert report["hits"], "sha256 形式的泄漏没被抓到"
    assert any(h["secret"]["kind"] == "sha256" for h in report["hits"])
    assert report["leak_count"] == 1


def test_leak_scan_clean_returns_zero(tmp_path):
    """无泄漏时必须 0 命中、退出码 0。"""
    sealed_root = tmp_path / "experiments"
    sd = _make_sealed(sealed_root)
    ws = _make_workspace(tmp_path)

    report = leak_scan.scan(ws, leak_scan.build_secret_index([sd]))
    assert report["hits"] == [] and report["leak_count"] == 0
    assert report["clean"] is True
    assert report["scanned"] == 2, "应扫到 artifacts + logs 两个文本文件"

    rc = leak_scan.main(["--workspace", str(ws), "--sealed", str(sd), "--json-out",
                         str(tmp_path / "leak.json")])
    assert rc == 0
    assert json.loads((tmp_path / "leak.json").read_text(encoding="utf-8"))["clean"] is True


def test_leak_scan_self_answer_not_counted_as_leak(tmp_path):
    """任务自己跑出的结论（同任务目录）不算泄漏，严格模式才算。"""
    sealed_root = tmp_path / "experiments"
    sd = _make_sealed(sealed_root, task_id="arvo:9999")
    ws = _make_workspace(tmp_path)
    (ws / "CG-99-arvo-9999" / "artifacts" / "case.json").write_text(
        '{"defect_file": "src/parser/vuln_engine.c"}', encoding="utf-8")

    secrets = leak_scan.build_secret_index([sd])
    normal = leak_scan.scan(ws, secrets)
    assert normal["hits"] == [] and normal["clean"] is True
    assert normal["self_hit_count"] >= 1, "同任务命中应记进 self_hits"

    strict = leak_scan.scan(ws, secrets, include_self=True)
    assert strict["leak_count"] >= 1 and strict["clean"] is False
    assert strict["self_hits"], "严格模式必须把自查命中列出来"


def test_leak_scan_ignores_generic_boilerplate(tmp_path):
    """标识符型样板词（如 libFuzzer 入口名）横跨多个任务时必须豁免，不能当泄漏。"""
    sealed_root = tmp_path / "experiments"
    sd = _make_sealed(sealed_root)
    answer = json.loads((sd / "ANSWER.json").read_text(encoding="utf-8"))
    answer["defect_location"] = "LLVMFuzzerTestOneInput_PLACEHOLDER_LONG"
    (sd / "ANSWER.json").write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")

    ws = _make_workspace(tmp_path)
    for i in range(6):
        d = ws / f"CG-9{i}-arvo-800{i}"
        (d / "artifacts").mkdir(parents=True)
        (d / "task.json").write_text(json.dumps({"task_id": f"arvo:800{i}"}), encoding="utf-8")
        (d / "artifacts" / "repo_map.json").write_text(
            '{"entry": "LLVMFuzzerTestOneInput_PLACEHOLDER_LONG"}', encoding="utf-8")

    report = leak_scan.scan(ws, leak_scan.build_secret_index([sd]))
    assert report["hits"] == []
    assert report["ignored_generic"], "样板词没有被识别出来"


def test_repo_leak_scan_is_clean():
    """仓库自身现状：跨任务泄漏为 0（自查命中允许存在）。"""
    rc = leak_scan.main([])
    assert rc == 0


# --------------------------------------------------------------------------- #
# C. docs/CONTAMINATION.md
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def md():
    p = ROOT / "docs" / "CONTAMINATION.md"
    assert p.is_file(), "缺少 docs/CONTAMINATION.md"
    return p.read_text(encoding="utf-8")


def test_contamination_md_has_matrix(md):
    assert "任务 × 构造器/模板来源矩阵" in md
    assert "| 案例 | task_id | 构造器/模板来源 | 含答案污染 | 开发集 | 干净 | 正式集 |" in md
    for r in PROV["rows"]:
        assert f"| {r['case_id']} |" in md, f"矩阵漏了 {r['case_id']}"


def test_contamination_md_highlights_counts(md):
    s = PROV["summary"]
    assert f"**官方 PoC 模板 {s['with_poc_template']} 例**" in md
    assert f"**干净 {s['clean']} 例**" in md
    assert s["with_poc_template"] == 3 and s["clean"] == 7


def test_contamination_md_hard_rule_and_exclusion(md):
    assert "**正式集任务不得使用含答案模板**" in md
    assert "互斥性结论：EVAL_SET" in md
    assert "= ∅" in md


def test_contamination_md_generated_by_script(md):
    """文档必须能由脚本复现，避免手改后与 JSON 打架。"""
    assert "生成源：`experiments/eval_set.py`" in md
    fresh = eval_set.render_md(eval_set.build(probe_docker=False, generated_at="x"))
    assert "**正式集任务不得使用含答案模板**" in fresh
    assert fresh.strip().splitlines()[0] == md.strip().splitlines()[0]
