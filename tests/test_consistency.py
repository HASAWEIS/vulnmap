"""一致性审计脚本自身的测试：干净仓库必须过，篡改一个数字必须被抓住。

fixture 全部在 tmp_path 里造，绝不动仓库真实产物（真实案例目前有已知
不一致，测试不能拿真实数据当"必须 0 mismatch"的前提）。
"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import check_consistency as cc  # noqa: E402


# ---------------------------------------------------------------- fixture 构造
def _case(case_id, *, verdict="pass", ccv=True, hs=False, defect="target_defect",
          generation="generated_and_verified", mc_verified=True,
          llm_enabled=True, stage="causal_chain_verified", course_ready=False):
    return {
        "schema": "vulnmap.case.v1",
        "case_id": case_id,
        "task_id": "arvo:1",
        "verdict": verdict,
        "acceptance": {
            "stage": stage,
            "causal_chain_verified": ccv,
            "counts_as_target_defect": defect == "target_defect",
            "defect_class": defect,
            "high_severity_confirmed": hs,
            "course_ready": course_ready,
        },
        "generation": {"state": generation, "counts_in_denominator": True},
        "model_contribution": {
            "verified_pinpoint": mc_verified,
            "verified_generation": mc_verified,
            "verified_new_contribution": mc_verified,
        },
        "agent": {"role_version": "report-v1", "prompt_version": "report-p1",
                  "llm_enabled": llm_enabled},
    }


def _make_db(ws_dir: Path, *, llm_ok=0, llm_err=0):
    rt = ws_dir / ".runtime"
    rt.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(rt / "vulnmap.db"))
    con.execute("CREATE TABLE attempts (id TEXT, stage TEXT, n INTEGER, "
                "outcome TEXT, detail TEXT)")
    n = 0
    con.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                ("a0", "recon", 1, "completed", json.dumps({"seconds": 0.1})))
    for _ in range(llm_ok):
        n += 1
        detail = {"llm": {"role": "locate", "status": "ok", "model": "m"}}
        con.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                    (f"a{n}", "locate", 2, "llm_ok", json.dumps(detail)))
    for _ in range(llm_err):
        n += 1
        detail = {"llm": {"role": "locate", "status": "error", "model": "m"}}
        con.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                    (f"a{n}", "locate", 2, "llm_error", json.dumps(detail)))
    con.commit()
    con.close()


def build_repo(tmp_path):
    """造一个四份"真相"完全对齐的最小仓库。"""
    root = tmp_path / "repo"
    (root / "experiments").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)

    cases = {
        "CG-A-arvo-1": _case("CG-A", llm_enabled=True),
        "CG-B-arvo-2": _case("CG-B", llm_enabled=False, verdict="generated_but_unverified",
                             ccv=False, mc_verified=False,
                             generation="generated_but_unverified",
                             stage="not_verified"),
        "CG-C-arvo-3": _case("CG-C", llm_enabled=True, defect="harness_ub",
                             hs=False),
    }
    for dirname, case in cases.items():
        d = root / "workspace" / dirname / "artifacts" / "report"
        d.mkdir(parents=True)
        (d / "case.json").write_text(json.dumps(case, ensure_ascii=False),
                                     encoding="utf-8")
        ws = root / "workspace" / dirname
        _make_db(ws, llm_ok=1 if case["agent"]["llm_enabled"] else 0)

    # 与 case.json 聚合一致（2 通过 / 1 因果链 / 1 模型贡献 / 0 高危）
    totals = {
        "cases": 3,
        "local_dual_run_pass": 2,
        "generation_ok": 2,
        "generation_unsupported": 0,
        "causal_chain_verified": 2,
        "  of_which_target_defect": 1,
        "  harness_ub_cases": 1,
        "high_severity_confirmed": 0,
        "model_new_contribution": 2,
        "  of_which_locate_pinpoint": 2,
        "  of_which_generation": 2,
        "course_ready": 0,
    }
    (root / "experiments" / "LEDGER.json").write_text(
        json.dumps({"rows": [], "totals": totals}, ensure_ascii=False),
        encoding="utf-8")
    (root / "experiments" / "PROVENANCE.json").write_text(
        json.dumps({"rows": [{"case_id": c.split("-")[0] + "-" + c.split("-")[1],
                              "dir": d} for c, d in
                             [(k, k) for k in cases]]}, ensure_ascii=False),
        encoding="utf-8")
    (root / "docs" / "STATUS.md").write_text(
        "\n".join([
            "# 项目状态",
            "",
            "## 当前计数",
            "",
            "| 指标 | 数值 |",
            "|---|---|",
            "| 案例数 | 3 |",
            "| 本地双端通过 | 2 |",
            "| 因果链闭合 | 2 |",
            "| 模型新增贡献 | 2（定位类 2 / 生成类 2） |",
            "| course_ready | 0 |",
            "",
            "## 案例明细",
            "",
            "| 案例数 | 999 |",  # 不在「当前计数」小节，必须被忽略
        ]) + "\n",
        encoding="utf-8")
    return root


@pytest.fixture()
def repo(tmp_path):
    return build_repo(tmp_path)


# ---------------------------------------------------------------- 一致时通过
def test_clean_fixture_has_no_mismatch(repo):
    result = cc.audit(repo)
    assert result["mismatches"] == [], result["mismatches"]
    assert result["summary"]["consistent"] is True
    assert result["summary"]["cases"] == 3
    assert all(c["ok"] for c in result["checks"])


def test_clean_fixture_cli_exit_zero(repo, tmp_path):
    out = tmp_path / "CONSISTENCY.json"
    rc = cc.main(["--root", str(repo), "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["mismatches"] == []
    for key in ("generated_at", "checks", "mismatches"):
        assert key in data


def test_every_check_has_required_fields(repo):
    result = cc.audit(repo)
    assert result["checks"]
    for c in result["checks"]:
        assert {"name", "expected", "actual", "ok"} <= set(c)
        assert isinstance(c["ok"], bool)


# ---------------------------------------------------------------- 篡改一个数字
def test_tampered_status_number_detected(repo, tmp_path):
    status = repo / "docs" / "STATUS.md"
    text = status.read_text(encoding="utf-8").replace("| 本地双端通过 | 2 |",
                                                     "| 本地双端通过 | 3 |")
    status.write_text(text, encoding="utf-8")
    result = cc.audit(repo)
    assert result["mismatches"], "STATUS.md 数字被篡改却没检出"
    keys = {(m["check"], m["key"]) for m in result["mismatches"]}
    assert ("status_md_vs_ledger_totals", "本地双端通过") in keys
    # CLI 必须返回 1
    rc = cc.main(["--root", str(repo), "--out", str(tmp_path / "o.json"),
                  "--quiet"])
    assert rc == 1


def test_tampered_ledger_total_detected(repo):
    p = repo / "experiments" / "LEDGER.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["totals"]["causal_chain_verified"] = 3
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    result = cc.audit(repo)
    keys = {(m["check"], m["key"]) for m in result["mismatches"]}
    assert ("ledger_totals_vs_case_json", "causal_chain_verified") in keys


def test_tampered_case_aggregate_detected(repo):
    """改 case.json 的一个布尔值，台账聚合就必须对不上。"""
    p = repo / "workspace" / "CG-A-arvo-1" / "artifacts" / "report" / "case.json"
    case = json.loads(p.read_text(encoding="utf-8"))
    case["model_contribution"]["verified_new_contribution"] = False
    p.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
    result = cc.audit(repo)
    keys = {(m["check"], m["key"]) for m in result["mismatches"]}
    assert ("ledger_totals_vs_case_json", "model_new_contribution") in keys


def test_llm_flag_contradiction_detected(repo):
    """报告说没调用 LLM，日志里却有 llm.status=ok -> 必须抓出来。"""
    p = repo / "workspace" / "CG-A-arvo-1" / "artifacts" / "report" / "case.json"
    case = json.loads(p.read_text(encoding="utf-8"))
    case["agent"]["llm_enabled"] = False
    p.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
    result = cc.audit(repo)
    names = {m["key"] for m in result["mismatches"]
             if m["check"] == "llm_enabled_vs_attempts_llm_ok"}
    assert "CG-A" in names


def test_llm_log_added_for_disabled_case_detected(repo, tmp_path):
    """反向：案例声明未用 LLM，但库里新冒出一条 llm ok。"""
    ws = repo / "workspace" / "CG-B-arvo-2"
    db = ws / ".runtime" / "vulnmap.db"
    con = sqlite3.connect(str(db))
    con.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                ("zz", "locate", 2, "llm_ok",
                 json.dumps({"llm": {"status": "ok"}})))
    con.commit()
    con.close()
    result = cc.audit(repo)
    names = {m["key"] for m in result["mismatches"]
             if m["check"] == "llm_enabled_vs_attempts_llm_ok"}
    assert "CG-B" in names


def test_llm_error_only_is_not_ok(repo):
    """status=error 不等于 ok，不能算"调用成功"。"""
    ws = repo / "workspace" / "CG-A-arvo-1"
    db = ws / ".runtime" / "vulnmap.db"
    con = sqlite3.connect(str(db))
    con.execute("DELETE FROM attempts")
    con.execute("INSERT INTO attempts VALUES (?,?,?,?,?)",
                ("e1", "locate", 2, "llm_error",
                 json.dumps({"llm": {"status": "error"}})))
    con.commit()
    con.close()
    info = cc.llm_status_ok(repo, "CG-A-arvo-1")
    assert info["llm_rows"] == 1
    assert info["llm_status_ok"] == 0


# ---------------------------------------------------------------- 溯源 / 文件缺失
def test_provenance_missing_case_detected(repo):
    p = repo / "experiments" / "PROVENANCE.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["rows"] = [r for r in data["rows"] if r["case_id"] != "CG-C"]
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    result = cc.audit(repo)
    checks = {m["check"] for m in result["mismatches"]}
    assert "provenance_case_ids" in checks


def test_provenance_extra_case_detected(repo):
    p = repo / "experiments" / "PROVENANCE.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["rows"].append({"case_id": "CG-X", "dir": "CG-X-arvo-9"})
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    result = cc.audit(repo)
    checks = {m["check"] for m in result["mismatches"]}
    assert "provenance_dirs_vs_workspace" in checks


def test_missing_ledger_reports_mismatch(tmp_path):
    root = build_repo(tmp_path)
    (root / "experiments" / "LEDGER.json").unlink()
    result = cc.audit(root)
    assert any(m["check"] == "file_present" for m in result["mismatches"])
    assert result["summary"]["consistent"] is False


# ---------------------------------------------------------------- 真实仓库（形态）
def test_real_repo_audit_shape():
    """真实仓库跑得通、JSON 形状正确；不假设 mismatch 数（已知有真实不一致）。"""
    result = cc.audit(ROOT)
    assert result["summary"]["cases"] == len(cc.load_cases(ROOT))
    assert isinstance(result["mismatches"], list)
    for m in result["mismatches"]:
        assert {"check", "key", "expected", "actual"} <= set(m)
    ok_names = {"llm_enabled_vs_attempts_llm_ok", "ledger_totals_vs_case_json",
                "status_md_vs_ledger_totals", "provenance_case_ids",
                "provenance_dirs_vs_workspace"}
    assert {m["check"] for m in result["mismatches"]} <= ok_names


def test_real_repo_script_is_read_only(tmp_path):
    """审计不得改动被审计文件（只写自己的 CONSISTENCY.json）。"""
    files = [ROOT / "experiments" / "LEDGER.json",
             ROOT / "experiments" / "PROVENANCE.json",
             ROOT / "docs" / "STATUS.md"]
    before = {f: f.read_bytes() for f in files}
    cc.main(["--root", str(ROOT), "--out", str(tmp_path / "C.json"), "--quiet"])
    after = {f: f.read_bytes() for f in files}
    assert before == after
