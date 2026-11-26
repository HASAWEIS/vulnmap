"""文档必须与台账一致：漂移就让测试失败，而不是等答辩时才发现口径打架。"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "experiments"))

import gen_docs  # noqa: E402


def test_status_md_matches_ledger(tmp_path, monkeypatch):
    led, meta, exp = gen_docs.load()
    rs = gen_docs.rows(led, meta)
    # 生成到临时目录后与仓库内文件逐字比对
    monkeypatch.setattr(gen_docs, "DOCS", tmp_path)
    generated = gen_docs.write_status(led, rs, exp).read_text(encoding="utf-8")
    committed = (ROOT / "docs" / "STATUS.md").read_text(encoding="utf-8")
    assert generated == committed, "docs/STATUS.md 与台账不同步，请运行 python3 experiments/gen_docs.py"


def test_csv_rows_equal_ledger_rows():
    led, meta, _ = gen_docs.load()
    rs = gen_docs.rows(led, meta)
    assert len(rs) == led["totals"]["cases"]
    assert {r["编号"] for r in rs} == gen_docs.case_ids(led, meta)


def test_no_hardcoded_progress_in_readme():
    """README 不得写死进度数字（历史事故：写着 71 passed 而实际已过百）。"""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    import re
    bad = re.findall(r"#\s*\d+\s+passed", text)
    assert not bad, f"README 出现写死的测试数：{bad}"


def test_case_meta_covers_ledger():
    led, meta, _ = gen_docs.load()
    ids = gen_docs.case_ids(led, meta)
    missing = {i for i in ids if i not in meta}
    assert not missing, f"case_meta.json 缺这些案例：{missing}"


def test_case_meta_identity_matches_workspace():
    """meta 里的 project/cwe 必须与案例真实工件一致。

    历史事故：CG-06 在 meta 里写成 harfbuzz / `CWE-*}`，
    实际是 yara / CWE-unknown —— 身份错误会直接污染统计可信度。
    """
    import json as _json
    led, meta, _ = gen_docs.load()
    problems = []
    for cid in sorted(gen_docs.case_ids(led, meta)):
        m = meta.get(cid, {})
        task = None
        for d in (ROOT / "workspace").glob(f"{cid}*"):
            tp = d / "task.json"
            if tp.exists():
                task = _json.loads(tp.read_text(encoding="utf-8"))
                break
        if not task:
            continue
        if m.get("project") and task.get("project") and m["project"] != task["project"]:
            problems.append(f"{cid}: meta.project={m['project']} != task.project={task['project']}")
    assert not problems, problems


def test_no_placeholder_cwe():
    """CWE 不允许出现占位/残缺值（如 `CWE-*}`）。"""
    import json as _json
    _, meta, _ = gen_docs.load()
    # CWE-unknown 是诚实的"未知"，允许；其余必须是 CWE-<数字>
    bad = {k: v.get("cwe") for k, v in meta.items()
           if isinstance(v, dict) and v.get("cwe") and v["cwe"] != "CWE-unknown"
           and not __import__("re").fullmatch(r"CWE-\d+(: .+)?", str(v["cwe"]))}
    assert not bad, f"meta 里存在非规范 CWE：{bad}"


def test_ledger_matches_case_artifacts():
    """台账必须与每份 case.json 的 verdict 一致。

    历史事故：CG-10 台账写 generation_unsupported，工件实际是 inconclusive。
    漂移会让答辩时的数字与证据对不上。
    """
    import json as _json
    led, _, _ = gen_docs.load()
    drift = []
    for r in led["rows"]:
        cid = r.get("case_id") or r.get("case_dir")
        case_p = None
        for d in (ROOT / "workspace").glob(f"{cid}*"):
            cand = d / "artifacts" / "report" / "case.json"
            if cand.exists():
                case_p = cand
                break
        if not case_p:
            continue
        actual = _json.loads(case_p.read_text(encoding="utf-8")).get("verdict")
        if r.get("verdict") != actual:
            drift.append(f"{cid}: 台账={r.get('verdict')} 工件={actual}")
    assert not drift, "台账与工件不一致，请重跑 python3 experiments/ledger.py: " + "; ".join(drift)


def test_ledger_covers_all_workspaces():
    """workspace 下有 case.json 的案例，台账里必须有。"""
    led, _, _ = gen_docs.load()
    ids = gen_docs.case_ids(led, gen_docs.load()[1])
    missing = []
    for d in sorted((ROOT / "workspace").iterdir()):
        if not d.is_dir():
            continue
        if re.match(r"^S\d", d.name):
            continue
        if (d / "artifacts" / "report" / "case.json").exists():
            short = "-".join(d.name.split("-")[:2])
            if short not in ids and d.name not in ids:
                missing.append(d.name)
    assert not missing, f"台账漏掉这些案例：{missing}（运行 ledger.py）"
