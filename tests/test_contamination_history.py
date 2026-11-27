"""污染披露的完备性：每例要么真干净，要么有 dev_history 交代；被污染者不得进盲测集。

背景：docs/CONTAMINATION.md 曾把 CG-04 / CG-09 / CG-12 列为「干净正式集」，
但它们在冻结之后被用于门禁修复、构造器开发、多轮复跑 —— 干净 ≠ 还能盲测。
本测试锁住三件事：
    1) 正式集每个案例都带 dev_history 字段（空也要有字段）；
    2) 有 dev_history 的案例，每条记录都能落到 purpose + 证据；
    3) dirty（答案回灌／用其驱动工具改动）的案例不得出现在盲测可用集里。
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import eval_set  # noqa: E402

MANIFEST = ROOT / "experiments" / "EVAL_SET.json"
DOC = ROOT / "docs" / "CONTAMINATION.md"
PROV = json.loads((ROOT / "experiments" / "PROVENANCE.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def doc() -> dict:
    assert MANIFEST.is_file(), "缺少 experiments/EVAL_SET.json"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def entries(doc) -> list[dict]:
    return doc["eval_set"]


@pytest.fixture(scope="module")
def md() -> str:
    return DOC.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# A. 字段完备：每例都有 dev_history
# --------------------------------------------------------------------------- #
def test_every_case_has_dev_history_field(entries):
    """字段必须存在（哪怕是空列表）—— 缺字段等于「没交代」，不是「没问题」。"""
    for e in entries:
        assert "dev_history" in e, f"{e['case_id']} 缺 dev_history 字段"
        assert isinstance(e["dev_history"], list)
        assert isinstance(e["dirty"], bool)
        assert isinstance(e["blind_usable"], bool)
        assert e["first_run_score_preserved"] is True, (
            f"{e['case_id']} 的冻结首跑成绩必须原样保留，不得因披露而改写"
        )


def test_each_history_record_is_explained(entries):
    """每条开发使用记录都要有用途 + 证据 + 三个布尔口径，不能只写「用过」。"""
    for e in entries:
        for h in e["dev_history"]:
            assert h.get("purpose"), f"{e['case_id']} 有记录没写用途"
            assert h.get("evidence"), f"{e['case_id']} 的记录缺证据"
            assert all(isinstance(h.get(k), bool) for k in
                       ("rerun", "constructor_rerun", "answer_feedback", "affects_blind_eval")), (
                f"{e['case_id']} 记录缺布尔口径：{h}"
            )
            assert h.get("phase") in {"pre_freeze", "post_freeze"}


def test_named_cases_are_disclosed(entries):
    """点名交代：CG-04 / CG-09 / CG-12 必须各有一条 dev_history（本轮的核心指控）。"""
    by_case = {e["case_id"]: e for e in entries}
    for cid in ("CG-04", "CG-09", "CG-12"):
        assert cid in by_case, f"正式集缺 {cid}"
        assert by_case[cid]["dev_history"], f"{cid} 有开发记录却写成无 dev_history"
        assert by_case[cid]["dirty"] is True, f"{cid} 参与过工具修复/复跑，必须标 dirty"


# --------------------------------------------------------------------------- #
# B. 盲测集：干净 + 未被调参用过
# --------------------------------------------------------------------------- #
def test_dirty_cases_excluded_from_blind_set(doc):
    blind = set(doc["blind_set"]["ids"])
    for e in doc["eval_set"]:
        if e["dirty"]:
            assert e["task_id"] not in blind, f"{e['case_id']} 已 dirty 却仍在盲测集"
            assert e["blind_usable"] is False
            assert e["blind_blockers"], f"{e['case_id']} 未说明为何不能盲测"


def test_contaminated_cases_never_in_blind_set(doc):
    """答案回灌（官方 PoC／参考答案／现成利用进工作区）→ 永不得进盲测集。"""
    blind = set(doc["blind_set"]["ids"])
    for e in doc["eval_set"]:
        if any(h["answer_feedback"] for h in e["dev_history"]):
            assert e["task_id"] not in blind, f"{e['case_id']} 有答案回灌却仍在盲测集"
            assert e["dirty"] is True


def test_blind_set_only_clean_and_untuned(doc):
    """盲测集只收：不在 DEV_SET、无 dev_history 阻断、且可跑。"""
    dev_ids = {r["task_id"] for r in PROV["rows"] if r["in_dev_set"]}
    by_tid = {e["task_id"]: e for e in doc["eval_set"]}
    for tid in doc["blind_set"]["ids"]:
        assert tid not in dev_ids, f"{tid} 在开发集里，不能进盲测集"
        e = by_tid[tid]
        assert e["dirty"] is False and e["runnable"] is True
        assert not any(h["answer_feedback"] or h["affects_blind_eval"] for h in e["dev_history"])


def test_blind_set_counts_consistent(doc):
    expect = [e["task_id"] for e in doc["eval_set"] if e["blind_usable"]]
    assert doc["blind_set"]["ids"] == expect
    assert doc["blind_set"]["count"] == len(expect) == doc["counts"]["blind"]
    assert doc["counts"]["dirty"] == sum(1 for e in doc["eval_set"] if e["dirty"])
    assert doc["counts"]["with_dev_history"] == sum(1 for e in doc["eval_set"] if e["dev_history"])


def test_manifest_matches_generator(doc):
    """清单里的 dev_history/dirty/blind 必须与生成器现算结果一致（防手改）。"""
    fresh = eval_set.build(probe_docker=False, generated_at="1970-01-01T00:00:00")
    fresh_by = {e["task_id"]: e for e in fresh["eval_set"]}
    for e in doc["eval_set"]:
        f = fresh_by[e["task_id"]]
        assert e["dirty"] == f["dirty"], e["case_id"]
        assert e["blind_usable"] == f["blind_usable"], e["case_id"]
        assert len(e["dev_history"]) == len(f["dev_history"]), e["case_id"]
    assert doc["blind_set"]["ids"] == fresh["blind_set"]["ids"]


# --------------------------------------------------------------------------- #
# C. 文档披露
# --------------------------------------------------------------------------- #
def test_doc_has_dev_history_section(md):
    assert "## 开发期使用披露（dev_history）" in md
    assert "| 案例 | dirty | 盲测可用 |" in md
    assert "**盲测可用" in md
    assert "首跑成绩" in md and "不改" in md, "文档必须写明冻结首跑成绩不被改写"


def test_doc_lists_every_case_with_history_or_none(md, entries):
    """每个正式集案例都要在 dev_history 表里出现：有记录的写用途，没记录的写「无」。"""
    for e in entries:
        assert f"| {e['case_id']} |" in md, f"文档漏了 {e['case_id']}"
        if not e["dev_history"]:
            assert f"| {e['case_id']} | 否 |" in md, (
                f"{e['case_id']} 无 dev_history，文档应显式写「无」而不是省略"
            )


def test_doc_discloses_constructor_rerun(md):
    """构造器复跑必须点名——这是「非自主能力」的核心证据。"""
    assert "构造器复跑" in md
    for cid in ("CG-12",):
        rows = [ln for ln in md.splitlines() if ln.startswith(f"| {cid} |")]
        assert any("构造器复跑" in ln for ln in rows), f"{cid} 的构造器复跑没披露"


def test_doc_discloses_answer_feedback(md):
    assert "答案回灌" in md
    rows = [ln for ln in md.splitlines() if ln.startswith("| EG-02 |") and "答案回灌" in ln]
    assert rows, "EG-02 的答案级回灌（poc.pdf 已落工作区）没披露"


def test_clean_claim_is_not_blind_claim(md):
    """「干净 7 例」必须与「盲测可用」分开表述，不能拿污染口径冒充盲测口径。"""
    # 干净例数会随新增案例增加，这里只要求「干净」与「盲测」分开表述
    assert "**干净 " in md and " 例**" in md, "缺「干净 N 例」表述"
    assert "**盲测可用" in md
    assert "不等于" in md and "盲测" in md


# --------------------------------------------------------------------------- #
# D. 不改成绩：case.json / LEDGER 口径不动
# --------------------------------------------------------------------------- #
def test_verdicts_untouched(entries):
    """披露不得顺手改成绩：正式集条目的 verdict 必须仍等于 case.json 里的值。"""
    for e in entries:
        cp = ROOT / "workspace" / e["dir"] / "artifacts" / "report" / "case.json"
        if not cp.is_file():
            continue
        case = json.loads(cp.read_text(encoding="utf-8"))
        assert e["verdict"] == case.get("verdict"), (
            f"{e['case_id']} verdict 被改：manifest={e['verdict']} case.json={case.get('verdict')}"
        )


def test_generator_never_writes_ledger_or_case_json():
    """披露只发生在 EVAL_SET/文档里：生成器不得触碰 LEDGER.json 与任何 case.json。"""
    src = (ROOT / "experiments" / "eval_set.py").read_text(encoding="utf-8")
    writes = [ln for ln in src.splitlines() if "write_text" in ln or ".write_bytes" in ln]
    assert writes, "生成器应当只写 EVAL_SET/文档"
    for forbidden in ("LEDGER", "case.json", "workspace"):
        assert not any(forbidden in ln for ln in writes), (
            f"eval_set.py 的写入语句里出现了 {forbidden}，披露不应改写成绩文件"
        )
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    assert led["totals"]["cases"] >= len(PROV["rows"]), "台账案例数不应少于 PROVENANCE 行数"
