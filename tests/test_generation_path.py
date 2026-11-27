"""生成路径标注自证：9 例全覆盖、逐行有真实证据路径、builder 不得标「自主」。

关键：测试会用文档声明的同一套优先级（模板哈希 → proposed_by=builder → llm+rounds → none）
从 workspace 的 verify/result.json 与 agent/templates/PROVENANCE.json 重算一遍，
再和 docs/GENERATION-PATH.md 的表格逐行比对 —— 文档写错就炸。
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

# 文档范围外新增的案例（各自有独立材料页），不计入这三份 9 例快照
POST_SCOPE = {"AR6", "AR7"}

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace"
DOC = ROOT / "docs" / "GENERATION-PATH.md"
TPL_PROV = ROOT / "agent" / "templates" / "PROVENANCE.json"

ROW = re.compile(r"^\|\s*((?:CG|VG)-\d+)\s*\|")


def _short(case_id: str, dir_name: str = "") -> str:
    """统一成 CG-xx / VG-xx 短号：S* 案例的 case.json.case_id 是目录名（S14-CG29-arvo-11011）。"""
    for src in (case_id or "", dir_name or ""):
        m = re.search(r"(CG|VG)-?([0-9]+)", src)
        if m:
            return f"{m.group(1)}-{int(m.group(2)):02d}"
    return case_id or dir_name


def _high_cases() -> list[dict]:
    out = []
    for d in sorted(WS.iterdir()):
        cp = d / "artifacts" / "report" / "case.json"
        if not cp.is_file():
            continue
        c = json.loads(cp.read_text(encoding="utf-8"))
        if (c.get("acceptance") or {}).get("high_severity_confirmed"):
            out.append({"case_id": c.get("case_id"), "dir": d.name,
                        "short": _short(c.get("case_id"), d.name)})
    return out


def _sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _template_for(case_id: str, dir_name: str = "") -> Path | None:
    """agent/templates/PROVENANCE.json 里 identical_to_poc 指向本案的模板文件。

    注意：该字段在模板清单里写的是**目录名**（CG-14-arvo-11253），不是短案例号（CG-14），
    两种写法都要认，否则会把模板案例误判成 none。
    """
    if not TPL_PROV.is_file():
        return None
    data = json.loads(TPL_PROV.read_text(encoding="utf-8"))
    for t in data.get("templates", []):
        owner = t.get("identical_to_poc") or ""
        if owner and (owner == case_id or owner == dir_name or owner.startswith(case_id + "-")):
            p = TPL_PROV.parent / t["file"]
            return p if p.is_file() else None
    return None


def classify(dir_name: str, case_id: str) -> tuple[str, list[str]]:

    """按文档声明的优先级重算 generation_path，返回 (路径, 证据片段列表)。"""
    ev: list[str] = []
    vr = WS / dir_name / "artifacts" / "verify" / "result.json"
    if not vr.is_file():
        ev.append(f"{vr.relative_to(ROOT)}: 不存在")
        return "none", ev

    v = json.loads(vr.read_text(encoding="utf-8"))
    cand = (v.get("candidates") or [{}])[0]
    proposed = cand.get("proposed_by")
    sha = (cand.get("input_sha256") or "")[:16]
    rounds = (v.get("model_loop") or {}).get("rounds") or []
    ev.append(f"{vr.relative_to(ROOT)}: proposed_by={proposed}, input_sha256={sha or None}, model_loop.rounds={len(rounds)}")

    tpl = _template_for(_short(case_id, dir_name), dir_name)
    if tpl is not None and sha and sha == _sha16(tpl):
        ev.append(f"{tpl.relative_to(ROOT)}: sha256 前缀 {sha} 与候选相同（模板＝构造器产物）")
        return "builder", ev
    if proposed == "builder":
        ev.append(f"evidence_source={cand.get('evidence_source')}")
        return "builder", ev
    if proposed == "llm" and rounds:
        ev.append(f"model_loop.rounds={[r.get('verdict') for r in rounds]}")
        return "model", ev
    return "none", ev


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.is_file(), "缺少 docs/GENERATION-PATH.md"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def rows(text) -> dict[str, str]:
    out = {}
    for ln in text.splitlines():
        m = ROW.match(ln)
        if m:
            out[m.group(1)] = ln
    return out


# --------------------------------------------------------------------------- #
# A. 覆盖
# --------------------------------------------------------------------------- #
def test_covers_nine_high_cases(rows):
    high = [h for h in _high_cases() if h["short"] not in POST_SCOPE]
    assert len(high) == 9, f"高危案例数为 {len(high)}：{[h['short'] for h in high]}"
    missing = [h["short"] for h in high if h["short"] not in rows]
    assert not missing, f"文档漏了：{missing}"


def test_each_row_names_workspace(rows):
    for cid, ln in rows.items():
        assert re.search(r"\|\s*(?:CG|VG|S\d+-)[\w\-]*\d{2,5}[\w\-]*\s*\|", ln) or "workspace/" in ln, (
            f"{cid} 行没写 workspace"
        )


# --------------------------------------------------------------------------- #
# B. 每行都有真实证据路径
# --------------------------------------------------------------------------- #
def test_every_row_has_resolvable_evidence(rows):
    for cid, ln in rows.items():
        paths = re.findall(r"(workspace/[A-Za-z0-9_./\-]+|agent/[A-Za-z0-9_./\-]+)", ln)
        assert paths, f"{cid} 行没有任何文件路径证据"
        missing = [p for p in paths if not (ROOT / p).exists()]
        assert not missing, f"{cid} 行引用了不存在的路径：{missing}"


# --------------------------------------------------------------------------- #
# C. 标注必须与数据重算一致
# --------------------------------------------------------------------------- #
def test_labels_match_recomputation(rows):
    high = {h["short"]: (h["case_id"], h["dir"]) for h in _high_cases()}
    for cid, ln in rows.items():
        real_case, real_dir = high[cid]
        expected, ev = classify(real_dir, real_case)
        cell = ln.split("|")[3]
        got = cell.strip().strip("*")
        if expected == "model":
            assert got.startswith("model"), f"{cid} 应为 model，文档写 {got}（证据：{ev}）"
        elif expected == "builder":
            assert got.startswith("builder"), f"{cid} 应为 builder，文档写 {got}（证据：{ev}）"
        else:
            assert got.startswith("none"), f"{cid} 应为 none，文档写 {got}（证据：{ev}）"


def test_cg14_template_case_is_builder(rows):
    """回归钉子：CG-14 的 input_sha256 与官方 PoC 模板同字节，绝不能被写成 rule/none。"""
    ln = rows["CG-14"]
    assert "builder" in ln.split("|")[3], "CG-14 被标成了非 builder"
    assert "cg14_ofctl.bin" in ln, "CG-14 行没写出模板证据"


def test_cg07_only_model_case(rows):
    model_rows = [cid for cid, ln in rows.items() if ln.split("|")[3].strip().strip("*").startswith("model")]
    assert model_rows == ["CG-07"], f"model 路径应只有 CG-07，实际：{model_rows}"


# --------------------------------------------------------------------------- #
# D. builder 不得标「自主」
# --------------------------------------------------------------------------- #
def test_builder_rows_never_claim_autonomy(rows):
    for cid, ln in rows.items():
        cells = [c.strip() for c in ln.split("|")]
        path, autonomy = cells[3], cells[5]
        if path.strip("*").startswith("builder") or path.startswith("none"):
            assert autonomy.strip().strip("*") in ("否", "否（工具能力）", "no"), (
                f"{cid} 是 {path}，却在自主列写了 {autonomy}"
            )


def test_summary_counts_match_rows(text, rows):
    def path_of(ln: str) -> str:
        return ln.split("|")[3].strip().strip("*").strip()

    builder = [c for c, ln in rows.items() if path_of(ln).startswith("builder")]
    model = [c for c, ln in rows.items() if path_of(ln).startswith("model")]
    none = [c for c, ln in rows.items() if path_of(ln).startswith("none")]
    assert len(builder) == 3, f"builder 行数 {len(builder)}：{builder}"
    assert len(model) == 1, f"model 行数 {len(model)}：{model}"
    assert len(none) == 5, f"none 行数 {len(none)}：{none}"
    assert "| builder | **3** |" in text, "汇总里的 builder 数量与逐行不一致"
    assert "| model | **1** |" in text, "汇总里的 model 数量与逐行不一致"
    assert "| none | **5** |" in text, "汇总里的 none 数量与逐行不一致"


def test_doc_states_autonomy_rate(text):
    assert "1/9" in text, "文档没有明确写出「模型自主 = 1/9」"
    assert "不得计入" in text or "不得写成" in text
