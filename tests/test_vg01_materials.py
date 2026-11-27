"""VG-01 材料补齐自证：PoC 实体可执行且哈希对得上、日志/报告/来源齐、MODEL-PARAMS 覆盖 9 例。

底线：补齐只补产物，不改分数。任何判定字段（verdict / acceptance / severity）被改动都要在这里炸掉。
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

# 文档范围外新增的案例（各自有独立材料页），不计入这三份 9 例快照
POST_SCOPE = {"AR6", "AR7"}

ROOT = Path(__file__).resolve().parent.parent
WS = ROOT / "workspace"
VG = WS / "VG-01-nltk-wordnet"
CASE = VG / "artifacts" / "report" / "case.json"
POC = VG / "poc" / "request.sh"
LOGS = {"vuln": VG / "logs" / "vg01-vuln.log", "patched": VG / "logs" / "vg01-patched.log"}
REPORT = VG / "report.md"
SOURCE = VG / "SOURCE.md"
MODEL_PARAMS = ROOT / "docs" / "MODEL-PARAMS.md"
MATERIALS = ROOT / "docs" / "MATERIALS.md"


def _case() -> dict:
    return json.loads(CASE.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# 1. PoC 实体
# --------------------------------------------------------------------------- #
def test_poc_exists_and_is_executable():
    assert POC.is_file(), "缺少 poc/request.sh"
    assert POC.stat().st_mode & 0o111, "poc/request.sh 没有执行位"
    text = POC.read_text(encoding="utf-8")
    assert "SHUTDOWN%20THE%20SERVER" in text, "PoC 里没有真正的 shutdown 请求路径"
    assert "X-Shutdown-Token" in text, "PoC 缺少补丁侧对照所需的 token 分支"


def test_poc_shell_syntax_ok():
    """sh -n 只做语法检查，不联网、不起服务。"""
    cp = subprocess.run(["sh", "-n", str(POC)], capture_output=True, text=True, timeout=30)
    assert cp.returncode == 0, f"request.sh 语法错误：{cp.stderr}"


def test_case_poc_points_to_real_artifact():
    poc = _case()["poc"]
    assert poc["path"] == "poc/request.sh", f"case.json.poc.path 仍指向 {poc['path']}"
    assert re.fullmatch(r"[0-9a-f]{64}", poc["sha256"] or ""), "case.json.poc.sha256 为空或格式不对"
    assert poc["sha256"] == _sha(POC), "case.json.poc.sha256 与磁盘文件不一致"
    assert poc["size"] == POC.stat().st_size, "case.json.poc.size 与磁盘文件不一致"
    assert poc["size"] > 0


# --------------------------------------------------------------------------- #
# 2. 日志（实测结果转写，必须自报性质）
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("side", ["vuln", "patched"])
def test_logs_exist_and_declare_transcription(side):
    p = LOGS[side]
    assert p.is_file(), f"缺少 {p.relative_to(ROOT)}"
    text = p.read_text(encoding="utf-8")
    assert "转写" in text, f"{p.name} 没写明是实测结果转写（防止被当成原始 stdout）"
    assert "experiments/vg01/RESULT.json" in text, f"{p.name} 没写来源"


def test_vuln_log_records_unauthenticated_shutdown():
    text = LOGS["vuln"].read_text(encoding="utf-8")
    for needle in ("index_status=200", "shutdown_result=RemoteDisconnected", "alive_after_shutdown=false"):
        assert needle in text, f"vg01-vuln.log 缺实测值 {needle}"


def test_patched_log_records_blocked_shutdown():
    text = LOGS["patched"].read_text(encoding="utf-8")
    for needle in ("index_status=200", "shutdown_result=HTTPError", "alive_after_shutdown=true"):
        assert needle in text, f"vg01-patched.log 缺实测值 {needle}"


def test_logs_match_result_json():
    """日志里的三个判定值必须与实测量测原件一致，不许手改口径。"""
    res = json.loads((VG / "artifacts" / "RESULT.json").read_text(encoding="utf-8"))
    for side in ("vuln", "patched"):
        block = res[side]
        text = LOGS[side].read_text(encoding="utf-8")
        assert f"index_status={block['index_status']}" in text
        assert f"shutdown_result={block['shutdown_result']}" in text
        assert f"alive_after_shutdown={str(block['alive_after_shutdown']).lower()}" in text


# --------------------------------------------------------------------------- #
# 3. 报告与来源
# --------------------------------------------------------------------------- #
def test_report_has_required_sections():
    assert REPORT.is_file(), "缺少 report.md"
    text = REPORT.read_text(encoding="utf-8")
    for sec in ("项目与版本", "CWE 与危害", "请求（PoC）", "补丁对照", "局限"):
        assert sec in text, f"report.md 缺小节：{sec}"
    assert "40d0bc1d" in text and "CWE-306" in text
    assert "poc/request.sh" in text


def test_source_anchors_upstream_commit():
    assert SOURCE.is_file(), "缺少 SOURCE.md"
    text = SOURCE.read_text(encoding="utf-8")
    assert "https://github.com/nltk/nltk" in text, "SOURCE.md 缺 repo URL"
    assert "40d0bc1d" in text, "SOURCE.md 缺 commit"
    assert "nltk/app/wordnet_app.py:87" in text, "SOURCE.md 缺关键文件行号"


# --------------------------------------------------------------------------- #
# 4. MODEL-PARAMS 覆盖 9 例
# --------------------------------------------------------------------------- #
def _high_cases() -> list[str]:
    out = []
    for d in sorted(WS.iterdir()):
        cp = d / "artifacts" / "report" / "case.json"
        if not cp.is_file():
            continue
        c = json.loads(cp.read_text(encoding="utf-8"))
        if (c.get("acceptance") or {}).get("high_severity_confirmed"):
            out.append(c.get("case_id"))
    return out


def test_model_params_exists_and_has_columns():
    assert MODEL_PARAMS.is_file(), "缺少 docs/MODEL-PARAMS.md"
    text = MODEL_PARAMS.read_text(encoding="utf-8")
    for col in ("model", "locate prompt_version", "verify prompt_version", "report prompt_version", "来源"):
        assert col in text, f"MODEL-PARAMS 缺列：{col}"


def test_model_params_covers_nine_high_cases():
    text = MODEL_PARAMS.read_text(encoding="utf-8")
    high = [h for h in _high_cases() if h not in POST_SCOPE]
    assert len(high) == 9, f"高危案例数为 {len(high)}：{high}"
    missing = [c for c in high if c not in text]
    assert not missing, f"MODEL-PARAMS 漏了：{missing}"
    rows = [ln for ln in text.splitlines() if ln.startswith("| ") and "deepseek-flash" in ln]
    assert len(rows) >= 9, f"逐例行只有 {len(rows)} 行，应为 9"
    assert "0/9" in text, "必须如实写出 verify 提示词/采样参数的 0/9 缺口"


# --------------------------------------------------------------------------- #
# 5. MATERIALS 的 VG-01 行已更新
# --------------------------------------------------------------------------- #
def test_materials_vg01_row_updated():
    text = MATERIALS.read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines() if ln.startswith("| VG-01 |")]
    assert rows, "MATERIALS 没有 VG-01 行"
    row = rows[0]
    assert "poc/request.sh" in row, "VG-01 行仍没提真实 PoC 实体"
    assert "vg01-vuln.log" in row, "VG-01 行仍没提日志"
    assert "**缺**（无 logs 目录）" not in row, "VG-01 行还是旧的缺口描述"


# --------------------------------------------------------------------------- #
# 6. 分数不许动
# --------------------------------------------------------------------------- #
def test_scores_untouched():
    c = _case()
    assert c["verdict"] == "pass"
    acc = c["acceptance"]
    assert acc["local_verified"] is True
    assert acc["high_severity_confirmed"] is True
    assert c["severity"]["state"] == "assessed"
    assert c["severity"]["is_high_severity"] is True
    assert c["cwe"] == "CWE-306"
    # 只有 poc 字段允许被本次替换
    assert set(c["poc"]) == {"path", "sha256", "size"}
