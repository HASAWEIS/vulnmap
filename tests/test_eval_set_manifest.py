"""EVAL_SET manifest 自证：repo_sha256 不许静默 null，有归档必须等于 sha256sum。

背景（历史事故）：CG-09 / CG-12 两个案例的 `workspace/<dir>/repo-vul.tar.gz`
没落地时，`repo_sha256` 直接写成 null 却没有进 `unresolved`，
导致"清单已冻结"的说法无法复算 —— 所有 null 都必须带显式 unresolved 标记，
所有非 null 都必须能被本地归档复算出来。
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "experiments"))

import pytest  # noqa: E402

import eval_set  # noqa: E402

MANIFEST = ROOT / "experiments" / "EVAL_SET.json"
WS = ROOT / "workspace"

# 本轮补齐归档的两个案例：必须已解析
RESOLVED_TARGETS = {"CG-09": "arvo:53666", "CG-12": "arvo:11081"}


def _manifest() -> dict:
    assert MANIFEST.is_file(), "缺少 experiments/EVAL_SET.json"
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _archive(entry: dict) -> Path:
    return WS / entry["dir"] / "repo-vul.tar.gz"


@pytest.fixture(scope="module")
def doc() -> dict:
    return _manifest()


# --------------------------------------------------------------------------- #
# A. null 必须带 unresolved 标记
# --------------------------------------------------------------------------- #
def test_null_repo_sha256_must_be_flagged_unresolved(doc):
    """repo_sha256 为 null 的条目必须在 unresolved 里点名，不能静默留空。"""
    for e in doc["eval_set"]:
        if e["repo_sha256"] is None:
            assert "repo_sha256" in e["unresolved"], (
                f"{e['case_id']} repo_sha256=null 却未标记 unresolved"
            )
            assert e["repo_sha256_source"] != "workspace/repo-vul.tar.gz", (
                f"{e['case_id']} 声称取自工作区归档，但归档不存在（源字段与事实矛盾）"
            )


def test_non_null_repo_sha256_has_trusted_source(doc):
    """非 null 的 repo_sha256 必须说明来源；取自 ARCHIVE.json 声明值的必须标 unverified。"""
    for e in doc["eval_set"]:
        if e["repo_sha256"] is None:
            continue
        assert isinstance(e["repo_sha256"], str) and len(e["repo_sha256"]) == 64, e["case_id"]
        int(e["repo_sha256"], 16)  # 必须是十六进制
        assert e["repo_sha256_source"], f"{e['case_id']} 缺 repo_sha256_source"
        if not _archive(e).is_file():
            assert "repo_sha256:unverified" in e["unresolved"], (
                f"{e['case_id']} 归档缺失却复用了声明值，必须标 repo_sha256:unverified"
            )


# --------------------------------------------------------------------------- #
# B. 有归档的必须等于 sha256sum
# --------------------------------------------------------------------------- #
def test_sha256_matches_archive_on_disk(doc):
    """工作区有 repo-vul.tar.gz 的条目，repo_sha256 必须等于逐字节 sha256。"""
    checked = 0
    for e in doc["eval_set"]:
        ap = _archive(e)
        if not ap.is_file():
            continue
        checked += 1
        actual = _sha256(ap)
        assert e["repo_sha256"] == actual, (
            f"{e['case_id']} repo_sha256 与磁盘归档不一致："
            f"manifest={e['repo_sha256']} disk={actual}"
        )
        assert e["repo_sha256_source"] == "workspace/repo-vul.tar.gz", e["case_id"]
        assert "repo_sha256" not in e["unresolved"], e["case_id"]
    assert checked >= 5, f"只复算了 {checked} 个归档，期望 >= 5"


def test_shipped_archives_are_real_gzip(checked_archives):
    """新落地的归档必须 >1MB 且 gzip 头合法（挡 404 页面 / 空文件进门）。"""
    for path in checked_archives:
        size = path.stat().st_size
        assert size > 1 << 20, f"{path.name} 只有 {size} 字节，不是完整归档"
        with path.open("rb") as fh:
            assert fh.read(2) == b"\x1f\x8b", f"{path} 不是 gzip"


@pytest.fixture(scope="module")
def checked_archives(doc) -> list:
    return [ap for ap in (_archive(e) for e in doc["eval_set"]) if ap.is_file()]


# --------------------------------------------------------------------------- #
# C. CG-09 / CG-12 必须已解析
# --------------------------------------------------------------------------- #
def test_cg09_cg12_repo_sha256_resolved(doc):
    """本轮补齐的两个案例：repo_sha256 必须非 null、等于磁盘归档、无 unresolved 残留。"""
    by_case = {e["case_id"]: e for e in doc["eval_set"]}
    for case_id, task_id in RESOLVED_TARGETS.items():
        assert case_id in by_case, f"正式集缺 {case_id}"
        e = by_case[case_id]
        assert e["task_id"] == task_id
        assert e["repo_sha256"] is not None, f"{case_id} repo_sha256 仍为 null"
        assert len(e["repo_sha256"]) == 64
        assert "repo_sha256" not in e["unresolved"], f"{case_id} 仍标 repo_sha256 unresolved"
        ap = _archive(e)
        assert ap.is_file(), f"{case_id} 缺 {ap.relative_to(ROOT)}"
        assert e["repo_sha256"] == _sha256(ap), f"{case_id} 哈希与归档不符"


# --------------------------------------------------------------------------- #
# D. 清单与生成器一致（防手改）
# --------------------------------------------------------------------------- #
def test_manifest_matches_generator_repo_hashes(doc):
    """EVAL_SET.json 的 repo_sha256 必须等于 eval_set.py 现在重算的结果（不探 docker）。"""
    fresh = eval_set.build(probe_docker=False, generated_at="1970-01-01T00:00:00")
    fresh_by = {e["task_id"]: e["repo_sha256"] for e in fresh["eval_set"]}
    disk_by = {e["task_id"]: e["repo_sha256"] for e in doc["eval_set"]}
    assert fresh_by == disk_by, "repo_sha256 与生成器重算结果不一致，请重跑 experiments/eval_set.py"


def test_manifest_schema_and_counts(doc):
    assert doc["schema"] == eval_set.SCHEMA
    assert doc["counts"]["eval"] == len(doc["eval_set"])
    resolved = sum(1 for e in doc["eval_set"] if e["repo_sha256"])
    assert resolved >= 5, f"已解析 repo_sha256 仅 {resolved} 条"
    # caveats 不得再把已补齐的归档列为缺失
    missing = [e["case_id"] for e in doc["eval_set"] if "repo_sha256" in e["unresolved"]]
    joined = "\n".join(doc["caveats"])
    for cid in set(RESOLVED_TARGETS) - set(missing):
        assert f"{cid}" not in joined, f"caveats 仍把 {cid} 当成缺归档"
