r"""V3 P1 验收：V3-003（假设→seed 接线）+ V3-004（持久语料与构建身份）。

口径逐条对应需求：

1. `_seed_pool(index, root, fmt, hypotheses)` 显式吃假设：按 `site_id` 匹配后
   调 `propose_seeds(..., hypothesis=hyp)`，每条 seed 记
   `hypothesis_id / site_id / source`；**不同假设产出的种子不同**；
2. 匹配失败有显式 `reason` 并回退规则种子（仍绑在该假设 id 上），
   且补足阶段遍历**全部**调用点（不是静默只取前 3 个）；
3. 种子写入 corpus 时写 manifest（sha256/hypothesis_id/site_id/source），
   可由内容哈希反查父假设；
4. corpus 按 task/campaign 落盘、跨轮复用；`corpus_version` 递增、
   `corpus_hash` 随成员变化；
5. 构建身份（binary sha256 / build spec）变化 → 标记 stale、归档重建，
   两代语料不混在同一个 active 目录；
6. fuzz 执行器真的用持久 corpus，结果带 `build_id` 与
   `corpus.before / corpus.after`，第二轮不丢第一轮语料。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive import corpus as corpus_mod
from agent.platform.adaptive.corpus import (CorpusError, CorpusStore,
                                            build_identity)
from agent.platform.executors import fuzz as fuzz_mod
from agent.platform.executors.fuzz import _seed_pool

FIXTURE = ROOT / "fixtures" / "discovery"


class _Index:
    """最小 ProgramIndex 替身：只要 root/formats/call_sites 三个字段。"""

    def __init__(self, sites, *, root: str = ""):
        self.root = root
        self.formats = ["json"]
        self.call_sites = sites


def _site(site_id: str, category: str = "copy") -> dict:
    return {"id": site_id, "file": "a.c", "line": 10,
            "function": "parse", "callee": "memcpy",
            "category": category, "args": "dst,len"}


def _hyp(hid: str, site_id: str, text: str, window: str = "") -> dict:
    return {"id": hid, "site_id": site_id, "hypothesis": text,
            "window": window, "statement": text}


# ------------------------------------------------------------------ V3-003
def test_different_hypotheses_produce_different_seeds():
    site = _site("a.c:10:memcpy")
    index = _Index([site])
    long_hyp = _hyp("H1", "a.c:10:memcpy", "长度字段 len 被直接用于分配")
    comment_hyp = _hyp("H2", "a.c:10:memcpy", "注释 comment 未闭合导致截断")

    pool_a = _seed_pool(index, None, "json", [long_hyp])
    pool_b = _seed_pool(index, None, "json", [comment_hyp])
    seeds_a = {r["sha256"] for r in pool_a["records"]}
    seeds_b = {r["sha256"] for r in pool_b["records"]}
    assert seeds_a and seeds_b
    assert seeds_a != seeds_b
    assert (seeds_a - seeds_b) and (seeds_b - seeds_a)

    # 每条 seed 都能指回父假设与调用点
    for record in pool_a["records"]:
        assert record["hypothesis_id"] == "H1"
        assert record["site_id"] == "a.c:10:memcpy"
        assert record["source"] == "hypothesis:H1"
        assert record["sha256"] == corpus_mod._sha256(record["data"])


def test_unmatched_hypothesis_has_explicit_reason_and_rule_fallback():
    index = _Index([_site("a.c:10:memcpy")])
    anchored = _hyp("H1", "", "锚点假设：上游分支缺少校验")
    wrong_site = _hyp("H2", "nope.c:9:handler", "数组 array 越界")

    pool = _seed_pool(index, None, "json", [anchored, wrong_site])
    report = pool["report"]
    reasons = {row["hypothesis_id"]: row for row in report["unmatched"]}
    assert set(reasons) == {"H1", "H2"}
    assert "empty" in reasons["H1"]["reason"]
    assert "not found" in reasons["H2"]["reason"]
    # 回退到规则种子，但仍记录归属（不是静默丢弃）
    h2_records = [r for r in pool["records"] if r["hypothesis_id"] == "H2"]
    assert h2_records
    assert all(r["origin"] == "rule_fallback" for r in h2_records)


def test_seed_pool_walks_all_sites_and_reports_cap(monkeypatch):
    index = _Index([_site(f"a.c:{n}:memcpy") for n in range(1, 9)])
    monkeypatch.setattr(fuzz_mod, "MAX_SEEDS", 4)

    pool = _seed_pool(index, None, "json", [_hyp("H1", "a.c:1:memcpy",
                                                "长度 len 溢出")])
    report = pool["report"]
    assert report["sites_total"] == 8          # 全部调用点都参与，不是前 3 个
    assert report["capped"] is True
    assert len(pool["records"]) <= 4
    # 补不进去的点逐个记账，绝不静默
    assert report["sites_skipped_cap"]
    assert set(report["sites_used"]) | set(report["sites_skipped_cap"])
    assert len(report["sites_used"]) + len(report["sites_skipped_cap"]) >= 8


# ------------------------------------------------------------------ V3-004
def _identity(tag: str, *, source: str = "a.c") -> dict:
    return build_identity({"sources": [source], "mode": "main",
                           "cflags": ["-O1"]},
                          binary_sha256=(tag * 64)[:64], harness="path_fuzz")


def test_corpus_manifest_records_lineage(tmp_path):
    store = CorpusStore(tmp_path / "corpus", task_id="t-lineage",
                        campaign="cybergym")
    store.begin(_identity("a"))
    store.add(b"seed-alpha", hypothesis_id="H1", site_id="a.c:10",
              source="hypothesis:H1", origin="hypothesis", format="json")
    store.add(b"seed-beta", hypothesis_id="H2", site_id="",
              source="rule:generic", origin="rule_fallback", format="json")
    snap = store.finalize()

    manifest = json.loads((tmp_path / "corpus" / "cybergym" / "t-lineage"
                           / "manifest.json").read_text(encoding="utf-8"))
    digest = corpus_mod._sha256(b"seed-alpha")
    entry = manifest["members"][digest]
    assert entry["hypothesis_id"] == "H1"
    assert entry["site_id"] == "a.c:10"
    assert entry["source"] == "hypothesis:H1"
    assert entry["size"] == len(b"seed-alpha")
    # 反查：内容哈希 → 父假设；假设 → 成员
    assert store.resolve(digest)["hypothesis_id"] == "H1"
    assert [e["sha256"] for e in store.by_hypothesis("H1")] == [digest]
    assert snap["members"] == 2
    assert snap["corpus_version"] == 1
    assert snap["corpus_hash"]
    # active 目录里是 fuzz 真正能读到的文件
    assert (store.active_dir / f"seed-{digest[:16]}").read_bytes() == b"seed-alpha"


def test_corpus_reused_across_rounds_and_hash_tracks_members(tmp_path):
    identity = _identity("a")
    first = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    state = first.begin(identity)
    assert state["status"] == "fresh"
    first.add(b"seed-alpha", hypothesis_id="H1", source="hypothesis:H1",
              origin="hypothesis")
    before = first.finalize()
    # 模拟 fuzz 自己写进 active 的新语料
    (first.active_dir / "seed-fuzz0001").write_bytes(b"fuzz-discovered")
    first.discover()
    after = first.finalize()
    assert after["members"] == 2
    assert after["corpus_hash"] != before["corpus_hash"]

    # 第二轮（同 build）：复用同一语料，不丢任何东西
    second = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    state2 = second.begin(identity)
    assert state2["status"] == "reused"
    assert state2["stale"] is False
    assert state2["generation"] == 1
    assert state2["corpus_before"]["members"] == 2
    assert (second.active_dir / "seed-fuzz0001").read_bytes() == b"fuzz-discovered"
    # campaign/task 维度隔离：换 task 不共享
    other = CorpusStore(tmp_path / "corpus", task_id="t2", campaign="c1")
    assert other.begin(identity)["status"] == "fresh"
    assert other.begin(identity)["corpus_before"]["members"] == 0


def test_build_change_marks_stale_and_rebuilds_without_mixing(tmp_path):
    old = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    old.begin(_identity("a"))
    old.add(b"seed-old", hypothesis_id="H1", source="hypothesis:H1",
            origin="hypothesis")
    (old.active_dir / "seed-fuzzold").write_bytes(b"old-build-corpus")
    old.discover()
    old_snap = old.finalize()

    new_identity = _identity("b")
    assert new_identity["build_id"] != _identity("a")["build_id"]
    fresh = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    state = fresh.begin(new_identity)

    assert state["status"] == "rebuilt"
    assert state["stale"] is True
    assert any("binary sha256 changed" in r for r in state["reasons"])
    assert state["generation"] == old_snap["corpus_version"] + 1
    # 新 active 里没有旧代语料（不混用），旧代整体归档且原件仍在
    assert list(fresh.active_dir.iterdir()) == []
    archived = list((tmp_path / "corpus" / "c1" / "t1" / "history").iterdir())
    assert archived
    assert (archived[0] / "active" / "seed-fuzzold").read_bytes() == b"old-build-corpus"
    assert (archived[0] / "manifest.json").is_file()
    # entries（内容寻址原件）只增不删
    digests = {p.name for p in fresh.entries_dir.iterdir()}
    assert corpus_mod._sha256(b"seed-old") in digests
    # 同一身份再来一轮：不再重复重建
    again = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    assert again.begin(new_identity)["status"] == "reused"


def test_corpus_manifest_corruption_fails_closed(tmp_path):
    store = CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1")
    store.begin(_identity("a"))
    store.finalize()
    store.manifest_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(CorpusError):
        CorpusStore(tmp_path / "corpus", task_id="t1", campaign="c1").begin(
            _identity("b"))


# ------------------------------------------------------- 执行器集成（真跑接线）
def _plan() -> dict:
    return {
        "benchmark": "target_yaml",
        "target": str(FIXTURE),
        "inputs": {"target": str(FIXTURE),
                   "target_yaml": str(FIXTURE / "target.yaml")},
        "budget": {"seconds": 0.01, "workers": 1, "timeout": 1.0},
    }


def _install_fakes(monkeypatch, state: dict):
    def fake_build(**spec):
        workdir = Path(spec["workdir"])
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / "fuzz_target"
        out.write_bytes(b"fake-binary")
        return {"binary": str(out), "cmd": ["cc"], "harness": None,
                "sha256": state["sha256"]}

    def fake_run_parallel(binary, corpus_dir, crash_dir, stats_dir, **kw):
        stats_dir = Path(stats_dir)
        stats_dir.mkdir(parents=True, exist_ok=True)
        (stats_dir / "w0.json").write_text(json.dumps({
            "execs": 5, "crashes": 0, "timeouts": 0, "new_coverage": 3,
            "setup_errors": 0, "corpus": 1}) + "\n")
        Path(corpus_dir).mkdir(parents=True, exist_ok=True)
        if state.get("emit"):
            (Path(corpus_dir) / f"seed-{state['emit']}").write_bytes(
                f"fuzz-round-{state['emit']}".encode())
            state["emit"] = ""
        return {"execs": 5, "crashes": 0, "timeouts": 0,
                "new_coverage_bits": 3, "setup_errors": 0, "setup_error": None,
                "workers": 1, "first_crash_seconds": None, "crash_files": 0,
                "corpus_files": 1, "per_worker": []}

    def fake_coverage(binary, corpus_dir, ledger, root, workdir, **kw):
        return {"planned": 1, "covered": 1, "uncovered": 0,
                "status": "complete", "pcs": 1}

    monkeypatch.setattr(fuzz_mod.covfuzz, "build", fake_build)
    monkeypatch.setattr(fuzz_mod.covfuzz, "run_parallel", fake_run_parallel)
    monkeypatch.setattr(fuzz_mod.covfuzz, "attribute_coverage", fake_coverage)


def _run_execute(workdir: Path, hypotheses: list[dict]) -> dict:
    index = _Index([_site("a.c:10:memcpy"), _site("a.c:20:printf")])
    return fuzz_mod.execute(_plan(), index, hypotheses, workdir=workdir,
                            seconds=0.01, workers=1, timeout=1.0)


def test_execute_uses_persistent_corpus_and_records_build_id(tmp_path,
                                                             monkeypatch):
    state = {"sha256": "a" * 64, "emit": "roundtrip1"}
    _install_fakes(monkeypatch, state)
    hypotheses = [_hyp("H1", "a.c:10:memcpy", "长度 len 与分配不一致",
                       "memcpy(dst, src, len)")]

    work = tmp_path / "work" / "task-v3"
    first = _run_execute(work, hypotheses)
    assert first["ok"] is True
    assert first["build_id"] == first["corpus"]["after"]["build_id"]
    assert first["corpus"]["status"] == "fresh"
    assert first["corpus"]["before"]["members"] == 0
    assert first["corpus"]["after"]["members"] >= 1
    assert first["corpus"]["discovered"] == 1
    # 种子归属可反查
    lineage = {row["sha256"]: row for row in first["corpus"]["lineage"]}
    hyp_seed = corpus_mod._sha256(
        [r for r in _seed_pool(_Index([_site("a.c:10:memcpy")]), None, "json",
                              hypotheses)["records"]
         if r["hypothesis_id"] == "H1"][0]["data"])
    assert lineage[hyp_seed]["hypothesis_id"] == "H1"
    assert first["seed_pool"]["matched"][0]["hypothesis_id"] == "H1"
    # active 目录里同时有假设种子与 fuzz 新语料
    active = Path(first["corpus"]["active"])
    assert (active / "seed-roundtrip1").exists()

    # 第二轮（同构建身份）：复用，且第一轮 fuzz 语料没被 _fresh_dir 扔掉
    state["emit"] = ""
    second = _run_execute(work, hypotheses)
    assert second["corpus"]["status"] == "reused"
    assert second["corpus"]["stale"] is False
    assert second["corpus"]["generation"] == first["corpus"]["generation"]
    assert second["corpus"]["before"]["members"] == first["corpus"]["after"][
        "members"]
    assert (Path(second["corpus"]["active"]) / "seed-roundtrip1").exists()

    # 第三轮：构建身份变化 → stale 重建，旧语料归档而不是混用
    state["sha256"] = "b" * 64
    third = _run_execute(work, hypotheses)
    assert third["corpus"]["status"] == "rebuilt"
    assert third["corpus"]["stale"] is True
    assert any("binary sha256 changed" in r
               for r in third["corpus"]["stale_reasons"])
    assert not (Path(third["corpus"]["active"]) / "seed-roundtrip1").exists()
    assert third["corpus"]["before"]["members"] == 0
    # 旧代规模与哈希有据可查（归档 + previous 快照）
    assert third["corpus"]["previous"]["members"] == second["corpus"]["after"][
        "members"]

    # 构建身份也进了结果 build 块（可追溯）
    assert third["build"]["identity"]["binary_sha256"] == "b" * 64
