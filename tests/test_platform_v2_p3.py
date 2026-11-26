"""V2 P3 验收：独立验证 / 复核 / Case Pack / 状态机。

口径（与需求逐条对应）：

1. **CyberGym 双端**：同一输入的 vuln 崩 / fix 干净才算 `verified`，判据 kind
   `vuln_fix_diff`，要求双端；缺一侧即 `needs_evidence`，fix 也崩即 `no_repro`；
2. **ExploitGym flag（EG-02 类）**：官方入口取到 flag 即成立，**不要求** fix 端；
   同一份证据喂给 CyberGym 双端规则必然 `local_dual_run_failed`，
   但这里不得被误杀；
3. **VulnGym 行为差分**：基线/修补两侧可观测且方向符合预期才算 `verified`，
   两侧一致即负结果；
4. **错误口径拒绝**：给 CyberGym 递 flag、给 ExploitGym 递 vul/fix 一律
   `VerificationError`，且不留下半成品记录；口径缺失（target_yaml）落 `rejected`；
   Reviewer 不得把未通过的验证升格为 accept；
5. **CasePack**：task/state/events/candidates/verifications/reviews/manifest/report
   齐备，内容哈希可复算并写入 `reports` 表；

另有两条全局硬约束：
- 任何 P3 产物都不得出现 `confirmed`（确认结论只能由“验证 + 复核”共同支撑）；
- 状态机只走 CANDIDATE→VERIFYING→REVIEW→REPORTED/CLOSED，
  失败落 REJECTED/NO_REPRO/NEEDS_EVIDENCE。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from agent import benchmark_policy
from agent.platform import (EventBus, EvidenceStore, PlatformStore, TaskSpec,
                            build_casepack, run_review, run_verification)
from agent.platform.candidates import from_crash, sha256_hex
from agent.platform.casepack import FILES, SELF_FILE, CasePackError
from agent.platform.review import CHECKS, ReviewError, derive_verdict
from agent.platform.store import SCHEMA, SCHEMA_P1, SCHEMA_P2
from agent.platform.verify import (BENCHMARK_KIND, VerificationError,
                                   evaluate, normalize_spec)

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "platform.py"

CANDIDATE_CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES",
                   "PLANNED", "RUNNING", "CANDIDATE")


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), *args],
                          capture_output=True, text=True)


def _task(tmp_path, *, task_id="p3", benchmark="cybergym", db_name="p.db",
          target=None):
    """把任务推进到 CANDIDATE（用状态机显式迁移，不跑 fuzz）。"""
    store = PlatformStore(tmp_path / db_name)
    bus = EventBus(store)
    spec = TaskSpec(task_id=task_id, benchmark=benchmark,
                    target=target or str(tmp_path / "ws"))
    store.create_task(spec)
    bus.emit(task_id, "task.created", payload=spec.to_dict())
    for state in CANDIDATE_CHAIN:
        store.transition(task_id, state, reason="p3 fixture")
    return store, bus


def _candidate(store, task_id, *, data=b"CRASH" + b"A" * 48, candidate_id="C1",
               crash=True):
    """写入一条 Candidate 及其输入/日志证据，返回 (candidate, shas)。"""
    log = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
           "#0 0x1 in parse_record a.c:16\n")
    evidence = EvidenceStore(store, store.path.parent / "evidence")
    input_ref = evidence.put_bytes(task_id, "crash_input", data,
                                   source_stage="RUNNING")
    log_ref = evidence.put_bytes(task_id, "crash_log", log.encode("utf-8"),
                                 source_stage="RUNNING")
    parsed = {"crash_type": "heap-buffer-overflow", "access": "WRITE",
              "function": "parse_record", "file": "a.c", "line": 16,
              "frames": [{"func": "parse_record", "file": "a.c", "line": 16}]}
    cand = from_crash(
        {"input_bytes": data, "input_sha256": sha256_hex(data), "log": log,
         "stack_hash": "0123456789abcdef", "crash_type": "heap-buffer-overflow",
         "parsed": parsed, "diagnostic_valid": crash},
        task_id=task_id, candidate_id=candidate_id, exec_id="exec-p3",
        plan_sha256="p" * 64, build_sha256="b" * 64)
    cand.detail["input_evidence_sha256"] = input_ref.sha256
    cand.detail["log_evidence_sha256"] = log_ref.sha256
    cand.evidence_sha256 = log_ref.sha256
    store.save_candidate(cand)
    return cand, {"input": input_ref.sha256, "log": log_ref.sha256}


def _files(tmp_path, name="vul.log", text="AddressSanitizer: heap-buffer-overflow\n"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _hashes_and_kinds(store, task_id):
    return {row["sha256"]: row for row in store.list_evidence(task_id)}


def _assert_no_confirmed(text: str) -> None:
    assert "confirmed" not in text.lower()


# ------------------------------------------------------------------ CyberGym
def test_cybergym_dual_end_verification(tmp_path):
    store, bus = _task(tmp_path, task_id="cg-p3")
    cand, shas = _candidate(store, "cg-p3")
    vul_log = _files(tmp_path, "vul.log")
    fix_log = _files(tmp_path, "fix.log", "program exited cleanly\n")

    out = run_verification("cg-p3", store, bus, spec={
        "input": {"sha256": cand.input_sha256},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })

    assert out["verified"] is True
    assert out["kind"] == "vuln_fix_diff"
    assert out["dual_required"] is True
    assert out["status"] == "verified" and out["blockers"] == []
    assert out["checks"]["vul_crashed"] and out["checks"]["fix_clean"]
    assert out["checks"]["same_input"] is True
    assert out["state"] == "VERIFYING"

    # 表 + 事件
    row = store.get_verification("cg-p3", out["verification_id"])
    assert row is not None
    assert row["verified"] is True and row["status"] == "verified"
    assert row["candidate_id"] == "C1"
    assert row["kind"] == "vuln_fix_diff" == BENCHMARK_KIND["cybergym"]
    assert row["detail"]["dual_required"] is True
    assert row["detail"]["policy"]["kind"] == "vuln_fix_diff"
    types = [e["event_type"] for e in bus.list("cg-p3")]
    assert "verification.recorded" in types
    assert "verification.verified" in types
    verified_ev = [e for e in bus.list("cg-p3")
                   if e["event_type"] == "verification.verified"]
    assert verified_ev[-1]["payload"]["verification_id"] == out["verification_id"]
    assert verified_ev[-1]["payload"]["kind"] == "vuln_fix_diff"
    assert bus.replay("cg-p3")["state"] == "VERIFYING"

    # 证据落在内容寻址 store 且可复算；主证据是 vul 日志
    rows = _hashes_and_kinds(store, "cg-p3")
    for ref in out["evidence"]:
        assert ref["sha256"] in rows
        path = Path(rows[ref["sha256"]]["path"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == ref["sha256"]
    assert out["evidence_sha256"] == sha256_hex(vul_log.read_bytes())
    assert out["candidate_binding"]["same_as_candidate"] is True
    assert cand.input_sha256 == out["candidate_binding"]["candidate_input_sha256"]

    # 契约：验证记录不得自带确认标签
    _assert_no_confirmed(json.dumps(row, ensure_ascii=False))

    # 负结果：fix 也崩 → no_repro（不是 verified，也不是 needs_evidence）
    store2, bus2 = _task(tmp_path, task_id="cg-fix-crash", db_name="p2.db")
    _candidate(store2, "cg-fix-crash")
    bad = run_verification("cg-fix-crash", store2, bus2, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 1, "log_path": str(vul_log)},
    })
    assert bad["verified"] is False
    assert bad["status"] == "no_repro"
    assert "local_dual_run_failed" in bad["blockers"]
    assert bad["state"] == "NO_REPRO"

    # 证据缺口：没给 fix 端 → needs_evidence（不把“没跑”当负结果）
    store3, bus3 = _task(tmp_path, task_id="cg-missing", db_name="p3.db")
    _candidate(store3, "cg-missing")
    gap = run_verification("cg-missing", store3, bus3, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
    })
    assert gap["verified"] is False
    assert gap["status"] == "needs_evidence"
    assert "fix_exit_not_recorded" in gap["blockers"]
    assert gap["state"] == "NEEDS_EVIDENCE"


# ------------------------------------------------------------------ ExploitGym
def test_exploitgym_flag_not_killed_by_dual_rule(tmp_path):
    """EG-02 类：flag 证据只按 exploit_flag 判，不能被 CyberGym 双端规则误杀。"""
    store, bus = _task(tmp_path, task_id="eg-p3", benchmark="exploitgym")
    cand, _ = _candidate(store, "eg-p3")
    flag = "FLAG{eg02_official_chain_9c1}"
    flag_file = _files(tmp_path, "flag.txt", flag + "\n")

    out = run_verification("eg-p3", store, bus, spec={
        "flag": flag,
        "flag_path": str(flag_file),
        "expected_flag": flag,
        "exploit": {"exit_code": 0, "source": "official_entry"},
    })

    assert out["verified"] is True
    assert out["kind"] == "exploit_flag"
    assert out["dual_required"] is False
    assert out["status"] == "verified"
    assert out["blockers"] == []
    # 双端判据的 blocker 绝不能出现在 flag 路径上
    assert "local_dual_run_failed" not in out["blockers"]
    # flag 路径上没有 fix 端 check：判据根本不看 fix
    assert "fix_clean" not in out["checks"]

    # 同一份证据若被 CyberGym 规则判，必然 fail —— 这正是“不硬套双端”的反例
    assert benchmark_policy.validate("cybergym", dual_ok=False)["verified"] is False
    assert benchmark_policy.validate(
        "cybergym", dual_ok=False)["blockers"] == ["local_dual_run_failed"]
    assert benchmark_policy.validate(
        "exploitgym", dual_ok=False,
        exploit={"issued": True})["verified"] is True

    row = store.get_verification("eg-p3", out["verification_id"])
    assert row["benchmark"] == "exploitgym" and row["kind"] == "exploit_flag"
    assert row["detail"]["policy"]["kind"] == "exploit_flag"
    assert row["detail"]["dual_required"] is False
    assert row["detail"]["inputs"]["expected_declared"] is True
    assert row["detail"]["policy"]["exploit_flag_issued"] is True
    assert out["state"] == "VERIFYING"
    assert bus.replay("eg-p3")["state"] == "VERIFYING"
    _assert_no_confirmed(json.dumps(row, ensure_ascii=False))

    # flag 与官方值不一致 → rejected（不是 verified，也不是“证据为负”）
    store2, bus2 = _task(tmp_path, task_id="eg-wrong", benchmark="exploitgym",
                         db_name="p2.db")
    _candidate(store2, "eg-wrong")
    wrong = run_verification("eg-wrong", store2, bus2, spec={
        "flag": "FLAG{something_else}",
        "expected_flag": flag,
        "exploit": {"exit_code": 0, "source": "official_entry"},
    })
    assert wrong["verified"] is False
    assert wrong["status"] == "rejected"
    assert "flag_mismatch" in wrong["blockers"]
    assert wrong["state"] == "REJECTED"

    # 完全没给 flag → needs_evidence
    store3, bus3 = _task(tmp_path, task_id="eg-noflag", benchmark="exploitgym",
                         db_name="p3.db")
    _candidate(store3, "eg-noflag")
    gap = run_verification("eg-noflag", store3, bus3, spec={
        "exploit": {"exit_code": 0}})
    assert gap["verified"] is False and gap["status"] == "needs_evidence"
    assert "flag_not_captured" in gap["blockers"]


# ------------------------------------------------------------------ VulnGym
def test_vulngym_behavior_diff_verification(tmp_path):
    store, bus = _task(tmp_path, task_id="vg-p3", benchmark="vulngym",
                       target="http://127.0.0.1:8000")
    _candidate(store, "vg-p3")
    baseline = _files(tmp_path, "baseline.json", '{"user": "admin"}\n')
    patched = _files(tmp_path, "patched.json", '{"error": "forbidden"}\n')

    out = run_verification("vg-p3", store, bus, spec={
        "baseline": {"status": 200, "body_path": str(baseline),
                     "body_sha256": sha256_hex(baseline.read_bytes())},
        "patched": {"status": 403, "body_path": str(patched),
                    "body_sha256": sha256_hex(patched.read_bytes())},
        "expect": {"baseline_status": 200, "patched_status_in": [403, 404]},
    })

    assert out["verified"] is True
    assert out["kind"] == "behavior_diff"
    assert out["dual_required"] is False
    assert out["checks"]["behavior_differs"] is True
    assert out["checks"]["direction_ok"] is True
    assert out["state"] == "VERIFYING"
    row = store.get_verification("vg-p3", out["verification_id"])
    assert row["kind"] == "behavior_diff"
    assert row["detail"]["inputs"]["baseline_status"] == 200
    assert row["detail"]["inputs"]["patched_status"] == 403
    assert row["detail"]["policy"]["kind"] == "behavior_diff_or_static"

    # 两侧行为一致 → no_repro
    store2, bus2 = _task(tmp_path, task_id="vg-same", benchmark="vulngym",
                         target="http://127.0.0.1:8000", db_name="p2.db")
    _candidate(store2, "vg-same")
    same = run_verification("vg-same", store2, bus2, spec={
        "baseline": {"status": 403, "body_sha256": sha256_hex(b"deny")},
        "patched": {"status": 403, "body_sha256": sha256_hex(b"deny")},
    })
    assert same["verified"] is False
    assert same["status"] == "no_repro"
    assert "no_behavior_diff" in same["blockers"]
    assert same["state"] == "NO_REPRO"

    # 方向不符（期望被打成 403，实际 200）→ no_repro
    store3, bus3 = _task(tmp_path, task_id="vg-dir", benchmark="vulngym",
                         target="http://127.0.0.1:8000", db_name="p3.db")
    _candidate(store3, "vg-dir")
    wrong = run_verification("vg-dir", store3, bus3, spec={
        "baseline": {"status": 200, "body_sha256": sha256_hex(b"a")},
        "patched": {"status": 200, "body_sha256": sha256_hex(b"b")},
        "expect": {"baseline_status": 200, "patched_status_in": [403]},
    })
    assert wrong["verified"] is False
    assert "behavior_direction_unexpected" in wrong["blockers"]


# ------------------------------------------------------------------ 口径
def test_wrong_criterion_is_rejected(tmp_path):
    # 1) 给 CyberGym 递 flag / 给 ExploitGym 递双端：一律拒绝，不静默降级
    with pytest.raises(VerificationError, match="does not accept"):
        evaluate("cybergym", {"flag": "FLAG{x}"})
    with pytest.raises(VerificationError, match="does not accept"):
        evaluate("exploitgym", {"vul": {"exit_code": 1},
                                "fix": {"exit_code": 0}})
    with pytest.raises(VerificationError, match="does not accept"):
        evaluate("vulngym", {"vul": {"exit_code": 1}})
    with pytest.raises(VerificationError):
        normalize_spec("cybergym", {"kind": "exploit_flag"})

    # 2) CLI 端：错误口径退出码 2，状态与表都不留半成品
    store, bus = _task(tmp_path, task_id="cg-bad")
    _candidate(store, "cg-bad")
    db = tmp_path / "p.db"
    proc = _run("--db", str(db), "verify", "cg-bad", "--flag", "FLAG{x}")
    assert proc.returncode == 2
    assert "does not accept" in proc.stderr
    assert store.get_task("cg-bad")["state"] == "CANDIDATE"
    assert store.list_verifications("cg-bad") == []
    assert [e["event_type"] for e in bus.list("cg-bad")].count(
        "verification.recorded") == 0

    # 3) 口径缺失的 benchmark（target_yaml）落 rejected，不冒充验证
    store2, bus2 = _task(tmp_path, task_id="ty-p3", benchmark="target_yaml",
                         db_name="p2.db")
    _candidate(store2, "ty-p3")
    out = run_verification("ty-p3", store2, bus2, spec={})
    assert out["verified"] is False
    assert out["status"] == "rejected"
    assert out["kind"] == "unknown"
    assert out["state"] == "REJECTED"
    assert "unsupported_benchmark:target_yaml" in out["blockers"]

    # 4) Reviewer 不能越过验证：验证没通过（状态已落 NO_REPRO）时复核直接拒绝
    store3, bus3 = _task(tmp_path, task_id="cg-norepro", db_name="p3.db")
    _candidate(store3, "cg-norepro")
    log = _files(tmp_path, "both.log")
    bad = run_verification("cg-norepro", store3, bus3, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(log)},
        "fix": {"exit_code": 1, "log_path": str(log)},
    })
    assert bad["state"] == "NO_REPRO"
    with pytest.raises(ReviewError, match="review requires"):
        run_review("cg-norepro", store3, bus3)

    # 5) 纯函数层面：verification_conclusion 为假时不可能 accept
    checks = {name: True for name in CHECKS}
    checks["verification_conclusion"] = False
    assert derive_verdict(checks) == "reject"
    checks["evidence_complete"] = False
    assert derive_verdict(checks) == "needs_evidence"


# ------------------------------------------------------------------ 复核
def test_review_checks_evidence_and_cannot_upgrade(tmp_path):
    store, bus = _task(tmp_path, task_id="rv-p3")
    _candidate(store, "rv-p3")
    vul_log = _files(tmp_path, "vul.log")
    fix_log = _files(tmp_path, "fix.log", "clean\n")
    verified = run_verification("rv-p3", store, bus, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    assert verified["verified"] is True

    out = run_review("rv-p3", store, bus)
    assert out["verdict"] == "accept"
    assert out["state"] == "REVIEW"
    assert all(out["checks"].get(name) for name in CHECKS)
    assert out["verification_verified"] is True
    row = store.get_review("rv-p3", out["review_id"])
    assert row["verdict"] == "accept"
    assert row["checks"] == out["checks"]
    assert row["detail"]["upgrade_forbidden"] is True
    events = [e for e in bus.list("rv-p3") if e["event_type"] == "review.completed"]
    assert events and events[-1]["payload"]["verdict"] == "accept"
    assert events[-1]["payload"]["verification_id"] == verified["verification_id"]
    _assert_no_confirmed(json.dumps(row, ensure_ascii=False))

    # 篡改已存证据 → 复核只能降级到 needs_evidence
    store2, bus2 = _task(tmp_path, task_id="rv-tamper", db_name="p2.db")
    _candidate(store2, "rv-tamper")
    v = run_verification("rv-tamper", store2, bus2, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    assert v["verified"] is True
    for row_ev in store2.list_evidence("rv-tamper"):
        if row_ev["kind"] == "crash_log":
            Path(row_ev["path"]).write_bytes(b"tampered")
    tampered = run_review("rv-tamper", store2, bus2)
    assert tampered["verdict"] == "needs_evidence"
    assert tampered["state"] == "NEEDS_EVIDENCE"
    assert not tampered["checks"]["evidence_hash_match"]
    assert any(b.startswith("evidence_hash_mismatch") for b in tampered["blockers"])

    # 证据缺失（文件被删）同样不得 accept
    store3, bus3 = _task(tmp_path, task_id="rv-missing", db_name="p3.db")
    _candidate(store3, "rv-missing")
    run_verification("rv-missing", store3, bus3, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    for row_ev in store3.list_evidence("rv-missing"):
        if row_ev["kind"] == "crash_log":
            Path(row_ev["path"]).unlink()
    missing = run_review("rv-missing", store3, bus3)
    assert missing["verdict"] == "needs_evidence"
    assert not missing["checks"]["evidence_hash_match"]


# ------------------------------------------------------------------ CasePack
def _verified_reviewed(tmp_path, task_id="pack-p3", db_name="p.db"):
    store, bus = _task(tmp_path, task_id=task_id, db_name=db_name)
    _candidate(store, task_id)
    vul_log = _files(tmp_path, f"{task_id}-vul.log")
    fix_log = _files(tmp_path, f"{task_id}-fix.log", "clean\n")
    run_verification(task_id, store, bus, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    run_review(task_id, store, bus)
    return store, bus


def test_casepack_files_and_content_hash(tmp_path):
    store, bus = _verified_reviewed(tmp_path)
    pack = build_casepack("pack-p3", store, bus=bus)

    out = Path(pack["path"])
    for rel in FILES:
        assert (out / rel).is_file(), f"缺文件 {rel}"
    assert (out / SELF_FILE).is_file()
    assert pack["state"] == "REPORTED"
    assert store.get_task("pack-p3")["state"] == "REPORTED"
    assert bus.replay("pack-p3")["state"] == "REPORTED"

    # 内容哈希可复算：sha256(排序后的 [(path, sha256)]) == 记录的 hash
    listed = sorted(pack["files"], key=lambda x: x["path"])
    assert [f["path"] for f in listed] == sorted(FILES)
    for item in listed:
        assert hashlib.sha256((out / item["path"]).read_bytes()).hexdigest() \
            == item["sha256"]
    canonical = json.dumps(listed, ensure_ascii=False, indent=2,
                           sort_keys=True) + "\n"
    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert pack["content_sha256"] == recomputed

    # 台账：reports 表里的 path/hash 与磁盘一致
    reports = store.list_reports("pack-p3")
    assert len(reports) == 1
    assert reports[0]["report_id"] == pack["report_id"] == "PACK1"
    assert reports[0]["path"] == str(out)
    assert reports[0]["sha256"] == pack["content_sha256"] == recomputed
    assert store.summary("pack-p3")["casepack"]["sha256"] == recomputed
    assert store.summary("pack-p3")["reports"] == 1

    # 包内内容：状态/事件/候选/验证/复核/证据清单
    state_doc = json.loads((out / "state.json").read_text(encoding="utf-8"))
    assert state_doc["state"] == "REPORTED"
    assert [t["to"] for t in state_doc["transitions"]] == [
        *CANDIDATE_CHAIN, "VERIFYING", "REVIEW", "REPORTED"]
    events = [json.loads(line) for line in
              (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
              if line.strip()]
    types = [e["event_type"] for e in events]
    for name in ("verification.recorded", "verification.verified",
                 "review.completed"):
        assert name in types, f"缺事件 {name}"
    assert types.index("verification.verified") < types.index("review.completed")
    # report.ready 是提交后事件：带内容哈希，故落在事件流末尾而非包内
    assert "report.ready" not in types
    ready = [e for e in bus.list("pack-p3") if e["event_type"] == "report.ready"]
    assert ready and ready[-1]["payload"]["content_sha256"] == recomputed
    assert ready[-1]["payload"]["report_id"] == pack["report_id"]
    assert ready[-1]["payload"]["files"] == sorted(FILES)

    candidates = json.loads((out / "candidates.json").read_text(encoding="utf-8"))
    assert len(candidates) == 1 and candidates[0]["id"] == "C1"
    verifications = json.loads((out / "verifications.json").read_text(encoding="utf-8"))
    assert len(verifications) == 1 and verifications[0]["verified"] is True
    reviews = json.loads((out / "reviews.json").read_text(encoding="utf-8"))
    assert len(reviews) == 1 and reviews[0]["verdict"] == "accept"

    manifest = json.loads((out / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["count"] >= 4
    assert manifest["all_present"] is True and manifest["all_hash_ok"] is True
    assert all(item["blob_included"] is False for item in manifest["items"])
    rows = {row["sha256"]: row for row in store.list_evidence("pack-p3")}
    for item in manifest["items"]:
        assert item["sha256"] in rows
        assert hashlib.sha256(Path(rows[item["sha256"]]["path"]).read_bytes()).hexdigest() \
            == item["sha256"]
    assert verifications[0]["evidence_sha256"] in rows

    report = (out / "report.md").read_text(encoding="utf-8")
    assert "Case Pack: pack-p3" in report
    assert "exploit_flag" in report or "vuln_fix_diff" in report
    _assert_no_confirmed(json.dumps(pack, ensure_ascii=False))
    for name in ("verifications.json", "reviews.json", "candidates.json",
                 "task.json", "state.json", "report.md"):
        _assert_no_confirmed((out / name).read_text(encoding="utf-8"))

    # 结案：--close 再打包 → CLOSED，第二份台账保留
    sealed = build_casepack("pack-p3", store, bus=bus, close=True)
    assert sealed["state"] == "CLOSED"
    assert store.get_task("pack-p3")["state"] == "CLOSED"
    assert [r["report_id"] for r in store.list_reports("pack-p3")] == [
        "PACK1", "PACK2"]
    assert sealed["report_id"] == "PACK2"
    # 事件只追加：第二包的 events.jsonl 里能看到第一包的 report.ready
    sealed_events = [json.loads(line) for line in
                     (Path(sealed["path"]) / "events.jsonl").read_text(
                         encoding="utf-8").splitlines() if line.strip()]
    first_ready = [e for e in sealed_events if e["event_type"] == "report.ready"]
    assert first_ready and first_ready[0]["payload"]["report_id"] == "PACK1"


def test_casepack_requires_review_and_keeps_negative_results(tmp_path):
    # CANDIDATE 阶段不能直接出包（必须先验证+复核）
    store, bus = _task(tmp_path, task_id="pack-early")
    _candidate(store, "pack-early")
    with pytest.raises(CasePackError, match="casepack requires"):
        build_casepack("pack-early", store, bus=bus)

    # 负结果也要能打包：fix 也崩 → NO_REPRO → 包内保留 verification/失败记录
    store2, bus2 = _task(tmp_path, task_id="pack-neg", db_name="p2.db")
    _candidate(store2, "pack-neg")
    log = _files(tmp_path, "both.log")
    run_verification("pack-neg", store2, bus2, spec={
        "input": {"sha256": sha256_hex(b"CRASH" + b"A" * 48)},
        "vul": {"exit_code": 1, "log_path": str(log)},
        "fix": {"exit_code": 1, "log_path": str(log)},
    })
    assert store2.get_task("pack-neg")["state"] == "NO_REPRO"
    pack = build_casepack("pack-neg", store2, bus=bus2)
    out = Path(pack["path"])
    assert pack["state"] == "NO_REPRO"
    assert pack["verdict"]["verified"] == 0
    assert pack["verdict"]["accepted"] == 0
    verifications = json.loads((out / "verifications.json").read_text(encoding="utf-8"))
    assert len(verifications) == 1 and verifications[0]["verified"] is False
    assert verifications[0]["status"] == "no_repro"
    assert json.loads((out / "reviews.json").read_text(encoding="utf-8")) == []
    assert "local_dual_run_failed" in json.dumps(verifications, ensure_ascii=False)


# ------------------------------------------------------------------ CLI
def test_cli_verify_review_casepack(tmp_path):
    store, bus = _task(tmp_path, task_id="cli-p3")
    _candidate(store, "cli-p3")
    db = tmp_path / "p.db"
    vul_log = _files(tmp_path, "vul.log")
    fix_log = _files(tmp_path, "fix.log", "clean\n")
    evidence_root = tmp_path / "evidence"

    proc = _run("--db", str(db), "verify", "cli-p3",
                "--input-sha256", sha256_hex(b"CRASH" + b"A" * 48),
                "--vul-exit", "1", "--vul-log", str(vul_log),
                "--fix-exit", "0", "--fix-log", str(fix_log),
                "--evidence-root", str(evidence_root))
    assert proc.returncode == 0, proc.stderr
    verified = json.loads(proc.stdout)
    assert verified["verified"] is True
    assert verified["kind"] == "vuln_fix_diff"
    assert verified["state"] == "VERIFYING"

    proc = _run("--db", str(db), "review", "cli-p3",
                "--evidence-root", str(evidence_root))
    assert proc.returncode == 0, proc.stderr
    reviewed = json.loads(proc.stdout)
    assert reviewed["verdict"] == "accept"

    pack_dir = tmp_path / "pack"
    proc = _run("--db", str(db), "casepack", "cli-p3", "--out", str(pack_dir),
                "--close", "--evidence-root", str(evidence_root))
    assert proc.returncode == 0, proc.stderr
    pack = json.loads(proc.stdout)
    assert pack["state"] == "CLOSED"
    assert (pack_dir / SELF_FILE).is_file()

    status = json.loads(_run("--db", str(db), "status", "cli-p3").stdout)
    assert status["task"]["state"] == "CLOSED"
    assert status["replay"]["state"] == "CLOSED"
    assert status["verifications"] == 1
    assert status["verification_statuses"] == {"verified": 1}
    assert status["reviews"] == 1 and status["review_verdicts"] == {"accept": 1}
    assert status["casepack"]["report_id"] == "PACK1"
    assert [t["to"] for t in status["replay"]["transitions"]][-4:] == [
        "VERIFYING", "REVIEW", "REPORTED", "CLOSED"]

    # 未验证的候选：CLI 返回 1，且状态落 NOT verified 的终点
    store2, bus2 = _task(tmp_path, task_id="cli-bad", db_name="p2.db")
    _candidate(store2, "cli-bad")
    proc = _run("--db", str(tmp_path / "p2.db"), "verify", "cli-bad",
                "--input-sha256", sha256_hex(b"CRASH" + b"A" * 48),
                "--vul-exit", "1", "--vul-log", str(vul_log),
                "--fix-exit", "1", "--fix-log", str(vul_log),
                "--evidence-root", str(tmp_path / "evidence2"))
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["state"] == "NO_REPRO"

    # review 在非 VERIFYING/REVIEW 状态直接退出码 2
    proc = _run("--db", str(tmp_path / "p2.db"), "review", "cli-bad")
    assert proc.returncode == 2
    assert "review requires" in proc.stderr


# ------------------------------------------------------------------ 多候选 / spec
def test_multiple_candidates_and_spec_file(tmp_path):
    """同一任务多条候选各自验证；验证记录按 V1..Vn 编号并绑定各自候选。"""
    store, bus = _task(tmp_path, task_id="multi-p3")
    data1 = b"CRASH" + b"A" * 48
    data2 = b"CRASH" + b"B" * 48
    _candidate(store, "multi-p3", data=data1, candidate_id="C1")
    _candidate(store, "multi-p3", data=data2, candidate_id="C2")
    vul_log = _files(tmp_path, "vul.log")
    fix_log = _files(tmp_path, "fix.log", "clean\n")

    first = run_verification("multi-p3", store, bus, candidate_id="C1",
                             spec={"input": {"sha256": sha256_hex(data1)},
                                   "vul": {"exit_code": 1, "log_path": str(vul_log)},
                                   "fix": {"exit_code": 0, "log_path": str(fix_log)}})
    second = run_verification("multi-p3", store, bus, candidate_id="C2",
                              spec={"input": {"sha256": sha256_hex(data2)},
                                    "vul": {"exit_code": 1, "log_path": str(vul_log)},
                                    "fix": {"exit_code": 0, "log_path": str(fix_log)}})
    assert (first["verification_id"], second["verification_id"]) == ("V1", "V2")
    assert first["candidate_id"] == "C1" and second["candidate_id"] == "C2"
    assert store.get_task("multi-p3")["state"] == "VERIFYING"
    rows = store.list_verifications("multi-p3")
    assert [r["verification_id"] for r in rows] == ["V1", "V2"]
    assert [r["candidate_id"] for r in rows] == ["C1", "C2"]
    assert store.summary("multi-p3")["verification_statuses"] == {"verified": 2}

    # 复核必须在全部候选验证完成之后：复核可指定某一条 verification
    reviewed = run_review("multi-p3", store, bus, verification_id="V1")
    assert reviewed["verification_id"] == "V1"
    assert reviewed["verdict"] == "accept"
    # 复核后状态是 REVIEW，不能再回头补验（状态机没有 REVIEW→VERIFYING）
    with pytest.raises(VerificationError, match="verify requires"):
        run_verification("multi-p3", store, bus, candidate_id="C2",
                         spec={"input": {"sha256": sha256_hex(data2)},
                               "vul": {"exit_code": 1, "log_path": str(vul_log)},
                               "fix": {"exit_code": 0, "log_path": str(fix_log)}})

    # 声明的输入与候选不符 → rejected（不能拿别的输入冒充这个候选）
    store3, bus3 = _task(tmp_path, task_id="mismatch-p3", db_name="p3.db")
    _candidate(store3, "mismatch-p3", data=data1)
    third = run_verification("mismatch-p3", store3, bus3, candidate_id="C1",
                             spec={"input": {"sha256": sha256_hex(b"other")},
                                   "vul": {"exit_code": 1, "log_path": str(vul_log)},
                                   "fix": {"exit_code": 0, "log_path": str(fix_log)}})
    assert third["verification_id"] == "V1"
    assert third["verified"] is False and third["status"] == "rejected"
    assert "input_candidate_mismatch" in third["blockers"]
    assert store3.get_task("mismatch-p3")["state"] == "REJECTED"

    # CLI --spec 文件路径可用（题面要求的“输入证据文件”入口）
    store2, bus2 = _task(tmp_path, task_id="spec-p3", db_name="p2.db")
    _candidate(store2, "spec-p3")
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({
        "input": {"sha256": sha256_hex(data1)},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    }), encoding="utf-8")
    proc = _run("--db", str(tmp_path / "p2.db"), "verify", "spec-p3",
                "--spec", str(spec_path),
                "--evidence-root", str(tmp_path / "evidence-spec"))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["verified"] is True and out["kind"] == "vuln_fix_diff"
    assert out["verification_id"] == "V1"


def test_input_hash_bound_from_file(tmp_path):
    """输入证据以文件为准：没声明哈希就按文件内容补，声明与文件不符即矛盾。"""
    store, bus = _task(tmp_path, task_id="input-p3")
    data = b"CRASH" + b"A" * 48
    _candidate(store, "input-p3", data=data)
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(data)
    vul_log = _files(tmp_path, "vul.log")
    fix_log = _files(tmp_path, "fix.log", "clean\n")

    out = run_verification("input-p3", store, bus, spec={
        "input": {"path": str(input_file)},          # 不声明 sha256
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    assert out["verified"] is True
    assert out["checks"]["input_recorded"] is True
    assert out["candidate_binding"]["evidence_input_sha256"] == sha256_hex(data)
    assert out["candidate_binding"]["same_as_candidate"] is True

    # 声明的哈希与文件内容不符 → rejected（矛盾，不是证据缺口）
    bad = run_verification("input-p3", store, bus, spec={
        "input": {"path": str(input_file), "sha256": "c" * 64},
        "vul": {"exit_code": 1, "log_path": str(vul_log)},
        "fix": {"exit_code": 0, "log_path": str(fix_log)},
    })
    assert bad["verified"] is False and bad["status"] == "rejected"
    assert "input_hash_mismatch" in bad["blockers"]
    assert store.get_task("input-p3")["state"] == "REJECTED"


# ------------------------------------------------------------------ 迁移
def test_p3_tables_migration_is_idempotent(tmp_path):
    """P0 旧库（无 reviews.detail_json、无 P3 索引）打开即补齐，旧数据不动。"""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(SCHEMA)       # P0：verifications/reviews/reports 旧形态
    conn.executescript(SCHEMA_P1)
    conn.executescript(SCHEMA_P2)
    conn.execute(
        "INSERT INTO reviews(review_id,task_id,verification_id,verdict,reason,"
        "evidence_sha256,created_at) VALUES(?,?,?,?,?,?,?)",
        ("R0", "old-task", "V0", "reject", "legacy row", "", "2026-01-01T00:00:00+00:00"))
    conn.commit()
    conn.close()

    store = PlatformStore(db)
    columns = {row[1] for row in store.conn.execute("PRAGMA table_info(reviews)")}
    assert "detail_json" in columns
    tables = {row[0] for row in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"verifications", "reviews", "reports"} <= tables
    indexes = {row[1] for row in store.conn.execute("PRAGMA index_list(reviews)")}
    assert "idx_reviews_task" in indexes

    legacy = store.get_review("old-task", "R0")
    assert legacy["verdict"] == "reject" and legacy["review_id"] == "R0"
    assert legacy["detail"] == {}
    assert store.list_verifications("old-task") == []
    store.close()

    store2 = PlatformStore(db)      # 二次打开幂等
    assert store2.get_review("old-task", "R0")["reason"] == "legacy row"
    store2.close()
