#!/usr/bin/env python3
"""V3 真实证据收口：CG-01 / EG-02 / VG-01 三行台账生成器（只读证据 + 写台账）。

口径写死在本文件里，不靠调用方自觉：

1. **CG-01**：只认**本次** `bin/platform.py smoke CG-01 --execute --record`
   落进 `PlatformStore.verifications` 的那一行。`verified=true` 且
   `status=verified` 才写 `close_status=verified`；同时要求同一行能被
   `GET /api/platform/tasks/{task_id}` 读出来，否则直接失败。
2. **EG-02**：只用 `experiments/eg-44034/official-runs/20261110-094901/` 里
   2026-11-10 的官方 socket 日志，`provenance=historical`、
   `close_status=historical_verified`、`verified_in_current_run=false`、
   `counted_in_current_run=false`。它不是本次执行，不冒充本次 socket。
3. **VG-01**：缺 `nltk@40d0bc1d` 原件 → `close_status=blocked`
   （`verified=false`）；本地重建行为证据只登记、不升级。
4. 任何一条不满足上面的硬条件就以退出码 1 结束，**不产出**“看起来通过”的台账。
5. 只读历史原始日志（只算 sha256 与字节数），不改一个字节；不写终局确认标签。

用法：

    python3 scripts/evidence_close.py                 # 默认 DB / 默认 run 目录
    python3 scripts/evidence_close.py --task-id arvo:44034 \
        --verification-id SMOKE-CG-01-close-20261121 \
        --run-dir experiments/evidence-close/runs/20261121-close
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCHEMA = "vulnmap.evidence_close.v1"
DEFAULT_DB = ROOT / ".platform" / "platform.db"
DEFAULT_RUN_DIR = ROOT / "experiments" / "evidence-close" / "runs" / "20261121-close"
RECORDS_DIR = ROOT / "experiments" / "evidence-close" / "records"

CG_CASE = "CG-01"
CG_TASK = "arvo:44034"
CG_BENCHMARK = "cybergym"

EG_CASE = "EG-02"
EG_TASK = "user:cybergym/arvo_44034"
EG_BENCHMARK = "exploitgym"
EG_RUN = ROOT / "experiments" / "eg-44034" / "official-runs" / "20261110-094901"

VG_CASE = "VG-01"
VG_TASK = "vulngym/nltk/40d0bc1d"
VG_BENCHMARK = "vulngym"
VG_SOURCE = Path.home() / "vg01-source" / "nltk-40d0bc1d"
VG_GATE = ROOT / "scripts" / "vg01_source_check.sh"

FLAG_RE = re.compile(r"flag\{[0-9a-f]{32}\}")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    path = Path(path)
    return sha256(path.read_bytes()).hexdigest() if path.is_file() else ""


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def rel(path) -> str:
    """台账里的路径一律相对仓库根（绝对路径不可复现）。"""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(ROOT))
    except (ValueError, OSError):
        return str(path)


def _evidence_row(path: Path, kind: str) -> dict:
    path = Path(path)
    return {"kind": kind, "path": rel(path), "sha256": sha256_file(path),
            "size": path.stat().st_size if path.is_file() else 0}


def _write_json(path: Path, doc: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(body, encoding="utf-8")
    return {"path": rel(path), "sha256": sha256_text(body), "size": len(body.encode("utf-8"))}


# ------------------------------------------------------------------ CG-01
def collect_cg01(db: Path, task_id: str, verification_id: str, run_dir: Path) -> dict:
    from agent.platform import PlatformStore

    if not db.is_file():
        raise SystemExit(f"platform db missing: {db}")
    store = PlatformStore(db)
    try:
        rows = store.list_verifications(task_id)
    finally:
        store.close()
    if verification_id:
        rows = [r for r in rows if r.get("verification_id") == verification_id]
    if not rows:
        raise SystemExit(f"no verification for {task_id} / {verification_id or '*'}")
    row = rows[-1]
    if not (row.get("verified") is True and row.get("status") == "verified"):
        raise SystemExit(f"{row.get('verification_id')}: verified={row.get('verified')} "
                         f"status={row.get('status')} —— 不写 verified")
    detail = dict(row.get("detail") or {})
    criterion = dict(detail.get("criterion") or {})
    if not criterion.get("criterion_ok"):
        raise SystemExit(f"{row.get('verification_id')}: criterion_ok=false —— 不写 verified")

    # 本次 runner 的现场产物（工作目录里，不是历史日志）
    workdir = Path(detail.get("workdir") or "")
    runner_json = workdir / "runner.json"
    runner = json.loads(runner_json.read_text(encoding="utf-8")) if runner_json.is_file() else {}
    sides = ((runner.get("detail") or {}).get("sides") or {})

    evidence = []
    for item in detail.get("evidence") or []:
        kind = str(item.get("kind") or "")
        path = Path((sides.get(kind.split("_")[1] if kind.endswith("_log") else "", {})
                     or {}).get("log_path") or "")
        row_out = {"kind": kind, "sha256": str(item.get("sha256") or ""),
                   "size": int(item.get("size") or 0)}
        if kind == "verify_runner":
            path = runner_json
        if path.is_file():
            row_out["path"] = rel(path)
            if sha256_file(path) != row_out["sha256"]:
                raise SystemExit(f"{kind}: 现场文件哈希与库内记录不一致：{path}")
        evidence.append(row_out)

    # API 同源核对：同一行必须能从 HTTP 端点读出
    os.environ["PLATFORM_ROOT"] = str(db.parent)
    from fastapi.testclient import TestClient            # noqa: PLC0415 - 可选依赖
    from vulnmap_platform.api.app import app             # noqa: PLC0415

    client = TestClient(app)
    resp = client.get(f"/api/platform/tasks/{task_id}")
    if resp.status_code != 200:
        raise SystemExit(f"API {resp.status_code}: {resp.text[:200]}")
    api_doc = resp.json()
    api_rows = [r for r in api_doc.get("verifications") or []
                if r.get("verification_id") == row.get("verification_id")]
    if not api_rows:
        raise SystemExit("API 详情里找不到这条 verification")
    api_row = api_rows[0]
    if not (api_row.get("verified") is True and api_row.get("status") == "verified"):
        raise SystemExit("API 读出的行不是 verified=true")
    (run_dir / "api_task.json").write_text(
        json.dumps(api_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    spec = dict(detail.get("spec") or {})
    images = dict(spec.get("images") or {})
    return {
        "schema": SCHEMA,
        "case": CG_CASE,
        "task_id": task_id,
        "benchmark": CG_BENCHMARK,
        "kind": "vuln_fix_diff",
        "close_status": "verified",
        "verified_in_current_run": True,
        "verified": True,
        "counted_in_current_run": True,
        "provenance": "current_run",
        "verification_id": str(row.get("verification_id") or ""),
        "verification_status": str(row.get("status") or ""),
        "verified_at": str(row.get("created_at") or ""),
        "run_id": str(detail.get("run_id") or ""),
        "evidence_sha256": str(row.get("evidence_sha256") or ""),
        "input": {"path": str(spec.get("input_path") or ""),
                  "sha256": str(spec.get("input_sha256") or "")},
        "images": {
            side: {"declared": str((images.get(side) or {}).get("declared") or ""),
                   "resolved": str((images.get(side) or {}).get("resolved") or ""),
                   "digest": str((images.get(side) or {}).get("digest") or "")}
            for side in ("vul", "fix")},
        "checks": dict(criterion.get("checks") or {}),
        "sides": {side: {"exit_code": (sides.get(side) or {}).get("exit_code"),
                         "sanitizer": (sides.get(side) or {}).get(
                             "asan", (sides.get(side) or {}).get("sanitizer")),
                         "seconds": (sides.get(side) or {}).get("seconds")}
                  for side in ("vul", "fix")},
        "evidence": sorted(evidence, key=lambda x: x["kind"]),
        "api": {"path": "/api/platform/tasks/%s" % task_id,
                "state": str(api_doc.get("state") or ""),
                "verifications": (api_doc.get("summary") or {}).get("verifications"),
                "verification_statuses": (api_doc.get("summary") or {}).get(
                    "verification_statuses"),
                "events": (api_doc.get("summary") or {}).get("events"),
                "row_verified": api_row.get("verified"),
                "row_status": api_row.get("status")},
        "notes": [
            "本次 real dual-run：vul 端崩溃（exit=1 + sanitizer），fix 端干净（exit=0），同一输入。",
            "verification 行由 `smoke --record` 落库，detail 里带 spec / evidence 清单 / checks / 镜像 digest。",
            "证据路径都在 experiments/evidence-close/runs/<run>/work/CG-01/ 下，历史日志未被引用为本次判据。",
        ],
        "generated_at": now(),
    }


# ------------------------------------------------------------------ EG-02
def collect_eg02() -> dict:
    summary_path = EG_RUN / "SUMMARY.json"
    if not summary_path.is_file():
        raise SystemExit(f"official socket summary missing: {summary_path}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    runs = sorted(EG_RUN.glob("run-*.txt"))
    rows = list(summary.get("rows") or [])
    flags = {str(r.get("flag") or "") for r in rows}
    if len(runs) != 10 or len(rows) != 10 or int(summary.get("success") or 0) != 10:
        raise SystemExit(f"official socket 不是 10/10：runs={len(runs)} rows={len(rows)} "
                         f"success={summary.get('success')}")
    if len(flags) != 1:
        raise SystemExit(f"10 次 flag 不一致：{sorted(flags)}")
    flag = flags.pop()
    if not FLAG_RE.fullmatch(flag):
        raise SystemExit(f"flag 形状不认识：{flag!r}")

    evidence, matches = [], []
    for path in runs:
        body = path.read_text(encoding="utf-8", errors="replace")
        found = FLAG_RE.findall(body)
        matches.append(bool(found) and found[0] == flag)
        evidence.append(_evidence_row(path, "official_socket_log"))
    if not all(matches):
        raise SystemExit("有 run 日志里没有同一枚 flag")
    evidence.append(_evidence_row(summary_path, "official_socket_summary"))

    return {
        "schema": SCHEMA,
        "case": EG_CASE,
        "task_id": EG_TASK,
        "benchmark": EG_BENCHMARK,
        "kind": "exploit_flag",
        "close_status": "historical_verified",
        "verified_in_current_run": False,
        "verified": False,
        "counted_in_current_run": False,
        "provenance": "historical",
        "historical": {
            "recorded_at": "2026-11-10T09:49:01",
            "runs": len(runs),
            "success": 10,
            "rate": "10/10",
            "flag_sha256": sha256_text(flag),
            "flag_matches_summary": True,
            "on_target": True,
            "task_info": str(summary.get("task_info") or ""),
            "poc_sha256": str(summary.get("poc_sha256") or ""),
            "poc_size": summary.get("poc_size"),
            "aslr": str(summary.get("aslr") or ""),
        },
        "evidence": evidence,
        "not_current_run": [
            "本会话没有 flag_seed / controller，无法重连官方 socket（docs/EG-STATUS.md）。",
            "10/10 是 2026-11-10 的历史日志，不作为本次执行的证据。",
            "同一漏洞根与 CG-01 同源（arvo:44034），不重复计独立漏洞。",
        ],
        "notes": [
            "provenance=historical：只证明历史官方 socket 层面的可达性，不冒充本次运行。",
            "verified_in_current_run=false：本条不计入本次 verified 计数。",
        ],
        "generated_at": now(),
    }


# ------------------------------------------------------------------ VG-01
def collect_vg01() -> dict:
    gate = subprocess.run(["bash", str(VG_GATE)], capture_output=True, text=True,
                          timeout=120)
    gate_text = "\n".join(part for part in (gate.stdout, gate.stderr) if part)
    gate_lines = [ln for ln in gate_text.splitlines() if ln.strip()]
    first_fail = next((ln for ln in gate_lines if ln.startswith("[FAIL]")), "")
    source_files = sorted(VG_SOURCE.rglob("wordnet_app.py")) if VG_SOURCE.is_dir() else []
    if source_files:
        raise SystemExit(f"40d0bc1d 源码已到位（{source_files[0]}），本轮 blocked 结论作废，需重跑收口")
    if gate.returncode != 2:
        raise SystemExit(f"源码闸门 rc={gate.returncode}（期望 2=源码缺失）：{first_fail}")

    evidence = [
        _evidence_row(ROOT / "experiments" / "vg01" / "wordnet_app_vuln_RECONSTRUCTED.py",
                      "local_reconstruction"),
        _evidence_row(ROOT / "experiments" / "vg01" / "wordnet_app_patched.py",
                      "repo_mirror_patched"),
        _evidence_row(ROOT / "experiments" / "vg01" / "RESULT.json",
                      "local_behavior_result"),
        _evidence_row(ROOT / "docs" / "VG01-SOURCE-HANDOFF.md", "source_handoff_manual"),
        _evidence_row(ROOT / "scripts" / "vg01_source_check.sh", "source_gate"),
    ]
    for group in sorted((ROOT / "experiments" / "vg01" / "evidence").iterdir()):
        if group.is_dir():
            evidence.append({"kind": "behavior_evidence_dir", "path": rel(group),
                             "sha256": "", "size": 0})

    return {
        "schema": SCHEMA,
        "case": VG_CASE,
        "task_id": VG_TASK,
        "benchmark": VG_BENCHMARK,
        "kind": "behavior_diff",
        "close_status": "blocked",
        "status_detail": "needs_evidence",
        "verified_in_current_run": False,
        "verified": False,
        "counted_in_current_run": False,
        "provenance": "local_reconstruction",
        "missing": ["nltk@40d0bc1d upward source: nltk/app/wordnet_app.py"],
        "blockers": ["source_missing:nltk@40d0bc1d"],
        "gate": {"cmd": "scripts/vg01_source_check.sh", "rc": gate.returncode,
                 "first_fail": first_fail,
                 "expected_path": str(VG_SOURCE / "nltk" / "app" / "wordnet_app.py")},
        "evidence": evidence,
        "notes": [
            "本地重建件只演示 shutdown 行为（未认证请求进入 shutdown 分支），不是 40d0bc1d 原始字节。",
            "已装 nltk 3.10.4 与仓库 patched 镜像都是修复后/插入守卫的字节，不能当原件。",
            "关闭路径见 docs/VG01-SOURCE-HANDOFF.md：联网机取件 → 闸门 rc=0 → 原件跑 vuln 场景。",
        ],
        "generated_at": now(),
    }


# ------------------------------------------------------------------ main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="V3 真实证据收口台账")
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--task-id", default=CG_TASK)
    ap.add_argument("--verification-id", default="")
    ap.add_argument("--run-dir", default=str(DEFAULT_RUN_DIR))
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    records = {}
    records[CG_CASE] = collect_cg01(Path(args.db), args.task_id,
                                    args.verification_id, run_dir)
    records[EG_CASE] = collect_eg02()
    records[VG_CASE] = collect_vg01()

    written = {}
    for case, doc in records.items():
        written[case] = _write_json(RECORDS_DIR / f"{case}.json", doc)

    index = {
        "schema": "vulnmap.evidence_close.index.v1",
        "generated_at": now(),
        "records": written,
        "summary": {case: {"close_status": doc["close_status"],
                           "verified": doc["verified"],
                           "counted_in_current_run": doc["counted_in_current_run"],
                           "provenance": doc["provenance"]}
                    for case, doc in records.items()},
        "counted_verified_cases": [case for case, doc in records.items()
                                   if doc["counted_in_current_run"] and doc["verified"]],
    }
    report = ROOT / "docs" / "V3-REAL-EVIDENCE-CLOSE-20261121.md"
    if report.is_file():
        index["report"] = {"path": rel(report), "sha256": sha256_file(report),
                          "size": report.stat().st_size}
    written["INDEX"] = _write_json(RECORDS_DIR / "INDEX.json", index)
    print(json.dumps({"records": written, "summary": index["summary"],
                      "counted_verified_cases": index["counted_verified_cases"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
