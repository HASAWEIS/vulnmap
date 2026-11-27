"""独立校验器：只读运行包 + 冻结任务 + 保留答案，不看报告 narrate。

判定来源优先级（与项目既有口径一致）：
  运行时事实 > 原始记录 > 工件哈希 > 报告自述

退出语义：
  pass       结果符合预期，证据齐备，预算未超
  incomplete 观测不足或预算不够，且结果如实报了 unknown/未完成（诚实，不算通过）
  fail       结果与预期不符、证据缺失、哈希不符、跨运行引用、超预算、类别非自主
"""
from __future__ import annotations

import json
import pathlib

from .classify import AUTONOMOUS, classify
from .pack import RunPack, sha_file


def verify(pack_dir, *, expected_path, require_autonomous=True) -> dict:
    pack = RunPack(pack_dir)
    run = pack.run()
    frozen = pack.frozen()
    result = pack.result_or_none()
    cls = classify(pack)
    checks, reasons = {}, []

    # 1) 冻结材料未被改动
    frozen_ok, frozen_bad = True, []
    base = pathlib.Path(run.get("base_dir") or pathlib.Path(pack_dir).parent)
    for rel, meta in (frozen.get("files") or {}).items():
        p = base / rel
        if not p.is_file() or sha_file(p) != meta.get("sha256"):
            frozen_ok = False
            frozen_bad.append(rel)
    checks["frozen_inputs_intact"] = frozen_ok
    if not frozen_ok:
        reasons.append("冻结材料被改动或缺失: %s" % frozen_bad)

    # 2) 预算
    budget = run.get("budget") or {}
    obs = pack.observations()
    max_obs = budget.get("max_observations")
    over_obs = max_obs is not None and len(obs) > int(max_obs)
    elapsed = float(run.get("finished_at") or 0) - float(run.get("started_at") or 0)
    max_sec = budget.get("max_seconds")
    over_time = max_sec is not None and elapsed > float(max_sec)
    checks["budget_observations"] = not over_obs
    checks["budget_seconds"] = not over_time
    if over_obs:
        reasons.append("观测次数 %d 超过预算 %s" % (len(obs), max_obs))
    if over_time:
        reasons.append("运行时长 %.1fs 超过预算 %ss" % (elapsed, max_sec))

    # 3) 结果归属本次运行
    same_run = bool(result) and str(result.get("run_id")) == str(run.get("run_id"))
    checks["result_belongs_to_run"] = same_run
    if not same_run:
        reasons.append("result.run_id 与运行包不一致（跨运行引用）")

    # 4) 工件溯源：报告引用的每个工件必须存在、哈希一致、且由本次运行记录
    recorded = {a.get("path"): a for a in pack.artifacts()}
    prov_ok, prov_bad = True, []
    for name, finding in ((result or {}).get("findings") or {}).items():
        art = finding.get("artifact")
        if not art:
            continue
        rel = pathlib.Path(art)
        p = pathlib.Path(pack_dir) / rel
        rec = recorded.get(rel.as_posix())
        if not p.is_file() or rec is None or rec.get("sha256") != sha_file(p):
            prov_ok = False
            prov_bad.append({"name": name, "artifact": art})
    checks["artifact_provenance"] = prov_ok
    if not prov_ok:
        reasons.append("工件溯源不成立: %s" % prov_bad)

    # 5) 与保留答案比对
    expected = json.loads(pathlib.Path(expected_path).read_text(encoding="utf-8"))
    findings = (result or {}).get("findings") or {}
    matched, mismatched, unknown_ok, unknown_bad, missing = 0, [], 0, [], []
    for key, exp in expected.get("items", {}).items():
        got = findings.get(key)
        if not got:
            missing.append(key)
            continue
        if exp.get("observable") is False:
            if got.get("status") == "unknown":
                unknown_ok += 1
            else:
                unknown_bad.append({"key": key, "got": got.get("status")})
            continue
        if (got.get("status") == "ok"
                and int(got.get("entries", -1)) == int(exp.get("entries", -2))
                and int(got.get("errors", -1)) == int(exp.get("errors", -2))):
            matched += 1
        else:
            mismatched.append({"key": key, "got": got, "expected": exp})
    checks["expected_matched"] = not (mismatched or unknown_bad or missing)
    if missing:
        reasons.append("结果缺少条目: %s" % missing)
    if mismatched:
        reasons.append("与保留答案不符: %s" % [m["key"] for m in mismatched])
    if unknown_bad:
        reasons.append("可观测项被报成非 ok: %s" % [u["key"] for u in unknown_bad])

    # 6) 类别
    class_ok = (cls["class"] == AUTONOMOUS) if require_autonomous else True
    checks["class_autonomous"] = class_ok
    if not class_ok:
        reasons.append("类别为 %s，不满足自主要求" % cls["class"])

    hard_fail = [k for k in ("frozen_inputs_intact", "budget_observations",
                             "budget_seconds", "result_belongs_to_run",
                             "artifact_provenance", "class_autonomous")
                 if checks.get(k) is False]
    if hard_fail or mismatched or missing or unknown_bad:
        verdict = "fail"
    elif unknown_ok and not mismatched:
        verdict = "incomplete" if unknown_ok else "pass"
        if unknown_ok and len(findings) == unknown_ok:
            verdict = "incomplete"
        else:
            verdict = "pass"
    else:
        verdict = "pass"
    if unknown_ok:
        reasons.append("含 %d 项如实报告的 unknown（观测不足/预算不足）" % unknown_ok)

    return {"schema": "vulnmap.autonomy.verify.v1",
            "pack": str(pack_dir), "run_id": run.get("run_id"),
            "class": cls["class"], "class_reasons": cls["reasons"],
            "class_counts": cls["counts"], "checks": checks,
            "verdict": verdict, "reasons": reasons,
            "counts": {"matched": matched, "mismatched": len(mismatched),
                       "unknown_honest": unknown_ok, "missing": len(missing),
                       "observations": len(obs), "artifacts": len(recorded)}}
