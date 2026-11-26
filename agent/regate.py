"""判据重算（re-gate）：用**已落盘的证据**重新跑一遍判据代码。

背景：`artifacts/verify/result.json` 里的 `root_cause` 是判据代码在**那一次运行**
算出来的快照。判据本身修好了（例如帧解析器丢掉含逗号的 C++ 签名），
但重跑 verify 需要 docker 镜像与真实执行；镜像已经不在本机时，
既不能假装重跑过，也不能让修好的判据永远不生效。

本模块的边界，写死在这里免得被误用：
- **只读** `artifacts/verify/result.json` 与它指向的原始日志（logs/*.log 字节不动）；
- 不改 `vul_exit` / `fix_exit` / `verdict` / `poc` —— 双端观测值只能由真跑产生；
- 只重算 `root_cause`（matched / confidence / reason / evidence）与 `cwe_by_crash`；
- 重算结果比原判**更弱**时不采纳（记 conflict），避免判据改动顺手把已通过的案例翻掉；
- 结果里带 `rejudged`  provenance（日志 sha256、解析帧数、判据版本），可逐条复算。
"""
from __future__ import annotations

import json
from pathlib import Path

from .diagnostics import check_root_cause, cwe_for_crash, parse_diagnosis
from .util import sha256_file

CONFIDENCE_RANK = {"none": 0, "inconclusive": 1, "weak": 2, "strong": 3}

# 判据版本：改动 diagnostics 的帧解析/CWE 映射时同步 +1，provenance 里会记下来
CRITERIA_VERSION = "diagnostics-frames-v2+container-overflow-v1"


def _read_text(p: Path) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return p.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return p.read_bytes().decode("utf-8", "replace")


def _sink_for(verify: dict, claim: dict) -> tuple[dict, str]:
    """重算用的 sink：verify 落盘的崩溃点优先，其次 locate claim（与 report 同序）。"""
    ev = (verify.get("root_cause") or {}).get("evidence") or {}
    sink = ev.get("sink") or {}
    if isinstance(sink, dict) and sink.get("file"):
        return dict(sink), "verify.root_cause.evidence.sink"
    hit = ev.get("text_hit") or {}
    if isinstance(hit, dict) and hit.get("file"):
        return {"file": hit.get("file"), "line": hit.get("line")}, \
               "verify.root_cause.evidence.text_hit"
    s = (claim or {}).get("sink") or {}
    if isinstance(s, dict) and s.get("file"):
        return dict(s), "locate.claim.sink"
    return {}, "none"


def rejudge_root_cause(ws: Path, verify: dict, claim: dict | None = None) -> dict:
    """用当前判据从落盘证据重算 root_cause。返回 applied/root_cause/provenance。"""
    ws = Path(ws)
    claim = claim or {}
    old = dict(verify.get("root_cause") or {})
    old_conf = str(old.get("confidence") or "none")
    sink, sink_source = _sink_for(verify, claim)
    subject = (claim.get("subject") or (verify.get("claim_used") or {}).get("subject")
               or sink.get("function") or sink.get("symbol") or "")

    rel_log = str((verify.get("vul") or {}).get("log") or "").strip()
    log_path = ws / rel_log if rel_log else None
    out = {
        "applied": False,
        "criteria": CRITERIA_VERSION,
        "previous": {"matched": old.get("matched"), "confidence": old_conf,
                     "reason": old.get("reason", "")},
        "reason": "",
        "provenance": {"log": rel_log, "sink_source": sink_source, "subject": subject},
    }
    if not log_path or not log_path.exists():
        out["reason"] = "no_persisted_log"
        return out
    text = _read_text(log_path)
    diag = parse_diagnosis(text)
    if not diag.is_defect:
        # 落盘日志里没有缺陷报告，而已落盘判定是 weak/strong：这是判据与证据
        # 对不上的信号，必须报冲突交人工，不能静默保留也不能静默降级
        out["reason"] = "no_defect_diagnosis_in_log"
        if CONFIDENCE_RANK.get(old_conf, 0) >= CONFIDENCE_RANK["weak"]:
            out["conflict"] = True
        return out
    claimed = verify.get("cwe_by_crash") or claim.get("cwe") or ""
    claim_cwe = cwe_for_crash(diag.kind, diag.write, claimed) or claimed
    cons = check_root_cause(diag, sink, claim_cwe, sink_function=subject)
    new_conf = cons.confidence
    out["provenance"].update({
        "log_sha256": sha256_file(log_path),
        "frames_parsed": len(diag.frames),
        "user_frames": len(diag.user_frames),
        "kind": diag.kind, "write": diag.write,
    })
    out["candidate"] = {"matched": cons.matched, "confidence": new_conf,
                        "reason": cons.reason, "evidence": cons.evidence,
                        "cwe_by_crash": claim_cwe}
    if CONFIDENCE_RANK.get(new_conf, -1) < CONFIDENCE_RANK.get(old_conf, 0):
        # 判据重算只会让结论更保守时不动已落盘判定：记冲突，交人工
        out["reason"] = f"rejudge_weaker:{old_conf}->{new_conf}"
        out["conflict"] = True
        return out
    if (cons.matched, new_conf, cons.reason) == (bool(old.get("matched")), old_conf,
                                                 old.get("reason")):
        out["reason"] = "unchanged"
        return out
    out["applied"] = True
    out["reason"] = f"rejudged:{old_conf}->{new_conf}"
    out["root_cause"] = {"matched": cons.matched, "confidence": new_conf,
                         "reason": cons.reason, "evidence": cons.evidence,
                         "provenance": old.get("provenance") or {},
                         "rejudged": {"criteria": CRITERIA_VERSION,
                                      "previous": out["previous"],
                                      "log": rel_log,
                                      "log_sha256": out["provenance"]["log_sha256"],
                                      "frames_parsed": out["provenance"]["frames_parsed"]}}
    out["cwe_by_crash"] = claim_cwe
    return out


def apply_rejudge(verify: dict, rejudge: dict) -> dict:
    """把重算结果落到 verify dict（新 dict）：只动 root_cause / cwe_by_crash。"""
    out = dict(verify or {})
    if not rejudge.get("applied"):
        return out
    out["root_cause"] = rejudge["root_cause"]
    out["cwe_by_crash"] = rejudge.get("cwe_by_crash") or out.get("cwe_by_crash")
    return out


def rejudge_summary(rejudge: dict) -> dict:
    """写进 case.json 的精简版（不含大段 evidence）。"""
    keep = ("applied", "criteria", "previous", "reason", "conflict")
    out = {k: rejudge.get(k) for k in keep if rejudge.get(k) not in (None, "")}
    out["provenance"] = {k: rejudge.get("provenance", {}).get(k)
                         for k in ("log", "log_sha256", "frames_parsed", "user_frames",
                                   "sink_source", "subject", "kind", "write")}
    return json.loads(json.dumps(out, ensure_ascii=False))
