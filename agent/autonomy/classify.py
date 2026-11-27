"""按运行事实把一次运行分到三类，并给出理由。

只看事实，不看报告怎么写：
- 有介入流水（人提供输入/提示/修正） -> 至多 agent_assisted
- 工件哈希等于"开始时可见材料"的哈希 -> 视为搬运既有文件，降为 manual_baseline
- 工件产生时刻早于 run.started_at -> 视为旧文件，降级
- 无介入、工件均为本次产生 -> agent_autonomous

预算超限由 verify.py 判负，这里只做分类。
"""
from __future__ import annotations

from .pack import RunPack

MANUAL = "manual_baseline"
ASSISTED = "agent_assisted"
AUTONOMOUS = "agent_autonomous"

#: 视为"关键输入介入"的干预类型（其余如"只读观察"不影响自主性）
KEY_INPUT_KINDS = {"provided_input", "edited_input", "supplied_answer",
                   "hint_branch", "fixed_output", "replaced_artifact"}


def classify(pack: RunPack) -> dict:
    run = pack.run()
    frozen = pack.frozen().get("files") or {}
    frozen_hashes = {v.get("sha256") for v in frozen.values() if v.get("sha256")}
    interventions = pack.interventions()
    artifacts = pack.artifacts()

    reasons = []
    kind = AUTONOMOUS

    key_hits = [i for i in interventions if i.get("kind") in KEY_INPUT_KINDS]
    other_hits = [i for i in interventions if i.get("kind") not in KEY_INPUT_KINDS]

    carried = [a for a in artifacts if a.get("sha256") in frozen_hashes]
    stale = [a for a in artifacts
             if float(a.get("ts") or 0) < float(run.get("started_at") or 0)]
    foreign = [a for a in artifacts if a.get("producer") not in ("agent",)]

    if carried:
        reasons.append("工件与开始时可见材料哈希相同（搬运既有文件）: %s"
                       % [a.get("name") for a in carried])
        kind = MANUAL
    if key_hits:
        reasons.append("存在关键输入类人工介入: %s" % [i.get("kind") for i in key_hits])
        if kind != MANUAL:
            kind = ASSISTED
    if stale:
        reasons.append("工件产生时刻早于本次运行开始: %s" % [a.get("name") for a in stale])
        if kind != MANUAL:
            kind = MANUAL
    if foreign:
        reasons.append("工件由非 Agent 产生: %s" % [a.get("producer") for a in foreign])
        kind = MANUAL
    if other_hits and kind == AUTONOMOUS:
        reasons.append("存在非关键介入（记录保留）: %s" % [i.get("kind") for i in other_hits])

    if not artifacts:
        reasons.append("无工件记录，无法主张任何完成")
        kind = MANUAL

    return {"class": kind, "reasons": reasons,
            "counts": {"interventions": len(interventions),
                       "key_interventions": len(key_hits),
                       "artifacts": len(artifacts),
                       "carried": len(carried), "stale": len(stale),
                       "foreign": len(foreign)}}
