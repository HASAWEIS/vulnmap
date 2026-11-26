"""V3 P4b 验收：研究报告进 CasePack、五指标对照、三类分离、负结果与确定性。

断言口径以 `/tmp/p4b-contract.md`（Lead 定稿契约）为准，**不**以实现为准：

1. **CasePack 收纳研究产物**（仅当任务有 `research.json`）：包内出现
   `research.json` + `research/{timeline,rounds,decisions,evidence_refs}.json` +
   `compare.json`；`research.json` 与源文件字节相同；`casepack.json` 的
   `research.sha256` 可由 `sha256sum` 复算；研究产物进 `content_sha256`；
   `reports` 台账的 sha 与 `content_sha256` 一致。
2. **没有研究产物就不伪造**：包仍只有原 9 个文件，`research.status == "absent"`，
   不写空轮次。
3. **五指标**：`time_to_first_crash / coverage / candidates / action_acceptance /
   repeat_rate` 的数值按契约公式给出；未知一律 `null` + `known=false` + `reason`，
   **不是 0**（0 是事实，未知是未知）。
4. **负结果保留**：coverage delta=0、无基准、指标不可比都进
   `negative_results` / `comparability.reasons`。
5. **不伪造裁决**：整包任何文件都不得出现 `"verified": true` / `"confirmed": true`；
   研究报告写 `verification_allowed=true` 时包级结论仍是“未验证”。
6. **三类分离**：`report.md` / `report.html` 各有“工程采纳”“漏洞验证”“研究进展”
   三个小节；研究循环的动作次数不出现在“漏洞验证”段当结论。
7. **确定性**：同输入两次打包，无时间戳的研究派生文件（timeline/rounds/
   decisions/evidence_refs）与 `compare.json` 字节相同；`report.html` 按既有 P3
   口径验证——同一批台账快照重渲染必得同一份字节，且包内的 html 就是它所记录
   快照的确定性函数（打包自身会 append `report.ready`，所以“连续两次打包”
   html 的事件数本就差 1，那不是不确定性）。
8. **冲突**：坏 JSON / schema 不认识 / 报告属于别的 task / 与 `research.mapped`
   登记的 `report_sha256` 不一致 → `CasePackError`，且不半写。

全部测试用临时 `PLATFORM_ROOT`，不碰仓库 `.platform`，也不改实现文件。
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (Budget, EventBus, EvidenceStore,  # noqa: E402
                            PlatformStore, TaskSpec, build_casepack)
from agent.platform.adaptive import cli as adaptive_cli  # noqa: E402
from agent.platform.adaptive.controller import (  # noqa: E402
    ControllerResult, PhaseRecord, RoundRecord)
from agent.platform.adaptive.policy import (Decision,  # noqa: E402
                                            VerificationRequest)
from agent.platform.adaptive.session import Diagnosis, Observation  # noqa: E402
from agent.platform.casepack import (FILES, SELF_FILE,  # noqa: E402
                                     CasePackError)
from agent.platform import casepack as casepack_mod  # noqa: E402

TASK = "task-v3-p4b"
OTHER_TASK = "task-v3-p4b-other"
DB = "platform.db"

#: 研究产物进包的相对路径（契约 §2）
RESEARCH_RELS = (
    "research.json",
    "research/timeline.json",
    "research/rounds.json",
    "research/decisions.json",
    "research/evidence_refs.json",
    "compare.json",
)

#: 研究派生文件：同一输入重算字节相同、且**不含时间戳**（契约 §0.5）
DERIVED_RELS = (
    "research/timeline.json",
    "research/rounds.json",
    "research/decisions.json",
    "research/evidence_refs.json",
    "compare.json",
)

#: `casepack.json` 的 research 块必须带的键（契约 §2）
RESEARCH_BLOCK_KEYS = ("status", "path", "sha256", "recorded_sha256", "match",
                       "task_id", "rounds", "executions", "candidates",
                       "stop_reason", "verification_allowed")

#: 三类分离的三个小节标题（契约 §2 + 任务书）
SECTION_TITLES = ("工程采纳", "漏洞验证", "研究进展")

CMP_SCHEMA = "vulnmap.adaptive.compare.v1"
CMP_METRICS = ("time_to_first_crash", "coverage", "candidates",
               "action_acceptance", "repeat_rate")

CHAIN = ("PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED",
         "RUNNING", "NO_REPRO")

EVIDENCE_BODY = b'{"exec_id":"exec-r001","stats":{"execs":120,"crashes":1}}\n'
EVIDENCE_SHA = hashlib.sha256(EVIDENCE_BODY).hexdigest()
UNREGISTERED_SHA = "b" * 64

#: 自裁决字段（任何 True 都是伪造；契约 §0.1）
FORGED_RE = re.compile(r'"\s*(?:verified|confirmed)\s*"\s*:\s*true', re.I)

#: 把“采纳/动作次数”写成结论的写法：漏洞验证段里一条都不许有（契约 §0.2）
COUNT_CLAIMS = (
    r"采纳[^。\n|]{0,4}[:：=]?\s*\d",
    r"动作(?:数|次数)?[^。\n|]{0,4}[:：=]?\s*\d",
    r"\d+\s*个动作",
    r"proposed\s*[:=]\s*\d",
)


# ------------------------------------------------------------------ 小工具
def _canonical_sha(files: list[dict]) -> str:
    listed = sorted(files, key=lambda x: x["path"])
    canonical = json.dumps(listed, ensure_ascii=False, indent=2,
                           sort_keys=True) + "\n"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _dump(doc) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compare():
    """延迟导入：`compare.py` 由 compare-dev 并行落地，缺文件时按“未落地”失败。"""
    return importlib.import_module("agent.platform.adaptive.compare")


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _md_section(text: str, title: str) -> str | None:
    """取 markdown 里 `## <title>` 到**同级/更高级**标题之间的正文。

    子标题（`### …`）属于本节内容，不算边界：研究进展的轮次表就在子标题下。
    """
    lines = text.splitlines()
    level = None
    start = None
    for index, line in enumerate(lines):
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if start is None:
            if heading and heading.group(1).startswith("##") \
                    and title in heading.group(2):
                level = len(heading.group(1))
                start = index + 1
            continue
        if heading and len(heading.group(1)) <= (level or 2):
            return "\n".join(lines[start:index])
    return "\n".join(lines[start:]) if start is not None else None


def _html_section(text: str, title: str) -> str | None:
    """取 HTML 里 `<h2>title…</h2>` 到下一个 `<h2>` 之间的正文。"""
    for match in re.finditer(r"<h2[^>]*>(.*?)</h2>(.*?)(?=<h2|</main>)",
                             text, re.S):
        heading = re.sub(r"<[^>]+>", "", match.group(1))
        if title in heading:
            return match.group(2)
    return None


def _html_titles(text: str) -> list[str]:
    return [re.sub(r"<[^>]+>", "", raw).strip()
            for raw in re.findall(r"<h2[^>]*>(.*?)</h2>", text, re.S)]


def _mentions_round(entry, round_no: int) -> bool:
    """负结果条目是否指向某一轮（显式 round 字段或 item 里带轮号）。"""
    if entry.get("round") == round_no:
        return True
    item = str(entry.get("item") or "")
    return bool(re.search(rf"(?:round|轮)[^0-9]{{0,3}}{round_no}\b", item))


def _first_diff(left: bytes, right: bytes) -> str:
    """两条字节的第一个差异行（给失败信息定位用）。"""
    a_lines = left.decode("utf-8", "replace").splitlines()
    b_lines = right.decode("utf-8", "replace").splitlines()
    for index, (a, b) in enumerate(zip(a_lines, b_lines), 1):
        if a != b:
            return f"line {index}: {a.strip()[:160]!r} → {b.strip()[:160]!r}"
    return f"行数不同：{len(a_lines)} → {len(b_lines)}"


def _rounds_of(doc):
    """rounds 文档既可能是裸列表，也可能是带 summary 的 dict。"""
    if isinstance(doc, list):
        return doc
    for key in ("rounds", "items"):
        value = doc.get(key)
        if isinstance(value, list):
            return value
    return []


# ------------------------------------------------------------------ fixtures
def _store(tmp_path) -> tuple[PlatformStore, EventBus, Path]:
    root = tmp_path / "platform"
    root.mkdir(parents=True, exist_ok=True)
    store = PlatformStore(root / DB)
    bus = EventBus(store)
    return store, bus, root


def _open_task(store: PlatformStore, task_id: str = TASK) -> None:
    spec = TaskSpec(task_id=task_id, benchmark="vulngym",
                    target=str(store.path.parent / "ws"), mode="fuzz",
                    budget=Budget(max_seconds=60, max_execs=1000,
                                  max_tokens=1000, max_turns=8))
    store.create_task(spec)
    for state in CHAIN:
        store.transition(task_id, state, reason="p4b fixture")


def _report_doc(task_id: str = TASK, *, state: str = "NO_REPRO",
                stop_reason: str = "repeated_facts",
                controller_state: str = "completed",
                verification_allowed: bool = False) -> dict:
    """用**真实 dataclass** 拼出 `ControllerResult.to_dict()` 形状的研究报告。

    事实安排（供断言复算）：

    - 3 轮，`facts_hash` 全同 → `repeats.same_facts = 2`；
    - 动作：applied 3 / rejected 1 / skipped 1 → `proposed = 5`，
      `action_acceptance = 3/5`；
    - `repeat_rate = (2 + 1) / (3 + 5) = 3/8`；
    - 第 3 轮 `compare` 给 coverage covered=5 / uncovered=7 / delta=0.0
      → delta 0 是**事实**，必须留在负结果里；
    - 报告不带任何时钟事实 → `time_to_first_crash` 未知（不能是 0）。
    """
    result = ControllerResult(status=controller_state, stop_reason=stop_reason)
    facts = "f" * 16

    first = RoundRecord(round_no=1, facts_hash=facts)
    first.diagnosis = Diagnosis(code="no_execution", severity="info",
                               reasons=("event_stream_empty",))
    first.actions = [
        {"action_id": "a-r01-1", "tool": "run_epoch", "status": "applied",
         "before_sha256": "", "after_sha256": "", "invalidations": [],
         "evidence_refs": [EVIDENCE_SHA], "candidates": 0, "error": None},
        {"action_id": "a-r01-2", "tool": "settle", "status": "rejected",
         "before_sha256": "", "after_sha256": "", "invalidations": [],
         "evidence_refs": [], "candidates": 0, "error": None},
    ]
    first.compare = {"status": "unknown", "comparable": "unknown",
                     "reason": "no_previous_observation",
                     "verdict": "not_evaluated"}
    first.note = "no_execution"

    second = RoundRecord(round_no=2, facts_hash=facts)
    second.diagnosis = Diagnosis(code="target_unreached", severity="warn",
                                reasons=("coverage_flat",))
    second.revision = "hr-0001"
    second.build = {"build_id": "b1", "status": "ok", "exit_code": 0,
                    "log_path": "/tmp/p4b-build.log"}
    second.smoke = {"smoke_id": "s1", "status": "passed", "kind": "script",
                    "exit_code": 0}
    second.actions = [
        {"action_id": "a-r02-1", "tool": "run_epoch", "status": "applied",
         "invalidations": ["execution_facts"],
         "evidence_refs": [EVIDENCE_SHA, UNREGISTERED_SHA], "candidates": 0,
         "error": None},
        {"action_id": "a-r02-2", "tool": "settle", "status": "skipped",
         "invalidations": [], "evidence_refs": [], "candidates": 0,
         "error": None},
    ]
    second.compare = {"status": "applied", "comparable": "true",
                      "reason": "same_build", "metric": "coverage", "delta": 0.0,
                      "verdict": "not_evaluated"}
    second.engineering = Decision(scope="engineering", adopt=False,
                                  subject="hr-0001",
                                  reasons=("smoke_same_coverage",))
    second.stop_reason = "repeated_facts"
    second.note = "no_repro"

    third = RoundRecord(round_no=3, facts_hash=facts)
    third.actions = [
        {"action_id": "a-r03-1", "tool": "build_overlay", "status": "applied",
         "invalidations": [], "evidence_refs": [EVIDENCE_SHA], "candidates": 0,
         "error": None},
    ]
    third.compare = {"status": "applied", "comparable": "true",
                     "reason": "same_build", "metric": "coverage",
                     "covered": 5, "uncovered": 7, "delta": 0.0,
                     "verdict": "not_evaluated"}
    third.engineering = Decision(scope="engineering", adopt=True,
                                 subject="hr-0001", reasons=("build_ok",))
    third.note = "no_repro"

    result.rounds = [first, second, third]
    result.timeline = []
    for round_no in (1, 2, 3):
        for phase, status in (("OBSERVE", "ok"), ("DIAGNOSE", "ok"),
                              ("PROPOSE", "ok"), ("AUTHORIZE", "ok"),
                              ("STAGE", "ok"), ("BUILD", "ok"),
                              ("SMOKE", "passed"), ("EXECUTE", "applied"),
                              ("COLLECT", "ok"),
                              ("COMPARE", "unknown" if round_no == 1
                               else "applied")):
            result.timeline.append(PhaseRecord(round_no, phase, status, ""))
    result.timeline.append(PhaseRecord(3, "STOP", "repeated",
                                       "facts seen 3x"))
    result.final = Observation(task_id=task_id, round_no=3, facts_hash=facts,
                               coverage={"planned": 12, "covered": 5,
                                         "uncovered": 7, "status": "partial"},
                               candidates=1, snapshot_status="applied")
    if verification_allowed:
        result.verification = VerificationRequest(
            allowed=True, blockers=(), candidate_refs=("a-r02-1",),
            diagnosis="candidate_ready")

    return {
        "schema": adaptive_cli.SCHEMA,
        "schema_version": adaptive_cli.SCHEMA_VERSION,
        "task_id": task_id, "benchmark": "vulngym", "campaign": "vulngym",
        "generated_at": "2026-11-20T00:00:00+00:00",
        "state": state, "controller_state": controller_state,
        "stop_reason": stop_reason, "max_rounds": 6,
        "rounds": len(result.rounds), "executions": 2,
        "executions_applied": 2, "executions_failed": 0, "candidates": 1,
        "observed_rounds": 3,
        "verification_allowed": bool(result.verification is not None
                                     and result.verification.allowed),
        "note": adaptive_cli.NOTE, "controller": result.to_dict(),
        "deps": {}, "budget": {}, "paths": {},
    }


def _baseline_events() -> list[dict]:
    """单次 fuzz 对照臂的事件事实：首个崩溃 1.5s、最终 coverage 12/28、2+1 候选。"""
    return [
        {"seq": 1, "ts": "2026-11-20T00:00:00+00:00",
         "event_type": "exec.started", "stage": "RUNNING",
         "payload": {"exec_id": "e-sf-1", "kind": "fuzz", "mode": "explore"}},
        {"seq": 2, "ts": "2026-11-20T00:00:02+00:00",
         "event_type": "exec.finished", "stage": "RUNNING",
         "payload": {"exec_id": "e-sf-1", "kind": "fuzz",
                     "outcome": "candidate", "candidates": 2,
                     "fuzz": {"execs": 120, "crashes": 1,
                              "first_crash_seconds": 1.5},
                     "coverage": {"planned": 40, "covered": 10,
                                  "uncovered": 30, "status": "partial"}}},
        {"seq": 3, "ts": "2026-11-20T00:00:09+00:00",
         "event_type": "exec.finished", "stage": "RUNNING",
         "payload": {"exec_id": "e-sf-2", "kind": "fuzz",
                     "outcome": "candidate", "candidates": 1,
                     "fuzz": {"execs": 200, "crashes": 1,
                              "first_crash_seconds": 1.5},
                     "coverage": {"planned": 40, "covered": 12,
                                  "uncovered": 28, "status": "partial"}}},
    ]


def _emit_research_session(store: PlatformStore, task_id: str, report: Path,
                           sha: str, *, with_events: bool = True) -> None:
    if not with_events:
        return
    store.append_event(task_id, "research.started", stage="RUNNING",
                       payload={"campaign": "vulngym", "max_rounds": 6})
    store.append_event(task_id, "exec.started", stage="RUNNING",
                       payload={"exec_id": "exec-r001-aaaa", "kind": "fuzz",
                                "mode": "explore"})
    store.append_event(task_id, "exec.finished", stage="RUNNING",
                       payload={"exec_id": "exec-r001-aaaa", "kind": "fuzz",
                                "outcome": "no_repro", "candidates": 0,
                                "fuzz": {"execs": 60},
                                "coverage": {"planned": 12, "covered": 5,
                                             "uncovered": 7,
                                             "status": "partial"},
                                "evidence_sha256": EVIDENCE_SHA})
    store.append_event(task_id, "research.mapped", stage="NO_REPRO", payload={
        "state": "NO_REPRO", "target_state": "NO_REPRO",
        "stop_reason": "repeated_facts", "rounds": 3, "executions": 2,
        "candidates": 1, "observed_rounds": 3, "verification_allowed": False,
        "report_path": str(report), "report_sha256": sha})


def _research_fixture(tmp_path, *, task_id: str = TASK,
                      verification_allowed: bool = False,
                      with_events: bool = True):
    """有研究产物的任务：research.json 落在 `<PLATFORM_ROOT>/research/<task>/`。"""
    store, bus, root = _store(tmp_path)
    _open_task(store, task_id)
    report = root / "research" / task_id / "research.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    text = _dump(_report_doc(task_id,
                             verification_allowed=verification_allowed))
    report.write_text(text, encoding="utf-8")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    _emit_research_session(store, task_id, report, sha, with_events=with_events)
    EvidenceStore(store, root / "evidence").put_bytes(
        task_id, "exec_stats", EVIDENCE_BODY, source_stage="RUNNING")
    return store, bus, root, report, sha


def _plain_fixture(tmp_path, *, task_id: str = TASK):
    """没有研究产物的任务（从未跑过研究循环）。"""
    store, bus, root = _store(tmp_path)
    _open_task(store, task_id)
    store.append_event(task_id, "exec.started", stage="RUNNING",
                       payload={"exec_id": "e-plain", "kind": "fuzz"})
    store.append_event(task_id, "exec.finished", stage="RUNNING",
                       payload={"exec_id": "e-plain", "kind": "fuzz",
                                "outcome": "no_repro", "candidates": 0,
                                "fuzz": {"execs": 10}})
    return store, bus, root


# ====================================================================== 1
def test_casepack_packs_research_artifacts_with_recomputable_hashes(tmp_path):
    """研究产物进包，且每一层哈希都能用 sha256 复算（契约 §2）。"""
    store, bus, root, report, sha = _research_fixture(tmp_path)
    pack = build_casepack(TASK, store, bus=bus)
    out = Path(pack["path"])
    listed = {item["path"]: item for item in pack["files"]}

    pack_doc = json.loads((out / SELF_FILE).read_text(encoding="utf-8"))

    # 1) 文件齐备：原 9 个 + 研究产物 6 个，且都进 files 列表
    for rel in FILES:
        assert (out / rel).is_file(), f"缺基础文件 {rel}"
    research_files = getattr(casepack_mod, "research_files", None)
    assert research_files is not None, "契约 §2 要求 casepack.research_files()"
    assert set(RESEARCH_RELS) <= set(research_files(pack_doc["research"]))
    for rel in RESEARCH_RELS:
        assert (out / rel).is_file(), f"缺研究产物 {rel}"
        assert rel in listed, f"{rel} 未进 casepack.json 的 files"
    assert set(FILES) <= set(listed)
    assert set(RESEARCH_RELS) <= set(listed)

    # 2) research.json 是原样复制（字节不动，含它自己的 generated_at）
    assert (out / "research.json").read_bytes() == report.read_bytes()
    assert listed["research.json"]["sha256"] == sha

    # 3) 每个文件的 sha256/size 与磁盘一致（可 sha256sum 复算）
    for rel, item in listed.items():
        path = out / rel
        assert path.is_file(), rel
        assert item["sha256"] == _sha(path), rel
        assert item["size"] == path.stat().st_size, rel

    # 4) casepack.json 的 research 块：登记哈希 = 源哈希 = 复算哈希
    block = pack_doc["research"]
    for key in RESEARCH_BLOCK_KEYS:
        assert key in block, f"research 块缺 {key}"
    assert block["status"] == "ok"
    assert block["task_id"] == TASK
    assert block["sha256"] == _sha(out / "research.json") == sha
    assert block["recorded_sha256"] == sha
    assert block["match"] is True
    assert block["rounds"] == 3
    assert block["executions"] == 2
    assert block["candidates"] == 1
    assert block["stop_reason"] == "repeated_facts"
    assert block["verification_allowed"] is False
    assert re.fullmatch(r"[0-9a-f]{64}", block["sha256"])

    # 5) content_sha256 覆盖研究产物，且可用 files 列表重算
    assert pack["content_sha256"] == _canonical_sha(pack["files"])
    assert pack_doc["content_sha256"] == pack["content_sha256"]
    assert listed["compare.json"]["sha256"] == _sha(out / "compare.json")

    # 6) reports 台账 sha 与 content_sha256 一致（台账 ↔ 磁盘唯一纽带）
    reports = store.list_reports(TASK)
    assert len(reports) == 1
    assert reports[0]["sha256"] == pack["content_sha256"]
    assert reports[0]["report_id"] == pack["report_id"]
    assert reports[0]["path"] == str(out)

    # 7) 研究产物自身的结构（契约 §2 的每项内容都在）
    timeline = json.loads((out / "research" / "timeline.json").read_text(
        encoding="utf-8"))
    assert isinstance(timeline.get("phases"), list) and timeline["phases"], timeline
    assert {"OBSERVE", "STOP"} <= {str(row.get("phase"))
                                   for row in timeline["phases"]}

    rounds = _rounds_of(json.loads((out / "research" / "rounds.json").read_text(
        encoding="utf-8")))
    assert [row["round"] for row in rounds] == [1, 2, 3]
    for row in rounds:
        assert {"diagnosis", "plan", "actions", "compare", "adopted",
                "reverted", "invalidations", "evidence_refs"} <= set(row), row
    assert rounds[1]["adopted"] is False
    assert rounds[2]["adopted"] is False          # 采纳账不冒充轮次结论

    decisions = json.loads((out / "research" / "decisions.json").read_text(
        encoding="utf-8"))
    # 工程采纳账（adoptions）在里面；每轮 engineering 决策的 scope 只能是 engineering
    assert [item for item in _walk(decisions) if "adoptions" in item], \
        "decisions.json 缺工程采纳账"
    scopes = {item["scope"] for item in _walk(decisions) if item.get("scope")}
    assert scopes and scopes <= {"engineering"}, scopes
    # 独立的 verification 分离段：只转录验证/复核计数，不掺研究动作数
    verif_sections = [item for item in _walk(decisions)
                      if {"verifications", "verified", "reviews"} <= set(item)]
    assert verif_sections, "decisions.json 缺 verification 分离段"
    assert verif_sections[0]["verifications"] == 0
    assert verif_sections[0]["verified"] == 0

    refs = json.loads((out / "research" / "evidence_refs.json").read_text(
        encoding="utf-8"))
    resolved_entries = [item for item in _walk(refs)
                        if EVIDENCE_SHA in [str(v) for v in item.values()]]
    assert resolved_entries, f"evidence_refs 未列出已登记证据 {EVIDENCE_SHA}"
    assert any(item.get("registered") and item.get("present")
               and item.get("hash_ok") for item in resolved_entries), \
        f"已登记证据未解析成命中：{resolved_entries}"
    missing_entries = [item for item in _walk(refs)
                       if UNREGISTERED_SHA in [str(v) for v in item.values()]]
    assert missing_entries, "未登记的证据引用也应列出（不静默丢弃）"
    assert not any(item.get("hash_ok") or item.get("registered")
                   for item in missing_entries), missing_entries
    assert any(item.get("reason") or item.get("status")
               for item in missing_entries), \
        f"未登记引用必须说明原因：{missing_entries}"

    # 8) compare.json 是契约 §1.4 的文档形状
    compare = json.loads((out / "compare.json").read_text(encoding="utf-8"))
    assert compare["schema"] == CMP_SCHEMA
    assert compare["schema_version"] == 1
    assert compare["verdict"] == "not_evaluated"
    assert [row["metric"] for row in compare["metrics"]] == list(CMP_METRICS)
    assert set(compare["arms"]) == {"research", "single_fuzz"}
    assert isinstance(compare["counts_are_not_intelligence"]["note"], str)
    assert isinstance(compare["negative_results"], list)
    assert isinstance(compare["comparability"]["reasons"], list)


# ====================================================================== 2
def test_casepack_without_research_keeps_base_files_and_reports_absent(tmp_path):
    """没有研究产物：包仍只有原 9 个文件，status=absent，不伪造空轮次。"""
    store, bus, root = _plain_fixture(tmp_path)
    pack = build_casepack(TASK, store, bus=bus)
    out = Path(pack["path"])

    assert {item["path"] for item in pack["files"]} == set(FILES)
    assert pack["content_sha256"] == _canonical_sha(pack["files"])

    pack_doc = json.loads((out / SELF_FILE).read_text(encoding="utf-8"))
    block = pack_doc["research"]
    for key in RESEARCH_BLOCK_KEYS:
        assert key in block, f"absent 时 research 块仍须有 {key}"
    assert block["status"] == "absent"
    assert block["sha256"] in ("", None), "absent 时不得编造 sha256"
    assert block["recorded_sha256"] in ("", None)
    # 没有产物就没有可对账的对象：match 只能是“未知”，不能自称匹配
    assert block["match"] in (False, None), block["match"]
    assert block["match"] is not True
    assert block["rounds"] in (0, None)
    assert block["executions"] in (0, None)
    assert block["candidates"] in (0, None)
    assert block["stop_reason"] in ("", None)
    assert block["verification_allowed"] is False

    # 不写研究产物，也不写空轮次
    assert not (out / "research").exists()
    for rel in RESEARCH_RELS:
        assert not (out / rel).exists(), f"absent 时不该出现 {rel}"
    assert "timeline" not in (out / SELF_FILE).read_text(encoding="utf-8")
    # 清单层面也不冒充：没有研究产物就没有额外文件
    assert tuple(casepack_mod.research_files(None)) == ()


# ====================================================================== 3
def test_compare_five_metrics_follow_contract_formulas():
    """五指标数值与契约公式一致；未知是 null+known=false+reason，不是 0。"""
    cmp = _compare()
    report = json.loads(_dump(_report_doc(TASK)))
    treatment = cmp.metrics_from_report(report, arm="research")

    assert treatment["arm"] == "research"
    assert treatment["arm_label"] == "研究循环"
    assert treatment["source"] == "report"
    assert treatment["rounds"] == 3
    assert treatment["observed_rounds"] == 3
    assert treatment["executions"] == 2
    assert treatment["candidates"] == 1
    assert treatment["stopped"] == "repeated_facts"

    # action_acceptance = applied / proposed，proposed 为五种状态之和
    assert treatment["actions"] == {"proposed": 5, "applied": 3, "rejected": 1,
                                    "skipped": 1, "failed": 0, "unknown": 0}
    assert treatment["action_acceptance"]["known"] is True
    assert treatment["action_acceptance"]["value"] == pytest.approx(3 / 5)
    assert treatment["action_acceptance"]["reason"] == ""

    # repeats / repeat_rate = (same_facts + skipped) / (rounds + proposed)
    assert treatment["repeats"]["same_facts"] == 2
    assert treatment["repeats"]["skipped_actions"] == 1
    assert treatment["repeat_rate"]["known"] is True
    assert treatment["repeat_rate"]["value"] == pytest.approx((2 + 1) / (3 + 5))
    assert treatment["repeat_rate"]["value"] <= 1.0

    # coverage 用报告事实（delta 允许 0.0：0 是事实）
    assert treatment["coverage"]["known"] is True
    assert treatment["coverage"]["covered"] == 5
    assert treatment["coverage"]["uncovered"] == 7
    assert treatment["coverage"]["delta"] == 0.0

    # 报告没有时钟事实 → 未知，不是 0
    ttfc = treatment["time_to_first_crash"]
    assert ttfc["known"] is False
    assert ttfc["value"] is None
    assert ttfc["value"] != 0
    assert ttfc["reason"], "未知必须给 reason"

    # ---- 对照臂：事件事实
    baseline = cmp.metrics_from_events(_baseline_events(), arm="single_fuzz")
    assert baseline["arm"] == "single_fuzz"
    assert baseline["arm_label"] == "单次 fuzz"
    assert baseline["source"] == "events"
    assert baseline["executions"] == 1
    assert baseline["candidates"] == 3          # 2 + 1
    assert baseline["time_to_first_crash"]["value"] == pytest.approx(1.5)
    assert baseline["time_to_first_crash"]["unit"] == "s"
    assert baseline["time_to_first_crash"]["metric_kind"] == "fuzz_seconds"
    assert baseline["coverage"]["covered"] == 12   # 取最后一条有 coverage 的
    assert baseline["coverage"]["uncovered"] == 28
    assert baseline["action_acceptance"]["known"] is False
    assert baseline["action_acceptance"]["value"] is None
    assert baseline["action_acceptance"]["reason"], "未知必须给 reason"
    assert baseline["repeat_rate"]["known"] is False
    assert baseline["repeat_rate"]["value"] is None
    assert baseline["repeat_rate"]["reason"] == "no_rounds_or_actions"

    # 报告臂确实“有轮次但一个动作都没提” → 契约 §1.2 的 no_actions
    idle = cmp.metrics_from_report(
        {"state": "NO_REPRO", "rounds": 1, "executions": 1, "candidates": 0,
         "stop_reason": "",
         "controller": {"rounds": [{"round": 1, "facts_hash": "a" * 16,
                                    "actions": []}], "timeline": []}},
        arm="research")
    assert idle["actions"]["proposed"] == 0
    assert idle["action_acceptance"]["known"] is False
    assert idle["action_acceptance"]["value"] is None
    assert idle["action_acceptance"]["reason"] == "no_actions"

    # ---- 合并：已 known 的字段不被更弱的事实覆盖
    merged = cmp.merge_metrics(treatment, _baseline_events())
    assert merged["source"] == "report+events"
    assert merged["coverage"]["covered"] == 5, "报告事实被事件覆盖了"
    assert merged["time_to_first_crash"]["value"] == pytest.approx(1.5)
    assert merged["time_to_first_crash"]["known"] is True

    # ---- 对照文档：五指标各一行，delta/ratio 按公式
    doc = cmp.compare_arms(baseline, treatment)
    assert doc["schema"] == CMP_SCHEMA and doc["schema_version"] == 1
    assert doc["verdict"] == "not_evaluated"
    assert set(doc["arms"]) == {"research", "single_fuzz"}
    assert [row["metric"] for row in doc["metrics"]] == list(CMP_METRICS)
    rows = {row["metric"]: row for row in doc["metrics"]}

    ttfc = rows["time_to_first_crash"]
    assert ttfc["baseline"] == pytest.approx(1.5)
    assert ttfc["treatment"] is None
    assert ttfc["delta"] is None and ttfc["ratio"] is None
    assert ttfc["known"] is False and ttfc["direction"] == "unknown"
    assert ttfc["reason"]

    cands = rows["candidates"]
    assert cands["baseline"] == 3 and cands["treatment"] == 1
    assert cands["delta"] == -2                              # treatment - baseline
    assert cands["ratio"] == pytest.approx(1 / 3)
    assert cands["direction"] == "worse"                     # 越高越好
    assert cands["known"] is True

    accept = rows["action_acceptance"]
    assert accept["treatment"] == pytest.approx(3 / 5)
    assert accept["baseline"] is None
    assert accept["known"] is False
    assert accept["delta"] is None, "未知一侧的 Δ 不能写成 0"

    repeat = rows["repeat_rate"]
    assert repeat["treatment"] == pytest.approx((2 + 1) / (3 + 5))
    assert repeat["baseline"] is None
    assert repeat["known"] is False

    coverage = rows["coverage"]
    assert coverage["known"] is True
    assert coverage["baseline"] is not None and coverage["treatment"] is not None
    if isinstance(coverage["baseline"], (int, float)):
        assert coverage["delta"] == pytest.approx(
            coverage["treatment"] - coverage["baseline"])

    # ---- 动作数只当工作量记账，不做能力推断
    # 研究循环臂有动作事实 → 精确计数；事件臂没有动作事实 → 只允许“未知(0/None)”，
    # 契约 §1.4 示例写 0，§0.3 又不许把未知填成 0：两者都算守住“不猜”。
    counts = doc["counts_are_not_intelligence"]
    assert counts["actions_proposed"]["research"] == 5
    assert counts["actions_proposed"]["single_fuzz"] in (0, None)
    assert counts["rounds"]["research"] == 3
    assert counts["rounds"]["single_fuzz"] in (0, None)
    assert counts["actions_per_candidate"]["research"] == pytest.approx(5 / 1)
    assert "不推断" in counts["note"] or "工作量" in counts["note"]
    # 对照文档自己也不产裁决：允许“verified/confirmed 不在此处产生”这类否定说明，
    # 但不许出现裁决字段
    dumped = json.dumps(doc, ensure_ascii=False)
    assert doc["note"]
    assert FORGED_RE.search(dumped) is None
    verdict_keys = {str(key).lower() for item in _walk(doc) for key in item}
    assert not (verdict_keys & {"verified", "confirmed"}), \
        verdict_keys & {"verified", "confirmed"}


# ====================================================================== 4
def test_compare_keeps_negative_results_and_comparability_reasons():
    """delta=0 / 无基准 / 指标不可比：全部留在文档里（契约 §1.5、§0.4）。"""
    cmp = _compare()

    # 1) coverage delta = 0 的轮次进 rounds 与 negative_results
    doc = cmp.build_compare(research_report=_report_doc(TASK))
    assert doc["comparable"] is False
    assert "no_baseline" in doc["comparability"]["reasons"]
    assert "no_baseline" in (doc.get("notes") or [])
    rounds = {row["round"]: row for row in doc["rounds"]}
    assert sorted(rounds) == [1, 2, 3]
    assert rounds[1]["coverage_delta"] is None
    assert rounds[2]["coverage_delta"] == 0.0
    assert rounds[3]["coverage_delta"] == 0.0
    assert rounds[2]["gain"] == "none"
    assert rounds[3]["gain"] == "none"

    negative = doc["negative_results"]
    assert negative, "负结果一条都不许丢"
    assert all(entry.get("reason") for entry in negative), negative
    zero_rows = [entry for entry in negative
                 if _mentions_round(entry, 2) or _mentions_round(entry, 3)]
    assert zero_rows, f"coverage delta=0 的轮次未进负结果：{negative}"
    assert any(token in str(entry.get("reason") or "")
               for entry in zero_rows
               for token in ("coverage", "delta", "gain", "zero")), zero_rows
    unknown_items = [str(entry.get("item") or "") for entry in negative]
    assert "time_to_first_crash" in unknown_items, \
        f"未知指标未进负结果：{unknown_items}"
    assert "compare" in unknown_items, f"无基准/不可比未进负结果：{unknown_items}"

    # 2) 两侧都拿不到事实 → 没有可比指标
    empty_base = cmp.metrics_from_report({}, arm="single_fuzz")
    empty_treat = cmp.metrics_from_report({}, arm="research")
    empty = cmp.compare_arms(empty_base, empty_treat)
    assert empty["comparable"] is False
    assert "no_shared_metric" in empty["comparability"]["reasons"]
    assert all(row["known"] is False for row in empty["metrics"])
    assert all(row["delta"] is None for row in empty["metrics"])
    assert all(row["ratio"] is None for row in empty["metrics"])

    # 3) 指标不可比：fuzz_seconds vs wall_clock_seconds
    research_events = [
        {"seq": 1, "ts": "2026-11-20T00:00:00+00:00",
         "event_type": "exec.started", "stage": "RUNNING",
         "payload": {"exec_id": "exec-r001", "kind": "fuzz"}},
        {"seq": 2, "ts": "2026-11-20T00:00:03+00:00",
         "event_type": "exec.finished", "stage": "RUNNING",
         "payload": {"exec_id": "exec-r001", "kind": "fuzz",
                     "outcome": "candidate", "candidates": 1,
                     "fuzz": {"execs": 50}, "coverage": {}}},
    ]
    baseline = cmp.metrics_from_events(_baseline_events(), arm="single_fuzz")
    treatment = cmp.metrics_from_events(research_events, arm="research")
    assert treatment["time_to_first_crash"]["metric_kind"] == "wall_clock_seconds"
    assert treatment["time_to_first_crash"]["value"] == pytest.approx(3.0)
    # 事件侧没有 coverage 事实 → 全 None + reason，"未知"不是 0
    assert treatment["coverage"]["known"] is False
    assert treatment["coverage"]["covered"] is None
    assert treatment["coverage"]["delta"] is None
    assert treatment["coverage"]["reason"] == "no_coverage_facts"

    mixed = cmp.compare_arms(baseline, treatment)
    row = {item["metric"]: item for item in mixed["metrics"]}[
        "time_to_first_crash"]
    assert row["known"] is False
    assert "metric_kind_mismatch" in str(row["reason"])
    assert row["delta"] is None
    assert row["direction"] == "unknown"


# ====================================================================== 5
def test_casepack_never_forges_verified_or_confirmed(tmp_path):
    """报告说 verification_allowed=true，包级结论仍是“未验证”（契约 §0.1）。"""
    store, bus, root, report, sha = _research_fixture(
        tmp_path, verification_allowed=True)
    pack = build_casepack(TASK, store, bus=bus)
    out = Path(pack["path"])

    pack_doc = json.loads((out / SELF_FILE).read_text(encoding="utf-8"))
    # 报告事实照抄（allowed 只是“可以去验证”）
    assert pack_doc["research"]["verification_allowed"] is True
    assert report.read_text(encoding="utf-8").count('"allowed": true') >= 1
    # 但包级结论仍然是未验证：没有 run_verification 就没有 verified
    assert pack["verdict"]["benchmark_verified"] is False
    assert pack["verdict"]["verified"] == 0
    assert pack["verdict"]["accepted_by_review"] is False
    assert pack_doc["verdict"]["benchmark_verified"] is False
    assert pack_doc["verdict"]["verified"] == 0

    # 整包所有文件（含 report.md/html、compare.json、decisions.json）都不得
    # 出现自裁决字段
    texts: dict[str, str] = {}
    for path in sorted(out.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(out))
            texts[rel] = path.read_text(encoding="utf-8", errors="replace")
    assert "research.json" in texts
    for rel, text in texts.items():
        hit = FORGED_RE.search(text)
        assert hit is None, f"{rel} 出现自裁决字段：{hit.group(0) if hit else ''}"
        assert '"status": "verified"' not in text, f"{rel} 凭空写 verified 状态"
        # “confirmed” 只允许出现在“不在此处产生”这类否定说明里
        for line in text.splitlines():
            if "confirmed" not in line.lower():
                continue
            assert any(token in line for token in
                       ("不", "未", "无", "非", "not ", "never", "≠")), \
                f"{rel} 把 confirmed 当结论写：{line.strip()}"

    # 网页上 benchmark_verified 渲染成“否”，且研究段不产裁决
    html = texts["report.html"]
    index = html.find("benchmark_verified")
    assert index >= 0
    assert "否" in html[index:index + 240], html[index:index + 240]
    for rel in ("compare.json", "research/decisions.json"):
        blob = texts[rel]
        assert '"verified": true' not in blob
        assert '"confirmed": true' not in blob


# ====================================================================== 6
def test_report_sections_separate_engineering_verification_and_progress(tmp_path):
    """三类分离：三个小节各就各位；动作次数不进“漏洞验证”当结论。"""
    store, bus, root, report, sha = _research_fixture(tmp_path)
    pack = build_casepack(TASK, store, bus=bus)
    out = Path(pack["path"])
    md = (out / "report.md").read_text(encoding="utf-8")
    html = (out / "report.html").read_text(encoding="utf-8")

    for title in SECTION_TITLES:
        assert _md_section(md, title) is not None, f"report.md 缺小节：{title}"
    titles = _html_titles(html)
    for title in SECTION_TITLES:
        assert any(title in heading for heading in titles), \
            f"report.html 缺小节：{title}（实际 {titles}）"

    # “漏洞验证”段只谈验证：不接受率/重复率细节，不把工程采纳或研究动作次数
    # 写成结论（允许出现“这些不在此列”这类否定说明）
    verif_md = _md_section(md, "漏洞验证")
    verif_html = _html_section(html, "漏洞验证")
    assert verif_md is not None and verif_html is not None
    for section, tag in ((verif_md, "md"), (verif_html, "html")):
        for needle in ("action_acceptance", "repeat_rate", "接受率"):
            assert needle not in section, f"漏洞验证段({tag})混入 {needle}"
        for pattern in COUNT_CLAIMS:
            hit = re.search(pattern, section)
            assert hit is None, (
                f"漏洞验证段({tag})把动作/采纳次数当结论：{hit.group(0) if hit else ''}")
        # 结论性的 verified 也不许在此段凭空出现（本 fixture 一条验证都没有）
        assert "verified 1" not in section and "verified：1" not in section

    # 动作次数（工作量）应在“研究进展”段，且标了“不推断”
    progress_md = _md_section(md, "研究进展")
    progress_html = _html_section(html, "研究进展")
    assert progress_md is not None and progress_html is not None
    assert re.search(r"轮次[^。\n]{0,30}\d", progress_md), progress_md
    assert re.search(r"轮次[^。\n]{0,30}\d", progress_html), progress_html
    assert "动作" in progress_md and "动作" in progress_html
    assert ("不推断" in progress_md or "工作量" in progress_md
            or "不推断" in progress_html or "工作量" in progress_html)

    # “工程采纳”段来自 adoptions/engineering 决策，不是研究结论
    adopt_md = _md_section(md, "工程采纳")
    assert adopt_md is not None
    assert "engineering" in adopt_md or "采纳" in adopt_md
    assert "confirmed" not in adopt_md.lower()
    assert "verified" not in adopt_md.lower()


# ====================================================================== 7
def _pack_snapshot(out: Path) -> dict:
    """把包**自己记录**的快照读回来：渲染它应当与包内文件逐字相同。

    口径沿用 P3：`report.html` 是“同一批台账快照”的确定性函数，
    不是“同一任务连续打包字节相同”（打包自身会 append `report.ready`）。
    """
    def read(rel: str):
        return json.loads((out / rel).read_text(encoding="utf-8"))

    pack_doc = read(SELF_FILE)
    return {
        "task": read("task.json"),
        "state": read("state.json"),
        "candidates": read("candidates.json"),
        "verifications": read("verifications.json"),
        "reviews": read("reviews.json"),
        "manifest": read("evidence/manifest.json"),
        "verdict": pack_doc["verdict"],
        "research": {
            "block": pack_doc["research"],
            "timeline": read("research/timeline.json"),
            "rounds": read("research/rounds.json"),
            "decisions": read("research/decisions.json"),
            "evidence_refs": read("research/evidence_refs.json"),
            "compare": read("compare.json"),
        },
    }


def test_research_artifacts_and_html_are_deterministic(tmp_path):
    """派生文档字节可复算；report.html 是所记录快照的确定性函数（P3 口径）。"""
    store, bus, root, report, sha = _research_fixture(tmp_path)
    first = build_casepack(TASK, store, bus=bus)
    out = Path(first["path"])
    # 1) 无时间戳的派生文档 + research.json（原样复制）两次打包必须字节相同
    rels = DERIVED_RELS + ("research.json",)
    snap = {rel: (out / rel).read_bytes() for rel in rels}

    second = build_casepack(TASK, store, bus=bus)
    assert Path(second["path"]) == out
    for rel in rels:
        now_bytes = (out / rel).read_bytes()
        if now_bytes != snap[rel]:
            pytest.fail(f"{rel} 两次打包字节不同（派生文件必须确定性重算）："
                        + _first_diff(snap[rel], now_bytes))

    # 派生文件不带时间戳（research.json 除外：它是原样复制的源文件）
    for rel in DERIVED_RELS:
        text = snap[rel].decode("utf-8")
        assert "generated_at" not in text, f"{rel} 含时间戳"
        assert '"at"' not in text, f"{rel} 含时间戳字段"
    assert "generated_at" in snap["research.json"].decode("utf-8")

    # 2) report.html：同一批入参渲染两次必得同一份字节
    args = _pack_snapshot(out)
    render = casepack_mod.render_report_html
    html_once = render(args["task"], args["state"], args["candidates"],
                       args["verifications"], args["reviews"],
                       args["manifest"], args["verdict"], args["research"])
    html_twice = render(args["task"], args["state"], args["candidates"],
                        args["verifications"], args["reviews"],
                        args["manifest"], args["verdict"], args["research"])
    assert html_once == html_twice, "同一批快照渲染两次字节不同（不可复算）"

    # 包里的 report.html 必须**就是**它所记录快照的确定性函数：
    # 用第二个包自身的 state / manifest / research 重渲染，逐字相同。
    packed_html = (out / "report.html").read_text(encoding="utf-8")
    assert packed_html == html_once, (
        "包内 report.html 与“用包自身记录的快照重渲染”不一致："
        + _first_diff(packed_html.encode("utf-8"), html_once.encode("utf-8")))
    # 事件数来自台账快照（这也是连续打包时唯一会变的那一格，不是时间戳）
    assert (f'<dt>事件数</dt><dd>{args["state"]["events"]}</dd>'
            in html_once)
    assert "<script" not in html_once.lower()

    # 3) 第二次打包的内容哈希与台账也对得上（不是只有文件没变）
    assert second["content_sha256"] == _canonical_sha(second["files"])
    assert store.list_reports(TASK)[-1]["sha256"] == second["content_sha256"]


# ====================================================================== 8
@pytest.mark.parametrize("case", ["bad_json", "unknown_schema", "foreign_task",
                                  "hash_mismatch"])
def test_casepack_rejects_conflicting_research_artifacts(tmp_path, case):
    """四类冲突一律 CasePackError，且不半写（契约 §2）。"""
    store, bus, root, report, sha = _research_fixture(tmp_path)
    out = root / "casepacks" / TASK

    if case == "bad_json":
        report.write_text("{not json", encoding="utf-8")
        needles = ("json",)
    elif case == "unknown_schema":
        report.write_text(_dump({"schema": "vulnmap.research.run.v999",
                                 "task_id": TASK}), encoding="utf-8")
        needles = ("schema",)
    elif case == "foreign_task":
        report.write_text(_dump(_report_doc(OTHER_TASK)), encoding="utf-8")
        needles = ("任务", "task", "belong")
    else:                                   # 与 research.mapped 登记的哈希不一致
        doc = _report_doc(TASK)
        doc["note"] = doc["note"] + " tampered-after-mapping"
        report.write_text(_dump(doc), encoding="utf-8")
        assert _sha(report) != sha
        needles = ("sha256", "hash", "digest", "哈希")

    with pytest.raises(CasePackError) as excinfo:
        build_casepack(TASK, store, bus=bus)
    message = str(excinfo.value)
    assert message.strip(), "CasePackError 必须给出可读原因"
    assert any(needle.lower() in message.lower() for needle in needles), \
        (case, message)

    # 不半写：没有 casepack.json、没有台账、任务状态没被推着走
    assert not (out / SELF_FILE).exists()
    assert store.list_reports(TASK) == []
    assert store.get_task(TASK)["state"] in ("REVIEW", "NO_REPRO", "REPORTED")
