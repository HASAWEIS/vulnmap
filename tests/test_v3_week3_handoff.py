r"""V3 第 3 周回归：原始执行证据 → 待复核项 → 独立复核者的**交接**（V3-019）。

被测实现：`agent/platform/adaptive/handoff.py`（口径见模块 docstring 与本文件
各组说明）、`agent/platform/store.py` 的 W3 方法、`agent/platform/verify.py`
的只读钩子 `raw_execution_refs()` / `raw_handoff_view()`、`casepack.py` 的
`handoff.json` 接入。

夹具全部自己搭（不 import 其它测试模块）：真 `PlatformStore` + 真
`EvidenceStore`（内容寻址落盘）+ 真 `EventBus`（`exec.started/exec.finished`）+
真 `RevisionStore`/`HarnessRevision` 账本。封存记录的 "原始记录" 是**盘上的字节**，
所以本文件里凡是涉及 `evidence_sha256` 的断言都回到磁盘复算，不读内存对象。

六组用例：

| 组 | 用例 | 用的是什么事实 / 断言什么 |
|---|---|---|
| 1 成功链路 | `test_seal_then_review_keeps_one_identity` | 一次真执行（事件 + 证据 blob + revision 账本）→ `open_pending()` 封存出 `HI1/pending` → `raw_handoff_view()` 只读钩子 → `review_item()` 判 `accepted`。断言 record/item/verdict 的 `run_id`/`execution_id`/`evidence_sha256` 三方完全一致；盘上 blob 的 sha256 就是 `evidence_sha256`；`store.summary()["handoff"]` 计数与 `handoff_view` 一致 |
| 2a 错任务 | `test_wrong_task_evidence_is_rejected` | 同一条证据登记到**另一个** task，并伪造该 task 的待复核项 → 记录完好但属于别人：`rejected` + `wrong_task`，结论为空 |
| 2b 旧版本 | `test_stale_revision_is_rejected` / `test_stale_policy_version_is_rejected` | 记录写 r1、账本 head 已是 r2 → `rejected` + `stale_revision`；记录写 `v3-w2`、复核期望 `v3-w3` → `rejected` + `stale_version` |
| 2c 缺证据 | `test_missing_evidence_file_needs_evidence` / `test_evidence_not_in_store_needs_evidence` | 删掉盘上 blob → `needs_evidence` + `evidence_file_missing`；`evidence_sha256` 不在库里 → `needs_evidence`；两者都不进 `conclusions` |
| 3 摘要不被接受 | `test_verifier_rejects_model_summary_argument` / `test_raw_record_carrying_summary_is_not_accepted` | 给 verifier 递 `summary` → `HandoffError: model_summary_not_accepted…`；原始记录里带模型摘要字段 → `raw_source_only` 检查失败、不采纳、不进结论 |
| 4 CasePack 可追溯 | `test_casepack_carries_handoff_trace` | 一个 accepted + 一个 pending + 一个 needs_evidence → `handoff.json` 在 `casepack.FILES` 且可 `json.load`；`conclusions` 只含 accepted；`pack["verdict"]["handoff"]` 计数与视图一致；`report.md` 里逐行出现项 id 与状态，`report.html` 里出现交接计数与 `needs_evidence`（并指向 `handoff.json`） |
| 5 隔离/授权验收门 | `test_proposal_gate_unit_requires_both_acceptances` / `test_controller_stops_at_advisory_only_before_acceptance` / `test_controller_proceeds_after_acceptance` | 单元：`metadata` 未验收 → `advisory`，严格解析下 `"false"` 仍是 `advisory`，两者都验收 → `apply`；集成：真跑 `ResearchController`（`fixtures_config` 工作区 + 只报事实的 runner）——未验收 `stop_reason=="advisory_only"`、无新 revision、`adoptions.jsonl` 无新增、runner 一次都没被调用；验收后不再出现 `advisory_only` |
| 6 词表对账 | `test_status_vocabularies_match_handoff_module` | `store.REVIEW_ITEM_STATUSES == handoff.STATUSES`；`HANDOFF_VERDICT_STATUSES == handoff.TERMINAL_STATUSES` |

核心口径（**不因绿灯放宽**）：身份不对/任务不对/版本不对 → `rejected`；
证据不在库/文件缺失 → `needs_evidence`；只有 `accepted` 项进 `conclusions`；
模型摘要永远不进复核入口。
"""
from __future__ import annotations

import json
import shutil
import sys
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import casepack as casepack_mod  # noqa: E402
from agent.platform import verify as verify_mod  # noqa: E402
from agent.platform.adaptive import handoff  # noqa: E402
from agent.platform.adaptive.controller import ResearchController  # noqa: E402
from agent.platform.adaptive.revision import (  # noqa: E402
    HarnessRevision,
    RevisionStore,
    manifest_of,
)
from agent.platform.adaptive.workspace import TaskWorkspace  # noqa: E402
from agent.platform.events import EventBus  # noqa: E402
from agent.platform.evidence import EvidenceStore  # noqa: E402
from agent.platform.program import ProgramIndex  # noqa: E402
from agent.platform.store import PlatformStore  # noqa: E402
from agent.platform.task import TRANSITIONS, Budget, TaskSpec  # noqa: E402

TASK = "task-v3-w3-handoff"
OTHER = "task-v3-w3-other"
PY = sys.executable
FIXTURES = ROOT / "tests" / "fixtures_config"

#: 执行侧口径：策略版本与 plan 哈希（record 复算 run_id 用得到）
POLICY = "v3-w3"
PLAN_SHA = "p" * 64
EXEC_ID = "exec-0001"

#: `fixtures_config` 的构建/冒烟命令（周 2 夹具口径；本轮 plan 没有 revision，
#: 所以这两条命令在下面的集成用例里不会被真跑）
BUILD_COMMAND = [PY, "-m", "py_compile", "target.py", "runner.py"]
SMOKE_COMMAND = [PY, "target.py", "--config", "config/active.json",
                 "--probe", "smoke.jsonl"]


# ------------------------------------------------------------------ 通用小工具
def _sha_of(path: Path) -> str:
    return sha256(Path(path).read_bytes()).hexdigest()


def _new_store(base: Path, *, task_id: str = TASK,
               metadata: dict | None = None) -> PlatformStore:
    store = PlatformStore(base / "platform.db")
    store.create_task(TaskSpec(
        task_id=task_id, benchmark="vulngym", target="http://127.0.0.1:1/x",
        budget=Budget(max_seconds=60, max_execs=100, max_tokens=1000,
                      max_turns=8),
        metadata=metadata or {}))
    return store


def _revision_store(base: Path) -> RevisionStore:
    """真 revision 账本：一条 `r1` 并置为 head。"""
    revisions = RevisionStore(base / "revisions")
    first = HarnessRevision.create(manifest=manifest_of({"a.py": b"1"}),
                                   reason="r1")
    revisions.add(first)
    revisions.set_current(first.revision_id)
    return revisions


def _revision(revisions: RevisionStore, name: str,
              parent: HarnessRevision | None = None) -> HarnessRevision:
    revision = HarnessRevision.create(
        manifest=manifest_of({f"{name}.py": name.encode()}),
        reason=name, parent=parent)
    return revisions.add(revision)


def _execution(store: PlatformStore, base: Path, *, task_id: str = TASK,
               exec_id: str = EXEC_ID, policy_version: str = POLICY) -> dict:
    """造一次**真事件**的执行：证据 blob 落盘 + started/finished 两条事件。

    返回封存/复核要用到的事实：证据 sha、事件 sha 与派生 run_id。
    """
    evidence = EvidenceStore(store, base / "evidence")
    stats = json.dumps({"execs": 6, "crashes": 0, "outcome": "no_repro"},
                       ensure_ascii=False).encode("utf-8")
    ref = evidence.put_bytes(task_id, "exec_stats", stats)
    bus = EventBus(store)
    bus.emit(task_id, "exec.started", stage="RUNNING", payload={
        "exec_id": exec_id, "kind": "fuzz", "plan_sha256": PLAN_SHA,
        "policy_version": policy_version})
    bus.emit(task_id, "exec.finished", stage="RUNNING", payload={
        "exec_id": exec_id, "kind": "fuzz", "plan_sha256": PLAN_SHA,
        "outcome": "no_repro", "evidence_sha256": ref.sha256,
        "build": {"build_id": "b1", "harness": "hr-x"}})
    return {"evidence_sha256": ref.sha256, "path": Path(ref.path),
            "bytes": stats, "exec_id": exec_id,
            "run_id": handoff.derive_run_id(task_id, exec_id, PLAN_SHA)}


class Fixture:
    """一整套交接夹具：库 + 证据目录 + revision 账本 + 一次执行 + 一条待复核项。"""

    def __init__(self, base: Path, *, task_id: str = TASK,
                 metadata: dict | None = None,
                 policy_version: str = POLICY) -> None:
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self.task_id = task_id
        self.store = _new_store(self.base, task_id=task_id, metadata=metadata)
        self.evidence_root = self.base / "evidence"
        self.revisions = _revision_store(self.base)
        self.revision_id = self.revisions.current().revision_id
        self.execution = _execution(self.store, self.base, task_id=task_id,
                                    policy_version=policy_version)
        self.item = handoff.open_pending(
            self.store, task_id, execution_id=self.execution["exec_id"],
            evidence_root=self.evidence_root, revision_id=self.revision_id,
            policy_version=policy_version)

    # ---- 复核 ----
    def review(self, item_id: str = "", **kwargs) -> dict:
        return handoff.review_item(
            self.store, self.task_id, item_id or self.item["item_id"],
            evidence_root=kwargs.pop("evidence_root", self.evidence_root),
            revisions=kwargs.pop("revisions", self.revisions),
            policy_version=kwargs.pop("policy_version", POLICY))

    def view(self, **kwargs) -> dict:
        return handoff.handoff_view(self.store, self.task_id,
                                    revisions=kwargs.pop("revisions",
                                                         self.revisions))

    def blob_path(self, sha256_value: str) -> Path:
        return handoff.raw_evidence_path(self.store, self.task_id,
                                         sha256_value,
                                         evidence_root=self.evidence_root)


# ================================================== 1. 成功链路
def test_seal_then_review_keeps_one_identity(tmp_path):
    """封存 → pending 项 → 只读钩子 → 复核 accepted：全程**一个**三方身份。

    事实来源（逐个写明，不重叠）：
    - `run_id` 只能由 `derive_run_id(task_id, execution_id, plan_sha256)` 派生；
    - `execution_id` 只来自 `exec.finished` 的 `exec_id`；
    - `evidence_sha256` 是**封存记录盘上字节**的 sha256（自指哈希不写进内容）。
    """
    fx = Fixture(tmp_path)
    item, execution = fx.item, fx.execution

    # --- 封存结果：待复核项是唯一入口态，身份由原始记录复算，不由调用方声明 ---
    assert item["item_id"] == "HI1"
    assert item["task_id"] == TASK
    assert item["status"] == "pending"                    # 落库即 pending
    assert item["source"] == "exec.finished"              # 只认执行证据
    assert item["verdict_id"] == ""                       # 还没有定性
    assert item["run_id"] == execution["run_id"] == \
        handoff.derive_run_id(TASK, EXEC_ID, PLAN_SHA)
    assert handoff.derive_run_id(TASK, EXEC_ID, PLAN_SHA).startswith("run-")
    assert item["execution_id"] == EXEC_ID == execution["exec_id"]

    # --- 盘上 blob：文件哈希就是 evidence_sha256（不是另一套口径） ---
    blob = fx.blob_path(item["evidence_sha256"])
    assert blob.is_file()
    assert _sha_of(blob) == item["evidence_sha256"]
    record_doc = json.loads(blob.read_text(encoding="utf-8"))
    assert record_doc["schema"] == handoff.RAW_SCHEMA
    for name in ("task_id", "run_id", "execution_id"):
        assert record_doc[name] == item[name], name
    assert record_doc["source_evidence_sha256"] == execution["evidence_sha256"]
    # 落盘的就是源证据本身（没被复制成"看起来像证据"的另一份）
    assert execution["path"].is_file()
    assert _sha_of(execution["path"]) == execution["evidence_sha256"]

    # --- 只读钩子：验证侧只读原始记录，摘要恒不接受 ---
    raw = verify_mod.raw_handoff_view(fx.store, TASK)
    assert raw["model_summary_accepted"] is False
    assert raw["counts"] == {"refs": 1, "registered": 1, "traceable": 1}
    ref = raw["refs"][0]
    assert ref["execution_id"] == EXEC_ID
    assert ref["evidence_sha256"] == execution["evidence_sha256"]
    assert ref["registered"] is True and ref["present"] is True
    assert ref["hash_ok"] is True
    assert ref["event_type"] == "exec.finished"

    # --- 复核：accepted 且三项检查全过 ---
    reviewed = fx.review()
    verdict = reviewed["verdict"]
    assert verdict["verdict_id"] == "HV1"
    assert verdict["status"] == "accepted"
    assert verdict["blockers"] == []
    assert all(verdict["checks"].values()), verdict["checks"]
    assert set(verdict["checks"]) == set(handoff.CHECKS)
    assert verdict["detail"]["model_summary_accepted"] is False
    assert reviewed["item"]["status"] == "accepted"

    # --- record / item / verdict 三方身份完全一致 ---
    for name in ("run_id", "execution_id"):
        assert record_doc[name] == item[name] == \
            verdict[name] == reviewed["item"][name], name
    # 记录侧的 evidence_sha256 就是它自己的文件哈希：本体不写自身哈希
    # （自指哈希写不进自己的内容里），所以这一维只认盘上字节。
    assert "evidence_sha256" not in record_doc
    assert _sha_of(blob) == item["evidence_sha256"] == \
        verdict["evidence_sha256"] == reviewed["item"]["evidence_sha256"]

    # --- 视图与台账摘要 ---
    view = fx.view()
    assert view["counts"] == {"pending": 0, "accepted": 1, "rejected": 0,
                              "needs_evidence": 0, "items": 1,
                              "conclusions": 1, "unverified": 0}
    assert len(view["conclusions"]) == 1
    conclusion = view["conclusions"][0]
    assert conclusion["item_id"] == item["item_id"]
    for name in ("run_id", "execution_id", "evidence_sha256"):
        assert conclusion[name] == item[name], name
    assert conclusion["verdict_id"] == verdict["verdict_id"]
    assert view["items"][0]["revision_current"] is True

    assert fx.store.summary(TASK)["handoff"] == {
        "items": 1, "pending": 0, "accepted": 1, "rejected": 0,
        "needs_evidence": 0, "verdicts": 1,
        "last_item": "HI1", "last_verdict": "HV1"}
    assert [v["verdict_id"] for v in
            fx.store.list_handoff_verdicts(TASK)] == ["HV1"]

    # --- 幂等：同三方身份再开项不产生第二条 ---
    again = handoff.open_pending(fx.store, TASK, execution_id=EXEC_ID,
                                 evidence_root=fx.evidence_root,
                                 revision_id=fx.revision_id,
                                 policy_version=POLICY)
    assert again["item_id"] == "HI1"
    assert len(fx.store.list_review_items(TASK)) == 1
    # 已定性的项不重复复核（补证据要重新封存）
    with pytest.raises(handoff.HandoffError) as excinfo:
        fx.review()
    assert str(excinfo.value).startswith("review_item_closed")


# ================================================== 2a. 错任务 ID
def test_wrong_task_evidence_is_rejected(tmp_path):
    """记录完好但属于**另一个任务**：这是硬拒绝（补证据救不了错任务）。

    做法：把同一条证据登记到 OTHER，再伪造 OTHER 的待复核项（三方身份照抄），
    复核时必须 `rejected` + `wrong_task`，且不进任何结论。
    """
    fx = Fixture(tmp_path)
    execution = fx.execution
    fx.store.create_task(TaskSpec(
        task_id=OTHER, benchmark="vulngym", target="http://127.0.0.1:1/y",
        budget=Budget(max_seconds=60, max_execs=100, max_tokens=1000,
                      max_turns=8), metadata={}))

    # 同一条证据（记录本体 + 源证据）登记到另一个 task
    for sha_value, kind in ((fx.item["evidence_sha256"], "raw_execution"),
                            (execution["evidence_sha256"], "exec_stats")):
        fx.store.add_evidence(OTHER, sha_value,
                              fx.blob_path(sha_value).stat().st_size,
                              str(fx.blob_path(sha_value)), kind=kind,
                              source_stage="RUNNING")
    forged = fx.store.save_review_item(
        dict(fx.item, task_id=OTHER, item_id="HI1"))
    assert forged["task_id"] == OTHER
    assert forged["evidence_sha256"] == fx.item["evidence_sha256"]

    reviewed = handoff.review_item(fx.store, OTHER, "HI1",
                                   evidence_root=fx.evidence_root,
                                   revisions=fx.revisions,
                                   policy_version=POLICY)
    verdict = reviewed["verdict"]
    assert verdict["status"] == "rejected"                # 不采纳
    assert any(b.startswith("wrong_task") for b in verdict["blockers"]), \
        verdict["blockers"]
    assert verdict["checks"]["task_match"] is False
    assert reviewed["item"]["status"] == "rejected"

    # 结论为空：错任务项永远不会变成可追溯结论
    view = handoff.handoff_view(fx.store, OTHER)
    assert view["conclusions"] == []
    assert view["counts"]["rejected"] == 1
    assert view["counts"]["conclusions"] == 0
    # 原任务那边一条项都没被牵连
    assert fx.store.list_review_items(TASK) == [
        fx.store.get_review_item(TASK, "HI1")]


# ================================================== 2b. 旧 revision / 旧版本
def test_stale_revision_is_rejected(tmp_path):
    """记录指向 r1、账本 head 已是 r2：旧版本的执行证据不算结论。"""
    fx = Fixture(tmp_path)
    first = fx.revisions.current()
    assert first.revision_id == fx.item["revision_id"]
    second = _revision(fx.revisions, "r2", parent=first)
    fx.revisions.set_current(second.revision_id)

    verdict = fx.review()["verdict"]
    assert verdict["status"] == "rejected"
    assert any(b.startswith("stale_revision") for b in verdict["blockers"]), \
        verdict["blockers"]
    assert f"head={second.revision_id}" in " ".join(verdict["blockers"])
    assert verdict["checks"]["revision_current"] is False
    assert fx.view()["conclusions"] == []


def test_stale_policy_version_is_rejected(tmp_path):
    """记录写 `v3-w2`、复核期望 `v3-w3`：协议/策略版本不对 → rejected。"""
    fx = Fixture(tmp_path, policy_version="v3-w2")
    assert fx.item["detail"]["policy_version"] == "v3-w2"
    verdict = fx.review(policy_version="v3-w3")["verdict"]
    assert verdict["status"] == "rejected"
    assert any(b.startswith("stale_version") for b in verdict["blockers"]), \
        verdict["blockers"]
    assert verdict["checks"]["version_current"] is False
    assert fx.view()["conclusions"] == []


# ================================================== 2c. 证据缺失
def test_missing_evidence_file_needs_evidence(tmp_path):
    """库里登记过、盘上文件被删 → `needs_evidence`（补材料后可重进复核）。"""
    fx = Fixture(tmp_path)
    blob = fx.blob_path(fx.item["evidence_sha256"])
    blob.unlink()
    assert not blob.exists()

    verdict = fx.review()["verdict"]
    assert verdict["status"] == "needs_evidence"          # 缺证据 ≠ 拒绝
    assert any("evidence_file_missing" in b for b in verdict["blockers"]), \
        verdict["blockers"]
    assert verdict["checks"]["record_hash_match"] is False
    assert fx.view()["conclusions"] == []
    # 项状态落成 needs_evidence（不是 accepted，也不是 rejected）
    assert fx.store.get_review_item(TASK, fx.item["item_id"])["status"] == \
        "needs_evidence"
    assert handoff.pending_items(fx.store, TASK)[0]["item_id"] == \
        fx.item["item_id"]                                # 还能被待办队列看见
    assert fx.store.summary(TASK)["handoff"]["needs_evidence"] == 1


def test_evidence_not_in_store_needs_evidence(tmp_path):
    """`evidence_sha256` 根本不在证据台账里 → `needs_evidence`。"""
    fx = Fixture(tmp_path)
    unknown = "f" * 64
    assert all(row["sha256"] != unknown
               for row in fx.store.list_evidence(TASK))
    fx.store.save_review_item(dict(fx.item, item_id="HI7",
                                   evidence_sha256=unknown))

    verdict = handoff.review_item(fx.store, TASK, "HI7",
                                  evidence_root=fx.evidence_root,
                                  revisions=fx.revisions,
                                  policy_version=POLICY)["verdict"]
    assert verdict["status"] == "needs_evidence"
    assert any(b.startswith("evidence_not_in_store") for b in
               verdict["blockers"]), verdict["blockers"]
    assert verdict["checks"]["record_present"] is False
    view = fx.view()
    assert view["conclusions"] == []
    assert view["counts"]["needs_evidence"] == 1


# ================================================== 3. 模型摘要不被接受
def test_verifier_rejects_model_summary_argument(tmp_path):
    """给 verifier 递摘要（哪怕只是"更清楚的复述"）→ `model_summary_not_accepted`。

    拒绝是**入口处**发生的：不落 verdict、不改项状态、不产生结论。
    """
    fx = Fixture(tmp_path)
    verifier = handoff.IndependentVerifier(
        fx.store, evidence_root=fx.evidence_root, revisions=fx.revisions,
        policy_version=POLICY)
    with pytest.raises(handoff.HandoffError) as excinfo:
        verifier.verify(fx.item, summary={"conclusion": "exploitable"})
    message = str(excinfo.value)
    assert "model_summary_not_accepted" in message
    assert "dict" in message                     # 能看出递进来的是什么类型
    for summary in ("漏洞已确认", ["exploitable"], {"claim": "x"}):
        with pytest.raises(handoff.HandoffError) as excinfo:
            verifier.verify(fx.item, summary=summary)
        assert "model_summary_not_accepted" in str(excinfo.value)

    # 什么都没写进去
    assert fx.store.list_handoff_verdicts(TASK) == []
    assert fx.store.get_review_item(TASK, fx.item["item_id"])["status"] == \
        "pending"
    assert fx.view()["conclusions"] == []

    # 不给摘要时同一份原始记录照常通过（拒绝的是摘要，不是这条证据）
    clean = verifier.verify(fx.item)
    assert clean["status"] == "accepted"
    assert clean["detail"]["model_summary_accepted"] is False
    # 空摘要等于没给摘要（None/""/{} 都不算"递了摘要"）
    assert verifier.verify(fx.item, summary="")["status"] == "accepted"


def test_raw_record_carrying_summary_is_not_accepted(tmp_path):
    """原始记录里带模型摘要字段 → `raw_source_only` 失败 → **rejected**。

    做法：直接写一个 `payload.finish.summary` 的 blob 并登记成证据（绕过
    `seal_execution`），再构造指向它的待复核项。记录本体完好（哈希对得上），
    但它**被模型加工过**：复核者按 `raw_source_only` 判 `rejected`——
    补证据救不了被加工的记录，所以不是 `needs_evidence`（这条口径是本组的核心：
    模型摘要进不了结论）。
    """
    fx = Fixture(tmp_path)
    source = fx.execution
    run_id = handoff.derive_run_id(TASK, "exec-0009", PLAN_SHA)
    body = {
        "schema": handoff.RAW_SCHEMA, "schema_version": handoff.SCHEMA_VERSION,
        "task_id": TASK, "run_id": run_id, "execution_id": "exec-0009",
        "plan_sha256": PLAN_SHA, "kind": "fuzz",
        "source_evidence_sha256": source["evidence_sha256"],
        "source_event_seq": 99, "source_event_type": "exec.finished",
        "revision_id": fx.revision_id, "build_id": "b1",
        "policy_version": POLICY, "recorded_by": "executor",
        "sealed_at": "2026-01-01T00:00:00+00:00",
        "payload": {"start": {},
                    "finish": {"exec_id": "exec-0009",
                               "summary": "exploitable"}},
    }
    from agent.platform.adaptive.contracts import canonical_json
    raw = canonical_json(body).encode("utf-8")
    digest = sha256(raw).hexdigest()
    path = fx.evidence_root / digest
    path.write_bytes(raw)
    fx.store.add_evidence(TASK, digest, len(raw), str(path),
                          kind=handoff.RAW_KIND, source_stage="RUNNING")
    fx.store.save_review_item(dict(
        fx.item, item_id="HI9", run_id=run_id, execution_id="exec-0009",
        evidence_sha256=digest, revision_id=fx.revision_id))

    reviewed = handoff.review_item(fx.store, TASK, "HI9",
                                   evidence_root=fx.evidence_root,
                                   revisions=fx.revisions,
                                   policy_version=POLICY)
    verdict = reviewed["verdict"]
    # 不采纳：被模型加工过的记录是**硬拒绝**（补材料救不了），不进结论。
    assert verdict["status"] == "rejected"
    assert verdict["checks"]["raw_source_only"] is False
    assert any("model_summary_in_record" in b for b in verdict["blockers"]), \
        verdict["blockers"]
    assert reviewed["item"]["status"] != "accepted"
    assert "HI9" not in [c["item_id"] for c in fx.view()["conclusions"]]


# ================================================== 4. CasePack 可追溯
#: 交接在 casepack 里的落点（包内文件名由 docs/V3-W3-HANDOFF.md 与本表统一）
HANDOFF_FILE = "handoff.json"


def _walk_to_packable(store: PlatformStore, task_id: str) -> list[str]:
    """按 `task.TRANSITIONS` 走一条**合法**最短链到 REVIEW（不许跳步）。"""
    chain = ["PREFLIGHT", "READY", "UNDERSTANDING", "HYPOTHESES", "PLANNED",
             "RUNNING", "CANDIDATE", "VERIFYING", "REVIEW"]
    source = store.get_task(task_id)["state"]
    for step in chain:
        assert step in TRANSITIONS[source], (source, step)
        store.transition(task_id, step, reason="w3 test: walk to packable")
        source = step
    return chain


def test_casepack_carries_handoff_trace(tmp_path):
    """一个 accepted + 一个 pending + 一个 needs_evidence 一起进包。

    断言的是**可追溯**：`handoff.json` 里的 `conclusions` 只含 accepted 项，
    另外两条如实标状态；包级 `verdict.handoff` / `pack["handoff"]` 的计数与视图
    一致；`report.md` 与 `report.html` **两处**都逐行有项 id 与状态
    （HTML 只是所记录快照的确定性函数，与 md/handoff.json 同源）。
    """
    # packer 已把 handoff.json 接进 `casepack.FILES`：清单里没有它就不算可追溯
    assert HANDOFF_FILE in tuple(casepack_mod.FILES)
    fx = Fixture(tmp_path)
    assert fx.review()["verdict"]["status"] == "accepted"  # HI1 → accepted
    # HI2：开一条新的执行但不复核 → pending
    execution = _execution(fx.store, fx.base, exec_id="exec-0002")
    pending = handoff.open_pending(fx.store, TASK,
                                   execution_id=execution["exec_id"],
                                   evidence_root=fx.evidence_root,
                                   revision_id=fx.revision_id,
                                   policy_version=POLICY)
    assert pending["item_id"] == "HI2" and pending["status"] == "pending"
    # HI3：再开一条并删掉盘上 blob → needs_evidence
    third = _execution(fx.store, fx.base, exec_id="exec-0003")
    gap = handoff.open_pending(fx.store, TASK,
                               execution_id=third["exec_id"],
                               evidence_root=fx.evidence_root,
                               revision_id=fx.revision_id,
                               policy_version=POLICY)
    handoff.raw_evidence_path(fx.store, TASK, gap["evidence_sha256"],
                             evidence_root=fx.evidence_root).unlink()
    assert handoff.review_item(fx.store, TASK, gap["item_id"],
                               evidence_root=fx.evidence_root,
                               revisions=fx.revisions,
                               policy_version=POLICY)[
        "verdict"]["status"] == "needs_evidence"

    view = fx.view()
    assert view["counts"]["items"] == 3
    assert view["counts"]["accepted"] == 1
    assert view["counts"]["pending"] == 1
    assert view["counts"]["needs_evidence"] == 1
    assert [c["item_id"] for c in view["conclusions"]] == ["HI1"]

    _walk_to_packable(fx.store, TASK)
    out = tmp_path / "casepack"
    pack = casepack_mod.build_casepack(TASK, fx.store, out_dir=out,
                                       evidence_root=fx.evidence_root,
                                       bus=EventBus(fx.store))

    assert HANDOFF_FILE in tuple(casepack_mod.FILES)
    handoff_path = out / HANDOFF_FILE
    assert handoff_path.is_file()
    doc = json.loads(handoff_path.read_text(encoding="utf-8"))

    assert [c["item_id"] for c in doc["conclusions"]] == ["HI1"]
    assert doc["conclusions"][0]["evidence_sha256"] == \
        fx.item["evidence_sha256"]
    statuses = {row["item_id"]: row["status"] for row in doc["items"]}
    assert statuses == {"HI1": "accepted", "HI2": "pending",
                        "HI3": "needs_evidence"}
    # `handoff.json` 就是只读视图的快照：计数与 `handoff_view()` 逐键相同
    assert doc["counts"] == view["counts"]
    assert doc["counts"]["accepted"] == 1
    assert doc["counts"]["conclusions"] == 1
    assert doc["counts"]["unverified"] == 2               # pending + needs
    assert doc["note"].startswith("只有 accepted")

    # 包级摘要的交接计数与视图一致（不另造第二套事实）
    verdict_handoff = pack["verdict"]["handoff"]
    assert verdict_handoff["items"] == 3
    assert verdict_handoff["accepted"] == 1
    assert verdict_handoff["pending"] == 1
    assert verdict_handoff["rejected"] == 0
    assert verdict_handoff["needs_evidence"] == 1
    assert verdict_handoff["conclusions"] == 1
    # 口径同一句话（措辞两处各写一遍，语义必须一致）
    assert verdict_handoff["note"] == casepack_mod.HANDOFF_NOTE
    assert "只有 accepted" in verdict_handoff["note"]
    assert "只有 accepted" in doc["note"]
    # 交接项不是 verified：包级 verified/benchmark_verified 不受影响
    assert pack["verdict"]["verified"] == 0
    assert pack["verdict"]["benchmark_verified"] is False
    assert pack["handoff"]["file"] == HANDOFF_FILE
    assert pack["handoff"]["unverified"] == 2
    for key in ("items", "pending", "accepted", "rejected", "needs_evidence",
                "conclusions", "unverified"):
        assert pack["handoff"]["counts"][key] == doc["counts"][key], key

    # report.md：可追溯明细逐行在表里（项 id 与状态都能对上）
    report_md = (out / "report.md").read_text(encoding="utf-8")
    assert "证据交接（handoff）" in report_md
    for item_id in ("HI1", "HI2", "HI3"):
        assert item_id in report_md, item_id
    assert "needs_evidence" in report_md
    assert "| HI1 | accepted |" in report_md
    assert "| HI3 | needs_evidence |" in report_md

    # report.html：与 md 同一份快照 —— 计数 + 逐项明细行都在网页里
    report_html = (out / "report.html").read_text(encoding="utf-8")
    assert "证据交接（handoff）" in report_html
    assert "needs_evidence" in report_html
    assert handoff_path.name in report_html
    assert "交接项</dt><dd>3 条" in report_html
    for item_id in ("HI1", "HI2", "HI3"):
        assert item_id in report_html, item_id
    assert "accepted" in report_html


# ================================================== 5. 隔离/授权验收门（单元）
def _platform_acceptance(task_id: str = TASK, tag: str = "a") -> dict:
    """一份**自洽的替身**平台侧隔离验收记录（只用于闸的单元口径）。

    事实替身（`SimpleNamespace`）只用来验“闸读的是平台记录，不是 metadata”；
    真隔离事实由 `tests/test_v3_isolation_acceptance.py` 真跑出来。
    """
    from types import SimpleNamespace

    def record(seed: str):
        facts = dict(isolation="bwrap", network="none", cap_drop=True,
                     ro_root=True, pidns=True, no_new_privs=True,
                     executed_isolated=True, log_sha256=seed * 64)
        return SimpleNamespace(build_id="bd-" + seed * 16,
                               smoke_id="sm-" + seed * 16, **facts)

    probes = [handoff.isolation_probe("write_confined", ok=True,
                                      evidence={"marker_absent": True}),
              handoff.isolation_probe("network_denied", ok=True,
                                      evidence={"exit_code": 3})]
    return handoff.build_isolation_acceptance(
        task_id=task_id, build=record(tag), smoke=record("b"),
        probes=probes).to_dict()


def test_proposal_gate_unit_requires_both_acceptances(tmp_path):
    """授权按 metadata 严格解析；隔离**只认平台侧记录**（自报恒为 advisory）。"""
    def decision(metadata, *, record=None):
        gate = handoff.ProposalGate(task={"task_id": TASK, "metadata": metadata},
                                    isolation_record=record)
        return gate.admit(scope="engineering", action="stage",
                          params={"revision": {"files": {}}})

    blocked = decision({})
    assert blocked.status == "advisory"                   # 只给建议
    assert blocked.to_dict()["applied"] is False
    assert set(blocked.blockers) == {"authorization:false", "isolation:missing"}
    assert blocked.acceptance["ok"] is False

    # 只有一半验收：仍然是 advisory（平台记录在，但没授权）
    half = decision({}, record=_platform_acceptance())
    assert half.status == "advisory"
    assert half.blockers == ("authorization:false",)
    assert half.acceptance["isolation"] == "accepted"
    assert half.acceptance["ok"] is False

    # 任务提交者自填 `isolation_accepted` **不再放行**：只留 advisory 痕迹
    self_report = decision({"isolation_accepted": "yes"})
    assert self_report.status == "advisory"
    assert self_report.acceptance["isolation"] == "missing"
    assert self_report.acceptance["declared"]["state"] == "declared"
    assert self_report.acceptance["declared"]["authority"] == "advisory"

    signed = decision({"authorized": True}, record=_platform_acceptance())
    assert signed.status == "apply"
    assert signed.blockers == ()
    assert signed.to_dict()["applied"] is True
    assert signed.acceptance["ok"] is True
    assert signed.acceptance["isolation"] == "accepted"
    assert signed.acceptance["evidence_sha256"]

    # 严格解析：字符串 "false" 不是授权；`"true"` 才是
    stringly = decision({"authorized": "false"}, record=_platform_acceptance())
    assert stringly.status == "advisory"
    assert "authorization:false" in stringly.blockers
    assert decision({"authorized": "true"},
                    record=_platform_acceptance()).status == "apply"
    # 不认识的写法既不算验收，也不冒充"没写"
    invalid = decision({"authorized": "maybe"}, record=_platform_acceptance())
    assert invalid.status == "advisory"
    assert invalid.acceptance["authorization"] == "invalid"

    # 记录被改一个字段 → 复算不上 → rejected
    forged = _platform_acceptance()
    forged["network"] = "host"
    tampered = decision({"authorized": True}, record=forged)
    assert tampered.status == "advisory"
    assert tampered.blockers == ("isolation:rejected",)

    # from_task 与 task= 同口径（没有平台记录 → 只给建议）
    task = {"task_id": TASK,
            "metadata": {"authorized": True, "isolation_accepted": "yes"}}
    assert handoff.ProposalGate.from_task(task).admit(
        action="stage").status == "advisory"
    assert handoff.ProposalGate.from_task(
        task, isolation_record=_platform_acceptance()).admit(
            action="stage").status == "apply"


# ================================================== 5. 验收门（集成）
class FactRunner:
    """执行器替身：只 `emit` 两条执行事件并回报事实（不跑子进程）。

    配置口径按"报告了实际加载版本"填（planned == loaded），免得 w2 的
    `config_not_effective/config_unverified` 把流程拦在提议之前——本组要看的
    只是验收闸，不是配置门。
    """

    def __init__(self, workspace: TaskWorkspace, store: PlatformStore,
                 task_id: str) -> None:
        self.workspace = workspace
        self.store = store
        self.task_id = task_id
        self.calls: list[str] = []

    def __call__(self, *, kind: str, mode: str, params: dict, binding) -> dict:
        exec_id = f"exec-{len(self.calls) + 1:04d}"
        planned = str(self.workspace.active_config_sha256() or "")
        fuzz = {"execs": 6, "crashes": 0, "timeouts": 0,
                "new_coverage_bits": 0, "setup_error": "",
                "stopped": "completed", "workers": 1}
        usage = {"seconds": 0.3, "execs": 6, "tokens": 0, "turns": 1}
        self.store.append_event(self.task_id, "exec.started", stage="RUNNING",
                                payload={"exec_id": exec_id, "kind": kind,
                                         "plan_sha256": "p" * 40,
                                         "config_planned_sha256": planned})
        self.store.append_event(self.task_id, "exec.finished", stage="RUNNING",
                                payload={
                                    "exec_id": exec_id, "kind": kind,
                                    "outcome": "no_repro", "candidates": 0,
                                    "plan_sha256": "p" * 40, "seconds": 0.3,
                                    "build": {"sha256": "b" * 64,
                                              "build_id": "b" * 64,
                                              "harness": "covfuzz"},
                                    "fuzz": fuzz, "evidence_sha256": "e" * 64,
                                    "error": None, "budget_usage": usage,
                                    "program_started": True,
                                    "input_processed": True,
                                    "checkpoint_reached": None,
                                    "config_planned_sha256": planned,
                                    "config_loaded_sha256": planned,
                                    "config_source": "loaded"})
        self.calls.append(exec_id)
        return {"execution_id": exec_id, "kind": kind, "mode": mode,
                "outcome": "no_repro", "candidates": 0,
                "build": {"sha256": "b" * 64}, "fuzz": fuzz,
                "coverage": {"status": "unavailable"},
                "budget_usage": usage, "evidence_sha256": "e" * 64,
                "error": None, "program_started": True,
                "input_processed": True, "checkpoint_reached": None,
                "loaded_config_sha256": planned}


def _workspace(base: Path, task_id: str) -> TaskWorkspace:
    """真 workspace：`tests/fixtures_config` 复制成只读原件（不写仓库夹具）。"""
    origin = base / "origin"
    shutil.copytree(FIXTURES, origin)
    return TaskWorkspace.create(base / "ws", origin, task_id=task_id,
                                build_command=BUILD_COMMAND,
                                smoke_command=SMOKE_COMMAND)


def _index(base: Path, task_id: str) -> ProgramIndex:
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "target.py").write_text("def parse(b):\n    return b\n",
                                   encoding="utf-8")
    return ProgramIndex(
        benchmark="vulngym", root=str(src), task_id=task_id,
        entry_points=[{"name": "parse", "file": "target.py"}],
        functions=[{"name": "parse", "file": "target.py"}],
        call_sites=[{"id": "cs-1", "file": "target.py", "line": 1,
                     "function": "parse", "callee": "parse"}],
        formats=["raw"], source_count=1, warnings=[])


def _gate_task(base: Path, task_id: str, metadata: dict
               ) -> tuple[PlatformStore, dict, TaskWorkspace, ProgramIndex]:
    """一个能提出动作的真任务：库 + 假设 + 配置模式工作区 + 程序索引。"""
    store = PlatformStore(base / "platform.db")
    store.create_task(TaskSpec(
        task_id=task_id, benchmark="vulngym", target="fixtures_config",
        mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=1000, max_tokens=1000,
                      max_turns=8), metadata=metadata))
    store.save_hypotheses(task_id, [{
        "id": "hyp-1", "statement": "VMAP1 头被解析后才处理 body",
        "falsifiable_by": "diff", "evidence_gap": [], "cost": {"level": "low"},
        "confidence": 0.5, "source": "static", "site_id": "cs-1",
        "hypothesis": "header", "window": "target.py:1-40",
        "falsification": "none"}])
    workspace = _workspace(base, task_id)
    return store, store.get_task(task_id), workspace, _index(base, task_id)


def test_controller_stops_at_advisory_only_before_acceptance(tmp_path):
    """未验收：只把提议写进建议清单，不授权/不执行/不建 revision/不写采纳。"""
    task_id = "task-v3-w3-gate-off"
    store, task, workspace, index = _gate_task(tmp_path, task_id, {})
    runner = FactRunner(workspace, store, task_id)
    revisions_before = len(workspace.revisions.all())
    assert workspace.revisions.adoptions() == ()

    controller = ResearchController(
        task=task, store=store, workspace=workspace, index=index,
        exec_runner=runner, max_rounds=1,
        proposal_gate=handoff.ProposalGate(task=task))
    result = controller.run()

    assert result.status == "completed"
    assert result.stop_reason == "advisory_only"
    assert result.error == ""
    assert runner.calls == []                        # 一次执行都没发生
    record = result.rounds[0]
    assert record.note == "advisory_only"
    assert record.stop_reason == "advisory_only"
    assert len(record.advisories) == 1
    advisory = record.advisories[0]
    assert advisory["status"] == "advisory"
    assert advisory["applied"] is False
    assert advisory["action"] == "propose"
    assert advisory["blockers"] == ["authorization:false", "isolation:missing"]
    assert advisory["params_sha256"]                    # 提议原文留了哈希

    phases = [(item.phase, item.status) for item in result.timeline]
    assert ("PROPOSE", "advisory") in phases
    assert ("STOP", "advisory") in phases
    assert not any(phase == "EXECUTE" for phase, _ in phases)

    # 工作副本/revision 账本没被动过
    assert len(workspace.revisions.all()) == revisions_before
    assert workspace.revisions.adoptions() == ()
    assert not (workspace.root / "store" / "adoptions.jsonl").exists()
    assert list(workspace.revisions.pending_invalidations()) == []


def _platform_record_for(store, workspace, task_id: str) -> dict:
    """用**真隔离** build+smoke 当证据的平台侧记录（组 6 的走线口径）。

    探针证据（越界写/断网）的真跑断言在
    `tests/test_v3_isolation_acceptance.py`；这里只验控制器/闸的接线。
    """
    build = workspace.build()
    smoke = workspace.smoke(build=build)
    assert build.executed_isolated is True and smoke.executed_isolated is True
    probes = [
        handoff.isolation_probe(
            "write_confined", ok=True,
            evidence={"build_id": build.build_id, "ro_root": build.ro_root,
                      "smoke_id": smoke.smoke_id,
                      "log_sha256": smoke.log_sha256}),
        handoff.isolation_probe(
            "network_denied", ok=True,
            evidence={"build_id": build.build_id, "network": build.network,
                      "smoke_id": smoke.smoke_id,
                      "log_sha256": build.log_sha256}),
    ]
    acceptance = handoff.build_isolation_acceptance(
        task_id=task_id, build=build, smoke=smoke, probes=probes)
    assert acceptance.status == "accepted", acceptance.reason
    return handoff.record_isolation_acceptance(store, acceptance=acceptance)


def test_controller_proceeds_after_acceptance(tmp_path):
    """授权 + **平台侧隔离记录**都成立后，闸不再拦路：控制器真执行了一轮。"""
    task_id = "task-v3-w3-gate-on"
    store, task, workspace, index = _gate_task(
        tmp_path, task_id, {"authorized": True})
    record = _platform_record_for(store, workspace, task_id)
    runner = FactRunner(workspace, store, task_id)
    gate = handoff.ProposalGate.from_task(store.get_task(task_id), store=store)
    assert gate.acceptance.ok is True
    assert gate.acceptance.acceptance_id == record["acceptance_id"]
    assert gate.acceptance.evidence_sha256 == record["evidence_sha256"]
    assert gate.admit(action="propose").status == "apply"

    controller = ResearchController(
        task=task, store=store, workspace=workspace, index=index,
        exec_runner=runner, max_rounds=1, proposal_gate=gate)
    result = controller.run()

    assert result.status == "completed"
    assert result.stop_reason != "advisory_only"      # 闸没再拦
    assert result.stop_reason == "max_rounds"
    assert runner.calls == ["exec-0001"]              # 提议真的执行了
    record = result.rounds[0]
    assert record.advisories == []
    assert record.note != "advisory_only"

    phases = [(item.phase, item.status) for item in result.timeline]
    assert ("AUTHORIZE", "accepted") in phases
    assert ("PROPOSE", "advisory") not in phases
    assert any(phase == "EXECUTE" for phase, _ in phases)


# ================================================== 6. 词表对账
def test_status_vocabularies_match_handoff_module():
    """store 与 adaptive.handoff 的状态词表必须是同一套（库不反向 import）。"""
    from agent.platform import store as store_mod

    assert store_mod.REVIEW_ITEM_STATUSES == handoff.STATUSES
    assert store_mod.HANDOFF_VERDICT_STATUSES == handoff.TERMINAL_STATUSES
    # 入口态只有一个；终态三个；终态是待复核状态的真子集
    assert handoff.STATUSES[0] == "pending"
    assert set(handoff.TERMINAL_STATUSES) <= set(handoff.STATUSES)
    assert len(handoff.TERMINAL_STATUSES) == len(handoff.STATUSES) - 1
    # 交接模块自己也不写 verified/confirmed 这类词
    assert "verified" not in handoff.STATUSES
    assert "confirmed" not in handoff.STATUSES
