r"""V3 P2b 验收：workspace / revision / session / controller / policy 的真实行为。

口径逐条对应《VULNMAP-V3 完整升级方案》§4（双循环）、§5（可信快照）、
§8（实验自修改与版本事务）、§9（统一数据契约）、§18.1（T04/T05/T06/T08/T10/T14/T15）：

1. **V3-007 / T08 原件只读**：`origin/` 一律 0444，直接 `open(..., "w")` 抛
   `PermissionError`；stage/build/smoke/revert 走完一圈后
   `origin_integrity()["ok"] is True`，且原件目录内容哈希与初始完全一致。
2. **T05 stage/commit/build/smoke 真执行**：stage 改 `seed_params.json` → commit
   产出带 parent/diff/changed_against 的新 revision；build 真的返回 0 且日志文件
   存在、`log_sha256` 与文件字节重算一致；smoke 改前 failed（target 侧）、改后
   passed；revision 快照里的 `seed_params.json` 是改后内容且只读。
3. **T06 旧 revision 不可变**：frozen dataclass；同 `revision_id` 不同 manifest
   构造 → `RevisionError(revision_tampered)`；chmod +w 后篡改快照 →
   `verify_manifest()` ok False 且 problems 含 `changed:`；篡改后的文档
   `from_dict()` 同样被拒。
4. **T05 revert 是真回退**：`working_manifest() == 目标 revision.manifest`，当前
   指针是新 revision 且 `reverted_to` 指回目标，旧快照字节未变，且 revert 自己
   登记了 build/smoke/coverage_baseline/corpus_members 四条待消费失效。
5. **T06 失效被控制器消费**：带 revision 的一轮里 build/smoke/coverage_baseline/
   corpus_members 全部 `status=="handled"` 且 `handled_by` 非空（build 用 build_id，
   smoke 用 smoke_id）；revision 的 `invalidations` 与
   `CHANGE_INVALIDATIONS["harness"]` 完全一致，跑完待消费集合被取空。
6. **T04 两轮反馈改变动作并命中**：第 1 轮 `no_execution` 且不改副本；第 2 轮
   `target_unreached` → 改 `seed_params.json`（raw→magic）→ build ok → smoke
   passed → adopted；runner 被调 2 次；`candidate_ready` + `verification.allowed`；
   控制器**不写**验证结论（`list_verifications()==[]`）。
7. **T10 相同事实有限停止**：runner 永远同样 no_repro → 只调 2 次、第 3 轮
   OBSERVE 即 `repeated_facts`、没有第 3 次 EXECUTE。
8. **T05/T08 harness 自崩 → revert 且不采纳**：注入写坏 `gen.py` 的 editor（能过
   py_compile，运行期 traceback）→ smoke `harness_error`、`adopted is False`、
   `reverted` 非空、工作树等于父 revision、`stop_reason=="harness_error"`、
   `status=="blocked"`、没有 verify 记录；该轮 corpus_members 记为 `deferred`。
9. **T08 假阳性门**：`engineering()` 在 `smoke.harness_failed` 时不采纳且
   failed 含 `smoke_passed`/`harness_healthy`；`false_positive()` 在 trial 的
   build_id 与本次 build 不一致时 failed 含 `execution_evidence`；
   `review_claim({"verified": True})` 不采纳并给出两条理由；
   `prune_verdict_fields()` 剥掉嵌套裁决字段。
10. **T15 裁决只认 verify**：空记录 → `not_verified`；伪造记录（schema 不对 /
    status=verified 但 verified=False / 带 confirmed）进 `invalid`；真实
    `verify.Verification` 形状的记录 → verified True（不调用 `run_verification`）。
11. **T14 模式与受信字段隔离**：session 固定 explore；`run_epoch` 在 verify ctx
    被 `mode_not_allowed` 拒绝；`replay_input` 在 explore ctx 被拒；advisor 建议
    带 `verified`/`binding` 被丢弃且 `advisor_errors` 非空；`ActionRequest` 参数
    带 `verified` → `trusted_field_forbidden`。
12. **预算/取消钩子**：`DeclaredBudget(limits={"turns": 1})` 在第一轮结算后停
    （第 2 轮不再开始）；`cancel=lambda: True` → `cancelled` 且 runner 0 次调用。
13. **LLM 只建议**：合法建议进 `plan.actions`（purpose=="advisor"）且
    `llm_suggestions==1`；advisor 抛异常只记 `advisor_errors`，确定性计划不变。

所有构建/冒烟都是真实 `subprocess.run`（py_compile + 本地 python 脚本），不
monkeypatch `subprocess.run` 或 `TaskWorkspace.build/smoke`。
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive import controller as controller_mod
from agent.platform.adaptive import policy as policy_mod
from agent.platform.adaptive.contracts import (CHANGE_INVALIDATIONS,
                                               ActionRequest, DeclaredBudget)
from agent.platform.adaptive.corpus import CorpusStore, build_identity
from agent.platform.adaptive.policy import AdoptionPolicy, prune_verdict_fields
from agent.platform.adaptive.revision import (BuildRecord, HarnessRevision,
                                              RevisionError, SmokeRecord,
                                              manifest_of)
from agent.platform.adaptive.session import (Diagnosis, Observation, ProposedAction,
                                             ResearchPlan, RevisionPlan,
                                             ResearchSession, SeedRole)
from agent.platform.adaptive.tools import build_registry, make_binding, make_context
from agent.platform.adaptive.workspace import TaskWorkspace, read_tree
from agent.platform.program import ProgramIndex
from agent.platform.store import PlatformStore
from agent.platform.task import Budget, TaskSpec
from agent.platform.verify import Verification

TASK = "task-v3-p2b"

#: 任务原件：`gen.py` 按 seed_params.json 里的 format 产出 MAGIC/raw 前缀，
#: `smoke.py` 只有 format=magic 才返回 0（这就是“目标侧行为”的判据）。
GEN_PY = (
    "import json\n"
    "from pathlib import Path\n"
    "def build(i=0):\n"
    "    p=json.loads(Path('seed_params.json').read_text())\n"
    "    return (b'MAGIC' if p.get('format')=='magic' else b'raw')+bytes([i])\n"
)
SMOKE_PY = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "import gen\n"
    "p=json.loads(Path('seed_params.json').read_text())\n"
    "if p.get('format')!='magic':\n"
    "    print('target not reached'); sys.exit(1)\n"
    "print('smoke ok')\n"
)
SEED_PARAMS_RAW = '{"format":"raw"}\n'
ORIGIN_FILES = {"gen.py": GEN_PY, "smoke.py": SMOKE_PY,
                "seed_params.json": SEED_PARAMS_RAW}
SEED_PARAMS_MAGIC = json.dumps(
    {"format": "magic", "seed_count": 2,
     "constraints": {"prefix": "MAGIC", "length": 8}},
    ensure_ascii=False, indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------ fixtures
def _store(base: Path):
    store = PlatformStore(base / "platform.db")
    store.create_task(TaskSpec(
        task_id=TASK, benchmark="vulngym", target="ws", mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=100000, max_tokens=100000,
                      max_turns=12),
        metadata={"authorized": True}))
    store.save_hypotheses(TASK, [{
        "id": "hyp-1", "statement": "magic parser", "falsifiable_by": "diff",
        "evidence_gap": [], "cost": {"level": "low"}, "confidence": 0.5,
        "source": "static", "site_id": "cs-1", "hypothesis": "memcpy",
        "window": "gen.py:1-5", "falsification": "none"}])
    return store, store.get_task(TASK)


def _index(base: Path):
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "gen.py").write_text("def parse(b):\n    return b\n",
                                encoding="utf-8")
    index = ProgramIndex(
        benchmark="vulngym", root=str(src), task_id=TASK,
        entry_points=[{"name": "parse", "file": "gen.py"}],
        functions=[{"name": "parse", "file": "gen.py"}],
        call_sites=[{"id": "cs-1", "file": "gen.py", "line": 1,
                     "function": "parse", "callee": "parse"}],
        formats=["raw"], source_count=1, warnings=[])
    return index, src


def _corpus(base: Path):
    corpus = CorpusStore(base / "corpus", task_id=TASK, campaign="vulngym")
    corpus.begin(build_identity({"target": "gen", "flags": "-O0"},
                                binary_sha256="a" * 64, harness="covfuzz",
                                target="gen"))
    return corpus


def _workspace(base: Path):
    """按 V3-007 建立任务副本（origin 只读 + current 可写 + 初始 revision）。"""
    origin = base / "origin"
    origin.mkdir(parents=True, exist_ok=True)
    for rel, body in ORIGIN_FILES.items():
        (origin / rel).write_text(body, encoding="utf-8")
    ws = TaskWorkspace.create(
        base / "ws", origin, task_id=TASK,
        build_command=[sys.executable, "-m", "py_compile", "gen.py", "smoke.py"],
        smoke_command=[sys.executable, "smoke.py"])
    return ws, origin


class FakeRunner:
    """隔离执行 worker 的替身：按第几次调用决定 hit，并落 exec 事件。

    只替身“执行器”本身（P2b 边界内不允许起真 fuzzer），构建/冒烟仍真跑。
    """

    def __init__(self, store, *, task_id=TASK, hit_from=None):
        self.store = store
        self.task_id = task_id
        self.hit_from = hit_from           # None = 永远 no_repro
        self.calls = []

    def __call__(self, *, kind, mode, params, binding):
        n = len(self.calls) + 1
        exec_id = f"exec-{n:04d}"
        hit = bool(self.hit_from is not None and n >= int(self.hit_from))
        fuzz = {"execs": 10, "crashes": 1 if hit else 0, "timeouts": 0,
                "new_coverage_bits": 5 if hit else 0, "workers": 1,
                "corpus_files": 2, "crash_files": 0, "setup_errors": 0,
                "setup_error": "", "slices": 1, "stopped": "completed"}
        cov = {"planned": 10, "covered": 7 if hit else 2,
               "uncovered": 3 if hit else 8, "status": "partial", "pcs": 20,
               "mapped_locations": 7 if hit else 2, "error": ""}
        build = {"sha256": binding.identity.get("build_id") or "corpusbuild"}
        outcome = "candidate" if hit else "no_repro"
        self.store.append_event(self.task_id, "exec.started", stage="RUNNING",
                                payload={"exec_id": exec_id, "kind": kind,
                                         "plan_sha256": "p" * 40,
                                         "benchmark": "vulngym",
                                         "target": "gen"})
        self.store.append_event(
            self.task_id, "exec.finished", stage="RUNNING",
            payload={"exec_id": exec_id, "kind": kind, "outcome": outcome,
                     "plan_sha256": "p" * 40,
                     "candidates": 1 if hit else 0, "seconds": 0.2,
                     "build": build, "fuzz": fuzz, "coverage": cov,
                     "seeds": 2, "dictionary_tokens": 3, "format": "raw",
                     "budget_usage": {"seconds": 0.2, "execs": 10,
                                      "tokens": 0, "turns": 1},
                     "evidence_sha256": ("e" if hit else "m") * 64,
                     "target_reached": hit, "error": None, "tokens": 0})
        self.calls.append(dict(params))
        return {"execution_id": exec_id, "kind": kind, "mode": mode,
                "outcome": outcome, "candidates": 1 if hit else 0,
                "build": build, "fuzz": fuzz, "coverage": cov, "seeds": 2,
                "dictionary_tokens": 3, "format": "raw",
                "budget_usage": {"seconds": 0.2, "execs": 10, "tokens": 0,
                                 "turns": 1},
                "evidence_sha256": ("e" if hit else "m") * 64,
                "target_reached": hit, "error": None}


def _run(base: Path, *, hit_from=None, budget=None, cancel=None,
         seed_role=None, max_attempts=3, max_rounds=4):
    """跑一次真实的慢循环（真 stage/build/smoke + 替身 exec worker）。"""
    base.mkdir(parents=True, exist_ok=True)
    store, task = _store(base)
    index, _src = _index(base)
    corpus = _corpus(base)
    ws, origin = _workspace(base)
    runner = FakeRunner(store, hit_from=hit_from)
    session = None
    if seed_role is not None:
        session = ResearchSession(
            binding=make_binding(task, campaign="vulngym", index=index,
                                 corpus=corpus),
            registry=build_registry(), store=store, seed_role=seed_role,
            max_attempts=max_attempts)
    ctl = controller_mod.ResearchController(
        task=task, store=store, workspace=ws, index=index, corpus=corpus,
        exec_runner=runner, policy=AdoptionPolicy(), max_rounds=max_rounds,
        budget=budget, cancel=cancel, session=session)
    result = ctl.run()
    return SimpleNamespace(store=store, task=task, index=index, corpus=corpus,
                           workspace=ws, origin=origin, runner=runner,
                           session=session, controller=ctl, result=result)


def _plan_action(plan, name):
    for action in plan.actions:
        if action.action == name:
            return action
    return None


def _stage_and_commit(ws, *, body=SEED_PARAMS_MAGIC, reason="switch seed format"):
    base = ws.current_revision()
    staged = ws.stage({"seed_params.json": body}, reason=reason)
    revision = ws.commit(reason=reason, hypothesis_id="hyp-1")
    return base, staged, revision


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ====================================================================== T08
def test_v3_007_origin_read_only_and_never_changes(tmp_path):
    """V3-007 / T08：原件 0444、拒绝写入，且全流程后内容哈希与初始一致。"""
    ws, origin = _workspace(tmp_path)
    writable_source = read_tree(origin)          # 任务原件（输入目录）
    frozen = ws.origin_dir                       # 工作区里的只读副本

    for rel in ORIGIN_FILES:
        assert (frozen / rel).stat().st_mode & 0o777 == 0o444, rel
        assert os.access(frozen / rel, os.W_OK) is False, rel

    with pytest.raises(PermissionError):
        open(frozen / "gen.py", "w")             # noqa: SIM115 - 就是要它抛

    before_bytes = read_tree(frozen)
    before_manifest = ws.manifest("origin")
    assert ws.origin_integrity()["ok"] is True

    # 走完整流程：build/smoke → stage/commit → build/smoke → revert
    base = ws.current_revision()
    build = ws.build(base)
    assert build.status == "ok", build
    smoke = ws.smoke(base, build=build)
    assert smoke.status == "failed", smoke
    _base, _staged, revision = _stage_and_commit(ws)
    assert ws.build(revision).status == "ok"
    ws.smoke(revision, build=ws.revisions.latest_build(revision.revision_id))
    ws.revert(to_revision=revision.parent_id, reason="rollback to origin")

    integrity = ws.origin_integrity()
    assert integrity["ok"] is True, integrity["problems"]
    assert integrity["problems"] == []
    after_bytes = read_tree(frozen)
    assert after_bytes == before_bytes
    assert ws.manifest("origin") == before_manifest
    for rel, data in before_bytes.items():
        assert (frozen / rel).stat().st_mode & 0o777 == 0o444, rel
        assert hashlib.sha256(after_bytes[rel]).hexdigest() == \
            hashlib.sha256(data).hexdigest()
    # create() 只读输入目录：任务原件本身也没有被改写
    assert read_tree(origin) == writable_source


# ====================================================================== T05
def test_stage_commit_build_smoke_really_execute(tmp_path):
    """T05：stage/commit 产新 revision；build 真返回 0；smoke 从 failed 变 passed。"""
    ws, _origin = _workspace(tmp_path)
    base = ws.current_revision()

    build0 = ws.build(base)
    assert build0.status == "ok"
    assert build0.exit_code == 0
    log0 = Path(build0.log_path)
    assert log0.is_file() and log0.stat().st_size > 0
    assert _sha(log0) == build0.log_sha256

    smoke0 = ws.smoke(base, build=build0)
    assert smoke0.status == "failed"
    assert smoke0.kind == "target"           # 目标行为不符，不是 harness 崩了
    assert smoke0.harness_failed is False
    assert smoke0.exit_code == 1

    staged = ws.stage({"seed_params.json": SEED_PARAMS_MAGIC},
                      reason="switch seed format to magic")
    assert staged.changed_paths == ("seed_params.json",)
    assert staged.staged[0]["before_sha256"] != staged.staged[0]["after_sha256"]

    revision = ws.commit(reason="switch seed format to magic",
                         hypothesis_id="hyp-1", tool="generator_editor")
    assert isinstance(revision, HarnessRevision)
    assert revision.parent_id == base.revision_id
    assert revision.revision_id != base.revision_id
    assert revision.diff.strip() != ""
    assert "seed_params.json" in revision.changed_against(base)
    assert "seed_params.json" in revision.diff

    build = ws.build(revision)
    assert build.status == "ok"
    assert build.exit_code == 0
    assert build.build_id.startswith("bd-")
    log = Path(build.log_path)
    assert log.is_file()
    assert log.stat().st_size > 0
    assert _sha(log) == build.log_sha256
    assert build.log_bytes == log.stat().st_size

    smoke = ws.smoke(revision, build=build)
    assert smoke.status == "passed"
    assert smoke.exit_code == 0
    assert smoke.harness_failed is False
    assert smoke.build_id == build.build_id
    smoke_log = Path(smoke.log_path)
    assert smoke_log.is_file() and smoke_log.stat().st_size > 0
    assert _sha(smoke_log) == smoke.log_sha256

    snapshot = ws.root / "revisions" / revision.revision_id / "seed_params.json"
    assert snapshot.read_text(encoding="utf-8") == SEED_PARAMS_MAGIC
    assert snapshot.stat().st_mode & 0o777 == 0o444
    assert os.access(snapshot, os.W_OK) is False
    assert ws.revisions.verify_manifest(
        revision.revision_id, ws.root / "revisions" / revision.revision_id
    )["ok"] is True


# ====================================================================== T06
def test_committed_revision_is_immutable(tmp_path):
    """T06/T08：frozen、同 id 不同内容被拒、快照被篡改可复核出来。"""
    ws, _origin = _workspace(tmp_path)
    _base, _staged, revision = _stage_and_commit(ws)

    assert dataclasses.is_dataclass(revision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        revision.reason = "rewritten"        # type: ignore[misc]

    tampered_manifest = manifest_of(
        {"gen.py": b"def parse(b):\n    return b'other'\n",
         "smoke.py": SMOKE_PY.encode("utf-8"),
         "seed_params.json": SEED_PARAMS_MAGIC.encode("utf-8")},
        mode=0o644)
    with pytest.raises(RevisionError) as excinfo:
        HarnessRevision(revision_id=revision.revision_id,
                        parent_id=revision.parent_id,
                        manifest=tampered_manifest,
                        reason=revision.reason, tool=revision.tool,
                        environment=dict(revision.environment))
    assert "revision_tampered" in str(excinfo.value)

    # 同 id + 同字段（除 diff 外全部一致）→ 重建成功且 id 不变（内容即身份）
    rebuilt = HarnessRevision.from_dict(revision.to_dict())
    assert rebuilt.revision_id == revision.revision_id
    assert rebuilt.manifest == revision.manifest

    # 直接改旧 revision 的快照文件 → 复核必须报出来
    snapshot_dir = ws.root / "revisions" / revision.revision_id
    target = snapshot_dir / "seed_params.json"
    os.chmod(target, 0o644)                  # 否则写不进去（这正是只读的证据）
    target.write_text('{"format": "tampered"}\n', encoding="utf-8")

    state = ws.revisions.verify_manifest(revision.revision_id, snapshot_dir)
    assert state["ok"] is False
    assert any(problem.startswith("changed:") for problem in state["problems"]), \
        state["problems"]
    assert "changed:seed_params.json" in state["problems"]

    # 篡改后的文档重新 from_dict 也要被拒（id 与内容对不上）
    doc = revision.to_dict()
    for entry in doc["manifest"]:
        if entry["path"] == "seed_params.json":
            entry["sha256"] = "f" * 64
    with pytest.raises(RevisionError) as excinfo:
        HarnessRevision.from_dict(doc)
    assert "revision_tampered" in str(excinfo.value)


# ====================================================================== T05
def test_revert_rebuilds_worktree_without_rewriting_history(tmp_path):
    """T05：revert 选父版本重建工作树，旧 revision 字节不动，失效重新登记。"""
    ws, _origin = _workspace(tmp_path)
    base, _staged, revision = _stage_and_commit(ws)

    old_dir = ws.root / "revisions" / base.revision_id
    old_bytes = read_tree(old_dir)
    old_manifest_sha = base.manifest_sha256

    # commit 已经登记过失效；先取空，证明 revert 自己会重新登记
    assert set(ws.revisions.consume_invalidations()) == \
        set(CHANGE_INVALIDATIONS["harness"])
    assert ws.revisions.pending_invalidations() == ()

    reverted = ws.revert()
    assert reverted.parent_id == revision.revision_id
    assert reverted.reverted_to == base.revision_id
    assert reverted.is_revert is True
    assert reverted.revision_id != revision.revision_id

    assert ws.working_manifest() == base.manifest
    assert reverted.manifest == base.manifest
    current = ws.current_revision()
    assert current.revision_id == reverted.revision_id
    assert current.reverted_to == base.revision_id

    # 旧 revision 的快照字节与 manifest 都没有被改写
    assert read_tree(old_dir) == old_bytes
    assert ws.revisions.get(base.revision_id).manifest_sha256 == old_manifest_sha
    assert ws.revisions.verify_manifest(base.revision_id, old_dir)["ok"] is True

    # revert 之后四条失效重新进待消费集合
    pending = set(ws.revisions.pending_invalidations())
    assert pending == set(CHANGE_INVALIDATIONS["harness"])
    assert pending == {"build", "smoke", "coverage_baseline", "corpus_members"}

    # 已提交的新 revision 也还在账本里（只增不改）
    assert {item.revision_id for item in ws.revisions.all()} == {
        base.revision_id, revision.revision_id, reverted.revision_id}


# ====================================================================== T06
def test_harness_invalidations_are_consumed_by_controller(tmp_path):
    """T06：带 revision 的一轮里，四条 harness 失效都必须被消费并给出落实者。"""
    env = _run(tmp_path, hit_from=2)
    result = env.result
    assert len(result.revisions) == 1, result.revisions

    revision = env.workspace.revisions.get(result.revisions[0])
    assert revision.invalidations == CHANGE_INVALIDATIONS["harness"]
    assert set(revision.invalidations) == {
        "build", "smoke", "coverage_baseline", "corpus_members"}

    round_two = next(item for item in result.rounds if item.round_no == 2)
    by_scope = {entry["scope"]: entry for entry in round_two.invalidations}
    for scope in ("build", "smoke", "coverage_baseline", "corpus_members"):
        assert scope in by_scope, (scope, round_two.invalidations)
        assert by_scope[scope]["status"] == "handled", by_scope[scope]
        assert by_scope[scope]["handled_by"], by_scope[scope]

    assert by_scope["build"]["handled_by"] == round_two.build["build_id"]
    assert by_scope["smoke"]["handled_by"] == round_two.smoke["smoke_id"]

    # 待消费集合真的被取空（只取出不落实 = 没有生效；这里既取出又落实）
    assert env.workspace.revisions.pending_invalidations() == ()


# ====================================================================== T04
def test_two_round_feedback_changes_action_and_reaches_candidate(tmp_path):
    """T04：第 2 轮用第 1 轮的反馈换动作（raw→magic），smoke 通过后才执行并命中。"""
    env = _run(tmp_path, hit_from=2)
    result = env.result
    assert result.status == "completed"
    assert len(result.rounds) == 2
    first, second = result.rounds

    # ---- 第 1 轮：没有任何执行事实，先按原配置执行，不改副本 ----
    assert first.diagnosis.code == "no_execution"
    assert first.revision == ""
    assert first.plan.revision is None
    assert first.build is None and first.smoke is None
    assert first.adopted is False

    # ---- 第 2 轮：看到 target_unreached，改 seed_params.json ----
    assert second.diagnosis.code == "target_unreached"
    assert second.diagnosis.reasons == ("target_not_reached",)
    assert second.plan.revision is not None
    assert "seed_params.json" in second.plan.revision.files
    body = second.plan.revision.files["seed_params.json"].decode("utf-8")
    assert json.loads(body)["format"] == "magic"

    assert second.build["status"] == "ok"
    assert second.build["exit_code"] == 0
    assert second.smoke["status"] == "passed"
    assert second.smoke["harness_failed"] is False
    assert second.adopted is True
    assert second.reverted == ""

    # ---- 动作真的变了：propose_seed_spec 的 format 从 raw 到 magic ----
    first_actions = json.dumps([action.to_dict() for action in first.plan.actions],
                               ensure_ascii=False)
    second_actions = json.dumps([action.to_dict() for action in second.plan.actions],
                                ensure_ascii=False)
    assert _plan_action(first.plan, "propose_seed_spec").params["format"] == "raw"
    assert _plan_action(second.plan, "propose_seed_spec").params["format"] == "magic"
    assert first_actions != second_actions
    assert '"format": "raw"' in first_actions
    assert '"format": "magic"' in second_actions

    # ---- 执行次数与命中 ----
    assert len(env.runner.calls) == 2
    assert second.stop_reason == "candidate_ready"
    assert result.stop_reason == "candidate_ready"
    assert result.verification is not None
    assert result.verification.allowed is True
    assert result.verification.blockers == ()
    assert result.verification.diagnosis == "candidate_observed"

    # 控制器绝不写验证结论：交给既有 verify 之前库里必须没有 verification
    assert env.store.list_verifications(TASK) == []

    # 工作副本停在被采纳的 revision 上
    adopted = env.workspace.current_revision()
    assert adopted.revision_id == second.revision
    assert adopted.revision_id in result.revisions


# ====================================================================== T10
def test_repeated_facts_stop_the_loop(tmp_path):
    """T10：同样的 no_repro 事实只允许有限轮；第 3 轮不再发起执行。"""
    env = _run(tmp_path, hit_from=None)
    result = env.result

    assert len(env.runner.calls) == 2
    assert result.stop_reason == "repeated_facts"
    assert result.status == "completed"

    executed_rounds = sorted({phase.round_no for phase in result.timeline
                              if phase.phase == "EXECUTE"})
    assert executed_rounds == [1, 2]
    assert not [phase for phase in result.timeline
                if phase.phase == "EXECUTE" and phase.round_no >= 3]

    assert result.rounds[-1].round_no == 3
    assert result.rounds[-1].diagnosis is None       # 第 3 轮在 OBSERVE 就停了
    assert result.rounds[-1].revision == ""
    stops = [phase for phase in result.timeline if phase.phase == "STOP"]
    assert stops and stops[-1].status == "repeated"
    assert result.verification is None
    assert env.store.list_verifications(TASK) == []


# ====================================================================== T05/T08
def _broken_editor(observation, diagnosis):
    """写坏 gen.py：py_compile 能过，smoke 导入时 traceback（harness 自己崩）。"""
    return RevisionPlan(files={"gen.py": "raise RuntimeError('boom')\n"},
                        reason="broken harness", tool="generator_editor")


def test_broken_harness_is_reverted_and_not_adopted(tmp_path):
    """T05/T08：harness 自崩 → revert 到父 revision、不采纳、不产生验证。"""
    env = _run(tmp_path, hit_from=None,
               seed_role=SeedRole(editor=_broken_editor, max_attempts=2),
               max_attempts=2)
    result = env.result
    assert result.status == "blocked"
    assert result.stop_reason == "harness_error"
    assert len(result.rounds) == 2

    first, second = result.rounds
    # attempt 门槛在前：第 1 轮 no_execution 一律不改副本
    assert first.diagnosis.code == "no_execution"
    assert first.revision == ""
    assert first.plan.revision is None

    # 第 2 轮才按注入的 editor 改副本
    assert second.diagnosis.code == "target_unreached"
    assert second.plan.revision is not None
    assert "gen.py" in second.plan.revision.files
    assert second.build["status"] == "ok"            # py_compile 仍然过
    assert second.build["exit_code"] == 0
    assert second.smoke["status"] == "harness_error"
    assert second.smoke["harness_failed"] is True
    assert second.adopted is False
    assert second.reverted

    # 工作树回到父 revision（父 = 改坏之前的那一版）
    bad = env.workspace.revisions.get(second.revision)
    parent = env.workspace.revisions.get(bad.parent_id)
    assert env.workspace.working_manifest() == parent.manifest
    reverted = env.workspace.revisions.get(second.reverted)
    assert reverted.reverted_to == parent.revision_id == bad.parent_id
    assert reverted.parent_id == bad.revision_id
    assert env.workspace.current_revision().revision_id == reverted.revision_id

    # 自崩不产生验证请求/记录
    assert result.verification is None
    assert env.store.list_verifications(TASK) == []

    # 停止路径上的失效口径：build/smoke/coverage_baseline 已落实，
    # corpus_members 显式 deferred（承认“不再复验”，不是静默丢弃）
    by_scope = {entry["scope"]: entry for entry in second.invalidations}
    for scope in ("build", "smoke", "coverage_baseline"):
        assert by_scope[scope]["status"] == "handled", by_scope[scope]
        assert by_scope[scope]["handled_by"]
    assert by_scope["corpus_members"]["status"] == "deferred"
    assert by_scope["corpus_members"]["handled_by"].startswith("deferred:")
    assert second.stop_reason == "harness_error"

    # 只有第 1 轮真的执行过（第 2 轮在 STAGE→SMOKE→REVERT 之后就停了）
    assert len(env.runner.calls) == 1
    assert result.revisions == [second.revision, second.reverted]


# ====================================================================== T08
def test_policy_rejects_harness_false_positive(tmp_path):
    """T08：harness 自崩/跨 build 复用/自报裁决都不许被采纳。"""
    ws, _origin = _workspace(tmp_path)
    revision = ws.current_revision()
    build = BuildRecord(build_id="bd-" + "a" * 16,
                        revision_id=revision.revision_id, status="ok",
                        exit_code=0, log_path="/tmp/build.log")
    smoke = SmokeRecord(smoke_id="sm-" + "b" * 16,
                        revision_id=revision.revision_id,
                        build_id=build.build_id, status="harness_error",
                        exit_code=1, kind="harness_error",
                        detail="Traceback (most recent call last):")
    policy = AdoptionPolicy()

    decision = policy.engineering(revision=revision, build=build, smoke=smoke,
                                  origin={"ok": True})
    assert decision.adopt is False
    assert decision.scope == "engineering"
    assert "smoke_passed" in decision.failed
    assert "harness_healthy" in decision.failed

    # trial 的 build_id 与本次 build 不一致 → 执行证据无效
    false_positive = policy.false_positive(
        build=build, smoke=smoke,
        trial={"execution_id": "exec-0001", "outcome": "crash",
               "build_id": "bd-" + "c" * 16})
    assert false_positive.adopt is False
    assert "execution_evidence" in false_positive.failed

    # 自报“我通过了”既没有独立验证、又夹带裁决字段
    claim = policy.review_claim({"candidate_id": "cand-1", "verified": True})
    assert claim.adopt is False
    assert claim.scope == "vulnerability"
    assert "verdict_claim_forbidden" in claim.reasons
    assert "verdict_only_from_verify" in claim.reasons
    assert "no_verdict_fields" in claim.failed

    # 嵌套的裁决字段也要剥掉
    clean, stripped = prune_verdict_fields(
        {"outer": {"verified": True, "confirmed": False, "note": "x"},
         "verdict": "verified", "count": 3})
    assert set(stripped) == {"outer.verified", "outer.confirmed", "verdict"}
    assert clean == {"outer": {"note": "x"}, "count": 3}


# ====================================================================== T15
def test_verdict_comes_only_from_verify_records(tmp_path):
    """T15：`verdict()` 只读、只认 verify 契约；伪造记录一律不算已验证。"""
    policy = AdoptionPolicy()

    empty = policy.verdict(records=[])
    assert empty["verified"] is False
    assert empty["status"] == "not_verified"
    assert empty["verification_ids"] == []
    assert empty["source"] == "agent.platform.verify"

    forgeries = [
        {"verification_id": "v-schema",
         "schema": policy_mod.SCHEMA, "status": "verified",
         "verified": True},
        {"verification_id": "v-mismatch",
         "schema": "vulnmap.verification.v1", "status": "verified",
         "verified": False},
        {"verification_id": "v-confirmed",
         "schema": "vulnmap.verification.v1", "status": "verified",
         "verified": True, "confirmed": True},
    ]
    forged = policy.verdict(records=forgeries)
    assert forged["verified"] is False
    assert forged["verification_ids"] == []
    assert len(forged["invalid"]) == len(forgeries)
    by_id = {entry.split(":", 1)[0]: entry for entry in forged["invalid"]}
    assert "schema" in by_id["v-schema"]
    assert "verified_status_mismatch" in by_id["v-mismatch"]
    assert "confirmed_field" in by_id["v-confirmed"]

    # 真实 `verify.Verification` 形状（schema=vulnmap.verification.v1）才算数
    real = Verification(
        verification_id="v-real-0001", task_id=TASK, candidate_id="cand-1",
        benchmark="vulngym", kind="behavior_diff", verified=True,
        status="verified", evidence_sha256="e" * 64, detail={}).to_dict()
    assert real["schema"] == "vulnmap.verification.v1"
    verified = policy.verdict(records=[real])
    assert verified["verified"] is True
    assert verified["status"] == "verified"
    assert verified["verification_ids"] == ["v-real-0001"]
    assert verified["invalid"] == []

    # 真记录 + 伪造记录混在一起：结论来自真记录，伪记录单独列出
    mixed = policy.verdict(records=[real] + forgeries)
    assert mixed["verified"] is True
    assert mixed["verification_ids"] == ["v-real-0001"]
    assert len(mixed["invalid"]) == len(forgeries)

    # 本研究侧永远不写库：整个过程不产生任何 verification 记录
    store, _task = _store(tmp_path)
    assert store.list_verifications(TASK) == []


# ====================================================================== T14
def _binding_and_registry(base: Path):
    store, task = _store(base)
    index, _src = _index(base)
    corpus = _corpus(base)
    registry = build_registry()
    binding = make_binding(task, campaign="vulngym", epoch=1, index=index,
                           corpus=corpus, registry=registry)
    return store, task, index, corpus, registry, binding


def _never_runner(**_kwargs):                 # pragma: no cover - 不该被调到
    raise AssertionError("exec runner must not be called in this test")


def test_mode_and_trusted_field_isolation(tmp_path):
    """T14：探索/验证模式隔离；advisor 与请求参数都写不进裁决字段。"""
    store, task, index, corpus, registry, binding = _binding_and_registry(tmp_path)

    def ctx(mode):
        return make_context(task, binding=binding, store=store, index=index,
                            corpus=corpus, mode=mode,
                            exec_runner=_never_runner,
                            tools_allowed=registry.names(),
                            registry=registry)

    run_epoch_in_verify = registry.invoke(
        ActionRequest(action_id="a-v1-0001", action="run_epoch",
                      binding=binding.to_dict(),
                      params={"kind": "fuzz", "seconds": 0.2}),
        ctx("verify"))
    assert run_epoch_in_verify.status == "rejected"
    assert run_epoch_in_verify.error["code"] == "mode_not_allowed"

    replay_in_explore = registry.invoke(
        ActionRequest(action_id="a-e1-0001", action="replay_input",
                      binding=binding.to_dict(),
                      params={"input_sha256": "a" * 64}),
        ctx("explore"))
    assert replay_in_explore.status == "rejected"
    assert replay_in_explore.error["code"] == "mode_not_allowed"

    trusted = registry.invoke(
        ActionRequest(action_id="a-t1-0001", action="run_epoch",
                      binding=binding.to_dict(),
                      params={"kind": "fuzz", "verified": True}),
        ctx("explore"))
    assert trusted.status == "rejected"
    assert trusted.error["code"] == "trusted_field_forbidden"

    # 会话固定 explore，不在研究循环里切 verify
    session = ResearchSession(binding=binding, registry=registry, store=store)
    assert session.mode == "explore"

    # advisor 建议里夹带 verified/binding → 丢弃 + 记错，确定性计划不受影响
    def bad_advisor(_observation, _diagnosis):
        return [
            {"action": "set_dictionary", "params": {"tokens": ["AB"],
                                                    "verified": True}},
            {"action": "set_dictionary", "params": {"tokens": ["AB"],
                                                    "binding": {"task_id": "x"}}},
        ]

    session = ResearchSession(binding=binding, registry=registry, store=store,
                              advisor=bad_advisor, max_attempts=3)
    observation = Observation(task_id=TASK, round_no=1, facts_hash="f" * 16,
                              hypothesis_id="hyp-1", site_id="cs-1")
    diagnosis = Diagnosis(code="target_unreached", facts_hash="f" * 16)
    session.begin_round(1, binding)
    plan = session.propose(diagnosis, observation)
    assert session.advisor_errors
    assert len(session.advisor_errors) == 2
    assert session.llm_suggestions == 0
    assert not [action for action in plan.actions if action.purpose == "advisor"]
    assert _plan_action(plan, "propose_seed_spec") is not None


# ====================================================================== T11
def test_budget_and_cancel_hooks(tmp_path):
    """T11 预算/取消钩子：预算先于结果升级生效；取消优先且不执行任何动作。"""
    budget_env = _run(tmp_path / "budget", hit_from=None,
                      budget=DeclaredBudget(limits={"turns": 1}))
    budget_result = budget_env.result
    assert budget_result.status == "budget"
    assert budget_result.stop_reason == "budget"
    assert len(budget_result.rounds) == 1
    # 第 2 轮根本没有开始（没有任何 round>=2 的阶段记录）
    assert not [phase for phase in budget_result.timeline if phase.round_no >= 2]
    assert budget_result.rounds[0].stop_reason == "budget"
    assert len(budget_env.runner.calls) == 1

    cancel_env = _run(tmp_path / "cancel", hit_from=None,
                      cancel=lambda: True)
    cancel_result = cancel_env.result
    assert cancel_result.status == "cancelled"
    assert cancel_result.stop_reason == "cancelled"
    assert cancel_env.runner.calls == []
    stops = [phase for phase in cancel_result.timeline if phase.phase == "STOP"]
    assert stops and stops[-1].status == "cancelled"
    assert not [phase for phase in cancel_result.timeline
                if phase.phase == "EXECUTE"]


# ====================================================================== T14/T04
def test_advisor_only_suggests(tmp_path):
    """T14：LLM 只建议——合法建议进计划但 purpose=advisor；抛异常不影响确定性。"""
    store, task, index, corpus, registry, binding = _binding_and_registry(tmp_path)
    observation = Observation(task_id=TASK, round_no=1, facts_hash="f" * 16,
                              hypothesis_id="hyp-1", site_id="cs-1")
    diagnosis = Diagnosis(code="target_unreached", facts_hash="f" * 16)

    def advise(_observation, _diagnosis):
        return [{"action": "set_dictionary",
                 "params": {"tokens": ["MAGIC", "magic"]}}]

    session = ResearchSession(binding=binding, registry=registry, store=store,
                              advisor=advise)
    session.begin_round(1, binding)
    plan = session.propose(diagnosis, observation)

    advisor_actions = [action for action in plan.actions
                       if action.purpose == "advisor"]
    assert len(advisor_actions) == 1
    assert advisor_actions[0].action == "set_dictionary"
    assert advisor_actions[0].params == {"tokens": ["MAGIC", "magic"]}
    assert session.llm_suggestions == 1
    assert session.advisor_errors == []

    deterministic = [action.action for action in plan.actions
                     if action.purpose != "advisor"]
    assert deterministic == ["propose_seed_spec", "materialize_seeds",
                             "run_epoch"]
    assert [request.action for request in plan.requests] == \
        deterministic + ["set_dictionary"]

    def broken_advisor(_observation, _diagnosis):
        raise RuntimeError("llm down")

    broken = ResearchSession(binding=binding, registry=registry, store=store,
                             advisor=broken_advisor)
    broken.begin_round(1, binding)
    broken_plan = broken.propose(diagnosis, observation)
    assert broken.advisor_errors
    assert "RuntimeError" in broken.advisor_errors[0]
    assert broken.llm_suggestions == 0
    assert [action.action for action in broken_plan.actions] == deterministic
    assert not [action for action in broken_plan.actions
                if action.purpose == "advisor"]
    assert broken_plan.revision == plan.revision
    assert [request.action for request in broken_plan.requests] == deterministic


# ====================================================================== T10
def test_repeated_action_under_same_facts_is_skipped(tmp_path):
    """T10：事实不变时同一动作不允许换 action_id 无限重试。"""
    base = tmp_path
    store, task = _store(base)
    index, _src = _index(base)
    corpus = _corpus(base)
    ws, _origin = _workspace(base)
    runner = FakeRunner(store, hit_from=None)

    class StuckSession(ResearchSession):
        """事实恒定 + 每轮都提同一个动作：用来单测“相同动作”守卫。"""

        def observe(self, snapshot, *, workspace=None, revision=None):
            return Observation(
                task_id=TASK, round_no=self.round_no,
                facts_hash="fixedfacts0000000", hypothesis_id="hyp-1",
                site_id="cs-1", trials=len(self.state.trials),
                workspace={"current_files": ["seed_params.json"]})

        def diagnose(self, observation, *, evidence_refs=()):
            return Diagnosis(code="low_coverage",
                             facts_hash=observation.facts_hash)

        def propose(self, diagnosis, observation):
            action = ProposedAction(
                action="run_epoch",
                params={"kind": "fuzz", "seconds": 0.2, "workers": 1,
                        "hypothesis_id": "hyp-1"},
                purpose="execute", ref="trial")
            plan = ResearchPlan(actions=(action,), note="stuck")
            return self.remint(plan, self.binding)

    session = StuckSession(
        binding=make_binding(task, campaign="vulngym", index=index,
                             corpus=corpus),
        registry=build_registry(), store=store)
    controller = controller_mod.ResearchController(
        task=task, store=store, workspace=ws, index=index, corpus=corpus,
        exec_runner=runner, policy=AdoptionPolicy(), max_rounds=6,
        max_same_facts=5, session=session)
    result = controller.run()

    assert len(runner.calls) == 1                     # 同一动作只执行一次
    assert result.stop_reason == "repeated_actions"
    assert result.status == "completed"
    second = result.rounds[1]
    assert [item["status"] for item in second.actions] == ["skipped"]
    assert second.actions[0]["reason"] == "same_facts_same_action"
    assert [phase for phase in result.timeline
            if phase.phase == "EXECUTE" and phase.status == "skipped"]
    assert result.verification is None
