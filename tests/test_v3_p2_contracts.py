r"""V3 P2a 验收：V3-005（单一动作契约与 Registry）+ V3-006（可信执行快照）。

口径逐条对应需求与《V3 完整升级方案》§5/§6/§8：

1. **schema/handler/权限/invalidations 同源**
   - 工具表里每个 spec 的 `schema.properties` 与 handler 真实签名逐参数一致、
     `required` 由签名推出、`invalidations` 只能来自 `CHANGE_INVALIDATIONS[changes]`；
   - 签名漂移 / 失效范围自写一套 / 注册 L3 → 构造期 `ToolError`（不是运行期才发现）；
   - `tool_schema_hash` 随 schema 变化（binding 的一部分）。
2. **伪造身份拒绝**
   - 换 task_id、改 epoch 后沿用旧 hash、带了受信字段（verified…）、
     未授权任务跑 L1 工具、跨 execution 指定别的 execution_id —— 全部 `rejected`，
     且不落地任何变更、不产生失效登记。
3. **unknown 语义**
   - 没有覆盖指标 → `coverage.covered/delta/comparable` 都是 `unknown`，**不是 0**；
   - `new_coverage_bits` 无论 0 还是 >0 都**推不出** `checkpoint_reached`
     （覆盖动了 ≠ 目标分支命中；语义见 `docs/V3-TARGET-SEMANTICS.md`）；
   - 没有任何 execution → `get_execution_facts` 返回 `status=unknown`。
4. **跨 execution 拒绝**
   - 用 exec-A 的游标读 exec-B → `SnapshotError(cross_execution)`；
   - 合并两个 execution 的快照 → 同上；同 execution 合并允许。
5. **invalidations**
   - `set_dictionary` → `input_dedup`（进入待消费集，`consume_invalidations()` 清空）；
   - 同内容重复 → `noop` 且不登记失效；
   - `materialize_seeds` → 语料成员真的写进 `CorpusStore`（可反查父假设）。
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive import contracts, snapshot, tools
from agent.platform.adaptive.contracts import (BUDGET_LIMIT_KEYS,
                                              CHANGE_INVALIDATIONS,
                                              INVALIDATION_SCOPES, UNKNOWN,
                                              ActionRejected, ActionRequest,
                                              ActionResult, Binding,
                                              DeclaredBudget, Registry,
                                              SessionState, ToolContext,
                                              ToolError, ToolOutcome, ToolSpec)
from agent.platform.adaptive.corpus import CorpusStore, build_identity
from agent.platform.adaptive.snapshot import (CROSS_EXECUTION, Cursor,
                                              SnapshotError,
                                              TrustedExecutionSnapshot, tri)
from agent.platform.adaptive.tools import (MODE_EXPLORE, MODE_VERIFY, REGISTRY,
                                           make_binding, make_context)
from agent.platform.executors import EXEC_FACT_FIELDS, EXECUTORS
from agent.platform.program import ProgramIndex
from agent.platform.store import PlatformStore
from agent.platform.task import Budget, TaskSpec

TASK = "task-v3-p2a"
EXEC_A = "exec-aaaa0001"
EXEC_B = "exec-bbbb0002"


@pytest.fixture(autouse=True)
def _clean_registry_pending():
    """全局 REGISTRY 的待消费失效是进程级状态：每个用例前后清空，断言才与顺序无关。"""
    REGISTRY.consume_invalidations()
    yield
    REGISTRY.consume_invalidations()


# ------------------------------------------------------------------ fixtures
def _store(tmp_path, *, authorized=True, metadata=None):
    store = PlatformStore(tmp_path / "platform.db")
    meta = {"authorized": authorized} if metadata is None else dict(metadata)
    spec = TaskSpec(task_id=TASK, benchmark="vulngym",
                    target="http://127.0.0.1:9/target", mode="fuzz",
                    budget=Budget(max_seconds=600, max_execs=100000,
                                  max_tokens=100000, max_turns=12),
                    metadata=meta)
    store.create_task(spec)
    return store, store.get_task(TASK)


def _index(tmp_path):
    root = tmp_path / "src"
    root.mkdir(exist_ok=True)
    (root / "parse.c").write_text(
        "int parse(char *b) {\n  char dst[8];\n  memcpy(dst, b, 64);\n"
        "  return 0;\n}\n", encoding="utf-8")
    index = ProgramIndex(benchmark="vulngym", root=str(root), task_id=TASK,
                         entry_points=[{"name": "parse", "file": "parse.c"}],
                         functions=[{"name": "parse", "file": "parse.c"}],
                         call_sites=[{"id": "cs-1", "file": "parse.c",
                                      "line": 3, "function": "parse",
                                      "callee": "memcpy"}],
                         formats=["raw"], source_count=1, warnings=[])
    return index, root


def _hypotheses(store, *, site_id="cs-1"):
    store.save_hypotheses(TASK, [{
        "id": "hyp-1", "statement": "parse 的 memcpy 用未校验长度",
        "falsifiable_by": "同一输入在 vul/fix 双端行为不同",
        "evidence_gap": [], "cost": {"level": "low"}, "confidence": 0.6,
        "source": "static", "site_id": site_id, "hypothesis": "memcpy 溢出",
        "window": "parse.c:1-5", "falsification": "无差异",
    }])
    return store.list_hypotheses(TASK)


def _append_execution(store, exec_id, *, stats=None, coverage=None,
                      build=None, outcome="no_repro", error=None,
                      seeds=4, dictionary_tokens=7, budget=None):
    store.append_event(TASK, "exec.started", stage="RUNNING", payload={
        "exec_id": exec_id, "kind": "fuzz", "kind_override": "",
        "plan_sha256": "p" * 40, "benchmark": "vulngym",
        "target": "http://127.0.0.1:9/target",
        "budget": {"seconds": 5.0, "workers": 1, "timeout": 2.0},
        "caps": {"seconds": 5.0, "max_execs": 1000},
        "workdir": "/tmp/work",
    })
    store.append_event(TASK, "exec.finished", stage="RUNNING", payload={
        "exec_id": exec_id, "outcome": outcome, "kind": "fuzz",
        "plan_sha256": "p" * 40, "candidates": 0, "seconds": 1.5,
        "build": build if build is not None else {"sha256": "b" * 64,
                                                  "harness": "covfuzz"},
        "fuzz": stats if stats is not None else {
            "execs": 120, "crashes": 0, "timeouts": 0,
            "new_coverage_bits": 12, "workers": 1, "corpus_files": 4,
            "crash_files": 0, "setup_errors": 0, "setup_error": "",
            "slices": 1, "stopped": "completed"},
        "coverage": coverage if coverage is not None else {
            "planned": 5, "covered": 3, "uncovered": 2, "status": "partial",
            "pcs": 40, "mapped_locations": 3, "error": ""},
        "seeds": seeds, "dictionary_tokens": dictionary_tokens,
        "format": "raw",
        "budget_usage": {"seconds": 1.5, "execs": 120, "tokens": 0, "turns": 1},
        "budget": budget if budget is not None else {
            "limits": {"max_seconds": 600, "max_execs": 100000,
                       "max_tokens": 100000, "max_turns": 12},
            "used": {"seconds": 1.5, "execs": 120, "tokens": 0, "turns": 1},
            "remaining": {"seconds": 598.5, "execs": 99880,
                          "tokens": 100000, "turns": 11},
            "violations": []},
        "evidence_sha256": "e" * 64, "tokens": 0, "error": error,
    })


def _corpus(tmp_path, *, binary_sha="a" * 64):
    corpus = CorpusStore(tmp_path / "corpus", task_id=TASK, campaign="vulngym")
    corpus.begin(build_identity({"target": "parse", "flags": "-O0"},
                                binary_sha256=binary_sha, harness="covfuzz",
                                target="parse"))
    return corpus


class _Runner:
    """假执行 worker：只回执行反馈，不碰判定（真 worker 在 P2b 接）。"""

    def __init__(self, **feedback):
        self.feedback = feedback
        self.calls = []

    def __call__(self, *, kind, mode, params, binding):
        self.calls.append({"kind": kind, "mode": mode, "params": params,
                           "binding": binding})
        body = dict(self.feedback)
        body.setdefault("execution_id", f"exec-fake-{len(self.calls)}")
        return body


def _ctx(tmp_path, *, store=None, authorized=True, mode=MODE_EXPLORE,
         runner=None, corpus=None, index=None, session=None, grant=None,
         budget=None, extra_grant=()):
    if store is None:
        store, task = _store(tmp_path, authorized=authorized)
    else:
        task = store.get_task(TASK)
    if index is None:
        index, _ = _index(tmp_path)
    binding = make_binding(task, campaign="vulngym", epoch=0,
                           execution_id="", index=index, corpus=corpus)
    ctx = make_context(task, binding=binding, store=store, index=index,
                       corpus=corpus, session=session, mode=mode,
                       exec_runner=runner, extra_grant=extra_grant)
    if grant is not None:
        ctx.grant = grant
    if budget is not None:
        ctx.budget = budget
    return ctx


def _request(action, params=None, *, binding=None, action_id="act-1",
             budget=None, hypothesis_id="", evidence_refs=()):
    return ActionRequest(
        action_id=action_id, action=action,
        binding=binding if binding is not None else {},
        params=dict(params or {}), hypothesis_id=hypothesis_id,
        evidence_refs=tuple(evidence_refs), budget=dict(budget or {}))


# ============================================================ 1. schema 同源
def test_tool_table_schema_is_derived_from_handler():
    seen = set()
    for spec in REGISTRY.specs():
        signature = inspect.signature(spec.handler)
        names = [n for n in signature.parameters if n != "ctx"]
        assert set(names) == set(spec.schema["properties"]), spec.name
        assert list(spec.schema["required"]) == sorted(
            n for n in names
            if signature.parameters[n].default is inspect.Parameter.empty)
        assert spec.schema["additionalProperties"] is False
        assert spec.schema["type"] == "object"
        assert spec.schema["name"] == spec.name
        assert spec.schema["permission"] == spec.permission
        assert spec.schema["invalidations"] == list(spec.invalidations)
        for name, decl in spec.schema["properties"].items():
            assert decl["type"] in contracts._TYPE_CHECKS, (spec.name, name)
        # 失效范围必须与 changes 的派生值一致（工具不能自写一套）
        assert spec.invalidations == CHANGE_INVALIDATIONS[spec.changes]
        for scope in spec.invalidations:
            assert scope in INVALIDATION_SCOPES
        assert spec.permission in contracts.PERMISSIONS
        assert spec.permission not in contracts.NEVER_EXPOSED
        seen.add(spec.name)
    assert seen == set(tools.HANDLERS) == set(REGISTRY.names())
    assert seen == {"get_task_facts", "get_execution_facts", "read_source_window",
                    "propose_seed_spec", "materialize_seeds", "set_dictionary",
                    "run_epoch", "replay_input", "compare_trials",
                    "finish_research"}


def test_handler_signature_drift_fails_at_registration():
    def drifted(ctx, declared_only=None, undeclared=None):
        return ToolOutcome()

    with pytest.raises(ToolError) as exc:
        ToolSpec(name="drifted_tool", group="read", summary="漂移样例",
                 handler=drifted,
                 params={"declared_only": {"type": "string", "default": ""}})
    assert "schema/handler" in str(exc.value)

    def no_ctx(declared_only=""):
        return ToolOutcome()

    with pytest.raises(ToolError):
        ToolSpec(name="no_ctx_tool", group="read", summary="没有 ctx",
                 handler=no_ctx,
                 params={"declared_only": {"type": "string", "default": ""}})

    def varargs(ctx, **kwargs):
        return ToolOutcome()

    with pytest.raises(ToolError):
        ToolSpec(name="varargs_tool", group="read", summary="**kwargs",
                 handler=varargs, params={})


def test_invalidations_and_permission_must_be_declared_once():
    def handler(ctx, tokens=None):
        return ToolOutcome()  # tokens 默认 None，schema 也用 nullable None

    with pytest.raises(ToolError) as exc:
        ToolSpec(name="bad_scope", group="input", summary="自写失效范围",
                 handler=handler, params={"tokens": {"type": "array",
                                                     "default": None,
                                                     "nullable": True}},
                 changes="corpus", invalidations=("build",))
    assert "同源" in str(exc.value) or "不一致" in str(exc.value)

    with pytest.raises(ToolError):
        ToolSpec(name="l3_tool", group="close", summary="想写裁决",
                 handler=handler, permission="L3",
                 params={"tokens": {"type": "array", "default": None,
                                    "nullable": True}})

    with pytest.raises(ToolError):
        ToolSpec(name="bad_changes", group="input", summary="未知变更类别",
                 handler=handler, changes="magic",
                 params={"tokens": {"type": "array", "default": None,
                                    "nullable": True}})

    with pytest.raises(ToolError):
        ToolSpec(name="cost_on_read", group="read", summary="只读计费",
                 handler=handler, permission="L0", cost=lambda p: {"seconds": 1},
                 params={"tokens": {"type": "array", "default": None,
                                    "nullable": True}})


def test_tool_schema_hash_tracks_schema_changes():
    base = tools.build_registry()

    def handler(ctx, lines=1):
        return ToolOutcome()

    narrow = Registry([ToolSpec(name="probe", group="read", summary="窄",
                                handler=handler,
                                params={"lines": {"type": "integer",
                                                  "default": 1,
                                                  "maximum": 10}})])
    wide = Registry([ToolSpec(name="probe", group="read", summary="窄",
                              handler=handler,
                              params={"lines": {"type": "integer",
                                                "default": 1,
                                                "maximum": 20}})])
    assert narrow.tool_schema_hash != wide.tool_schema_hash
    assert base.tool_schema_hash == tools.build_registry().tool_schema_hash


def test_exec_kinds_mirror_installed_executors():
    assert set(tools.EXEC_KINDS) == set(EXECUTORS)


# ============================================================ 2. 伪造身份
@pytest.mark.parametrize("mutation", ["task", "epoch", "hash"])
def test_forged_identity_is_rejected(tmp_path, mutation):
    ctx = _ctx(tmp_path)
    claimed = json.loads(json.dumps(ctx.binding.to_dict()))
    if mutation == "task":
        claimed["task_id"] = "task-other"
        claimed["hash"] = Binding.from_dict({
            **{k: v for k, v in claimed.items() if k != "hash"}}).hash
    elif mutation == "epoch":
        claimed["epoch"] = int(claimed["epoch"]) + 1
        claimed.pop("hash")                 # 让 from_dict 用旧字段重算 → 与 ctx 不同
        claimed["hash"] = Binding.from_dict(claimed).hash
    else:
        claimed["hash"] = "b" + "0" * 32
    request = _request("get_task_facts", binding=claimed)
    result = REGISTRY.invoke(request, ctx)
    assert result.status == "rejected"
    assert result.error["code"] in ("forged_identity", "binding_mismatch")
    assert result.payload == {}
    assert result.invalidations == ()


def test_trusted_fields_cannot_be_written_by_model(tmp_path):
    ctx = _ctx(tmp_path)
    for params, field in (({"reason": "done", "verified": True}, "verified"),
                          ({"reason": "done", "status": "PASS"}, "status")):
        result = REGISTRY.invoke(
            _request("finish_research", params, binding=ctx.binding.to_dict()),
            ctx)
        assert result.status == "rejected"
        assert result.error["code"] == "trusted_field_forbidden"
        assert result.error["field"] == field
    assert ctx.state().finished is None


def test_permission_gate_follows_authorization(tmp_path):
    store, task = _store(tmp_path, authorized=False)
    ctx = _ctx(tmp_path, store=store)
    assert ctx.grant == frozenset({"L0"})       # 未授权任务：只有只读
    blocked = REGISTRY.invoke(
        _request("set_dictionary", {"tokens": ["A"]},
                 binding=ctx.binding.to_dict()), ctx)
    assert blocked.status == "rejected"
    assert blocked.error["code"] == "permission_denied"
    assert "L1" in blocked.error["reason"]
    assert ctx.state().dictionary == {}

    read = REGISTRY.invoke(
        _request("get_task_facts", binding=ctx.binding.to_dict()), ctx)
    assert read.status == "applied"
    assert read.payload["authorization"]["ok"] is False

    # L2 需要显式 allow_external；只授权 authorized=true 不够
    store2, _ = _store(tmp_path / "two", metadata={"authorized": True})
    ctx2 = _ctx(tmp_path / "two", store=store2)

    def handler(ctx, note=""):
        return ToolOutcome()

    l2 = ToolSpec(name="external_fetch", group="read", summary="外联",
                  handler=handler, permission="L2",
                  params={"note": {"type": "string", "default": "",
                                   "max_length": 20}})
    reg = Registry([l2])
    ctx2.tools_allowed = reg.names()
    result = reg.invoke(_request("external_fetch", binding=ctx2.binding.to_dict(),
                                 action_id="act-l2"), ctx2)
    assert result.status == "rejected"
    assert result.error["code"] == "permission_denied"

    ctx3 = _ctx(tmp_path / "three",
                store=_store(tmp_path / "three",
                             metadata={"authorized": True,
                                       "allow_external": True})[0])
    assert "L2" in ctx3.grant
    ctx3.tools_allowed = reg.names()
    assert reg.invoke(_request("external_fetch", binding=ctx3.binding.to_dict(),
                               action_id="act-l2"), ctx3).status == "applied"


def test_missing_identity_is_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    result = REGISTRY.invoke(_request("get_task_facts"), ctx)
    assert result.status == "rejected"
    assert result.error["code"] == "missing_identity"


# ============================================================ 3. unknown 语义
def test_unknown_is_not_zero_when_coverage_unavailable(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A,
                      stats={"execs": 90, "crashes": 0, "timeouts": 0,
                             "new_coverage_bits": None, "stopped": "completed",
                             "setup_error": ""},
                      coverage={"planned": 5, "covered": 0, "uncovered": 5,
                                "status": "unavailable",
                                "error": "covfuzz: no bitmap"})
    ctx = _ctx(tmp_path, store=store)
    result = REGISTRY.invoke(
        _request("get_execution_facts", {"execution_id": EXEC_A},
                 binding=ctx.binding.to_dict()), ctx)
    facts = result.payload["groups"]
    assert facts["coverage"]["covered"] == UNKNOWN      # 不是 0
    assert facts["coverage"]["uncovered"] == UNKNOWN    # 不是 5
    assert facts["coverage"]["metric_kind"] == UNKNOWN
    assert facts["coverage"]["delta"] == UNKNOWN
    assert facts["coverage"]["comparable"] == UNKNOWN
    assert "coverage.covered" in result.payload["unknowns"]
    assert "coverage.delta" in result.payload["unknowns"]
    # 目标可达：没有检查点探针 → checkpoint_reached/target_reached 都是 unknown，
    # 不能因为“覆盖指标缺失”就判成 false（false 只能来自显式探针）
    assert facts["input"]["target_reached"] == UNKNOWN
    assert facts["input"]["checkpoint_reached"] == UNKNOWN
    assert facts["input"]["program_started"] == "true"     # execs=90：进程真跑过
    assert facts["input"]["input_processed"] == UNKNOWN    # 没有输入探针
    assert facts["input"]["observation_source"] == "no_checkpoint_probe"
    # 有观测的部分照旧给真值
    assert facts["input"]["input_consumed"] == "true"
    assert facts["fault"]["outcome"] == "no_repro"
    assert facts["fault"]["candidates"] == 0            # 真报了 0 个候选
    assert result.status == "applied"
    assert result.payload["sources"]["coverage"] == "observed"


def test_zero_coverage_bits_does_not_mean_target_missing(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A,
                      stats={"execs": 10, "crashes": 0, "timeouts": 0,
                             "new_coverage_bits": 0, "stopped": "completed"},
                      coverage={"status": "complete", "planned": 5, "covered": 5,
                                "uncovered": 0})
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    assert snap.get("input.target_reached") == UNKNOWN
    assert snap.get("input.checkpoint_reached") == UNKNOWN
    assert snap.get("input.observation_source") == "no_checkpoint_probe"
    assert snap.get("coverage.covered") == 5            # 真值照给
    assert snap.tri("coverage.comparable") == UNKNOWN   # 没有 baseline 就不宣称可比

    # 反过来：bits>0 也不许推成“到达”（覆盖动了不等于目标分支命中）
    _append_execution(store, EXEC_B,
                      stats={"execs": 10, "crashes": 0, "timeouts": 0,
                             "new_coverage_bits": 12, "stopped": "completed"},
                      coverage={"status": "complete", "planned": 5, "covered": 5,
                                "uncovered": 0})
    snap_b = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_B)
    assert snap_b.get("input.target_reached") == UNKNOWN
    assert snap_b.get("input.checkpoint_reached") == UNKNOWN
    assert snap_b.get("input.program_started") == "true"


def test_no_execution_yet_reports_unknown(tmp_path):
    store, _ = _store(tmp_path)
    ctx = _ctx(tmp_path, store=store)
    result = REGISTRY.invoke(
        _request("get_execution_facts", binding=ctx.binding.to_dict()), ctx)
    assert result.status == UNKNOWN
    assert result.ok is False
    assert result.error["code"] == "no_execution_facts"
    payload = result.payload
    assert payload["execution_id"] == ""
    assert payload["groups"]["coverage"]["covered"] == UNKNOWN
    assert payload["groups"]["input"]["target_reached"] == UNKNOWN
    assert payload["status"] == UNKNOWN
    # 只有任务身份与预算声明是已知的
    assert payload["groups"]["identity"]["task_id"] == TASK


def test_snapshot_marks_sources_and_unknown_paths(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    index, _ = _index(tmp_path)
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A,
                                            index=index, campaign="vulngym")
    assert snap.sources["coverage"] == "observed"
    assert snap.sources["identity"] == "declared"
    assert snap.sources["budget"] == "declared"
    # iso/网络/命令不在事件里 → unknown（不编造）
    assert snap.get("config.isolation") == UNKNOWN
    assert snap.get("config.network") == UNKNOWN
    assert snap.get("config.command") == UNKNOWN
    assert "config.isolation" in snap.unknown_paths()
    # 声明过的真值照给
    assert snap.get("identity.build_id") == "b" * 64
    assert snap.get("input.seeds") == 4
    assert snap.get("budget.remaining_seconds") == 598.5
    assert snap.get("program.call_sites") == 1
    assert snap.get("coverage.covered") == 3
    assert snap.get("fault.outcome") == "no_repro"


# ============================================================ 4. 跨 execution
def test_cross_execution_cursor_is_rejected(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    _append_execution(store, EXEC_B)
    snap_a = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    snap_b = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_B)
    assert snap_a.execution_id != snap_b.execution_id

    with pytest.raises(SnapshotError) as exc:
        TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_B,
                                         cursor=snap_a.cursor)
    assert exc.value.code == CROSS_EXECUTION

    with pytest.raises(SnapshotError) as exc:
        snap_a.merge(snap_b)
    assert exc.value.code == CROSS_EXECUTION

    merged = snap_a.merge(TrustedExecutionSnapshot.collect(
        store, TASK, execution_id=EXEC_A))
    assert merged.execution_id == EXEC_A
    assert merged.get("coverage.covered") == 3

    # 工具层同样是拒绝，不是“帮你换个 execution”
    ctx = _ctx(tmp_path, store=store)
    result = REGISTRY.invoke(
        _request("get_execution_facts", {"execution_id": EXEC_A},
                 binding=Binding(
                     task_id=TASK, campaign="vulngym",
                     execution_id=EXEC_B,
                     identity=ctx.binding.identity).to_dict()), ctx)
    assert result.status == "rejected"
    assert result.error["code"] in ("cross_execution", "forged_identity")


def test_cursor_only_moves_forward(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    assert snap.cursor.seq >= 1
    with pytest.raises(SnapshotError):
        snap.cursor.advance(snap.cursor.seq - 1)
    later = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A,
                                             cursor=snap.cursor)
    assert later.cursor.seq == snap.cursor.seq
    assert later.events == 0            # 游标之后没有新事件，不是“没有事实”


# ============================================================ 5. invalidations
def test_invalidations_are_declared_consumed_and_idempotent(tmp_path):
    REGISTRY.consume_invalidations()          # 先清空：断言“恰好一条”，不依赖用例顺序
    ctx = _ctx(tmp_path)
    first = REGISTRY.invoke(
        _request("set_dictionary", {"tokens": ["A", "BB"]},
                 binding=ctx.binding.to_dict()), ctx)
    assert first.status == "applied"
    assert first.invalidations == ("input_dedup",)
    assert REGISTRY.pending_invalidations() == ("input_dedup",)
    assert REGISTRY.consume_invalidations() == ("input_dedup",)
    assert REGISTRY.pending_invalidations() == ()
    assert first.before_sha256 and first.after_sha256
    assert first.before_sha256 != first.after_sha256
    assert first.changed_fields == ("dictionary",)

    again = REGISTRY.invoke(
        _request("set_dictionary", {"tokens": ["BB", "A"]},
                 binding=ctx.binding.to_dict(), action_id="act-2"), ctx)
    assert again.status == "noop"            # 同内容 = 没变化
    assert again.invalidations == ()
    assert REGISTRY.pending_invalidations() == ()
    assert again.before_sha256 == again.after_sha256


def test_materialize_seeds_writes_corpus_and_invalidates(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    corpus = _corpus(tmp_path)
    ctx = _ctx(tmp_path, store=store, corpus=corpus)
    proposed = REGISTRY.invoke(
        _request("propose_seed_spec",
                 {"hypothesis_id": "hyp-1", "count": 3, "format": "raw"},
                 binding=ctx.binding.to_dict(), hypothesis_id="hyp-1"), ctx)
    assert proposed.status == "applied"
    spec = proposed.payload["seed_spec"]
    assert spec["hypothesis_id"] == "hyp-1"
    assert spec["site_id"] == "cs-1"        # 从假设带出，不用模型再填
    assert proposed.invalidations == ()     # 只提案，不失效任何东西

    made = REGISTRY.invoke(
        _request("materialize_seeds", {"spec_id": spec["spec_id"],
                                       "max_seeds": 3},
                 binding=ctx.binding.to_dict()), ctx)
    assert made.status == "applied"
    assert set(made.invalidations) == {"input_dedup", "corpus_members"}
    members = made.payload["materialized"]
    assert len(members) == 3
    for digest in members:
        entry = corpus.resolve(digest)
        assert entry is not None
        assert entry["hypothesis_id"] == "hyp-1"     # 可由内容反查父假设
        assert entry["site_id"] == "cs-1"
    snap = corpus.snapshot()
    assert snap["members"] == 3
    assert snap["hypotheses"] == ["hyp-1"]

    repeat = REGISTRY.invoke(
        _request("materialize_seeds", {"spec_id": spec["spec_id"],
                                       "max_seeds": 3},
                 binding=ctx.binding.to_dict(), action_id="act-3"), ctx)
    assert repeat.status == "noop"
    assert repeat.invalidations == ()


def test_rejected_actions_leave_no_invalidations(tmp_path):
    ctx = _ctx(tmp_path)
    before = REGISTRY.pending_invalidations()
    bad = REGISTRY.invoke(
        _request("set_dictionary", {"tokens": ["A"], "max_tokens": "many"},
                 binding=ctx.binding.to_dict()), ctx)
    assert bad.status == "rejected"
    assert bad.error["code"] == "invalid_params"
    assert bad.error["field"] == "max_tokens"
    assert REGISTRY.pending_invalidations() == before
    assert ctx.state().dictionary == {}


# ============================================================ 6. 参数与模式
def test_param_validation_is_uniform(tmp_path):
    ctx = _ctx(tmp_path)
    cases = [
        ("get_task_facts", {"include_evidence": "true"}, "include_evidence"),
        ("get_task_facts", {"nope": 1}, "nope"),
        ("read_source_window", {}, "path"),
        ("read_source_window", {"path": "parse.c", "max_lines": 10_000},
         "max_lines"),
        ("set_dictionary", {"tokens": ["hé"]}, "tokens"),
        ("run_epoch", {"seconds": 0}, "seconds"),
        ("compare_trials", {"left": "t-001", "right": "t-002",
                            "metric": "vibes"}, "metric"),
    ]
    for action, params, field in cases:
        result = REGISTRY.invoke(
            _request(action, params, binding=ctx.binding.to_dict()), ctx)
        assert result.status == "rejected", (action, params)
        assert result.error["code"] == "invalid_params", (action, params)
        assert result.error["field"] == field, (action, params)


def test_unknown_tool_and_unsupported_are_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    result = REGISTRY.invoke(
        _request("shell_exec", {"cmd": "sh"}, binding=ctx.binding.to_dict()), ctx)
    assert result.status == "rejected"
    assert result.error["code"] == "unknown_tool"
    assert "shell_exec" in result.error["reason"]

    def handler(ctx, note=""):
        return ToolOutcome()

    ctx.tools_allowed = None
    reg = Registry([ToolSpec(name="not_ready", group="read", summary="未接通",
                             handler=handler, unsupported="P3 才接",
                             params={"note": {"type": "string", "default": "",
                                              "max_length": 10}})])
    blocked = reg.invoke(_request("not_ready", binding=ctx.binding.to_dict(),
                                  action_id="act-x"), ctx)
    assert blocked.status == "rejected"
    assert blocked.error["code"] == "unsupported"


def test_explore_and_verify_modes_are_separated(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    corpus = _corpus(tmp_path)
    runner = _Runner(fuzz={"execs": 30, "new_coverage_bits": 4}, coverage={
        "status": "partial", "covered": 2, "planned": 5, "uncovered": 3})
    explore = _ctx(tmp_path, store=store, corpus=corpus, runner=runner,
                   mode=MODE_EXPLORE)
    ran = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=explore.binding.to_dict()),
        explore)
    assert ran.status == "applied"
    assert runner.calls[-1]["mode"] == MODE_EXPLORE

    verify = _ctx(tmp_path, store=store, corpus=corpus, runner=runner,
                  mode=MODE_VERIFY, session=explore.session)
    leak = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=verify.binding.to_dict(),
                 action_id="act-v1"), verify)
    assert leak.status == "rejected"
    assert leak.error["code"] == "mode_not_allowed"

    ctx_explore = _ctx(tmp_path, store=store, corpus=corpus, runner=runner,
                       mode=MODE_EXPLORE, session=explore.session)
    early = REGISTRY.invoke(
        _request("replay_input", {"input_sha256": "0" * 64},
                 binding=ctx_explore.binding.to_dict(), action_id="act-v2"),
        ctx_explore)
    assert early.status == "rejected"
    assert early.error["code"] == "mode_not_allowed"


# ============================================================ 7. 预算与拒绝原因
def test_budget_hook_blocks_and_settles(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    runner = _Runner(fuzz={"execs": 10, "new_coverage_bits": 1},
                     coverage={"status": "complete", "covered": 5, "planned": 5,
                               "uncovered": 0},
                     budget_usage={"seconds": 0.5, "execs": 10, "tokens": 0,
                                   "turns": 1})
    tight = DeclaredBudget(limits={"seconds": 1.0, "turns": 1},
                           used={"seconds": 0.5, "turns": 0})
    ctx = _ctx(tmp_path, store=store, runner=runner, budget=tight)
    blocked = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 2.0}, binding=ctx.binding.to_dict()),
        ctx)
    assert blocked.status == "rejected"
    assert blocked.error["code"] == "budget_exceeded"
    assert runner.calls == []                    # 没跑，就没花额度

    roomy = DeclaredBudget(limits={"seconds": 10.0, "turns": 3},
                           used={"seconds": 0.5, "turns": 0})
    ctx = _ctx(tmp_path, store=store, runner=runner, budget=roomy)
    ok = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict(),
                 action_id="act-b2"), ctx)
    assert ok.status == "applied"
    assert ok.budget["reserved"] == {"seconds": 1.0, "turns": 1.0}
    assert roomy.snapshot()["used"]["turns"] == 1.0     # 结算记到账上

    # 请求预算只当“我最多能花这么多”的上限：写小 → 没钱做，拒绝；
    # 写大 → 只是上限，不拦；写不认识的键 → 参数错误
    short = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict(),
                 action_id="act-b3", budget={"seconds": 0.5}), ctx)
    assert short.status == "rejected"
    assert short.error["code"] == "budget_exceeded"

    wide = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict(),
                 action_id="act-b4", budget={"seconds": 5.0}), ctx)
    assert wide.status == "applied"

    bogus = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict(),
                 action_id="act-b5", budget={"usd": 1.0}), ctx)
    assert bogus.status == "rejected"
    assert bogus.error["code"] == "invalid_params"


def test_handler_level_rejections_have_reasons(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    ctx = _ctx(tmp_path, store=store)
    cases = [
        ("propose_seed_spec", {"hypothesis_id": "hyp-404"}, "unknown_hypothesis"),
        ("materialize_seeds", {"spec_id": "ss-deadbeef"}, "unknown_seed_spec"),
        ("read_source_window", {"path": "../outside.c"},
         "source_path_outside_root"),
        ("replay_input", {"input_sha256": "0" * 64}, "mode_not_allowed"),
        ("compare_trials", {"left": "t-001", "right": "t-002"}, "unknown_trial"),
        ("run_epoch", {"kind": "qemu"}, "invalid_params"),
    ]
    for action, params, code in cases:
        result = REGISTRY.invoke(
            _request(action, params, binding=ctx.binding.to_dict()), ctx)
        assert result.status == "rejected", (action, params)
        assert result.error["code"] == code, (action, params)
        assert result.error["reason"], (action, params)
        assert result.error["hint"] is not None


def test_executor_absence_is_a_rejection_not_a_fake_run(tmp_path):
    ctx = _ctx(tmp_path, runner=None)
    result = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict()),
        ctx)
    assert result.status == "rejected"
    assert result.error["code"] == "executor_unavailable"
    assert ctx.state().trials == {}


def test_store_absence_and_unreadable_file(tmp_path):
    store, _ = _store(tmp_path)
    ctx = _ctx(tmp_path, store=store)
    ctx.store = None
    result = REGISTRY.invoke(
        _request("get_task_facts", binding=ctx.binding.to_dict()), ctx)
    assert result.status == "rejected"
    assert result.error["code"] == "store_unavailable"

    ctx = _ctx(tmp_path, store=store)
    missing = REGISTRY.invoke(
        _request("read_source_window", {"path": "nope.c"},
                 binding=ctx.binding.to_dict(), action_id="act-r2"), ctx)
    assert missing.status == "failed"
    assert missing.error["code"] == "source_unreadable"


# ============================================================ 8. 事实/对照
def test_task_facts_are_observed_counts(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    index, root = _index(tmp_path)
    store.save_program_index(TASK, index)
    _append_execution(store, EXEC_A)
    ctx = _ctx(tmp_path, store=store, index=index)
    result = REGISTRY.invoke(
        _request("get_task_facts", {"include_evidence": True},
                 binding=ctx.binding.to_dict()), ctx)
    assert result.status == "applied"
    counts = result.payload["counts"]
    assert counts["hypotheses"] == 1
    assert counts["candidates"] == 0            # 真的一个都没有
    assert counts["program_index"] == 1
    assert counts["events"] == 2
    assert result.payload["program"]["present"] == "true"
    # 用量来自事件流（exec.finished.seconds=1.5），不是拍脑袋的 0
    assert result.payload["budget"]["used"]["seconds"] == 1.5
    assert result.payload["budget"]["remaining"]["seconds"] == 598.5
    assert result.payload["authorization"]["ok"] is True
    assert result.payload["evidence"] == []


def test_compare_trials_refuses_cross_build_delta(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    corpus = _corpus(tmp_path)
    session = SessionState()
    session.trials["t-001"] = {"trial_id": "t-001", "build_id": "b1",
                               "metrics": {"covered": 5, "crashes": 0,
                                           "execs": 10},
                               "kind": "fuzz", "mode": MODE_EXPLORE,
                               "outcome": "no_repro", "unknowns": [],
                               "candidates": 0, "execution_id": "e1",
                               "budget_used": {}, "created_at": ""}
    session.trials["t-002"] = {**session.trials["t-001"], "trial_id": "t-002",
                               "build_id": "b2", "metrics": {
                                   "covered": 7, "crashes": 0, "execs": 10}}
    ctx = _ctx(tmp_path, store=store, corpus=corpus, session=session)

    cross = REGISTRY.invoke(
        _request("compare_trials", {"left": "t-001", "right": "t-002"},
                 binding=ctx.binding.to_dict()), ctx)
    assert cross.status == UNKNOWN
    assert cross.payload["comparable"] == "false"
    assert cross.payload["delta"] == UNKNOWN
    assert cross.payload["verdict"] == "not_evaluated"

    session.trials["t-002"]["build_id"] = "b1"
    same = REGISTRY.invoke(
        _request("compare_trials", {"left": "t-001", "right": "t-002"},
                 binding=ctx.binding.to_dict(), action_id="act-c2"), ctx)
    assert same.status == "applied"
    assert same.payload["comparable"] == "true"
    assert same.payload["delta"] == -2.0


def test_finish_research_only_records_reason(tmp_path):
    ctx = _ctx(tmp_path)
    done = REGISTRY.invoke(
        _request("finish_research", {"reason": "连续两轮无新增事实",
                                     "stop": "no_progress",
                                     "next_action": "换目标"},
                 binding=ctx.binding.to_dict()), ctx)
    assert done.status == "applied"
    assert done.invalidations == ()
    assert set(done.payload["finished"]) == {"reason", "stop", "next_action",
                                             "trials", "seeds", "at"}
    again = REGISTRY.invoke(
        _request("finish_research", {"reason": "连续两轮无新增事实",
                                     "stop": "no_progress"},
                 binding=ctx.binding.to_dict(), action_id="act-f2"), ctx)
    assert again.status == "noop"


# ============================================================ 9. 契约形状
def test_action_result_shape_and_five_states():
    result = ActionResult(action_id="act-1", tool="get_task_facts",
                          status="applied", before_sha256="a", after_sha256="b",
                          changed_fields=("dictionary",),
                          invalidations=("input_dedup",))
    doc = result.to_dict()
    assert set(doc) >= {"schema", "action_id", "tool", "status", "ok",
                        "binding_hash", "before_sha256", "after_sha256",
                        "changed_fields", "invalidations", "payload", "error",
                        "budget", "evidence_refs", "created_at"}
    assert doc["ok"] is True and doc["error"] is None
    assert contracts.STATUSES == ("applied", "noop", "rejected", "failed",
                                  "unknown")
    for status in contracts.STATUSES:
        item = ActionResult(action_id="act-1", tool="t", status=status)
        assert item.ok is (status in ("applied", "noop"))
        assert item.is_unknown is (status == "unknown")
    with pytest.raises(ToolError):
        ActionResult(action_id="act-1", tool="t", status="passed")


def test_fact_view_hook_matches_snapshot_inputs(tmp_path):
    """执行器只读钩子给出的字段，快照层真的在用（同源，不各写一套）。"""
    start = {"exec_id": EXEC_A, "kind": "fuzz", "budget": {"seconds": 5}}
    finish = {"exec_id": EXEC_A, "outcome": "no_repro",
              "build": {"sha256": "b" * 64, "harness": "covfuzz"},
              "fuzz": {"execs": 1, "new_coverage_bits": None,
                       "stopped": "completed", "setup_error": ""},
              "coverage": {"status": "unavailable"}, "error": None,
              "seeds": 2, "dictionary_tokens": 3, "format": "raw"}
    from agent.platform.executors import execution_fact_view
    view = execution_fact_view(start, finish)
    for key in ("present", "flags", "kind", "build", "fuzz", "coverage",
                "evidence_sha256", "error", "seeds", "dictionary_tokens",
                "format", "budget", "setup_error", "candidates", "outcome"):
        assert key in view, key
    assert view["fuzz"]["new_coverage_bits"] is None      # 不填 0
    assert view["flags"]["error_observed"] is True        # 明确观测到“无 error”
    assert view["flags"]["setup_error_observed"] is True
    assert set(EXEC_FACT_FIELDS) == {"start", "finish", "fuzz"}

    # 快照用同一份视图构建出的结论与之相符
    facts = snapshot._exec_view(start, finish)
    assert facts["fuzz"] == view["fuzz"]
    assert facts["flags"] == view["flags"]


def test_tool_context_budget_port_matches_task_budget(tmp_path):
    store, task = _store(tmp_path)
    ctx = _ctx(tmp_path, store=store)
    snap = ctx.budget.snapshot()
    for name, key in BUDGET_LIMIT_KEYS.items():
        if key in (task.get("budget") or {}):
            assert snap["limits"][name] == float(task["budget"][key])
    assert snap["used"]["turns"] == 0.0
    assert ctx.tools_allowed == REGISTRY.names()


# ============================================================ 10. 正向路径
def test_source_window_is_bounded_and_hashed(tmp_path):
    store, _ = _store(tmp_path)
    index, root = _index(tmp_path)
    ctx = _ctx(tmp_path, store=store, index=index)
    result = REGISTRY.invoke(
        _request("read_source_window", {"path": "parse.c", "start_line": 2,
                                        "max_lines": 2},
                 binding=ctx.binding.to_dict()), ctx)
    assert result.status == "applied"
    payload = result.payload
    assert payload["start_line"] == 2 and payload["end_line"] == 3
    assert payload["total_lines"] == 5
    assert payload["truncated"] is True
    assert [row["n"] for row in payload["lines"]] == [2, 3]
    assert payload["file_sha256"] == payload["file_sha256"].lower()
    assert len(payload["file_sha256"]) == 64
    assert result.invalidations == ()

    too_wide = REGISTRY.invoke(
        _request("read_source_window", {"path": "parse.c", "max_lines": 999},
                 binding=ctx.binding.to_dict(), action_id="act-rw2"), ctx)
    assert too_wide.status == "rejected"
    assert too_wide.error["code"] == "invalid_params"


def test_execution_facts_group_filter(tmp_path):
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    ctx = _ctx(tmp_path, store=store)
    one = REGISTRY.invoke(
        _request("get_execution_facts",
                 {"execution_id": EXEC_A, "groups": ["coverage"]},
                 binding=ctx.binding.to_dict()), ctx)
    assert one.status == "applied"
    assert set(one.payload["groups"]) == {"coverage"}
    bad = REGISTRY.invoke(
        _request("get_execution_facts", {"groups": ["vibes"]},
                 binding=ctx.binding.to_dict(), action_id="act-g2"), ctx)
    assert bad.status == "rejected"
    assert bad.error["code"] == "unknown_group"


def test_run_epoch_records_unknown_metrics(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    runner = _Runner(outcome="no_repro")            # 什么指标都没给
    ctx = _ctx(tmp_path, store=store, runner=runner)
    result = REGISTRY.invoke(
        _request("run_epoch", {"seconds": 1.0}, binding=ctx.binding.to_dict()),
        ctx)
    assert result.status == "applied"
    trial = result.payload["trial"]
    assert trial["metrics"]["covered"] == UNKNOWN
    assert trial["metrics"]["execs"] == UNKNOWN
    assert {"covered", "execs", "coverage_status"} <= set(trial["unknowns"])
    assert trial["build_id"] == UNKNOWN
    # 记录下来的 trial 可以参与对照，但结论只能是 unknown
    compared = REGISTRY.invoke(
        _request("compare_trials", {"left": trial["trial_id"],
                                    "right": trial["trial_id"]},
                 binding=ctx.binding.to_dict(), action_id="act-c3"), ctx)
    assert compared.status == UNKNOWN
    assert compared.payload["comparable"] == UNKNOWN
    assert compared.payload["delta"] == UNKNOWN


def test_verify_mode_replays_registered_input(tmp_path):
    store, _ = _store(tmp_path)
    _hypotheses(store)
    corpus = _corpus(tmp_path)
    entry = corpus.add(b'{"a": 1}', hypothesis_id="hyp-1", site_id="cs-1",
                       source="test", origin="seed")
    runner = _Runner(crashed=True, outcome="candidate",
                     evidence_sha256="e" * 64,
                     fuzz={"execs": 1, "new_coverage_bits": 3},
                     coverage={"status": "complete", "covered": 1,
                               "planned": 1, "uncovered": 0})
    ctx = _ctx(tmp_path, store=store, corpus=corpus, runner=runner,
               mode=MODE_VERIFY)
    result = REGISTRY.invoke(
        _request("replay_input", {"input_sha256": entry["sha256"]},
                 binding=ctx.binding.to_dict()), ctx)
    assert result.status == "applied"
    trial = result.payload["trial"]
    assert trial["mode"] == MODE_VERIFY
    assert trial["reproduced"] == "true"
    assert trial["input_sha256"] == entry["sha256"]
    assert trial["parent_hypothesis"] == "hyp-1"      # 输入可反查父假设
    assert result.evidence_refs == ("e" * 64,)
    assert runner.calls[-1]["kind"] == "replay"
    assert set(result.invalidations) == {"execution_facts", "trial_compare",
                                         "coverage_baseline"}
    assert set(REGISTRY.consume_invalidations()) >= {"execution_facts"}


# ============================================================ 11. 失败不留半截
def test_failed_handler_rolls_back_and_charges(tmp_path):
    store, _ = _store(tmp_path)

    def explodes(ctx, note=""):
        ctx.state().dictionary = {"tokens": ["LEAK"], "digest": "x",
                                 "version": 99}
        ctx.state().touch()
        raise RuntimeError("worker died mid-write")

    def refuses_after_write(ctx, note=""):
        ctx.state().dictionary = {"tokens": ["LEAK"], "digest": "x",
                                 "version": 99}
        ctx.state().touch()
        raise ActionRejected("nope", "读后发现假设不存在")

    budget = DeclaredBudget(limits={"seconds": 10.0, "turns": 2},
                            used={"seconds": 0.0, "turns": 0})
    reg = Registry([
        ToolSpec(name="boom", group="experiment", summary="会崩的实验",
                 handler=explodes, permission="L1", changes="execution",
                 cost=lambda p: {"seconds": 2.0, "turns": 1},
                 params={"note": {"type": "string", "default": "",
                                  "max_length": 10}}),
        ToolSpec(name="nope_tool", group="experiment", summary="读后拒绝",
                 handler=refuses_after_write, permission="L1",
                 changes="execution",
                 cost=lambda p: {"seconds": 2.0, "turns": 1},
                 params={"note": {"type": "string", "default": "",
                                  "max_length": 10}}),
    ])
    ctx = _ctx(tmp_path, store=store, budget=budget)
    ctx.tools_allowed = reg.names()
    failed = reg.invoke(_request("boom", binding=ctx.binding.to_dict()), ctx)
    assert failed.status == "failed"
    assert failed.error["code"] == "handler_error"
    assert "worker died" in failed.error["reason"]
    assert ctx.state().dictionary == {}          # 半截变更被回滚
    assert failed.invalidations == ()
    assert reg.pending_invalidations() == ()
    # 崩了的动作按预留保守扣账（usage 不明，不填 0）
    assert budget.snapshot()["used"]["seconds"] == 2.0
    assert budget.snapshot()["used"]["turns"] == 1.0

    rejected = reg.invoke(_request("nope_tool", binding=ctx.binding.to_dict(),
                                   action_id="act-n2"), ctx)
    assert rejected.status == "rejected"
    assert rejected.error["code"] == "nope"
    assert ctx.state().dictionary == {}
    assert budget.snapshot()["used"]["seconds"] == 2.0   # 没做事就不加钱


# ============================================================ 12. 身份分量
@pytest.mark.parametrize("mutation", ["extra_identity", "unknown_field"])
def test_binding_rejects_smuggled_identity_parts(tmp_path, mutation):
    ctx = _ctx(tmp_path)
    claimed = json.loads(json.dumps(ctx.binding.to_dict()))
    if mutation == "extra_identity":
        claimed["identity"]["trusted"] = "true"
    else:
        claimed["tool_schema_hash"] = "0" * 64
    result = REGISTRY.invoke(
        _request("get_task_facts", binding=claimed), ctx)
    assert result.status == "rejected"
    assert result.error["code"] in ("invalid_identity", "forged_identity")


def test_binding_identity_covers_tool_schema(tmp_path):
    """工具 schema 是绑定身份的一部分：换一张工具表就是新绑定。"""
    store, task = _store(tmp_path)

    def handler(ctx, note=""):
        return ToolOutcome()

    alt = Registry([ToolSpec(name="probe", group="read", summary="另一张表",
                             handler=handler,
                             params={"note": {"type": "string", "default": "",
                                              "max_length": 8}})])
    a = make_binding(task, registry=REGISTRY)
    b = make_binding(task, registry=alt)
    assert a.hash != b.hash
    assert a.identity["tool_schema_hash"] == REGISTRY.tool_schema_hash
    assert b.identity["tool_schema_hash"] == alt.tool_schema_hash
    ctx = _ctx(tmp_path, store=store)
    result = REGISTRY.invoke(
        _request("get_task_facts", binding=b.to_dict()), ctx)
    assert result.status == "rejected"
    assert result.error["code"] in ("forged_identity", "binding_mismatch")


# ============================================================ 13. 复审回归
def test_complete_status_without_metric_is_unknown(tmp_path):
    """B1：status=complete 但没有任何覆盖读数 → 指标/截断/可比都必须 unknown。"""
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A,
                      coverage={"status": "complete", "baseline_id": "base-1"})
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    assert snap.get("coverage.metric_kind") == UNKNOWN
    assert snap.get("coverage.covered") == UNKNOWN
    assert snap.get("coverage.truncated") == UNKNOWN
    assert snap.get("coverage.comparable") == UNKNOWN
    assert snap.get("coverage.delta") == UNKNOWN
    assert "coverage.comparable" in snap.unknown_paths()


def test_running_execution_has_no_result_status(tmp_path):
    """B2：只有 exec.started（还在跑）→ 不能报 applied，也不能编观测来源。"""
    store, _ = _store(tmp_path)
    store.append_event(TASK, "exec.started", stage="RUNNING", payload={
        "exec_id": EXEC_A, "kind": "fuzz", "plan_sha256": "p" * 40,
        "budget": {"seconds": 5.0}, "workdir": "/tmp/work"})
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    assert snap.complete is False
    assert snap.status == UNKNOWN
    assert snap.get("input.observation_source") == UNKNOWN
    assert snap.get("input.target_reached") == UNKNOWN
    assert snap.get("config.engine") == "fuzz"      # 已知的照给

    ctx = _ctx(tmp_path, store=store)
    result = REGISTRY.invoke(
        _request("get_execution_facts", {"execution_id": EXEC_A},
                 binding=ctx.binding.to_dict()), ctx)
    assert result.status == UNKNOWN
    assert result.payload["complete"] is False


def test_untracked_denials_are_unknown_not_empty(tmp_path):
    """B3：没有追踪过拒绝记录 → unknown；追踪过且为空 → 才是 []。"""
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    plain = _ctx(tmp_path, store=store)
    assert plain.denials is None
    untracked = REGISTRY.invoke(
        _request("get_execution_facts", {"execution_id": EXEC_A},
                 binding=plain.binding.to_dict()), plain)
    assert untracked.payload["groups"]["budget"]["denials"] == UNKNOWN

    base = _ctx(tmp_path, store=store)
    tracked = make_context(store.get_task(TASK), binding=base.binding,
                           store=store, index=base.index,
                           tools_allowed=REGISTRY.names(), denials=())
    tracked_result = REGISTRY.invoke(
        _request("get_execution_facts", {"execution_id": EXEC_A},
                 binding=tracked.binding.to_dict(), action_id="act-d2"),
        tracked)
    assert tracked_result.payload["groups"]["budget"]["denials"] == []


def test_tools_allowed_is_enforced(tmp_path):
    """B3：会话允许集合之外的工具体不得执行。"""
    ctx = _ctx(tmp_path)
    ctx.tools_allowed = ("get_task_facts",)
    blocked = REGISTRY.invoke(
        _request("set_dictionary", {"tokens": ["A"]},
                 binding=ctx.binding.to_dict()), ctx)
    assert blocked.status == "rejected"
    assert blocked.error["code"] == "tool_not_allowed"
    assert ctx.state().dictionary == {}


def test_partial_corpus_write_is_failed_not_rejected(tmp_path):
    """B4：第 2 条语料写失败时，磁盘已有成员 → 必须报 failed 且登记 corpus_members。"""
    REGISTRY.consume_invalidations(TASK)
    store, _ = _store(tmp_path)
    _hypotheses(store)
    real = _corpus(tmp_path)

    class _Flaky:
        def __init__(self, inner):
            self.inner = inner
            self.calls = 0

        def add(self, *a, **kw):
            self.calls += 1
            if self.calls == 2:
                raise OSError("disk full")
            return self.inner.add(*a, **kw)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    flaky = _Flaky(real)
    ctx = _ctx(tmp_path, store=store, corpus=flaky)
    proposed = REGISTRY.invoke(
        _request("propose_seed_spec", {"hypothesis_id": "hyp-1", "count": 3},
                 binding=ctx.binding.to_dict()), ctx)
    spec_id = proposed.payload["seed_spec"]["spec_id"]
    result = REGISTRY.invoke(
        _request("materialize_seeds", {"spec_id": spec_id, "max_seeds": 3},
                 binding=ctx.binding.to_dict(), action_id="act-m2"), ctx)
    assert result.status == "failed"
    assert result.error["code"] == "corpus_write_failed"
    assert len(result.payload["materialized"]) == 1        # 既成事实，如实报
    written = result.payload["materialized"][0]
    assert real.resolve(written) is not None               # 磁盘上确实有
    assert written in ctx.state().seeds                    # 台账与磁盘一致（未回滚）
    assert set(result.invalidations) == {"input_dedup", "corpus_members"}
    assert "corpus_members" in REGISTRY.pending_invalidations(TASK)

    clean = REGISTRY.invoke(
        _request("materialize_seeds", {"spec_id": spec_id, "max_seeds": 3},
                 binding=ctx.binding.to_dict(), action_id="act-m3"), ctx)
    assert clean.status in ("applied", "noop")


def test_default_values_must_match_handler_signature():
    """①：schema 默认 7、handler 默认 None 这种两套口径要构造期就失败。"""
    def handler(ctx, lines=None):
        return ToolOutcome()

    with pytest.raises(ToolError) as exc:
        ToolSpec(name="default_drift", group="read", summary="默认值漂移",
                 handler=handler,
                 params={"lines": {"type": "integer", "default": 7}})
    assert "默认值不同源" in str(exc.value)

    def other(ctx, lines):
        return ToolOutcome()

    with pytest.raises(ToolError):
        ToolSpec(name="default_invented", group="read", summary="凭空默认",
                 handler=other,
                 params={"lines": {"type": "integer", "default": 7}})


@pytest.mark.parametrize("field", ["verified", "confirmed", "verdict", "status"])
def test_adjudication_fields_can_never_be_declared(field):
    """②：任何工具都不许把裁决字段声明成参数（不是“声明后再比对”）。"""
    def handler(ctx, **kwargs):
        return ToolOutcome()

    def named(ctx, value=""):
        return ToolOutcome()

    with pytest.raises(ToolError) as exc:
        ToolSpec(name="sneaky", group="close", summary="想写裁决",
                 handler=named,
                 params={field: {"type": "string", "default": "",
                                 "max_length": 20}})
    assert "裁决/可信字段" in str(exc.value) or "不对账" in str(exc.value)


def test_merge_refuses_cross_task(tmp_path):
    """④：同名 execution 但不同任务/不同绑定也不能合并。"""
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A)
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A,
                                            binding_hash="b" + "1" * 31)
    other_task = TrustedExecutionSnapshot(
        task_id="task-other", execution_id=EXEC_A, groups=snap.groups,
        cursor=snap.cursor, sources=snap.sources, complete=True,
        binding_hash="b" + "1" * 31)
    with pytest.raises(SnapshotError) as exc:
        snap.merge(other_task)
    assert exc.value.code == CROSS_EXECUTION

    other_binding = TrustedExecutionSnapshot(
        task_id=TASK, execution_id=EXEC_A, groups=snap.groups,
        cursor=snap.cursor, sources=snap.sources, complete=True,
        binding_hash="b" + "2" * 31)
    with pytest.raises(SnapshotError) as exc:
        snap.merge(other_binding)
    assert exc.value.code == "binding_mismatch"


def test_failed_with_changes_only_spares_external_effects(tmp_path):
    """只有“会话外副作用”类别才能用 changed_fields 换来不回滚。"""
    store, _ = _store(tmp_path)

    def sneaky(ctx, note=""):
        ctx.state().dictionary = {"tokens": ["SNEAK"], "digest": "x",
                                 "version": 1}
        ctx.state().touch()
        return ToolOutcome(status="failed", changed_fields=("dictionary",),
                           invalidations=("input_dedup",),
                           error={"code": "pretend_failed", "reason": "假装失败",
                                  "field": "", "hint": ""})

    reg = Registry([ToolSpec(name="sneaky_fail", group="input", summary="想逃回滚",
                             handler=sneaky, permission="L1",
                             changes="dictionary",
                             params={"note": {"type": "string", "default": "",
                                              "max_length": 10}})])
    ctx = _ctx(tmp_path, store=store)
    ctx.tools_allowed = reg.names()
    result = reg.invoke(_request("sneaky_fail", binding=ctx.binding.to_dict()),
                        ctx)
    assert result.status == "failed"
    assert ctx.state().dictionary == {}          # dictionary 类别的失败仍然回滚
    assert reg.pending_invalidations(TASK) == ()


def test_empty_finish_event_is_not_a_conclusion(tmp_path):
    """N1：只有 {"exec_id": ...} 的 exec.finished → 没有实质观测，status 仍是 unknown。"""
    store, _ = _store(tmp_path)
    store.append_event(TASK, "exec.finished", stage="RUNNING",
                       payload={"exec_id": "exec-empty-1"})
    snap = TrustedExecutionSnapshot.collect(store, TASK,
                                            execution_id="exec-empty-1")
    assert snap.complete is True            # 事件确实到了
    assert snap.observed() is False         # 但没有任何实质观测
    assert snap.status == UNKNOWN
    # 标签可以说明“为什么没有”（这里=事件里没有检查点探针），但不能被当成观测
    assert snap.get("input.observation_source") in (UNKNOWN, "no_checkpoint_probe")
    assert snap.get("fault.setup_error_detail") in ("", UNKNOWN)
    assert "input.target_reached" in snap.unknown_paths()


def test_synthetic_labels_alone_do_not_upgrade_status(tmp_path):
    """N1：只有合成标签（observation_source / *_detail）也不许把 status 抬成 applied。"""
    store, _ = _store(tmp_path)
    _append_execution(store, EXEC_A,
                      stats={"execs": 0, "stopped": "completed"},
                      coverage={"status": "unavailable", "error": ""},
                      build=None)
    snap = TrustedExecutionSnapshot.collect(store, TASK, execution_id=EXEC_A)
    # outcome 是实质观测，所以这里是 applied —— 但 coverage 组不得因标签变“有值”
    assert snap.status == "applied"
    assert snap.get("coverage.status") == "unavailable"
    assert snap.get("coverage.metric_kind") == UNKNOWN
    assert "coverage.metric_kind" in snap.unknown_paths()


def test_rolled_back_failure_declares_nothing(tmp_path):
    """N4：回滚后的 failed 不能对外声明 changed_fields / invalidations。"""
    store, _ = _store(tmp_path)

    def sneaky(ctx, note=""):
        ctx.state().dictionary = {"tokens": ["SNEAK"], "digest": "x",
                                 "version": 1}
        ctx.state().touch()
        return ToolOutcome(status="failed", changed_fields=("dictionary",),
                           invalidations=("input_dedup",),
                           error={"code": "pretend_failed", "reason": "x",
                                  "field": "", "hint": ""})

    reg = Registry([ToolSpec(name="sneaky2", group="input", summary="逃回滚",
                             handler=sneaky, permission="L1",
                             changes="dictionary",
                             params={"note": {"type": "string", "default": "",
                                              "max_length": 8}})])
    ctx = _ctx(tmp_path, store=store)
    ctx.tools_allowed = reg.names()
    result = reg.invoke(_request("sneaky2", binding=ctx.binding.to_dict()), ctx)
    assert result.status == "failed"
    assert result.changed_fields == ()
    assert result.invalidations == ()
    assert result.payload["rolled_back"] is True
    assert ctx.state().dictionary == {}
    assert reg.pending_invalidations(TASK) == ()
    assert reg.consume_invalidations(TASK) == ()


def test_external_effect_keeps_only_declared_fields(tmp_path):
    """N2：corpus 类工具只能保留自己**声明过**的会话字段，顺手改的字典照样回滚。"""
    store, _ = _store(tmp_path)

    def sloppy(ctx, note=""):
        session = ctx.state()
        session.seeds = {"fake": {"sha256": "f" * 64}}
        session.dictionary = {"tokens": ["SMUGGLED"], "digest": "y",
                              "version": 7}
        session.touch()
        return ToolOutcome(
            status="failed", changed_fields=("seeds",),
            invalidations=("input_dedup", "corpus_members"),
            error={"code": "corpus_write_failed", "reason": "partial",
                   "field": "", "hint": ""})

    reg = Registry([ToolSpec(name="sloppy_corpus", group="input",
                             summary="写一半的语料工具", handler=sloppy,
                             permission="L1", changes="corpus",
                             params={"note": {"type": "string", "default": "",
                                              "max_length": 8}})])
    ctx = _ctx(tmp_path, store=store)
    ctx.tools_allowed = reg.names()
    result = reg.invoke(_request("sloppy_corpus",
                                 binding=ctx.binding.to_dict()), ctx)
    assert result.status == "failed"
    assert ctx.state().seeds == {"fake": {"sha256": "f" * 64}}   # 声明过 → 保留
    assert ctx.state().dictionary == {}                          # 没声明 → 回滚
    assert set(result.invalidations) == {"input_dedup", "corpus_members"}
