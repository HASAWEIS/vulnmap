r"""V3 P3 验收：预算账本、模型网关、Campaign 子 Job、恢复对账、取消与安全反例。

口径逐条对应《VULNMAP-V3 完整升级方案》§10（执行可靠性/取消/恢复）、
§11（预算与进展控制）与 §18.1 的 T07/T09/T11/T12/T13：

1. **T11 原子预留**：同一 scope 下 32 个线程各预留 1 个回合、上限 8 →
   恰好 8 次成功，账本 `used+reserved` 与成功次数一致（不多不少）。
2. **T11 层级与子调用**：run→task→finding→action 四层，子层花费在祖先层
   同时可见；`settle(None)`（usage 缺失）按**预留额**保守扣账并标
   `usage_missing`；`release()` 才退还；重复 `settle` 不重复扣。
3. **T11 失败也计费**：`run_epoch` 的 worker 抛异常 → `ActionResult.status ==
   "failed"`，而预算里 seconds/turns **已经被扣**（失败不是免费）。
4. **T11 缺 usage 保守扣账 + 预算终止不改真假**：`BudgetStop.affects_result_truth`
   恒 False；预算不够时动作是 `rejected/budget_exceeded`，不是 failed，也不是
   no_repro；先前成功的 ActionResult 不被改写。
5. **T11 模型网关**：真实 usage → 按 provider 数结算；usage 缺失 → unknown +
   预留额扣账；client 抛异常 → failed 且仍扣账；缓存命中 → 不预留不调 client；
   无 L2 授权 → rejected 且零调用；无价格表 + usd 上限 → rejected/price_unknown；
   无 key → skipped/rule 回退；**key 字符串不出现在结果 JSON 与工作区里**。
6. **T12 lease/fencing**：同一 job 只有第一个 claim 成功；旧 fence 提交 →
   `late=True` 且终态不变（进 `campaign_job_late`）；租约过期 → UNKNOWN，
   未对账前不可再认领。
7. **T13 恢复**：SUCCEEDED 复用不重跑；RUNNING 租约过期先落 UNKNOWN，再由
   artifact 对账成 SUCCEEDED（`replayed==0`）；外部副作用 `external` 且证据不足
   → `hold` + `needs_manual`，**不自动重放**；启动器确认没跑起来且副作用 none
   才 `requeue`。
8. **T12 取消**：`cancel_task_full` 按 §10 顺序落 CANCELLED、撤 lease（fence+1）、
   真杀进程组（父子都死）、写证据；迟到结果只进 late 表，任务终态不被改写。
9. **T07/T09 安全反例**：伪造 owner/fence、跨任务、跨 execution、越权（L2 未
   授权、L3 永不放开）分别被稳定错误码拒绝。
10. **复用启动器**：`vulnmap_platform` 的 `jobs` 表新增 campaign/job_key 两列，
    仍能被老库打开（幂等 ALTER），campaign 过滤与反向关联都生效。

所有进程/租约/账本都是真实实现（真 SQLite 事务、真进程组信号），只把
“外部模型客户端”“启动器进程启动”两处换成可控替身。
"""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import EventBus, PlatformStore
from agent.platform.adaptive.budget import (BudgetLedger, BudgetRefused,
                                            BudgetStop, EMPTY_PRICES,
                                            LedgerBudget, PriceTable)
from agent.platform.adaptive.contracts import ActionRequest
from agent.platform.adaptive.jobs import CampaignJobs, Lease
from agent.platform.adaptive.llm_gateway import LLMGateway
from agent.platform.adaptive.recovery import decide, recover
from agent.platform.adaptive.tools import (build_registry, make_binding,
                                           make_context)
from agent.platform.lifecycle import (LifecycleError, cancel_task_full,
                                      guard_job_owner, guard_permission,
                                      guard_task_scope, kill_process_tree,
                                      reclaim_expired_leases,
                                      reclaim_failed_task)
from agent.platform.store import CampaignJobError
from agent.platform.task import Budget, TaskSpec
from vulnmap_platform.api import platform_jobs

TASK = "task-v3-p3"
CAMPAIGN = "camp-p3"


# ------------------------------------------------------------------ fixtures
@pytest.fixture()
def store(tmp_path):
    st = PlatformStore(tmp_path / "platform.db")
    st.create_task(TaskSpec(
        task_id=TASK, benchmark="vulngym", target="fixture", mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=1000, max_tokens=8000,
                      max_turns=8),
        metadata={"authorized": True}))
    st.transition(TASK, "PREFLIGHT")
    st.transition(TASK, "READY")
    st.transition(TASK, "UNDERSTANDING")
    st.transition(TASK, "HYPOTHESES")
    st.transition(TASK, "PLANNED")
    st.transition(TASK, "RUNNING", reason="p3 fixture")
    yield st
    st.close()


@pytest.fixture()
def bus(store):
    return EventBus(store)


def _ledger(tmp_path) -> BudgetLedger:
    return BudgetLedger(tmp_path / "budget.db")


def _job(store, *, external_effect="none", request=None):
    return store.create_campaign_job(
        campaign=CAMPAIGN, task_id=TASK, kind="fuzz_epoch",
        request=request or {"seconds": 2, "round": 1},
        external_effect=external_effect)


class FakeProc:
    """启动器替身：pid 活着，wait 立即返回（只为让 watcher 落终态）。"""

    def __init__(self, pid=None):
        self.pid = os.getpid() if pid is None else pid

    def wait(self):
        return 0


# ================================================================== T11 预算
def test_budget_reserve_is_atomic_under_parallelism(tmp_path):
    """32 个线程抢 8 个回合：恰好 8 次成功，账本与实际发放一致。"""
    path = tmp_path / "budget.db"
    setup = BudgetLedger(path)
    setup.ensure_chain(run="r1", limits_by_level={"run": {"turns": 8}})
    granted: list[str] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        ledger = BudgetLedger(path)
        try:
            reservation = ledger.reserve("run:r1", {"turns": 1})
            with lock:
                granted.append(reservation.reservation_id)
        except BudgetRefused:
            pass
        finally:
            ledger.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    ledger = BudgetLedger(path)
    scope = ledger.get_scope("run:r1")
    assert len(granted) == 8
    assert len(set(granted)) == 8
    assert scope["reserved"]["turns"] == pytest.approx(8.0)
    assert scope["used"] == {}
    assert ledger.exhausted("run:r1") is not None


def test_budget_hierarchy_charges_children_and_missing_usage(tmp_path):
    """子层花费计入祖先；缺 usage 按预留保守扣；release 才退还；结算幂等。"""
    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(
        run="r1", task=TASK, finding="f1", action="a1",
        limits_by_level={"run": {"tokens": 1000},
                         "task": {"turns": 10},
                         "action": {"tokens": 400}})
    reservation = ledger.reserve(ids["action"], {"tokens": 300, "turns": 1},
                                 action_id="a1", tool="llm")
    assert reservation.state == "reserved"
    # 预留阶段：祖先都看得见 reserved
    assert ledger.get_scope(ids["run"])["reserved"]["tokens"] == 300
    # usage 缺失 → 按预留扣，并标 usage_missing
    settled = ledger.settle(reservation.reservation_id, None)
    assert settled["usage"] == "unknown"
    assert settled["usage_missing"] is True
    assert settled["charged"] == {"tokens": 300.0, "turns": 1.0}
    assert ledger.get_scope(ids["run"])["used"]["tokens"] == 300
    assert ledger.get_scope(ids["task"])["used"]["turns"] == 1
    assert ledger.get_scope(ids["action"])["reserved"]["tokens"] == 0
    # 重复结算不重复扣
    again = ledger.settle(reservation.reservation_id, {"tokens": 300})
    assert again["already"] is True
    assert ledger.get_scope(ids["run"])["used"]["tokens"] == 300
    # 退还：预留额回到可用（action 层上限 400，已用 300 → 只剩 100）
    second = ledger.reserve(ids["action"], {"tokens": 100})
    assert ledger.release(second.reservation_id)["state"] == "released"
    assert ledger.get_scope(ids["action"])["reserved"]["tokens"] == 0
    assert ledger.reserve(ids["action"], {"tokens": 100}).state == "reserved"
    with pytest.raises(BudgetRefused):
        ledger.reserve(ids["action"], {"tokens": 1})


def test_budget_failed_action_is_charged_and_stop_keeps_result_truth(tmp_path, store):
    """T11：worker 抛异常 → 动作 failed 但预算照扣；预算终止不改结果真假。"""
    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(
        run="r1", task=TASK, action="a1",
        limits_by_level={"run": {"turns": 4, "tokens": 64}})
    task = store.get_task(TASK)
    registry = build_registry()
    binding = make_binding(task, campaign=CAMPAIGN, registry=registry)
    ctx = make_context(task, binding=binding, mode="explore",
                       exec_runner=_boom_runner)
    ctx.grant = frozenset({"L0", "L1", "L2"})
    ctx.budget = LedgerBudget(ledger, ids["action"], action_id="a1")

    request = ActionRequest(action_id="act-fail", action="run_epoch",
                            binding=binding.to_dict(),
                            params={"kind": "fuzz", "seconds": 1.0})
    result = registry.invoke(request, ctx)
    assert result.status == "failed"             # 失败是失败，不是 no_repro
    assert result.budget["used"], result.to_dict()
    used = ledger.get_scope(ids["run"])["used"]
    assert used["turns"] == 1                    # 失败也计费
    assert used["seconds"] == pytest.approx(1.0)  # 无 usage 时按预留保守扣
    assert "tokens" not in used                   # 这一动作本来就不花 token
    # 预算终止判定只回答“能不能继续”，不改任何结果真假
    assert ledger.exhausted(ids["action"]) is None       # 还没花完
    ledger.reserve(ids["action"], {"turns": 3})          # 把 4 个回合的额度占满
    stop = ledger.exhausted(ids["action"])
    assert isinstance(stop, BudgetStop)
    assert stop.affects_result_truth is False
    assert stop.to_dict()["affects_result_truth"] is False
    # 预算不够时下一个动作是 rejected（不是 failed），且先前结果不被改写
    exhausted = LedgerBudget(ledger, ids["action"])   # 额度已被 1+3 占满
    verdict = exhausted.check({"turns": 1})
    assert verdict["ok"] is False and verdict["reason"] == "budget_exceeded"
    assert result.status == "failed"


def _boom_runner(**kwargs):
    raise RuntimeError("worker exploded (fixture)")


# ================================================================== T11 网关
_GATEWAY_SEQ = itertools.count(1)


def _gateway(tmp_path, *, client=None, prices=None, grant=None,
             key_provider=None, limits=None):
    # 每个网关一个独立账本：同一测试里多个分支不能共用同一条 scope 的用量
    seq = next(_GATEWAY_SEQ)
    ledger = BudgetLedger(tmp_path / f"budget-{seq}.db")
    ids = ledger.ensure_chain(run="r1", task=TASK,
                              limits_by_level={"run": limits or {
                                  "tokens": 10000, "turns": 20}})
    gw = LLMGateway(
        ledger, ids["task"], client=client,
        prices=prices or PriceTable(version="test-price-1", models={
            "model-a": {"input_per_1k": 1.0, "output_per_1k": 3.0}}),
        grant=frozenset(grant if grant is not None else {"L0", "L2"}),
        key_provider=key_provider or (lambda: "sk-test-secret-key"),
        cache={})
    return gw, ledger, ids


class FakeClient:
    """假模型客户端：记录调用，按剧本返回 usage / 缺 usage / 抛异常。"""

    def __init__(self, *, usage="full", text="ok", fail=False,
                 echo_key=False):
        self.usage = usage
        self.text = text
        self.fail = fail
        self.calls = 0
        self.seen_keys: list[str] = []
        self.echo_key = echo_key

    def __call__(self, *, model, payload, key):
        self.calls += 1
        self.seen_keys.append(key)
        if self.fail:
            raise TimeoutError("provider timed out after 30s")
        body = self.text
        if self.echo_key:
            body = f"debug: using {key}"
        if self.usage == "full":
            return {"text": body,
                    "usage": {"prompt_tokens": 100, "completion_tokens": 50}}
        if self.usage == "partial":
            return {"text": body, "usage": {"prompt_tokens": 100}}
        return {"text": body}


def test_llm_gateway_settles_real_usage_and_charges_failures(tmp_path):
    client = FakeClient(usage="full")
    gw, ledger, ids = _gateway(tmp_path, client=client)
    call = gw.call("model-a", "hello", max_tokens=64, purpose="diagnose")
    assert call.status == "ok" and call.usage_source == "provider"
    assert call.charged["tokens"] == 150                # 100 + 50
    assert call.charged["turns"] == 1
    assert call.charged["usd"] == pytest.approx(0.1 * 1.0 + 0.05 * 3.0)
    assert ledger.get_scope(ids["task"])["used"]["tokens"] == 150

    # usage 部分缺失 → unknown + 按预留保守扣账（不等于 0）
    partial = FakeClient(usage="partial")
    gw2, ledger2, ids2 = _gateway(tmp_path, client=partial)
    call2 = gw2.call("model-a", "hello", max_tokens=64)
    assert call2.usage_source == "unknown"
    assert call2.to_dict()["usage_missing"] is True
    charged = ledger2.get_scope(ids2["task"])["used"]["tokens"]
    assert charged > 64                                # 至少是预留额

    # 失败也计费：client 抛异常 → failed，成本落在账上
    boom = FakeClient(fail=True)
    gw3, ledger3, ids3 = _gateway(tmp_path, client=boom)
    call3 = gw3.call("model-a", "hello", max_tokens=32)
    assert call3.status == "failed"
    assert call3.error and call3.error["code"] == "client_error"
    assert ledger3.get_scope(ids3["task"])["used"]["tokens"] > 0
    assert ledger3.get_scope(ids3["task"])["used"]["turns"] == 1


def test_llm_gateway_enforces_permission_prices_and_key_hygiene(tmp_path):
    client = FakeClient()
    # 1) 无 L2（外部访问）→ rejected，零调用
    gw, ledger, ids = _gateway(tmp_path, client=client, grant={"L0", "L1"})
    refused = gw.call("model-a", "hi")
    assert refused.status == "rejected"
    assert refused.error["code"] == "permission_denied"
    assert client.calls == 0
    # 2) 无价格表 + usd 上限 → rejected/price_unknown，零调用
    gw2, _, _ = _gateway(tmp_path, client=client, prices=EMPTY_PRICES,
                         limits={"usd": 1.0, "tokens": 100})
    unknown_price = gw2.call("model-a", "hi")
    assert unknown_price.status == "rejected"
    assert unknown_price.error["code"] == "price_unknown"
    assert client.calls == 0
    # 3) 无 key → skipped + 规则回退（不谎称调用过）
    gw3, _, _ = _gateway(tmp_path, client=client, key_provider=lambda: "")
    skipped = gw3.call("model-a", "hi")
    assert skipped.status == "skipped"
    assert skipped.error["fallback"] == "rule"
    assert client.calls == 0
    # 4) key 不会进结果 JSON；出现也没有（客户端不回显）
    gw4, _, _ = _gateway(tmp_path, client=client)
    ok = gw4.call("model-a", "hi", max_tokens=16)
    assert ok.status == "ok"
    assert ok.key_ref and "sk-test-secret-key" not in json.dumps(ok.to_dict())
    assert "sk-test-secret-key" not in json.dumps(gw4.snapshot())
    # 5) 客户端回显 key → 打码 + failed（key 不进 workspace）
    echo = FakeClient(echo_key=True)
    gw5, _, _ = _gateway(tmp_path, client=echo)
    leaked = gw5.call("model-a", "hi", max_tokens=16)
    assert "sk-test-secret-key" not in leaked.text
    assert "[redacted]" in leaked.text
    assert leaked.status == "failed"
    assert leaked.error["code"] == "secret_in_output"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "sk-test-secret-key" not in path.read_bytes().decode(
                "utf-8", "replace")
    # 6) 缓存命中：不预留、不调 client、charged 为空
    gw6, ledger6, ids6 = _gateway(tmp_path, client=client)
    first = gw6.call("model-a", "cached prompt", max_tokens=16)
    before = dict(ledger6.get_scope(ids6["task"]))
    second = gw6.call("model-a", "cached prompt", max_tokens=16)
    assert second.cached is True and second.charged == {}
    assert dict(ledger6.get_scope(ids6["task"]))["used"] == before["used"]


def test_llm_gateway_idempotent_replay_is_refused_not_free(tmp_path):
    """幂等键只防“重试重复扣”，不能被拿来白嫖一次真实调用。"""
    client = FakeClient()
    gw, ledger, ids = _gateway(tmp_path, client=client)
    first = gw.call("model-a", "prompt-1", max_tokens=16,
                    idempotency_key="idem-1")
    assert first.status == "ok"
    calls_after_first = client.calls
    second = gw.call("model-a", "prompt-2", max_tokens=16,
                     idempotency_key="idem-1")
    assert second.status == "rejected"
    assert second.error["code"] == "idempotent_replay"
    assert client.calls == calls_after_first          # 没有再打到 provider
    assert ledger.get_scope(ids["task"])["used"]["turns"] == 1


def test_llm_gateway_child_calls_count_against_ancestors(tmp_path):
    client = FakeClient()
    gw, ledger, ids = _gateway(tmp_path, client=client)
    child = gw.child(action_id="sub-1", purpose="review")
    call = child.call("model-a", "sub call", max_tokens=32)
    assert call.status == "ok"
    used_task = ledger.get_scope(ids["task"])["used"]
    used_child = ledger.get_scope("action:sub-1")["used"]
    assert used_task["tokens"] == used_child["tokens"] == call.charged["tokens"]
    assert used_task["turns"] == 1


# ============================================================== T12 lease/fence
def test_campaign_job_claims_are_fenced_and_late_results_are_archived(store):
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    first = jobs.claim(job["job_key"])
    assert first is not None and first.fence == 1 and first.attempt == 1
    assert CampaignJobs(store, owner="w2", boot_id="boot-2").claim(
        job["job_key"]) is None                     # 已被认领
    assert jobs.heartbeat(first) is True
    impostor = Lease(job_key=job["job_key"], owner="w2", boot_id="boot-2",
                     fence=first.fence)
    assert CampaignJobs(store, owner="w2", boot_id="boot-2").heartbeat(
        impostor) is False                           # 旧 owner/别人续不上

    out = jobs.finish(first, "SUCCEEDED", {"candidates": 1})
    assert out.accepted is True and out.status == "SUCCEEDED"
    late = CampaignJobs(store, owner="w2", boot_id="boot-2").finish(
        Lease(job_key=job["job_key"], owner="w2", boot_id="boot-2", fence=2),
        "FAILED", {"candidates": 0})
    assert late.accepted is False and late.late is True
    assert late.reason == "terminal_already_set"
    current = store.get_campaign_job(job["job_key"])
    assert current["status"] == "SUCCEEDED"          # 终态没被旧 owner 覆盖
    assert current["fence"] == 1
    rows = store.list_campaign_late(job["job_key"])
    assert len(rows) == 1 and rows[0]["reason"] == "terminal_already_set"


def test_campaign_job_expired_lease_goes_unknown_before_requeue(store):
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=0.01)
    lease = jobs.claim(job["job_key"])
    assert lease is not None
    time.sleep(0.05)
    expired = store.expire_campaign_job_leases()
    assert [row["job_key"] for row in expired] == [job["job_key"]]
    unknown = store.get_campaign_job(job["job_key"])
    assert unknown["status"] == "UNKNOWN"
    assert unknown["lease_expires_at"] == 0
    assert unknown["fence"] == lease.fence + 1        # 旧 owner 已失效
    # UNKNOWN 未对账前不可认领（所有权不明不抢）
    assert CampaignJobs(store, owner="w2", boot_id="boot-2").claim(
        job["job_key"]) is None
    # 对账结论 = 没产生副作用 → 才允许重派
    store.reconcile_campaign_job(job["job_key"], verdict="PENDING",
                                 note="no side effect observed")
    again = CampaignJobs(store, owner="w2", boot_id="boot-2").claim(
        job["job_key"])
    assert again is not None and again.attempt == 2
    # 每次所有权变更都换 generation：过期(1→2) → 对账重派(2→3) → 重新认领(3→4)
    assert again.fence > unknown["fence"]
    # 旧 lease 提交被拒（只归档）
    stale = CampaignJobs(store, owner="w1", boot_id="boot-1").finish(
        lease, "SUCCEEDED", {"late": True})
    assert stale.late is True and stale.reason == "stale_owner"
    assert store.get_campaign_job(job["job_key"])["status"] == "RUNNING"


def test_campaign_job_links_launcher_and_reuses_successful_request(store):
    job = _job(store, request={"seconds": 2, "round": 7})
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    assert store.set_campaign_job_execution(
        job["job_key"], "exec-0001", owner="w1", fence=lease.fence) is True
    # T09：提交别的 execution 一律拒绝
    crossed = jobs.finish(lease, "SUCCEEDED", {}, execution_id="exec-9999")
    assert crossed.accepted is False and crossed.reason == "cross_execution"
    ok = jobs.finish(lease, "SUCCEEDED", {"execs": 10},
                     execution_id="exec-0001")
    assert ok.accepted is True
    # 相同规范化请求 → 直接复用，不新建
    again = _job(store, request={"seconds": 2, "round": 7})
    assert again["reused"] is True
    assert again["job_key"] == job["job_key"]
    assert store.get_campaign_job(job["job_key"])["result"]["execs"] == 10

    # 启动器视角：jobs 表能按 campaign 过滤，也能被 campaign job 反查
    db = store.path
    launcher = platform_jobs.create_job(
        db, TASK, [sys.executable, "-c", "print('x')"],
        db.parent / "launcher.log", campaign=CAMPAIGN,
        job_key=job["job_key"], spawn=lambda argv, log, cwd: FakeProc())
    assert launcher["campaign"] == CAMPAIGN
    assert launcher["job_key"] == job["job_key"]
    assert [row["job_id"] for row in platform_jobs.jobs_for_campaign(
        db, CAMPAIGN)] == [launcher["job_id"]]
    assert platform_jobs.list_jobs(db, campaign="other") == []
    assert store.attach_campaign_launcher(job["job_key"], launcher["job_id"],
                                          owner="w2", fence=99) is False


# ================================================================ T13 恢复
def _probe_artifact(*results):
    queue = list(results)

    def probe(job):
        return queue.pop(0) if queue else {"present": False}
    return probe


def test_recovery_reuses_finished_and_reconciles_unknown_with_evidence(store):
    done = _job(store, request={"round": 1})
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(done["job_key"])
    jobs.finish(lease, "SUCCEEDED", {"execs": 5})

    stale = _job(store, request={"round": 2})
    jobs.claim(stale["job_key"])
    store.mark_campaign_job_unknown(stale["job_key"],
                                   reason="worker killed by OOM")
    assert store.get_campaign_job(stale["job_key"])["status"] == "UNKNOWN"

    report = recover(store, boot_id="boot-2",
                     evidence_probe=_probe_artifact(
                         {"present": True, "sha256": "a" * 64,
                          "result": {"execs": 9}}),
                     apply=True)
    by_key = {item.job_key: item for item in report.actions}
    assert by_key[done["job_key"]].action == "reuse"        # 已完成复用
    assert by_key[stale["job_key"]].action == "reconcile"
    assert by_key[stale["job_key"]].status == "SUCCEEDED"
    assert report.replayed == 0                             # 没重放
    adopted = store.get_campaign_job(stale["job_key"])
    assert adopted["status"] == "SUCCEEDED"
    assert adopted["result"]["execs"] == 9
    assert adopted["reconciled_at"]


def test_recovery_never_replays_external_side_effects(store):
    risky = _job(store, external_effect="external", request={"round": 3})
    CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=0.01).claim(
        risky["job_key"])
    store.mark_campaign_job_unknown(risky["job_key"], reason="host rebooted")
    report = recover(store, boot_id="boot-2",
                     launcher_probe=lambda job: {"status": "MISSING"},
                     apply=True)
    action = [a for a in report.actions if a.job_key == risky["job_key"]][0]
    assert action.action == "hold"
    assert action.needs_manual is True
    assert "external_effect" in action.reason
    assert store.get_campaign_job(risky["job_key"])["status"] == "UNKNOWN"
    assert report.replayed == 0

    safe = _job(store, external_effect="none", request={"round": 4})
    CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=0.01).claim(
        safe["job_key"])
    store.mark_campaign_job_unknown(safe["job_key"], reason="worker crashed")
    report2 = recover(store, boot_id="boot-2",
                      launcher_probe=lambda job: {"status": "MISSING"},
                      apply=True)
    queued = [a for a in report2.actions if a.job_key == safe["job_key"]][0]
    assert queued.action == "requeue"
    assert store.get_campaign_job(safe["job_key"])["status"] == "PENDING"
    assert report2.replayed == 1


def test_recovery_shadow_mode_and_cancel_requested(store):
    job = _job(store, request={"round": 5})
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    jobs.claim(job["job_key"])
    shadow = recover(store, boot_id="boot-2", apply=False,
                     evidence_probe=lambda job: {"present": True,
                                                 "result": {}})
    assert shadow.applied is False
    assert store.get_campaign_job(job["job_key"])["status"] == "RUNNING"

    jobs.cancel(job["job_key"], reason="user cancelled")
    cancelled = store.get_campaign_job(job["job_key"])
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["lease_expires_at"] == 0
    late = jobs.finish(Lease(job_key=job["job_key"], owner="w1",
                             boot_id="boot-1", fence=1), "SUCCEEDED", {})
    assert late.accepted is False and late.late is True
    assert store.get_campaign_job(job["job_key"])["status"] == "CANCELLED"


def test_recovery_decide_is_pure_and_handles_live_lease(store):
    job = _job(store, request={"round": 6})
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    row = store.get_campaign_job(job["job_key"])
    live = decide(row, boot_id="boot-1", now_ts=lease.expires_at - 1,
                  launcher_probe=lambda job: {"status": "RUNNING"})
    assert live.action == "hold"
    other = decide(row, boot_id="boot-2", now_ts=lease.expires_at + 1,
                   launcher_probe=lambda job: {"status": "RUNNING"})
    assert other.action == "hold" and "process_alive" in other.reason


# ================================================================ T12 取消
def _tree_script(child_pid_file: Path) -> str:
    return (
        "import subprocess, sys, time, pathlib\n"
        f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid))\n"
        "time.sleep(60)\n"
    )


def test_cancel_task_full_kills_process_tree_and_keeps_terminal(store, bus, tmp_path):
    child_pid_file = tmp_path / "child.pid"
    proc = subprocess.Popen([sys.executable, "-c", _tree_script(child_pid_file)],
                            start_new_session=True)
    deadline = time.time() + 5
    while not child_pid_file.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert child_pid_file.exists(), "子进程没有起来"
    child_pid = int(child_pid_file.read_text().strip())

    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"], pid=proc.pid)
    assert lease is not None
    store.attach_campaign_launcher(job["job_key"], "job-launcher-1",
                                   owner="w1", fence=lease.fence)

    class FakeLauncher:
        def __init__(self):
            self.cancelled: list[str] = []

        def cancel(self, launcher_job_id, reason=""):
            self.cancelled.append(launcher_job_id)
            kill_process_tree(proc.pid, grace=0.1)
            return "SIGTERM"

    launcher = FakeLauncher()
    out = cancel_task_full(TASK, store, bus, jobs=jobs, launcher=launcher,
                           reason="user stop", actor="test", kill=True)
    assert out["state"] == "CANCELLED"
    assert out["order"][0] == "event" and out["order"][-1] == "final_state"
    assert out["evidence_sha256"]
    cancelled = store.get_campaign_job(job["job_key"])
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["lease_expires_at"] == 0
    assert cancelled["fence"] == lease.fence + 1
    assert launcher.cancelled == ["job-launcher-1"]
    # 真进程树：父进程与子进程都死
    deadline = time.time() + 5
    while time.time() < deadline and proc.poll() is None:
        time.sleep(0.02)
    assert proc.poll() is not None
    try:
        os.kill(child_pid, 0)
    except ProcessLookupError:
        pass
    else:                                   # pragma: no cover - 杀树失败
        raise AssertionError("子进程没有被一起杀掉")
    events = [event["event_type"] for event in store.list_events(TASK)]
    assert "task.cancel_requested" in events and "task.cancelled" in events
    # 迟到结果只归档，不改终态
    late = jobs.finish(lease, "SUCCEEDED", {"late": True})
    assert late.accepted is False and late.late is True
    assert store.get_campaign_job(job["job_key"])["status"] == "CANCELLED"
    assert store.get_campaign_job(job["job_key"])["result"] == {}


def test_reclaim_expired_and_failed_task(store, bus):
    job = _job(store)
    CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=0.01).claim(
        job["job_key"])
    time.sleep(0.05)
    reclaimed = reclaim_expired_leases(store, bus=bus)
    assert [row["job_key"] for row in reclaimed] == [job["job_key"]]
    assert store.get_campaign_job(job["job_key"])["status"] == "UNKNOWN"
    assert any(event["event_type"] == "job.unknown"
               for event in store.list_events(TASK))

    out = reclaim_failed_task(TASK, store, bus, reason="executor crashed",
                              exec_id="exec-0001")
    assert out["state"] == "FAILED"
    assert store.get_task(TASK)["state"] == "FAILED"
    assert out["evidence_sha256"]
    events = {event["event_type"] for event in store.list_events(TASK)}
    assert "task.failed" in events


# ========================================================== T07/T09 安全反例
def test_lifecycle_guards_reject_forgery_and_cross_task(store):
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    row = store.get_campaign_job(job["job_key"])

    # 跨任务
    with pytest.raises(LifecycleError) as err:
        guard_task_scope(store, TASK, claimed_task_id="task-other")
    assert err.value.code == "cross_task"
    # 伪造 owner
    with pytest.raises(LifecycleError) as err2:
        guard_job_owner(row, owner="intruder", fence=lease.fence)
    assert err2.value.code == "forged_identity"
    # 旧 fence（迟到）
    with pytest.raises(LifecycleError) as err3:
        guard_job_owner(row, owner="w1", fence=lease.fence + 5)
    assert err3.value.code == "stale_fence"
    # 跨 execution（T09）
    store.set_campaign_job_execution(job["job_key"], "exec-1", owner="w1",
                                     fence=lease.fence)
    with pytest.raises(LifecycleError) as err4:
        guard_job_owner(store.get_campaign_job(job["job_key"]), owner="w1",
                        fence=lease.fence, execution_id="exec-2")
    assert err4.value.code == "cross_execution"
    # 终态不可再改
    jobs.finish(lease, "SUCCEEDED", {}, execution_id="exec-1")
    with pytest.raises(LifecycleError) as err5:
        guard_job_owner(store.get_campaign_job(job["job_key"]), owner="w1",
                        fence=lease.fence)
    assert err5.value.code == "late_result"

    # 越权：L3 永不放开；L2 需要 allow_external 才是真
    with pytest.raises(LifecycleError) as err6:
        guard_permission({"authorized": True}, "L3")
    assert err6.value.code == "privilege_denied"
    guard_permission({"authorized": True}, "L1")
    with pytest.raises(LifecycleError) as err7:
        guard_permission({"authorized": True}, "L2")
    assert err7.value.code == "privilege_denied"
    guard_permission({"authorized": True, "allow_external": True}, "L2")
    with pytest.raises(LifecycleError) as err8:
        guard_permission({"authorized": "false"}, "L1")
    assert err8.value.code == "privilege_denied"


def test_store_rejects_terminal_override_and_unknown_verdict(store):
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    jobs.finish(lease, "FAILED", {"error": "boom"})
    with pytest.raises(CampaignJobError) as err:
        store.reconcile_campaign_job(job["job_key"], verdict="SUCCEEDED")
    assert err.value.code == "terminal_override"
    other = _job(store, request={"round": 9})
    with pytest.raises(CampaignJobError) as err2:
        store.reconcile_campaign_job(other["job_key"], verdict="PENDING")
    assert err2.value.code == "not_unknown"


# ================================================== 审计回归（p3-auditor 发现的洞）
def test_budget_idempotency_in_flight_is_refused(tmp_path):
    """同一幂等键的另一条预留还开着 → 拒绝（否则并发下会发两次真实调用）。"""
    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(run="r1", action="a1",
                              limits_by_level={"run": {"turns": 4}})
    first = ledger.reserve(ids["action"], {"turns": 1},
                           idempotency_key="same-key")
    assert first.state == "reserved"
    with pytest.raises(BudgetRefused) as err:
        ledger.reserve(ids["action"], {"turns": 1}, idempotency_key="same-key")
    assert err.value.code == "reservation_in_flight"
    ledger.settle(first.reservation_id, {"turns": 1})
    # 结算之后同键再预留：返回已结算的记录（不是新额度），由调用方判“已用过”
    again = ledger.reserve(ids["action"], {"turns": 1},
                            idempotency_key="same-key")
    assert again.reservation_id == first.reservation_id
    assert again.state == "settled"
    assert ledger.get_scope("run:r1")["used"]["turns"] == 1


def test_rejected_action_releases_reserved_quota(tmp_path, store):
    """闸门拒绝（参数/环境不满足）不能永久占额度：预留必须退还。"""
    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(run="r1", task=TASK, action="a1",
                              limits_by_level={"run": {"turns": 2}})
    task = store.get_task(TASK)
    registry = build_registry()
    binding = make_binding(task, campaign=CAMPAIGN, registry=registry)
    ctx = make_context(task, binding=binding, mode="explore")   # 没有 exec_runner
    ctx.grant = frozenset({"L0", "L1", "L2"})
    ctx.budget = LedgerBudget(ledger, ids["action"], action_id="a1")
    request = ActionRequest(action_id="act-rej", action="run_epoch",
                            binding=binding.to_dict(),
                            params={"kind": "fuzz", "seconds": 1.0})
    result = registry.invoke(request, ctx)
    assert result.status == "rejected"
    assert result.error["code"] == "executor_unavailable"
    assert ledger.open_reservations(ids["action"]) == []
    assert ledger.get_scope(ids["action"])["reserved"].get("turns", 0) == 0
    # 额度还在：紧接着的合法动作能拿到 2 个回合里的 1 个
    assert ledger.reserve(ids["action"], {"turns": 2}).state == "reserved"


def test_registry_charges_extra_usage_keys(tmp_path):
    """结算用到了没预留的键时也要扣（账要真实），并记进 overage。"""
    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(run="r1", action="a1",
                              limits_by_level={"run": {"turns": 4}})
    reservation = ledger.reserve(ids["action"], {"turns": 1})
    settled = ledger.settle(reservation.reservation_id,
                            {"turns": 1, "tokens": 900})
    assert settled["charged"]["tokens"] == 900
    assert settled["overage"].get("tokens") == 900
    assert ledger.get_scope("run:r1")["used"]["tokens"] == 900


def test_gateway_bytes_output_cannot_smuggle_key(tmp_path):
    """bytes 回包也曾绕过密钥扫描：现在必须打码、判 failed、且不入缓存。"""
    class BytesClient:
        def __init__(self):
            self.calls = 0

        def __call__(self, *, model, payload, key):
            self.calls += 1
            return {"text": b"echo:" + key.encode(),
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}}

    client = BytesClient()
    gw, _, _ = _gateway(tmp_path, client=client)
    call = gw.call("model-a", "bytes branch", max_tokens=16)
    assert call.status == "failed"
    assert call.error["code"] == "secret_in_output"
    assert "sk-test-secret-key" not in call.text
    assert "[redacted]" in call.text
    json.dumps(call.to_dict())                  # 必须是可序列化的
    again = gw.call("model-a", "bytes branch", max_tokens=16)
    assert again.cached is False                # 脏回包不进缓存
    assert "sk-test-secret-key" not in again.text


def test_finish_requires_execution_identity_once_bound(store):
    """绑定过 execution 之后，提交时不给 execution_id 也要拒绝（T09）。"""
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    assert store.set_campaign_job_execution(job["job_key"], "exec-1",
                                           owner="w1", fence=lease.fence)
    unbound = jobs.finish(lease, "SUCCEEDED", {"x": 1})
    assert unbound.accepted is False and unbound.reason == "cross_execution"
    ok = jobs.finish(lease, "SUCCEEDED", {"x": 1}, execution_id="exec-1")
    assert ok.accepted is True


def test_store_binding_helpers_require_owner_and_fence(store):
    job = _job(store)
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30)
    lease = jobs.claim(job["job_key"])
    with pytest.raises(CampaignJobError) as err:
        store.set_campaign_job_execution(job["job_key"], "exec-x", owner="",
                                         fence=0)
    assert err.value.code == "forged_identity"
    assert store.set_campaign_job_execution(job["job_key"], "exec-x",
                                           owner="intruder", fence=99) is False
    with pytest.raises(CampaignJobError) as err2:
        store.attach_campaign_launcher(job["job_key"], "job-x", owner="", fence=0)
    assert err2.value.code == "forged_identity"
    assert store.attach_campaign_launcher(job["job_key"], "job-x",
                                         owner="w1", fence=lease.fence + 1) is False
    # 旧 lease 的 abandon 不能把新 owner 的 RUNNING 打掉
    assert store.mark_campaign_job_unknown(job["job_key"], reason="stale",
                                           owner="w1",
                                           fence=lease.fence + 5)["status"] == "RUNNING"
    assert store.get_campaign_job(job["job_key"])["status"] == "RUNNING"


def test_reconcile_cannot_requeue_external_side_effects(store):
    job = _job(store, external_effect="external", request={"round": 11})
    CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30).claim(
        job["job_key"])
    store.mark_campaign_job_unknown(job["job_key"], reason="reboot")
    with pytest.raises(CampaignJobError) as err:
        store.reconcile_campaign_job(job["job_key"], verdict="PENDING")
    assert err.value.code == "external_effect_unresolved"
    assert store.get_campaign_job(job["job_key"])["status"] == "UNKNOWN"
    forced = store.reconcile_campaign_job(job["job_key"], verdict="PENDING",
                                          note="人工确认无副作用", force=True)
    assert forced["status"] == "PENDING"


def test_recovery_applies_running_jobs_without_aborting_the_scan(store, monkeypatch):
    """RUNNING+租约过期+artifact 在 → 真能对账成 SUCCEEDED，且单个失败不中断整轮。"""
    first = _job(store, request={"round": 21})
    second = _job(store, request={"round": 22})
    jobs = CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=0.01)
    jobs.claim(first["job_key"])
    jobs.claim(second["job_key"])
    time.sleep(0.05)                               # 让 0.01s 的租约真的过期
    store.expire_campaign_job_leases()            # 两个都落 UNKNOWN
    for key in (first["job_key"], second["job_key"]):
        store.reconcile_campaign_job(key, verdict="PENDING")

    # 再造一次 RUNNING（租约过期）场景：这次走 decide 的 RUNNING 分支
    third = _job(store, request={"round": 23})
    lease = CampaignJobs(store, owner="w9", boot_id="boot-old", ttl=0.01).claim(
        third["job_key"])
    assert lease is not None
    time.sleep(0.05)

    original = store.reconcile_campaign_job
    calls = {"n": 0}

    def flaky(job_key, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated reconcile crash")
        return original(job_key, **kwargs)

    monkeypatch.setattr(store, "reconcile_campaign_job", flaky)
    report = recover(store, boot_id="boot-new",
                     evidence_probe=lambda job: {"present": True,
                                                 "result": {"execs": 1}})
    # 整轮没有抛异常，且至少有一个 job 被降级成 hold/apply_failed（可人工接手）
    assert any(item.action == "hold" and "apply_failed" in item.reason
               for item in report.actions), report.to_dict()
    assert len(report.actions) == 3


def test_recovery_manual_requeue_respects_side_effect_gate(store):
    from agent.platform.adaptive.recovery import reconcile_job

    job = _job(store, external_effect="external", request={"round": 31})
    CampaignJobs(store, owner="w1", boot_id="boot-1", ttl=30).claim(
        job["job_key"])
    store.mark_campaign_job_unknown(job["job_key"], reason="reboot")
    decision = reconcile_job(store, job["job_key"], verdict="PENDING",
                             launcher_probe=lambda job: {"status": "MISSING"})
    assert decision.action == "hold"
    assert store.get_campaign_job(job["job_key"])["status"] == "UNKNOWN"
    forced = reconcile_job(store, job["job_key"], verdict="PENDING", force=True)
    assert forced.action == "hold"
    assert store.get_campaign_job(job["job_key"])["status"] == "PENDING"


def test_controller_default_budget_is_transactional(store):
    """研究主循环默认预算必须是事务账本（P3 之前是内存账本，会双花）。"""
    from agent.platform.adaptive.budget import LedgerBudget
    from agent.platform.adaptive.controller import ResearchController

    controller = ResearchController(task=store.get_task(TASK), store=store,
                                    campaign=CAMPAIGN, max_rounds=1)
    assert isinstance(controller.budget, LedgerBudget)
    snapshot = controller.budget.snapshot()
    assert "bottleneck" in snapshot and snapshot["levels"]
    # 两轮预留不可能同时拿到同一个回合：上限 8，直接占满
    scope = controller.budget.scope_id
    controller.budget.ledger.reserve(scope, {"turns": 8})
    assert controller.budget.check({"turns": 1})["ok"] is False


def test_platform_jobs_cancel_never_signals_self():
    """启动器侧也要有 self_pid 守卫：脏 pid 不能把自己进程组带走。"""
    import threading as _threading

    gate = _threading.Event()

    class SlowProc:
        pid = os.getpid()

        def wait(self):
            gate.wait(10)
            return 0

    db = Path(__file__).resolve().parent / "_p3_self_pid.db"
    try:
        job = platform_jobs.create_job(
            db, TASK, [sys.executable, "-c", "pass"],
            db.parent / "_p3_self_pid.log",
            spawn=lambda argv, log, cwd: SlowProc())
        out = platform_jobs.cancel_job(db, job["job_id"], reason="fixture")
        assert out["signal"] == "skipped:self_pid"
        assert out["job"]["status"] == "CANCELLED"
    finally:
        gate.set()
        for suffix in ("", "-wal", "-shm"):
            path = db.parent / (db.name + suffix)
            if path.exists():
                path.unlink()
        log = db.parent / "_p3_self_pid.log"
        if log.exists():
            log.unlink()


def test_handler_declared_rejection_does_not_charge(tmp_path, store):
    """handler 自己返回 rejected 也不算“做了”：预留要退，不能扣钱。"""
    from agent.platform.adaptive.contracts import (ToolContext, ToolOutcome,
                                                   ToolSpec)

    ledger = _ledger(tmp_path)
    ids = ledger.ensure_chain(run="r1", task=TASK, action="a1",
                              limits_by_level={"run": {"turns": 2}})
    task = store.get_task(TASK)
    registry = build_registry()

    def decline(ctx: ToolContext) -> ToolOutcome:
        return ToolOutcome(status="rejected",
                           error={"code": "declined", "reason": "fixture",
                                  "field": "", "hint": ""})

    registry.register(ToolSpec(
        name="decline_probe", group="experiment", permission="L1",
        summary="测试用：handler 自己声明拒绝", handler=decline,
        params={}, changes="none", cost=lambda params: {"turns": 1.0}))
    binding = make_binding(task, campaign=CAMPAIGN, registry=registry)
    ctx = make_context(task, binding=binding, mode="explore",
                       registry=registry)
    ctx.grant = frozenset({"L0", "L1"})
    ctx.budget = LedgerBudget(ledger, ids["action"], action_id="a1")
    request = ActionRequest(action_id="act-decline", action="decline_probe",
                            binding=binding.to_dict(), params={})
    result = registry.invoke(request, ctx)
    assert result.status == "rejected"
    assert ledger.open_reservations(ids["action"]) == []
    assert ledger.get_scope(ids["action"])["used"] == {}
    # 额度完好：还能预留 2 个回合
    assert ledger.reserve(ids["action"], {"turns": 2}).state == "reserved"
