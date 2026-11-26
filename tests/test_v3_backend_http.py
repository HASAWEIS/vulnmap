"""V3 P5（V3-018）验收：可选 HTTP 服务型后端。

口径（《VULNMAP-V3 完整升级方案》§14、§5、§10）：

1. **能力先声明**：版本固定、逐项 supported/unsupported、探测证据可复算；
   缺必需能力在发请求之前阻断（`CapabilityMissing` / `rejected`）。
2. **真实 oracle**：对本地 HTTP server 打两侧请求，成功、差异、超时、不可达
   四种结局都要如实记账；差异只写 `checks.behavior_differs`，**不写 verified**。
3. **证据与快照**：`collect()` 把请求/结果/快照/两侧响应体写进内容寻址证据库，
   并生成七组执行事实；缺的字段是 `unknown`，不是 0。
4. **身份一致**：伪造 binding_hash / 跨 benchmark 在发请求前 `rejected`。
5. **租约与恢复**：owner + fence 互斥；恢复按“终态复用 → 证据采纳 → 活跃租约
   挂起 → 只读动作重派 → 外部副作用人工”的顺序判定，不盲目重放。
6. **接 Registry/ToolContext**：`backend_diff` 走同一 Registry 闸门，写证据、
   快照、session trial 与失效登记。

所有测试用临时目录 + 临时 `PlatformStore` + 本地 `ThreadingHTTPServer`，
不碰仓库 `.platform`，也不访问外网。
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import PlatformStore, TaskSpec  # noqa: E402
from agent.platform.adaptive.backends import (  # noqa: E402
    BACKEND_REGISTRY, BACKEND_VERSION, Backend, BackendRefused, BackendRequest,
    Capabilities, Capability, CapabilityMissing, HttpServiceBackend)
from agent.platform.adaptive.backends.contracts import (  # noqa: E402
    BackendError, BackendResult)
from agent.platform.adaptive.contracts import (  # noqa: E402
    ActionRejected, ActionRequest, Binding)
from agent.platform.adaptive.tools import (  # noqa: E402
    MODE_EXPLORE, make_binding, make_context)
from agent.platform.task import Budget  # noqa: E402

TASK = "task-v3-be"
EXEC = "exec-be-0001"


# ====================================================================== server
class _Server:
    """本地 HTTP server：/same 200、/deny 403、/slow 慢响应、/reset 直接断开。"""

    def __init__(self) -> None:
        self.hits = 0
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):                      # noqa: N802 - 标准库接口
                with outer.lock:
                    outer.hits += 1
                if self.path.startswith("/slow"):
                    time.sleep(0.8)
                if self.path.startswith("/reset"):
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.close_connection = True
                    return
                code = 403 if self.path.startswith("/deny") else 200
                body = b"denied" if code == 403 else b"ok"
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *args):          # noqa: D401 - 静默
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


@pytest.fixture()
def server():
    srv = _Server()
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture(autouse=True)
def _clean_registry_pending():
    BACKEND_REGISTRY.consume_invalidations()
    yield
    BACKEND_REGISTRY.consume_invalidations()


# ====================================================================== store
def _store(tmp_path: Path, *, benchmark: str = "vulngym"):
    store = PlatformStore(tmp_path / "platform.db")
    store.create_task(TaskSpec(
        task_id=TASK, benchmark=benchmark, target="http://127.0.0.1:9/target",
        mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=1000, max_tokens=10000,
                      max_turns=12),
        metadata={"authorized": True}))
    return store, store.get_task(TASK)


def _ctx(tmp_path: Path, store, backend, *, execution_id: str = EXEC):
    task = store.get_task(TASK)
    binding = make_binding(task, campaign="vulngym", epoch=0,
                           execution_id=execution_id)
    ctx = make_context(task, binding=binding, store=store, mode=MODE_EXPLORE,
                       backend=backend,
                       tools_allowed=BACKEND_REGISTRY.names())
    ctx.evidence_root = tmp_path / "evidence"
    return binding, ctx


def _backend(tmp_path: Path, *, timeout: float = 1.0) -> HttpServiceBackend:
    return HttpServiceBackend(workdir=tmp_path / "backend", timeout=timeout)


def _dead_url() -> str:
    """拿一个刚释放的本地端口：连接会被拒绝，但没有外网依赖。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/target"


def _request(server: _Server, *, baseline: str = "/same", patched: str = "/same",
             request_id: str = "be-test-1", timeout: float = 1.0,
             binding_hash: str = "", **kwargs) -> BackendRequest:
    return BackendRequest.behavior_diff(
        request_id=request_id,
        baseline_url=server.base + baseline,
        patched_url=server.base + patched,
        timeout=timeout, binding_hash=binding_hash, **kwargs)


def _assert_no_verdict(doc) -> None:
    text = json.dumps(doc, ensure_ascii=False, default=str).lower()
    for word in ("verified", "confirmed", "verdict"):
        assert word not in text, f"backend artifact must not carry {word!r}"


# ====================================================================== 1 能力
def test_capabilities_fixed_version_and_probe_evidence(tmp_path):
    backend = _backend(tmp_path)
    caps = backend.capabilities(probe=True)
    doc = caps.to_dict()

    assert caps.backend == "http_service"
    assert caps.version == BACKEND_VERSION == "vulnmap.backend.http_service.v1"
    assert caps.required == ("behavior_diff",)
    assert caps.supports("behavior_diff")
    assert caps.supports("timeout")
    for name in ("container_image", "sanitizer", "coverage", "fuzz",
                 "redirect_follow", "proxy"):
        assert doc["capabilities"][name]["status"] == "unsupported"
        assert doc["capabilities"][name]["reason"], name
    proof = doc["probe"]
    assert len(proof["source_sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in proof["source_sha256"])
    assert proof["generated_at"]
    _assert_no_verdict(doc)

    with pytest.raises(CapabilityMissing) as exc:
        caps.require("fuzz")
    assert exc.value.code == "backend_capability_missing"


# ====================================================================== 2 成功
def test_success_is_applied_no_diff_and_collect_writes_evidence(tmp_path, server):
    store, _ = _store(tmp_path)
    backend = _backend(tmp_path)
    result = backend.execute(_request(server), binding=None)

    assert result.status == "applied"
    assert result.outcome == "no_diff"
    assert result.checks["behavior_differs"] is False
    assert result.checks["baseline_status"] == 200
    assert result.checks["patched_status"] == 200
    assert result.checks["baseline_body_sha256"] == \
        result.checks["patched_body_sha256"]
    assert result.blockers == ()
    _assert_no_verdict(result.to_dict())

    collected = backend.collect(result, store=store, task_id=TASK,
                                evidence_root=tmp_path / "evidence")
    kinds = {item["kind"] for item in collected["evidence"]}
    assert {"backend_request", "backend_result", "backend_snapshot",
            "backend_baseline_body", "backend_patched_body"} <= kinds
    rows = store.list_evidence(TASK)
    assert len(rows) >= 5
    for row in rows:
        path = Path(row["path"])
        assert path.is_file()
        assert sha256(path.read_bytes()).hexdigest() == row["sha256"]

    snap = collected["snapshot"]
    assert snap["complete"] is True
    assert snap["status"] == "applied"
    assert snap["groups"]["identity"]["backend"] == "http_service"
    assert snap["groups"]["identity"]["backend_version"] == BACKEND_VERSION
    assert snap["groups"]["fault"]["outcome"] == "no_diff"
    assert snap["groups"]["fault"]["timeout"] == "false"
    assert snap["groups"]["coverage"]["metric_kind"] == "behavior_diff"
    assert snap["groups"]["config"]["engine"] == "http_service"
    _assert_no_verdict(snap)


# ====================================================================== 3 差异
def test_behavior_difference_detected_without_verdict(tmp_path, server):
    backend = _backend(tmp_path)
    request = _request(server, patched="/deny",
                       expect={"baseline_status": 200,
                               "patched_status_in": [403]})
    result = backend.execute(request, binding=None)

    assert result.status == "applied"
    assert result.outcome == "diff"
    assert result.checks["behavior_differs"] is True
    assert result.checks["baseline_status"] == 200
    assert result.checks["patched_status"] == 403
    assert result.checks["baseline_body_sha256"] != \
        result.checks["patched_body_sha256"]
    assert result.checks["expect_matches"] is True
    _assert_no_verdict(result.to_dict())
    assert "verified" not in result.to_dict()


# ====================================================================== 4 超时
def test_timeout_is_failed_gap_not_no_diff(tmp_path, server):
    backend = _backend(tmp_path, timeout=0.25)
    result = backend.execute(_request(server, baseline="/slow", timeout=0.25),
                             binding=None)

    assert result.status == "failed"
    assert result.outcome == "timeout"
    assert result.checks["timeout"] is True
    assert result.sides["baseline"]["timed_out"] is True
    assert result.blockers == ("backend_timeout:baseline",)
    assert result.error["code"] == "backend_timeout"
    assert result.outcome != "no_diff"

    collected = backend.collect(result, store=None)
    snap = collected["snapshot"]
    assert snap["groups"]["fault"]["timeout"] == "true"
    assert snap["groups"]["fault"]["outcome"] == "timeout"
    assert snap["groups"]["fault"]["error"]
    assert snap["complete"] is True


# ====================================================================== 5 不可达
def test_unreachable_is_failed_with_blocker(tmp_path):
    backend = _backend(tmp_path, timeout=1.0)
    dead = _dead_url()
    request = BackendRequest.behavior_diff(
        request_id="be-dead-1", baseline_url=dead + "/a",
        patched_url=dead + "/b", timeout=1.0)
    result = backend.execute(request, binding=None)

    assert result.status == "failed"
    assert result.outcome == "unreachable"
    assert any(item.startswith("backend_unreachable:")
               for item in result.blockers)
    assert result.sides["baseline"]["connection_closed"] is True
    assert result.error["code"] == "backend_unreachable"
    snap = backend.collect(result)["snapshot"]
    assert snap["groups"]["fault"]["error"]
    assert snap["groups"]["input"]["target_reached"] == "false"


# ====================================================================== 6 恢复
def test_recovery_reuses_adopts_requeues_and_holds(tmp_path):
    _store(tmp_path)
    backend = _backend(tmp_path)

    # 1) 终态：直接复用，不再跑
    action = backend.recover({"request_id": "be-1", "status": "applied"})
    assert action.action == "reuse" and action.status == "applied"

    # 2) 有可复算证据：采纳为完成
    proof = tmp_path / "proof.bin"
    proof.write_bytes(b"behavior-diff-result")
    digest = sha256(proof.read_bytes()).hexdigest()
    action = backend.recover({
        "request_id": "be-2", "status": "unknown",
        "evidence": [{"path": str(proof), "sha256": digest, "size": 20}]})
    assert action.action == "adopt" and action.status == "applied"

    # 证据被改过 → 不能采纳
    proof.write_bytes(b"tampered")
    action = backend.recover({
        "request_id": "be-2b", "status": "unknown",
        "evidence": [{"path": str(proof), "sha256": digest, "size": 20}]})
    assert action.action != "adopt"

    # 3) 租约还活着：挂起，不抢不重放
    lease = backend.lease("be-3", owner="worker-a")
    action = backend.recover({"request_id": "be-3", "status": "unknown",
                              "lease": lease.to_dict()})
    assert action.action == "hold" and action.status == "unknown"
    assert action.needs_manual is False

    # 4) 租约过期 + 只读动作：允许重派（HTTP GET 幂等）
    expired = {"key": "be-4", "owner": "worker-a", "fence": 1,
               "backend": "http_service", "issued_at": 0.0,
               "expires_at": 1.0}
    action = backend.recover({"request_id": "be-4", "status": "unknown",
                              "lease": expired, "effect": "read_only"})
    assert action.action == "requeue"

    # 5) 外部副作用不明确：人工看一眼，不自动重放
    action = backend.recover({"request_id": "be-5", "status": "unknown",
                              "lease": expired, "effect": "external"})
    assert action.action == "hold" and action.needs_manual is True

    # 5b) 连租约都没有：所有权完全不明，先标 unknown
    action = backend.recover({"request_id": "be-6", "status": "unknown",
                              "effect": "external"})
    assert action.action == "mark_unknown" and action.needs_manual is True

    # 租约互斥与显式释放
    with pytest.raises(BackendRefused) as exc:
        backend.lease("be-3", owner="worker-b")
    assert exc.value.code == "lease_held"
    assert backend.release(lease) is True
    assert backend.lease("be-3", owner="worker-b").fence > lease.fence


def test_lease_lost_mid_flight_is_unknown_not_failure_or_success(tmp_path, server):
    """请求发出后租约过期：不知道成没成 → unknown，不能自宣失败或成功。"""
    ticks = iter([100.0, 1000.0])          # lease 发行一次、提交前检查一次
    backend = HttpServiceBackend(workdir=tmp_path / "backend",
                                 clock=lambda: next(ticks),
                                 lease_ttl=5.0, timeout=1.0)
    result = backend.execute(
        _request(server, request_id="be-lost-1", execution_id=EXEC),
        binding=None)

    assert result.status == "unknown"
    assert result.outcome == "unknown"
    assert result.error["code"] == "lease_lost"
    assert result.blockers == ("backend_lease_lost:lease_expired",)
    assert result.sides["baseline"]["status"] == 200   # 请求确实发出过
    snap = backend.collect(result)["snapshot"]
    assert snap["status"] == "unknown"                 # 不再声称“跑完了”
    assert snap["groups"]["fault"]["outcome"] == "unknown"
    _assert_no_verdict(result.to_dict())


def test_backend_tool_specs_are_derived_from_handlers(tmp_path, server):
    import inspect

    names = set(BACKEND_REGISTRY.names())
    assert {"backend_capabilities", "backend_diff", "backend_recover"} <= names
    for spec in BACKEND_REGISTRY.specs():
        if not spec.name.startswith("backend_"):
            continue
        signature = inspect.signature(spec.handler)
        params = [name for name in signature.parameters if name != "ctx"]
        assert set(params) == set(spec.schema["properties"]), spec.name
        assert list(spec.schema["required"]) == sorted(
            name for name in params
            if signature.parameters[name].default is inspect.Parameter.empty)
        assert spec.schema["permission"] == spec.permission
        assert spec.schema["invalidations"] == list(spec.invalidations)


def test_backend_capabilities_and_recover_tools_through_registry(tmp_path, server):
    store, _ = _store(tmp_path)
    backend = _backend(tmp_path)
    binding, ctx = _ctx(tmp_path, store, backend)

    caps = BACKEND_REGISTRY.invoke(
        ActionRequest(action_id="act-cap-1", action="backend_capabilities",
                      binding=binding.to_dict(), params={"probe": True}), ctx)
    assert caps.status == "applied"
    assert caps.payload["version"] == BACKEND_VERSION
    assert caps.payload["capabilities"]["backend"] == "http_service"

    recover = BACKEND_REGISTRY.invoke(
        ActionRequest(action_id="act-rec-1", action="backend_recover",
                      binding=binding.to_dict(),
                      params={"request_id": "be-done-1",
                              "record_status": "applied"}), ctx)
    assert recover.status == "applied"
    assert recover.payload["recovery"]["action"] == "reuse"
    assert recover.payload["recovery"]["status"] == "applied"


# ====================================================================== 7 身份
def test_forged_binding_and_wrong_benchmark_are_rejected_before_request(
        tmp_path, server):
    _, task = _store(tmp_path)
    backend = _backend(tmp_path)
    binding = make_binding(task, campaign="vulngym", epoch=0,
                           execution_id=EXEC)

    forged = _request(server, binding_hash="f" * 32)
    result = backend.execute(forged, binding=binding)
    assert result.status == "rejected"
    assert result.error["code"] == "forged_identity"
    assert server.hits == 0, "身份不符时不能先打一枪"

    # 同 task 但 benchmark 不是 vulngym：不支持，直接拒绝
    _, other_task = _store(tmp_path / "cyber", benchmark="cybergym")
    cybergym = make_binding(other_task, campaign="cybergym", epoch=0,
                            execution_id="exec-cy-1")
    result = backend.execute(_request(server, request_id="be-cy-1"),
                             binding=cybergym)
    assert result.status == "rejected"
    assert result.error["code"] == "unsupported_benchmark"
    assert server.hits == 0

    # 任务/执行 id 不一致也是伪造
    result = backend.execute(
        BackendRequest.behavior_diff(
            request_id="be-task-1", baseline_url=server.base + "/same",
            patched_url=server.base + "/same", timeout=1.0,
            task_id="task-other"),
        binding=binding)
    assert result.status == "rejected"
    assert result.error["code"] == "forged_identity"
    assert server.hits == 0


# ====================================================================== 8 接 Registry
def test_registry_tool_writes_evidence_snapshot_trial_and_invalidation(
        tmp_path, server):
    store, _ = _store(tmp_path)
    backend = _backend(tmp_path)
    binding, ctx = _ctx(tmp_path, store, backend)

    request = ActionRequest(
        action_id="act-be-1", action="backend_diff",
        binding=binding.to_dict(),
        params={"baseline_url": server.base + "/same",
                "patched_url": server.base + "/deny", "timeout": 1.0})
    result = BACKEND_REGISTRY.invoke(request, ctx)

    assert result.status == "applied", result.error
    payload = result.payload
    assert payload["outcome"] == "diff"
    assert payload["checks"]["behavior_differs"] is True
    assert payload["snapshot"]["status"] == "applied"
    assert "bd-001" in ctx.session.trials
    assert ctx.session.trials["bd-001"]["outcome"] == "diff"
    assert result.changed_fields == ("trials",)
    assert "execution_facts" in result.invalidations
    assert "execution_facts" in BACKEND_REGISTRY.pending_invalidations(TASK)
    kinds = {item["kind"] for item in store.list_evidence(TASK)}
    assert {"backend_request", "backend_result", "backend_snapshot"} <= kinds
    _assert_no_verdict(result.to_dict())


def test_missing_capability_blocks_tool_before_any_request(tmp_path):
    store, _ = _store(tmp_path)

    class _NoDiffBackend(Backend):
        name = "no_diff"
        version = "vulnmap.backend.no_diff.v1"

        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def capabilities(self, *, probe: bool = False) -> Capabilities:
            return Capabilities(
                backend=self.name, version=self.version,
                items={"behavior_diff": Capability(
                    "behavior_diff", "unsupported", reason="测试用缺能力")},
                required=("behavior_diff",))

        def execute(self, request, *, binding=None):   # pragma: no cover
            self.calls += 1
            raise AssertionError("能力缺失时不得执行")

    backend = _NoDiffBackend()
    binding, ctx = _ctx(tmp_path, store, backend)
    result = BACKEND_REGISTRY.invoke(
        ActionRequest(action_id="act-be-2", action="backend_diff",
                      binding=binding.to_dict(),
                      params={"baseline_url": "http://127.0.0.1:9/a",
                              "patched_url": "http://127.0.0.1:9/b"}),
        ctx)

    assert result.status == "rejected"
    assert result.error["code"] == "backend_capability_missing"
    assert backend.calls == 0
    assert store.list_evidence(TASK) == []


# ====================================================================== 9 离线
def test_collect_without_store_returns_snapshot_and_local_refs(tmp_path, server):
    backend = _backend(tmp_path)
    result = backend.execute(_request(server), binding=None)
    collected = backend.collect(result)

    assert collected["snapshot"]["complete"] is True
    assert collected["snapshot"]["groups"]["fault"]["outcome"] == "no_diff"
    refs = collected["evidence"]
    assert {item["kind"] for item in refs} >= {"backend_request",
                                               "backend_result",
                                               "backend_snapshot"}
    assert all(item["persisted"] is False for item in refs)
    assert all(len(item["sha256"]) == 64 for item in refs)
    _assert_no_verdict(collected["snapshot"])


# ====================================================================== 10 契约
def test_result_contract_refuses_verdict_fields_and_bad_status(tmp_path):
    with pytest.raises(BackendError):
        BackendResult(backend="http_service", backend_version="v1",
                      request_id="be-1", status="applied", outcome="no_diff",
                      checks={"verified": True})
    with pytest.raises(BackendError):
        BackendResult(backend="http_service", backend_version="v1",
                      request_id="be-1", status="passed", outcome="no_diff")
    with pytest.raises(BackendError):
        BackendResult(backend="http_service", backend_version="v1",
                      request_id="be-1", status="failed", outcome="timeout")
    with pytest.raises(ActionRejected):
        # 建一个声明了 unknown 字段的 binding（身份分量只认白名单）
        Binding(task_id=TASK, identity={"benchmark": "vulngym", "trusted": "true"})
