"""V3-018：HTTP 服务型后端（VulnGym 基线/修补请求），不依赖任何镜像。

实现方式（不新增 docker 镜像、不依赖新服务）：

1. `capabilities()` 先声明本后端能做什么：`behavior_diff`、`timeout`、
   `connection_closed`、`tls` 为 supported；`container_image`、`sanitizer`、
   `coverage`、`fuzz`、`redirect_follow`、`proxy` 明确 unsupported 并写原因；
2. `execute()` 对基线/修补两侧各打**一次** HTTP 请求：
   - 不跟随重定向（3xx 原样记账，避免“拦截页 302 到登录页”被当成 200）；
   - 显式关闭环境代理（`ProxyHandler({})`），只连请求里声明的两个 URL；
   - 响应体截断到 1 MiB，`body_sha256` 现场计算；
   - 连接被拒/被重置记 `connection_closed=True`（这本身是有效差分信号）；
   - 超时记 `backend_timeout:<side>` + `status=failed`，是**缺口**不是负结果；
   - 两侧都没拿到响应记 `unreachable`，也不冒充“没有差异”。
3. `collect()` 继承基类：结果/请求/快照/两侧响应体写入内容寻址证据，并生成
   七组事实快照；
4. `lease()/recover()` 继承基类：owner + fence 租约；恢复先对账，HTTP GET
   声明为 `read_only`，只有租约过期且无证据时才允许 `requeue`。

**本模块不写 `verified`**：`checks.behavior_differs` 只是“两侧观测不同”，
漏洞结论仍由 `agent.platform.verify.evaluate_vulngym` 与 `benchmark_policy`
推导。
"""
from __future__ import annotations

import http.client
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from .base import Backend
from .contracts import (BACKEND_NAME, BACKEND_VERSION, BackendError,
                        BackendRefused, BackendRequest, BackendResult,
                        Capabilities, Capability, CapabilityMissing,
                        LeaseLost, now, sha256_hex)

SCHEMA = "vulnmap.backend.http_service.v1"

#: 响应体上限：与 runners.vulngym 同口径（1 MiB），不把整份响应塞进内存
MAX_BODY = 1 << 20

#: 允许的方法：GET/POST/HEAD；其余方法没有理由出现在 VulnGym 差分里
SUPPORTED_METHODS = ("GET", "POST", "HEAD")

SIDES = ("baseline", "patched")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟跳转：3xx 作为 HTTPError 原样返回。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def source_sha256() -> str:
    """本实现文件的哈希：能力探测证据的一部分（版本固定 + 源码可复算）。"""
    return sha256_hex(Path(__file__).read_bytes())


class HttpServiceBackend(Backend):
    """对两个 HTTP 端点做行为差分的后端；不需要镜像、不需要容器。"""

    name = BACKEND_NAME
    version = BACKEND_VERSION
    effect = "read_only"

    def __init__(self, *, workdir: Path | str | None = None,
                 clock=time.time, timeout: float = 10.0,
                 lease_ttl: float = 30.0, owner: str = "") -> None:
        super().__init__(workdir=workdir, clock=clock, lease_ttl=lease_ttl,
                         owner=owner)
        timeout = float(timeout or 10.0)
        if timeout <= 0:
            raise BackendError("http backend timeout must be > 0")
        self.timeout = timeout
        if self.workdir is None:
            # 没有显式工作目录时用临时目录：响应体要落盘才能算证据
            self.workdir = Path(tempfile.mkdtemp(prefix="vulnmap-http-"))

    # ------------------------------------------------------------ 能力
    def capabilities(self, *, probe: bool = False) -> Capabilities:
        evidence = {
            "transport": "urllib.request",
            "redirects_followed": False,
            "proxy": "disabled",
            "max_body": MAX_BODY,
            "methods": list(SUPPORTED_METHODS),
            "per_side_timeout": True,
        }
        items = {
            "behavior_diff": Capability(
                "behavior_diff", "supported",
                evidence={**evidence, "schema": SCHEMA}),
            "timeout": Capability(
                "timeout", "supported",
                evidence={"unit": "seconds", "blocker": "backend_timeout:<side>"}),
            "connection_closed": Capability(
                "connection_closed", "supported",
                evidence={"signal": "connection_closed",
                          "meaning": "reset/refused is a valid diff signal"}),
            "tls": Capability(
                "tls", "supported",
                evidence={"schemes": ["http", "https"],
                          "verify": "urllib default"}),
            "redirect_follow": Capability(
                "redirect_follow", "unsupported",
                reason="3xx 原样记账，避免拦截页跳登录页被当成 200"),
            "proxy": Capability(
                "proxy", "unsupported",
                reason="显式禁用环境代理，防止请求被 HTTP_PROXY 带出声明主机"),
            "container_image": Capability(
                "container_image", "unsupported",
                reason="本后端按设计不依赖任何镜像（纯 HTTP 服务）"),
            "sanitizer": Capability(
                "sanitizer", "unsupported",
                reason="HTTP 行为差分没有内存 sanitizer 观测"),
            "coverage": Capability(
                "coverage", "unsupported",
                reason="行为差分不产覆盖率，不能横向冒充覆盖百分比"),
            "fuzz": Capability(
                "fuzz", "unsupported",
                reason="输入级 fuzz 由既有 covfuzz 执行器承担"),
        }
        proof = {"generated_at": now(), "source_sha256": source_sha256(),
                 "module": __name__, "no_image_dependency": True}
        if probe:
            proof["probe"] = "static-declaration"
        return Capabilities(backend=self.name, version=self.version,
                            items=items, required=("behavior_diff",),
                            probe=proof)

    # ------------------------------------------------------------ 执行
    def execute(self, request: BackendRequest, *,
                binding: Any = None) -> BackendResult:
        started = time.monotonic()
        if not isinstance(request, BackendRequest):
            raise BackendError(
                f"execute() needs BackendRequest, got {type(request).__name__}")

        problem = self._identity_problem(request, binding)
        if problem is not None:
            return self._rejected(request, problem, started=started)

        try:
            self.capabilities().require("behavior_diff")
        except CapabilityMissing as exc:
            return self._rejected(request, exc, started=started)

        if request.action != "behavior_diff":
            return self._rejected(
                request,
                BackendRefused("unsupported_action",
                               f"http_service 只实现了 behavior_diff，"
                               f"收到 {request.action!r}",
                               field_name="action"),
                started=started)

        params = dict(request.params or {})
        validation = self._validate_params(params)
        if validation is not None:
            return self._rejected(request, validation, started=started)

        lease = None
        if request.execution_id:
            try:
                lease = self.lease(request.execution_id,
                                   ttl=max(2 * float(params["timeout"]) + 5.0,
                                           self._ttl))
            except BackendRefused as exc:
                return self._rejected(request, exc, started=started)

        run_dir = Path(self.workdir) / request.request_id
        run_dir.mkdir(parents=True, exist_ok=True)
        sides: dict[str, dict] = {}
        try:
            for side in SIDES:
                sides[side] = self._fetch(
                    str(params[f"{side}_url"]), side, run_dir,
                    method=str(params["method"]),
                    headers=dict(params.get("headers") or {}),
                    timeout=float(params["timeout"]))
            if lease is not None:
                self.check_lease(lease)
        except LeaseLost as exc:
            # 请求可能已经发出去过：不知道成没成 → unknown，不自己宣布失败
            return BackendResult(
                backend=self.name, backend_version=self.version,
                request_id=request.request_id, task_id=request.task_id,
                execution_id=request.execution_id, status="unknown",
                outcome="unknown", binding_hash=request.binding_hash,
                request=request.to_dict(), sides=sides,
                blockers=[f"backend_lease_lost:{exc.reason}"],
                seconds=round(time.monotonic() - started, 3),
                lease=lease.to_dict() if lease else None,
                error={"code": "lease_lost", "reason": str(exc),
                       "field": "execution_id", "hint": "先对账再重派"})
        finally:
            if lease is not None:
                self.release(lease)

        seconds = round(time.monotonic() - started, 3)
        return self._build_result(request, sides, seconds=seconds,
                                  lease=lease)

    # ------------------------------------------------------------ 校验
    def _identity_problem(self, request: BackendRequest,
                          binding: Any) -> BackendRefused | None:
        if binding is None:
            return None
        trusted_hash = str(getattr(binding, "hash", "") or "")
        if request.binding_hash and trusted_hash \
                and request.binding_hash != trusted_hash:
            return BackendRefused(
                "forged_identity",
                "请求里的 binding_hash 与本次会话的可信绑定不一致",
                field_name="binding_hash",
                hint="身份由服务端填；请求只能原样回带")
        task_id = str(getattr(binding, "task_id", "") or "")
        if request.task_id and task_id and request.task_id != task_id:
            return BackendRefused(
                "forged_identity",
                f"请求 task_id={request.task_id!r} 与绑定 {task_id!r} 不一致",
                field_name="task_id")
        execution = str(getattr(binding, "execution_id", "") or "")
        if request.execution_id and execution \
                and request.execution_id != execution:
            return BackendRefused(
                "cross_execution",
                f"请求 execution_id={request.execution_id!r} 与绑定 "
                f"{execution!r} 不同（禁止跨 execution 拼接）",
                field_name="execution_id")
        identity = dict(getattr(binding, "identity", {}) or {})
        benchmark = str(identity.get("benchmark") or "")
        if benchmark and benchmark != "vulngym":
            return BackendRefused(
                "unsupported_benchmark",
                f"http_service 只做 vulngym 行为差分，绑定是 {benchmark!r}",
                field_name="benchmark")
        return None

    def _validate_params(self, params: Mapping) -> BackendRefused | None:
        missing = [f"{side}_url" for side in SIDES
                   if not str(params.get(f"{side}_url") or "").strip()]
        if missing:
            return BackendRefused(
                "backend_not_configured",
                f"http_service 需要 {missing}（缺一侧就不做差分，不拿 "
                "target 顶替修补侧）", field_name=missing[0])
        for side in SIDES:
            url = str(params[f"{side}_url"]).strip()
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return BackendRefused(
                    "unsupported_url",
                    f"{side}_url 只支持 http/https 且必须有主机：{url!r}",
                    field_name=f"{side}_url")
        method = str(params.get("method") or "GET").upper()
        if method not in SUPPORTED_METHODS:
            return BackendRefused(
                "unsupported_method",
                f"method={method!r} 不在 {list(SUPPORTED_METHODS)} 内",
                field_name="method")
        headers = params.get("headers") or {}
        if not isinstance(headers, Mapping) or any(
                not isinstance(v, str) for v in headers.values()):
            return BackendRefused("invalid_headers",
                                  "headers 必须是字符串到字符串的对象",
                                  field_name="headers")
        try:
            timeout = float(params.get("timeout") or self.timeout)
        except (TypeError, ValueError):
            timeout = -1.0
        if timeout <= 0:
            return BackendRefused("invalid_timeout",
                                  f"timeout 必须 > 0，收到 {params.get('timeout')!r}",
                                  field_name="timeout")
        # 规范化：后续 _fetch 直接读 params
        params["method"] = method
        params["headers"] = dict(headers)
        params["timeout"] = timeout
        return None

    # ------------------------------------------------------------ 单侧请求
    def _fetch(self, url: str, side: str, run_dir: Path, *, method: str,
               headers: Mapping, timeout: float) -> dict:
        request = urllib.request.Request(url, method=method,
                                         headers=dict(headers or {}))
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        started = time.monotonic()
        status, body, timed_out, closed, error = None, b"", False, False, ""
        try:
            with opener.open(request, timeout=timeout) as resp:
                status = int(getattr(resp, "status", 0) or 0)
                body = resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:       # 3xx/4xx/5xx（不跟跳转）
            status = int(exc.code)
            try:
                body = exc.read(MAX_BODY) or b""
            except Exception:                       # noqa: BLE001 - 读不到体不算失败
                body = b""
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                timed_out = True
            else:
                closed = True
                error = f"{type(reason).__name__}: {reason}"
        except (socket.timeout, TimeoutError):
            timed_out = True
        except (ConnectionResetError, ConnectionAbortedError,
                http.client.HTTPException, OSError) as exc:
            closed = True
            error = f"{type(exc).__name__}: {exc}"
        seconds = round(time.monotonic() - started, 3)
        digest = sha256_hex(body)
        path = Path(run_dir) / f"{side}.body"
        if body:
            path.write_bytes(body)
        return {
            "url": url,
            "status": status,
            "body_path": str(path) if body else "",
            "body_sha256": digest if body else "",
            "body_bytes": len(body),
            "connection_closed": closed,
            "timed_out": timed_out,
            "seconds": seconds,
            "error": error or ("timeout" if timed_out else ""),
        }

    # ------------------------------------------------------------ 结果
    def _build_result(self, request: BackendRequest, sides: Mapping,
                      *, seconds: float, lease: Any) -> BackendResult:
        checks = self._checks(sides, dict(request.params.get("expect") or {}),
                              method=request.method)
        timed = [side for side in SIDES if (sides.get(side) or {}).get("timed_out")]
        responded = [side for side in SIDES if _responded(sides.get(side) or {})]
        evidence = tuple(
            {"kind": f"{side}_body",
             "path": str((sides.get(side) or {}).get("body_path") or ""),
             "sha256": str((sides.get(side) or {}).get("body_sha256") or ""),
             "size": int((sides.get(side) or {}).get("body_bytes") or 0)}
            for side in SIDES
            if (sides.get(side) or {}).get("body_path"))

        blockers: list[str] = []
        if timed:
            blockers = [f"backend_timeout:{side}" for side in timed]
            status, outcome = "failed", "timeout"
            error = {"code": "backend_timeout",
                     "reason": f"两侧请求超时：{', '.join(timed)}",
                     "field": "timeout",
                     "hint": "超时是缺口，不是 no_diff；调大 timeout 或先确认服务健康"}
        elif not responded:
            blockers = [f"backend_unreachable:{side}" for side in SIDES]
            status, outcome = "failed", "unreachable"
            error = {"code": "backend_unreachable",
                     "reason": "基线与修补两侧都没有拿到响应",
                     "field": "",
                     "hint": "先修服务可达性；不可达不能洗成没有差异"}
        else:
            status = "applied"
            outcome = "diff" if checks["behavior_differs"] else "no_diff"
            error = None

        return BackendResult(
            backend=self.name, backend_version=self.version,
            request_id=request.request_id, task_id=request.task_id,
            execution_id=request.execution_id, status=status, outcome=outcome,
            binding_hash=request.binding_hash, request=request.to_dict(),
            checks=checks, sides={side: dict(sides.get(side) or {})
                                  for side in SIDES},
            blockers=tuple(blockers), evidence=evidence, seconds=seconds,
            lease=lease.to_dict() if lease else None, error=error)

    def _checks(self, sides: Mapping, expect: Mapping, *, method: str) -> dict:
        data = {side: dict(sides.get(side) or {}) for side in SIDES}
        b_status = data["baseline"].get("status")
        p_status = data["patched"].get("status")
        b_body = str(data["baseline"].get("body_sha256") or "")
        p_body = str(data["patched"].get("body_sha256") or "")
        b_closed = bool(data["baseline"].get("connection_closed"))
        p_closed = bool(data["patched"].get("connection_closed"))
        differs = ((b_status != p_status)
                   or (bool(b_body) and bool(p_body) and b_body != p_body)
                   or (p_closed != b_closed))
        expect_ok: Any = "unknown"
        if expect:
            ok = True
            want_baseline = expect.get("baseline_status")
            want_patched = (expect.get("patched_status_in")
                            or expect.get("patched_status"))
            if want_baseline is not None:
                try:
                    ok = ok and b_status == int(want_baseline)
                except (TypeError, ValueError):
                    ok = False
            if want_patched is not None:
                allowed = (want_patched if isinstance(want_patched, (list, tuple))
                           else [want_patched])
                try:
                    ok = ok and p_status in {int(x) for x in allowed}
                except (TypeError, ValueError):
                    ok = False
            expect_ok = bool(ok)
        return {
            "method": method,
            "baseline_status": b_status,
            "patched_status": p_status,
            "baseline_body_sha256": b_body,
            "patched_body_sha256": p_body,
            "baseline_closed": b_closed,
            "patched_closed": p_closed,
            "behavior_differs": bool(differs),
            "expect_matches": expect_ok,
            "timeout": any(bool(data[side].get("timed_out")) for side in SIDES),
            "responded": [side for side in SIDES if _responded(data[side])],
        }

    def _rejected(self, request: BackendRequest, exc: BackendRefused,
                  *, started: float) -> BackendResult:
        return BackendResult(
            backend=self.name, backend_version=self.version,
            request_id=request.request_id, task_id=request.task_id,
            execution_id=request.execution_id, status="rejected",
            outcome="rejected", binding_hash=request.binding_hash,
            request=request.to_dict(),
            blockers=[exc.code],
            seconds=round(time.monotonic() - started, 3),
            error=exc.to_dict())


def _responded(side: Mapping) -> bool:
    """这一侧到底有没有拿到响应：断开/超时都不算（那是缺口或差分信号）。"""
    return (side.get("status") is not None
            or bool(str(side.get("body_sha256") or "")))


__all__ = ["HttpServiceBackend", "MAX_BODY", "SUPPORTED_METHODS", "SCHEMA",
           "source_sha256"]
