"""VulnGym runner：基线 / 修补两组 HTTP 行为差分。

判据（`behavior_diff`）仍由 [verify.evaluate_vulngym](../../platform/verify.py)
推导，本 runner 只把两侧**打出来**并落成证据：

- 每条 URL 只打一次 GET（`method` 可覆盖），**不跟随重定向**——3xx 原样记账，
  否则“拦截页 302 到登录页”会被当成 200；
- 响应体截断到 1 MiB 并写 `baseline.body` / `patched.body`，`body_sha256` 现场复算；
- 连接被拒/被重置记 `connection_closed=True`（这本身是有效的差分信号：
  “修补后直接断开”）；
- 超时记 `runner_timeout:<side>` + `completed=False`，是**缺口**不是负结果。

网络策略：只允许 `http`/`https`，只连 spec 里声明的两个 URL，
不解析跳转、不访问第三个主机、不走代理（`ProxyHandler({})` 显式关掉环境代理，
避免宿主 `HTTP_PROXY` 把请求带出本机）。
"""
from __future__ import annotations

import http.client
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .base import Runner, RunnerError, RunnerResult, sha256_hex

MAX_BODY = 1 << 20
SIDES = ("baseline", "patched")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟跳转：3xx 作为 HTTPError 原样返回。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _text(value) -> str:
    return str(value or "").strip()


class VulnGymRunner(Runner):
    name = "vulngym"
    benchmark = "vulngym"
    kind = "behavior_diff"

    # -------------------------------------------------------------- 配置
    def _url(self, spec: dict, side: str) -> str:
        raw = self.option(spec, f"{side}_url", f"{side}_target")
        if not raw:
            declared = spec.get(side) or {}
            if isinstance(declared, dict):
                raw = declared.get("url")
        return _text(raw)

    def _opener(self):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    # -------------------------------------------------------------- 单侧
    def _fetch(self, url: str, side: str, *, method: str,
               headers: dict, timeout: float) -> dict:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise RunnerError(
                f"{side}: unsupported url {url!r} (http/https with host only)")
        request = urllib.request.Request(url, method=method,
                                         headers=dict(headers or {}))
        started = time.monotonic()
        status, body, timed_out, closed, error = None, b"", False, False, ""
        try:
            with self._opener().open(request, timeout=timeout) as resp:
                status = int(getattr(resp, "status", 0) or 0)
                body = resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:      # 3xx/4xx/5xx（不跟跳转）
            status = int(exc.code)
            try:
                body = exc.read(MAX_BODY) or b""
            except Exception:                      # noqa: BLE001 - 读不到响应体不算失败
                body = b""
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                timed_out = True
            else:
                closed, error = True, f"{type(reason).__name__}: {reason}"
        except (socket.timeout, TimeoutError):
            timed_out = True
        except (ConnectionResetError, ConnectionAbortedError,
                http.client.HTTPException, OSError) as exc:
            closed, error = True, f"{type(exc).__name__}: {exc}"
        seconds = round(time.monotonic() - started, 3)
        if timed_out or closed or status is None:
            return {"url": url, "status": None, "body_path": "", "body_sha256": "",
                    "connection_closed": closed, "timed_out": timed_out,
                    "seconds": seconds, "error": error or
                    ("timeout" if timed_out else "")}
        body_path = self.write_bytes(f"{side}.body", body)
        digest = sha256_hex(body)
        log = (f"# side={side}\n# url={url}\n# method={method}\n"
               f"# status={status}\n# body_bytes={len(body)}\n"
               f"# body_sha256={digest}\n# seconds={seconds}\n")
        self.write_text(f"{side}.log", log)
        return {"url": url, "status": status, "body_path": str(body_path),
                "body_sha256": digest, "connection_closed": False,
                "timed_out": False, "seconds": seconds, "error": ""}

    # -------------------------------------------------------------- 执行
    def run(self, spec: dict) -> RunnerResult:
        try:
            self.isolation_info()
        except RunnerError as exc:
            return self.failure("runner_unavailable:isolation", error=str(exc))

        method = (_text(self.option(spec, "method", default="GET")) or "GET").upper()
        headers = self.option(spec, "headers", default={}) or {}
        if not isinstance(headers, dict):
            return self.failure("runner_spec_invalid", error="headers must be an object")
        expect = spec.get("expect") or {}
        urls = {side: self._url(spec, side) for side in SIDES}
        missing = [f"{side}_url" for side, url in urls.items() if not url]
        if missing:
            return self.failure(
                "runner_not_configured:" + ",".join(missing),
                error=f"vulngym runner needs {missing}")

        sides: dict[str, dict] = {}
        blockers: list[str] = []
        try:
            for side in SIDES:
                result = self._fetch(urls[side], side, method=method,
                                     headers=headers, timeout=self.timeout)
                if result["timed_out"]:
                    blockers.append(f"runner_timeout:{side}")
                elif result["connection_closed"]:
                    blockers.append(f"connection_failed:{side}")
                sides[side] = result
        except RunnerError as exc:
            return self.failure("runner_spec_invalid", error=str(exc))

        completed = not any(side["timed_out"] for side in sides.values())
        criterion_spec = {"expect": dict(expect or {})}
        evidence = []
        for side in SIDES:
            data = sides[side]
            criterion_spec[side] = {
                "status": data["status"],
                "body_path": data["body_path"],
                "body_sha256": data["body_sha256"],
                "connection_closed": bool(data["connection_closed"]),
            }
            path = data.get("body_path")
            if path and Path(path).is_file():
                evidence.append(self.evidence(f"verify_{side}_body", path))
        checks = {
            "method": method,
            "baseline_status": sides["baseline"]["status"],
            "patched_status": sides["patched"]["status"],
            "baseline_body_sha256": sides["baseline"]["body_sha256"],
            "patched_body_sha256": sides["patched"]["body_sha256"],
            "baseline_closed": bool(sides["baseline"]["connection_closed"]),
            "patched_closed": bool(sides["patched"]["connection_closed"]),
            "timeout": not completed,
            "errors": {side: sides[side]["error"] for side in SIDES
                       if sides[side]["error"]},
        }
        detail = {"sides": sides, "expect": dict(expect or {}),
                  "request": {"method": method, "redirects_followed": False,
                              "proxy": "disabled"}}
        return RunnerResult(
            runner=self.name, benchmark=self.benchmark, kind=self.kind,
            completed=completed,
            timed_out=not completed,
            spec=criterion_spec, checks=checks, blockers=blockers,
            evidence=evidence, policy=self.policy(), detail=detail)
