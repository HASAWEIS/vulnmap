"""V2 P3.5 runner 基类：把“真的跑一次 benchmark”收敛成一个受控动作。

P3 的 `verify` 只校验**证据**（文件/退出码/flag）；P3.5 补上证据是怎么来的：
CyberGym 跑 vul/fix 镜像、ExploitGym 走官方 socket 或 `--exploit-cmd`、
VulnGym 打基线/修补两组 HTTP。三者共用一个受控执行壳，规则只有四条：

1. **口径只来自 benchmark**：runner 名字必须等于任务 benchmark，
   `cybergym` 任务不能拿 `exploitgym` runner 跑（`RunnerMismatch`，不是 blocker）；
2. **runner 只产证据，不产结论**：`RunnerResult.spec` 是喂给
   [verify.evaluate](../../platform/verify.py) 的判据输入，`verified` 永远由
   `benchmark_policy` 推导——runner 自己写不了“通过”；
3. **失败必须留痕**：跑不动/超时/镜像缺失一律 `completed=False` + 具体 blocker
   （`runner_timeout:*` / `runner_unavailable:*` / `runner_error:*`），
   并且**不允许** `completed=False` 却不带 blocker；
4. **隔离与超时是显式的**：每个 runner 都记录 `policy{isolation,network,timeout,…}`，
   宿主侧默认走 [agent/discovery/isolation](../../discovery/isolation.py) 的
   bwrap/unshare（断网 + 只读根 + cap-drop），不可用时退回 `none` 并在策略里写明
   “网络=host”，`require_isolation=True` 时直接失败（fail-closed）。

字段契约见 `RunnerResult`；任何 runner 产物都不得出现“确认”类标签。
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from ...discovery import isolation as sandbox

SCHEMA = "vulnmap.runner.v1"

DEFAULT_TIMEOUT = 60.0
MAX_TIMEOUT = 3600.0
MAX_LOG_BYTES = 2 << 20          # 日志截断：只留尾部，避免把内存吃穿

RUNNER_NAMES = ("cybergym", "exploitgym", "vulngym")
# 宿主侧包裹层：container 由 runner 自己承担（CyberGym 跑的就是镜像），
# 不再套一层 docker-in-docker。
ISOLATION_MODES = ("auto", "bwrap", "unshare", "none")

# “还没有证据”：落 needs_evidence，绝不当成负结果
RUNNER_GAP_BLOCKERS = frozenset({
    "runner_incomplete", "runner_timeout", "runner_error", "runner_unavailable",
    "runner_not_configured", "docker_unavailable", "image_not_found",
    "input_not_recorded", "flag_not_captured", "baseline_not_recorded",
    "patched_not_recorded", "http_error", "connection_failed", "infra_error",
})
RUNNER_GAP_PREFIXES = (
    "runner_timeout:", "runner_error:", "runner_unavailable:",
    "runner_not_configured:", "docker_unavailable:", "image_not_found:",
    "http_error:", "connection_failed:",
)
# “口径/证据自相矛盾”：落 rejected
RUNNER_REJECT_BLOCKERS = frozenset({
    "runner_spec_invalid", "runner_benchmark_mismatch", "flag_mismatch",
    "behavior_unobserved",
})


class RunnerError(ValueError):
    """runner 无法执行（配置缺失、隔离不可用、宿主缺工具）。"""


class RunnerMismatch(RunnerError):
    """runner 与 benchmark 口径不符——契约错误，不落记录。"""


def _timeout(value) -> float:
    try:
        number = float(value) if value not in (None, "") else DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        raise RunnerError(f"timeout must be a number: {value!r}")
    if number <= 0:
        raise RunnerError(f"timeout must be > 0: {number!r}")
    return min(number, MAX_TIMEOUT)


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def _terminate(proc: subprocess.Popen) -> None:
    """按进程组收掉子进程（preexec 里 setsid，子进程可能又起了孙子进程）。"""
    for send in (signal.SIGKILL,):
        try:
            os.killpg(os.getpgid(proc.pid), send)
            return
        except (OSError, ProcessLookupError):
            pass
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        pass


# ------------------------------------------------------------------ 结果契约
@dataclass
class RunnerResult:
    """一次 runner 执行的产物。

    - `spec`：喂给 verify.evaluate 的判据输入（只含该 benchmark 自己的字段）；
    - `completed`：runner 是否跑到终点（不含“判据成立与否”）；
    - `blockers`：缺口/口径问题；`completed=False` 时至少一条；
    - `evidence`：[{kind, path, sha256, size}]，verify 会重新哈希并进 EvidenceStore；
    - `policy`：隔离模式、网络、超时等执行策略快照。
    """
    runner: str
    benchmark: str
    kind: str
    completed: bool
    timed_out: bool
    spec: dict = field(default_factory=dict)
    checks: dict = field(default_factory=dict)
    blockers: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    elapsed: float = 0.0
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.spec = dict(self.spec or {})
        self.checks = dict(self.checks or {})
        self.blockers = [str(b) for b in (self.blockers or [])]
        self.evidence = [dict(item) for item in (self.evidence or [])]
        self.policy = dict(self.policy or {})
        self.detail = dict(self.detail or {})

    @property
    def outcome(self) -> str:
        return "completed" if self.completed else "incomplete"

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "runner": self.runner,
            "benchmark": self.benchmark,
            "kind": self.kind,
            "outcome": self.outcome,
            "completed": bool(self.completed),
            "timed_out": bool(self.timed_out),
            "elapsed": self.elapsed,
            "checks": dict(self.checks),
            "blockers": list(self.blockers),
            "evidence": [dict(item) for item in self.evidence],
            "policy": dict(self.policy),
            "detail": dict(self.detail),
        }

    def validate(self) -> None:
        if self.runner not in RUNNER_NAMES:
            raise RunnerError(f"unknown runner: {self.runner!r}")
        if self.benchmark not in RUNNER_NAMES:
            raise RunnerError(f"unknown benchmark: {self.benchmark!r}")
        if self.runner != self.benchmark:
            raise RunnerError(
                f"runner {self.runner!r} cannot produce evidence for "
                f"benchmark {self.benchmark!r}")
        if not isinstance(self.spec, dict):
            raise RunnerError("runner spec must be a dict")
        if self.completed and self.timed_out:
            raise RunnerError("completed result cannot be marked timed_out")
        # 失败必须留痕：没有 blocker 的“跑不动”会变成不可解释的空结论
        if not self.completed and not self.blockers:
            raise RunnerError("incomplete runner result requires at least one blocker")
        for item in self.evidence:
            path = str(item.get("path") or "")
            if not path:
                raise RunnerError("runner evidence entry requires a path")
            digest = str(item.get("sha256") or "")
            if digest and not (len(digest) == 64 and
                               all(c in "0123456789abcdef" for c in digest)):
                raise RunnerError(f"bad evidence sha256: {digest!r}")
        if "confirmed" in json.dumps(self.to_dict(), ensure_ascii=False).lower():
            raise RunnerError("runner result must not carry a confirmation label")


# ------------------------------------------------------------------ 执行壳
class Runner:
    """runner 公共执行壳：隔离前缀 + 超时 + 日志落盘 + 证据登记。"""

    name = ""
    benchmark = ""
    kind = ""

    def __init__(self, *, workdir, timeout=None, isolation: str = "auto",
                 require_isolation: bool = False, options: dict | None = None):
        self.workdir = Path(workdir).expanduser()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.timeout = _timeout(timeout)
        self.isolation_mode = (isolation or "auto").strip().lower()
        if self.isolation_mode not in ISOLATION_MODES:
            raise RunnerError(
                f"unknown isolation mode {isolation!r}; runner supports "
                f"{ISOLATION_MODES} (container 由 runner 自己承担)")
        self.require_isolation = bool(require_isolation)
        self.options = dict(options or {})
        self._isolation = None

    # -------------------------------------------------------------- 配置
    def option(self, spec: dict, *keys, default=None):
        """显式构造参数优先于本次 spec，spec 优先于默认值。"""
        for key in keys:
            value = self.options.get(key)
            if value not in (None, "", [], {}):
                return value
        for key in keys:
            value = (spec or {}).get(key)
            if value not in (None, "", [], {}):
                return value
        return default

    def isolation_info(self) -> dict:
        if self._isolation is None:
            try:
                self._isolation = sandbox.resolve(
                    self.isolation_mode, require=self.require_isolation)
            except (RuntimeError, ValueError) as exc:
                raise RunnerError(f"isolation {self.isolation_mode!r} unavailable: {exc}")
        return self._isolation

    def policy(self) -> dict:
        base = {"isolation": self.isolation_mode, "timeout": self.timeout,
                "require_isolation": self.require_isolation}
        try:
            info = self.isolation_info()
        except RunnerError as exc:
            return {**base, "network": "unknown", "error": str(exc)}
        if info.get("mode") == "none" and self.require_isolation:
            return {**base, "network": info.get("network"), "error": "isolation required"}
        return {**base,
                "isolation": info.get("mode"),
                "network": info.get("network"),
                "no_new_privs": bool(info.get("no_new_privs")),
                "cap_drop": bool(info.get("cap_drop")),
                "ro_root": bool(info.get("ro_root")),
                "pidns": bool(info.get("pidns"))}

    # -------------------------------------------------------------- 工具
    def write_bytes(self, name: str, data: bytes) -> Path:
        path = self.workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_text(self, name: str, text: str) -> Path:
        return self.write_bytes(name, str(text).encode("utf-8", "replace"))

    def spawn(self, argv, *, timeout=None, log_name: str = "",
              extra_env: dict | None = None) -> dict:
        """在隔离前缀下跑一条命令；超时按进程组收，输出落 workdir 日志。"""
        budget = _timeout(timeout if timeout is not None else self.timeout)
        try:
            info = self.isolation_info()
        except RunnerError as exc:
            return {"argv": [str(a) for a in argv], "exit_code": None,
                    "timed_out": False, "output": "", "seconds": 0.0,
                    "log_path": "", "error": str(exc), "infra_error": True}
        prefix = sandbox.prefix_for(info)
        full = [str(a) for a in list(prefix) + list(argv)]
        env = dict(os.environ)
        for key, value in (extra_env or {}).items():
            env[str(key)] = str(value)
        started = time.monotonic()
        text, timed_out, error = "", False, ""
        proc = None
        try:
            proc = subprocess.Popen(
                full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, errors="replace", env=env,
                preexec_fn=sandbox.preexec(info, budget))
        except OSError as exc:
            error = f"spawn failed: {exc}"
        if proc is not None:
            try:
                text = proc.communicate(timeout=budget)[0] or ""
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate(proc)
                try:
                    text = proc.communicate(timeout=5)[0] or ""
                except subprocess.TimeoutExpired:
                    text = ""
        elapsed = round(time.monotonic() - started, 3)
        text = str(text)[-MAX_LOG_BYTES:]
        log_path = self.write_text(log_name, text) if log_name else None
        return {"argv": full, "exit_code": (None if (timed_out or proc is None)
                                            else proc.returncode),
                "timed_out": timed_out, "output": text, "seconds": elapsed,
                "log_path": str(log_path) if log_path else "",
                "error": error, "infra_error": bool(error)}

    def evidence(self, kind: str, path) -> dict:
        path = Path(path)
        if not path.is_file():
            raise RunnerError(f"runner evidence missing on disk: {path}")
        data = path.read_bytes()
        return {"kind": kind, "path": str(path),
                "sha256": sha256_hex(data), "size": len(data)}

    # -------------------------------------------------------------- 生命周期
    def failure(self, blocker: str, *, error: str = "", spec: dict | None = None) -> RunnerResult:
        return RunnerResult(
            runner=self.name, benchmark=self.benchmark, kind=self.kind,
            completed=False, timed_out=str(blocker).startswith("runner_timeout"),
            spec=dict(spec or {}), checks={}, blockers=[str(blocker)],
            evidence=[], policy=self.policy(), elapsed=0.0,
            detail={"error": str(error or "")})

    def run(self, spec: dict) -> RunnerResult:      # pragma: no cover - 抽象
        raise NotImplementedError

    def safe_run(self, spec: dict) -> RunnerResult:
        """跑一次并保证“失败也落证据”：任何异常都转成带 blocker 的结果。"""
        started = time.monotonic()
        try:
            result = self.run(dict(spec or {}))
        except RunnerMismatch:
            raise
        except Exception as exc:                     # noqa: BLE001 - 失败不得逃逸
            result = self.failure(f"runner_error:{type(exc).__name__}",
                                  error=f"{type(exc).__name__}: {exc}")
        if not isinstance(result, RunnerResult):
            raise RunnerError(f"{self.name} runner returned {type(result).__name__}")
        result.elapsed = round(time.monotonic() - started, 3)
        result.policy = {**(result.policy or self.policy()), "elapsed": result.elapsed}
        result.validate()
        self.record(result)
        return result

    def record(self, result: RunnerResult) -> Path:
        """把结果快照写成 runner.json 并登记为证据（失败结果同样落盘）。"""
        doc = result.to_dict()
        data = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n").encode("utf-8")
        path = self.write_bytes("runner.json", data)
        if not any(item.get("kind") == "verify_runner" for item in result.evidence):
            result.evidence.append({"kind": "verify_runner", "path": str(path),
                                    "sha256": sha256_hex(data), "size": len(data)})
        return path
