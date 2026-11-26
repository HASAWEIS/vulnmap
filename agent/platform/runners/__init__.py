"""V2 P3.5 runner 集合：按 benchmark 选执行方式，只产证据不产结论。

| benchmark | runner | 做什么 | 产出判据输入 |
|---|---|---|---|
| cybergym | [CyberGymRunner](cybergym.py) | docker 跑 vul/fix 镜像，同输入 | `input/vul/fix`（退出码 + sanitizer + 日志） |
| exploitgym | [ExploitGymRunner](exploitgym.py) | 官方 socket 或 `--exploit-cmd` | `flag/flag_path/exploit` |
| vulngym | [VulnGymRunner](vulngym.py) | 基线/修补两组 HTTP | `baseline/patched/expect` |

`select_runner` 是唯一入口：runner 名字与任务 benchmark 不一致时抛
`RunnerMismatch`（口径错误，不落半成品记录），benchmark 没有对应 runner 时抛
`RunnerError`（例如 `target_yaml`）。
"""
from __future__ import annotations

from .base import (DEFAULT_TIMEOUT, ISOLATION_MODES, RUNNER_GAP_BLOCKERS,
                   RUNNER_GAP_PREFIXES, RUNNER_NAMES, RUNNER_REJECT_BLOCKERS,
                   Runner, RunnerError, RunnerMismatch, RunnerResult,
                   sha256_hex)
from .cybergym import CyberGymRunner
from .exploitgym import ExploitGymRunner
from .vulngym import VulnGymRunner

RUNNERS = {
    "cybergym": CyberGymRunner,
    "exploitgym": ExploitGymRunner,
    "vulngym": VulnGymRunner,
}

__all__ = [
    "DEFAULT_TIMEOUT", "ISOLATION_MODES", "RUNNERS", "RUNNER_GAP_BLOCKERS",
    "RUNNER_GAP_PREFIXES", "RUNNER_NAMES", "RUNNER_REJECT_BLOCKERS", "Runner",
    "RunnerError", "RunnerMismatch", "RunnerResult", "CyberGymRunner",
    "ExploitGymRunner", "VulnGymRunner", "select_runner", "sha256_hex",
]


def select_runner(benchmark: str, *, name: str = "", workdir=None,
                  timeout=None, isolation: str = "auto",
                  require_isolation: bool = False,
                  options: dict | None = None) -> Runner:
    """取该 benchmark 的 runner；名字与 benchmark 不符直接拒绝。"""
    bench = (benchmark or "").strip().lower()
    want = (name or "").strip().lower() or "auto"
    if want == "auto":
        if bench not in RUNNERS:
            raise RunnerError(
                f"no runner for benchmark {bench or 'unknown'!r} "
                f"(available: {sorted(RUNNERS)})")
        cls = RUNNERS[bench]
    else:
        if want not in RUNNERS:
            raise RunnerError(
                f"unknown runner {want!r} (available: {sorted(RUNNERS)})")
        if bench and want != bench:
            raise RunnerMismatch(
                f"runner {want!r} cannot run benchmark {bench!r}; "
                f"benchmark {bench} has its own runner")
        cls = RUNNERS[want]
    return cls(workdir=workdir, timeout=timeout, isolation=isolation,
               require_isolation=require_isolation, options=options)
