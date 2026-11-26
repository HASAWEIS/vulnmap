"""受控命令执行：策略闸门 → 超时 → 退出码 → 日志落盘 → 禁止 shell 注入。

策略在 **exec 之前**执行：`stage` 必填，非白名单工具直接 `ToolDenied`，
不会产生任何子进程。
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..policy import check_tool, classify


@dataclass
class CmdResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False
    tool: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def gate(argv: list[str], stage: str | None, tool: str | None) -> str:
    """返回本次调用的策略工具名；stage 缺失即视为无授权调用。"""
    if not stage:
        raise PermissionError("shell call without stage: tool policy cannot be enforced")
    name = classify(tool or "shell.run", argv=argv)
    check_tool(stage, name)
    return name


def run(argv, *, cwd=None, timeout=120, env=None, stage: str | None = None,
        tool: str | None = None) -> CmdResult:
    if isinstance(argv, str):
        argv = shlex.split(argv)
    name = gate(list(argv), stage, tool)
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd) if cwd else None, capture_output=True,
                              text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        return CmdResult(argv, proc.returncode, proc.stdout, proc.stderr,
                         time.monotonic() - started, tool=name)
    except FileNotFoundError as exc:
        return CmdResult(argv, 127, "", str(exc), time.monotonic() - started, tool=name)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return CmdResult(argv, 124, out, err, time.monotonic() - started, timed_out=True, tool=name)


def run_logged(argv, log_path: Path, *, cwd=None, timeout=120, env=None,
               stage: str | None = None, tool: str | None = None) -> CmdResult:
    res = run(argv, cwd=cwd, timeout=timeout, env=env, stage=stage, tool=tool)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    body = (f"$ {' '.join(res.argv)}\n"
            f"# tool={res.tool} exit={res.exit_code} seconds={res.seconds:.2f} timeout={res.timed_out}\n"
            f"--- stdout ---\n{res.stdout}\n--- stderr ---\n{res.stderr}\n")
    log_path.write_text(body, encoding="utf-8")
    return res
