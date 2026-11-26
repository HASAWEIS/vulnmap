"""按阶段的工具白名单（代码里拦截，不靠提示词）。

`check_tool` 必须在**工具真正执行前**被调用；`tools/shell.py` 与 `tools/binscan.py`
的入口都已强制走这里，绕过它需要显式传 `policy_bypass=True`，该参数只在测试里用。
"""
from __future__ import annotations

from .contracts import ToolPolicy
from .errors import ContractViolation

STAGE_POLICIES: dict[str, ToolPolicy] = {
    "recon": ToolPolicy(allowed=("Read", "Grep", "Glob", "Shell.read", "Shell.build")),
    "locate": ToolPolicy(allowed=("Read", "Grep", "Glob", "Cscope", "IDA")),
    "verify": ToolPolicy(allowed=("Read", "Write.artifacts", "Shell.docker", "Shell.gdb", "Shell.afl")),
    "exploit": ToolPolicy(allowed=("Read", "Write.artifacts", "Shell.docker", "Shell.gdb", "Shell.python")),
    "report": ToolPolicy(allowed=("Read", "Write.report")),
}

DEFAULT_DENIED = ("WebFetch", "WebSearch", "AskUserQuestion")

# 工具名 → 归类。未列出的工具名按原样判定（白名单里没有就拒）。
TOOL_ALIASES = {
    "shell.run": "Shell.read",
    "shell.run_logged": "Shell.read",
    "shell.docker": "Shell.docker",
    "shell.gdb": "Shell.gdb",
    "binscan": "Read",
}


class ToolDenied(PermissionError):
    """阶段尝试使用白名单外的工具。"""


def policy_for(stage: str) -> ToolPolicy:
    base = STAGE_POLICIES.get(stage, ToolPolicy(allowed=()))
    return ToolPolicy(allowed=base.allowed, denied=DEFAULT_DENIED)


def classify(tool: str, *, argv: list[str] | None = None) -> str:
    """把真实调用归类成策略里的名字（例如 docker/gdb 前缀归到 Shell.docker / Shell.gdb）。"""
    if argv:
        head = argv[0].rsplit("/", 1)[-1]
        if head == "docker":
            return "Shell.docker"
        if head in ("gdb", "gdb-static"):
            return "Shell.gdb"
        if head in ("afl-fuzz", "afl-showmap"):
            return "Shell.afl"
        if head in ("python", "python3"):
            return "Shell.python"
        if head in ("cc", "gcc", "clang", "make", "cmake", "ninja", "ld"):
            return "Shell.build"
    return TOOL_ALIASES.get(tool, tool)


def check_tool(stage: str, tool: str) -> None:
    pol = policy_for(stage)
    if not pol.permits(tool):
        raise ToolDenied(f"stage {stage} may not use tool {tool}")


def check_stage(stage: str) -> None:
    if stage and stage not in STAGE_POLICIES:
        raise ContractViolation(f"unknown stage: {stage}")
