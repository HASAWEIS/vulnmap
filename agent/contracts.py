"""阶段请求/结果契约（对齐 BinSight AgentRequest）。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Literal

STAGES = ("recon", "locate", "verify", "exploit", "report")
_MCP_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ContractError(ValueError):
    """请求或结果不满足契约。"""


def _safe_rel(name: str) -> bool:
    if not name or not name.strip() or "\x00" in name:
        return False
    p = Path(name)
    return not p.is_absolute() and ".." not in p.parts


@dataclass(frozen=True)
class McpServer:
    name: str
    url: str

    def __post_init__(self) -> None:
        if not _MCP_NAME.match(self.name):
            raise ContractError(f"bad mcp name: {self.name}")
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            raise ContractError(f"mcp url must be http(s): {self.url}")


@dataclass(frozen=True)
class ToolPolicy:
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ("WebFetch", "WebSearch", "AskUserQuestion")

    def permits(self, tool: str) -> bool:
        if tool in self.denied:
            return False
        return not self.allowed or tool in self.allowed


@dataclass(frozen=True)
class Budget:
    max_turns: int = 40
    timeout_seconds: int = 3600
    max_output_repairs: int = 1
    finalization_turns: int = 3

    def __post_init__(self) -> None:
        if self.max_turns < 1:
            raise ContractError("max_turns must be >= 1")
        if self.finalization_turns >= self.max_turns:
            raise ContractError("finalization reserve must be smaller than max_turns")


@dataclass(frozen=True)
class OutputContract:
    logical_name: str
    schema: str
    required_fields: tuple[str, ...] = ()
    json_object: bool = True
    min_bytes: int = 2
    max_bytes: int = 8 * 1024 * 1024


@dataclass(frozen=True)
class StageRequest:
    run_id: str
    stage: str
    role_version: str
    prompt_version: str
    prompt: str
    skills: tuple[str, ...] = ()
    mcp_servers: tuple[McpServer, ...] = ()
    tool_policy: ToolPolicy = field(default_factory=ToolPolicy)
    budget: Budget = field(default_factory=Budget)
    required_outputs: tuple[str, ...] = ()
    output_contracts: tuple[OutputContract, ...] = ()
    resume_session_id: str | None = None

    def __post_init__(self) -> None:
        if self.stage not in STAGES:
            raise ContractError(f"unknown stage: {self.stage}")
        for name in self.skills + self.required_outputs:
            if not _safe_rel(name):
                raise ContractError(f"unsafe relative name: {name}")
        declared = {c.logical_name for c in self.output_contracts}
        unknown = declared - set(self.required_outputs)
        if unknown:
            raise ContractError(f"contracts not in required_outputs: {sorted(unknown)}")

    def contract(self, logical_name: str) -> OutputContract | None:
        for c in self.output_contracts:
            if c.logical_name == logical_name:
                return c
        return None


@dataclass
class StageResult:
    stage: str
    status: Literal["completed", "failed", "cancelled"]
    artifacts: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    stop_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)
