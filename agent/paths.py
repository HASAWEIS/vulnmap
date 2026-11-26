"""工作区布局与资源根目录。"""
from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def workspace_layout(ws: Path) -> dict[str, Path]:
    ws = ws.resolve()
    return {
        "root": ws,
        "src": ws / "src",
        "build": ws / "build",
        "artifacts": ws / "artifacts",
        "logs": ws / "logs",
        "runtime": ws / ".runtime",
    }


def ensure_layout(ws: Path) -> dict[str, Path]:
    layout = workspace_layout(ws)
    for key in ("src", "build", "artifacts", "logs", "runtime"):
        layout[key].mkdir(parents=True, exist_ok=True)
    return layout
