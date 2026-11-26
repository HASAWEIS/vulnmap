"""案例级公共工具：从 task.json 推导镜像名、取镜像 digest。"""
from __future__ import annotations

import json
from pathlib import Path

from .checkpoint import digest_or_placeholder


def load_task(ws: Path) -> dict:
    p = Path(ws) / "task.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def image_for(ws: Path, side: str) -> str:
    """从 task.json 推导镜像名。

    - CyberGym: n132/arvo:<n>-vul|fix
    - ExploitGym: cybergym/arvo:<n>-vul.<mode>-nogit（无 fix 侧）
    side ∈ {vul, fix}。显式 image_vul/image_fix 优先。
    """
    task = load_task(ws)
    benchmark = task.get("benchmark")
    if benchmark == "exploitgym":
        for key in (f"image_{side}", f"{side}_image"):
            if task.get(key):
                return str(task[key])
        if side != "vul":
            return ""            # ExploitGym 只提供 vul 侧
        if task.get("image"):
            return str(task["image"])
        tid = str(task.get("task_id", ""))
        num = tid.split("_")[-1] if "_" in tid else (tid.split(":")[-1] if ":" in tid else "")
        mode = str(task.get("image_mode") or "exp.none")
        return f"cybergym/arvo:{num}-vul.{mode}-nogit" if num else ""
    if benchmark != "cybergym":
        return ""
    for key in (f"image_{side}", f"{side}_image"):
        if task.get(key):
            return str(task[key])
    tid = str(task.get("task_id", ""))
    arvo = tid.split(":")[-1] if ":" in tid else tid
    return f"n132/arvo:{arvo}-{side}" if arvo else ""


def image_pair(ws: Path) -> dict:
    """返回 {name, digest, present} 三元组，供检查点绑定使用。"""
    out = {}
    for side in ("vul", "fix"):
        name = image_for(ws, side)
        digest = digest_or_placeholder(name) if name else ""
        out[side] = {"name": name, "digest": digest,
                     "present": bool(name) and not digest.startswith("sha256:unresolved-")}
    return out
