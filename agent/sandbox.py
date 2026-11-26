"""访问隔离：把 Agent 跑在容器里，只挂载允许的资料。

为什么不用 uid 隔离：本机 Agent 与数据同属 uid 1000，0700/0600 挡不住同用户读取；
无 root 时也无法把封存目录改属主或用 setpriv 切组。

因此隔离改为**挂载可见性**：
- 只挂载 workspace（Agent 的输入与产物）；
- 封存目录**不进入挂载表**，容器内不存在该路径；
- 容器内以非 root 用户运行，减少对宿主的影响。

这不是密码学隔离，但把"靠自觉不读"变成了"路径不存在"。
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

SANDBOX_IMAGE = "python:3.12-slim"


def probe(sealed: Path) -> dict:
    """检查容器内封存路径是否真的不可达。"""
    sealed = Path(sealed).resolve()
    ws = (sealed.parent.parent / "workspace").resolve()
    argv = [
        "docker", "run", "--rm",
        "--network", "none",
        "--user", "1000:1000",
        "-v", f"{ws}:/work:ro",
        SANDBOX_IMAGE,
        "sh", "-c",
        f"ls {sealed} 2>&1; echo '---'; ls /work >/dev/null 2>&1 && echo work_mounted",
    ]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    out = res.stdout
    return {
        "sealed_visible": "No such file or directory" not in out and "cannot access" not in out.lower(),
        "work_mounted": "work_mounted" in out,
        "raw": out.strip()[:400],
    }


def run_guarded(ws: Path, sealed: Path, cmd: list[str], *, timeout: int = 1800) -> dict:
    """在容器内执行 Agent 命令；封存目录不在挂载表里。"""
    ws, sealed = Path(ws).resolve(), Path(sealed).resolve()
    argv = [
        "docker", "run", "--rm", "--network", "none",
        "--user", "1000:1000",
        "-v", f"{ws}:/work",
        SANDBOX_IMAGE, *cmd,
    ]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return {"exit_code": res.returncode, "stdout": res.stdout[-4000:],
            "stderr": res.stderr[-2000:], "argv": argv}
