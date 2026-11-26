"""工作区隔离自检。

约定的隔离不能只靠"评分器不主动读取"——那只是纪律，不是约束。
这里做两件事：
1. 权限层：封存目录必须是 0700/0600，避免其他用户/进程读取；
2. 运行层：Agent 阶段运行前，断言它**没有**读封存目录下任何文件的路径。

第 2 条是运行期断言，无法阻止同 uid 的恶意读取，但能发现"代码路径意外引用了
封存资料"这种最常见的泄漏形式。
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

SEALED_DIRS = ("experiments/sealed-3938", "experiments/sealed-10096")
PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def check_permissions(root: Path | None = None) -> list[str]:
    """返回违规列表；空表示封存目录权限合格。"""
    root = Path(root or PACKAGE_ROOT)
    problems = []
    for rel in SEALED_DIRS:
        d = root / rel
        if not d.exists():
            continue
        mode = d.stat().st_mode & 0o777
        if mode & 0o077:
            problems.append(f"{rel}: dir mode {oct(mode)} allows group/other access")
        for f in d.rglob("*"):
            if f.is_file():
                m = f.stat().st_mode & 0o777
                if m & 0o077:
                    problems.append(f"{f.relative_to(root)}: file mode {oct(m)} too open")
    return problems


def sealed_paths(root: Path | None = None) -> set[Path]:
    root = Path(root or PACKAGE_ROOT)
    out: set[Path] = set()
    for rel in SEALED_DIRS:
        d = root / rel
        if d.exists():
            out |= {p.resolve() for p in d.rglob("*") if p.is_file()}
    return out


def assert_workspace_reads_confined(ws: Path, root: Path | None = None) -> list[str]:
    """检查工作区里是否出现封存资料的副本（内容一致 = 泄漏）。"""
    import hashlib
    ws, root = Path(ws), Path(root or PACKAGE_ROOT)
    sealed = {}
    for p in sealed_paths(root):
        sealed[hashlib.sha256(p.read_bytes()).hexdigest()] = str(p.relative_to(root))
    hits = []
    for f in ws.rglob("*"):
        if not f.is_file():
            continue
        try:
            h = hashlib.sha256(f.read_bytes()).hexdigest()
        except OSError:
            continue
        if h in sealed:
            hits.append(f"{f}: identical to sealed {sealed[h]}")
    return hits


class ReadAuditor:
    """运行期审计：扫描阶段结束时的文件描述符。

    **能力边界（重要）**：只能证明"扫描时没有仍打开的封存文件描述符"。
    - 文件若已读取并关闭，检测不到；
    - 子进程读取未必覆盖。

    因此它**不能**证明"运行期间没读过"，只能作为"结束时无残留句柄"的证据。
    真正的访问限制应落在执行 Agent 工具的隔离环境里（容器挂载 / 独立用户）。
    """

    def __init__(self, root: Path | None = None):
        self.root = Path(root or PACKAGE_ROOT)
        self.sealed = sealed_paths(self.root)
        self.opened: list[str] = []
        self.violations: list[str] = []

    def record(self, path: Path) -> None:
        try:
            p = Path(path).resolve()
        except OSError:
            return
        self.opened.append(str(p))
        if p in self.sealed:
            self.violations.append(str(p))

    def scan_process_open_files(self, pid: int | None = None) -> list[str]:
        """扫描进程已打开的文件描述符，找出指向封存资料的。"""
        import os
        base = Path(f"/proc/{pid or os.getpid()}/fd")
        hits = []
        try:
            for fd in base.iterdir():
                try:
                    target = Path(os.readlink(fd))
                except OSError:
                    continue
                if target.resolve() in self.sealed:
                    hits.append(str(target))
        except OSError:
            pass
        self.violations.extend(hits)
        return hits

    def report(self) -> dict:
        return {"opened_count": len(self.opened),
                "sealed_opened": sorted(set(self.violations)),
                "no_open_handle_at_scan": not self.violations,
                # 明确不声称 stronger 结论
                "proves_no_read_during_run": False,
                "limitation": "仅证明扫描时无残留句柄；已读后关闭的文件检测不到"}
