"""补丁工作区的文件与进程原语：读树、复制树、算哈希、跑命令、写日志。

这里只做**实验副本**相关的事，绝不碰 origin：

- `read_tree()` 把源树读成 `{相对路径: bytes}`（跳过 `.git` / `__pycache__` /
  `.platform` / 虚拟环境等非源码目录，有数量与体积上限）；
- `write_tree()` 只在目标目录里重建，先清空再写（回滚就是「用基线字节重写」）；
- `tree_manifest()` / `tree_sha256()` 给原件与副本同一把尺子；
- `run_command()` 用干净环境（`PATH` 最小集合、`HOME`/`TMPDIR` 指到副本外、
  `PYTHONDONTWRITEBYTECODE=1`）在指定目录里执行，捕获退出码与截断日志。
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .contracts import PatchError, json_bytes, safe_relpath, sha256_bytes

#: 读树时跳过的目录名（都不是「目标源码」，读进来只会污染哈希）
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".tox", ".venv", "venv", "node_modules", ".platform", ".idea", ".vscode",
})
#: 读树上限（超过就拒绝，不静默截断）
MAX_TREE_FILES = 4000
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
#: 日志截断（完整日志另存文件，doc 里只放尾部）
LOG_TAIL = 4000


@dataclass(frozen=True)
class CommandResult:
    cmd: str
    root: str
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    duration: float = 0.0

    @property
    def output(self) -> str:
        return (self.stdout or "") + (self.stderr or "")

    def to_dict(self) -> dict:
        return {"cmd": self.cmd, "root": self.root,
                "exit_code": self.exit_code, "timed_out": bool(self.timed_out),
                "duration": round(float(self.duration), 3)}


def read_tree(root: Path | str, *, max_files: int = MAX_TREE_FILES,
              max_bytes: int = MAX_TREE_BYTES) -> dict[str, bytes]:
    """读源码树：相对路径 → bytes；符号链接跳过（不跟到树外）。"""
    base = Path(root)
    if not base.is_dir():
        raise PatchError(f"source root is not a directory: {base}")
    files: dict[str, bytes] = {}
    total = 0
    for path in sorted(base.rglob("*")):
        rel_parts = path.relative_to(base).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            raise PatchError(f"file too large to patch: {path}")
        data = path.read_bytes()
        rel = "/".join(rel_parts)
        files[rel] = data
        total += len(data)
        if len(files) > max_files:
            raise PatchError(f"source tree has more than {max_files} files")
        if total > max_bytes:
            raise PatchError(f"source tree larger than {max_bytes} bytes")
    if not files:
        raise PatchError(f"source tree is empty: {base}")
    return files


def write_tree(dst: Path | str, files: Mapping[str, bytes]) -> None:
    """把 `{rel: bytes}` 原样重建到 dst（先清空；只在副本目录调用）。"""
    target = Path(dst)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    for rel, data in sorted(files.items()):
        rel = safe_relpath(rel)
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(data))


def tree_manifest(files: Mapping[str, bytes]) -> dict[str, str]:
    return {str(rel): sha256_bytes(bytes(data))
            for rel, data in sorted(files.items())}


def tree_sha256(manifest: Mapping[str, str]) -> str:
    """整棵树的哈希：对「路径 + 文件哈希」排序后做一次摘要。"""
    payload = "\n".join(f"{rel} {digest}"
                        for rel, digest in sorted(manifest.items()))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def manifest_of_tree(root: Path | str) -> dict[str, str]:
    return tree_manifest(read_tree(root))


def _clean_env(root: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    home = Path(tempfile.gettempdir()) / "vulnmap-patch-home"
    home.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "PATCH_ROOT": str(root),
        "PATCH_EXPERIMENT": "1",
    }
    for key, value in (extra or {}).items():
        env[str(key)] = str(value)
    return env


def run_command(cmd: str, *, cwd: Path | str, timeout: float = 60.0,
                env: Mapping[str, str] | None = None) -> CommandResult:
    """在 `cwd` 里跑一条命令；超时/异常都落成结果，不向上抛。"""
    import time

    root = Path(cwd).resolve()
    text = str(cmd or "").strip()
    if not text:
        raise PatchError("empty command")
    text = text.replace("{ROOT}", str(root))
    started = time.monotonic()
    try:
        proc = subprocess.run(text, shell=True, cwd=str(root),
                              env=_clean_env(root, env), capture_output=True,
                              text=True, errors="replace", timeout=timeout)
        return CommandResult(cmd=text, root=str(root), exit_code=proc.returncode,
                             timed_out=False, stdout=proc.stdout or "",
                             stderr=proc.stderr or "",
                             duration=time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(cmd=text, root=str(root), exit_code=None,
                             timed_out=True,
                             stdout=_as_text(exc.stdout),
                             stderr=_as_text(exc.stderr) or "timeout",
                             duration=time.monotonic() - started)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def write_log(path: Path | str, result: CommandResult) -> dict:
    """把完整输出写到日志文件，返回 doc 里要记的摘要（含日志自身哈希）。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = (f"$ {result.cmd}\n"
            f"cwd={result.root} exit={result.exit_code} "
            f"timed_out={result.timed_out}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}\n")
    data = body.encode("utf-8")
    target.write_bytes(data)
    return {"log": str(target), "log_sha256": sha256_bytes(data),
            "log_size": len(data), "output_tail": _tail(result.output)}


def _tail(text: str, limit: int = LOG_TAIL) -> str:
    text = str(text or "")
    return text if len(text) <= limit else "…" + text[-limit:]


def write_json(path: Path | str, doc) -> bytes:
    """确定性写 JSON，返回实际写入的字节（供调用方算 sha）。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = json_bytes(doc)
    target.write_bytes(data)
    return data


def read_json(path: Path | str) -> dict:
    target = Path(path)
    try:
        import json
        return json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PatchError(f"missing patch artifact: {target}") from exc
    except ValueError as exc:
        raise PatchError(f"bad patch artifact JSON: {target} ({exc})") from exc


def file_sha256(path: Path | str) -> str:
    return sha256_bytes(Path(path).read_bytes())


__all__ = [
    "SKIP_DIRS", "MAX_TREE_FILES", "MAX_TREE_BYTES", "MAX_FILE_BYTES",
    "LOG_TAIL", "CommandResult", "read_tree", "write_tree", "tree_manifest",
    "tree_sha256", "manifest_of_tree", "run_command", "write_log",
    "write_json", "read_json", "file_sha256",
]
