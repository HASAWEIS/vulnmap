"""统一 diff 的生成、严格解析、应用与「像修复还是像掩盖」的硬检查。

§13 写得很直白：补丁**不能靠删功能、吞异常、改测试预期**来“修复”。所以这里
除了生成/应用 diff，还要在写盘前做一轮可解释的拒绝：

- 只改已存在的文本文件（不新建、不删除、不重命名、不改二进制）；
- 不改测试文件（`test_*` / `tests/` / `conftest.py`），避免“改预期”；
- 新增行不得是 `pytest.skip` / `xfail` / `unittest.skip`；
- 新增的 `except ...:` 块里只有 `pass` / 空 `return` 视为吞异常；
- diff 规模有上限（文件数、hunk 数、增删行数），超了要先显式放宽。

解析器只支持本工作流自己产出的统一 diff 子集（`--- a/x` / `+++ b/x` /
`@@ -l,c +l,c @@`），遇到别的形状一律 `PatchError`，不猜。
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from .contracts import PatchError, safe_relpath

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

#: 默认硬上限（可用 limits 覆盖，但必须显式）
DEFAULT_LIMITS = {
    "max_files": 3,
    "max_hunks": 16,
    "max_changed_lines": 120,
    "max_diff_bytes": 256 * 1024,
    "max_file_bytes": 8 * 1024 * 1024,
}

#: 测试文件：补丁不许改（改预期 = 假修复）
TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*$|_test\.(py|js|ts|go|rs|c|cc|cpp)$"
    r"|(^|/)conftest\.py$|(^|/)pytest\.ini$")
#: 跳过/放行的写法：修 bug 不该新增这些
SKIP_PATTERNS = (
    re.compile(r"\bpytest\.(skip|xfail)\b"),
    re.compile(r"\bunittest\.skip\b"),
    re.compile(r"@unittest\.skip"),
    re.compile(r"\bself\.skipTest\b"),
)
#: 吞异常：`except ...:` 后紧跟 `pass` / 空 `return`
EXCEPT_RE = re.compile(r"^\s*except\b[^:]*:\s*(#.*)?$")
SWALLOW_RE = re.compile(r"^\s*(pass|return(\s+None)?)\s*(#.*)?$")


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[tuple[str, str], ...] = ()      # (tag, text) tag ∈ {" ", "-", "+"}

    @property
    def added(self) -> int:
        return sum(1 for tag, _ in self.lines if tag == "+")

    @property
    def removed(self) -> int:
        return sum(1 for tag, _ in self.lines if tag == "-")


@dataclass(frozen=True)
class FileDiff:
    path: str
    hunks: tuple[Hunk, ...] = ()

    @property
    def added(self) -> int:
        return sum(h.added for h in self.hunks)

    @property
    def removed(self) -> int:
        return sum(h.removed for h in self.hunks)


# ====================================================================== 生成
def _lines(text: str) -> list[str]:
    """按行切分（不含行尾符）；空文本就是 0 行。"""
    if text == "":
        return []
    return text.splitlines()


def build_unified(path: str, before: str, after: str, *, context: int = 3) -> str:
    """生成 `a/<path>` → `b/<path>` 的统一 diff（无时间戳，确定性）。"""
    rel = safe_relpath(path)
    diff = difflib.unified_diff(_lines(before), _lines(after),
                                fromfile=f"a/{rel}", tofile=f"b/{rel}",
                                n=context, lineterm="")
    text = "\n".join(diff)
    return text + "\n" if text else ""


# ====================================================================== 解析
def _header_path(value: str) -> str:
    """`a/foo.py\t(timestamp)` → `foo.py`。"""
    text = value.split("\t")[0].strip()
    return text


def _strip_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def parse_unified(diff_text: str) -> tuple[FileDiff, ...]:
    """严格解析统一 diff；形状不认识就报错，不做容错猜测。"""
    if not str(diff_text or "").strip():
        raise PatchError("empty diff")
    lines = str(diff_text).replace("\r\n", "\n").split("\n")
    files: list[FileDiff] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("--- "):
            old_path = _header_path(line[4:])
            if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                raise PatchError("malformed diff: missing '+++' header")
            new_path = _header_path(lines[index + 1][4:])
            if _strip_prefix(old_path) != _strip_prefix(new_path):
                raise PatchError("rename/copy diff is not supported")
            path = safe_relpath(_strip_prefix(new_path))
            if path == "dev/null" or old_path.strip() == "/dev/null":
                raise PatchError("file creation/deletion is not supported")
            index += 2
            hunks: list[Hunk] = []
            while index < len(lines) and lines[index].startswith("@@"):
                match = HUNK_RE.match(lines[index])
                if not match:
                    raise PatchError(f"malformed hunk header: {lines[index]!r}")
                old_start = int(match.group(1))
                old_count = int(match.group(2) or 1)
                new_start = int(match.group(3))
                new_count = int(match.group(4) or 1)
                index += 1
                body: list[tuple[str, str]] = []
                seen_old = seen_new = 0
                while index < len(lines):
                    raw = lines[index]
                    # 只有本 hunk 的行数已经对上了，才可能是下一段头部；
                    # 否则 "--- x" 可能只是一条被删除、内容以 "-- " 开头的行。
                    complete = (seen_old == old_count and seen_new == new_count)
                    if raw.startswith("@@"):
                        break
                    if complete and raw.startswith("--- "):
                        break
                    if raw.startswith(("diff --git", "index ", "new file mode",
                                       "deleted file mode", "similarity index")):
                        break
                    if raw == "":
                        # 末尾空行（split 的产物）：只有后面已无 hunk 时才算结束
                        if index + 1 >= len(lines):
                            index += 1
                            break
                        raise PatchError("unexpected blank line inside hunk")
                    tag, text = raw[0], raw[1:]
                    if tag == " ":
                        seen_old += 1
                        seen_new += 1
                    elif tag == "-":
                        seen_old += 1
                    elif tag == "+":
                        seen_new += 1
                    elif tag == "\\":
                        index += 1
                        continue
                    else:
                        raise PatchError(
                            f"unexpected diff line {raw[:40]!r}; "
                            "only unified context/added/removed lines are supported")
                    body.append((tag, text))
                    index += 1
                if seen_old != old_count or seen_new != new_count:
                    raise PatchError(
                        f"{path}: hunk counts mismatch (@@ -{old_start},{old_count} "
                        f"+{new_start},{new_count} @@ saw -{seen_old} +{seen_new})")
                hunks.append(Hunk(old_start=old_start, old_count=old_count,
                                  new_start=new_start, new_count=new_count,
                                  lines=tuple(body)))
            if not hunks:
                raise PatchError(f"{path}: diff header without any hunk")
            files.append(FileDiff(path=path, hunks=tuple(hunks)))
        elif line.strip() == "":
            index += 1
        else:
            raise PatchError(f"unexpected diff line: {line[:60]!r}")
    if not files:
        raise PatchError("diff contains no file changes")
    paths = [item.path for item in files]
    if len(set(paths)) != len(paths):
        raise PatchError("diff touches the same file twice")
    return tuple(files)


# ====================================================================== 应用
def _apply_hunks(lines: list[str], hunks: Iterable[Hunk], *, path: str) -> list[str]:
    out: list[str] = []
    cursor = 0
    for hunk in hunks:
        if hunk.old_count == 0:
            start = hunk.old_start
        else:
            start = hunk.old_start - 1
        if start < cursor:
            raise PatchError(f"{path}: overlapping hunks")
        if start > len(lines):
            raise PatchError(f"{path}: hunk starts past end of file")
        out.extend(lines[cursor:start])
        cursor = start
        for tag, text in hunk.lines:
            if tag in (" ", "-"):
                if cursor >= len(lines) or lines[cursor] != text:
                    found = lines[cursor] if cursor < len(lines) else "<eof>"
                    raise PatchError(
                        f"{path}: context mismatch at line {cursor + 1}: "
                        f"expected {text!r} found {found!r}")
                if tag == " ":
                    out.append(text)
                cursor += 1
            else:
                out.append(text)
    out.extend(lines[cursor:])
    return out


def apply_unified(diff_text: str, files: Mapping[str, str]) -> dict[str, str]:
    """把 diff 应用到 `{path: text}` 上，返回新映射（不写盘、不改入参）。

    上下文必须逐字匹配；任何不匹配都 `PatchError`，绝不“尽力而为”。
    """
    parsed = parse_unified(diff_text)
    result = {str(key): str(value) for key, value in files.items()}
    for file_diff in parsed:
        if file_diff.path not in result:
            raise PatchError(
                f"{file_diff.path}: diff targets a file absent from the tree")
        before = result[file_diff.path]
        after_lines = _apply_hunks(_lines(before), file_diff.hunks,
                                   path=file_diff.path)
        after = "\n".join(after_lines)
        if before.endswith("\n") and after_lines:
            after += "\n"
        result[file_diff.path] = after
    return result


# ====================================================================== 检查
def changed_stats(file_diff: FileDiff) -> dict:
    return {"path": file_diff.path, "added": file_diff.added,
            "removed": file_diff.removed, "hunks": len(file_diff.hunks)}


def hygiene_problems(file_diffs: Iterable[FileDiff], diff_text: str, *,
                     limits: Mapping | None = None,
                     allow_large: bool = False) -> tuple[str, ...]:
    """拒绝“假修复”：改测试、跳过、吞异常、动二进制、规模失控。"""
    caps = dict(DEFAULT_LIMITS)
    caps.update(dict(limits or {}))
    problems: list[str] = []
    file_diffs = list(file_diffs)
    if not file_diffs:
        return ("empty_diff",)
    if len(diff_text.encode("utf-8")) > int(caps["max_diff_bytes"]):
        problems.append("diff_too_large")
    if len(file_diffs) > int(caps["max_files"]):
        problems.append(f"too_many_files:{len(file_diffs)}")
    hunks = sum(len(item.hunks) for item in file_diffs)
    if hunks > int(caps["max_hunks"]):
        problems.append(f"too_many_hunks:{hunks}")
    changed = sum(item.added + item.removed for item in file_diffs)
    if changed > int(caps["max_changed_lines"]) and not allow_large:
        problems.append(f"too_many_changed_lines:{changed}")

    for item in file_diffs:
        if TEST_PATH.search(item.path):
            problems.append(f"touches_test_file:{item.path}")
        for hunk in item.hunks:
            added = [text for tag, text in hunk.lines if tag == "+"]
            removed = [text for tag, text in hunk.lines if tag == "-"]
            for text in added:
                for pattern in SKIP_PATTERNS:
                    if pattern.search(text):
                        problems.append(f"adds_skip:{item.path}")
            # 吞异常：新增 except 块里紧接着只有 pass / 空 return
            for position, text in enumerate(added):
                if EXCEPT_RE.match(text):
                    tail = added[position + 1:position + 3]
                    if tail and all(SWALLOW_RE.match(t) for t in tail):
                        problems.append(f"swallows_exception:{item.path}")
            if removed and not added:
                problems.append(f"deletes_without_replacement:{item.path}")
    return tuple(dict.fromkeys(problems))


def diff_paths(file_diffs: Iterable[FileDiff]) -> tuple[str, ...]:
    return tuple(item.path for item in file_diffs)


def apply_to_text(diff_text: str, path: str, before: str) -> str:
    """单文件便利入口（根因定位与补丁必须落在同一个文件上）。"""
    return apply_unified(diff_text, {path: before})[path]


__all__ = [
    "DEFAULT_LIMITS", "TEST_PATH", "Hunk", "FileDiff", "build_unified",
    "parse_unified", "apply_unified", "apply_to_text", "changed_stats",
    "diff_paths", "hygiene_problems",
]
