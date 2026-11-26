"""V2 P1：ProgramIndex —— 跨 benchmark 的统一“程序理解”产物。

边界（与 P0 一致：只读，不执行目标）：
- target_yaml：直接复用 Discovery D0（profile.scan）与 D1（callsites.scan）；
- cybergym / exploitgym：读 workspace/task.json + src/ 源码目录，复用 D0/D1 的
  解析函数做**有界扫描**（大仓源文件数远超一次索引能承受的量，必须截断并记录）；
- vulngym：workspace 通常没有源码树，从 SOURCE.md + task.json 提取静态定位锚点
  （repo/commit/file/line/symbol），不伪造源码事实。

契约字段（任务要求的最小集）：
  benchmark / root / entry_points / functions / call_sites / coverage / formats /
  source_count
扩展字段（审计需要，不替代最小集）：
  task_id / anchors / sources / notes / meta / counts / sha256

ProgramIndex 只描述“程序长什么样、危险调用在哪”，不产出漏洞结论；
结论由 verify/review（P3）给出。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..discovery import callsites as d1
from ..discovery import profile as d0

SCHEMA = "vulnmap.program_index.v1"

# 有界扫描：大仓不能全量解析（CG-01 全量 D0 就要 ~12s，D1 更慢）
WORKSPACE_MAX_SOURCES = 240
TARGET_YAML_MAX_SOURCES = 1_200
MAX_FUNCTIONS = 800
MAX_CALL_SITES = 240
MAX_LISTED_SOURCES = 400
FORMAT_SCAN_LIMIT = 20_000

# workspace 扫描优先级：task.json component 指向的文件最优先，其次 harness/fuzzer
PREFER_TAIL = ("fuzz", "harness")

META_KEYS = ("schema", "case_id", "task_id", "benchmark", "project", "component",
             "target_cwe", "image_vul", "image_fix", "image", "image_mode",
             "model", "run_id")

SOURCE_SUFFIXES = set(d0.SRC_SUFFIXES) | {".py", ".js", ".ts", ".java", ".go", ".rb"}

# ---- P3.7 源码包自动解包（CG/EG workspace 只带 repo-vul.tar.gz 时）
UNPACK_SCHEMA = "vulnmap.unpack.v1"
#: 按优先级尝试的源码包名（CG 案例实际用 repo-vul.tar.gz）
UNPACK_ARCHIVES = ("repo-vul.tar.gz", "repo-vul.tgz", "repo.tar.gz", "src.tar.gz")
#: 解包缓存目录名：<workspace>/.unpacked/<archive_sha256[:16]>/
UNPACK_CACHE_DIRNAME = ".unpacked"
UNPACK_MANIFEST = "manifest.json"
UNPACK_MAX_BYTES = 2 << 30          # 解包后总字节上限（防 gzip 炸弹）
UNPACK_MAX_MEMBERS = 200_000        # 成员数上限
UNPACK_SOURCE_LOOKUPS = 8           # 找 src/ 时最多看几层子目录

#: 镜像 digest 只做审计：docker inspect 失败不阻断静态索引（记 warning）
IMAGE_SIDES = {"cybergym": ("vul", "fix"), "exploitgym": ("vul",)}
_IMAGE_CACHE: dict[str, dict] = {}


class ProgramError(ValueError):
    """ProgramIndex 契约/构建错误。"""


class UnpackError(ProgramError):
    """源码包解包失败（路径穿越/成员类型/超限/损坏），必须让 understand 失败。"""


# ---------------------------------------------------------------- 规范化
def _canonical(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest(doc: dict) -> str:
    """内容哈希：忽略 sha256 字段本身，保证 save 前后可复算。"""
    clean = {k: v for k, v in doc.items() if k != "sha256"}
    return hashlib.sha256(_canonical(clean).encode("utf-8")).hexdigest()


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return None


# ---------------------------------------------------------------- P3.7 解包
def _file_sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _safe_member_path(name: str) -> str:
    """tar 成员名 → 安全的相对 posix 路径；任何越界形态都直接拒绝。

    拒绝：绝对路径、Windows 盘符/UNC、含 NUL、含 `..` 段、空名。
    不做“就地修正”（例如把 `..` 抹掉）——那会把攻击包静默变成另一种树。
    """
    raw = str(name or "").replace("\\", "/")
    if not raw or raw in (".", "./"):
        raise UnpackError(f"tar member has no usable name: {name!r}")
    if raw.startswith("/") or raw.startswith("//"):
        raise UnpackError(f"tar member is absolute: {name!r}")
    if re.match(r"^[A-Za-z]:", raw):
        raise UnpackError(f"tar member has drive prefix: {name!r}")
    if "\x00" in raw:
        raise UnpackError(f"tar member name contains NUL: {name!r}")
    parts = [part for part in PurePosixPath(raw).parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UnpackError(f"tar member escapes root: {name!r}")
    if not parts:
        raise UnpackError(f"tar member has no usable name: {name!r}")
    return "/".join(parts)


def _checked_members(tf: tarfile.TarFile, *, max_bytes: int) -> list[tuple]:
    """先全量校验再解包：任何越界/链接/超限都在写盘前被拒。"""
    members = tf.getmembers()
    if len(members) > UNPACK_MAX_MEMBERS:
        raise UnpackError(
            f"tar has too many members: {len(members)} > {UNPACK_MAX_MEMBERS}")
    out: list[tuple] = []
    total = 0
    for member in members:
        rel = _safe_member_path(member.name)
        if member.isdir():
            out.append((member, rel))
            continue
        if not member.isfile():
            # 符号链接/硬链接/设备/FIFO 都可能把写入点或读取点挪到根外
            raise UnpackError(
                f"tar member type not allowed: {member.name!r} "
                f"(only regular files and directories)")
        total += max(0, int(member.size))
        if total > max_bytes:
            raise UnpackError(
                f"tar expands beyond limit: >{max_bytes} bytes")
        out.append((member, rel))
    return out


@dataclass
class UnpackResult:
    """一次源码包解包的结果（可用于审计的不可变事实）。"""

    archive: str
    sha256: str
    cache_dir: str
    root: str
    src_root: str
    files: int
    bytes: int
    cached: bool = False
    schema: str = UNPACK_SCHEMA

    def to_meta(self) -> dict:
        return {
            "schema": self.schema,
            "archive": self.archive,
            "sha256": self.sha256,
            "cache_dir": self.cache_dir,
            "root": self.root,
            "src_root": self.src_root,
            "files": int(self.files),
            "bytes": int(self.bytes),
            "cached": bool(self.cached),
        }


def _has_sources(root: Path) -> bool:
    try:
        for child in root.iterdir():
            if child.is_file() and child.suffix.lower() in d0.SRC_SUFFIXES:
                return True
            if child.is_dir() and child.name in ("src", "lib", "source"):
                for inner in child.iterdir():
                    if inner.is_file() and inner.suffix.lower() in d0.SRC_SUFFIXES:
                        return True
    except OSError:
        return False
    return False


def find_src_root(root: Path) -> Path:
    """在解包树里找真正的源码根：`<root>/src` → `<child>/src` → 有源文件的最浅目录。"""
    root = Path(root)
    candidates: list[Path] = [root / "src"]
    try:
        children = sorted((p for p in root.iterdir() if p.is_dir()),
                          key=lambda p: p.name)[:UNPACK_SOURCE_LOOKUPS]
    except OSError:
        children = []
    candidates.extend(child / "src" for child in children)
    if root.is_dir() and _has_sources(root):
        candidates.append(root)
    for child in children:
        if _has_sources(child):
            candidates.append(child)
    for cand in candidates:
        if cand.is_dir() and _has_sources(cand):
            return cand
    # 没有可直接识别的源码：退回解包根，由 _source_files 全量兜底
    return root


def _manifest_matches(cache_dir: Path, sha256: str) -> dict | None:
    manifest = cache_dir / UNPACK_MANIFEST
    if not manifest.is_file():
        return None
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict) or doc.get("sha256") != sha256:
        return None
    return doc


def unpack_archive(archive: Path | str, *, cache_root: Path | str | None = None,
                   max_bytes: int = UNPACK_MAX_BYTES) -> UnpackResult:
    """把源码包解到内容寻址缓存 `<cache_root>/<sha256[:16]>/`。

    - 缓存键是**包内容哈希**，同包重复调用只做一次解包；
    - 先校验全部成员再写盘：绝对路径、`..`、盘符、链接/设备一律 `UnpackError`；
    - 先解到 `.tmp-*` 再 `os.replace` 原子换入，半成品不会留成“可用缓存”；
    - 写入点只可能落在 cache_root（默认 `<archive 所在目录>/.unpacked`），不出仓库。
    """
    archive = Path(archive)
    if not archive.is_file():
        raise UnpackError(f"source archive not found: {archive}")
    sha256 = _file_sha256(archive)
    root_dir = Path(cache_root) if cache_root else archive.parent / UNPACK_CACHE_DIRNAME
    target = root_dir / sha256[:16]

    cached = _manifest_matches(target, sha256)
    if cached is not None:
        src_rel = str(cached.get("src_rel") or "")
        src_root = (target / src_rel) if src_rel else target
        if not src_root.is_dir():
            src_root = target
        return UnpackResult(
            archive=str(archive), sha256=sha256, cache_dir=str(target),
            root=str(target), src_root=str(src_root),
            files=int(cached.get("files") or 0),
            bytes=int(cached.get("bytes") or 0), cached=True)

    root_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f".tmp-{sha256[:8]}-", dir=str(root_dir)))
    try:
        try:
            with tarfile.open(archive, mode="r:*") as tf:
                members = _checked_members(tf, max_bytes=max_bytes)
                for member, rel in members:
                    dest = tmp / rel
                    if member.isdir():
                        dest.mkdir(parents=True, exist_ok=True)
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    source = tf.extractfile(member)
                    if source is None:
                        raise UnpackError(f"tar member unreadable: {member.name!r}")
                    with source, open(dest, "wb") as fh:
                        shutil.copyfileobj(source, fh, 1 << 20)
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise UnpackError(
                f"source archive unreadable: {archive}: "
                f"{type(exc).__name__}: {exc}") from exc
        # 落盘后复核：所有路径（含解析后的真实路径）都在 tmp 内
        resolved_root = tmp.resolve()
        files = 0
        total = 0
        for path in sorted(tmp.rglob("*")):
            if path.is_symlink():
                raise UnpackError(f"unpacked tree contains a symlink: {path}")
            if not path.is_file():
                continue
            try:
                path.resolve().relative_to(resolved_root)
            except ValueError:
                raise UnpackError(f"unpacked path escapes root: {path}")
            files += 1
            total += path.stat().st_size
        src_root = find_src_root(tmp)
        try:
            src_rel = src_root.relative_to(tmp).as_posix()
        except ValueError:
            src_rel = ""
        if src_rel == ".":
            src_rel = ""
        manifest_doc = {
            "schema": UNPACK_SCHEMA, "archive": str(archive), "sha256": sha256,
            "files": files, "bytes": total, "src_rel": src_rel,
        }
        (tmp / UNPACK_MANIFEST).write_text(
            json.dumps(manifest_doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        if target.exists():
            # 只有缓存键（sha 前 16 位）对得上才敢清理，防止误删
            if target.parent == root_dir:
                shutil.rmtree(target, ignore_errors=True)
            else:
                raise UnpackError(f"refuse to replace cache dir outside root: {target}")
        os.replace(tmp, target)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        # 并发解包：另一个进程可能已经把同一个包原子换入，直接命中它的缓存
        raced = _manifest_matches(target, sha256)
        if raced is not None:
            src_rel_raced = str(raced.get("src_rel") or "")
            return UnpackResult(
                archive=str(archive), sha256=sha256, cache_dir=str(target),
                root=str(target),
                src_root=str((target / src_rel_raced) if src_rel_raced else target),
                files=int(raced.get("files") or 0),
                bytes=int(raced.get("bytes") or 0), cached=True)
        raise

    src_root = (target / src_rel) if src_rel else target
    return UnpackResult(
        archive=str(archive), sha256=sha256, cache_dir=str(target),
        root=str(target), src_root=str(src_root),
        files=int(manifest_doc["files"]), bytes=int(manifest_doc["bytes"]),
        cached=False)


def discover_archives(workspace: Path | str) -> list[Path]:
    """workspace 里按优先级找到的源码包（只认固定名，不递归）。"""
    ws = Path(workspace)
    found: list[Path] = []
    for name in UNPACK_ARCHIVES:
        path = ws / name
        if path.is_file():
            found.append(path)
    return found


def ensure_sources(workspace: Path | str, *,
                   cache_root: Path | str | None = None) -> UnpackResult | None:
    """workspace 没有可用 src/ 时，解包 repo-vul.tar.gz 供 D0/D1 使用。

    返回 None 表示“没有源码包可解”（不是错误）；解包本身失败抛 `UnpackError`。
    """
    for archive in discover_archives(workspace):
        return unpack_archive(archive, cache_root=cache_root)
    return None


# ---------------------------------------------------------------- P3.7 镜像
def image_state(workspace: Path | str, benchmark: str) -> tuple[dict, list[str]]:
    """从 task.json 推镜像名并取 digest；失败只记 warning，绝不阻断索引。"""
    ws = Path(workspace)
    key = f"{ws.resolve()}::{benchmark}"
    cached = _IMAGE_CACHE.get(key)
    if cached is not None:
        return dict(cached["images"]), list(cached["warnings"])

    images: dict = {}
    warnings: list[str] = []
    sides = IMAGE_SIDES.get(benchmark, ())
    if sides:
        try:
            from ..casekit import image_for
            from ..checkpoint import image_digest
        except Exception as exc:  # noqa: BLE001 - 旧模块导入失败也不阻断
            warnings.append(f"镜像模块不可用：{type(exc).__name__}: {exc}")
            image_for = image_digest = None  # type: ignore[assignment]
        for side in sides:
            if image_for is None or image_digest is None:
                break
            try:
                name = str(image_for(ws, side) or "")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"image_{side} 解析失败：{type(exc).__name__}: {exc}")
                continue
            if not name:
                continue
            digest = ""
            try:
                digest = image_digest(name)
            except Exception as exc:  # noqa: BLE001 - docker 缺失/镜像不在本地
                warnings.append(
                    f"docker inspect {name} 未取到 digest："
                    f"{type(exc).__name__}: {str(exc)[:160]}")
            images[side] = {"name": name, "digest": digest, "present": bool(digest)}
    _IMAGE_CACHE[key] = {"images": dict(images), "warnings": list(warnings)}
    return images, warnings


# ---------------------------------------------------------------- 复用 D0/D1
#: 扫描时跳过的目录名：解包缓存（P3.7）不能反过来被当成“工作区源码”
_SKIP_DIRS = frozenset({UNPACK_CACHE_DIRNAME, ".git", "__pycache__", "node_modules"})


def _skip_path(root: Path, path: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return any(part in _SKIP_DIRS for part in rel.parts)


def _source_files(root: Path, limit: int,
                  prefer: tuple[str, ...] = ()) -> tuple[list[Path], int]:
    """确定性挑选源文件：component 文件 → harness/fuzzer → 路径浅的优先。"""
    found: list[Path] = []
    for path in d0._walk(root):
        if path.is_file() and path.suffix.lower() in d0.SRC_SUFFIXES:
            if _skip_path(root, path):
                continue
            found.append(path)

    def rank(path: Path) -> tuple:
        rel = path.relative_to(root).as_posix()
        low = rel.lower()
        for i, token in enumerate(prefer):
            if token and token.lower() in low:
                return (i, rel.count("/"), rel)
        return (len(prefer), rel.count("/"), rel)

    ranked = sorted(found, key=rank)
    return ranked[:max(0, int(limit))], len(found)


def _functions_from(texts: dict[str, str]) -> list[dict]:
    functions: list[dict] = []
    for rel, text in texts.items():
        for name, start in d0.iter_functions(text):
            functions.append({"name": name, "file": rel,
                              "line": d0._line_of(text, start)})
    functions.sort(key=lambda f: (f["file"], f["line"], f["name"]))
    return functions


def _entries_from(texts: dict[str, str], functions: list[dict]) -> list[dict]:
    """入口：main / libFuzzer harness / 文件名含 fuzz|harness 的函数。"""
    entries: list[dict] = []
    seen: set[tuple] = set()

    def add(kind: str, name: str, rel: str, line: int) -> None:
        key = (kind, name, rel, line)
        if key in seen:
            return
        seen.add(key)
        entries.append({"kind": kind, "name": name, "file": rel, "line": line})

    patterns = (
        ("main", "main", re.compile(r"\bmain\s*\(")),
        ("fuzzer", "LLVMFuzzerTestOneInput", re.compile(r"\bLLVMFuzzerTestOneInput\s*\(")),
        ("fuzzer_init", "LLVMFuzzerInitialize", re.compile(r"\bLLVMFuzzerInitialize\s*\(")),
    )
    for rel, text in texts.items():
        clean = d0._strip_comments(text)
        for kind, name, pattern in patterns:
            m = pattern.search(clean)
            if m:
                add(kind, name, rel, d0._line_of(text, m.start()))
        base = Path(rel).name.lower()
        if "fuzz" in base or "harness" in base:
            for fn in functions:
                if fn["file"] == rel:
                    add("harness", fn["name"], rel, fn["line"])
    entries.sort(key=lambda e: (e["file"], e["line"], e["kind"], e["name"]))
    return entries


TYPE_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_ \t\*]*")


def _owner_loose(clean: str, spans: list[dict], offset: int) -> str:
    """D1 归属失败时的兜底：K&R 风格（返回类型单独一行）函数定义识别。

    只接受「标识符( + 上一行是纯类型前缀」的形状；不确定时保留 "?"，
    宁可少标一个函数，也不把调用语句误标成定义。
    """
    owner = d1._owner(spans, offset)
    if owner != "?":
        return owner
    pos = clean.rfind("\n", 0, offset)
    for _ in range(500):
        prev = clean.rfind("\n", 0, pos)
        if prev < 0:
            break
        line = clean[prev + 1:pos]
        # 定义位置：函数名顶格 + 上一行是顶格的纯类型前缀（K&R 风格）
        m = re.match(r"([A-Za-z_]\w*)\s*\(", line)
        if m and m.group(1) not in d0.CTRL_KEYWORDS:
            head_start = clean.rfind("\n", 0, prev) + 1
            head = clean[head_start:prev]
            if (TYPE_PREFIX.fullmatch(head.strip()) and head[:1] not in (" ", "\t")
                    and ";" not in head and "(" not in head):
                return m.group(1)
        pos = prev
    return owner


def _sites_from(texts: dict[str, str]) -> list[dict]:
    """D1 调用点扫描核心（复用危险函数表/可达性/可控性判定），输入限定为文件集。"""
    spans_by_file = {rel: d1._function_spans(text) for rel, text in texts.items()}
    reachable = d1._reachable_names(texts, spans_by_file)
    sites: list[dict] = []
    for rel, text in texts.items():
        clean = d0._strip_comments(text)
        spans = spans_by_file[rel]
        for callee, (category, weight) in d1.DANGEROUS.items():
            start = 0
            while True:
                idx = clean.find(callee, start)
                if idx < 0:
                    break
                start = idx + 1
                before = clean[idx - 1] if idx > 0 else " "
                if before.isalnum() or before == "_":
                    continue
                open_paren = idx + len(callee)
                while open_paren < len(clean) and clean[open_paren] in " \t\r\n":
                    open_paren += 1
                if open_paren >= len(clean) or clean[open_paren] != "(":
                    continue
                args = d1._call_args(clean, open_paren)
                function = _owner_loose(clean, spans, idx)
                controlled = d1._controlled(args)
                reach = function in reachable
                sites.append({
                    "function": function,
                    "file": rel,
                    "line": d0._line_of(text, idx),
                    "callee": callee,
                    "category": category,
                    "args": args,
                    "controlled": controlled,
                    "reachable": reach,
                    "score": weight * (2 if reach else 1) * (2 if controlled else 1),
                    "status": "unanalyzed",
                })
    sites.sort(key=lambda s: (-s["score"], s["file"], s["line"], s["callee"]))
    for i, site in enumerate(sites):
        site["id"] = f"{site['file']}:{site['line']}:{site['callee']}#{i}"
    return sites


def _detect_formats(root: Path) -> list[str]:
    """只读 magic/扩展名识别（与 D0 同表），文件数有上限。"""
    formats: list[str] = []
    scanned = 0
    for path in d0._walk(root):
        if not path.is_file() or path.suffix.lower() in d0.SRC_SUFFIXES:
            continue
        if _skip_path(root, path):
            continue
        scanned += 1
        if scanned > FORMAT_SCAN_LIMIT:
            break
        fmt = d0.detect_format(path)
        if fmt and fmt not in formats:
            formats.append(fmt)
    return formats


def _prefer_tokens(meta: dict) -> tuple[str, ...]:
    tokens: list[str] = []
    component = str(meta.get("component") or "")
    for part in re.split(r"[\s,;]+", component):
        part = part.strip()
        if not part:
            continue
        if "/" in part or Path(part).suffix.lower() in SOURCE_SUFFIXES:
            tokens.append(part)
        elif re.fullmatch(r"[A-Za-z_]\w{2,}", part):
            tokens.append(part)
    tokens.extend(PREFER_TAIL)
    return tuple(dict.fromkeys(tokens))


def _find_source(root: Path, token: str) -> tuple[str, str]:
    """把 component 里的相对路径解析到 workspace 内的真实文件。

    返回 (resolved_rel, content)；找不到时返回 ("", "")。
    """
    direct = root / token
    if direct.is_file():
        return _rel(root, direct), (_read_text(direct) or "")
    name = Path(token).name
    if not name:
        return "", ""
    for path in d0._walk(root):
        if path.is_file() and path.name == name:
            return _rel(root, path), (_read_text(path) or "")
    return "", ""


def _find_symbol_line(text: str, symbol: str) -> int:
    if not text or not symbol:
        return 0
    clean = d0._strip_comments(text)
    for m in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}\s*\(", clean):
        return d0._line_of(text, m.start())
    return 0


def _looks_like_symbol(token: str) -> bool:
    """只接受函数/方法名形态：含下划线，或小写开头后接大写（do_GET / pdfi_*）。

    纯单词（browser / WordNet）不接受：宁可不给锚点，也不伪造定位。
    """
    if not re.fullmatch(r"[A-Za-z_]\w{2,}", token):
        return False
    if not (token[0].islower() or token[0] == "_"):
        return False   # ClassName/WordNet 不当作函数符号
    return "_" in token or bool(re.search(r"[a-z][A-Z]", token))


def _component_anchors(meta: dict, root: Path | None) -> list[dict]:
    """task.json component → 静态定位锚点（文件 + 符号 + 行号）。"""
    anchors: list[dict] = []
    component = str(meta.get("component") or "").strip()
    if not component:
        return anchors
    files: list[str] = []
    symbols: list[str] = []
    for part in re.split(r"[\s,;]+", component):
        part = part.strip()
        if not part:
            continue
        if "/" in part or Path(part).suffix.lower() in SOURCE_SUFFIXES:
            files.append(part)
        elif _looks_like_symbol(part):
            symbols.append(part)
    resolved = {tok: _find_source(root, tok) if root else ("", "") for tok in files}
    for tok, (rel, text) in resolved.items():
        line = 0
        for symbol in symbols:
            line = _find_symbol_line(text, symbol)
            if line:
                break
        anchors.append({
            "kind": "task_component",
            "file": tok,
            "resolved_file": rel,
            "line": line,
            "symbol": symbols[0] if symbols and line else "",
            "repo": "",
            "commit": "",
            "verified": bool(rel) and bool(line),
            "note": ("workspace 源码中解析到符号行" if line else
                     "component 只给文件/符号，行号未解析（需上游源码确认）"),
        })
    if files or symbols:
        if not files:
            anchors.append({
                "kind": "task_component",
                "file": "",
                "resolved_file": "",
                "line": 0,
                "symbol": symbols[0],
                "repo": "",
                "commit": "",
                "verified": False,
                "note": "component 只给符号名，没有文件；需按 benchmark 元数据或上游源码定位",
            })
    return anchors


# ---------------------------------------------------------------- 契约对象
@dataclass
class ProgramIndex:
    benchmark: str
    root: str
    task_id: str = ""
    entry_points: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    call_sites: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    formats: list = field(default_factory=list)
    source_count: int = 0
    anchors: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    images: dict = field(default_factory=dict)
    unpack: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    schema: str = SCHEMA

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        doc = {
            "schema": self.schema,
            "task_id": self.task_id,
            "benchmark": self.benchmark,
            "root": self.root,
            "entry_points": list(self.entry_points),
            "functions": list(self.functions),
            "call_sites": list(self.call_sites),
            "coverage": dict(self.coverage),
            "formats": list(self.formats),
            "source_count": int(self.source_count),
            "anchors": list(self.anchors),
            "sources": list(self.sources),
            "notes": list(self.notes),
            "meta": dict(self.meta),
            "images": dict(self.images),
            "unpack": dict(self.unpack),
            "warnings": list(self.warnings),
        }
        doc["counts"] = {
            "entry_points": len(self.entry_points),
            "functions": len(self.functions),
            "call_sites": len(self.call_sites),
            "anchors": len(self.anchors),
        }
        doc["sha256"] = digest(doc)
        return doc

    @classmethod
    def from_dict(cls, doc: dict) -> "ProgramIndex":
        if not isinstance(doc, dict):
            raise ProgramError("program index doc must be a dict")
        return cls(
            benchmark=str(doc.get("benchmark") or ""),
            root=str(doc.get("root") or ""),
            task_id=str(doc.get("task_id") or ""),
            entry_points=list(doc.get("entry_points") or []),
            functions=list(doc.get("functions") or []),
            call_sites=list(doc.get("call_sites") or []),
            coverage=dict(doc.get("coverage") or {}),
            formats=list(doc.get("formats") or []),
            source_count=int(doc.get("source_count") or 0),
            anchors=list(doc.get("anchors") or []),
            sources=list(doc.get("sources") or []),
            notes=list(doc.get("notes") or []),
            meta=dict(doc.get("meta") or {}),
            images=dict(doc.get("images") or {}),
            unpack=dict(doc.get("unpack") or {}),
            warnings=list(doc.get("warnings") or []),
            schema=str(doc.get("schema") or SCHEMA),
        )

    @property
    def sha256(self) -> str:
        return digest(self.to_dict())

    def validate(self) -> None:
        for name in ("benchmark", "root"):
            if not str(getattr(self, name) or "").strip():
                raise ProgramError(f"program index missing {name}")
        for name in ("entry_points", "functions", "call_sites", "anchors",
                     "sources", "notes", "formats", "warnings"):
            if not isinstance(getattr(self, name), list):
                raise ProgramError(f"{name} must be a list")
        for name in ("coverage", "images", "unpack", "meta"):
            if not isinstance(getattr(self, name), dict):
                raise ProgramError(f"{name} must be a dict")
        if not (isinstance(self.source_count, int) and self.source_count >= 0):
            raise ProgramError("source_count must be a non-negative int")

    # ---- 构建入口 ----
    @classmethod
    def build(cls, task: dict, *, max_sources: int | None = None,
              max_functions: int = MAX_FUNCTIONS,
              max_call_sites: int = MAX_CALL_SITES,
              unpack_root: str | Path | None = None) -> "ProgramIndex":
        """按 benchmark 分派；task 是 store.get_task()/TaskSpec.to_dict() 形态。"""
        if not isinstance(task, dict):
            raise ProgramError("task must be a dict")
        benchmark = str(task.get("benchmark") or "")
        target = str(task.get("target") or "")
        if not target:
            raise ProgramError("task.target is required")
        task_id = str(task.get("task_id") or "")
        metadata = task.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        if benchmark == "vulngym":
            index = _vulngym_index(task_id, target, metadata,
                                   max_sources=max_sources,
                                   max_functions=max_functions,
                                   max_call_sites=max_call_sites)
        elif benchmark in ("cybergym", "exploitgym"):
            index = _workspace_index(task_id, benchmark, target,
                                     max_sources=max_sources,
                                     max_functions=max_functions,
                                     max_call_sites=max_call_sites,
                                     unpack_root=unpack_root)
        elif benchmark == "target_yaml":
            index = _target_yaml_index(task_id, target,
                                       max_functions=max_functions,
                                       max_call_sites=max_call_sites)
        else:
            raise ProgramError(f"unsupported benchmark: {benchmark!r}")
        index.validate()
        return index


# ---------------------------------------------------------------- target.yaml
def _target_yaml_index(task_id: str, target: str, *,
                       max_functions: int, max_call_sites: int) -> ProgramIndex:
    path = Path(target)
    root = path.parent if path.is_file() else path
    if not root.is_dir():
        raise ProgramError(f"target_yaml root is not a directory: {root}")

    notes = ["target_yaml：使用 Discovery D0（profile.scan）与 D1（callsites.scan）全量扫描"]
    declared = {}
    yaml_path = None
    try:
        from ..discovery import targetspec
        yaml_path = targetspec.find(root) if root.is_dir() else None
        if yaml_path is not None:
            declared = targetspec.load(yaml_path)
            notes.append(f"target.yaml: {_rel(root, yaml_path)}")
    except Exception as exc:  # noqa: BLE001 - yaml 非法不应阻断静态索引
        notes.append(f"target.yaml 解析失败（忽略声明字段）：{type(exc).__name__}")

    prof = d0.scan(root)
    ledger = d1.scan(root)

    entries = [{"kind": "main", "name": "main",
                "file": e.get("file", ""), "line": int(e.get("line") or 0)}
               for e in prof.get("entries", [])]
    functions = list(prof.get("functions", []))
    total_functions = len(functions)
    kept_functions = functions[:max_functions]
    total_sites = len(ledger.get("sites", []))
    kept_sites = list(ledger.get("sites", []))[:max_call_sites]

    formats = list(prof.get("formats") or [])
    declared_format = (declared or {}).get("format")
    if declared_format and declared_format != "unknown" and declared_format not in formats:
        formats.insert(0, declared_format)

    sources = list(prof.get("sources") or [])
    coverage = {
        "planned": total_sites,
        "covered": int(ledger.get("covered") or 0),
        "uncovered": int(ledger.get("uncovered") or total_sites),
        "status": ledger.get("status", "partial" if total_sites else "complete"),
        "scanned_sources": len(sources),
        "total_sources": int(prof.get("source_count") or len(sources)),
        "truncated_sources": 0,
        "truncated_sites": max(0, total_sites - len(kept_sites)),
        "truncated_functions": max(0, total_functions - len(kept_functions)),
        "mode": "static_source",
    }
    return ProgramIndex(
        benchmark="target_yaml",
        root=str(root.resolve()),
        task_id=task_id,
        entry_points=entries,
        functions=kept_functions,
        call_sites=kept_sites,
        coverage=coverage,
        formats=formats or ["unknown"],
        source_count=int(prof.get("source_count") or 0),
        anchors=[],
        sources=sources[:MAX_LISTED_SOURCES],
        notes=notes,
        meta={"declared": {k: v for k, v in (declared or {}).items()
                           if k in ("name", "format", "build", "fuzz")}},
    )


# ---------------------------------------------------------------- CG / EG
def _workspace_index(task_id: str, benchmark: str, target: str, *,
                     max_sources: int | None, max_functions: int,
                     max_call_sites: int,
                     unpack_root: str | Path | None = None) -> ProgramIndex:
    ws = Path(target)
    if not ws.is_dir():
        raise ProgramError(f"{benchmark} workspace is not a directory: {ws}")

    meta: dict = {"workspace": str(ws.resolve())}
    task_json = ws / "task.json"
    if task_json.is_file():
        try:
            data = json.loads(task_json.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                meta.update({k: data[k] for k in META_KEYS if k in data})
                meta["task_json"] = _rel(ws, task_json)
        except (OSError, json.JSONDecodeError) as exc:
            meta["task_json_error"] = type(exc).__name__

    src_root = ws / "src" if (ws / "src").is_dir() else ws
    limit = WORKSPACE_MAX_SOURCES if max_sources is None else int(max_sources)
    prefer = _prefer_tokens(meta)
    files, total_sources = _source_files(src_root, limit, prefer)

    # ---- P3.7：src/ 为空时自动解包 repo-vul.tar.gz，把解包树接进 D0/D1
    unpack_meta: dict = {}
    unpack_note = ""
    if total_sources == 0:
        unpacked = ensure_sources(ws, cache_root=unpack_root)
        if unpacked is not None:
            src_root = Path(unpacked.src_root)
            files, total_sources = _source_files(src_root, limit, prefer)
            unpack_meta = unpacked.to_meta()
            meta["unpack"] = unpack_meta
            try:
                shown = _rel(ws, src_root)
            except Exception:  # noqa: BLE001 - 仅用于提示文本
                shown = str(src_root)
            unpack_note = (
                f"解包 {Path(unpacked.archive).name}：sha256 {unpacked.sha256}，"
                f"{unpacked.files} 个文件 / {unpacked.bytes} 字节，"
                f"{'命中缓存' if unpacked.cached else '首次解包'} → {shown}")

    texts: dict[str, str] = {}
    for path in files:
        text = _read_text(path)
        if text is not None:
            texts[_rel(src_root, path)] = text

    functions = _functions_from(texts)
    total_functions = len(functions)
    kept_functions = functions[:max_functions]
    entries = _entries_from(texts, functions)
    sites = _sites_from(texts)
    total_sites = len(sites)
    kept_sites = sites[:max_call_sites]
    formats = _detect_formats(src_root) or ["unknown"]
    anchors = _component_anchors(meta, src_root)

    truncated_sources = max(0, total_sources - len(texts))
    coverage = {
        "planned": total_sites,
        "covered": 0,
        "uncovered": total_sites,
        "status": "partial" if total_sites else "complete",
        "scanned_sources": len(texts),
        "total_sources": total_sources,
        "truncated_sources": truncated_sources,
        "truncated_sites": max(0, total_sites - len(kept_sites)),
        "truncated_functions": max(0, total_functions - len(kept_functions)),
        "mode": "static_source_bounded",
    }
    notes = [
        f"{benchmark}：workspace task.json + src/ 有界静态扫描",
        f"源文件上限 {limit}（命中 {len(texts)}/{total_sources}）；"
        "排序优先级：task.json component → fuzz/harness → 路径深度",
    ]
    if unpack_note:
        notes.append(unpack_note)
    if total_sources == 0:
        notes.append("src/ 内没有 C/C++ 源文件，且 workspace 没有可解的源码包："
                     "无法静态索引，需先补齐 repo-vul.tar.gz 或 src/ 后重跑 understand")

    # ---- P3.7：镜像 digest 只做审计（docker inspect 失败不阻断索引）
    images, warnings = image_state(ws, benchmark)
    for warning in warnings:
        notes.append(f"镜像：{warning}")
    if warnings:
        notes.append("镜像 digest 未全部取到：记 warning，不阻断静态索引（审计字段见 images）")
    if truncated_sources:
        notes.append(f"截断 {truncated_sources} 个源文件：functions/call_sites 只覆盖扫描子集")
    if not entries:
        notes.append("未识别入口（main/LLVMFuzzerTestOneInput/harness）：入口需从 build.sh 确认")

    return ProgramIndex(
        benchmark=benchmark,
        root=str(src_root.resolve()),
        task_id=task_id,
        entry_points=entries,
        functions=kept_functions,
        call_sites=kept_sites,
        coverage=coverage,
        formats=formats,
        source_count=total_sources,
        anchors=anchors,
        sources=[_rel(src_root, p) for p in files][:MAX_LISTED_SOURCES],
        notes=notes,
        meta=meta,
        images=images,
        unpack=unpack_meta,
        warnings=warnings,
    )


# ---------------------------------------------------------------- VulnGym
def _workspace_path(target: str, metadata: dict) -> Path | None:
    if not target.startswith(("http://", "https://")):
        path = Path(target)
        if path.is_file():
            return path.parent
        if path.is_dir():
            return path
    for key in ("workspace", "source_md", "local_path"):
        raw = metadata.get(key)
        if not raw:
            continue
        path = Path(str(raw))
        if path.is_file():
            return path.parent
        if path.is_dir():
            return path
    return None


def _parse_source_md(path: Path) -> dict:
    """SOURCE.md：表格字段优先，正文/行内反引号作为兜底。"""
    info: dict = {"path": str(path)}
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return info
    row_keys = {
        "repo": ("repo url", "repo", "仓库", "仓库地址"),
        "commit": ("commit", "上游 commit", "修订"),
        "file": ("关键文件", "key file", "file"),
        "line": ("关键行", "key line"),
        "task": ("任务 id", "task id"),
    }
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        key = cells[0].lower().rstrip(":")
        for field_name, names in row_keys.items():
            if key not in names:
                continue
            value = cells[1]
            if field_name == "line":
                m = re.match(r"(\d+)", value)
                info["line"] = int(m.group(1)) if m else 0
                info.setdefault("line_text", value)
            elif value:
                info.setdefault(field_name, value)
    if "repo" not in info:
        m = re.search(r"https?://[^\s|)`]+", text)
        if m:
            info["repo"] = m.group(0)
    if "commit" not in info:
        m = re.search(r"(?i)\bcommit\b[^\n|]{0,40}?\b([0-9a-f]{7,40})\b", text)
        if m:
            info["commit"] = m.group(1)
    symbol_text = info.get("line_text") or text
    m = re.search(r"\b([A-Za-z_]\w*\.[A-Za-z_]\w*)\b", symbol_text)
    if m:
        info["symbol"] = m.group(1)
    else:
        m = re.search(r"`([A-Za-z_]\w*)`", text)
        if m:
            info["symbol"] = m.group(1)
    return info


def _vulngym_index(task_id: str, target: str, metadata: dict, *,
                   max_sources: int | None, max_functions: int,
                   max_call_sites: int) -> ProgramIndex:
    ws = _workspace_path(target, metadata)
    meta: dict = {"target": target}
    if ws is not None:
        meta["workspace"] = str(ws.resolve())
        task_json = ws / "task.json"
        if task_json.is_file():
            try:
                data = json.loads(task_json.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    meta.update({k: data[k] for k in META_KEYS if k in data})
                    meta["task_json"] = _rel(ws, task_json)
            except (OSError, json.JSONDecodeError) as exc:
                meta["task_json_error"] = type(exc).__name__

    source_md = None
    raw_md = metadata.get("source_md")
    if raw_md:
        candidate = Path(str(raw_md))
        source_md = candidate if candidate.is_file() else None
    if source_md is None and ws is not None:
        for name in ("SOURCE.md", "source.md", "SOURCE.MD"):
            if (ws / name).is_file():
                source_md = ws / name
                break

    anchors: list[dict] = []
    notes = ["vulngym：服务型目标，静态定位锚点优先来自 SOURCE.md 与 task.json"]
    md_info: dict = {}
    if source_md is not None:
        md_info = _parse_source_md(source_md)
        meta["source_md"] = str(source_md.resolve())
        verified = False
        resolved_file = ""
        if ws is not None and md_info.get("file"):
            rel, _text = _find_source(ws, md_info["file"])
            if rel:
                verified = True
                resolved_file = rel
        anchors.append({
            "kind": "source_md",
            "file": md_info.get("file", ""),
            "resolved_file": resolved_file,
            "line": int(md_info.get("line") or 0),
            "symbol": md_info.get("symbol", ""),
            "repo": md_info.get("repo", ""),
            "commit": md_info.get("commit", ""),
            "verified": verified,
            "note": ("workspace 内有镜像源码，可本仓复算" if verified else
                     "workspace 无源码树：行号必须按 repo+commit 在上游复算，不能只写行号"),
        })
        notes.append(f"SOURCE.md: {_rel(ws, source_md) if ws else source_md}")
    else:
        notes.append("未找到 SOURCE.md：锚点只能来自 task.json 元数据，可复算性最弱")

    anchors.extend(_component_anchors(meta, ws) if ws is not None else [])
    if not anchors and meta.get("component"):
        anchors.append({
            "kind": "task_metadata", "file": "", "resolved_file": "",
            "line": 0, "symbol": str(meta.get("component")),
            "repo": "", "commit": "", "verified": False,
            "note": "只有 component 文本：无文件/行号，需人工或上游源码补全",
        })

    # 若 workspace 恰好带源码树（部分 VulnGym 复现包会有），仍然做有界静态索引
    src_root = ws / "src" if ws is not None and (ws / "src").is_dir() else None
    entries: list[dict] = []
    functions: list[dict] = []
    sites: list[dict] = []
    total_sources = 0
    scanned_sources = 0
    sources: list[str] = []
    files: list[Path] = []
    if src_root is not None:
        limit = WORKSPACE_MAX_SOURCES if max_sources is None else int(max_sources)
        files, total_sources = _source_files(src_root, limit, _prefer_tokens(meta))
        if total_sources == 0:
            # src/ 存在但没有源文件（VG-01 就是空目录）：退回 anchors_only
            src_root, files = None, []
    if src_root is not None:
        texts: dict[str, str] = {}
        for path in files:
            text = _read_text(path)
            if text is not None:
                texts[_rel(src_root, path)] = text
        scanned_sources = len(texts)
        functions = _functions_from(texts)[:max_functions]
        entries = _entries_from(texts, functions)
        sites = _sites_from(texts)
        sources = [_rel(src_root, p) for p in files][:MAX_LISTED_SOURCES]
        notes.append(f"workspace 内有 src/ 源码树：有界扫描 {scanned_sources}/{total_sources}")
    else:
        notes.append("workspace 无可用源码树（src/ 缺失或为空）："
                     "source_count=0，call_sites/coverage 为空")

    total_sites = len(sites)
    kept_sites = sites[:max_call_sites]
    if src_root is not None:
        coverage = {
            "planned": total_sites, "covered": 0, "uncovered": total_sites,
            "status": "partial" if total_sites else "complete",
            "scanned_sources": scanned_sources, "total_sources": total_sources,
            "truncated_sources": max(0, total_sources - scanned_sources),
            "truncated_sites": max(0, total_sites - len(kept_sites)),
            "truncated_functions": 0, "mode": "static_source_bounded",
        }
    else:
        coverage = {
            "planned": 0, "covered": 0, "uncovered": 0, "status": "unavailable",
            "scanned_sources": 0, "total_sources": 0, "truncated_sources": 0,
            "truncated_sites": 0, "truncated_functions": 0,
            "mode": "anchors_only",
            "reason": "workspace 无源码树：只有 SOURCE.md/task.json 静态锚点",
        }

    return ProgramIndex(
        benchmark="vulngym",
        root=str((src_root or ws).resolve()) if (src_root or ws) is not None else target,
        task_id=task_id,
        entry_points=entries,
        functions=functions,
        call_sites=kept_sites,
        coverage=coverage,
        formats=(_detect_formats(src_root) or ["unknown"]) if src_root is not None
        else ["unknown"],
        source_count=total_sources,
        anchors=anchors,
        sources=sources,
        notes=notes,
        meta=meta,
    )
