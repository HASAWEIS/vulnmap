"""V2 P3.7 重放执行器：把「旧案例已有的 PoC + 旧日志」重放一遍。

P2 的 fuzz 执行器只在**新构建**上从零找崩溃；但仓里已经有一批跑过的案例
（`workspace/<case>/artifacts/verify/*.bin` + `logs/*vul*.log`），它们的 PoC
本来就是可用的判据输入。P3.7 让规划器在这类工作区上优先 `kind=replay`：

~~~text
discover_pocs(workspace)          # 只读发现旧 PoC（不递归、不联网、不改文件）
        ↓ 选一条（显式 poc → plan.inputs.replay.poc_path → 稳定排序第一条）
execute(plan, index, ...)         # 重放一次（docker 或本地命令），落日志
        ↓
候选崩溃记录（candidates.from_crash 认得的形状）+ 判据输入 spec
~~~

三条硬约束：

1. **不产结论**：`execute()` 只回答“这条 PoC 在这套执行环境里跑出了什么”
   （退出码 / sanitizer 文本 / 日志哈希），`spec` 是喂给 `verify --spec` 的
   **判据输入**，永远不写 `verified`/`confirmed`/`verdict`——判据仍由
   [benchmark_policy](../../benchmark_policy.py) 唯一推导；
2. **跑不动就是跑不动**：没 PoC、没有执行手段（无 docker 且无命令）、超时、
   隔离要求不满足，一律抛 `ReplayError`，由编排层落 `FAILED` 而不是 `NO_REPRO`
   （“没跑起来”决不能被记成“不可复现”）；
3. **可复算**：PoC 与旧日志都算 sha256；本次重放的完整输出落盘并给路径，
   `stack_hash = sha256("replay:" + crash_type + ":" + 归一化前三个栈帧)`，
   与 D3 的 sha1 口径分开（replay 的栈来自另一套执行环境，不假装同源）。

执行顺序（确定性，按优先级解析）：显式 `poc` → `plan.inputs.replay.poc_path`
→ `discover_pocs()` 第一条；命令：`replay_cmd` 参数 → `plan.inputs.replay.cmd`
→ 环境变量 `VULNMAP_REPLAY_CMD` → docker 镜像。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path

SCHEMA = "vulnmap.replay.v1"

DEFAULT_TIMEOUT = 60.0
MAX_TIMEOUT = 3600.0

#: 单条 PoC 的上限（拒绝把整卷数据当输入；旧案例的 PoC 都是几 KB 级）
MAX_POC_BYTES = 4 << 20
#: 日志只留尾部（与 runners/base.MAX_LOG_BYTES 同口径，避免吃穿内存）
MAX_LOG_BYTES = 2 << 20

#: docker 模式默认命令与容器内挂载点
DEFAULT_ARGV = ["/bin/arvo"]
CONTAINER_POC = "/tmp/poc"

#: 旧 PoC 的候选目录（只扫已存在目录的**直接子文件**，不递归）
POC_DIRS = ("artifacts/verify", "artifacts/poc", "artifacts/crash", "artifacts/crashes",
            "artifacts/exploit", "poc", "pocs", "crash", "crashes", "candidates")
POC_SUFFIXES = {".bin", ".pdf", ".pdfi", ".ps", ".poc", ".input", ".dat", ".crash"}
#: 明显不是 PoC 的后缀（日志/清单/说明）
SKIP_SUFFIXES = {".json", ".log", ".md", ".txt"}
#: 文件名以这些词开头也认（`poc-1`、`case3` 之类没有后缀的样本）
POC_PREFIXES = ("poc", "crash", "case")

#: sanitizer 签名（与 runners/cybergym.SANITIZER_RE 同口径）
SANITIZER_RE = re.compile(
    r"(AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|"
    r"UndefinedBehaviorSanitizer|HWAddressSanitizer|runtime error:|"
    r"SUMMARY: [A-Za-z]+Sanitizer)")
#: 崩溃类型抽取（ASAN 族 → SUMMARY 兜底 → UBSAN runtime error）
TYPE_RES = (
    re.compile(r"ERROR: (?:AddressSanitizer|LeakSanitizer|HWAddressSanitizer|"
               r"MemorySanitizer|ThreadSanitizer): ([\w-]+)"),
    re.compile(r"SUMMARY: [A-Za-z]+Sanitizer: ([\w-]+)"),
)
UB_RE = re.compile(r"runtime error: (.+)")
#: 栈帧行：`#N 0xADDR in func /path/file.c:LINE(:COL)`。
#: 路径组用**非贪婪**，这样 `pdf_font.c:332:9` 解析成 file=pdf_font.c / line=332
#: （D3 的 FRAME 用贪婪 `\S+`，会把 332 吃进路径、把 9 当行号；这里只用自己的一套
#: 归一化文本算 replay 的 stack_hash，不改 Discovery 的解析）
FRAME_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+(.+?):(\d+)(?::\d+)?\s*$", re.M)
SKIP_FUNC = re.compile(r"(__interceptor|__asan|__ubsan|sanitizer|asan_|ubsan_)", re.I)
SKIP_PATH = re.compile(r"(libsanitizer|/sanitizer/|asan_interceptors|compiler-rt"
                       r"|^/usr/include/|^\.\./)", re.I)

#: ExploitGym：flag 只按形态抽（最终形态校验仍是 verify.FLAG_RE）
FLAG_RE = re.compile(r"[A-Za-z]{2,12}\{[A-Za-z0-9_\-.:]{3,200}\}")

#: 非 0 退出但没有任何 sanitizer 文本时的崩溃类型
NONZERO_EXIT_TYPE = "replay_nonzero_exit"


class ReplayError(RuntimeError):
    """重放跑不动（无 PoC / 无执行手段 / 超时 / 隔离不满足）→ 编排层落 FAILED。"""


# ------------------------------------------------------------------ 工具
def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _text(value) -> str:
    return str(value or "").strip()


def _rel(workspace: Path | None, path: Path) -> str:
    """workspace 内相对路径（拿不到就退回绝对路径，绝不抛错）。"""
    if workspace is not None:
        try:
            return str(Path(path).resolve().relative_to(Path(workspace).resolve()))
        except (ValueError, OSError):
            pass
    return str(path)


# ------------------------------------------------------------------ 发现
def _bind_log(workspace: Path, poc: Path) -> tuple[str, str]:
    """给 PoC 绑旧日志：logs/<stem>.log → logs/*stem*vul*.log → 同目录 <stem>.log。"""
    stem = poc.stem
    logs_dir = workspace / "logs"
    direct = logs_dir / f"{stem}.log"
    try:
        if direct.is_file():
            return str(direct.resolve()), _sha256_file(direct)
    except OSError:
        pass
    try:
        if logs_dir.is_dir():
            named = sorted(
                p for p in logs_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".log"
                and stem in p.name and "vul" in p.name.lower())
            if named:
                return str(named[0].resolve()), _sha256_file(named[0])
    except OSError:
        pass
    sibling = poc.with_suffix(".log")
    try:
        if sibling.is_file() and sibling.resolve() != poc.resolve():
            return str(sibling.resolve()), _sha256_file(sibling)
    except OSError:
        pass
    return "", ""


def _is_poc_candidate(path: Path, size: int) -> bool:
    if size <= 0 or size > MAX_POC_BYTES:
        return False
    suffix = path.suffix.lower()
    if suffix in SKIP_SUFFIXES:
        return False
    if suffix in POC_SUFFIXES:
        return True
    return path.name.lower().startswith(POC_PREFIXES)


def _entry(workspace: Path, path: Path, *, source: str,
           known_exit=None) -> dict:
    """构造一条 PoC 条目（path/source/sha256/size/log/log_sha256/known_exit）。"""
    data = Path(path).read_bytes()
    log, log_sha = _bind_log(workspace, Path(path))
    return {
        "path": str(Path(path).resolve()),
        "source": source,
        "sha256": _sha256_bytes(data),
        "size": len(data),
        "log": log,
        "log_sha256": log_sha,
        "known_exit": known_exit if isinstance(known_exit, int) else None,
    }


def _result_json_entry(workspace: Path) -> dict | None:
    """`artifacts/verify/result.json` 声明的 PoC：优先条目（带旧退出码）。"""
    result_path = workspace / "artifacts" / "verify" / "result.json"
    try:
        if not result_path.is_file():
            return None
        doc = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    declared = doc.get("poc") or {}
    if not isinstance(declared, dict):
        return None
    raw = _text(declared.get("path"))
    if not raw:
        return None
    poc_path = Path(raw).expanduser()
    if not poc_path.is_absolute():
        poc_path = workspace / poc_path
    try:
        if not poc_path.is_file():
            return None
    except OSError:
        return None
    vul = doc.get("vul") or {}
    exit_code = vul.get("exit_code") if isinstance(vul, dict) else None
    try:
        exit_code = int(exit_code) if exit_code not in (None, "") else None
    except (TypeError, ValueError):
        exit_code = None
    return _entry(workspace, poc_path, source="artifacts/verify/result.json",
                  known_exit=exit_code)


def discover_pocs(workspace) -> list[dict]:
    """只读发现旧 PoC（稳定排序、按 sha256 去重、不递归、不改文件）。

    返回元素：`{path, source, sha256, size, log, log_sha256, known_exit}`。
    `artifacts/verify/result.json` 声明的那条排在**最前**（它是唯一带旧退出码的
    条目），其余按 `(source, path)` 排序——同一工作区多次调用结果完全一致。
    """
    if workspace in (None, ""):
        return []
    root = Path(str(workspace)).expanduser()
    try:
        if not root.is_dir():
            return []
        root = root.resolve()
    except OSError:
        return []

    ordered: list[dict] = []
    primary = _result_json_entry(root)
    if primary is not None:
        ordered.append(primary)

    for rel in POC_DIRS:
        directory = root / rel
        try:
            if not directory.is_dir():
                continue
            children = sorted(p for p in directory.iterdir() if p.is_file())
        except OSError:
            continue
        for path in children:
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if not _is_poc_candidate(path, size):
                continue
            try:
                ordered.append(_entry(root, path, source=str(path.relative_to(root))))
            except OSError:
                continue

    # 同内容只留首次出现；后出现条目的 log / known_exit 补给空字段
    final: list[dict] = []
    seen: dict[str, dict] = {}
    for item in ordered:
        digest = item["sha256"]
        first = seen.get(digest)
        if first is not None:
            for key in ("log", "log_sha256", "known_exit"):
                if first.get(key) in ("", None):
                    first[key] = item.get(key)
            continue
        seen[digest] = item
        final.append(item)

    final.sort(key=lambda item: (item["source"], item["path"]))
    heads = [item for item in final
             if item["source"] == "artifacts/verify/result.json"]
    rest = [item for item in final
            if item["source"] != "artifacts/verify/result.json"]
    return heads + rest


# ------------------------------------------------------------------ 解析
def _crash_type(log: str) -> str:
    for pattern in TYPE_RES:
        found = pattern.search(log or "")
        if found:
            return found.group(1)
    if UB_RE.search(log or ""):
        return "undefined-behavior"
    return NONZERO_EXIT_TYPE


def _frames(log: str) -> list[str]:
    """归一化栈帧：`function@basename:line`（抹掉地址与绝对路径差异）。"""
    out: list[str] = []
    for _idx, func, path, line in FRAME_RE.findall(log or ""):
        if SKIP_FUNC.search(func) or SKIP_PATH.search(path):
            continue
        out.append(f"{func.strip()}@{Path(path).name}:{int(line)}")
        if len(out) >= 3:
            break
    return out


def _stack_hash(crash_type: str, log: str) -> str:
    key = f"replay:{crash_type}:{':'.join(_frames(log))}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _flag(text: str) -> str:
    found = FLAG_RE.search(text or "")
    return found.group(0) if found else ""


# ------------------------------------------------------------------ 解析执行
def _workspace_path(plan: dict, index) -> Path | None:
    inputs = plan.get("inputs") or {}
    meta = getattr(index, "meta", {}) if index is not None else {}
    meta = meta if isinstance(meta, dict) else {}
    for value in (inputs.get("workspace"), meta.get("workspace"),
                  inputs.get("target"), plan.get("target")):
        text = _text(value)
        if not text or text.startswith(("http://", "https://")):
            continue
        try:
            path = Path(text).expanduser()
            if path.is_dir():
                return path.resolve()
        except OSError:
            continue
    return None


def _resolve_poc(plan: dict, workspace: Path | None, poc) -> Path:
    raw = poc
    if raw in (None, ""):
        replay_in = (plan.get("inputs") or {}).get("replay") or {}
        raw = replay_in.get("poc_path") or ""
    if raw not in (None, ""):
        path = Path(str(raw)).expanduser()
        if not path.is_absolute() and workspace is not None:
            path = Path(workspace) / path
        try:
            if path.is_file():
                return path.resolve()
        except OSError:
            pass
        raise ReplayError(f"replay_no_poc: PoC not found: {path}")

    pocs = discover_pocs(workspace) if workspace is not None else []
    if not pocs:
        raise ReplayError(
            f"replay_no_poc: no legacy PoC under {workspace or '<no workspace>'} "
            f"(looked for {POC_DIRS})")
    return Path(pocs[0]["path"])


def _resolve_timeout(plan: dict, timeout) -> float:
    candidate = timeout
    if candidate in (None, "", 0):
        replay_in = (plan.get("inputs") or {}).get("replay") or {}
        candidate = replay_in.get("timeout")
    if candidate in (None, "", 0):
        candidate = (plan.get("budget") or {}).get("timeout")
    try:
        value = float(candidate) if candidate not in (None, "") else DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        raise ReplayError(f"replay_bad_timeout: timeout must be a number: {candidate!r}")
    if value <= 0:
        raise ReplayError(f"replay_bad_timeout: timeout must be > 0: {value!r}")
    return min(value, MAX_TIMEOUT)


def _image(plan: dict, index, workspace: Path | None) -> str:
    inputs = plan.get("inputs") or {}
    replay_in = inputs.get("replay") or {}
    meta = getattr(index, "meta", {}) if index is not None else {}
    meta = meta if isinstance(meta, dict) else {}
    for value in (replay_in.get("image"), inputs.get("image_vul"),
                  meta.get("image_vul")):
        text = _text(value)
        if text:
            return text
    if workspace is not None:
        try:
            from ...casekit import image_for
            return _text(image_for(Path(workspace), "vul"))
        except Exception:                               # noqa: BLE001 - 推导失败按缺镜像处理
            return ""
    return ""


def _substitute(token: str, poc: Path) -> str:
    """命令模板：含 `{poc}` 的串替换成宿主 PoC 绝对路径。"""
    return token.replace("{poc}", str(poc))


def _resolve_command(plan: dict, index, workspace: Path | None, poc: Path,
                     replay_cmd) -> tuple[str, list[str], dict]:
    """返回 (method, argv, policy_extra)。顺序：参数 → plan → 环境变量 → docker。"""
    inputs = plan.get("inputs") or {}
    replay_in = inputs.get("replay") or {}
    raw, source = replay_cmd, "replay_cmd"
    if raw in (None, "", []):
        raw, source = replay_in.get("cmd"), "plan"
    if raw in (None, "", []):
        raw, source = os.environ.get("VULNMAP_REPLAY_CMD"), "env"
    if raw not in (None, "", []):
        argv = (shlex.split(raw) if isinstance(raw, str)
                else [str(item) for item in raw])
        if not argv:
            raise ReplayError("replay_no_executor: empty replay command")
        return "cmd", [_substitute(item, poc) for item in argv], {
            "command_source": source}

    docker = shutil.which("docker")
    if docker is None:
        raise ReplayError(
            "replay_no_executor: docker not found in PATH "
            "(pass --replay-cmd, set plan.inputs.replay.cmd or "
            "VULNMAP_REPLAY_CMD)")
    image = _image(plan, index, workspace)
    if not image:
        raise ReplayError(
            "replay_no_executor: cannot resolve the vul image "
            "(set plan.inputs.replay.image / plan.inputs.image_vul / "
            "workspace task.json image_vul)")
    declared = replay_in.get("argv") or list(DEFAULT_ARGV)
    argv = [_substitute(str(item), poc) for item in declared]
    command = [docker, "run", "--rm", "--network", "none",
               "-v", f"{poc}:{CONTAINER_POC}:ro", image, *argv]
    return "docker", command, {"command_source": "docker", "image": image,
                               "argv": argv}


def _kill_group(proc: subprocess.Popen) -> None:
    """按进程组收掉子进程（start_new_session=True 起的是新会话）。"""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        return
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        pass


def _spawn(argv: list[str], timeout: float) -> dict:
    """跑一条命令：输出合并、尾部截断、超时按进程组收掉。"""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        raise ReplayError(
            f"replay_no_executor: cannot spawn {argv[0]!r}: {exc}") from exc
    try:
        raw = proc.communicate(timeout=timeout)[0] or b""
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            raw = proc.communicate(timeout=5)[0] or b""
        except subprocess.TimeoutExpired:
            raw = b""
        elapsed = round(time.monotonic() - started, 3)
        raise ReplayError(
            f"replay_timeout: exceeded {timeout:.1f}s "
            f"(partial output {len(raw)} bytes, {elapsed}s)") from None
    elapsed = round(time.monotonic() - started, 3)
    truncated = len(raw) > MAX_LOG_BYTES
    tail = raw[-MAX_LOG_BYTES:]
    return {"exit_code": int(proc.returncode if proc.returncode is not None else -1),
            "log": tail.decode("utf-8", "replace"),
            "seconds": elapsed, "truncated": truncated,
            "output_bytes": len(raw)}


# ------------------------------------------------------------------ 判据输入
def _build_spec(benchmark: str, *, poc: Path, poc_sha: str, log_path: str,
                exit_code: int, crashed: bool, flag: str,
                poc_source: str, source_log: str, asan: str = "") -> dict:
    """拼判据输入（只放事实；`verified`/`verdict` 一律不出现）。

    `asan` 是 sanitizer 命中摘要（未命中＝空串，键始终存在）：`verify` 的
    CyberGym 判据用 `vul_crashed = exit != 0 or vul.asan`，所以「ASAN 命中但
    退出码 0」在重放侧和判据侧的口径一致——不会出现 replay 说崩、verify 说没崩。
    `fix` 仍留空：单侧重放不伪造修补端。
    """
    common = {
        "benchmark": benchmark,
        "input": {"path": str(poc), "sha256": poc_sha},
    }
    replay = {"poc_source": poc_source, "source_log": source_log}
    if benchmark == "cybergym":
        return {
            **common,
            "vul": {"exit_code": exit_code, "log_path": log_path,
                    "crashed": crashed, "asan": str(asan or "")},
            "fix": {},
            "replay": dict(replay),
        }
    if benchmark == "exploitgym":
        return {
            **common,
            "exploit": {"exit_code": exit_code, "log_path": log_path},
            "flag": flag,
            "replay": dict(replay),
        }
    # target_yaml / vulngym：本仓没有对应的双端判据，不伪造判据字段
    return {**common, "replay": dict(replay)}


# ------------------------------------------------------------------ 执行
def execute(plan: dict, index, hypotheses=(), workdir=None, *, poc=None,
            replay_cmd=None, timeout=None, isolation: str = "auto",
            require_isolation: bool = False) -> dict:
    """重放一条旧 PoC，返回崩溃记录 / 统计 / 判据输入（**不产结论**）。

    `poc` 显式指定时优先；否则 `plan.inputs.replay.poc_path`；
    再否则取 `discover_pocs(workspace)` 的第一条。没有 PoC、没有执行手段、
    超时、隔离要求不满足都抛 `ReplayError`（编排层落 FAILED）。
    """
    plan = dict(plan or {})
    benchmark = _text(plan.get("benchmark"))
    isolation_mode = (_text(isolation) or "auto").lower()
    if require_isolation and isolation_mode == "none":
        raise ReplayError(
            "replay_isolation: require_isolation=True but isolation='none'")

    workspace = _workspace_path(plan, index)
    poc_path = _resolve_poc(plan, workspace, poc)
    try:
        data = Path(poc_path).read_bytes()
    except OSError as exc:
        raise ReplayError(f"replay_no_poc: cannot read PoC {poc_path}: {exc}") from exc
    if not data:
        raise ReplayError(f"replay_no_poc: PoC is empty: {poc_path}")
    if len(data) > MAX_POC_BYTES:
        raise ReplayError(
            f"replay_no_poc: PoC too large ({len(data)} > {MAX_POC_BYTES}): {poc_path}")
    poc_sha = _sha256_bytes(data)

    # 旧日志/来源：优先用 discover_pocs 里同一条记录（同 sha 或同路径）
    entry = None
    if workspace is not None:
        for item in discover_pocs(workspace):
            if item["sha256"] == poc_sha or Path(item["path"]) == poc_path:
                entry = item
                break
    if entry is None:
        entry = {
            "path": str(poc_path),
            "source": _rel(workspace, poc_path),
            "sha256": poc_sha,
            "size": len(data),
            "log": "",
            "log_sha256": "",
            "known_exit": None,
        }

    eff_timeout = _resolve_timeout(plan, timeout)
    method, command, policy_extra = _resolve_command(
        plan, index, workspace, poc_path, replay_cmd)

    workdir_path = Path(str(workdir or (plan.get("inputs") or {}).get("workdir")
                           or (os.getcwd()))).expanduser()
    log_dir = workdir_path / "replay"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{poc_sha[:12]}.log"

    started = time.time()
    run = _spawn(command, eff_timeout)
    log = run["log"]
    try:
        log_path.write_text(log, encoding="utf-8", errors="replace")
    except OSError:
        pass

    sanitizer = bool(SANITIZER_RE.search(log))
    crashed = bool(run["exit_code"] != 0 or sanitizer)
    crash_type = _crash_type(log) if crashed else ""
    seconds = round(time.time() - started, 2)

    policy = {
        "isolation": isolation_mode,
        "require_isolation": bool(require_isolation),
        "network": "none" if method == "docker" else "host",
        "timeout": eff_timeout,
        "method": method,
        "truncated": bool(run["truncated"]),
        "output_bytes": int(run["output_bytes"]),
        "sanitizer": sanitizer,
        "hypotheses": len(list(hypotheses or [])),
        **policy_extra,
    }

    crashes: list[dict] = []
    if crashed:
        try:
            from ...discovery import triage
            parsed = triage.parse_log(log)
        except Exception:                                   # noqa: BLE001
            parsed = {}
        crashes.append({
            "input_bytes": data,
            "input_sha256": poc_sha,
            "crash_type": crash_type,
            "stack_hash": _stack_hash(crash_type, log),
            "log": log[-8000:],
            "input_path": str(poc_path),
            "log_path": str(log_path),
            "parsed": parsed,
            "diagnostic_valid": True,
            "access": parsed.get("access"),
            "access_size": parsed.get("access_size"),
        })

    # sanitizer 命中摘要（喂 spec.vul.asan，让「ASAN 命中但退出码 0」两侧同口径）
    asan = ""
    if crashed and sanitizer:
        asan = crash_type if crash_type and crash_type != NONZERO_EXIT_TYPE else ""
        if not asan:
            found = SANITIZER_RE.search(log)
            asan = found.group(0) if found else ""

    spec = _build_spec(
        benchmark, poc=poc_path, poc_sha=poc_sha, log_path=str(log_path),
        exit_code=run["exit_code"], crashed=crashed, flag=_flag(log),
        poc_source=entry["source"], source_log=str(entry.get("log") or ""),
        asan=asan)

    return {
        "ok": True,
        "poc": entry,
        "command": list(command),
        "exit_code": run["exit_code"],
        "crashed": crashed,
        "crash_type": crash_type,
        "log_path": str(log_path),
        "log": log,
        "seconds": seconds,
        "stats": {"execs": 1, "crashes": len(crashes), "timeouts": 0,
                  "stopped": "completed"},
        "crashes": crashes,
        "coverage": {"mode": "replay", "planned": 0, "covered": 0,
                     "uncovered": 0, "status": "complete"},
        "build": {"binary": "", "sha256": "", "harness": "replay"},
        "replay": {
            "spec": spec,
            "source_log": str(entry.get("log") or ""),
            "source_log_sha256": str(entry.get("log_sha256") or ""),
            "poc_source": entry["source"],
            "method": method,
            "policy": policy,
            "workspace": str(workspace or ""),
            "known_exit": entry.get("known_exit"),
        },
    }


__all__ = ["SCHEMA", "ReplayError", "POC_DIRS", "POC_SUFFIXES",
           "discover_pocs", "execute"]
