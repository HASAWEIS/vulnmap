"""V2 P3.8：runner spec 自动生成 —— 让 `task.json` / metadata 直接喂 runner。

P3.5 的 runner 需要一份**显式**的执行输入（镜像名、镜像内命令、socket 地址、
基线/修补 URL）。真实案例的这些事实分散在 `workspace/<case>/task.json`
与任务 metadata（`--meta image_vul=...`）里，靠人手抄一遍既慢又容易抄错口径。
本模块只做一件事：**把这些事实翻译成 runner spec，并把缺的东西说清楚**。

三条硬约束：

1. **只翻译，不发明**：字段来自 `task.json` / metadata / 调用方显式覆盖；
   没有任何默认值能凭空造出“镜像名”或“服务地址”。缺就是缺，进 `blockers`；
2. **缺口是缺口，不是负结果**：所有 blocker 都用 runner 词表里已有的
   `runner_*` / `docker_unavailable:` / `image_not_found:` / `connection_failed:` /
   `http_error:` 前缀，`verify._status` 一律归 `needs_evidence`——
   本模块**没有**任何写 `verified` 的路径（本文件不出现对它的赋值）；
3. **本机能不能跑是事实**：`probe=True` 时真的去查 `docker image inspect`、
   真的去连 `host:port`、真的去 GET 两个 URL。本机没有 arvo 镜像、
   没有 ExploitGym 服务、没有 VulnGym 实例时，smoke 必须如实报 `needs_evidence`，
   而不是让 `docker run` 用 125 退出码冒充“vul 端崩了”。

**可审计补充配置（V3 CG-01 smoke）**：`task.json` 是历史记录，语义字段不手改；
缺的执行事实（容器内命令、判据输入、本地镜像别名）写进 `<workspace>/smoke.json`
（schema `vulnmap.smoke_config.v1`，见 [docs/V3-CG01-SMOKE.md](../../../docs/V3-CG01-SMOKE.md)）。
本模块只读它，优先级 `overrides > smoke.json > metadata > task.json`，并用
`smoke_config` 字段回传该文件的路径，保证“这次跑的命令/输入从哪来”可审计。

字段映射（一个 benchmark 一套，不互相污染）：

| benchmark | 读什么 | 生成 |
|---|---|---|
| CyberGym | `image_vul`/`image_fix`（别名 `vul_image`/`fix_image`）+ `harness_cmd`/`entry` + `smoke.json` 的 `input_path`/`input_sha256`/镜像候选 | `image_vul`、`image_fix`、`cmd`、`input_path`、`input_sha256`、`images`（含 digest）、`docker` |
| ExploitGym | `image`/`mode`/`task_info`（dict、JSON 字符串或文件路径） | `mode`（`socket` / `exploit_cmd`）、`host`/`port` 或 `exploit_cmd`、`image`、`image_mode`、`expected_flag` |
| VulnGym | `service_url` 或 `baseline_url`+`patched_url` | `baseline_url`、`patched_url`、`method`、`expect` |

产物字段见 `build_runner_spec()` 的返回（`schema=vulnmap.runner_spec.v1`）。
"""
from __future__ import annotations

import json
import shlex
import shutil
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from hashlib import sha256
from pathlib import Path

SCHEMA = "vulnmap.runner_spec.v1"
#: 可审计补充配置：`<workspace>/smoke.json`（不写回 task.json）
SMOKE_SCHEMA = "vulnmap.smoke_config.v1"
SMOKE_FILENAME = "smoke.json"
#: 镜像候选的“两侧”口径（vul 崩 / fix 干净）
IMAGE_SIDES = ("vul", "fix")
#: smoke.json 认识的顶层键；其余键进 warnings（不静默吞掉）
SMOKE_KEYS = frozenset({
    "schema", "case_id", "task_id", "benchmark",
    "harness_cmd", "harness", "cmd", "command", "entry", "entry_point",
    "input_path", "input_file", "input", "input_sha256",
    "images", "image_vul", "image_fix", "docker",
    "notes", "provenance", "description", "comment",
})
#: smoke.json 里能直接写进 runner spec 的键（镜像走 `images` 候选，不直接覆盖声明）
SMOKE_RUNNER_KEYS = ("harness_cmd", "harness", "cmd", "command", "entry",
                     "entry_point", "input_path", "input_file", "input",
                     "input_sha256", "docker")

#: benchmark → runner 名（一一对应；没有 runner 的 benchmark 不在这里）
RUNNER_FOR = {"cybergym": "cybergym", "exploitgym": "exploitgym",
              "vulngym": "vulngym"}
BENCHMARKS = tuple(RUNNER_FOR)

#: 每个 benchmark 认的 runner 键白名单：调用方覆盖只会透传这些，
#: 判据键（vul/fix/flag/baseline/patched…）一律不进 runner spec。
RUNNER_KEYS = {
    "cybergym": ("image_vul", "vul_image", "image_fix", "fix_image",
                 "harness_cmd", "cmd", "command", "input_path", "input_file",
                 "input", "docker"),
    "exploitgym": ("image", "image_mode", "mode", "transport", "host", "port",
                   "exploit_cmd", "expected_flag", "task_info"),
    "vulngym": ("service_url", "base_url", "baseline_url", "baseline",
                "patched_url", "patched", "method", "headers", "expect"),
}

#: 必填字段（缺了就不知道该跑什么 → blocker）
REQUIRED = {
    "cybergym": ("image_vul", "image_fix", "cmd"),
    "exploitgym": ("image", "mode", "exploit_target"),
    "vulngym": ("baseline_url", "patched_url"),
}

#: 缺口型 blocker（verify._status 会把它们归 needs_evidence，不归 no_repro）
#: `input_not_found` / `input_sha_mismatch`：声明的判据输入不存在或与声明的
#: sha256 不符——此时**没有**可信输入可挂载，属于“缺证据”，不是“复现失败”。
GAP_BLOCKERS = frozenset({
    "docker_unavailable", "image_not_found", "connection_failed", "http_error",
    "runner_not_configured", "runner_unavailable", "runner_timeout",
    "input_not_found", "input_sha_mismatch",
})

DEFAULT_PROBE_TIMEOUT = 3.0
DEFAULT_DOCKER = "docker"
SOCKET_MODES = ("socket", "exploit_cmd")
#: docker 客户端连不上 daemon 时的特征串（区别于“镜像不存在”）
DAEMON_HINTS = ("cannot connect to the docker daemon",
                "is the docker daemon running",
                "permission denied while trying to connect",
                "error during connect")


class SpecError(ValueError):
    """spec 生成的契约错误（只用于参数本身非法，例如 benchmark 未知）。"""


# ------------------------------------------------------------------ 小工具
def _text(value) -> str:
    return str(value or "").strip()


def _first(data: dict, keys, default=None):
    """按顺序取第一个非空值（`""`/`[]`/`{}`/None 都算没写）。"""
    for key in keys:
        value = (data or {}).get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _as_argv(value) -> list:
    """命令形态归一：字符串按 shell 规则拆，list 原样，dict 取 argv 类字段。"""
    if isinstance(value, str):
        return shlex.split(value)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if isinstance(value, dict):
        for key in ("argv", "cmd", "command", "entry", "run"):
            if value.get(key) not in (None, "", [], {}):
                return _as_argv(value[key])
    return []


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(items) -> list:
    out, seen = [], set()
    for item in items or []:
        text = str(item or "")
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _workspace_path(workspace) -> Path | None:
    if not workspace:
        return None
    path = Path(str(workspace)).expanduser()
    return path if path.is_dir() else None


def load_task_json(workspace=None, *, path=None) -> tuple[dict, str]:
    """读 `<workspace>/task.json`（或显式 path）。读不到返回 ({}, "")，不抛。"""
    target = None
    if path:
        target = Path(str(path)).expanduser()
    elif workspace:
        base = Path(str(workspace)).expanduser()
        target = base / "task.json" if base.is_dir() else base
    if target is None or not target.is_file():
        return {}, ""
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, str(target)
    return (dict(doc) if isinstance(doc, dict) else {}), str(target)


def _hex64(value: str) -> str:
    text = _text(value).lower()
    return text if (len(text) == 64 and
                    all(char in "0123456789abcdef" for char in text)) else ""


def _as_text_list(value) -> list:
    """镜像候选归一：字符串 / 列表 / `{"image": ...}` 都变成字符串列表。"""
    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        return [_text(value)] if _text(value) else []
    if isinstance(value, dict):
        for key in ("image", "name", "ref", "images"):
            if value.get(key) not in (None, "", [], {}):
                return _as_text_list(value[key])
        return []
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_as_text_list(item))
        return out
    return [_text(value)] if _text(value) else []


def load_smoke_config(workspace=None, *, path=None) -> tuple[dict, str]:
    """读 `<workspace>/smoke.json`（或显式 path）。

    这是**追加**配置：`task.json` 的历史语义字段不动，缺的执行事实写在这里。
    读不到返回 `({}, "")`；文件存在但读不动/不是 JSON 对象 → `SpecError`
    （配置坏了要立刻看见，不能当成“没配”继续跑）。
    """
    target = None
    if path:
        target = Path(str(path)).expanduser()
    elif workspace:
        base = Path(str(workspace)).expanduser()
        target = base / SMOKE_FILENAME if base.is_dir() else base
    if target is None or not target.is_file():
        return {}, ""
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SpecError(f"smoke config unreadable: {target} ({exc})") from exc
    if not isinstance(doc, dict):
        raise SpecError(f"smoke config must be a JSON object: {target}")
    return dict(doc), str(target)


def _normalize_smoke(doc: dict, bench: str, warnings: list) -> dict:
    """把 smoke.json 归一成 `{runner, images, input_sha256}`（只认自己的键）。"""
    schema = _text(doc.get("schema"))
    if schema and schema != SMOKE_SCHEMA:
        raise SpecError(
            f"smoke config schema must be {SMOKE_SCHEMA!r}: {schema!r}")
    declared_bench = _text(doc.get("benchmark")).lower()
    if declared_bench and declared_bench != bench:
        raise SpecError(
            f"smoke config benchmark {declared_bench!r} != task benchmark "
            f"{bench!r}")
    unknown = sorted(str(key) for key in set(doc) - SMOKE_KEYS)
    if unknown:
        warnings.append("smoke config unknown keys ignored: " + ",".join(unknown))

    runner: dict = {}
    cmd = _as_argv(_first(doc, ("harness_cmd", "harness", "cmd", "command",
                               "entry", "entry_point")))
    if cmd:
        runner["harness_cmd"] = [str(item) for item in cmd]
    raw_input = _first(doc, ("input_path", "input_file", "input"))
    if isinstance(raw_input, dict):
        raw_input = _first(raw_input, ("path", "file"))
    if _text(raw_input):
        runner["input_path"] = _text(raw_input)
    expected_sha = _text(doc.get("input_sha256"))
    if expected_sha:
        if not _hex64(expected_sha):
            raise SpecError(
                f"smoke config input_sha256 must be 64 lowercase hex: "
                f"{expected_sha!r}")
        runner["input_sha256"] = _hex64(expected_sha)
    docker = _text(doc.get("docker"))
    if docker:
        runner["docker"] = docker

    images: dict = {side: [] for side in IMAGE_SIDES}
    declared_images = doc.get("images")
    if declared_images not in (None, "", [], {}):
        if not isinstance(declared_images, dict):
            raise SpecError("smoke config images must be an object of "
                            "{vul: [...], fix: [...]}")
        for side in IMAGE_SIDES:
            images[side] = _as_text_list(declared_images.get(side)
                                         or declared_images.get(f"image_{side}"))
        unknown_sides = sorted(str(key) for key in set(declared_images)
                               - set(IMAGE_SIDES)
                               - {f"image_{side}" for side in IMAGE_SIDES})
        if unknown_sides:
            warnings.append("smoke config images: unknown sides ignored: "
                            + ",".join(unknown_sides))
    for key, side in (("image_vul", "vul"), ("image_fix", "fix")):
        images[side] = _dedupe(images[side] + _as_text_list(doc.get(key)))
    images = {side: _dedupe(values) for side, values in images.items()}
    return {"runner": runner, "images": images,
            "input_sha256": _hex64(expected_sha)}


#: 命令/输入的别名 → 规范键：合并时就归一，避免“高优先级层的别名被低优先级层
#: 的另一个别名压住”（例如 smoke 的 harness_cmd 盖掉 overrides 的 cmd）
CANONICAL_KEYS = {
    "harness": "harness_cmd", "entry": "harness_cmd",
    "entry_point": "harness_cmd", "cmd": "harness_cmd",
    "command": "harness_cmd",
    "input_file": "input_path", "input": "input_path",
}


def _canonical_key(key: str, bench: str) -> str:
    if bench == "cybergym":
        return CANONICAL_KEYS.get(key, key)
    return key


def _merge(metadata, task_json, overrides, bench: str, *,
           smoke=None) -> tuple[dict, dict]:
    """合并事实源：task.json < metadata < smoke < 显式覆盖；记录每个键的来源。"""
    allowed = set(RUNNER_KEYS.get(bench, ())) | {"benchmark", "task_id",
                                                 "case_id"}
    merged: dict = {}
    sources: dict = {}
    layers = [("task_json", task_json), ("metadata", metadata),
              ("smoke", smoke)]
    for name, doc in layers:
        if not isinstance(doc, dict):
            continue
        for key, value in doc.items():
            if value in (None, "", [], {}):
                continue
            if name == "smoke" and str(key) not in SMOKE_RUNNER_KEYS:
                continue
            canon = _canonical_key(str(key), bench)
            merged[canon] = value
            sources[canon] = name
    for key, value in dict(overrides or {}).items():
        if value in (None, "", [], {}):
            continue
        if key not in allowed and _canonical_key(str(key), bench) not in allowed:
            continue
        canon = _canonical_key(str(key), bench)
        merged[canon] = value
        sources[canon] = "overrides"
    return merged, sources


def _task_info(value, workspace) -> dict:
    """`task_info` 可以是 dict、JSON 文本、JSON/任务文件路径，或 `host:port`。"""
    if isinstance(value, dict):
        return dict(value)
    text = _text(value)
    if not text:
        return {}
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return dict(doc) if isinstance(doc, dict) else {}
    candidate = Path(text).expanduser()
    if not candidate.is_absolute() and workspace:
        candidate = Path(str(workspace)).expanduser() / candidate
    if candidate.is_file():
        try:
            doc = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return dict(doc) if isinstance(doc, dict) else {}
    host, sep, port = text.partition(":")
    if sep and _as_int(port) is not None:
        return {"host": host, "port": port}
    return {"host": text} if text else {}


# ------------------------------------------------------------------ 本机探测
def _run_probe(argv, timeout: float, *, limit: int | None = 4000) -> tuple:
    """跑一条探测命令，返回 (returncode|None, stdout, stderr)。不抛。

    `limit=None` 保留完整 stdout（`docker image inspect` 的 JSON 超过 4KB，
    截断后不能解析——镜像 digest 就靠它）。
    """
    try:
        proc = subprocess.run(
            [str(item) for item in argv], capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=max(0.1, float(timeout)),
            errors="replace")
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except OSError as exc:
        return 126, "", f"{type(exc).__name__}: {exc}"
    out = proc.stdout or ""
    err = proc.stderr or ""
    if limit is not None:
        out, err = out[-limit:], err[-limit:]
    return proc.returncode, out, err


def docker_path(docker: str = DEFAULT_DOCKER) -> str:
    """docker 可执行文件的位置；不存在返回空串（不抛）。"""
    name = _text(docker) or DEFAULT_DOCKER
    found = shutil.which(name)
    if found:
        return found
    candidate = Path(name).expanduser()
    return str(candidate) if candidate.is_file() else ""


def image_probe(docker: str = DEFAULT_DOCKER, image: str = "",
                *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> tuple[str, str]:
    """本机镜像状态：present / missing / unavailable（daemon 连不上）。"""
    name = _text(docker) or DEFAULT_DOCKER
    target = _text(image)
    if not target:
        return "missing", "image not declared"
    binary = docker_path(name)
    if not binary:
        return "unavailable", f"{name} not found"
    code, out, err = _run_probe([binary, "image", "inspect", target], timeout)
    if code == 0:
        return "present", ""
    blob = f"{err}\n{out}".strip().lower()
    if code is None:
        return "unavailable", "docker image inspect timed out"
    if any(hint in blob for hint in DAEMON_HINTS):
        return "unavailable", blob[:300]
    return "missing", (blob[:300] or f"exit {code}")


def image_facts(docker: str = DEFAULT_DOCKER, image: str = "",
                *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> dict:
    """镜像状态 + 审计字段（Id/RepoDigests/Created/Cmd）。

    `state` 与 [image_probe] 同词表；`digest` 取镜像内容地址（`Id`，形如
    `sha256:...`），`repo_digests` 原样保留 `repo@sha256:...`，smoke 证据里
    必须能回答“这次到底跑的是哪一个构建”。解析失败只少字段，不改 `state`。
    """
    target = _text(image)
    state, detail = image_probe(docker, target, timeout=timeout)
    facts = {"image": target, "state": state, "detail": detail,
             "image_id": "", "digest": "", "repo_digests": [],
             "created": "", "working_dir": "", "cmd": []}
    if state != "present":
        return facts
    binary = docker_path(_text(docker) or DEFAULT_DOCKER)
    if not binary:
        return facts
    code, out, _err = _run_probe([binary, "image", "inspect", target], timeout,
                                 limit=None)
    if code != 0:
        return facts
    try:
        doc = json.loads(out)
    except json.JSONDecodeError:
        return facts
    entry = doc[0] if isinstance(doc, list) and doc else doc
    if not isinstance(entry, dict):
        return facts
    config = entry.get("Config") if isinstance(entry.get("Config"), dict) else {}
    facts["image_id"] = _text(entry.get("Id"))
    facts["digest"] = facts["image_id"]
    facts["repo_digests"] = [str(item) for item in
                             _as_text_list(entry.get("RepoDigests"))]
    facts["created"] = _text(entry.get("Created"))
    facts["working_dir"] = _text(config.get("WorkingDir"))
    facts["cmd"] = _as_argv(config.get("Cmd"))
    return facts


def tcp_probe(host: str, port, *, timeout: float = 1.0) -> tuple[bool, str]:
    """TCP 能不能连上（ExploitGym 官方 socket 的可用性）。"""
    number = _as_int(port)
    if not _text(host) or number is None:
        return False, "host/port not declared"
    try:
        with socket.create_connection((_text(host), number),
                                      timeout=max(0.1, float(timeout))) as sock:
            sock.settimeout(max(0.1, float(timeout)))
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, f"{_text(host)}:{number} connectable"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """探测不跟跳转：3xx 原样记账。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_probe(url: str, *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> tuple[bool, str]:
    """GET 一次（禁代理、不跟跳转），只回答“这个 URL 现在能不能回话”。"""
    text = _text(url)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, f"unsupported url: {text!r}"
    request = urllib.request.Request(
        text, method="GET", headers={"User-Agent": "vulnmap-runner-spec"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        _NoRedirect())
    try:
        with opener.open(request, timeout=max(0.1, float(timeout))) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            try:
                resp.read(4096)
            except Exception:                       # noqa: BLE001 - 读不完不影响可达性
                pass
    except urllib.error.HTTPError as exc:           # 4xx/5xx 说明服务在
        return True, f"HTTP {int(exc.code)}"
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return False, "timeout"
        return False, f"{type(reason).__name__}: {reason}"
    except (socket.timeout, TimeoutError):
        return False, "timeout"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, f"HTTP {status or 200}"


# ------------------------------------------------------------------ 各 benchmark
def _cybergym(data: dict, *, workspace: Path | None, docker: str,
              probe: bool, probe_timeout: float, spec: dict, missing: list,
              blockers: list, warnings: list, notes: list, probes: list,
              sources: dict) -> None:
    image_vul = _text(_first(data, ("image_vul", "vul_image")))
    image_fix = _text(_first(data, ("image_fix", "fix_image")))
    cmd = _as_argv(_first(data, ("harness_cmd", "harness", "entry",
                                 "entry_point", "cmd", "command")))
    smoke = data.get("_smoke") or {}
    smoke_images = (smoke.get("images") or {}) if isinstance(smoke, dict) else {}
    expected_sha = _hex64(_text(_first(data, ("input_sha256",))))

    raw_input = _first(data, ("input_path", "input_file", "input"))
    if isinstance(raw_input, dict):
        raw_input = _first(raw_input, ("path", "file"))
    input_path = _text(raw_input)
    if input_path and workspace is not None and not Path(input_path).is_absolute():
        candidate = workspace / input_path
        if candidate.is_file():
            input_path = str(candidate)
            sources["input_path"] = f"workspace:{sources.get('input_path', '')}"
    docker_bin = _text(docker) or DEFAULT_DOCKER

    # ---- 镜像：声明值 + smoke.json 里的本地候选（别名不覆盖声明，只兜底）
    resolved: dict = {}
    for side, key, image in (("vul", "image_vul", image_vul),
                             ("fix", "image_fix", image_fix)):
        candidates = _dedupe(_as_text_list([image])
                             + _as_text_list(smoke_images.get(side)))
        resolved[side] = {"declared": image, "candidates": candidates,
                          "resolved": (candidates[0] if candidates else ""),
                          "state": "declared" if candidates else "missing",
                          "detail": "", "image_id": "", "digest": "",
                          "repo_digests": []}
        if candidates:
            spec[key] = candidates[0]
        else:
            missing.append(key)
    if cmd:
        spec["cmd"] = [str(item) for item in cmd]
    else:
        missing.append("cmd")

    # ---- 判据输入：必须在盘上、且与声明的 sha256 一致（否则没有可信输入）
    input_actual = ""
    if input_path:
        path = Path(input_path).expanduser()
        if path.is_file():
            input_actual = sha256(path.read_bytes()).hexdigest()
            spec["input_path"] = str(path)
            spec["input_sha256"] = input_actual
            if expected_sha and expected_sha != input_actual:
                blockers.append(
                    f"input_sha_mismatch:{expected_sha[:12]}!={input_actual[:12]}")
                warnings.append(
                    f"smoke.json 声明的 input_sha256={expected_sha} 与实际文件"
                    f" {input_actual} 不符：先确认是不是同一份 PoC")
        else:
            blockers.append(f"input_not_found:{input_path}")
            warnings.append(
                f"declared input not on disk: {input_path}（不挂载、不执行）")
    else:
        warnings.append(
            "input_path not declared: 两侧无法声明同一输入"
            "（verify 会在判据里落 input_not_recorded）")
    spec["docker"] = docker_bin

    if missing:
        blockers.append("runner_not_configured:" + ",".join(missing))

    if not probe:
        spec["images"] = resolved
        return
    binary = docker_path(docker_bin)
    probes.append({"name": "docker", "target": docker_bin,
                   "ok": bool(binary), "detail": binary or "not found"})
    if not binary:
        blockers.append(f"docker_unavailable:{docker_bin}")
        spec["images"] = resolved
        return
    for side, key in (("vul", "image_vul"), ("fix", "image_fix")):
        info = resolved[side]
        if not info["candidates"]:
            continue
        facts = None
        chosen = info["candidates"][0]
        for candidate in info["candidates"]:
            facts = image_facts(binary, candidate, timeout=probe_timeout)
            if facts["state"] == "present":
                chosen = candidate
                break
        facts = facts or {"state": "missing", "detail": "no candidate"}
        info.update(resolved=chosen, state=facts.get("state", "missing"),
                    detail=facts.get("detail", ""),
                    image_id=facts.get("image_id", ""),
                    digest=facts.get("digest", ""),
                    repo_digests=list(facts.get("repo_digests") or []))
        probes.append({"name": key, "target": chosen,
                       "ok": info["state"] == "present",
                       "detail": info["state"] if not info["detail"]
                       else f"{info['state']}: {info['detail']}"})
        if info["state"] == "present":
            spec[key] = chosen
            if info["declared"] and chosen != info["declared"]:
                notes.append(
                    f"{key}: 声明 {info['declared']} 本机不存在，改用本地别名 "
                    f"{chosen}（digest {info['digest'] or 'unknown'}）")
        elif info["state"] == "missing":
            blockers.append(f"image_not_found:{info['declared'] or chosen}")
        else:
            blockers.append(f"docker_unavailable:{docker_bin}")
    if expected_sha and input_actual and expected_sha != input_actual:
        notes.append("input_sha256 与 smoke.json 声明不符：不执行 runner")
    spec["images"] = resolved
    notes.append("镜像内命令来自 harness_cmd/entry；未声明时 runner 自己会拒绝执行")


def _exploitgym(data: dict, *, workspace: Path | None, docker: str,
                probe: bool, probe_timeout: float, spec: dict, missing: list,
                blockers: list, warnings: list, notes: list, probes: list,
                sources: dict) -> None:
    image = _text(_first(data, ("image", "image_vul")))
    image_mode = _text(_first(data, ("image_mode", "mode")))
    info = _task_info(_first(data, ("task_info", "taskInfo", "taskinfo")),
                      workspace)

    host = _text(_first(info, ("host", "target_host", "hostname")))
    port = _first(info, ("port", "target_port"))
    address = _text(_first(info, ("address", "addr", "target", "endpoint",
                                  "url")))
    if address and (not host or _as_int(port) is None):
        parsed = urllib.parse.urlsplit(
            address if "//" in address else f"//{address}")
        host = host or _text(parsed.hostname)
        if _as_int(port) is None:
            port = parsed.port
    if not host:
        host = _text(_first(data, ("host", "target_host")))
    if _as_int(port) is None:
        port = _first(data, ("port", "target_port"))

    exploit_cmd = _as_argv(_first(info, ("exploit_cmd", "exploit", "cmd",
                                        "command", "run"))
                           or _first(data, ("exploit_cmd", "exploit_script")))
    expected = _text(_first(info, ("expected_flag", "flag", "answer"))
                     or _first(data, ("expected_flag",)))

    declared = _text(_first(info, ("transport",)) or
                     (info.get("mode")
                      if _text(info.get("mode")).lower() in SOCKET_MODES else ""))
    transport = declared.lower() or _text(_first(data, ("transport",))).lower()
    if transport not in SOCKET_MODES:
        transport = ""
    if not transport:
        if host and _as_int(port) is not None:
            transport = "socket"
        elif exploit_cmd:
            transport = "exploit_cmd"

    field_missing: list = []
    if image:
        spec["image"] = image
    else:
        field_missing.append("image")
    if image_mode:
        spec["image_mode"] = image_mode
    else:
        field_missing.append("mode")
    if field_missing:
        missing.extend(field_missing)
        blockers.append("runner_not_configured:" + ",".join(field_missing))

    if transport == "socket":
        number = _as_int(port)
        if not host or number is None:
            missing.extend(["host", "port"])
            blockers.append("runner_not_configured:host,port")
        else:
            spec["mode"] = "socket"
            spec["host"] = host
            spec["port"] = number
        if probe and host and number is not None:
            ok, detail = tcp_probe(host, number, timeout=min(probe_timeout, 2.0))
            probes.append({"name": "socket", "target": f"{host}:{number}",
                           "ok": ok, "detail": detail})
            if not ok:
                blockers.append(f"connection_failed:{host}:{number}")
    elif transport == "exploit_cmd":
        if not exploit_cmd:
            missing.append("exploit_cmd")
            blockers.append("runner_not_configured:exploit_cmd")
        else:
            spec["mode"] = "exploit_cmd"
            spec["exploit_cmd"] = [str(item) for item in exploit_cmd]
            if probe:
                binary = docker_path(exploit_cmd[0]) or (
                    exploit_cmd[0] if Path(str(exploit_cmd[0])).is_file() else "")
                probes.append({"name": "exploit_cmd", "target": exploit_cmd[0],
                               "ok": bool(binary), "detail": binary or "not found"})
                if not binary:
                    blockers.append(f"runner_unavailable:{exploit_cmd[0]}")
            # 命令模式的“环境”就是本地镜像：只有这时才查本机镜像
            if probe and image:
                state, detail = image_probe(_text(docker) or DEFAULT_DOCKER,
                                            image, timeout=probe_timeout)
                probes.append({"name": "image", "target": image,
                               "ok": state == "present",
                               "detail": state if not detail else
                               f"{state}: {detail}"})
                if state == "missing":
                    blockers.append(f"image_not_found:{image}")
                elif state == "unavailable":
                    blockers.append(
                        f"docker_unavailable:{_text(docker) or DEFAULT_DOCKER}")
    else:
        missing.append("exploit_target")
        blockers.append("runner_not_configured:exploit_target")
        notes.append("ExploitGym 需要 host+port（官方 socket）或 exploit_cmd"
                     "（task_info 里给 host/port/exploit_cmd）")

    if expected:
        spec["expected_flag"] = expected
    else:
        warnings.append("expected_flag not declared: 只能验 flag 形态，"
                        "不能与官方值严格比对")
    notes.append("socket 模式下 image 只做审计：镜像由 benchmark 侧启动，"
                 "不对本机镜像做存在性判断")


def _vulngym(data: dict, *, workspace: Path | None, docker: str,
             probe: bool, probe_timeout: float, spec: dict, missing: list,
             blockers: list, warnings: list, notes: list, probes: list,
             sources: dict) -> None:
    service = _text(_first(data, ("service_url", "base_url", "target_url",
                                  "url")))
    baseline = _text(_first(data, ("baseline_url", "baseline",
                                   "baseline_target")))
    patched = _text(_first(data, ("patched_url", "patched", "patched_target")))
    if not baseline:
        baseline = service
    if not patched:
        patched = service
    if not baseline:
        missing.append("baseline_url")
    if not patched:
        missing.append("patched_url")
    if missing:
        blockers.append("runner_not_configured:" + ",".join(missing))
    if baseline:
        spec["baseline_url"] = baseline
    if patched:
        spec["patched_url"] = patched
    if service and baseline == patched == service:
        notes.append(f"service_url={service} 同时用于基线/修补两侧")

    expect = _first(data, ("expect",))
    if not isinstance(expect, dict):
        expect = {}
        baseline_want = _as_int(_first(data, ("expect_baseline_status",)))
        patched_want = _first(data, ("expect_patched_status",))
        if baseline_want is not None:
            expect["baseline_status"] = baseline_want
        if patched_want not in (None, "", [], {}):
            allowed = (patched_want if isinstance(patched_want, (list, tuple))
                       else [patched_want])
            codes = [code for code in (_as_int(item) for item in allowed)
                     if code is not None]
            if codes:
                expect["patched_status_in"] = codes
    if expect:
        spec["expect"] = dict(expect)
    else:
        warnings.append("expect not declared: 只要求两侧行为有差异，"
                        "不校验方向")
    method = _text(_first(data, ("method",))) or "GET"
    spec["method"] = method.upper()

    if not probe:
        return
    for side, url in (("baseline", baseline), ("patched", patched)):
        if not url:
            continue
        ok, detail = http_probe(url, timeout=probe_timeout)
        probes.append({"name": side, "target": url, "ok": ok, "detail": detail})
        if ok:
            continue
        if detail == "timeout":
            blockers.append(f"runner_timeout:{side}")
        else:
            blockers.append(f"connection_failed:{url}")


# ------------------------------------------------------------------ 入口
def build_runner_spec(benchmark: str = "", *, metadata=None, task_json=None,
                      workspace=None, overrides=None, probe: bool = True,
                      docker: str = DEFAULT_DOCKER,
                      probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
                      smoke_config=None) -> dict:
    """从 task.json / smoke.json / metadata 生成 runner spec（纯翻译 + 本机探测）。

    - `smoke_config`：`<workspace>/smoke.json` 的 dict、路径，或省略（默认读
      `<workspace>/smoke.json`）；优先级 `overrides > smoke > metadata > task_json`，
      每个键的来源记在 `sources` 里，路径记在 `smoke_config` 字段；
    - `probe=False`：只做字段映射（离线/单测用），不碰 docker/socket/HTTP；
    - 返回值 `ready=True` 表示“字段齐全且本机可用”，可以直接喂 runner；
    - `ready=False` 时 `blockers` 里是缺口（`verify` 会落 `needs_evidence`），
      `warnings` 里是“能跑但证据会不完整”的提示（缺输入、缺 expected_flag…）。
    """
    ws = _workspace_path(workspace)
    tdoc, tpath = ({}, "")
    if isinstance(task_json, dict):
        tdoc, tpath = dict(task_json), ""
    else:
        tdoc, tpath = load_task_json(ws)

    bench = _text(benchmark).lower() or _text(tdoc.get("benchmark")).lower()
    if bench not in RUNNER_FOR:
        raise SpecError(
            f"no runner spec for benchmark {bench or 'unknown'!r} "
            f"(available: {sorted(RUNNER_FOR)})")

    spec: dict = {}
    missing: list = []
    blockers: list = []
    warnings: list = []
    notes: list = []
    probes: list = []
    runner = RUNNER_FOR[bench]

    # ---- 追加配置：smoke.json（只补执行事实，不改 task.json 的语义字段）
    smoke_doc, smoke_path = ({}, "")
    if isinstance(smoke_config, dict):
        smoke_doc = dict(smoke_config)
    elif smoke_config not in (None, ""):
        smoke_doc, smoke_path = load_smoke_config(path=smoke_config)
    else:
        smoke_doc, smoke_path = load_smoke_config(ws)
    smoke: dict = {}
    if smoke_doc:
        smoke = _normalize_smoke(smoke_doc, bench, warnings)
        for key in ("case_id", "task_id"):
            declared_value = _text(smoke_doc.get(key))
            expected_value = _text(tdoc.get(key))
            if declared_value and expected_value and declared_value != expected_value:
                warnings.append(
                    f"smoke config {key}={declared_value!r} != task.json "
                    f"{expected_value!r}")
        notes.append(f"smoke config: {smoke_path or '<inline>'}")

    data, sources = _merge(metadata, tdoc, overrides, bench,
                           smoke=smoke.get("runner") if smoke else None)
    if smoke:
        data["_smoke"] = smoke

    # docker 解析：显式参数 > 任务声明 > 默认；显式给的就是"docker"时让任务声明优先
    explicit = _text(docker)
    declared = _text(_first(data, ("docker",)))
    docker_bin = (explicit if explicit and explicit != DEFAULT_DOCKER
                  else (declared or DEFAULT_DOCKER))

    builder = {"cybergym": _cybergym, "exploitgym": _exploitgym,
               "vulngym": _vulngym}[bench]
    builder(data, workspace=ws, docker=docker_bin, probe=bool(probe),
            probe_timeout=float(probe_timeout), spec=spec, missing=missing,
            blockers=blockers, warnings=warnings, notes=notes, probes=probes,
            sources=sources)

    blockers = _dedupe(blockers)
    missing = _dedupe(missing)
    # 不变量：spec 只许产“缺口型” blocker（否则会把缺口读成负结果）
    for blocker in blockers:
        prefix = blocker.split(":", 1)[0]
        if prefix not in GAP_BLOCKERS:
            raise SpecError(f"spec blocker must be a gap blocker: {blocker!r}")
    if blockers:
        notes.append("有缺口时不执行 runner：`docker run` 对缺失镜像会以 125 退出，"
                     "那不是“vul 端崩了”，不能当判据")
    return {
        "schema": SCHEMA,
        "benchmark": bench,
        "runner": runner,
        "task_id": _text(data.get("task_id")) or _text(tdoc.get("task_id")),
        "case_id": _text(data.get("case_id")) or _text(tdoc.get("case_id")),
        "ready": not blockers,
        "status": "ready" if not blockers else "needs_evidence",
        "required": list(REQUIRED.get(bench, ())),
        "spec": spec,
        "blockers": blockers,
        "missing": missing,
        "warnings": _dedupe(warnings),
        "notes": _dedupe(notes),
        "probes": probes,
        "sources": dict(sorted(sources.items())),
        "workspace": str(ws) if ws else "",
        "task_json": tpath,
        "smoke_config": smoke_path,
        "probe": bool(probe),
    }


def summarize(doc: dict) -> dict:
    """给 CLI/smoke 用的紧凑视图（不含大字段）。"""
    return {
        "benchmark": doc.get("benchmark", ""),
        "runner": doc.get("runner", ""),
        "case_id": doc.get("case_id", ""),
        "task_id": doc.get("task_id", ""),
        "ready": bool(doc.get("ready")),
        "status": doc.get("status", ""),
        "blockers": list(doc.get("blockers") or []),
        "missing": list(doc.get("missing") or []),
        "warnings": list(doc.get("warnings") or []),
        "probes": list(doc.get("probes") or []),
    }
