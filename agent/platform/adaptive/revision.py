"""V3-007：HarnessRevision —— 实验自修改的版本事务（只增、不改、可回退）。

口径（《V3 完整升级方案》§8「实验自修改与版本事务」、§9「统一数据契约」）：

- **每次变更生成 revision**：parent、完整文件 manifest、diff、创建原因、父假设、
  工具调用、环境身份与构建/冒烟结果。revision 一旦登记就**不再改写**：
  回退是“选父 revision + 重建工作树”，不是覆盖旧文件；旧 revision 的字节永远
  留在 `revisions/<id>/` 里，且被设为只读。
- **生成 revision 不等于采纳**：构建/冒烟记录（`BuildRecord` / `SmokeRecord`）
  是独立的事实条目，可以有多条（例如回退后重跑），revision 本身不因采纳而变。
  采纳决定由 `policy` 产出、控制器落事件，写到 `adoptions.jsonl`。
- **身份可复算**：`revision_id` 由（parent + manifest + 原因 + 假设 + 工具 +
  环境 + 回退目标）算出；`HarnessRevision.from_dict()` 会重算，改一个字节就
  对不上（`revision_tampered`）。
- **失效是显式的**：revision 创建时带 `invalidations`（只允许来自
  `contracts.CHANGE_INVALIDATIONS["harness"]`），进 `RevisionStore` 的待消费
  集合，控制器必须 `consume_invalidations()` 并逐项落实（§8 表格）。
- **只描述副本**：本模块不碰目标源码、不执行任何命令；执行在 `workspace`。

本模块只做版本账本，不写裁决字段、不调 LLM。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from .contracts import (CHANGE_INVALIDATIONS, INVALIDATION_SCOPES, digest_of)

SCHEMA = "vulnmap.adaptive.harness_revision.v1"
SCHEMA_VERSION = 1
BUILD_SCHEMA = "vulnmap.adaptive.harness_build.v1"
SMOKE_SCHEMA = "vulnmap.adaptive.harness_smoke.v1"
#: V3 第 2 周：配置效果（计划版本 vs 实际加载版本）的账本条目
CONFIG_EFFECT_SCHEMA = "vulnmap.adaptive.config_effect.v1"
#: 配置效果三值：`effective` / `not_effective` 都是**观测到的**，
#: `unknown` 只表示"没有可用的实际加载回报"，绝不回填计划版本
CONFIG_STATUSES = ("effective", "not_effective", "unknown")

REVISION_ID = re.compile(r"^hr-[0-9a-f]{16}$")
SAFE_REL = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/ -]{0,255}$")

#: 构建状态：`ok` 只代表“构建命令返回 0”。
BUILD_STATUSES = ("ok", "failed", "setup_error", "timeout")
#: 冒烟状态：`passed` 只代表“冒烟命令返回 0”；`harness_error` 是 harness 自己崩了，
#: 不是目标行为——它永远不能升格成漏洞证据（policy 的假阳性门）。
SMOKE_STATUSES = ("passed", "failed", "harness_error", "setup_error", "timeout")

#: harness 变更必然失效的域（与 §8 表格同一口径；工具表也从这里派生）
HARNESS_INVALIDATIONS = tuple(CHANGE_INVALIDATIONS["harness"])

#: manifest 里保留的字段（写入时裁剪，避免把任意元数据塞进盘）
FILE_KEYS = ("path", "sha256", "size", "mode")


class RevisionError(RuntimeError):
    """revision 账本不可用/被篡改/非法回退：宁可失败，也不留半截状态。"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relpath(value: str) -> str:
    """工作区内的相对路径：拒绝绝对路径、`..`、反斜杠与控制字符。"""
    raw = str(value or "").strip()
    if not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw:
        raise RevisionError(f"unsafe path: {value!r}")
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise RevisionError(f"unsafe path: {value!r}")
    if not SAFE_REL.match("/".join(parts)):
        raise RevisionError(f"unsafe path: {value!r}")
    return "/".join(parts)


# ====================================================================== 文件项
@dataclass(frozen=True)
class FileEntry:
    """manifest 的一行：路径 + 内容哈希 + 大小 + 权限位。"""

    path: str
    sha256: str
    size: int = 0
    mode: int = 0o444

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", safe_relpath(self.path))
        digest = str(self.sha256 or "").lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise RevisionError(f"FileEntry.sha256 非法：{self.sha256!r}")
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "size", int(self.size or 0))
        object.__setattr__(self, "mode", int(self.mode or 0o444))

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256,
                "size": int(self.size), "mode": int(self.mode)}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "FileEntry":
        return cls(path=str(doc.get("path") or ""),
                   sha256=str(doc.get("sha256") or ""),
                   size=int(doc.get("size") or 0),
                   mode=int(doc.get("mode") or 0o444))


def manifest_of(files: Mapping[str, bytes], *, mode: int = 0o444
                ) -> tuple[FileEntry, ...]:
    """由 {相对路径: 字节} 生成排序后的 manifest。"""
    normalized = {path: (data.encode("utf-8") if isinstance(data, str)
                         else bytes(data))
                  for path, data in files.items()}
    entries = [FileEntry(path=safe_relpath(path),
                         sha256=sha256_bytes(payload),
                         size=len(payload), mode=mode)
               for path, payload in normalized.items()]
    return tuple(sorted(entries, key=lambda e: e.path))


def manifest_sha256(manifest: Iterable[FileEntry]) -> str:
    return digest_of([entry.to_dict() for entry in manifest])


def manifest_paths(manifest: Iterable[FileEntry]) -> tuple[str, ...]:
    return tuple(entry.path for entry in manifest)


# ====================================================================== revision
@dataclass(frozen=True)
class HarnessRevision:
    """一次 harness/生成器副本变更的不可变记录（内容即身份）。"""

    revision_id: str = ""
    parent_id: str = ""
    manifest: tuple[FileEntry, ...] = ()
    diff: str = ""
    reason: str = ""
    hypothesis_id: str = ""
    action_id: str = ""
    tool: str = ""
    environment: Mapping = field(default_factory=dict)
    reverted_to: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        manifest = tuple(self.manifest or ())
        paths = [entry.path for entry in manifest]
        if len(set(paths)) != len(paths):
            raise RevisionError("manifest 有重复路径")
        if list(paths) != sorted(paths):
            manifest = tuple(sorted(manifest, key=lambda e: e.path))
        parent = str(self.parent_id or "")
        if parent and not REVISION_ID.match(parent):
            raise RevisionError(f"parent_id 非法：{parent!r}")
        reverted = str(self.reverted_to or "")
        if reverted and not REVISION_ID.match(reverted):
            raise RevisionError(f"reverted_to 非法：{reverted!r}")
        if not str(self.reason or "").strip():
            raise RevisionError("revision.reason 不能为空（无原因的变更不可审计）")
        env = {str(k): str(v) for k, v in dict(self.environment or {}).items()}
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "parent_id", parent)
        object.__setattr__(self, "reverted_to", reverted)
        object.__setattr__(self, "reason", str(self.reason))
        object.__setattr__(self, "hypothesis_id", str(self.hypothesis_id or ""))
        object.__setattr__(self, "action_id", str(self.action_id or ""))
        object.__setattr__(self, "tool", str(self.tool or ""))
        object.__setattr__(self, "environment", env)
        if parent and parent == str(self.revision_id or ""):
            raise RevisionError("revision 不能以自己为父")
        computed = self.compute_id()
        claimed = str(self.revision_id or "")
        if claimed and claimed != computed:
            raise RevisionError(
                "revision_tampered: revision_id 与内容不一致（旧 revision 不可改写）")
        object.__setattr__(self, "revision_id", computed)
        if not self.created_at:
            object.__setattr__(self, "created_at", now())

    # ---- 身份 ----
    def identity_doc(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "parent_id": self.parent_id,
            "manifest": [entry.to_dict() for entry in self.manifest],
            "reason": self.reason,
            "hypothesis_id": self.hypothesis_id,
            "action_id": self.action_id,
            "tool": self.tool,
            "environment": dict(self.environment),
            "reverted_to": self.reverted_to,
        }

    def compute_id(self) -> str:
        return "hr-" + digest_of(self.identity_doc())[:16]

    # ---- 读取 ----
    @property
    def manifest_sha256(self) -> str:
        return manifest_sha256(self.manifest)

    @property
    def diff_sha256(self) -> str:
        return sha256_bytes(self.diff.encode("utf-8"))

    @property
    def files(self) -> tuple[str, ...]:
        return manifest_paths(self.manifest)

    @property
    def is_root(self) -> bool:
        return not self.parent_id

    @property
    def is_revert(self) -> bool:
        return bool(self.reverted_to)

    @property
    def invalidations(self) -> tuple[str, ...]:
        """harness 副本变更必然失效的域（§8：build/smoke/覆盖基线/语料复验）。"""
        return HARNESS_INVALIDATIONS

    @property
    def active_config_sha256(self) -> str:
        """本 revision 携带的配置版本（`environment` 里的那一版；没有就是 `""`）。

        计划版本只能从 revision 里取：写进 `environment` 才叫"这一版 revision 用的
        是这个配置"，否则"配置改了"与"配置被这个 revision 用着"会混成一件事。
        """
        return str(self.environment.get("active_config_sha256") or "")

    @property
    def baseline_config_sha256(self) -> str:
        """任务基线（origin）那时的配置版本；没有配置面就是 `""`。"""
        return str(self.environment.get("baseline_config_sha256") or "")

    def file(self, path: str) -> FileEntry | None:
        wanted = safe_relpath(path)
        for entry in self.manifest:
            if entry.path == wanted:
                return entry
        return None

    def changed_against(self, other: "HarnessRevision") -> tuple[str, ...]:
        """相对另一个 revision 新增/修改/删除的路径（排序）。"""
        mine = {entry.path: entry.sha256 for entry in self.manifest}
        theirs = {entry.path: entry.sha256 for entry in other.manifest}
        return tuple(sorted(path for path in set(mine) | set(theirs)
                            if mine.get(path) != theirs.get(path)))

    def to_dict(self) -> dict:
        return {
            **self.identity_doc(),
            "revision_id": self.revision_id,
            "manifest_sha256": self.manifest_sha256,
            "diff": self.diff,
            "diff_sha256": self.diff_sha256,
            "invalidations": list(self.invalidations),
            "created_at": self.created_at,
            # 配置身份直接从 environment 派发（不另存一份，避免两处不一致）
            "active_config_sha256": self.active_config_sha256,
            "baseline_config_sha256": self.baseline_config_sha256,
        }

    @classmethod
    def create(cls, *, manifest: Iterable[FileEntry], diff: str = "",
               reason: str, parent: "HarnessRevision | None" = None,
               hypothesis_id: str = "", action_id: str = "", tool: str = "",
               environment: Mapping | None = None,
               reverted_to: str = "") -> "HarnessRevision":
        return cls(parent_id=(parent.revision_id if parent else ""),
                   manifest=tuple(manifest or ()), diff=str(diff or ""),
                   reason=reason, hypothesis_id=hypothesis_id,
                   action_id=action_id, tool=tool,
                   environment=dict(environment or {}),
                   reverted_to=str(reverted_to or ""))

    @classmethod
    def from_dict(cls, doc: Mapping) -> "HarnessRevision":
        if not isinstance(doc, Mapping):
            raise RevisionError("HarnessRevision must be a mapping")
        try:
            manifest = tuple(FileEntry.from_dict(item)
                             for item in (doc.get("manifest") or ()))
            revision = cls(
                revision_id=str(doc.get("revision_id") or ""),
                parent_id=str(doc.get("parent_id") or ""),
                manifest=manifest,
                diff=str(doc.get("diff") or ""),
                reason=str(doc.get("reason") or ""),
                hypothesis_id=str(doc.get("hypothesis_id") or ""),
                action_id=str(doc.get("action_id") or ""),
                tool=str(doc.get("tool") or ""),
                environment=dict(doc.get("environment") or {}),
                reverted_to=str(doc.get("reverted_to") or ""),
                created_at=str(doc.get("created_at") or ""),
            )
        except RevisionError:
            raise
        except (TypeError, ValueError) as exc:
            raise RevisionError(f"revision 文档非法：{exc}") from exc
        return revision


# ====================================================================== 执行记录
def build_identity(*, manifest_sha: str, command: Iterable[str],
                   toolchain: str = "", env_digest: str = "") -> str:
    """构建身份：manifest + 命令 + toolchain + 环境摘要（缓存键的最小集合）。"""
    return "bd-" + digest_of({
        "manifest_sha256": str(manifest_sha or ""),
        "command": [str(c) for c in (command or ())],
        "toolchain": str(toolchain or ""),
        "env_digest": str(env_digest or ""),
    })[:16]


@dataclass(frozen=True)
class BuildRecord:
    """一次真实构建的结果（可多条；revision 不因构建而改写）。"""

    build_id: str
    revision_id: str
    status: str
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    duration: float = 0.0
    log_path: str = ""
    log_sha256: str = ""
    log_bytes: int = 0
    truncated: bool = False
    toolchain: str = ""
    workdir: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    schema: str = BUILD_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in BUILD_STATUSES:
            raise RevisionError(f"unknown build status: {self.status!r}")
        if not REVISION_ID.match(str(self.revision_id or "")):
            raise RevisionError(f"build.revision_id 非法：{self.revision_id!r}")
        if not str(self.build_id or "").startswith("bd-"):
            raise RevisionError(f"build.build_id 非法：{self.build_id!r}")
        object.__setattr__(self, "command", tuple(str(c) for c in self.command))
        object.__setattr__(self, "duration", float(self.duration or 0.0))

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "build_id": self.build_id, "revision_id": self.revision_id,
            "status": self.status, "ok": self.ok,
            "command": list(self.command), "exit_code": self.exit_code,
            "duration": self.duration, "log_path": self.log_path,
            "log_sha256": self.log_sha256, "log_bytes": int(self.log_bytes),
            "truncated": bool(self.truncated), "toolchain": self.toolchain,
            "workdir": self.workdir,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "BuildRecord":
        return cls(
            build_id=str(doc.get("build_id") or ""),
            revision_id=str(doc.get("revision_id") or ""),
            status=str(doc.get("status") or ""),
            command=tuple(doc.get("command") or ()),
            exit_code=doc.get("exit_code"),
            duration=float(doc.get("duration") or 0.0),
            log_path=str(doc.get("log_path") or ""),
            log_sha256=str(doc.get("log_sha256") or ""),
            log_bytes=int(doc.get("log_bytes") or 0),
            truncated=bool(doc.get("truncated")),
            toolchain=str(doc.get("toolchain") or ""),
            workdir=str(doc.get("workdir") or ""),
            started_at=str(doc.get("started_at") or ""),
            finished_at=str(doc.get("finished_at") or ""),
            error=str(doc.get("error") or ""),
        )


@dataclass(frozen=True)
class SmokeRecord:
    """一次真实冒烟的结果；`kind=harness_error` 与“目标行为不符”严格分开。"""

    smoke_id: str
    revision_id: str
    build_id: str
    status: str
    exit_code: int | None = None
    duration: float = 0.0
    log_path: str = ""
    log_sha256: str = ""
    log_bytes: int = 0
    truncated: bool = False
    kind: str = ""
    detail: str = ""
    started_at: str = ""
    finished_at: str = ""
    schema: str = SMOKE_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in SMOKE_STATUSES:
            raise RevisionError(f"unknown smoke status: {self.status!r}")
        if not REVISION_ID.match(str(self.revision_id or "")):
            raise RevisionError(f"smoke.revision_id 非法：{self.revision_id!r}")
        object.__setattr__(self, "duration", float(self.duration or 0.0))

    @property
    def ok(self) -> bool:
        return self.status == "passed"

    @property
    def harness_failed(self) -> bool:
        """harness 自身崩了：只能让结论更弱，不能当成目标证据。"""
        return self.status == "harness_error" or self.kind == "harness_error"

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "schema_version": SCHEMA_VERSION,
            "smoke_id": self.smoke_id, "revision_id": self.revision_id,
            "build_id": self.build_id, "status": self.status, "ok": self.ok,
            "harness_failed": self.harness_failed, "exit_code": self.exit_code,
            "duration": self.duration, "log_path": self.log_path,
            "log_sha256": self.log_sha256, "log_bytes": int(self.log_bytes),
            "truncated": bool(self.truncated), "kind": self.kind,
            "detail": self.detail, "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "SmokeRecord":
        return cls(
            smoke_id=str(doc.get("smoke_id") or ""),
            revision_id=str(doc.get("revision_id") or ""),
            build_id=str(doc.get("build_id") or ""),
            status=str(doc.get("status") or ""),
            exit_code=doc.get("exit_code"),
            duration=float(doc.get("duration") or 0.0),
            log_path=str(doc.get("log_path") or ""),
            log_sha256=str(doc.get("log_sha256") or ""),
            log_bytes=int(doc.get("log_bytes") or 0),
            truncated=bool(doc.get("truncated")),
            kind=str(doc.get("kind") or ""),
            detail=str(doc.get("detail") or ""),
            started_at=str(doc.get("started_at") or ""),
            finished_at=str(doc.get("finished_at") or ""),
        )


# ====================================================================== 配置效果
def config_sha(value) -> str:
    """只认 64 位十六进制哈希；空/半截/非哈希一律 `""`（= 没观测到这一版）。"""
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        return ""
    return text


@dataclass(frozen=True)
class ConfigEffectRecord:
    """一次"配置效果"的账本条目：计划版本 vs **执行器实际加载**的版本。

    写不进去的假话不该存在于账本里，所以三个状态各自带不变量（§4）：

    | status | 要求 |
    |---|---|
    | `effective` | planned 与 loaded 都是 64 位 hex **且相等** |
    | `not_effective` | planned 与 loaded 都是 64 位 hex **且不相等** |
    | `unknown` | 至少一边没有可用的 64 位 hex（`loaded` 允许为空） |

    `unknown` 不是"没生效"，是"没有实际加载的回报"；`adoptable` 只认 `effective`——
    "配置改了"与"配置生效了"是两件事。
    """

    effect_id: str = ""
    revision_id: str = ""
    planned_sha256: str = ""
    loaded_sha256: str = ""
    status: str = "unknown"
    source: str = ""
    execution_id: str = ""
    round_no: int = 0
    reason: str = ""
    created_at: str = ""
    schema: str = CONFIG_EFFECT_SCHEMA

    def __post_init__(self) -> None:
        status = str(self.status or "")
        if status not in CONFIG_STATUSES:
            raise RevisionError(f"unknown config status: {status!r}")
        if not REVISION_ID.match(str(self.revision_id or "")):
            raise RevisionError(
                f"config_effect.revision_id 非法：{self.revision_id!r}")
        planned = config_sha(self.planned_sha256)
        loaded = config_sha(self.loaded_sha256)
        for name, raw, norm in (("planned_sha256", self.planned_sha256, planned),
                                ("loaded_sha256", self.loaded_sha256, loaded)):
            if str(raw or "").strip() and not norm:
                raise RevisionError(
                    f"config_effect.{name} 非法（必须是 64 位 hex）：{raw!r}")
        if status == "effective" and not (planned and loaded and planned == loaded):
            raise RevisionError(
                "config_effect.effective 需要 planned==loaded 且都是 64 位 hex")
        if status == "not_effective" and not (planned and loaded
                                              and planned != loaded):
            raise RevisionError(
                "config_effect.not_effective 需要 planned!=loaded 且都是 64 位 hex")
        if status == "unknown" and planned and loaded:
            # 两版都拿到了就一定能判定，写 unknown 等于把"能算出来的"降级成"不知道"
            raise RevisionError(
                "config_effect.unknown 不能同时带 planned 与 loaded（那样就能判定了）")
        round_no = int(self.round_no or 0)
        if round_no < 0:
            raise RevisionError(f"config_effect.round_no 非法：{self.round_no!r}")
        object.__setattr__(self, "planned_sha256", planned)
        object.__setattr__(self, "loaded_sha256", loaded)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "source", str(self.source or ""))
        object.__setattr__(self, "execution_id", str(self.execution_id or ""))
        object.__setattr__(self, "round_no", round_no)
        object.__setattr__(self, "reason", str(self.reason or ""))
        computed = self.compute_id()
        claimed = str(self.effect_id or "")
        if claimed and claimed != computed:
            raise RevisionError(
                "config_effect_tampered: effect_id 与内容不一致（旧账不可改写）")
        object.__setattr__(self, "effect_id", computed)
        if not self.created_at:
            object.__setattr__(self, "created_at", now())

    # ---- 身份 ----
    def identity_doc(self) -> dict:
        return {
            "schema": CONFIG_EFFECT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "revision_id": self.revision_id,
            "planned_sha256": self.planned_sha256,
            "loaded_sha256": self.loaded_sha256,
            "status": self.status,
            "source": self.source,
            "execution_id": self.execution_id,
            "round_no": self.round_no,
            "reason": self.reason,
        }

    def compute_id(self) -> str:
        return "ce-" + digest_of(self.identity_doc())[:16]

    # ---- 读取 ----
    @property
    def adoptable(self) -> bool:
        """只有"执行器确实加载了这一版"才可采纳；`unknown` 一律不可采纳。"""
        return self.status == "effective"

    def to_dict(self) -> dict:
        return {
            **self.identity_doc(),
            "effect_id": self.effect_id,
            "adoptable": self.adoptable,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "ConfigEffectRecord":
        if not isinstance(doc, Mapping):
            raise RevisionError("ConfigEffectRecord must be a mapping")
        try:
            return cls(
                effect_id=str(doc.get("effect_id") or ""),
                revision_id=str(doc.get("revision_id") or ""),
                planned_sha256=str(doc.get("planned_sha256") or ""),
                loaded_sha256=str(doc.get("loaded_sha256") or ""),
                status=str(doc.get("status") or ""),
                source=str(doc.get("source") or ""),
                execution_id=str(doc.get("execution_id") or ""),
                round_no=int(doc.get("round_no") or 0),
                reason=str(doc.get("reason") or ""),
                created_at=str(doc.get("created_at") or ""),
            )
        except RevisionError:
            raise
        except (TypeError, ValueError) as exc:
            raise RevisionError(f"config_effect 文档非法：{exc}") from exc


# ====================================================================== 账本
class RevisionStore:
    """任务级 revision 账本：`revisions.jsonl` 只追加，索引不重写旧记录。"""

    REVISIONS = "revisions.jsonl"
    BUILDS = "builds.jsonl"
    SMOKES = "smokes.jsonl"
    ADOPTIONS = "adoptions.jsonl"
    CONFIG_EFFECTS = "config_effects.jsonl"
    CURRENT = "current.json"

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._revisions: dict[str, HarnessRevision] = {}
        self._order: list[str] = []
        self._builds: dict[str, BuildRecord] = {}
        self._smokes: dict[str, SmokeRecord] = {}
        self._config_effects: dict[str, ConfigEffectRecord] = {}
        self._config_order: list[str] = []
        self._adoptions: list[dict] = []
        self._pending: list[str] = []
        self._load()

    # ---- 载入 ----
    def _file(self, name: str) -> Path:
        return self.root / name

    def _lines(self, name: str) -> list[dict]:
        path = self._file(name)
        if not path.exists():
            return []
        out: list[dict] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                out.append(json.loads(text))
            except json.JSONDecodeError as exc:      # pragma: no cover - 坏账本
                raise RevisionError(f"{name} 第 {len(out) + 1} 行不是合法 JSON") from exc
        return out

    def _load(self) -> None:
        for doc in self._lines(self.REVISIONS):
            revision = HarnessRevision.from_dict(doc)
            self._revisions[revision.revision_id] = revision
            self._order.append(revision.revision_id)
        for doc in self._lines(self.BUILDS):
            record = BuildRecord.from_dict(doc)
            self._builds[record.build_id] = record
        for doc in self._lines(self.SMOKES):
            record = SmokeRecord.from_dict(doc)
            self._smokes[record.smoke_id] = record
        for doc in self._lines(self.CONFIG_EFFECTS):
            effect = ConfigEffectRecord.from_dict(doc)
            self._config_effects[effect.effect_id] = effect
            self._config_order.append(effect.effect_id)
        self._adoptions = self._lines(self.ADOPTIONS)

    def _append(self, name: str, doc: Mapping) -> None:
        with self._lock:
            with self._file(name).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(doc, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    # ---- revision ----
    def add(self, revision: HarnessRevision) -> HarnessRevision:
        if not isinstance(revision, HarnessRevision):
            raise RevisionError("only HarnessRevision can be registered")
        with self._lock:
            existing = self._revisions.get(revision.revision_id)
            if existing is not None:
                if existing.to_dict() != revision.to_dict():
                    raise RevisionError(
                        "旧 revision 不可改写：同 id 不同内容")
                return existing
            if revision.parent_id and revision.parent_id not in self._revisions:
                raise RevisionError(
                    f"父 revision 不存在：{revision.parent_id!r}")
            self._append(self.REVISIONS, revision.to_dict())
            self._revisions[revision.revision_id] = revision
            self._order.append(revision.revision_id)
            return revision

    def get(self, revision_id: str) -> HarnessRevision:
        rev = self._revisions.get(str(revision_id or ""))
        if rev is None:
            raise RevisionError(f"revision 不存在：{revision_id!r}")
        return rev

    def has(self, revision_id: str) -> bool:
        return str(revision_id or "") in self._revisions

    def latest(self) -> HarnessRevision | None:
        return self._revisions[self._order[-1]] if self._order else None

    def all(self) -> tuple[HarnessRevision, ...]:
        return tuple(self._revisions[rid] for rid in self._order)

    def lineage(self, revision_id: str, limit: int = 64) -> tuple[HarnessRevision, ...]:
        """从根到该 revision 的链（回退时用来找父）。"""
        chain: list[HarnessRevision] = []
        current = self.get(revision_id)
        seen = set()
        while current is not None and len(chain) < int(limit):
            if current.revision_id in seen:         # pragma: no cover - 防御环
                raise RevisionError("revision 血缘成环")
            seen.add(current.revision_id)
            chain.append(current)
            current = (self._revisions.get(current.parent_id)
                       if current.parent_id else None)
        return tuple(reversed(chain))

    def children(self, revision_id: str) -> tuple[HarnessRevision, ...]:
        return tuple(rev for rev in self.all() if rev.parent_id == revision_id)

    # ---- 当前指针（选中的工作版本） ----
    def current(self) -> HarnessRevision | None:
        path = self._file(self.CURRENT)
        if not path.exists():
            return self.latest()
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):      # pragma: no cover
            return self.latest()
        rid = str(doc.get("revision_id") or "")
        return self._revisions.get(rid) or self.latest()

    def set_current(self, revision_id: str) -> HarnessRevision:
        revision = self.get(revision_id)
        payload = {"revision_id": revision.revision_id, "at": now()}
        tmp = self._file(self.CURRENT).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._file(self.CURRENT))
        return revision

    # ---- 构建 / 冒烟事实 ----
    def record_build(self, record: BuildRecord) -> BuildRecord:
        if not isinstance(record, BuildRecord):
            raise RevisionError("only BuildRecord can be recorded")
        self.get(record.revision_id)
        with self._lock:
            self._append(self.BUILDS, record.to_dict())
            self._builds[record.build_id] = record
        return record

    def record_smoke(self, record: SmokeRecord) -> SmokeRecord:
        if not isinstance(record, SmokeRecord):
            raise RevisionError("only SmokeRecord can be recorded")
        self.get(record.revision_id)
        with self._lock:
            self._append(self.SMOKES, record.to_dict())
            self._smokes[record.smoke_id] = record
        return record

    def builds(self, revision_id: str = "") -> tuple[BuildRecord, ...]:
        items = sorted(self._builds.values(), key=lambda r: r.started_at)
        if revision_id:
            items = [r for r in items if r.revision_id == revision_id]
        return tuple(items)

    def smokes(self, revision_id: str = "") -> tuple[SmokeRecord, ...]:
        items = sorted(self._smokes.values(), key=lambda r: r.started_at)
        if revision_id:
            items = [r for r in items if r.revision_id == revision_id]
        return tuple(items)

    def latest_build(self, revision_id: str) -> BuildRecord | None:
        items = self.builds(revision_id)
        return items[-1] if items else None

    def latest_smoke(self, revision_id: str) -> SmokeRecord | None:
        items = self.smokes(revision_id)
        return items[-1] if items else None

    # ---- 配置效果（计划版本 vs 实际加载版本） ----
    def record_config_effect(self, record: ConfigEffectRecord | Mapping | None = None,
                             **fields) -> ConfigEffectRecord:
        """落一条配置效果；`record` 可以是 `ConfigEffectRecord` 或字段映射。

        只增不改：同 id 同内容视为重复上报（幂等返回），同 id 不同内容直接拒绝。
        """
        if record is None:
            effect = ConfigEffectRecord(**fields)
        elif isinstance(record, ConfigEffectRecord):
            if fields:
                raise RevisionError("record_config_effect 不接受记录+字段混用")
            effect = record
        elif isinstance(record, Mapping):
            effect = ConfigEffectRecord(**{**dict(record), **fields})
        else:
            raise RevisionError("only ConfigEffectRecord can be recorded")
        self.get(effect.revision_id)
        with self._lock:
            existing = self._config_effects.get(effect.effect_id)
            if existing is not None:
                if existing.to_dict() != effect.to_dict():
                    raise RevisionError("旧配置效果不可改写：同 id 不同内容")
                return existing
            self._append(self.CONFIG_EFFECTS, effect.to_dict())
            self._config_effects[effect.effect_id] = effect
            self._config_order.append(effect.effect_id)
            return effect

    def config_effects(self, revision_id: str = "") -> tuple[ConfigEffectRecord, ...]:
        """按登记顺序返回配置效果（可只取某个 revision 的）。"""
        items = [self._config_effects[eid] for eid in self._config_order]
        if revision_id:
            items = [r for r in items if r.revision_id == revision_id]
        return tuple(items)

    def latest_config_effect(self, revision_id: str = "") -> ConfigEffectRecord | None:
        items = self.config_effects(revision_id)
        return items[-1] if items else None

    def config_effect_for_execution(self, execution_id: str) -> ConfigEffectRecord | None:
        """某次执行对应的那条配置效果（同一次执行多次上报取最后一条）。"""
        wanted = str(execution_id or "")
        if not wanted:
            return None
        for effect in reversed(self.config_effects()):
            if effect.execution_id == wanted:
                return effect
        return None

    def config_adoptable(self, revision_id: str) -> bool:
        """该 revision 最近一次配置效果是否可采纳（只有 `effective` 才是 True）。"""
        latest = self.latest_config_effect(revision_id)
        return bool(latest and latest.adoptable)

    # ---- 采纳账（只记录，不改 revision） ----
    def record_adoption(self, decision: Mapping) -> dict:
        doc = dict(decision or {})
        doc.setdefault("at", now())
        self._append(self.ADOPTIONS, doc)
        self._adoptions.append(doc)
        return doc

    def adoptions(self) -> tuple[dict, ...]:
        return tuple(dict(item) for item in self._adoptions)

    # ---- 失效 ----
    def note_invalidations(self, scopes: Iterable[str], *, source: str = "") -> tuple[str, ...]:
        wanted: list[str] = []
        for scope in scopes or ():
            name = str(scope)
            if name not in INVALIDATION_SCOPES:
                raise RevisionError(f"未知失效域：{name!r}")
            if name not in wanted:
                wanted.append(name)
        with self._lock:
            for name in wanted:
                if name not in self._pending:
                    self._pending.append(name)
        return tuple(wanted)

    def pending_invalidations(self) -> tuple[str, ...]:
        return tuple(self._pending)

    def consume_invalidations(self) -> tuple[str, ...]:
        """控制器消费：取出并清空。只取出不落实 = 没有真正失效（§8）。"""
        with self._lock:
            taken = tuple(self._pending)
            self._pending = []
        return taken

    # ---- 完整性 ----
    def verify_manifest(self, revision_id: str, directory: Path | str) -> dict:
        """目录与 manifest 对账：多/少/改一个文件都要报出来。"""
        revision = self.get(revision_id)
        root = Path(directory)
        problems: list[str] = []
        if not root.is_dir():
            return {"ok": False, "problems": ["missing_directory"],
                    "revision_id": revision.revision_id}
        seen = set()
        for entry in revision.manifest:
            path = root / entry.path
            seen.add(entry.path)
            if not path.is_file():
                problems.append(f"missing:{entry.path}")
                continue
            data = path.read_bytes()
            if sha256_bytes(data) != entry.sha256:
                problems.append(f"changed:{entry.path}")
            if len(data) != entry.size:
                problems.append(f"size:{entry.path}")
            if os.access(path, os.W_OK):
                problems.append(f"writable:{entry.path}")
        for path in sorted(root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(root).as_posix()
                if rel not in seen and "__pycache__" not in rel:
                    problems.append(f"extra:{rel}")
        return {"ok": not problems, "problems": problems,
                "revision_id": revision.revision_id,
                "manifest_sha256": revision.manifest_sha256}

    def to_dict(self) -> dict:
        return {
            "schema": "vulnmap.adaptive.revision_store.v1",
            "root": str(self.root),
            "revisions": [rev.to_dict() for rev in self.all()],
            "current": (self.current().revision_id if self.current() else ""),
            "builds": [rec.to_dict() for rec in self.builds()],
            "smokes": [rec.to_dict() for rec in self.smokes()],
            "config_effects": [rec.to_dict() for rec in self.config_effects()],
            "pending_invalidations": list(self.pending_invalidations()),
        }


def unified_diff(*, before: Mapping[str, bytes], after: Mapping[str, bytes],
                 limit: int = 20000) -> str:
    """生成可重建的 unified diff（二进制只记哈希变化，不塞乱码）。"""
    import difflib

    chunks: list[str] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        if old is None:
            chunks.append(f"--- /dev/null\n+++ b/{path}\n")
            chunks.append(f"@@ new file ({len(new or b'')} bytes, "
                          f"sha256 {sha256_bytes(new or b'')}) @@\n")
            continue
        if new is None:
            chunks.append(f"--- a/{path}\n+++ /dev/null\n")
            chunks.append(f"@@ deleted ({len(old)} bytes) @@\n")
            continue
        try:
            old_text = old.decode("utf-8")
            new_text = new.decode("utf-8")
        except UnicodeDecodeError:
            chunks.append(f"--- a/{path}\n+++ b/{path}\n")
            chunks.append(f"@@ binary change {sha256_bytes(old)[:16]} -> "
                          f"{sha256_bytes(new)[:16]} ({len(old)} -> {len(new)} bytes) @@\n")
            continue
        diff = difflib.unified_diff(
            old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}", n=3)
        chunks.extend(diff)
    text = "".join(chunks)
    if len(text) > int(limit):
        return text[:int(limit)] + f"\n... (diff truncated at {int(limit)} chars)\n"
    return text


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "BUILD_SCHEMA", "SMOKE_SCHEMA",
    "CONFIG_EFFECT_SCHEMA", "CONFIG_STATUSES",
    "BUILD_STATUSES", "SMOKE_STATUSES", "HARNESS_INVALIDATIONS", "FILE_KEYS",
    "RevisionError", "FileEntry", "manifest_of", "manifest_sha256",
    "manifest_paths", "HarnessRevision", "build_identity", "BuildRecord",
    "SmokeRecord", "ConfigEffectRecord", "config_sha", "RevisionStore",
    "unified_diff", "safe_relpath", "now", "sha256_bytes",
]
