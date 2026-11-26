"""V3-007：任务 overlay 工作区 —— 原件只读、副本可改、构建/冒烟真跑、回退不改旧账。

口径（《V3 完整升级方案》§8「实验自修改与版本事务」、§6「工具与权限」）：

- **原件不可写**：`create()` 先把任务原件复制成 `origin/`，文件一律 0444；
  所有写操作只允许落在 `current/`（工作副本），路径解析拒绝绝对路径、`..` 和
  `origin/`、`revisions/`、`builds/`。每次操作前后都可以用 `origin_integrity()`
  复核原件哈希——“原件没变”是算出来的，不是口头保证。
- **stage 就是写副本**：`stage()` 只写 `current/`，返回每个文件 before/after 哈希；
  `commit()` 生成不可变 `HarnessRevision`（完整 manifest + 可重建 diff + 原因 +
  父假设 + 环境身份），并把 `current/` 快照到 `revisions/<id>/` 后设为只读。
- **build/smoke 在强隔离里真实执行**：`subprocess.run(..., shell=False)` 带着
  `discovery.isolation` 的强隔离前缀（只有 `bwrap`/`container`）在副本目录真跑，
  记录退出码、耗时、完整日志哈希；没有 worker 就报 `setup_error`，不假装跑过。
  `smoke` 把“harness 自己崩了”（traceback/用法错误）与“目标行为不符”分开——
  前者永远是 `harness_error`，不能被 policy 升格成漏洞证据。
- **隔离 fail-closed**（口径唯一出处：`docs/V3-ISOLATION-ACCEPTANCE.md`）：
  `TaskWorkspace(isolation=..., require_isolation=...)` 默认 `auto` + 要求隔离；
  构建/冒烟前先 `isolation.resolve()`，**解析结果不是强隔离（`bwrap`/`container`）
  就 `WorkspaceError(strong_isolation_required)`，一个命令都不跑**——`auto` 降级到
  `unshare`、显式 `unshare`、`none` 一律在 spawn 前拒绝，绝不回退弱隔离或宿主
  `subprocess`。实际用到的模式/网络/cap/只读根与 `executed_isolated` 只写进
  **跑完之后**的记录
  （`IsolatedBuildRecord` / `IsolatedSmokeRecord` + `isolation-executions.jsonl`），
  计划中的隔离（`workspace.json` 的 policy）永远不冒充实际隔离。
- **revert 是选父版本重建工作树**：把目标 revision 的 manifest 复制回 `current/`，
  再登记一个**新** revision（`reverted_to` 指回目标），旧 revision 的字节不改不删。
- **失效要进账**：`commit()/revert()` 之后把 `build/smoke/coverage_baseline/
  corpus_members` 记进 `RevisionStore` 的待消费集合，由控制器逐项落实。
- **配置面白名单**（V3 第 2 周，口径见 `docs/V3-W2-CONFIG.md`）：原件里带
  `config/{samples,observation_points,active}.json` 时进入**配置模式**，只有
  `config/active.json` 可写（`stage_config()` 与配置模式下的 `stage()`），且只允许
  "切到**已有**样例 / 启用**已有**观测点"；`commit()` 再加一次差异守卫，配置面之外的
  改动一律 `config_source_edit_forbidden`。配置版本（`active_config_sha256`）与基线
  版本写进 `revision.environment`——**换配置必然换 revision id**。原件没变、目录清单
  没改、active 在白名单内，全部用哈希与差异集合**算出来**（`config_integrity()`），
  不是声明出来的。

本模块不判定漏洞、不写 verified/confirmed；执行只在任务副本里发生。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from ...discovery import isolation as sandbox
from .contracts import CHANGE_INVALIDATIONS
from .revision import (
    BuildRecord,
    HarnessRevision,
    RevisionStore,
    SmokeRecord,
    build_identity,
    manifest_of,
    manifest_sha256,
    safe_relpath,
    sha256_bytes,
    unified_diff,
)

SCHEMA = "vulnmap.adaptive.workspace.v1"
SCHEMA_VERSION = 1

#: 不进入副本的目录/文件（构建产物与 VCS 元数据不属于“任务原件”）
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".mypy_cache",
                       ".pytest_cache", ".ruff_cache", "node_modules"})
SKIP_SUFFIXES = (".pyc", ".pyo")

#: 有界复制：超限是拒绝，不是静默截断（任务原件应当很小）
MAX_FILES = 4096
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

#: 执行日志上限（完整日志另存文件；返回给模型的是有界摘要）
MAX_LOG_BYTES = 256 * 1024

#: 默认超时（秒）；调用方可覆盖
BUILD_TIMEOUT = 120.0
SMOKE_TIMEOUT = 60.0

# ====================================================================== 执行隔离
#: 隔离口径的唯一实现在 `agent/discovery/isolation.py`（bwrap/unshare/container/none）
ISOLATION_MODES = tuple(sandbox.MODES)
#: **强隔离**执行器：构建/冒烟只认这两种。判据是“断网 + 只读根 + cap-drop 至少
#: 由执行器本身保证”；`unshare` 缺只读根与 cap-drop，`none` 是宿主执行，都不算。
STRONG_ISOLATION_MODES = ("bwrap", "container")
#: 合格执行器 == 强隔离执行器（保留旧名给 policy/文档对账；`unshare` 不再“合格”）
QUALIFIED_ISOLATION_MODES = STRONG_ISOLATION_MODES
#: 低保证模式：只能被显式选择，且**不能承载 workspace 的自动应用**（build/smoke
#: 在 spawn 前就拒绝）。它们仍然可以出现在 discovery 执行器的显式参数里。
LOW_ASSURANCE_ISOLATION_MODES = ("unshare",)
#: 默认：auto 选最硬化的可用执行器，且**要求**强隔离（fail-closed）
DEFAULT_ISOLATION = "auto"
DEFAULT_REQUIRE_ISOLATION = True
#: 每次构建/冒烟的**实际**隔离事实只追加到这个台账（`workspace.root` 下）
ISOLATION_LEDGER = "isolation-executions.jsonl"
ISOLATION_LEDGER_SCHEMA = "vulnmap.adaptive.isolation_execution.v1"

#: 冒烟退出码 → 状态（126/127 是环境没装好，不是目标行为）
SETUP_ERROR_CODES = (126, 127)
#: harness 自身错误：Python traceback / argparse 用法错误都算“实验装置坏了”
HARNESS_ERROR_MARKERS = ("Traceback (most recent call last)",
                         "SyntaxError:", "ModuleNotFoundError:",
                         "ImportError:", "SMOKE:harness_error")
HARNESS_ERROR_CODES = (2,)

#: 环境变量里绝不继承给 worker 的名字片段（模型 API key 不能进目标侧）
SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD",
                  "CREDENTIAL", "COOKIE", "AUTH", "SESSION")

#: manifest 只描述内容（路径+哈希+大小）；POSIX 读写位由 verify 单独检查，
#: 否则“原件 0444 / 副本 0644”会让同一份内容算出两个 manifest。
CONTENT_MODE = 0o644

#: 工作区内的固定布局
ORIGIN = "origin"
CURRENT = "current"
REVISIONS = "revisions"
BUILDS = "builds"
LOGS = "logs"
META = "workspace.json"

# ====================================================================== 配置面
#: V3 第 2 周：任务原件里出现下面三个文件即进入**配置模式**
#: （口径唯一出处：docs/V3-W2-CONFIG.md §1）。前两个是原件（谁都不可改），
#: 只有 `config/active.json` 可以走白名单变更。
CONFIG_RELPATH = "config/active.json"
SAMPLES_RELPATH = "config/samples.json"
POINTS_RELPATH = "config/observation_points.json"

#: `config/active.json` 的 schema（不可改：改了就是 `config_field_not_whitelisted`）
CONFIG_ACTIVE_SCHEMA = "vulnmap.active_config.v1"
SAMPLE_CATALOG_SCHEMA = "vulnmap.sample_catalog.v1"
POINT_CATALOG_SCHEMA = "vulnmap.observation_point_catalog.v1"

#: active.json 允许出现的键（白名单是白名单，不是"只校验这两个字段"）
CONFIG_KEYS = ("schema", "sample", "observation_points")
#: 配置面原件：目录清单两个文件，任何改动都进不了 revision
CONFIG_SOURCE_PATHS = (SAMPLES_RELPATH, POINTS_RELPATH)
#: 配置模式下唯一可写的路径集合
CONFIG_WRITABLE_PATHS = (CONFIG_RELPATH,)

#: 工作区模式：`config`（有配置面 → 白名单）/ `generator`（第 1 周行为不变）
CONFIG_MODE_CONFIG = "config"
CONFIG_MODE_GENERATOR = "generator"
CONFIG_MODES = (CONFIG_MODE_CONFIG, CONFIG_MODE_GENERATOR)


class WorkspaceError(RuntimeError):
    """工作区不可用/越权/原件被改：宁可失败，也不留半截状态。"""


class ConfigError(WorkspaceError):
    """配置面违规（取 `WorkspaceError` 的子类：控制器只认一种错误入口）。

    错误码唯一词形见 docs/V3-W2-CONFIG.md §1.3，消息形如 `"<code>: <detail>"`；
    调用方用 `startswith` 认码，不解析自然语言。
    """


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_meta(root: Path | str) -> dict:
    """读 `workspace.json`（缺失/坏 JSON → `{}`：模式与基线都有现算的退路）。"""
    path = Path(root) / META
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


# ---- 配置版本哈希：唯一实现留在 `agent.platform.executors` ----
# 顶层导入会成环（`agent.platform` 先导执行器、执行器又导本包），因此延迟导入；
# 算法只有一份：规范化 JSON（sort_keys + 紧凑分隔符）的 sha256。
def _config_doc_sha(doc) -> str:
    """配置**文档** → 配置版本；不是 JSON 对象 → `""`（没观测到）。"""
    from ..executors import config_doc_sha256
    return config_doc_sha256(doc)


def _config_file_sha(path) -> str:
    """配置**文件** → 配置版本；缺失/不可读/坏 JSON → `""`（没观测到）。"""
    from ..executors import config_file_sha256
    return config_file_sha256(path)


def _json_object(raw, *, label: str) -> tuple[dict, str]:
    """读 JSON 对象 → `(doc, problem)`；problem 非空表示这一份不可用。

    这里**不抛**：配置面探测要能看见"目录清单坏了"这件事本身，
    而不是在 `create()` 里就炸掉（坏原件应当由校验/复核报出来）。
    """
    try:
        doc = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {}, f"{label}: 不是合法 JSON（{exc}）"
    if not isinstance(doc, dict):
        return {}, f"{label}: 必须是 JSON 对象"
    return dict(doc), ""


@dataclass(frozen=True)
class ConfigSurface:
    """一个目录里的配置面：样例目录 + 观测点目录 + 当前选择（`active.json`）。

    三份文件各司其职（docs/V3-W2-CONFIG.md §1.1）：

    - `config/samples.json`：样例目录（样例 id → 文件路径），**原件**；
    - `config/observation_points.json`：观测点目录（观测点 id → 探针名），**原件**；
    - `config/active.json`：当前选择，**唯一可写**，且只允许"切到已有样例 / 启用已有观测点"。

    `root` 就是被校验的那个目录（`origin/` 看基线，`current/` 看工作副本）：
    判断始终以**当前工作副本**为基线，所以回退（回到旧选择）也是一次合法变更。
    """

    root: Path
    samples: Mapping[str, str] = field(default_factory=dict)
    points: Mapping[str, str] = field(default_factory=dict)
    active: Mapping = field(default_factory=dict)
    problems: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        object.__setattr__(self, "samples", dict(self.samples or {}))
        object.__setattr__(self, "points", dict(self.points or {}))
        object.__setattr__(self, "active", dict(self.active or {}))
        object.__setattr__(self, "problems", tuple(self.problems or ()))

    # ------------------------------------------------------------------ 载入
    @classmethod
    def detect(cls, root: Path | str) -> ConfigSurface | None:
        """探测配置面：**两份目录清单**都在才算有配置面，否则 `None`（= generator 模式）。

        以目录清单为准而不是"有 `config/` 目录就算"：没有样例目录/观测点目录，
        "这个 id 存在不存在"根本无从判断，那种情况不构成可校验的配置面。
        """
        root = Path(root)
        if not all((root / rel).is_file()
                   for rel in (SAMPLES_RELPATH, POINTS_RELPATH)):
            return None
        return cls.load(root)

    @classmethod
    def load(cls, root: Path | str) -> ConfigSurface:
        """读三份文件（缺失/坏 JSON 不抛，记进 `problems`，由 `validate()` 报码）。"""
        root = Path(root)
        problems: list[str] = []
        for rel in (SAMPLES_RELPATH, POINTS_RELPATH):
            if not (root / rel).is_file():
                problems.append(f"{rel}: 缺失（没有目录清单就无法按白名单校验）")
        samples, problem = _catalogue(root / SAMPLES_RELPATH, key="samples",
                                      attr="path", label=SAMPLES_RELPATH)
        if problem:
            problems.append(problem)
        points, problem = _catalogue(root / POINTS_RELPATH, key="points",
                                     attr="probe", label=POINTS_RELPATH)
        if problem:
            problems.append(problem)
        active: dict = {}
        path = root / CONFIG_RELPATH
        if path.is_file():
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:   # pragma: no cover - 坏盘/坏编码
                raw = ""
                problems.append(f"{CONFIG_RELPATH}: 不可读（{exc}）")
            if raw:
                active, problem = _json_object(raw, label=CONFIG_RELPATH)
                if problem:
                    problems.append(problem)
        return cls(root=root, samples=samples, points=points, active=active,
                   problems=tuple(problems))

    # ------------------------------------------------------------------ 目录
    def sample_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.samples))

    def point_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.points))

    def catalogue(self) -> dict:
        """目录视图（排序；只读快照，供计划/报告引用）。"""
        return {
            "samples": [{"id": sid, "path": self.samples[sid]}
                        for sid in self.sample_ids()],
            "observation_points": [{"id": pid, "probe": self.points[pid]}
                                   for pid in self.point_ids()],
        }

    def sample_file(self, sample_id: str) -> Path | None:
        """样例 id → 工作副本里的文件路径（目录里没登记就是 `None`）。"""
        rel = self.samples.get(str(sample_id or ""))
        return (self.root / rel) if rel else None

    @property
    def observation_points(self) -> Mapping[str, str]:
        """观测点目录的别名（与 `config/observation_points.json` 同口径）。

        控制器/会话按**文件名**取成员（`surface.observation_points`），这里给同一个
        映射，不复制、不另存——两处不一致就是两份事实。
        """
        return self.points

    @property
    def observation_points_catalog(self) -> Mapping[str, str]:
        """`observation_points` 的显式别名（同样只指向 `points`）。"""
        return self.points

    # ------------------------------------------------------------------ 校验
    def validate(self, doc) -> dict:
        """白名单校验 `active.json`，返回规范化文档（键只留三个，观测点保持给定顺序）。

        通过 = 只改了两件被允许的事：切到**目录里已有**的样例、启用**目录里已有**
        的观测点子集。任何源码/脚本/目录清单改动都到不了这里。
        """
        if self.problems:
            raise ConfigError("config_invalid: " + "；".join(self.problems))
        if not isinstance(doc, Mapping):
            raise ConfigError("config_invalid: active.json 必须是 JSON 对象")
        extra = sorted({str(key) for key in doc} - set(CONFIG_KEYS))
        if extra:
            raise ConfigError(f"config_field_not_whitelisted: 白名单外键 {extra}")
        if "schema" not in doc:
            raise ConfigError("config_invalid: 缺少 schema")
        if str(doc.get("schema") or "") != CONFIG_ACTIVE_SCHEMA:
            raise ConfigError(
                f"config_field_not_whitelisted: schema={doc.get('schema')!r} 不可改"
                f"（必须 {CONFIG_ACTIVE_SCHEMA}）")
        if "sample" not in doc:
            raise ConfigError("config_invalid: 缺少 sample")
        sample = doc.get("sample")
        if not isinstance(sample, str) or not sample:
            raise ConfigError("config_invalid: sample 必须是非空字符串")
        path = self.samples.get(sample)
        if path is None:
            raise ConfigError(
                f"unknown_sample: {sample!r} 不在样例目录里（已有 {list(self.sample_ids())}）")
        if not (self.root / path).is_file():
            raise ConfigError(
                f"unknown_sample: {sample!r} 登记的样例文件不存在：{path}")
        if "observation_points" not in doc:
            raise ConfigError("config_invalid: 缺少 observation_points")
        raw_points = doc.get("observation_points")
        if not isinstance(raw_points, (list, tuple)):
            raise ConfigError("config_invalid: observation_points 必须是列表")
        picked: list[str] = []
        for item in raw_points:
            if not isinstance(item, str) or not item:
                raise ConfigError(
                    f"config_invalid: observation_points 里有非字符串：{item!r}")
            if item in picked:
                raise ConfigError(f"config_invalid: observation_points 有重复 id：{item!r}")
            if item not in self.points:
                raise ConfigError(
                    f"unknown_observation_point: {item!r} 不在观测点目录里"
                    f"（已有 {list(self.point_ids())}）")
            picked.append(item)
        return {"schema": CONFIG_ACTIVE_SCHEMA, "sample": sample,
                "observation_points": picked}

    # ------------------------------------------------------------------ 序列化
    def parse(self, payload) -> dict:
        """`dict` / JSON 字符串 / 字节 → JSON 对象（不是对象就 `config_invalid`）。"""
        if isinstance(payload, Mapping):
            return dict(payload)
        try:
            text = payload.decode("utf-8") if isinstance(payload, bytes) else str(payload)
            doc = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ConfigError(f"config_invalid: active.json 不是合法 JSON（{exc}）") from exc
        if not isinstance(doc, dict):
            raise ConfigError("config_invalid: active.json 必须是 JSON 对象")
        return doc

    def canonical(self, doc) -> str:
        """规范化 JSON 文本：同一个配置对象永远同一串字节、同一个版本哈希。"""
        return json.dumps(dict(doc), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))

    def sha256(self, doc) -> str:
        """配置文档的版本哈希（规范化后的 sha256；与执行器用同一份实现）。"""
        return _config_doc_sha(dict(doc or {}))

    def active_sha256(self) -> str:
        """本目录 `active.json` 的版本哈希；缺失/坏 JSON → `""`。"""
        return _config_file_sha(self.root / CONFIG_RELPATH)


def _catalogue(path: Path, *, key: str, attr: str, label: str
               ) -> tuple[dict[str, str], str]:
    """读样例/观测点目录 → `({id: 值}, problem)`；坏条目只记 problem 不猜。"""
    if not path.is_file():
        return {}, ""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:    # pragma: no cover - 坏盘/坏编码
        return {}, f"{label}: 不可读（{exc}）"
    doc, problem = _json_object(raw, label=label)
    if problem:
        return {}, problem
    items = doc.get(key)
    if not isinstance(items, list):
        return {}, f"{label}: {key} 必须是列表"
    out: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping):
            return {}, f"{label}: {key} 里有非对象条目"
        ident = item.get("id")
        target = item.get(attr)
        if not isinstance(ident, str) or not ident:
            return {}, f"{label}: {key} 里有非法 id"
        if not isinstance(target, str) or not target:
            return {}, f"{label}: {key}[{ident}] 的 {attr} 非法"
        if ident in out:
            return {}, f"{label}: {key} 里 id 重复：{ident!r}"
        out[ident] = target
    return out, ""


def config_path_allowed(rel: str) -> bool:
    """配置模式下唯一允许写的工作区路径（差异集合：不在集合里就拒绝）。"""
    return safe_relpath(rel) in CONFIG_WRITABLE_PATHS


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            raise WorkspaceError(f"副本里不允许符号链接：{path}")
        if path.is_file() and not path.name.endswith(SKIP_SUFFIXES):
            yield path


def read_tree(root: Path, *, max_files: int = MAX_FILES,
              max_file_bytes: int = MAX_FILE_BYTES,
              max_total_bytes: int = MAX_TOTAL_BYTES) -> dict[str, bytes]:
    """把目录读成 {相对路径: 字节}（有界；超限直接拒绝）。"""
    root = Path(root)
    if not root.is_dir():
        raise WorkspaceError(f"目录不存在：{root}")
    files: dict[str, bytes] = {}
    total = 0
    for path in _iter_files(root):
        if len(files) >= int(max_files):
            raise WorkspaceError(f"文件数超过上限 {max_files}：{root}")
        data = path.read_bytes()
        if len(data) > int(max_file_bytes):
            raise WorkspaceError(f"单文件超过上限 {max_file_bytes}：{path}")
        total += len(data)
        if total > int(max_total_bytes):
            raise WorkspaceError(f"总字节超过上限 {max_total_bytes}：{root}")
        files[path.relative_to(root).as_posix()] = data
    return files


def _clean_env(extra: Mapping | None, *, home: Path) -> dict[str, str]:
    """最小环境：只给 PATH/LANG/TZ/HOME/TMPDIR，凭据类变量一律不继承。"""
    env = {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": str(home),
        "TMPDIR": str(home / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "0",
    }
    for key, value in dict(extra or {}).items():
        name = str(key)
        if name in env:
            env[name] = str(value)
            continue
        if any(marker in name.upper() for marker in SECRET_MARKERS):
            continue
        env[name] = str(value)
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    return env


def _truncate(text: str, limit: int = MAX_LOG_BYTES) -> tuple[str, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= int(limit):
        return text, False
    return raw[:int(limit)].decode("utf-8", errors="ignore"), True


# ---------------------------------------------------------------- 隔离执行记录
def _strong_flags(mode: str) -> dict:
    """实测模式 → `qualified` / `strong` 两个布尔。

    `qualified` 是历史字段名，语义已收窄为“本次执行算不算强隔离”；`strong` 是
    新名字，两者同源同值。`unshare`/`none` 恒为 False——弱隔离不能靠记录洗白。
    """
    strong = str(mode or "") in STRONG_ISOLATION_MODES
    return {"qualified": strong, "strong": strong}


def _observed_isolation_facts(info: Mapping | None, prefix: Iterable[str] = (), *,
                    executed: bool = False) -> dict:
    """把**实际**发生的隔离事实压成记录字段。

    `executed=True` 只有一个含义：命令确实带着这个前缀被 spawn 过。因此
    `executed_isolated` 只在“真的跑了 + 模式属于**强隔离**执行器”时为真；
    计划里的隔离模式（`workspace.json` 的 policy）走不进这个函数。
    """
    doc = dict(info or {})
    mode = str(doc.get("mode") or "")
    prefix_list = [str(item) for item in (prefix or ())]
    return {
        "isolation": mode,
        "network": str(doc.get("network") or ""),
        "cap_drop": bool(doc.get("cap_drop")),
        "ro_root": bool(doc.get("ro_root")),
        "pidns": bool(doc.get("pidns")),
        "no_new_privs": bool(doc.get("no_new_privs")),
        **_strong_flags(mode),
        "executed_isolated": bool(executed and mode in STRONG_ISOLATION_MODES),
        "prefix_sha256": sha256_bytes(
            json.dumps(prefix_list, ensure_ascii=False).encode("utf-8")),
    }


#: 隔离事实字段（BuildRecord / SmokeRecord 子类共用的追加字段）
ISOLATION_FACT_KEYS = ("isolation", "network", "cap_drop", "ro_root", "pidns",
                       "no_new_privs", "qualified", "strong",
                       "executed_isolated", "prefix_sha256")


def _isolation_kwargs(doc: Mapping) -> dict:
    """从记录文档里取隔离事实（缺字段按“没观测到”处理，不猜）。

    `qualified`/`strong` 由 `isolation` 模式**复算**，不信任文档里的旧值；
    `executed_isolated` 也按强隔离口径复算——旧版本留下的 `unshare` 行（曾经
    自称 `executed_isolated=True`）读回来只能是 False。
    """
    doc = dict(doc or {})
    mode = str(doc.get("isolation") or "")
    strong = mode in STRONG_ISOLATION_MODES
    return {
        "isolation": mode,
        "network": str(doc.get("network") or ""),
        "cap_drop": bool(doc.get("cap_drop")),
        "ro_root": bool(doc.get("ro_root")),
        "pidns": bool(doc.get("pidns")),
        "no_new_privs": bool(doc.get("no_new_privs")),
        **_strong_flags(mode),
        "executed_isolated": bool(doc.get("executed_isolated")) and strong,
        "prefix_sha256": str(doc.get("prefix_sha256") or ""),
    }


@dataclass(frozen=True)
class IsolatedBuildRecord(BuildRecord):
    """在**强隔离**执行器里真跑过的构建记录。

    基类 `BuildRecord`（`revision.py`）只描述构建结果；本子类**追加**实际观测到的
    隔离事实。隔离事实是“跑出来的”：`executed_isolated` 为假时，这条记录不能当
    “隔离内构建”的证据，无论 policy 里写的是什么。`qualified`/`strong` 由实际
    模式复算：`unshare`/`none` 恒为 False。
    """

    isolation: str = ""
    network: str = ""
    cap_drop: bool = False
    ro_root: bool = False
    pidns: bool = False
    no_new_privs: bool = False
    qualified: bool = False
    strong: bool = False
    executed_isolated: bool = False
    prefix_sha256: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        for name, value in _isolation_kwargs(self.__dict__).items():
            object.__setattr__(self, name, value)

    def isolation_facts(self) -> dict:
        return {key: getattr(self, key) for key in ISOLATION_FACT_KEYS}

    def to_dict(self) -> dict:
        return {**super().to_dict(), **self.isolation_facts()}

    @classmethod
    def from_dict(cls, doc: Mapping) -> IsolatedBuildRecord:
        base = BuildRecord.from_dict(doc)
        return cls(
            build_id=base.build_id, revision_id=base.revision_id,
            status=base.status, command=base.command, exit_code=base.exit_code,
            duration=base.duration, log_path=base.log_path,
            log_sha256=base.log_sha256, log_bytes=base.log_bytes,
            truncated=base.truncated, toolchain=base.toolchain,
            workdir=base.workdir, started_at=base.started_at,
            finished_at=base.finished_at, error=base.error,
            **_isolation_kwargs(doc))


@dataclass(frozen=True)
class IsolatedSmokeRecord(SmokeRecord):
    """在**强隔离**执行器里真跑过的冒烟记录（字段语义同 `IsolatedBuildRecord`）。"""

    isolation: str = ""
    network: str = ""
    cap_drop: bool = False
    ro_root: bool = False
    pidns: bool = False
    no_new_privs: bool = False
    qualified: bool = False
    strong: bool = False
    executed_isolated: bool = False
    prefix_sha256: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        for name, value in _isolation_kwargs(self.__dict__).items():
            object.__setattr__(self, name, value)

    def isolation_facts(self) -> dict:
        return {key: getattr(self, key) for key in ISOLATION_FACT_KEYS}

    def to_dict(self) -> dict:
        return {**super().to_dict(), **self.isolation_facts()}

    @classmethod
    def from_dict(cls, doc: Mapping) -> IsolatedSmokeRecord:
        base = SmokeRecord.from_dict(doc)
        return cls(
            smoke_id=base.smoke_id, revision_id=base.revision_id,
            build_id=base.build_id, status=base.status,
            exit_code=base.exit_code, duration=base.duration,
            log_path=base.log_path, log_sha256=base.log_sha256,
            log_bytes=base.log_bytes, truncated=base.truncated,
            kind=base.kind, detail=base.detail, started_at=base.started_at,
            finished_at=base.finished_at, **_isolation_kwargs(doc))


@dataclass(frozen=True)
class StageResult:
    """一次 stage 的结算：改了哪些文件、每个文件 before/after 哈希。"""

    staged: tuple[dict, ...] = ()
    count: int = 0
    changed_paths: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not self.staged

    def to_dict(self) -> dict:
        return {"staged": [dict(item) for item in self.staged],
                "count": int(self.count),
                "changed_paths": list(self.changed_paths)}


class TaskWorkspace:
    """一个任务的实验副本：`origin/` 只读，`current/` 可写，revision 只增。"""

    def __init__(self, root: Path | str, *, task_id: str,
                 build_command: Iterable[str] = (),
                 smoke_command: Iterable[str] = (),
                 build_timeout: float = BUILD_TIMEOUT,
                 smoke_timeout: float = SMOKE_TIMEOUT,
                 toolchain: str = "",
                 config_mode: str = "",
                 isolation: str = DEFAULT_ISOLATION,
                 require_isolation: bool = DEFAULT_REQUIRE_ISOLATION) -> None:
        self.root = Path(root)
        self.task_id = str(task_id)
        self.build_command = tuple(str(c) for c in (build_command or ()))
        self.smoke_command = tuple(str(c) for c in (smoke_command or ()))
        self.build_timeout = float(build_timeout)
        self.smoke_timeout = float(smoke_timeout)
        self.toolchain = str(toolchain or "")
        self.revisions = RevisionStore(self.root / "store")
        self._staged_reason = ""
        # 配置模式与基线配置版本都持久化在 workspace.json 里（重启后仍是同一口径）；
        # 没有记录时按 origin 里有没有配置面现算，绝不"默认当成 generator"。
        meta = _read_meta(self.root)
        self._config_mode = str(config_mode or meta.get("config_mode") or "")
        self._baseline_config_sha256 = str(meta.get("baseline_config_sha256") or "")
        # 执行隔离：**先写进 policy，跑的时候再 resolve 一次**。policy 只描述"要求
        # 什么"，实际用了什么由 build/smoke 记录（见 `isolation_facts`）。
        self.isolation = str(isolation or meta.get("isolation")
                             or DEFAULT_ISOLATION).strip().lower()
        if self.isolation not in ISOLATION_MODES:
            raise WorkspaceError(
                f"unknown isolation mode: {self.isolation!r}（支持 "
                f"{list(ISOLATION_MODES)}）")
        self.require_isolation = bool(
            meta.get("require_isolation", require_isolation))
        if self.require_isolation and self.isolation == "none":
            raise WorkspaceError(
                "strong_isolation_required: require_isolation=True 但 mode='none'"
                "（宿主执行永远不算强隔离，拒绝建立会假装隔离的工作区）")

    # ------------------------------------------------------------------ 创建
    @classmethod
    def create(cls, root: Path | str, origin: Path | str, *, task_id: str,
               build_command: Iterable[str] = (),
               smoke_command: Iterable[str] = (),
               build_timeout: float = BUILD_TIMEOUT,
               smoke_timeout: float = SMOKE_TIMEOUT,
               toolchain: str = "",
               environment: Mapping | None = None,
               isolation: str = DEFAULT_ISOLATION,
               require_isolation: bool = DEFAULT_REQUIRE_ISOLATION
               ) -> TaskWorkspace:
        root = Path(root)
        if (root / META).exists():
            raise WorkspaceError(f"工作区已存在，拒绝覆盖：{root}")
        origin = Path(origin)
        files = read_tree(origin)
        if not files:
            raise WorkspaceError(f"任务原件为空：{origin}")

        for name in (ORIGIN, CURRENT, REVISIONS, BUILDS, LOGS):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "home").mkdir(exist_ok=True)

        # 原件副本：只读（0444），作为“原件没变”的对照
        for rel, data in files.items():
            _write_file(root / ORIGIN / rel, data, mode=0o444)
        # 工作副本：可写
        for rel, data in files.items():
            _write_file(root / CURRENT / rel, data, mode=0o644)

        ws = cls(root, task_id=task_id, build_command=build_command,
                 smoke_command=smoke_command, build_timeout=build_timeout,
                 smoke_timeout=smoke_timeout, toolchain=toolchain,
                 isolation=isolation, require_isolation=require_isolation)
        manifest = manifest_of(files, mode=CONTENT_MODE)
        env = dict(environment or {"toolchain": ws.toolchain})
        if ws.config_mode == CONFIG_MODE_CONFIG:
            # 基线配置版本：原件里那一版。根 revision 也带这一版，「换配置必然换 id」
            # 从第一条 revision 起就成立。
            ws._baseline_config_sha256 = _config_file_sha(
                ws.origin_dir / CONFIG_RELPATH)
            env["active_config_sha256"] = ws._baseline_config_sha256
            env["baseline_config_sha256"] = ws._baseline_config_sha256
        base = HarnessRevision.create(
            manifest=manifest, reason="origin snapshot",
            tool="workspace.create", environment=env)
        ws.revisions.add(base)
        ws._snapshot(base)
        ws.revisions.set_current(base.revision_id)
        ws._write_meta(origin=origin, base=base, environment=environment)
        return ws

    @classmethod
    def open(cls, root: Path | str) -> TaskWorkspace:
        root = Path(root)
        meta_path = root / META
        if not meta_path.exists():
            raise WorkspaceError(f"不是工作区（缺 {META}）：{root}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        ws = cls(root, task_id=str(meta.get("task_id") or ""),
                 build_command=meta.get("build_command") or (),
                 smoke_command=meta.get("smoke_command") or (),
                 build_timeout=float(meta.get("build_timeout") or BUILD_TIMEOUT),
                 smoke_timeout=float(meta.get("smoke_timeout") or SMOKE_TIMEOUT),
                 toolchain=str(meta.get("toolchain") or ""),
                 config_mode=str(meta.get("config_mode") or ""),
                 isolation=str(meta.get("isolation") or DEFAULT_ISOLATION),
                 require_isolation=bool(meta.get("require_isolation",
                                                DEFAULT_REQUIRE_ISOLATION)))
        if not (root / CURRENT).is_dir():
            raise WorkspaceError(f"工作区缺少 {CURRENT}/：{root}")
        return ws

    def _write_meta(self, *, origin: Path, base: HarnessRevision,
                    environment: Mapping | None) -> None:
        doc = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id, "created_at": now(),
            "origin_path": str(origin),
            "build_command": list(self.build_command),
            "smoke_command": list(self.smoke_command),
            "build_timeout": self.build_timeout,
            "smoke_timeout": self.smoke_timeout,
            "toolchain": self.toolchain,
            "environment": dict(environment or {}),
            "base_revision": base.revision_id,
            # 执行隔离的 **policy**（要求什么）；实际用了什么只写进 build/smoke
            # 记录与 isolation-executions.jsonl，两者不互相冒充。
            "isolation": self.isolation,
            "require_isolation": bool(self.require_isolation),
            # 配置模式与基线配置版本：重启后仍按同一口径判定（不重新"猜"）
            "config_mode": self.config_mode,
            "baseline_config_sha256": self.baseline_config_sha256(),
        }
        (self.root / META).write_text(
            json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------ 路径
    def _path(self, area: str, rel: str) -> Path:
        return self.root / area / safe_relpath(rel)

    def _write_guard(self, grant: Iterable[str] | None) -> None:
        """写副本是 L1：任务未授权时连 stage 都不给。"""
        if grant is None:
            return
        if "L1" not in set(grant or ()):
            raise WorkspaceError(
                f"permission_denied: 写实验副本需要 L1，本次授权={sorted(set(grant or ()))}")

    # ------------------------------------------------------------------ 读
    @property
    def origin_dir(self) -> Path:
        return self.root / ORIGIN

    @property
    def current_dir(self) -> Path:
        return self.root / CURRENT

    def current_revision(self) -> HarnessRevision | None:
        return self.revisions.current()

    def manifest(self, area: str = CURRENT) -> tuple:
        return manifest_of(read_tree(self.root / area), mode=CONTENT_MODE)

    def working_manifest(self) -> tuple:
        return self.manifest(CURRENT)

    def origin_integrity(self) -> dict:
        """复核原件副本：逐文件比对基线 revision 的 manifest + 只读位。"""
        problems: list[str] = []
        try:
            files = read_tree(self.origin_dir, max_files=MAX_FILES,
                              max_file_bytes=MAX_FILE_BYTES,
                              max_total_bytes=MAX_TOTAL_BYTES)
        except WorkspaceError as exc:
            return {"ok": False, "problems": [f"unreadable:{exc}"],
                    "manifest_sha256": ""}
        revisions = self.revisions.all()
        base = revisions[0] if revisions else None
        manifest = manifest_of(files, mode=CONTENT_MODE)
        if base is None:
            problems.append("no_baseline_revision")
        else:
            recorded = {entry.path: entry for entry in base.manifest}
            for rel, data in files.items():
                entry = recorded.get(rel)
                if entry is None:
                    problems.append(f"extra:{rel}")
                elif sha256_bytes(data) != entry.sha256:
                    problems.append(f"changed:{rel}")
            for rel in recorded:
                if rel not in files:
                    problems.append(f"missing:{rel}")
        for rel in files:
            if os.access(self.origin_dir / rel, os.W_OK):
                problems.append(f"writable:{rel}")
        return {"ok": not problems, "problems": problems,
                "manifest_sha256": manifest_sha256(manifest),
                "files": len(files)}

    def state(self) -> dict:
        current = self.current_revision()
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id, "root": str(self.root),
            "origin": self.origin_integrity(),
            "current_revision": current.revision_id if current else "",
            "revisions": len(self.revisions.all()),
            "pending_invalidations": list(self.revisions.pending_invalidations()),
            "builds": len(self.revisions.builds()),
            "smokes": len(self.revisions.smokes()),
            "config_mode": self.config_mode,
            "config": self.config_integrity(),
            # 两层分开：policy 只写“要求什么”，executions 只写“实际跑了什么”
            "isolation": self.isolation_policy(),
            "isolation_executions": self.isolation_summary(),
        }

    # ------------------------------------------------------------------ 隔离
    def isolation_policy(self) -> dict:
        """**计划**的隔离（要求什么），不是实际观测。

        实际隔离只在 `build()` / `smoke()` 跑完之后才存在：见记录上的
        `executed_isolated` 与 `isolation-executions.jsonl` 台账。
        """
        return {"mode": self.isolation,
                "require_isolation": bool(self.require_isolation),
                "strong_modes": list(STRONG_ISOLATION_MODES),
                "qualified_modes": list(QUALIFIED_ISOLATION_MODES),
                "low_assurance_modes": list(LOW_ASSURANCE_ISOLATION_MODES),
                "executions": len(self.isolation_ledger())}

    def isolation_summary(self) -> dict:
        """**实际**执行隔离的摘要快照（来自台账；没有台账就是 0 条）。"""
        rows = self.isolation_ledger()
        last = dict(rows[-1]) if rows else {}
        return {
            "count": len(rows),
            "builds": sum(1 for row in rows if row.get("stage") == "build"),
            "smokes": sum(1 for row in rows if row.get("stage") == "smoke"),
            "executed_isolated": sum(
                1 for row in rows if row.get("executed_isolated") is True),
            "strong_executions": sum(
                1 for row in rows if row.get("strong") is True),
            "low_assurance_executions": sum(
                1 for row in rows if row.get("strong") is not True),
            "last": ({key: last.get(key) for key in (
                "stage", "record_id", "isolation", "network", "cap_drop",
                "ro_root", "qualified", "strong", "executed_isolated",
                "evidence_sha256")}
                if last else {}),
        }

    def _resolve_isolation(self) -> dict:
        """解析**本次执行**要用的隔离；不是强隔离就拒绝，绝不回退宿主或弱隔离。

        硬约束：这个检查发生在任何子进程 spawn **之前**，也发生在复制快照之前。
        `auto` 解析到 `unshare`、显式 `unshare`、`none` 一律
        `WorkspaceError(strong_isolation_required)`——弱隔离不能承载自动应用。
        """
        mode = self.isolation
        try:
            info = sandbox.resolve(
                mode, require=bool(self.require_isolation))
        except (RuntimeError, ValueError) as exc:
            raise WorkspaceError(
                f"isolation_unavailable: mode={mode!r}: {exc}") from exc
        info = dict(info or {})
        actual = str(info.get("mode") or "")
        if actual not in STRONG_ISOLATION_MODES:
            raise WorkspaceError(
                "strong_isolation_required: "
                f"resolved={actual or '?'} requested={mode!r}："
                f"构建/冒烟只认强隔离执行器（{'/'.join(STRONG_ISOLATION_MODES)}）；"
                f"unshare/none 属于显式低保证模式，不能承载自动应用，"
                "拒绝回退弱隔离或宿主 subprocess（fail-closed）")
        if self.require_isolation and info.get("network") != "none":
            raise WorkspaceError(
                "strong_isolation_required: "
                f"mode={actual} network={info.get('network')!r}："
                "要求隔离时网络必须是 none")
        return info

    def _isolated_argv(self, info: Mapping, command: Iterable[str], *,
                       workdir: Path, env: Mapping | None = None) -> list[str]:
        """隔离前缀 + 目标命令；可写绑定只覆盖真正需要落盘的目录。"""
        mode = str((info or {}).get("mode") or "")
        home = self.root / "home"
        home.mkdir(parents=True, exist_ok=True)
        writable = [str(workdir), str(home)]
        if mode == "container":
            prefix = sandbox.prefix_for(
                dict(info), *writable, read_only=(), workdir=str(workdir),
                env=tuple(dict(env or {})))
        else:
            prefix = sandbox.prefix_for(dict(info), *writable)
        return [str(item) for item in list(prefix) + [str(c) for c in command]]

    @staticmethod
    def _isolation_header(info: Mapping) -> str:
        """日志头：**实际**隔离事实；没有这一行就没法复核“到底在哪儿跑的”。"""
        doc = dict(info or {})
        return ("# isolation: mode={mode} network={network} cap_drop={cap} "
                "ro_root={ro} pidns={pidns} no_new_privs={nnp}\n").format(
            mode=doc.get("mode") or "none", network=doc.get("network") or "host",
            cap=bool(doc.get("cap_drop")), ro=bool(doc.get("ro_root")),
            pidns=bool(doc.get("pidns")), nnp=bool(doc.get("no_new_privs")))

    def _record_isolation(self, *, stage: str, record_id: str,
                          revision_id: str, argv: Iterable[str],
                          info: Mapping, executed: bool,
                          evidence_sha256: str = "") -> dict:
        """把一次执行的隔离事实追加进台账（只增不改，可复核）。"""
        row = {
            "schema": ISOLATION_LEDGER_SCHEMA, "schema_version": SCHEMA_VERSION,
            "stage": str(stage), "record_id": str(record_id),
            "revision_id": str(revision_id), "task_id": self.task_id,
            "argv": [str(item) for item in argv],
            "evidence_sha256": str(evidence_sha256 or ""),
            **_observed_isolation_facts(info, argv, executed=executed),
            "at": now(),
        }
        with (self.root / ISOLATION_LEDGER).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return row

    def isolation_ledger(self) -> list[dict]:
        """已记录的**实际**执行隔离事实（坏行跳过，不伪造）。

        旧台账里可能留着 `unshare` 时代自称 `executed_isolated=True` 的行。
        读取时按**当前**强隔离口径复算 `qualified`/`strong`/`executed_isolated`，
        文件本身不改（台账只增不改）——历史行不能靠旧字段把弱隔离洗成隔离执行。
        """
        path = self.root / ISOLATION_LEDGER
        if not path.is_file():
            return []
        rows: list[dict] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text:
                continue
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(doc, dict):
                continue
            row = dict(doc)
            mode = str(row.get("isolation") or "")
            strong = mode in STRONG_ISOLATION_MODES
            row.update(_strong_flags(mode))
            row["executed_isolated"] = bool(
                row.get("executed_isolated")) and strong
            rows.append(row)
        return rows

    def isolation_facts_for(self, record_id: str) -> dict:
        """某条 build/smoke 记录的**实际**隔离事实（台账是唯一出处）。"""
        rid = str(record_id or "")
        for row in reversed(self.isolation_ledger()):
            if rid and str(row.get("record_id") or "") == rid:
                return dict(row)
        return {}

    # ------------------------------------------------------------------ 配置面
    @property
    def config_mode(self) -> str:
        """`config`（origin 有配置面，写入受白名单约束）| `generator`（第 1 周行为）。"""
        mode = str(self._config_mode or "")
        if mode in CONFIG_MODES:
            return mode
        return (CONFIG_MODE_CONFIG if ConfigSurface.detect(self.origin_dir)
                else CONFIG_MODE_GENERATOR)

    def config_surface_at(self, area: str = CURRENT) -> ConfigSurface | None:
        """指定区域的配置面（`current` 看工作副本，`origin` 看基线原件）。

        generator 模式 → `None`：没有目录清单就无从校验，也不假装有。
        """
        if self.config_mode != CONFIG_MODE_CONFIG:
            return None
        return ConfigSurface.load(self.root / area)

    @property
    def config_surface(self) -> ConfigSurface | None:
        """当前工作副本的配置面（`None` = 这个任务没有配置面）。"""
        return self.config_surface_at(CURRENT)

    def stage_config(self, doc, *, reason: str = "",
                     grant: Iterable[str] | None = None) -> StageResult:
        """显式配置变更入口：白名单校验通过才写 `config/active.json`。

        两种模式都可调，但**必须有配置面**（generator 模式 → `config_invalid`）：
        没有样例目录/观测点目录，"这个 id 存在不存在"根本无从判断。
        """
        self._write_guard(grant)
        surface = self.config_surface
        if surface is None:
            raise ConfigError(
                f"config_invalid: 工作区没有配置面（缺 {SAMPLES_RELPATH} / "
                f"{POINTS_RELPATH}），无法按白名单校验")
        validated = surface.validate(surface.parse(doc))
        new_sha = surface.sha256(validated)
        if new_sha and new_sha == self.active_config_sha256():
            raise WorkspaceError(
                f"no_change: 新配置与当前配置完全相同（{CONFIG_RELPATH}）")
        return self._stage_files({CONFIG_RELPATH: surface.canonical(validated)},
                                 reason=reason)

    def active_config_doc(self) -> dict:
        """工作副本里的**当前选择**（读盘；generator/缺失/坏 JSON → `{}`）。

        每次调用都重新读：`commit()`/`revert()` 之后工作区已经变了，
        计划侧不能吃构造时的旧快照（`docs/V3-W2-CONFIG.md` §1.2：以当前副本为基线）。
        """
        if self.config_mode != CONFIG_MODE_CONFIG:
            return {}
        surface = self.config_surface
        return dict(surface.active) if surface is not None else {}

    def active_config_sha256(self) -> str:
        """工作副本里那一版配置 = **计划版本**的唯一来源。

        缺失/坏 JSON/ generator 模式 → `""`（没观测到这一版），绝不回填别的值。
        """
        if self.config_mode != CONFIG_MODE_CONFIG:
            return ""
        return _config_file_sha(self.current_dir / CONFIG_RELPATH)

    def baseline_config_sha256(self) -> str:
        """任务基线（origin）那一刻的配置版本；generator 模式 → `""`。"""
        if self.config_mode != CONFIG_MODE_CONFIG:
            return ""
        if self._baseline_config_sha256:
            return self._baseline_config_sha256
        return _config_file_sha(self.origin_dir / CONFIG_RELPATH)

    def config_integrity(self) -> dict:
        """复核配置面：原件哈希对齐基线 revision + 目录清单未被改 + active 在白名单内。

        全部是**算出来的**：原件三份文件逐字节对基线 manifest，样例目录/观测点目录
        在 origin 与 current 之间逐字节一致，当前 `active.json` 过一遍白名单校验。
        """
        mode = self.config_mode
        surface = self.config_surface
        if mode != CONFIG_MODE_CONFIG:
            return {"ok": True, "mode": mode, "problems": [],
                    "active_config_sha256": "", "baseline_config_sha256": "",
                    "config_relpath": CONFIG_RELPATH, "samples": [],
                    "observation_points": [], "keys": []}
        problems: list[str] = []
        origin = self.config_surface_at(ORIGIN)
        if origin is not None:
            problems.extend(f"origin:{item}" for item in origin.problems)
        if surface is not None:
            problems.extend(f"current:{item}" for item in surface.problems)
        revisions = self.revisions.all()
        base = revisions[0] if revisions else None
        if base is None:
            problems.append("no_baseline_revision")
        else:
            recorded = {entry.path: entry.sha256 for entry in base.manifest}
            for rel in (SAMPLES_RELPATH, POINTS_RELPATH, CONFIG_RELPATH):
                path = self.origin_dir / rel
                if path.is_file():
                    if recorded.get(rel) is None:
                        problems.append(f"unregistered:{rel}")
                    elif sha256_bytes(path.read_bytes()) != recorded[rel]:
                        problems.append(f"changed:{rel}")
                elif recorded.get(rel) is not None:
                    problems.append(f"missing:{rel}")
        for rel in CONFIG_SOURCE_PATHS:
            left, right = self.origin_dir / rel, self.current_dir / rel
            if (left.is_file() and right.is_file()
                    and sha256_bytes(left.read_bytes()) != sha256_bytes(right.read_bytes())):
                problems.append(f"diverged:{rel}")
        active_path = self.current_dir / CONFIG_RELPATH
        if surface is not None and active_path.is_file():
            try:
                surface.validate(surface.parse(active_path.read_text(encoding="utf-8")))
            except ConfigError as exc:
                problems.append(f"active:{exc}")
        return {"ok": not problems, "mode": mode, "problems": problems,
                "active_config_sha256": self.active_config_sha256(),
                "baseline_config_sha256": self.baseline_config_sha256(),
                "config_relpath": CONFIG_RELPATH,
                "samples": list(surface.sample_ids()) if surface else [],
                "observation_points": list(surface.point_ids()) if surface else [],
                "keys": sorted(surface.active) if surface else []}

    # ------------------------------------------------------------------ stage
    def stage(self, files: Mapping[str, str | bytes], *,
              grant: Iterable[str] | None = None,
              reason: str = "") -> StageResult:
        """把候选修改写进 `current/`（只写副本，不碰原件/历史 revision）。

        配置模式下它就是白名单入口：只有 `config/active.json` 能写，别的路径一律
        `config_path_not_whitelisted`（整次调用拒绝，一个字节都不写）；写
        `config/active.json` 时和 `stage_config()` 走同一条校验。generator 模式
        行为与第 1 周完全一致。
        """
        self._write_guard(grant)
        if not files:
            return StageResult()
        if self.config_mode == CONFIG_MODE_CONFIG:
            return self._stage_in_config_mode(files, reason=reason)
        return self._stage_files(files, reason=reason)

    def _stage_in_config_mode(self, files: Mapping[str, str | bytes], *,
                              reason: str = "") -> StageResult:
        """配置模式：路径先过白名单（差异集合），再按配置校验写盘。"""
        outside: list[str] = []
        payload = None
        for path, data in files.items():
            rel = safe_relpath(path)
            if rel in CONFIG_WRITABLE_PATHS:
                payload = data
            else:
                outside.append(rel)
        if outside:
            raise ConfigError(
                f"config_path_not_whitelisted: 配置模式只允许改 "
                f"{CONFIG_RELPATH}，拒绝 {sorted(outside)}")
        if payload is None:                     # pragma: no cover - files 非空即不可达
            raise ConfigError(f"config_invalid: 没有 {CONFIG_RELPATH} 的内容")
        return self.stage_config(payload, reason=reason)

    def _stage_files(self, files: Mapping[str, str | bytes], *,
                     reason: str = "") -> StageResult:
        """真正落盘：写 `current/`，返回每个文件 before/after 哈希。"""
        staged: list[dict] = []
        for path, data in files.items():
            rel = safe_relpath(path)
            payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            target = self.current_dir / rel
            before = target.read_bytes() if target.is_file() else None
            _write_file(target, payload, mode=0o644)
            staged.append({
                "path": rel,
                "before_sha256": sha256_bytes(before) if before is not None else "",
                "after_sha256": sha256_bytes(payload),
                "size": len(payload),
                "created": before is None,
            })
        self._staged_reason = str(reason or "")
        return StageResult(staged=tuple(staged), count=len(staged),
                           changed_paths=tuple(item["path"] for item in staged))

    def commit(self, *, reason: str, hypothesis_id: str = "",
               action_id: str = "", tool: str = "",
               environment: Mapping | None = None) -> HarnessRevision:
        """把当前工作副本登记成新 revision（内容相同 → `no_change`）。

        配置模式下多做一次**差异守卫**：`changed_against(parent)` 必须落在
        `{config/active.json}` 里，否则 `config_source_edit_forbidden`——即使有人
        绕过 `stage()` 直接改了 `current/`，也进不了 revision。
        """
        parent = self.current_revision()
        manifest = self.working_manifest()
        digest = manifest_sha256(manifest)
        if parent is not None and digest == parent.manifest_sha256:
            raise WorkspaceError("no_change: 工作副本与当前 revision 完全相同")
        before = self._read_snapshot(parent) if parent else {}
        after = read_tree(self.current_dir)
        diff = unified_diff(before=before, after=after)
        env = dict(environment or {})
        env.setdefault("toolchain", self.toolchain)
        if self.config_mode == CONFIG_MODE_CONFIG:
            # 配置身份进 revision.environment：换配置必然换 revision id
            env["active_config_sha256"] = self.active_config_sha256()
            env["baseline_config_sha256"] = self.baseline_config_sha256()
        revision = HarnessRevision.create(
            manifest=manifest, diff=diff, reason=reason, parent=parent,
            hypothesis_id=hypothesis_id, action_id=action_id, tool=tool,
            environment=env)
        if self.config_mode == CONFIG_MODE_CONFIG and parent is not None:
            # 差异守卫：绕过 stage() 直接改 current/ 也进不了 revision
            # （差异集合 ⊆ {config/active.json}，否则原件/源码被动了）
            outside = sorted(set(revision.changed_against(parent))
                             - set(CONFIG_WRITABLE_PATHS))
            if outside:
                raise ConfigError(
                    f"config_source_edit_forbidden: 配置模式只允许改 "
                    f"{CONFIG_RELPATH}，本次改动了 {outside}")
        self.revisions.add(revision)
        self._snapshot(revision)
        self.revisions.set_current(revision.revision_id)
        self.revisions.note_invalidations(
            CHANGE_INVALIDATIONS["harness"],
            source=f"commit:{revision.revision_id}")
        return revision

    # ------------------------------------------------------------------ 回退
    def revert(self, to_revision: str = "", *, reason: str = "",
               grant: Iterable[str] | None = None,
               environment: Mapping | None = None) -> HarnessRevision:
        """选择父/指定 revision，把工作树重建回去；登记新 revision，旧的不改。"""
        self._write_guard(grant)
        current = self.current_revision()
        if current is None:
            raise WorkspaceError("没有当前 revision，无法回退")
        if to_revision:
            target = self.revisions.get(to_revision)
        else:
            if not current.parent_id:
                raise WorkspaceError("当前是初始 revision，没有父版本可回退")
            target = self.revisions.get(current.parent_id)
        if target.revision_id == current.revision_id:
            raise WorkspaceError("no_change: 回退目标就是当前 revision")
        if target.manifest_sha256 == current.manifest_sha256:
            raise WorkspaceError("no_change: 回退目标内容与当前一致")

        target_files = self._read_snapshot(target)
        if not target_files and target.manifest:
            raise WorkspaceError(
                f"revision 快照缺失：{target.revision_id}（旧版本不可重建）")
        # 真实重建工作树：先清空再按 manifest 落盘
        self._restore_tree(target_files)
        state = self.revisions.verify_manifest(target.revision_id,
                                              self.root / REVISIONS / target.revision_id)
        if not state["ok"]:
            raise WorkspaceError(
                f"目标 revision 快照已损坏：{state['problems']}")
        working = manifest_sha256(self.working_manifest())
        if working != target.manifest_sha256:
            raise WorkspaceError("回退后工作树与目标 manifest 不一致")

        env = dict(environment or {})
        env.setdefault("toolchain", self.toolchain)
        if self.config_mode == CONFIG_MODE_CONFIG:
            # 工作树已经重建回目标版本 → 配置身份就是目标那一版（算出来的）
            env["active_config_sha256"] = self.active_config_sha256()
            env["baseline_config_sha256"] = self.baseline_config_sha256()
        revision = HarnessRevision.create(
            manifest=target.manifest,
            diff=unified_diff(before=self._read_snapshot(current),
                              after=target_files),
            reason=(f"revert to {target.revision_id}"
                    + (f": {reason}" if reason else "")),
            parent=current, reverted_to=target.revision_id,
            tool="workspace.revert", environment=env)
        self.revisions.add(revision)
        self._snapshot(revision)
        self.revisions.set_current(revision.revision_id)
        self.revisions.note_invalidations(
            CHANGE_INVALIDATIONS["harness"],
            source=f"revert:{revision.revision_id}")
        return revision

    # ------------------------------------------------------------------ 构建
    def build(self, revision: str | HarnessRevision | None = None, *,
              grant: Iterable[str] | None = None,
              timeout: float | None = None) -> BuildRecord:
        """在**强隔离执行器**里真实执行构建命令，返回带日志哈希的构建事实。

        顺序是硬约束：先解析隔离（不是强隔离就 `WorkspaceError(
        strong_isolation_required)`，工作副本复制都不做、进程一个都不起），
        再复制快照、再 spawn。计划里的隔离模式只在 policy 里；记录里的隔离事实
        来自**本次**实际解析结果与是否真 spawn。
        """
        self._write_guard(grant)
        # 强隔离闸最先：弱隔离下连 revision/命令校验都不做，更不复制快照、不 spawn
        info = self._resolve_isolation()
        rev = self._resolve_revision(revision)
        if not self.build_command:
            raise WorkspaceError("setup_error: 未配置 build_command，不能假装构建")
        budget = float(timeout if timeout is not None else self.build_timeout)
        snapshot_dir = self.root / REVISIONS / rev.revision_id
        index = len(self.revisions.builds(rev.revision_id)) + 1
        workdir = self.root / BUILDS / f"{rev.revision_id}-{index:02d}"
        if workdir.exists():
            shutil.rmtree(workdir)
        _copy_tree(snapshot_dir, workdir, mode=0o644)

        cmd = list(self.build_command)
        env = _clean_env({}, home=self.root / "home")
        argv = self._isolated_argv(info, cmd, workdir=workdir, env=env)
        build_id = build_identity(
            manifest_sha=rev.manifest_sha256, command=cmd,
            toolchain=self.toolchain,
            env_digest=hashlib.sha256(
                json.dumps(env, sort_keys=True).encode()).hexdigest())
        started_at = now()
        clock = time.monotonic()
        status = "failed"
        exit_code: int | None = None
        error = ""
        output = ""
        spawned = False
        try:
            proc = subprocess.run(
                argv, cwd=str(workdir), capture_output=True, text=True,
                timeout=budget, env=env, shell=False, check=False,
                preexec_fn=sandbox.preexec(info, budget))
            spawned = True
            exit_code = int(proc.returncode)
            output = _combined(proc.stdout, proc.stderr, "BUILD")
            if exit_code == 0:
                status = "ok"
            elif exit_code in SETUP_ERROR_CODES:
                status = "setup_error"
                error = f"executable_unavailable:{exit_code}"
            else:
                status = "failed"
                error = f"build_exit:{exit_code}"
        except subprocess.TimeoutExpired as exc:
            spawned = True
            status = "timeout"
            exit_code = 124
            output = _combined(_text(exc.stdout), _text(exc.stderr), "BUILD")
            error = f"timeout:{budget}s"
        except OSError as exc:
            status = "setup_error"
            error = f"spawn_error:{type(exc).__name__}: {exc}"
            output = error
        duration = time.monotonic() - clock
        log_path, log_sha, log_bytes, truncated = self._write_log(
            f"{rev.revision_id}-build-{index:02d}.log",
            self._isolation_header(info) + output)
        facts = _observed_isolation_facts(info, argv, executed=spawned)
        record = IsolatedBuildRecord(
            build_id=build_id, revision_id=rev.revision_id, status=status,
            command=tuple(cmd), exit_code=exit_code, duration=round(duration, 4),
            log_path=str(log_path), log_sha256=log_sha, log_bytes=log_bytes,
            truncated=truncated, toolchain=self.toolchain,
            workdir=str(workdir), started_at=started_at, finished_at=now(),
            error=error, **facts)
        self.revisions.record_build(record)
        self._record_isolation(
            stage="build", record_id=build_id, revision_id=rev.revision_id,
            argv=argv, info=info, executed=spawned, evidence_sha256=log_sha)
        return record

    def smoke(self, revision: str | HarnessRevision | None = None, *,
              build: BuildRecord | None = None,
              grant: Iterable[str] | None = None,
              timeout: float | None = None) -> SmokeRecord:
        """在**强隔离**里对构建产物真实执行冒烟；harness 自崩与目标行为严格分开。

        冒烟的隔离同样先解析、后执行：解析结果不是 `bwrap`/`container` 就在
        spawn 前 `strong_isolation_required`（显式 `unshare` 与 auto 降级都拒绝）。
        目标产物必须是**强隔离内构建**出来的（台账/记录里
        `executed_isolated=True`），否则要求隔离时直接拒绝——宿主/弱隔离上构建
        的产物拿到强隔离里冒烟，等于把别处的执行混进隔离结论。
        """
        self._write_guard(grant)
        # 强隔离闸最先：弱隔离下不读构建记录、不 spawn——冒烟没有“弱隔离入口”
        info = self._resolve_isolation()
        rev = self._resolve_revision(revision)
        record = build or self.revisions.latest_build(rev.revision_id)
        if record is None:
            raise WorkspaceError("setup_error: 没有构建记录，不能冒烟")
        if not record.ok:
            raise WorkspaceError(
                f"setup_error: 构建状态 {record.status}，冒烟没有意义")
        if not self.smoke_command:
            raise WorkspaceError("setup_error: 未配置 smoke_command")
        workdir = Path(record.workdir)
        if not workdir.is_dir():
            raise WorkspaceError(f"setup_error: 构建目录不存在：{workdir}")
        budget = float(timeout if timeout is not None else self.smoke_timeout)
        build_facts = self.isolation_facts_for(record.build_id) or \
            getattr(record, "isolation_facts", dict)()
        if self.require_isolation and not bool(
                build_facts.get("executed_isolated")):
            raise WorkspaceError(
                "isolation_violation: "
                f"build={record.build_id} 没有实际隔离执行（executed_isolated="
                f"{bool(build_facts.get('executed_isolated'))}），"
                "不能在隔离里把它当构建产物")
        index = len(self.revisions.smokes(rev.revision_id)) + 1
        env = _clean_env({}, home=self.root / "home")
        argv = self._isolated_argv(info, self.smoke_command, workdir=workdir,
                                   env=env)
        started_at = now()
        clock = time.monotonic()
        status = "failed"
        kind = "target"
        detail = ""
        exit_code: int | None = None
        output = ""
        spawned = False
        try:
            proc = subprocess.run(
                argv, cwd=str(workdir), capture_output=True, text=True,
                timeout=budget, env=env, shell=False, check=False,
                preexec_fn=sandbox.preexec(info, budget))
            spawned = True
            exit_code = int(proc.returncode)
            output = _combined(proc.stdout, proc.stderr, "SMOKE")
            status, kind, detail = classify_smoke(exit_code, output)
        except subprocess.TimeoutExpired as exc:
            spawned = True
            status, kind = "timeout", "timeout"
            exit_code = 124
            output = _combined(_text(exc.stdout), _text(exc.stderr), "SMOKE")
            detail = "smoke_timeout"
        except OSError as exc:
            status, kind = "setup_error", "setup_error"
            detail = f"spawn_error:{type(exc).__name__}: {exc}"
            output = detail
        duration = time.monotonic() - clock
        log_path, log_sha, log_bytes, truncated = self._write_log(
            f"{rev.revision_id}-smoke-{index:02d}.log",
            self._isolation_header(info) + output)
        smoke_id = "sm-" + sha256_bytes(
            f"{rev.revision_id}|{record.build_id}|{index}|{started_at}".encode()
        )[:16]
        facts = _observed_isolation_facts(info, argv, executed=spawned)
        smoke = IsolatedSmokeRecord(
            smoke_id=smoke_id, revision_id=rev.revision_id,
            build_id=record.build_id, status=status, exit_code=exit_code,
            duration=round(duration, 4), log_path=str(log_path),
            log_sha256=log_sha, log_bytes=log_bytes, truncated=truncated,
            kind=kind, detail=detail, started_at=started_at, finished_at=now(),
            **facts)
        self.revisions.record_smoke(smoke)
        self._record_isolation(
            stage="smoke", record_id=smoke_id, revision_id=rev.revision_id,
            argv=argv, info=info, executed=spawned, evidence_sha256=log_sha)
        return smoke

    # ------------------------------------------------------------------ 内部
    def _resolve_revision(self, revision: str | HarnessRevision | None
                          ) -> HarnessRevision:
        if isinstance(revision, HarnessRevision):
            return self.revisions.get(revision.revision_id)
        if revision:
            return self.revisions.get(str(revision))
        current = self.current_revision()
        if current is None:
            raise WorkspaceError("没有当前 revision")
        return current

    def _snapshot(self, revision: HarnessRevision) -> Path:
        target = self.root / REVISIONS / revision.revision_id
        if target.exists():
            state = self.revisions.verify_manifest(revision.revision_id, target)
            if not state["ok"]:
                raise WorkspaceError(
                    f"旧 revision 快照被改：{state['problems']}")
            return target
        files = read_tree(self.current_dir) if revision.parent_id else \
            read_tree(self.origin_dir)
        if manifest_sha256(manifest_of(files, mode=CONTENT_MODE)) != revision.manifest_sha256:
            # 以 manifest 为准逐文件落盘，避免“current 里多出未登记文件”
            files = self._files_for(revision)
        if manifest_sha256(manifest_of(files, mode=CONTENT_MODE)) != revision.manifest_sha256:
            raise WorkspaceError("快照内容与 revision manifest 不一致")
        for rel, data in files.items():
            _write_file(target / rel, data, mode=0o444)
        return target

    def _files_for(self, revision: HarnessRevision) -> dict[str, bytes]:
        """按 manifest 从 current/origin 取字节（只取登记过的文件）。"""
        pool = {}
        for area in (self.current_dir, self.origin_dir):
            if not area.is_dir():
                continue
            for rel in [entry.path for entry in revision.manifest]:
                path = area / rel
                if path.is_file():
                    pool[rel] = path.read_bytes()
        missing = [e.path for e in revision.manifest if e.path not in pool]
        if missing:
            raise WorkspaceError(f"revision 缺少文件：{missing}")
        return {e.path: pool[e.path] for e in revision.manifest}

    def _read_snapshot(self, revision: HarnessRevision | None) -> dict[str, bytes]:
        if revision is None:
            return {}
        path = self.root / REVISIONS / revision.revision_id
        if not path.is_dir():
            raise WorkspaceError(f"revision 快照不存在：{revision.revision_id}")
        return read_tree(path)

    def _restore_tree(self, files: Mapping[str, bytes]) -> None:
        shutil.rmtree(self.current_dir, ignore_errors=True)
        self.current_dir.mkdir(parents=True, exist_ok=True)
        for rel, data in files.items():
            _write_file(self.current_dir / rel, data, mode=0o644)

    def _write_log(self, name: str, text: str) -> tuple[Path, str, int, bool]:
        body, truncated = _truncate(text)
        path = self.root / LOGS / name
        path.write_text(body, encoding="utf-8")
        raw = body.encode("utf-8")
        return path, sha256_bytes(raw), len(raw), truncated

    # ------------------------------------------------------------------ 复核
    def verify(self, revision: str | HarnessRevision | None = None) -> dict:
        rev = self._resolve_revision(revision)
        snap = self.revisions.verify_manifest(
            rev.revision_id, self.root / REVISIONS / rev.revision_id)
        origin = self.origin_integrity()
        return {"revision": snap, "origin": origin,
                "ok": bool(snap["ok"] and origin["ok"])}


def classify_smoke(exit_code: int, output: str) -> tuple[str, str, str]:
    """冒烟退出码/输出 → (status, kind, detail)。

    `kind` 只有三类：`target`（目标侧行为不符）、`harness_error`（装置坏了）、
    `setup_error`（环境没装好）。harness 自崩绝不能算“目标没问题/有问题”。
    """
    code = int(exit_code)
    text = output or ""
    if code == 0:
        return "passed", "", ""
    for marker in HARNESS_ERROR_MARKERS:
        if marker in text:
            line = next((ln for ln in reversed(text.splitlines())
                         if marker in ln), marker)
            return "harness_error", "harness_error", line.strip()[:300]
    if code in SETUP_ERROR_CODES:
        return "setup_error", "setup_error", f"executable_unavailable:{code}"
    if code in HARNESS_ERROR_CODES:
        return "harness_error", "usage_error", f"smoke_usage_error:{code}"
    return "failed", "target", f"smoke_exit:{code}"


def _combined(stdout, stderr, tag: str) -> str:
    out = _text(stdout)
    err = _text(stderr)
    return (f"[{tag} stdout]\n{out}\n[{tag} stderr]\n{err}\n")


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _write_file(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, mode)


def _copy_tree(src: Path, dst: Path, *, mode: int) -> None:
    files = read_tree(src)
    for rel, data in files.items():
        _write_file(dst / rel, data, mode=mode)


__all__ = [
    "BUILD_TIMEOUT",
    "CONFIG_ACTIVE_SCHEMA",
    "CONFIG_KEYS",
    "CONFIG_MODES",
    "CONFIG_MODE_CONFIG",
    "CONFIG_MODE_GENERATOR",
    "CONFIG_RELPATH",
    "CONFIG_SOURCE_PATHS",
    "CONFIG_WRITABLE_PATHS",
    "DEFAULT_ISOLATION",
    "DEFAULT_REQUIRE_ISOLATION",
    "HARNESS_ERROR_CODES",
    "HARNESS_ERROR_MARKERS",
    "ISOLATION_FACT_KEYS",
    "ISOLATION_LEDGER",
    "ISOLATION_LEDGER_SCHEMA",
    "ISOLATION_MODES",
    "MAX_FILES",
    "MAX_LOG_BYTES",
    "POINTS_RELPATH",
    "POINT_CATALOG_SCHEMA",
    "QUALIFIED_ISOLATION_MODES",
    "STRONG_ISOLATION_MODES",
    "LOW_ASSURANCE_ISOLATION_MODES",
    "SAMPLES_RELPATH",
    "SAMPLE_CATALOG_SCHEMA",
    "SCHEMA",
    "SCHEMA_VERSION",
    "SECRET_MARKERS",
    "SETUP_ERROR_CODES",
    "SKIP_DIRS",
    "SMOKE_TIMEOUT",
    "ConfigError",
    "ConfigSurface",
    "IsolatedBuildRecord",
    "IsolatedSmokeRecord",
    "StageResult",
    "TaskWorkspace",
    "WorkspaceError",
    "classify_smoke",
    "config_path_allowed",
    "read_tree",
]
