"""V3-004：持久语料（Corpus）与构建身份。

口径（对应《V3 完整升级方案》第 7 节「种子与语料」）：

- **按 task/campaign 维度落盘**：`root/<campaign>/<task>/`，跨轮复用，
  不再每轮 `_fresh_dir` 把语料扔掉；
- **内容寻址**：成员字节按 sha256 存放（`entries/<sha256>`），
  active 目录里只放 `seed-<sha256[:16]>`，与 Discovery fuzz 的命名一致；
- **manifest 可反查父假设**：每条成员记录
  `sha256 / size / hypothesis_id / site_id / source / origin / parent_sha256`；
- **语料版本与哈希**：`generation` 单调递增，`corpus_hash` 只对成员
  `(sha256,size)` 排序后取哈希（纯内容，不含构建身份）；
- **构建身份变化 = stale**：`build_id`（binary sha256 + build spec 摘要）
  与上一代不一致时，把上一代 active 语料整体归档到 `history/`，
  清空 active 后重建；两代语料绝不在同一 active 目录里混用，
  旧覆盖位图自然不可沿用；
- **只归档不删除**：历史语料原件与崩溃输入都保留（§7 明确不能因为
  minimize corpus 就把它们删掉）。

本模块只做语料的存取与身份判定，不判定漏洞、不调 LLM。
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "vulnmap.corpus.v1"
SCHEMA_VERSION = 1

#: manifest 里保留的成员字段（写入时按此裁剪，避免把任意元数据塞进盘）
_MEMBER_KEYS = ("sha256", "size", "hypothesis_id", "site_id", "source",
                "origin", "parent_sha256", "format", "basis", "added_at")


class CorpusError(RuntimeError):
    """语料目录不可用/身份不明：宁可失败，也不混用两代语料。"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slug(value: str) -> str:
    """把 task/campaign 名变成安全的单层目录名（不做路径穿越）。"""
    text = str(value or "").strip()
    if not text:
        return "default"
    safe = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in text)
    return safe.strip(".-") or "default"


def _spec_digest(spec: dict | None) -> str:
    """构建 spec 的稳定摘要：只取身份相关字段，忽略 workdir 之类运行期路径。"""
    if not isinstance(spec, dict):
        return ""
    drop = {"workdir", "out_name", "verbose", "timeout"}
    payload = {k: v for k, v in sorted(spec.items()) if k not in drop}
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return _sha256(text.encode("utf-8"))


def build_identity(spec: dict | None = None, *, binary_sha256: str = "",
                   harness: str = "", target: str = "",
                   extra: dict | None = None) -> dict:
    """组装并归一化一次构建的身份。

    `build_id` 同时覆盖 **build spec 摘要** 与 **binary sha256**：
    任一项变化（换源码、换 flags、换镜像/工具链、换 sanitizer 后的产物）
    都会得到新的 build_id，从而触发语料失效重建。
    """
    binary = str(binary_sha256 or "")
    spec_hash = _spec_digest(spec)
    payload = {"spec_hash": spec_hash, "binary_sha256": binary}
    if extra:
        payload["extra"] = {k: extra[k] for k in sorted(extra)}
    digest = _sha256(json.dumps(payload, sort_keys=True,
                                ensure_ascii=False, default=str).encode("utf-8"))
    return {
        "build_id": f"b{digest[:20]}",
        "binary_sha256": binary,
        "spec_hash": spec_hash,
        "harness": str(harness or ""),
        "target": str(target or ""),
        "extra": dict(extra or {}),
    }


def _normalize_identity(identity: dict | None) -> dict:
    if not isinstance(identity, dict):
        raise CorpusError("corpus.begin requires a build identity dict")
    build_id = str(identity.get("build_id") or "")
    if not build_id:
        raise CorpusError("build identity missing build_id")
    return {
        "build_id": build_id,
        "binary_sha256": str(identity.get("binary_sha256") or ""),
        "spec_hash": str(identity.get("spec_hash") or ""),
        "harness": str(identity.get("harness") or ""),
        "target": str(identity.get("target") or ""),
        "extra": dict(identity.get("extra") or {}),
    }


class CorpusStore:
    """一个 (campaign, task) 维度的持久语料库。

    目录布局::

        <root>/<campaign>/<task>/
            manifest.json          成员台账（含构建身份与 generation）
            active/                fuzz 直接读写的语料目录（跨轮保留）
            entries/<sha256>       原始字节（按内容寻址，只增不改）
            history/<gen>-<build>/ 失效代归档：manifest.json + active/
    """

    def __init__(self, root: Path | str, *, task_id: str = "",
                 campaign: str = "") -> None:
        self.base = Path(root)
        self.task_id = str(task_id or "")
        self.campaign = str(campaign or "")
        self.root = self.base / _slug(self.campaign) / _slug(self.task_id)
        self.manifest_path = self.root / "manifest.json"
        self.active_dir = self.root / "active"
        self.entries_dir = self.root / "entries"
        self.history_dir = self.root / "history"
        self._manifest: dict | None = None

    # ------------------------------------------------------------ manifest
    def _ensure_dirs(self) -> None:
        for path in (self.root, self.active_dir, self.entries_dir,
                     self.history_dir):
            path.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict | None:
        """读 manifest；损坏的台账直接报错，不猜也不覆盖。"""
        if self._manifest is not None:
            return self._manifest
        if not self.manifest_path.is_file():
            return None
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CorpusError(
                f"corpus manifest unreadable: {self.manifest_path}: {exc}") from exc
        if not isinstance(data, dict) or data.get("schema") != SCHEMA:
            raise CorpusError(
                f"corpus manifest schema mismatch: {self.manifest_path}")
        data.setdefault("members", {})
        data.setdefault("generation", 1)
        self._manifest = data
        return data

    def reload(self) -> dict | None:
        """丢掉进程内缓存，从磁盘重新读 manifest。

        用途：同一任务里还有别的写者（fuzz 执行器会用它自己的构建身份再
        `begin()` 一次），外部写完以后端口要能读到磁盘真相，而不是自己那份
        内存快照。读不到就是 `None`，不编造。
        """
        self._manifest = None
        return self.load()

    def _write(self) -> None:
        if self._manifest is None:
            raise CorpusError("corpus manifest not initialised")
        self._manifest["updated_at"] = _now()
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._manifest, ensure_ascii=False,
                                  indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
        tmp.replace(self.manifest_path)

    def _empty_manifest(self, identity: dict, *, generation: int,
                        stale: dict | None) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "task_id": self.task_id,
            "campaign": self.campaign,
            "generation": int(generation),
            "build": identity,
            "members": {},
            "stale": stale,
            "created_at": _now(),
            "updated_at": _now(),
        }

    # ------------------------------------------------------------ lifecycle
    def begin(self, identity: dict) -> dict:
        """按构建身份开一轮：复用 / 首建 / 失效重建。

        返回 `{"status": "fresh|reused|rebuilt", "stale": bool,
        "reasons": [...], "corpus_before": snapshot, "generation": int}`。
        `rebuilt` 时上一代 active 语料已整体归档，active 目录为空。
        """
        identity = _normalize_identity(identity)
        previous = self.load()
        reasons: list[str] = []
        stale: dict | None = None
        previous_snapshot: dict | None = None
        status = "fresh"
        if previous is None:
            self._manifest = self._empty_manifest(identity, generation=1,
                                                  stale=None)
        else:
            old_build = previous.get("build") or {}
            old_id = str(old_build.get("build_id") or "")
            if not old_id:
                # 老台账没有身份：当不可复用处理，但要留原因
                reasons.append("previous manifest has no build identity")
            elif old_id != identity["build_id"]:
                old_bin = str(old_build.get("binary_sha256") or "")
                if old_bin != identity["binary_sha256"]:
                    reasons.append(
                        "binary sha256 changed: "
                        f"{(old_bin or 'none')[:12]} -> "
                        f"{(identity['binary_sha256'] or 'none')[:12]}")
                old_spec = str(old_build.get("spec_hash") or "")
                if old_spec != identity["spec_hash"]:
                    reasons.append(
                        "build spec changed: "
                        f"{(old_spec or 'none')[:12]} -> "
                        f"{(identity['spec_hash'] or 'none')[:12]}")
                if not reasons:
                    reasons.append(
                        f"build_id changed: {old_id[:12]} -> "
                        f"{identity['build_id'][:12]}")
            else:
                status = "reused"

            if status == "reused":
                previous["build"] = identity
                previous["stale"] = None
                self._manifest = previous
            else:
                status = "rebuilt"
                previous_snapshot = self._snapshot(previous)
                archived = self._archive(previous)
                stale = {
                    "at": _now(),
                    "from_build_id": old_id,
                    "reasons": list(reasons),
                    "archived_to": archived,
                }
                self._manifest = self._empty_manifest(
                    identity,
                    generation=int(previous.get("generation") or 1) + 1,
                    stale=stale)

        self._ensure_dirs()
        self._write()
        return {
            "status": status,
            "stale": status == "rebuilt",
            "reasons": list(reasons),
            "corpus_before": self._snapshot(self._manifest),
            "previous": previous_snapshot,
            "generation": int(self._manifest["generation"]),
            "build_id": identity["build_id"],
        }

    def _archive(self, previous: dict) -> str:
        """归档上一代：manifest 副本 + active 语料整体搬走，不删除。"""
        generation = int(previous.get("generation") or 1)
        build = str((previous.get("build") or {}).get("build_id") or "nobuild")
        dest = self.history_dir / f"gen{generation:03d}-{build[:12]}"
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        stored = dest / "manifest.json"
        stored.write_text(json.dumps(previous, ensure_ascii=False,
                                     indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
        if self.active_dir.exists():
            shutil.move(str(self.active_dir), str(dest / "active"))
        self.active_dir.mkdir(parents=True, exist_ok=True)
        return str(dest)

    # ------------------------------------------------------------ members
    def add(self, data: bytes, *, hypothesis_id: str = "", site_id: str = "",
            source: str = "", origin: str = "seed", parent_sha256: str = "",
            format: str = "", basis: list[str] | None = None) -> dict:
        """写入一条语料成员（内容寻址，重复内容不重复记账）。"""
        if self._manifest is None:
            raise CorpusError("call begin() before add()")
        if not data:
            raise CorpusError("refusing to add empty seed bytes")
        digest = _sha256(data)
        members = self._manifest.setdefault("members", {})
        existing = members.get(digest)
        if isinstance(existing, dict):
            # 同一字节被另一条假设/来源再次提出：保留首次归属，记录来源集合
            sources = list(existing.get("sources") or [])
            if source and source not in sources:
                sources.append(source)
            existing["sources"] = sources
            return {**existing, "duplicate": True}
        self.entries_dir.mkdir(parents=True, exist_ok=True)
        entry_path = self.entries_dir / digest
        if not entry_path.exists():
            entry_path.write_bytes(data)
        self.active_dir.mkdir(parents=True, exist_ok=True)
        active_path = self.active_dir / f"seed-{digest[:16]}"
        if not active_path.exists():
            active_path.write_bytes(data)
        entry = {
            "sha256": digest,
            "size": len(data),
            "hypothesis_id": str(hypothesis_id or ""),
            "site_id": str(site_id or ""),
            "source": str(source or ""),
            "origin": str(origin or ""),
            "parent_sha256": str(parent_sha256 or ""),
            "format": str(format or ""),
            "basis": list(basis or []),
            "added_at": _now(),
            "generation": int(self._manifest.get("generation") or 1),
            "sources": [str(source)] if source else [],
        }
        members[digest] = entry
        return {**entry, "duplicate": False}

    def discover(self, *, origin: str = "fuzzer:coverage") -> list[dict]:
        """把 fuzz 自己写进 active 的新语料登记进台账（无父假设）。"""
        if self._manifest is None:
            raise CorpusError("call begin() before discover()")
        members = self._manifest.setdefault("members", {})
        found: list[dict] = []
        if not self.active_dir.is_dir():
            return found
        for path in sorted(self.active_dir.glob("*")):
            if not path.is_file():
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if not data:
                continue
            digest = _sha256(data)
            if digest in members:
                continue
            members[digest] = {
                "sha256": digest,
                "size": len(data),
                "hypothesis_id": "",
                "site_id": "",
                "source": origin,
                "origin": "discovered",
                "parent_sha256": "",
                "format": "",
                "basis": [],
                "added_at": _now(),
                "generation": int(self._manifest.get("generation") or 1),
                "sources": [origin],
            }
            found.append(members[digest])
        return found

    def resolve(self, sha256: str) -> dict | None:
        """按内容哈希反查成员（→ hypothesis_id/site_id/source）。"""
        manifest = self.load() or {}
        entry = (manifest.get("members") or {}).get(str(sha256 or ""))
        return dict(entry) if isinstance(entry, dict) else None

    def by_hypothesis(self, hypothesis_id: str) -> list[dict]:
        """某条假设派生出的全部语料（含失效代归档之外的当前成员）。"""
        manifest = self.load() or {}
        target = str(hypothesis_id or "")
        out = []
        for entry in (manifest.get("members") or {}).values():
            if isinstance(entry, dict) and entry.get("hypothesis_id") == target:
                out.append(dict(entry))
        out.sort(key=lambda e: (e.get("sha256") or ""))
        return out

    # ------------------------------------------------------------ snapshot
    def snapshot(self) -> dict:
        return self._snapshot(self.load() or {})

    def _snapshot(self, manifest: dict) -> dict:
        members = {k: v for k, v in (manifest.get("members") or {}).items()
                   if isinstance(v, dict)}
        lines = sorted(f"{digest}:{entry.get('size', 0)}"
                       for digest, entry in members.items())
        corpus_hash = _sha256("\n".join(lines).encode("utf-8")) if lines else ""
        hypotheses = sorted({str(e.get("hypothesis_id"))
                             for e in members.values()
                             if e.get("hypothesis_id")})
        build = manifest.get("build") or {}
        return {
            "schema": SCHEMA,
            "corpus_version": int(manifest.get("generation") or 0),
            "corpus_hash": corpus_hash,
            "build_id": str(build.get("build_id") or ""),
            "binary_sha256": str(build.get("binary_sha256") or ""),
            "members": len(members),
            "bytes": sum(int(e.get("size") or 0) for e in members.values()),
            "hypotheses": hypotheses,
            "stale": bool(manifest.get("stale")),
            "path": str(self.active_dir),
            "manifest": str(self.manifest_path),
        }

    def lineage(self, limit: int = 64) -> list[dict]:
        """当前成员的父假设索引（sha256 → hypothesis_id/site_id/source）。"""
        manifest = self.load() or {}
        rows = []
        for digest, entry in (manifest.get("members") or {}).items():
            if not isinstance(entry, dict):
                continue
            rows.append({
                "sha256": digest,
                "size": entry.get("size", 0),
                "hypothesis_id": entry.get("hypothesis_id", ""),
                "site_id": entry.get("site_id", ""),
                "source": entry.get("source", ""),
                "origin": entry.get("origin", ""),
            })
        rows.sort(key=lambda r: (r["hypothesis_id"], r["sha256"]))
        return rows[:int(limit)] if limit else rows

    def finalize(self) -> dict:
        """落盘并返回本轮结束快照（corpus_after）。"""
        if self._manifest is None:
            raise CorpusError("call begin() before finalize()")
        self._write()
        return self.snapshot()


__all__ = ["CorpusError", "CorpusStore", "SCHEMA", "SCHEMA_VERSION",
           "build_identity"]
