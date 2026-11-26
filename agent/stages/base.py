"""阶段基类：预算、检查点、工件落盘、结果校验的统一入口。

检查点语义（真复用，而不是记账）：
- 阶段开始：先算出 binding（镜像 digest + 输入工件 sha + 版本号），
  `load_or_none` 命中且磁盘工件仍与绑定一致 → 直接复用产物，跳过 execute()。
- 阶段结束：把产物 sha 补进 binding 再 `save`，落一条 checkpoints 记录。
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .. import checkpoint as ckpt
from ..budget import BudgetLease
from ..config import resolve as resolve_versions
from ..contracts import OutputContract, StageRequest, StageResult
from ..errors import BudgetExhausted, ContractViolation
from ..paths import ensure_layout
from ..policy import check_tool
from ..store import Store
from ..util import atomic_write_json, sha256_bytes, sha256_file, short_hash
from ..validate import validate_output

TOOL_VERSION = "vulnmap-1.0"


class Stage:
    name = "base"
    role_version = "base-v1"
    prompt_version = "base-p1"
    schema_version = "vulnmap.base.v1"
    # 该阶段产出、并被下游消费的工件（相对工作区路径）；用于检查点绑定
    outputs: tuple[str, ...] = ()

    def __init__(self, store: Store, run_id: str, workspace: Path, request: StageRequest,
                 **options):
        self.store = store
        self.run_id = run_id
        self.ws = Path(workspace).resolve()
        self.layout = ensure_layout(self.ws)
        self.request = request
        self.options = options
        # 版本号以 request 为准（编排器已按配置注入），配置缺失时才回落到类默认值
        if request.prompt_version:
            self.prompt_version = request.prompt_version
        if request.role_version:
            self.role_version = request.role_version
        self.started = time.monotonic()
        self._written: dict[str, dict] = {}
        self._guards: list = []
        self.reused = False
        self.checkpoint_key = ""

    # ---- 子类必须实现 ----
    def execute(self) -> dict:
        raise NotImplementedError

    # ---- 通用能力 ----
    def artifact_path(self, name: str) -> Path:
        p = self.layout["artifacts"] / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if not str(p.resolve()).startswith(str(self.layout["artifacts"].resolve())):
            raise ContractViolation(f"artifact path escapes: {name}")
        return p

    def log_path(self, name: str) -> Path:
        return self.layout["logs"] / name

    def write_artifact(self, name: str, obj: Any | bytes, schema: str = "") -> dict:
        path = self.artifact_path(name)
        if isinstance(obj, (bytes, bytearray)):
            raw = bytes(obj)
        else:
            raw = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        sha = sha256_bytes(raw)
        rel = str(path.relative_to(self.ws))
        self.store.add_artifact(self.run_id, self.name, name.split("/")[0] or name, rel, sha,
                                len(raw), schema, self.role_version)
        self._record_written(f"{self.name}/{name}", rel, sha, len(raw))
        return {"uri": rel, "sha256": sha, "size": len(raw)}

    def _record_written(self, logical: str, rel: str, sha: str, size: int) -> None:
        self._written[logical] = {"uri": rel, "sha256": sha, "size": size}

    def verify_artifact(self, logical_name: str, raw: bytes, guards=None) -> dict:
        """写盘前先过契约校验；未校验的产物不允许入库。"""
        contract = self.request.contract(logical_name) or OutputContract(
            logical_name=logical_name, schema="")
        data = validate_output(raw, contract, guards=guards or self._guards)
        self._guards = []
        return data

    def validate(self, logical_name: str, raw: bytes, guards=None) -> dict:
        return self.verify_artifact(logical_name, raw, guards)

    def allow(self, tool: str) -> None:
        """工具执行前的策略检查；所有工具封装都必须先过这里。"""
        check_tool(self.name, tool)

    def add_guard(self, guard) -> None:
        """注册下一个 validate 要跑的语义 guard（例如上游不可变检查）。"""
        self._guards.append(guard)

    def emit(self, logical_name: str, obj: Any, schema: str = "", guards=None) -> dict:
        """写盘 + 校验的组合：先序列化，再校验，最后落盘。"""
        if isinstance(obj, (bytes, bytearray)):
            raw = bytes(obj)
        else:
            raw = (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        effective = list(guards or []) + self._guards
        self._guards = []
        self.verify_artifact(logical_name, raw, guards=effective or None)
        rel = logical_name
        path = self.artifact_path(rel)
        path.write_bytes(raw)
        sha = sha256_bytes(raw)
        relstr = str(path.relative_to(self.ws))
        self.store.add_artifact(self.run_id, self.name, rel.split("/")[0] or rel, relstr, sha,
                                len(raw), schema or self.schema_version, self.role_version)
        self._record_written(logical_name, relstr, sha, len(raw))
        return {"uri": relstr, "sha256": sha, "size": len(raw)}

    # ---- 检查点 ----
    def input_hashes(self) -> dict[str, str]:
        """本阶段真正读取的输入工件 → sha256。子类覆盖以精确声明。"""
        out: dict[str, str] = {}
        for name in ("task.json", "description.txt", "error.txt", "repo-vul.tar.gz"):
            p = self.ws / name
            if p.exists():
                out[name] = sha256_file(p)
        return out

    def image_refs(self) -> list[str]:
        """本阶段会用到的容器镜像；子类覆盖。"""
        return []

    # 阶段是否真的需要跑容器。静态阶段（recon/locate）为 False：
    # 离线时允许镜像未就绪，但**不写检查点**，避免用占位 digest 骗过复用判定。
    requires_images = True

    def _image_present(self, img: str) -> bool:
        try:
            ckpt.image_digest(img)
            return True
        except Exception:
            return False

    def images_available(self) -> bool:
        try:
            self.image_digests()
            return True
        except (ckpt.ImageMissing, LookupError):
            return False

    def image_digests(self) -> dict[str, str]:
        """真实 digest；镜像缺失直接抛 ImageMissing，阶段 failed，不降级。"""
        out: dict[str, str] = {}
        for img in self.image_refs():
            if not img:
                raise ckpt.ImageMissing(f"stage {self.name}: empty image reference")
            out[img] = ckpt.image_digest(img)
        return out

    def binding(self, artifacts: dict[str, str] | None = None) -> dict:
        try:
            digests = self.image_digests()
        except (ckpt.ImageMissing, LookupError):
            if self.requires_images:
                raise
            # 静态阶段 + 镜像未就绪：不产生检查点（返回空绑定，调用方据此跳过保存）
            self._bindable = False
            return {}
        self._bindable = True
        # 单镜像：image_digest 就是它的真实 ID，可直接与 docker inspect 对账。
        # 多镜像：image_digest 留空，images 逐条记录（不用组合摘要，避免无法对账）。
        sole = list(digests.values())[0] if len(digests) == 1 else ""
        return ckpt.build_binding(
            run_id=self.run_id, stage=self.name,
            attempt=0,
            image_digest=sole,
            images=None if len(digests) == 1 else digests,
            inputs={**self.input_hashes(), **self.upstream_versions()},
            artifacts=artifacts or {},
            role_version=self.role_version,
            prompt_version=self.prompt_version,
            schema_version=self.schema_version,
            tool_version=TOOL_VERSION,
        )

    def _artifacts_exist(self, artifacts: dict[str, str]) -> bool:
        if not artifacts:
            return False
        for logical, sha in artifacts.items():
            path = self.ws / logical
            if not path.exists() or sha256_file(path) != sha:
                return False
        return True

    def cache_inputs(self) -> dict[str, str]:
        """可以安全复用的输入（不含被本阶段自身改写的目录指纹）。"""
        return self.input_hashes()

    def upstream_versions(self) -> dict[str, str]:
        """所有上游阶段的生效版本；上游换了 prompt 就让本阶段失效，避免产物级联陈旧。"""
        from ..config import STAGE_DEFAULT, resolve
        order = ("recon", "locate", "verify", "exploit")
        out = {}
        if self.name not in order:
            return out
        for stage in order[:order.index(self.name)]:
            v = resolve(stage, self.ws)
            out[f"{stage}.prompt_version"] = v["prompt_version"]
            out[f"{stage}.role_version"] = v["role_version"]
        return out

    def _try_reuse(self) -> dict | None:
        probe = self.binding(artifacts={})
        if not probe:
            return None   # 镜像未就绪：没有可比对的绑定，直接执行
        # 先查该阶段最近一条检查点，比对 inputs/版本/镜像后直接判定
        row = self.store.latest_checkpoint(self.run_id, self.name)
        if not row:
            return None
        old = json.loads(row["binding"])
        for key in ("image_digest", "inputs", "role_version", "prompt_version",
                    "schema_version", "tool_version"):
            if old.get(key) != probe.get(key):
                self._miss_reason = self._miss_label(key, old.get(key), probe.get(key))
                self.store.add_blackboard(
                    self.run_id, "observation", f"{self.name} 检查点未命中",
                    f"{key} 变化：{old.get(key)} -> {probe.get(key)}", status="unknown")
                self._record_miss()
                return None
        arts = old.get("artifacts") or {}
        if not self._artifacts_exist(arts):
            self._miss_reason = "artifact_sha_drift"
            self.store.add_blackboard(
                self.run_id, "observation", f"{self.name} 检查点未命中",
                "绑定工件缺失或 sha 变化", status="unknown")
            self._record_miss()
            return None
        self.checkpoint_key = row["key"]
        self._miss_reason = ""
        return {"binding": old, "artifacts": arts}

    @staticmethod
    def _miss_label(key: str, old_val, new_val) -> str:
        """把绑定差异翻译成人能读的失效原因。"""
        if key == "inputs":
            old_in = old_val or {}
            new_in = new_val or {}
            for name in sorted(set(old_in) | set(new_in)):
                if old_in.get(name) != new_in.get(name):
                    if name.endswith(".prompt_version"):
                        stage = name.split(".")[0]
                        return f"{stage}-prompt-{new_in.get(name)}"
                    if name.endswith(".role_version"):
                        stage = name.split(".")[0]
                        return f"{stage}-role-{new_in.get(name)}"
                    return f"input-changed:{name}"
            return "input-changed"
        if key == "prompt_version":
            return f"{new_val or 'no-prompt'}"
        if key == "role_version":
            return f"role:{new_val}"
        if key == "image_digest":
            return "image-digest-changed"
        if key == "schema_version":
            return f"schema:{new_val}"
        if key == "tool_version":
            return f"tool:{new_val}"
        return f"{key}-changed"

    def _record_miss(self) -> None:
        """未命中的原因落进 attempts.detail，事后能看出是谁把它踢下线的。"""
        reason = getattr(self, "_miss_reason", "") or "unknown"
        self.store.record_attempt(
            self.run_id, self.name, 0, short_hash([self.name, "miss", reason]),
            "invalidated", 0.0,
            detail=json.dumps({"invalidated_by": reason,
                               "stage": self.name}, ensure_ascii=False))

    def _save_checkpoint(self) -> str:
        art_shas = {meta["uri"]: meta["sha256"] for meta in self._written.values()}
        bound = self.binding(artifacts=art_shas)
        if not bound:
            # 静态阶段离线跑：产物照常落盘，但不写检查点（镜像 digest 未知，不可复用）
            try:
                missing = [img for img in self.image_refs() if not self._image_present(img)]
            except Exception:
                # image_refs 在缺镜像时可能直接抛错（如旧实现里解析 digest）：
                # 这是"基础设施证据缺失"，不是阶段失败，照常记录 blocked 即可
                missing = []
            self.store.add_blackboard(
                self.run_id, "observation", f"{self.name} 未写检查点",
                f"reason=image_missing; missing={missing}; "
                "本阶段不依赖镜像，产物已落盘，待镜像就绪后重新绑定",
                status="blocked")
            self._offline_blocked = missing
            return ""
        key = ckpt.save(self.store, self.run_id, self.name, bound)
        self.checkpoint_key = key
        return key

    # ---- 生命周期 ----
    def _audit_sealed(self) -> dict:
        """运行期审计：本阶段执行期间是否触达封存资料。"""
        try:
            from ..isolation import ReadAuditor
            a = ReadAuditor()
            a.scan_process_open_files()
            rep = a.report()
            rep.setdefault("clean", rep.get("no_open_handle_at_scan", True))
            self.store.add_blackboard(
                self.run_id, "observation", f"{self.name} 隔离审计",
                f"clean={rep['clean']} sealed_opened={rep['sealed_opened']}",
                status="ok" if rep["clean"] else "violation")
            return rep
        except Exception as exc:
            return {"clean": None, "error": f"{type(exc).__name__}: {exc}"}

    def run(self) -> StageResult:
        self.store.set_stage(self.run_id, self.name, "authorized")
        try:
            with BudgetLease(self.store, self.run_id, self.name, self.request.budget) as lease:
                reuse = self._try_reuse()
                if reuse:
                    self.reused = True
                    self.store.set_stage(self.run_id, self.name, "running")
                    lease.check_time()
                    data = {"reused": True, "checkpoint": self.checkpoint_key,
                            "artifacts": reuse["artifacts"]}
                    seconds = round(time.monotonic() - self.started, 2)
                    self.store.set_stage(self.run_id, self.name, "observed")
                    self.store.record_attempt(
                        self.run_id, self.name, 1,
                        short_hash([self.name, self.role_version, self.checkpoint_key]),
                        "completed", seconds,
                        detail=json.dumps({"reused_from_checkpoint": self.checkpoint_key,
                                           "seconds": seconds}, ensure_ascii=False))
                    self.store.set_stage(self.run_id, self.name, "committed")
                    return StageResult(stage=self.name, status="completed", data=data,
                                       usage={"seconds": 0.0, "reused": True})
                self.store.set_stage(self.run_id, self.name, "running")
                data = self.execute()
                audit = self._audit_sealed()
                if isinstance(data, dict):
                    data["_isolation_audit"] = audit
                    if audit.get("no_open_handle_at_scan") is False:
                        raise ContractViolation(
                            f"{self.name} touched sealed material: {audit['sealed_opened']}")
                lease.check_time()
            self.store.set_stage(self.run_id, self.name, "observed")
            key = self._save_checkpoint()
            seconds = round(time.monotonic() - self.started, 2)
            self.store.record_attempt(self.run_id, self.name, 1,
                                      short_hash([self.name, self.role_version]), "completed",
                                      seconds,
                                      detail=json.dumps({"checkpoint": key, "seconds": seconds},
                                                        ensure_ascii=False))
            self.store.set_stage(self.run_id, self.name, "committed")
            return StageResult(stage=self.name, status="completed", data=data,
                               usage={"seconds": seconds, "reused": False,
                                      "checkpoint": key})
        except BudgetExhausted as exc:
            self.store.set_stage(self.run_id, self.name, "failed", reason=exc.code)
            return StageResult(stage=self.name, status="failed", stop_reason=exc.code,
                               usage={"seconds": round(time.monotonic() - self.started, 2)})
        except Exception as exc:  # 阶段失败必须落盘，便于复盘
            self.store.set_stage(self.run_id, self.name, "failed", reason=type(exc).__name__)
            atomic_write_json(self.log_path(f"{self.name}.error.json"),
                              {"error": type(exc).__name__, "message": str(exc)})
            return StageResult(stage=self.name, status="failed", stop_reason=type(exc).__name__,
                               usage={"seconds": round(time.monotonic() - self.started, 2)})
