"""检查点：绑定镜像 digest、输入哈希、工件哈希与版本号。

命中条件必须同时满足：
1. 镜像 digest 一致（不接受 tag，也不接受空 digest）；
2. 输入工件 sha 完全一致；
3. role_version / prompt_version / schema_version 一致；
4. 绑定的工件文件仍然存在且 sha 未变（防止“伪造的绑定”与磁盘脱节）。
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .store import Store
from .util import canonical_json, sha256_file, short_hash

SCHEMA = "vulnmap.checkpoint.v1"


def build_binding(*, run_id: str, stage: str, attempt: int, image_digest: str | None,
                  images: dict[str, str] | None = None,
                  inputs: dict[str, str], artifacts: dict[str, str],
                  role_version: str, prompt_version: str, schema_version: str,
                  tool_version: str = "") -> dict:
    # 主 digest：只有一个镜像时就是它的真实 ID；多个镜像时置空，
    # 由 images 逐条记录（组合摘要不可与 docker inspect 对账，不能用）。
    if images:
        image_digest = ""
    if not image_digest and not (images or {}):
        # 只绑 run_id 的检查点等于假装实现：没有镜像 digest 直接拒绝构造
        raise ValueError(f"checkpoint for stage {stage} requires image_digest")
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "stage": stage,
        "attempt": attempt,
        "image_digest": image_digest or "",
        "images": dict(sorted((images or {}).items())),
        "inputs": inputs,
        "artifacts": artifacts,
        "role_version": role_version,
        "prompt_version": prompt_version,
        "schema_version": schema_version,
        "tool_version": tool_version,
    }


def artifact_hashes(paths: dict[str, Path]) -> dict[str, str]:
    return {name: sha256_file(p) for name, p in paths.items() if p.exists()}


def load_or_none(store: Store, run_id: str, stage: str, binding: dict) -> dict | None:
    return store.find_checkpoint(run_id, stage, binding)


def save(store: Store, run_id: str, stage: str, binding: dict) -> str:
    return store.save_checkpoint(run_id, stage, binding)


def idempotency_key(*parts: Any) -> str:
    return short_hash(list(parts), 32)


# ---- 镜像 digest ----
_DIGEST_CACHE: dict[str, str] = {}


def image_digest(image: str) -> str:
    """返回 `sha256:...` 形式的镜像 digest；镜像不存在时抛错（不静默退化为 tag）。

    本地镜像按 RepoDigests 优先，其次回落到镜像 ID（同样不可变）。
    """
    if not image:
        raise ValueError("empty image reference")
    if image in _DIGEST_CACHE:
        return _DIGEST_CACHE[image]
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}\t{{.Id}}", image],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise LookupError(f"image not present locally: {image}: {proc.stderr.strip()[:200]}")
    repo_digests, image_id = proc.stdout.strip().split("\t", 1)
    digests = json.loads(repo_digests or "[]")
    out = ""
    for d in digests:
        if "@sha256:" in d:
            out = "sha256:" + d.split("@sha256:", 1)[1]
            break
    if not out:
        out = image_id.strip() if image_id.strip().startswith("sha256:") else f"sha256:{image_id.strip()}"
    _DIGEST_CACHE[image] = out
    return out


class ImageMissing(LookupError):
    """镜像不在本地：阶段必须失败，不允许降级。"""


def digest_or_placeholder(image: str) -> str:
    """【已废弃】缺镜像时造占位 digest 会让检查点在环境被换掉后仍然命中。

    保留函数名仅为兼容旧调用点；行为改为直接抛 ImageMissing。
    """
    if not image:
        raise ImageMissing("empty image reference")
    try:
        return image_digest(image)
    except LookupError as exc:
        raise ImageMissing(str(exc)) from exc


def binding_fingerprint(binding: dict) -> str:
    return short_hash(canonical_json(binding), 32)


def binding_image_digests(binding: dict) -> list[str]:
    """绑定里出现过的全部 digest（主字段 + images 表），供一致性校验。"""
    out = []
    if binding.get("image_digest"):
        out.append(binding["image_digest"])
    out.extend((binding.get("images") or {}).values())
    return out


def verify_binding_images(binding: dict, image_name: str | None = None) -> None:
    """绑定的每个镜像 digest 都必须等于当前 docker inspect 的真实值。

    任何 "" / "unresolved-…" / 组合摘要 都会在这里暴露，而不是悄悄命中。
    单镜像阶段只写 image_digest，此时用 `image_name` 回查真实值。
    """
    images = binding.get("images") or {}
    if not images and not binding.get("image_digest"):
        raise ValueError(f"binding {binding.get('stage')} carries no image digest")
    for name, digest in images.items():
        if not digest.startswith("sha256:") or "unresolved" in digest:
            raise ValueError(f"binding image {name} has non-concrete digest: {digest}")
        actual = image_digest(name)
        if actual != digest:
            raise ValueError(f"binding image {name} digest {digest} != actual {actual}")
    if images:
        return
    digest = binding["image_digest"]
    if not digest.startswith("sha256:") or "unresolved" in digest:
        raise ValueError(f"binding image_digest is non-concrete: {digest}")
    if image_name:
        actual = image_digest(image_name)
        if actual != digest:
            raise ValueError(f"binding image {image_name} digest {digest} != actual {actual}")
