"""输出校验流水线：字节数 → JSON → 必填字段 → schema → 语义 guard。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .contracts import ContractError, OutputContract


def validate_output(raw: bytes, contract: OutputContract, *,
                    guards: list[Callable[[dict], None]] | None = None) -> dict:
    if not (contract.min_bytes <= len(raw) <= contract.max_bytes):
        raise ContractError(f"{contract.logical_name}: size {len(raw)} out of "
                            f"[{contract.min_bytes},{contract.max_bytes}]")
    text = raw.decode("utf-8", errors="strict").strip()
    if contract.json_object:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ContractError(f"{contract.logical_name}: invalid json: {exc}") from exc
    else:
        data = {"text": text}
    for field in contract.required_fields:
        if not isinstance(data, dict) or field not in data:
            raise ContractError(f"{contract.logical_name}: missing required field {field}")
    if isinstance(data, dict):
        declared = data.get("schema")
        if declared is not None and declared != contract.schema:
            raise ContractError(f"{contract.logical_name}: schema {declared} != {contract.schema}")
    for guard in guards or []:
        guard(data)
    return data


def guard_line_exists(src_root: Path, data: dict) -> None:
    for key in ("entry", "sink"):
        loc = data.get(key)
        if not isinstance(loc, dict) or not loc.get("file"):
            continue
        target = (src_root / loc["file"]).resolve()
        if not str(target).startswith(str(src_root.resolve())):
            raise ContractError(f"{key}.file escapes source root: {loc['file']}")
        if not target.exists():
            raise ContractError(f"{key}.file not found: {loc['file']}")
        line = loc.get("line")
        if isinstance(line, int) and line > 0:
            total = sum(1 for _ in target.open("rb"))
            if line > total:
                raise ContractError(f"{key}.line {line} exceeds file length {total}")


def guard_sha_matches(data: dict, *, expected: dict[str, str], key: str = "poc_sha256") -> None:
    got = data.get(key)
    if got is None:
        return
    want = expected.get(key)
    if want and got != want:
        raise ContractError(f"{key} mismatch: {got} != {want}")


def guard_upstream_untouched(input_refs: dict[str, str], data: dict) -> None:
    """阶段结果里回传的上游工件必须与输入完全一致。"""
    out = data.get("upstream") or {}
    for name, sha in out.items():
        if name in input_refs and input_refs[name] != sha:
            raise ContractError(f"mutated upstream artifact: {name}")
