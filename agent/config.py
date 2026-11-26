"""配置加载：prompt_version / role_version / 预算 / 模型，均可由文件覆盖。

优先级（后者覆盖前者）：
1. 代码默认值（`configs/versions.json` 不存在时的兜底）
2. `configs/versions.json`（仓库级默认）
3. `<workspace>/case.yaml` 或 `<workspace>/task.json` 里的 `versions` 段

检查点绑定的是**最终生效值**，所以改配置文件即可让旧检查点失效，
不需要动源码常量。
"""
from __future__ import annotations

import json
from pathlib import Path

from .paths import PACKAGE_ROOT

STAGE_DEFAULT = {
    "recon": {"role_version": "recon-v1", "prompt_version": "recon-p1"},
    "locate": {"role_version": "locate-v1", "prompt_version": "locate-p1"},
    "verify": {"role_version": "verify-v1", "prompt_version": "verify-p1"},
    "exploit": {"role_version": "exploit-v1", "prompt_version": "exploit-p1"},
    "report": {"role_version": "report-v1", "prompt_version": "report-p1"},
}

CONFIG_PATH = PACKAGE_ROOT / "configs" / "versions.json"


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def repo_versions() -> dict:
    return _read_json(CONFIG_PATH)


def workspace_versions(ws: Path) -> dict:
    """工作区级覆盖：case.yaml（YAML 子集，逐行 key: value）或 task.json 的 versions 段。"""
    ws = Path(ws)
    out: dict = {}
    task = _read_json(ws / "task.json")
    if isinstance(task.get("versions"), dict):
        out.update(task["versions"])
    yaml_path = ws / "case.yaml"
    if yaml_path.exists():
        # 只支持两层的极简 YAML：stage:\\n  key: value
        current = None
        for raw in yaml_path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            key, _, value = line.strip().partition(":")
            key, value = key.strip(), value.strip().strip('"\'')
            if not value:
                current = key
                out.setdefault(current, {}) if isinstance(out.get(current, {}), dict) else None
                out[current] = {}
            elif current:
                out.setdefault(current, {})
                if isinstance(out[current], dict):
                    out[current][key] = value
                else:
                    out[f"{current}.{key}"] = value
    return out


def resolve(stage: str, ws: Path) -> dict:
    """返回该阶段最终生效的 role_version / prompt_version。"""
    merged = dict(STAGE_DEFAULT.get(stage, {"role_version": f"{stage}-v1",
                                            "prompt_version": f"{stage}-p1"}))
    for source in (repo_versions(), workspace_versions(ws)):
        if not isinstance(source, dict):
            continue
        # 支持两种写法：{"locate": {"prompt_version": ...}} 与 {"locate.prompt_version": ...}
        for key in ("role_version", "prompt_version"):
            flat = source.get(f"{stage}.{key}")
            if isinstance(flat, str) and flat:
                merged[key] = flat
        section = source.get(stage)
        if isinstance(section, dict):
            for key in ("role_version", "prompt_version"):
                val = section.get(key)
                if isinstance(val, str) and val:
                    merged[key] = val
    return merged


def effective_versions(ws: Path) -> dict[str, dict]:
    return {stage: resolve(stage, ws) for stage in STAGE_DEFAULT}
