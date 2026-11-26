#!/usr/bin/env python3
"""配置夹具的「执行器」：真读一份配置 → 算 `loaded_config_sha256` → 真跑目标 → 报事实。

它模拟执行器的两件事（`docs/V3-W2-CONFIG.md` §2/§3）：

1. **实际加载的版本只由它回报**：`loaded_config_sha256` 是用
   `agent.platform.executors.config_file_sha256()` 读它**真的**交给进程的那份配置
   算出来的——不是从工作区/计划版本抄来的；
2. **没报就是没报**：`--no-report-config` 让它什么都不说（`loaded` 留空），
   调用侧只能得到 `unknown`，绝不回填 `planned`。

两种"配置没生效/不知道"的真反例：

- `--stale-config PATH`：配置已写盘，但执行器仍加载旧的副本（旧样例、旧观测点）——
  于是 `loaded != planned`，是**已观测的** `not_effective`；
- `--no-report-config`：执行器没带回报——`loaded` 缺失，只能 `unknown`。

输出（stdout 一行 JSON，schema=`vulnmap.config_fixture.run.v1`）：

```
loaded_config_sha256   执行器实际加载版本的语义哈希（"" 表示没算出来/没报）
loaded_source          reported / ""（缺失）
loaded_config_path     真的交给目标的配置文件
config_present         {planned: False, loaded: bool}   ← runner 不声称计划版本
program_started        目标进程是否真的起来了（OSError → False）
input_processed        True/False/None（观测点没启用 → None）
checkpoint_reached     True/False/None（同上）
target_exit_code       目标退出码（没跑起来 → None）
probes                 目标真的写下的探针行
sample                 目标真的解析的样例 id
stale                  bool（本次是否走了 --stale-config 旧配置）
```

用法：::

    python3 runner.py --config config/active.json --probe probe.jsonl --root .
    python3 runner.py --config config/active.json --stale-config old/active.json
    python3 runner.py --config config/active.json --no-report-config

退出码：0 目标退出 0；1 目标退出非 0；3 装置问题（找不到 target.py 等）。
目标自身的退出码在 `target_exit_code` 里，不在这里冒充。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

SCHEMA = "vulnmap.config_fixture.run.v1"
EXIT_USAGE = 3


def _ensure_executors():
    """拿到 `config_file_sha256`：配置身份只认执行器那一个实现，不另写一套。"""
    try:
        from agent.platform.executors import config_file_sha256
        return config_file_sha256
    except ImportError:
        pass
    candidates: list[Path] = []
    env_root = os.environ.get("VULNMAP_ROOT") or ""
    if env_root:
        candidates.append(Path(env_root))
    here = Path(__file__).resolve()
    candidates.extend(here.parents)
    candidates.append(Path.cwd())
    for candidate in candidates:
        if (candidate / "agent" / "platform" / "executors" / "__init__.py").is_file():
            sys.path.insert(0, str(candidate))
            break
    from agent.platform.executors import config_file_sha256
    return config_file_sha256


def read_json(path: Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def read_probes(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    probes: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict):
            probes.append(doc)
    return probes


def tri(enabled: bool, hit: bool):
    """观测点没启用 → None（没观测）；启用 → True/False（观测到的）。"""
    if not enabled:
        return None
    return bool(hit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="配置夹具的执行器替身")
    parser.add_argument("--root", default=".")
    parser.add_argument("--config", default="")
    parser.add_argument("--stale-config", default="")
    parser.add_argument("--probe", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--no-report-config", action="store_true",
                       help="模拟执行器没有回报实际加载版本（→ unknown）")
    args = parser.parse_args(argv)

    config_file_sha256 = _ensure_executors()
    root = Path(args.root)
    config_path = Path(args.stale_config or args.config
                       or (root / "config" / "active.json"))
    target_path = Path(args.target) if args.target else (root / "target.py")
    probe_path = Path(args.probe) if args.probe else Path("probe.jsonl")
    if probe_path.exists():
        probe_path.unlink()

    loaded_doc = read_json(config_path)
    loaded_sha = "" if args.no_report_config else config_file_sha256(config_path)
    enabled = [str(item) for item in (loaded_doc.get("observation_points") or [])]
    points_doc = read_json(root / "config" / "observation_points.json")
    mapping = {str(point.get("id")): str(point.get("probe") or point.get("id"))
               for point in (points_doc.get("points") or [])}

    program_started: bool | None
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    if not target_path.is_file():
        program_started = False
        stderr = f"usage_error: 找不到目标 {target_path}"
    else:
        try:
            proc = subprocess.run(
                [sys.executable, str(target_path), "--config", str(config_path),
                 "--probe", str(probe_path), "--root", str(root)],
                capture_output=True, text=True, timeout=float(args.timeout),
                cwd=str(root), shell=False, check=False)
            program_started = True          # 进程真的起来了（有退出码）
            exit_code = int(proc.returncode)
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            program_started = True          # 起来了，只是没在预算内结束
            exit_code = 124
            stdout = str(exc.stdout or "")
            stderr = str(exc.stderr or "")
        except OSError as exc:
            program_started = False
            stderr = f"spawn_error: {type(exc).__name__}: {exc}"

    probes = read_probes(probe_path)
    written = {str(item.get("probe")) for item in probes}
    guard_probe = mapping.get("guard", "checkpoint:guard")
    input_probe = mapping.get("input_processed", "input_processed")

    report = {
        "schema": SCHEMA,
        "stale": bool(args.stale_config),
        "config_path": str(config_path),
        "config_present": {"planned": False, "loaded": bool(loaded_sha)},
        "loaded_config_sha256": loaded_sha,
        "loaded_source": "" if args.no_report_config else "reported",
        "reported": not args.no_report_config,
        "sample": str(loaded_doc.get("sample") or ""),
        "observation_points": enabled,
        "probes": probes,
        "probe_hits": sorted(written),
        "program_started": program_started,
        "input_processed": tri("input_processed" in enabled,
                               input_probe in written),
        "checkpoint_reached": tri("guard" in enabled, guard_probe in written),
        "target_exit_code": exit_code,
        "target_stdout": stdout.strip().splitlines()[:5],
        "target_stderr": stderr.strip().splitlines()[:5],
    }
    print(json.dumps(report, sort_keys=True))
    if exit_code is None:
        return EXIT_USAGE
    return 0 if exit_code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
