#!/usr/bin/env python3
"""把「跑一次目标」归一成三段事实：`program_started / input_processed / checkpoint_reached`。

这是夹具侧的探针实现（真实子进程 + 真实探针文件），不是测试替身：

- `program_started`：子进程真的起来了（`OSError` / 找不到解释器 → `False`）；
- `input_processed`：目标自己写了 `input_processed` 探针 → `True`；探针开着但没写
  → `False`（进程跑了、输入没被处理）；`--no-probe` → `None`（没有观测手段，
  **只能** unknown，不能填 False）；
- `checkpoint_reached`：目标写了 `checkpoint` 探针 → `True`；探针开着、输入处理了
  但没命中 → `False`；其余 → `None`。

三个内置用例正好对应用户要的三组回归（见 `run_case`）：

| 用例 | 结果三元组 |
|---|---|
| `started_no_checkpoint` | `True / True / False`（起来了、处理了、没命中） |
| `checkpoint_hit` | `True / True / True`（确认命中） |
| `no_probe` | `True / None / None`（跑得起来但没有观测手段 → unknown） |
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "parser_target.py"

MAGIC = "MAGIC VMAP1"

#: 三个用例的输入：合法头 + 若干字段；只有 checkpoint_hit 带八位 hex 的 GUARD
CASE_INPUTS = {
    "started_no_checkpoint": "\n".join([
        MAGIC,
        "FIELD name=alpha",
        "FIELD mode=strict",
        "END",
    ]) + "\n",
    "checkpoint_hit": "\n".join([
        MAGIC,
        "FIELD name=alpha",
        "GUARD token=deadbeef",
        "END",
    ]) + "\n",
    "no_probe": "\n".join([
        MAGIC,
        "FIELD name=alpha",
        "GUARD token=deadbeef",
        "END",
    ]) + "\n",
}


def run_target(input_text: str, *, probe_path: Path | str,
               probe: bool = True, timeout: float = 10.0,
               target: Path | str = TARGET,
               interpreter: str | None = None) -> dict:
    """真跑一次目标，返回三段事实 + 原始观测细节（不填默认值）。

    `interpreter` 可替换成一条不存在的可执行路径，用来演示“进程根本没起来”
    （`program_started=False`）——这也是一种观测，不是 unknown。
    """
    probe_path = Path(probe_path)
    argv = [str(interpreter or sys.executable), str(target)]
    if probe:
        probe_path.parent.mkdir(parents=True, exist_ok=True)
        if probe_path.exists():
            probe_path.unlink()
        argv += ["--probe-out", str(probe_path)]
    else:
        argv += ["--no-probe"]
    facts = {"program_started": None, "input_processed": None,
             "checkpoint_reached": None}
    observation = {"argv": argv, "returncode": None, "stdout": "",
                   "stderr": "", "probe_events": []}
    try:
        proc = subprocess.run(argv, input=input_text, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        # 进程根本没起来：这是“启动失败”的观测，不是 unknown
        facts["program_started"] = False
        observation["stderr"] = f"{type(exc).__name__}: {exc}"
        return {"facts": facts, "observation": observation}
    facts["program_started"] = True
    observation["returncode"] = proc.returncode
    observation["stdout"] = (proc.stdout or "")[:2000]
    observation["stderr"] = (proc.stderr or "")[:2000]
    if not probe:
        # 没有观测手段：input_processed / checkpoint_reached 只能 unknown
        return {"facts": facts, "observation": observation}
    events: list[dict] = []
    if probe_path.exists():
        for line in probe_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    observation["probe_events"] = events
    processed = any(e.get("event") == "input_processed" for e in events)
    facts["input_processed"] = processed
    hit = any(e.get("event") == "checkpoint" and e.get("name") == "guard"
              for e in events)
    facts["checkpoint_reached"] = True if hit else (False if processed else None)
    return {"facts": facts, "observation": observation}


def run_case(name: str, *, probe_dir: Path | str,
             timeout: float = 10.0) -> dict:
    """跑一个内置用例（`started_no_checkpoint` / `checkpoint_hit` / `no_probe`）。"""
    if name not in CASE_INPUTS:
        raise KeyError(f"unknown case: {name!r}")
    probe_dir = Path(probe_dir)
    return run_target(CASE_INPUTS[name],
                      probe_path=probe_dir / f"probe-{name}.jsonl",
                      probe=(name != "no_probe"), timeout=timeout)


def case_facts(name: str, *, probe_dir) -> dict:
    """只取三段事实（写进 `exec.finished` / 断言用的形状）。"""
    return dict(run_case(name, probe_dir=probe_dir)["facts"])


CASES = tuple(CASE_INPUTS)

__all__ = ["CASE_INPUTS", "CASES", "run_target", "run_case",
           "case_facts"]
