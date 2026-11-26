#!/usr/bin/env python3
"""无害的「目标程序」替身：一个只会 parse 自己格式的解析器，用来区分三段语义。

它**不是**漏洞样本，也不做任何 I/O 之外的事：读 stdin 的文本，按自己的格式
逐行解析，并在两个真实的语义点上写探针事件（JSON Lines 追加到 `--probe-out`）：

| 探针事件 | 含义 | 对应事实 |
|---|---|---|
| `{"event": "input_processed"}` | 头字段合法，输入进入解析主循环 | `input_processed` |
| `{"event": "checkpoint", "name": "guard"}` | 走到了 `GUARD` 分支的检查点 | `checkpoint_reached` |

`--no-probe` 时**什么都不写**：这就是“没有观测手段”的场景——程序照跑，
但外部拿不到 `input_processed` / `checkpoint_reached` 的证据（只能是 unknown）。

输入格式（三行起）::

    MAGIC VMAP1
    FIELD name=value
    GUARD token=deadbeef
    END

退出码：0 正常；2 头字段不合法（此时**没有** `input_processed` 探针）。
"""
from __future__ import annotations

import json
import re
import sys

MAGIC = "MAGIC VMAP1"
GUARD_TOKEN = re.compile(r"^token=[0-9a-f]{8}$")


def _emit(path: str, doc: dict) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(doc, ensure_ascii=False, sort_keys=True) + "\n")


def parse(text: str, *, probe_path: str = "") -> dict:
    """解析文本，返回本次解析的结构化结果（探针是副作用，结果只描述 parse 到了什么）。"""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    result = {"ok": False, "fields": 0, "guard": False, "reason": ""}
    if not lines or lines[0] != MAGIC:
        result["reason"] = "bad_magic"
        return result
    # 头字段合法 → 输入真的进了解析主循环：这才是 input_processed 的证据
    _emit(probe_path, {"event": "input_processed"})
    for line in lines[1:]:
        if line == "END":
            result["ok"] = True
            continue
        if line.startswith("FIELD "):
            result["fields"] += 1
            continue
        if line.startswith("GUARD "):
            if GUARD_TOKEN.match(line[len("GUARD "):].strip()):
                result["guard"] = True
                _emit(probe_path, {"event": "checkpoint", "name": "guard"})
            continue
        result["reason"] = f"unknown_line:{line.split(' ', 1)[0]}"
    return result


def main(argv: list[str]) -> int:
    probe_path = ""
    no_probe = False
    for index, arg in enumerate(argv):
        if arg == "--probe-out" and index + 1 < len(argv):
            probe_path = argv[index + 1]
        elif arg == "--no-probe":
            no_probe = True
    text = sys.stdin.read()
    result = parse(text, probe_path="" if no_probe else probe_path)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    return 0 if result["ok"] else 2


if __name__ == "__main__":              # pragma: no cover - 由子进程入口覆盖
    raise SystemExit(main(sys.argv[1:]))
