#!/usr/bin/env python3
"""配置夹具的「无害目标」：按 active.json 选样例、按启用的观测点写 JSONL 探针。

它不是漏洞程序：把一个纯文本记录解析成字段，命中时写一行探针。它同时是
「禁止改的对照物」——配置模式下 `target.py` 属于源码面，任何写入都该被
`config_path_not_whitelisted` 拒绝（`docs/V3-W2-CONFIG.md` §1.2）。

输入格式（`samples/*.txt`）：

```
VMAP1                     ← magic 头，必须正好是第一行
key=value                 ← 任意多行字段
GUARD token=deadbeef      ← 可选检查点标记（只 gamma.txt 有）
```

观测点（`config/observation_points.json` 的 `probe` 字段）只在**被启用**时才写：

- `input_processed`：头合法、字段真的被解析出来 → 写一行；
- `checkpoint:guard`：body 里出现 `GUARD token=` → 写一行。

`没写探针行` 与 `观测点没启用` 是两件事，runner.py 负责把二者分开
（启用 + 无行 = 观测到 False；没启用 = None/unknown）。

用法：::

    python3 target.py --config config/active.json --probe probe.jsonl [--root .]

退出码：0 头合法；1 头/body 不合法（目标侧行为）；2 用法或读盘错误（装置问题）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MAGIC = "VMAP1"
GUARD_PREFIX = "GUARD token="
EXIT_OK = 0
EXIT_BAD_INPUT = 1
EXIT_USAGE = 2


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def probe_name(points_doc: dict, point_id: str) -> str:
    for point in (points_doc.get("points") or []):
        if str(point.get("id")) == point_id:
            return str(point.get("probe") or point_id)
    return point_id


def parse_sample(text: str) -> tuple[bool, dict, str]:
    """返回 (magic_ok, fields, guard_token)；body 坏掉一律 magic_ok=False。"""
    lines = [line.rstrip("\n") for line in text.splitlines() if line.strip()]
    if not lines or lines[0].strip() != MAGIC:
        return False, {}, ""
    fields: dict[str, str] = {}
    guard = ""
    for line in lines[1:]:
        if line.startswith(GUARD_PREFIX):
            guard = line[len(GUARD_PREFIX):].strip()
            continue
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            return False, {}, ""          # body 不是 key=value：目标没被喂对
        fields[key.strip()] = value.strip()
    return True, fields, guard


def write_probe(path: Path, probe: str, point: str, detail: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"probe": probe, "point": point,
                                 "detail": detail}, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="配置夹具的无害解析器")
    parser.add_argument("--config", default="config/active.json")
    parser.add_argument("--probe", default="probe.jsonl")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)

    root = Path(args.root)
    try:
        config = read_json(Path(args.config))
        catalog = read_json(root / "config" / "samples.json")
        points_doc = read_json(root / "config" / "observation_points.json")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"usage_error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    sample_id = str(config.get("sample") or "")
    entry = next((item for item in (catalog.get("samples") or [])
                  if str(item.get("id")) == sample_id), None)
    if entry is None:
        print(f"usage_error: 目录里没有样例 {sample_id!r}", file=sys.stderr)
        return EXIT_USAGE
    try:
        text = (root / str(entry.get("path"))).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"usage_error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    magic_ok, fields, guard = parse_sample(text)
    enabled = [str(item) for item in (config.get("observation_points") or [])]
    probe_path = Path(args.probe)
    emitted: list[str] = []
    if magic_ok and "input_processed" in enabled:
        name = probe_name(points_doc, "input_processed")
        write_probe(probe_path, name, "input_processed",
                    {"sample": sample_id, "fields": len(fields)})
        emitted.append(name)
    if magic_ok and guard and "guard" in enabled:
        name = probe_name(points_doc, "guard")
        write_probe(probe_path, name, "guard",
                    {"sample": sample_id, "token": guard})
        emitted.append(name)

    print(json.dumps({"sample": sample_id, "magic_ok": magic_ok,
                      "fields": len(fields), "guard_token": guard,
                      "probes": emitted}, sort_keys=True))
    return EXIT_OK if magic_ok else EXIT_BAD_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
