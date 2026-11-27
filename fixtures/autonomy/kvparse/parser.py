#!/usr/bin/env python3
"""无害的键值解析器：只用于自主闭环验收，不含任何漏洞。"""
from __future__ import annotations
import json, sys


def parse_line(line: str) -> dict:
    line = line.rstrip("\n")
    if not line or line.lstrip().startswith("#"):
        return {"kind": "empty" if not line else "comment"}
    if "=" not in line:
        raise ValueError("missing '='")
    key, _, value = line.partition("=")
    key = key.strip()
    if not key:
        raise ValueError("empty key")
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    elif value[:1] in "'\"" or value[-1:] in "'\"":
        raise ValueError("unbalanced quote")
    if value.lower() in ("true", "false"):
        return {"kind": "bool", "key": key, "value": value.lower() == "true"}
    try:
        return {"kind": "int", "key": key, "value": int(value)}
    except ValueError:
        pass
    return {"kind": "str", "key": key, "value": value}


def parse_text(text: str) -> dict:
    out, errors = [], []
    for i, line in enumerate(text.splitlines(), 1):
        try:
            out.append(parse_line(line))
        except ValueError as exc:
            errors.append({"line": i, "error": str(exc)})
    return {"entries": len(out), "errors": errors}


def main(argv):
    if len(argv) != 2:
        print("usage: parser.py FILE", file=sys.stderr)
        return 2
    try:
        text = open(argv[1], encoding="utf-8", errors="strict").read()
    except Exception as exc:
        print(json.dumps({"status": "unreadable", "reason": type(exc).__name__}))
        return 1
    print(json.dumps({"status": "ok", **parse_text(text)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
