#!/usr/bin/env python3
"""vulnmap covfuzz：对已构建的 ASAN+trace-pc 目标跑并行覆盖率 fuzz。

用法：
  python3 bin/covfuzz.py /tmp/cJSON/cjson_fuzz \
    --corpus /tmp/cjson-corpus2 --crashes /tmp/cjson-crashes2 \
    --stats /tmp/cjson-stats2 --seconds 60 --workers 4
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.discovery import covfuzz  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="coverage-guided fuzz (ASAN + trace-pc)")
    ap.add_argument("binary")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--crashes", required=True)
    ap.add_argument("--stats", required=True)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--format", default=None, help="结构化变异：png/tiff/json")
    ap.add_argument("--isolation",
                    choices=["auto", "bwrap", "unshare", "container", "none"],
                    default="auto", help="目标执行隔离方式（默认 auto）")
    ap.add_argument("--require-isolation", action="store_true",
                    help="隔离不可用时直接失败")
    ap.add_argument("--pcs", default=None, help="可选：把语料重跑后把 PC 并集写到该文件")
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.exists():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2
    stats = covfuzz.run_parallel(binary, args.corpus, args.crashes, args.stats,
                                 seconds=args.seconds, workers=args.workers,
                                 timeout=args.timeout, fmt=args.format,
                                 isolation=args.isolation,
                                 require_isolation=args.require_isolation)
    if args.pcs:
        pcs = covfuzz.collect_pcs(binary, args.corpus, Path(args.stats) / "pcs",
                                   isolation=args.isolation,
                                   require_isolation=args.require_isolation)
        from agent.discovery.coverage_map import read_pcs  # noqa: F401
        out = Path(args.pcs)
        out.parent.mkdir(parents=True, exist_ok=True)
        import struct
        unique = sorted(set(pcs))
        out.write_bytes(struct.pack("<i", len(unique))
                        + struct.pack("<" + "Q" * len(unique), *unique))
        stats["pcs"] = len(unique)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
