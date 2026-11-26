#!/usr/bin/env python3
"""vulnmap discover：只给源码/二进制，跑 D0-D5。

用法：
  python3 bin/discover.py fixtures/discovery --out /tmp/out --seconds 3 --max-sites 3
  python3 bin/discover.py fixtures/discovery --out /tmp/out --eval
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.discovery import campaign, targetspec  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="vulnmap Discovery v1.0")
    ap.add_argument("target", help="目标目录（源码/二进制所在根）")
    ap.add_argument("--out", default=None, help="证据输出目录")
    ap.add_argument("--seconds", type=float, default=None,
                    help="fuzz 时长（每 worker）；默认取 target.yaml 或 5s")
    ap.add_argument("--max-sites", type=int, default=8, help="进入分析的调用点数")
    ap.add_argument("--workers", type=int, default=None,
                    help="fuzz 进程数；默认取 target.yaml 或 4")
    ap.add_argument("--target-yaml", default=None,
                    help="构建/harness 描述文件；默认探测 <target>/target.yaml")
    ap.add_argument("--isolation",
                    choices=["auto", "bwrap", "unshare", "container", "none"],
                    default="auto", help="目标执行隔离方式（默认 auto）")
    ap.add_argument("--require-isolation", action="store_true",
                    help="隔离不可用时直接失败，不回退宿主网络")
    ap.add_argument("--init-target", action="store_true",
                    help="从源码布局生成 <target>/target.yaml 草稿后退出")
    ap.add_argument("--force", action="store_true", help="--init-target 覆盖已有文件")
    ap.add_argument("--strategy", choices=["ranked", "random"], default="ranked")
    ap.add_argument("--format", default=None, help="格式提示：json/png/...（默认取 D0）")
    ap.add_argument("--analysis", choices=["llm", "heuristic"], default="llm",
                    help="调用点分析模式：默认 llm；无 key/超时自动回退 heuristic")
    ap.add_argument("--no-llm", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--llm-review", action="store_true",
                    help="D3.5 复核走一次 LLM 独立判断（默认关闭=规则复核）；"
                         "失败自动回退规则复核，且不得越过 confirmed 门禁")
    ap.add_argument("--eval", action="store_true", help="D5：ranked vs random 对照")
    ap.add_argument("--ab", action="store_true", help="D5：Agent 种子 vs 纯 fuzz 对照")
    ap.add_argument("--db", default=None, help="SQLite 台账路径（默认 out/campaign.db）")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"target not found: {target}", file=sys.stderr)
        return 2
    out = Path(args.out).resolve() if args.out else target / "discovery-out"

    if args.init_target:
        try:
            path = targetspec.write_draft(target, force=args.force)
        except (FileExistsError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps({"target_yaml": str(path),
                          "content": path.read_text(encoding="utf-8")},
                         ensure_ascii=False, indent=2))
        return 0

    if args.eval:
        payload = campaign.evaluate(target, out, seconds=args.seconds or 5.0,
                                    max_sites=args.max_sites,
                                    workers=args.workers or 4,
                                    isolation=args.isolation,
                                    require_isolation=args.require_isolation)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.ab:
        payload = campaign.ab_seeds(target, out, seconds=args.seconds or 30.0,
                                    attempts=3, max_sites=args.max_sites,
                                    isolation=args.isolation,
                                    require_isolation=args.require_isolation)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    summary = campaign.run(target, out, seconds=args.seconds,
                           max_sites=args.max_sites, strategy=args.strategy,
                           format_hint=args.format,
                           use_llm=(args.analysis == "llm" and not args.no_llm),
                           use_llm_review=args.llm_review,
                           workers=args.workers,
                           db_path=Path(args.db) if args.db else None,
                           target_yaml=Path(args.target_yaml) if args.target_yaml else None,
                           isolation=args.isolation,
                           require_isolation=args.require_isolation)
    print(json.dumps({"campaign": summary["campaign"],
                      "risk_stats": summary["risk_stats"],
                      "coverage": summary["coverage"],
                      "fuzz": {k: summary["fuzz"][k] for k in
                               ("execs", "crashes", "first_crash_seconds")},
                      "review": summary["analysis"]["review"],
                      "out": str(out)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
