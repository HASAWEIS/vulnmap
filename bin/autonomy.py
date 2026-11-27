#!/usr/bin/env python3
"""自主闭环运行包 CLI：分类 / 校验 / 关联平台 run_id。"""
from __future__ import annotations
import argparse, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.autonomy.bridge import attach_platform  # noqa: E402
from agent.autonomy.classify import classify          # noqa: E402
from agent.autonomy.pack import RunPack              # noqa: E402
from agent.autonomy.verify import verify             # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="autonomy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_cls = sub.add_parser("classify", help="只看运行事实，判定 manual/assisted/autonomous")
    p_cls.add_argument("pack")

    p_ver = sub.add_parser("verify", help="独立校验（读保留答案，不看报告）")
    p_ver.add_argument("pack")
    p_ver.add_argument("--expected", required=True)
    p_ver.add_argument("--allow-assisted", action="store_true",
                       help="允许 agent_assisted 也算通过（默认只认自主）")

    p_att = sub.add_parser("attach", help="关联平台任务 run_id")
    p_att.add_argument("pack")
    p_att.add_argument("--db", required=True)
    p_att.add_argument("--task", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "classify":
        print(json.dumps(classify(RunPack(args.pack)), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "verify":
        res = verify(args.pack, expected_path=args.expected,
                     require_autonomous=not args.allow_assisted)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res["verdict"] == "pass" else 2
    if args.cmd == "attach":
        print(json.dumps(attach_platform(RunPack(args.pack), db_path=args.db,
                                         task_id=args.task), ensure_ascii=False, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
