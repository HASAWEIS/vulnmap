"""命令行入口：vulnmap run / status / context。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.budget import GlobalModelBudget  # noqa: E402
from agent.contracts import Budget  # noqa: E402
from agent.llm import set_global_budget  # noqa: E402
from agent.runtime.orchestrator import Orchestrator  # noqa: E402


def cmd_run(args) -> int:
    budget = Budget(max_turns=args.max_turns, timeout_seconds=args.timeout)
    orch = Orchestrator(Path(args.workspace), budget=budget)
    if getattr(args, "regate", False):
        # 判据/因果要素档案更新后重算判定：不重跑执行、不碰原始日志
        orch.regate = True
    # 全局模型预算：跨阶段累计，超限即终止整个 run
    guard = GlobalModelBudget(max_requests=args.max_requests,
                              max_tokens=args.max_tokens,
                              max_seconds=args.max_seconds)
    guard.bind(orch.store, orch.task.get("run_id") or "")
    set_global_budget(guard)
    orch.global_budget = guard
    if args.stages:
        orch.stage_limit = [s.strip() for s in args.stages.split(",") if s.strip()]
    outcome = orch.run()
    summary = json.loads((orch.layout["artifacts"] / "run_summary.json").read_text(encoding="utf-8"))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if outcome.status == "done" else 2


def cmd_status(args) -> int:
    orch = Orchestrator(Path(args.workspace))
    print(json.dumps(orch.summary(), ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_context(args) -> int:
    orch = Orchestrator(Path(args.workspace))
    print(json.dumps(orch.blackboard_context(), ensure_ascii=False, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulnmap", description="漏洞挖掘 Agent 运行时")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="跑完五个阶段")
    p_run.add_argument("workspace")
    p_run.add_argument("--max-turns", type=int, default=40)
    p_run.add_argument("--timeout", type=int, default=1800)
    p_run.add_argument("--max-requests", type=int, default=200,
                       help="整条 run 的模型请求上限（跨阶段累计）")
    p_run.add_argument("--max-tokens", type=int, default=2_000_000,
                       help="整条 run 的 token 上限（跨阶段累计）")
    p_run.add_argument("--max-seconds", type=int, default=7200,
                       help="整条 run 的墙钟上限（秒），超时强制终止")
    p_run.add_argument("--stages", default="",
                       help=("只跑指定阶段，逗号分隔，如 locate,report（离线模式用，不依赖镜像）；"
                             "未列出的阶段标记为 skipped，只向前跳过"))
    p_run.add_argument("--regate", action="store_true",
                       help=("re-gate：用已落盘证据重算判据（root_cause/因果要素/checks），"
                             "不重跑执行。缺镜像时镜像对账退化为检查点绑定 vs 旧 case.json"))
    p_run.set_defaults(func=cmd_run)

    p_st = sub.add_parser("status", help="查看阶段状态与工件")
    p_st.add_argument("workspace")
    p_st.set_defaults(func=cmd_status)

    p_cx = sub.add_parser("context", help="输出下一阶段上下文")
    p_cx.add_argument("workspace")
    p_cx.set_defaults(func=cmd_context)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
