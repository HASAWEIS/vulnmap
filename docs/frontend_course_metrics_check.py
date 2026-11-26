#!/usr/bin/env python3
"""docs/FRONTEND-COURSE-METRICS.md 的配套静态检查（只读，不改任何文件）。

用法：
    python3 docs/frontend_course_metrics_check.py [前端源目录]
默认前端源：/home/root_bupt/桌面/file/前端改版_20261115/MODIFIED_FILE
退出码 0 = 全过；1 = 有失败项。

检查三件事：
1. 课程三档口径卡片（内部 5/8 · 外部 0 · 后端 0）齐全、口径标签正确、来源文档真实存在；
2. 页面没有任何「课程已通过 / 评审通过」的肯定表述（否定语境除外）；
3. 现有 benchmark / 台账统计未被改动（benchStats 判据、stat-keys、metrics-grid、样式隔离），
   并用仓库测试里的同一组样例在 node 里复跑 benchStats 行为。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "/home/root_bupt/桌面/file/前端改版_20261115/MODIFIED_FILE")
HTML = SRC / "index.html"

FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS  " if cond else "FAIL  ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)


def main() -> int:
    html = HTML.read_text(encoding="utf-8")

    # ── 1. 快照与三档数字 ──────────────────────────────────────────
    m = re.search(r'<script id="course-metrics" type="application/json">(.+?)</script>', html, re.S)
    check("course-metrics 快照存在", bool(m))
    if not m:
        return finish()
    spec = json.loads(m.group(1))
    check("快照 schema = vulnmap.course_metrics.v1", spec.get("schema") == "vulnmap.course_metrics.v1")

    by_id = {x["id"]: x for x in spec.get("metrics", [])}
    check("三条指标齐全", set(by_id) == {"v2_internal", "external", "course_ready"}, str(sorted(by_id)))
    if len(by_id) != 3:
        return finish()
    check("V2 内部复核 = 5 / 8",
          (by_id["v2_internal"]["value"], by_id["v2_internal"]["denominator"]) == (5, 8))
    check("第三方独立复核 = 0", by_id["external"]["value"] == 0)
    check("后端 course_ready = 0", by_id["course_ready"]["value"] == 0)
    check("三档口径 = 内部 / 外部 / 后端",
          [by_id[k]["caliber"] for k in ("v2_internal", "external", "course_ready")]
          == ["internal", "external", "backend"])
    check("每条都带来源文档", all(m["sources"] and all(s.get("doc") for s in m["sources"])
                                  for m in spec["metrics"]))
    check("每条都带「不等于」说明", all(m.get("notEqual") for m in spec["metrics"]))

    # ── 1b. 文档口径 vs 现盘复算：差异必须写在卡片里，且与磁盘一致 ──
    v2 = by_id["v2_internal"]
    rec = v2.get("recompute")
    check("V2 卡片带现盘复算说明", bool(rec) and rec.get("value") == 4,
          f"recompute={rec and rec.get('value')}")
    check("现盘复算说明写明受影响案例 = CG-01",
          bool(rec) and rec.get("affected") == "CG-01")
    check("现盘复算说明给出复算依据文件",
          bool(rec) and all((REPO / x).is_file() for x in rec.get("sources", [])))
    check("页面出现「现盘复算」字样", "现盘复算" in html)
    cg01 = next((c for c in spec.get("cases", []) if c["case"] == "CG-01"), {})
    check("逐例表里 CG-01 标为「文档 true / 现盘 fail」", cg01.get("v2Now") is False)

    # 磁盘变了而卡片没跟上，就要红：review.json 在 → 不该再挂 fail；不在 → 必须挂说明
    cg01_review = REPO / "workspace" / "CG-01-arvo-44034" / "review.json"
    if cg01_review.is_file():
        check("CG-01 review.json 已恢复 → 卡片仍标记现盘 fail（需更新快照）",
              cg01.get("v2Now") is not False,
              "review.json 存在，请重跑 recompute.py 并把 v2Now / recompute 改回")
    else:
        check("CG-01 review.json 缺失 → 卡片已披露现盘 fail", cg01.get("v2Now") is False)

    docs = {s["doc"] for m in spec["metrics"] for s in m["sources"]}
    missing = sorted(d for d in docs if not (REPO / d).is_file())
    check("来源文档均存在于仓库", not missing, ", ".join(missing) or f"{len(docs)} 份")

    # ── 2. 不得写成「课程已通过」 ──────────────────────────────────
    hits = []
    for phrase in ("课程已通过", "课程通过", "评审通过", "验收通过"):
        for mm in re.finditer(re.escape(phrase), html):
            ctx = html[max(0, mm.start() - 12):mm.start()]
            if not re.search(r"(不等于|不构成|不得|不能|并非|未|否|不表述|不声称|不写成|不读成|不当作)", ctx):
                hits.append(phrase)
    check("没有「课程已通过」类肯定表述", not hits, ", ".join(sorted(set(hits))[:3]))
    check("页面写明「未通过、未判定」", "未通过、未判定" in html)

    # ── 3. 现有 benchmark / 台账统计未被改动 ───────────────────────
    bench = html[html.index("const BENCH_CRITERION"):html.index("const cell =")]
    check("benchStats 仍以 benchmark_verified 计通过", "benchmark_verified === true" in bench)
    check("benchStats 不用 local_verified 当通过", "local_verified)" not in bench)
    check("分赛道列仍在", all(k in html for k in ("CG 双端", "EG flag", "VG 行为")))
    check("撤回/分母口径仍在", "撤回" in html and "分母" in html)

    sk = re.search(r'<script id="stat-keys" type="application/json">(.+?)</script>', html, re.S)
    keys = {(g, k) for _, g, k in json.loads(sk.group(1))} if sk else set()
    check("stat-keys 未被改动",
          {("ledger_totals", "benchmark_verified"), ("ledger_totals", "local_dual_run_pass"),
           ("stats", "ledger_cases")} <= keys)

    inline_css = (re.search(r"<style>(.*?)</style>", html, re.S) or [None, ""])[1] if "<style>" in html else ""
    check("新卡片用独立类名 course-metric", 'class="course-metric"' in html and "course-metric{" in inline_css)
    check("内联样式不覆盖 .metric / .metrics-grid",
          not re.search(r"(^|[},])\s*\.(metrics-grid|metric|metric-)", inline_css))
    check("style.css 的 metrics-grid 未改",
          ".metrics-grid{display:grid" in (SRC / "style.css").read_text(encoding="utf-8"))

    # ── 4. 响应式断点 ─────────────────────────────────────────────
    check("课程卡片有 <=980px 断点", "@media(max-width:980px){.course-metrics" in html)
    check("课程卡片有 <=650px 单列断点",
          "@media(max-width:650px){" in html and "grid-template-columns:minmax(0,1fr)" in html)

    # ── 5. 内联脚本语法 + benchStats 行为回归（node）──────────────
    node = "node"
    try:
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "inline.js"
            f.write_text(scripts[-1], encoding="utf-8")
            r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
        check("内联脚本 node --check 通过", r.returncode == 0, r.stderr.strip()[:160])
    except FileNotFoundError:
        print("SKIP  内联脚本语法（node 不在 PATH）")

        node = None
    if node:
        items = [
            {"benchmark": "cybergym", "local_verified": True, "benchmark_verified": True,
             "exploit_flag_issued": False, "verdict": "pass", "causal_chain_verified": True,
             "high_severity_confirmed": True},
            {"benchmark": "cybergym", "local_verified": False, "benchmark_verified": False,
             "exploit_flag_issued": False, "verdict": "generated_but_unverified",
             "causal_chain_verified": False, "high_severity_confirmed": False},
            {"benchmark": "exploitgym", "local_verified": False, "benchmark_verified": True,
             "exploit_flag_issued": True, "verdict": "pass", "causal_chain_verified": False,
             "high_severity_confirmed": True},
            {"benchmark": "exploitgym", "local_verified": False, "benchmark_verified": False,
             "exploit_flag_issued": False, "verdict": "withdrawn", "causal_chain_verified": False,
             "high_severity_confirmed": False},
            {"benchmark": "vulngym", "local_verified": True, "benchmark_verified": True,
             "exploit_flag_issued": False, "verdict": "pass", "causal_chain_verified": False,
             "high_severity_confirmed": True},
        ]
        harness = ("const BENCH_LABEL={cybergym:'CyberGym',exploitgym:'ExploitGym',"
                   "vulngym:'VulnGym'};\nconst pct=(n,d)=>d?Math.round(n/d*100):0;\n"
                   + bench + "const items=" + json.dumps(items) + ";\n"
                   "console.log(JSON.stringify(benchStats(items)));\n")
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bench.js"
            f.write_text(harness, encoding="utf-8")
            r = subprocess.run([node, str(f)], capture_output=True, text=True)
        ok = r.returncode == 0
        stats = {}
        if ok:
            stats = {b["key"]: b for b in json.loads(r.stdout)}
            ok = ((stats["cybergym"]["n"], stats["cybergym"]["verified"], stats["cybergym"]["dual"]) == (2, 1, 1)
                  and (stats["exploitgym"]["n"], stats["exploitgym"]["verified"], stats["exploitgym"]["flag"]) == (2, 1, 1)
                  and (stats["vulngym"]["n"], stats["vulngym"]["verified"]) == (1, 1)
                  and sum(stats[k]["verified"] for k in stats) == 3)
        check("benchStats 回归：5 例 → 3 通过（CG 1 / EG 1 / VG 1）", ok, r.stderr.strip()[:160])

    return finish()


def finish() -> int:
    print()
    print(f"FAILED: {len(FAILS)}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
