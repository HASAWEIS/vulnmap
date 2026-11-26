#!/usr/bin/env python3
"""课程三指标前端数字一致性检查（只读）。

校验对象
  `dashboard.js` 里 `/* COURSE-METRICS:BEGIN … END */` 标记区的 `COURSE_METRICS` 快照
  （新版仪表盘三张卡片：V2 内部复核可提交 / 第三方独立复核 / 后端 course_ready）。

数字的唯一来源（全部只读，不写任何文件）
  CG-01        experiments/course-review-cg01/evidence/judgments.v2.json
                 → strict_submittable / external_independent_submittable
  批次六例      experiments/course-review-batch/summary.json
                 ＋ experiments/course-review-batch/evidence/<CASE>/judgments.v2.json（逐例复核）
  CG-14        experiments/course-review-batch/summary.json → separate（not_submittable）
  EG-02        experiments/course-review-eg02/{judgments.v2.json,summary.json}（不在分母，只验排除）
  course_ready workspace/<dir>/artifacts/report/case.json → acceptance.course_ready

一致性规则
  A. 页面快照合法、schema=v2、分母 8、scope 与 8 例审计范围一致、三指标 id/顺序固定。
  B. 页面三个值 = 现盘产物复算值；页面逐例行 = 逐例产物；页面内部「逐例计数 = 卡片值」。
  C. 页面 course_ready 逐例 = case.json.acceptance.course_ready（含 blocked_by）。
  D. 批次 summary 的 counts / 逐例 strict 标记 = evidence/<CASE>/judgments.v2.json。
  E. EG-02 不在分母、出现在 excluded；CG-14 计为不可提交。
  F. 任何一处不一致 → 逐条列出，退出码非 0。

用法
    python3 scripts/check_course_metrics.py                # 人类可读 + 退出码
    python3 scripts/check_course_metrics.py --quiet        # 只打印结论与失败项
    python3 scripts/check_course_metrics.py --json         # 机读结果
    python3 scripts/check_course_metrics.py --dashboard /path/to/dashboard.js

退出码
    0  一致
    2  数字/结构不一致（已列出具体条目）
    3  检查无法完成（找不到 dashboard.js 或关键来源文件缺失）
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "/* COURSE-METRICS:BEGIN"
END = "/* COURSE-METRICS:END */"
SCHEMA = "vulnmap.course_metrics.v2"

# 分母 8 例：docs/COURSE-CASE-AUDIT.md §0 的审计范围，顺序即页面表格顺序。
CASES = [
    {"case": "CG-01", "dir": "CG-01-arvo-44034", "task_id": "arvo:44034", "source": "cg01"},
    {"case": "CG-07", "dir": "CG-07-arvo-10096", "task_id": "arvo:10096", "source": "batch"},
    {"case": "CG-14", "dir": "CG-14-arvo-11253", "task_id": "arvo:11253", "source": "separate"},
    {"case": "CG-18", "dir": "S7-CG18-arvo-12420", "task_id": "arvo:12420", "source": "batch"},
    {"case": "CG-29", "dir": "S14-CG29-arvo-11011", "task_id": "arvo:11011", "source": "batch"},
    {"case": "CG-30", "dir": "S15-CG30-arvo-29633", "task_id": "arvo:29633", "source": "batch"},
    {"case": "CG-31", "dir": "S16-CG31-arvo-61675", "task_id": "arvo:61675", "source": "batch"},
    {"case": "CG-36", "dir": "S19-CG36-arvo-54839", "task_id": "arvo:54839", "source": "batch"},
]
CASE_IDS = [c["case"] for c in CASES]
METRIC_IDS = ["v2_internal", "external_independent", "backend_course_ready"]

CG01_JUDGMENTS = ROOT / "experiments" / "course-review-cg01" / "evidence" / "judgments.v2.json"
BATCH_SUMMARY = ROOT / "experiments" / "course-review-batch" / "summary.json"
BATCH_EVIDENCE = ROOT / "experiments" / "course-review-batch" / "evidence"
EG02_JUDGMENTS = ROOT / "experiments" / "course-review-eg02" / "judgments.v2.json"


class Report:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, ok: bool, code: str, msg: str) -> None:
        self.rows.append({"ok": bool(ok), "code": code, "msg": msg})

    def check(self, ok: bool, code: str, msg: str) -> None:
        self.add(ok, code, msg)

    @property
    def fails(self) -> list[dict]:
        return [r for r in self.rows if not r["ok"]]

    @property
    def oks(self) -> list[dict]:
        return [r for r in self.rows if r["ok"]]


def read_json(path: Path):
    """返回 (data, error)；只读。"""
    if not path.is_file():
        return None, f"缺文件 {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:  # noqa: BLE001
        return None, f"读取失败 {path}: {exc}"


def find_dashboard(explicit: str | None) -> Path | None:
    """按 CLI → 环境变量 → 仓库内软链 → 同级交付目录 的顺序定位 dashboard.js。"""
    if explicit:
        p = Path(explicit)
        return p.resolve() if p.is_file() else None
    candidates: list[Path] = []
    env = os.environ.get("COURSE_METRICS_DASHBOARD")
    if env:
        candidates.append(Path(env))
    candidates.append(ROOT / "vulnmap_platform" / "static" / "dashboard.js")
    candidates.append(ROOT / "web" / "dashboard.js")
    candidates.append(ROOT.parent / "前端收口_20261125.sv8KTO" / "MODIFIED_FILE" / "dashboard.js")
    for p in sorted(glob.glob(str(ROOT.parent / "前端收口*" / "MODIFIED_FILE" / "dashboard.js"))):
        candidates.append(Path(p))
    for p in candidates:
        if p.is_file():
            return p.resolve()
    return None


def extract_snapshot(js: str):
    """从标记区取出 COURSE_METRICS JSON；返回 (dict|None, error|None)。"""
    i, j = js.find(BEGIN), js.find(END)
    if i < 0 or j < 0 or j < i:
        return None, f"缺 COURSE-METRICS 标记区（{BEGIN} … {END}）"
    block = js[i:j + len(END)]
    k = block.find("const COURSE_METRICS")
    if k < 0:
        return None, "标记区内没有 const COURSE_METRICS"
    b = block.find("{", k)
    if b < 0:
        return None, "COURSE_METRICS 后没有对象字面量"
    try:
        snap, _ = json.JSONDecoder().raw_decode(block[b:])
    except json.JSONDecodeError as exc:
        return None, f"COURSE_METRICS 不是合法 JSON：{exc}"
    return snap, None


def load_case_json(report: Report) -> dict[str, dict]:
    """逐例读 case.json 的 acceptance.course_ready（缺失也记一条失败）。"""
    out: dict[str, dict] = {}
    for c in CASES:
        p = ROOT / "workspace" / c["dir"] / "artifacts" / "report" / "case.json"
        data, err = read_json(p)
        if data is None:
            report.check(False, "C-MISSING", f"{c['case']} case.json 不可读：{err}")
            out[c["case"]] = {"found": False, "course_ready": None, "blocked_by": None}
            continue
        acc = data.get("acceptance") or {}
        if "course_ready" not in acc:
            report.check(False, "C-FIELD", f"{c['case']} case.json 缺 acceptance.course_ready")
        out[c["case"]] = {
            "found": True,
            "course_ready": acc.get("course_ready"),
            "blocked_by": acc.get("blocked_by") or acc.get("course_ready_blocked_by"),
        }
    return out


def recompute(report: Report) -> dict[str, dict]:
    """从 judgments / summary / case.json 现算逐例与合计，并交叉校验 summary。"""
    cg01, cg01_err = read_json(CG01_JUDGMENTS)
    if cg01 is None:
        report.check(False, "B-MISSING", f"CG-01 judgments 不可读：{cg01_err}")
        cg01 = {}

    summary, sum_err = read_json(BATCH_SUMMARY)
    if summary is None:
        report.check(False, "B-MISSING", f"批次 summary 不可读：{sum_err}")
        summary = {}
    batch_by_case = {x.get("case"): x for x in summary.get("cases", [])}
    separate_by_case = {x.get("case"): x for x in summary.get("separate", [])}

    eg02, eg02_err = read_json(EG02_JUDGMENTS)
    if eg02 is None:
        report.check(False, "E-MISSING", f"EG-02 judgments 不可读：{eg02_err}")
        eg02 = {}

    case_json = load_case_json(report)
    per: dict[str, dict] = {}

    for c in CASES:
        case, src = c["case"], c["source"]
        jpath = BATCH_EVIDENCE / case / "judgments.v2.json"
        judgments, jerr = read_json(jpath) if src == "batch" else (None, None)

        if src == "cg01":
            v2 = cg01.get("strict_submittable") is True
            ext = cg01.get("external_independent_submittable") is True
            basis = str(CG01_JUDGMENTS.relative_to(ROOT))
        elif src == "batch":
            b = batch_by_case.get(case)
            if judgments is None:
                report.check(False, "D-MISSING", f"{case} judgments 不可读：{jerr}")
            if b is None:
                report.check(False, "D-MISSING", f"批次 summary 缺 {case}")
                v2 = judgments.get("strict_submittable") is True if judgments else False
                ext = judgments.get("external_independent_submittable") is True if judgments else False
            else:
                v2 = b.get("strict_submittable") is True
                ext = b.get("external_independent_submittable") is True
                if judgments is not None:
                    report.check(
                        (judgments.get("strict_submittable") is True) == v2,
                        "D-STRICT",
                        f"{case} strict_submittable：summary={v2} / judgments={judgments.get('strict_submittable')}",
                    )
                    report.check(
                        (judgments.get("external_independent_submittable") is True) == ext,
                        "D-EXTERNAL",
                        f"{case} external_independent_submittable：summary={ext} / "
                        f"judgments={judgments.get('external_independent_submittable')}",
                    )
            basis = f"experiments/course-review-batch/summary.json + evidence/{case}/judgments.v2.json"
        else:  # separate：CG-14，不进批次计数，按 not_submittable
            s = separate_by_case.get(case)
            if s is None:
                report.check(False, "D-MISSING", f"批次 summary separate 缺 {case}")
                v2 = ext = False
            else:
                report.check(s.get("bucket") == "not_submittable", "D-BUCKET",
                             f"{case} separate.bucket={s.get('bucket')!r}（期望 'not_submittable'）")
                report.check(not s.get("in_batch_count", False), "D-COUNT",
                             f"{case} separate.in_batch_count={s.get('in_batch_count')}（期望 False）")
                v2 = ext = False
            basis = "experiments/course-review-batch/summary.json → separate"

        cr = case_json[case]["course_ready"] is True
        per[case] = {
            "case": case,
            "task_id": c["task_id"],
            "dir": c["dir"],
            "v2_internal": v2,
            "external_independent": ext,
            "course_ready": cr,
            "course_ready_raw": case_json[case]["course_ready"],
            "course_ready_blocked_by": case_json[case]["blocked_by"],
            "basis": basis,
        }

    # —— 批次 summary 自洽性（counts 与逐例）——
    counts = summary.get("counts") or {}
    # summary.counts 只统计批次六例（CG-01 不在批次内、单独来自 cg01 judgments）
    batch_true_cases = sorted(c for c, v in per.items() if c in batch_by_case and v["v2_internal"])
    batch_false_cases = sorted(c for c, v in per.items() if c in batch_by_case and not v["v2_internal"])
    batch_ext_cases = sorted(c for c, v in per.items() if c in batch_by_case and v["external_independent"])
    report.check(counts.get("batch_size") == len(batch_by_case),
                 "D-SIZE", f"summary.counts.batch_size={counts.get('batch_size')} / 逐例 {len(batch_by_case)}")
    report.check(sorted(counts.get("strict_true_cases") or []) == batch_true_cases,
                 "D-TRUE", f"summary.counts.strict_true_cases={counts.get('strict_true_cases')} / 复算 {batch_true_cases}")
    report.check(sorted(counts.get("strict_false_cases") or []) == batch_false_cases,
                 "D-FALSE", f"summary.counts.strict_false_cases={counts.get('strict_false_cases')} / 复算 {batch_false_cases}")
    report.check(counts.get("strict_submittable_true") == len(batch_true_cases),
                 "D-TRUE-N", f"summary.counts.strict_submittable_true={counts.get('strict_submittable_true')} / 复算 {len(batch_true_cases)}")
    report.check(counts.get("strict_submittable_false") == len(batch_false_cases),
                 "D-FALSE-N", f"summary.counts.strict_submittable_false={counts.get('strict_submittable_false')} / 复算 {len(batch_false_cases)}")
    report.check(counts.get("external_independent_true") == len(batch_ext_cases),
                 "D-EXT-N", f"summary.counts.external_independent_true={counts.get('external_independent_true')} / 复算 {len(batch_ext_cases)}")
    listed = sorted(counts.get("separate_listed") or [])
    report.check(listed == sorted(separate_by_case), "D-SEP",
                 f"summary.counts.separate_listed={listed} / separate 桶 {sorted(separate_by_case)}")

    # —— 排除项 ——
    report.check(eg02.get("strict_submittable") is not True, "E-EG02",
                 "EG-02 judgments.strict_submittable 为 true（应排除、不计入分母）")
    report.check("EG-02" not in CASE_IDS, "E-EG02-SCOPE", "EG-02 不应出现在分母")

    return per


def check_page(report: Report, snap: dict, per: dict[str, dict]) -> dict:
    """页面快照 vs 现算值：结构、三数、逐例、内部自洽。"""
    report.check(snap.get("schema") == SCHEMA, "A-SCHEMA", f"schema={snap.get('schema')!r}（期望 {SCHEMA}）")

    den = snap.get("denominator") or {}
    report.check(den.get("value") == len(CASES), "A-DEN",
                 f"分母={den.get('value')}（期望 {len(CASES)}）")
    report.check(list(den.get("scope") or []) == CASE_IDS, "A-SCOPE",
                 f"分母 scope={den.get('scope')}（期望 {CASE_IDS}）")

    metrics = snap.get("metrics") or []
    report.check([m.get("id") for m in metrics] == METRIC_IDS, "A-IDS",
                 f"指标 id/顺序={[m.get('id') for m in metrics]}（期望 {METRIC_IDS}）")
    m = {x.get("id"): x for x in metrics}

    computed = {
        "v2_internal": sum(1 for v in per.values() if v["v2_internal"]),
        "external_independent": sum(1 for v in per.values() if v["external_independent"]),
        "backend_course_ready": sum(1 for v in per.values() if v["course_ready"]),
    }
    labels = {
        "v2_internal": "V2 内部复核可提交",
        "external_independent": "第三方独立复核",
        "backend_course_ready": "后端 course_ready",
    }
    for mid in METRIC_IDS:
        card = m.get(mid) or {}
        report.check(card.get("value") == computed[mid], "B-VALUE",
                     f"页面「{labels[mid]}」={card.get('value')} / 复算 {computed[mid]}")
        report.check(card.get("denominator") == len(CASES), "B-DEN",
                     f"页面「{labels[mid]}」分母={card.get('denominator')}（期望 {len(CASES)}）")

    # 逐例表
    rows = snap.get("cases") or []
    report.check(len(rows) == len(CASES), "B-ROWS",
                 f"逐例行数={len(rows)}（期望 {len(CASES)}）")
    by_case = {r.get("case"): r for r in rows}
    report.check(sorted(by_case) == sorted(CASE_IDS), "B-ROW-SET",
                 f"逐例表案例集合={sorted(by_case)}（期望 {sorted(CASE_IDS)}）")
    report.check(len(by_case) == len(rows), "B-ROW-DUP", "逐例表存在重复案例行")

    for case in CASE_IDS:
        row = by_case.get(case)
        if row is None:
            report.check(False, "B-ROW-MISS", f"逐例表缺 {case}")
            continue
        want = per[case]
        report.check(row.get("task_id") == want["task_id"], "B-ROW-TASK",
                     f"{case} task_id：页面={row.get('task_id')!r} / 期望={want['task_id']!r}")
        report.check(bool(row.get("v2_internal")) == want["v2_internal"], "B-ROW-V2",
                     f"{case} v2_internal：页面={row.get('v2_internal')} / 复算={want['v2_internal']}")
        report.check(bool(row.get("external_independent")) == want["external_independent"],
                     "B-ROW-EXT",
                     f"{case} external_independent：页面={row.get('external_independent')} "
                     f"/ 复算={want['external_independent']}")
        report.check(bool(row.get("course_ready")) == want["course_ready"], "B-ROW-CR",
                     f"{case} course_ready：页面={row.get('course_ready')} / case.json={want['course_ready']}")
        report.check(list(row.get("course_ready_blocked_by") or []) == list(want["course_ready_blocked_by"] or []),
                     "B-ROW-CR-BLOCKED",
                     f"{case} course_ready blocked_by：页面={row.get('course_ready_blocked_by')} "
                     f"/ case.json={want['course_ready_blocked_by']}")

    # 页面内部自洽：逐例计数必须等于卡片值
    for mid, key in (("v2_internal", "v2_internal"),
                     ("external_independent", "external_independent"),
                     ("backend_course_ready", "course_ready")):
        n = sum(1 for r in rows if r.get(key) is True)
        report.check((m.get(mid) or {}).get("value") == n, "B-SUM",
                     f"页面卡片「{labels[mid]}」={(m.get(mid) or {}).get('value')} / 逐例行合计 {n}")

    excluded = {x.get("case") for x in snap.get("excluded") or []}
    report.check({"VG-01", "EG-02"} <= excluded, "E-EXCLUDED",
                 f"excluded 含 VG-01 与 EG-02（实际 {sorted(x for x in excluded if x)}）")
    report.check(not (excluded & set(CASE_IDS)), "E-EXCLUDED-OVERLAP",
                 f"excluded 与分母重叠项：{sorted(excluded & set(CASE_IDS))}")
    return computed


def main() -> int:
    ap = argparse.ArgumentParser(description="课程三指标前端数字一致性检查（只读）")
    ap.add_argument("--dashboard", help="dashboard.js 路径（默认自动定位）")
    ap.add_argument("--json", action="store_true", help="输出机读 JSON")
    ap.add_argument("--quiet", action="store_true", help="只打印结论与失败项")
    args = ap.parse_args()

    report = Report()
    dash = find_dashboard(args.dashboard)
    if dash is None:
        print("[check] 找不到 dashboard.js（可用 --dashboard 指定）", file=sys.stderr)
        return 3

    try:
        js = dash.read_text(encoding="utf-8")
    except OSError as exc:  # noqa: BLE001
        print(f"[check] 读 dashboard.js 失败：{exc}", file=sys.stderr)
        return 3

    snap, err = extract_snapshot(js)
    if snap is None:
        print(f"[check] {dash}：{err}", file=sys.stderr)
        return 3

    per = recompute(report)
    computed = check_page(report, snap, per)

    page = {m.get("id"): m.get("value") for m in snap.get("metrics") or []}
    result = {
        "ok": not report.fails,
        "dashboard": str(dash),
        "computed": computed,
        "page": page,
        "cases": {k: {"v2_internal": v["v2_internal"],
                      "external_independent": v["external_independent"],
                      "course_ready": v["course_ready"]} for k, v in per.items()},
        "checks": report.rows,
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if not args.quiet:
            print("课程三指标前端数字一致性检查（只读）")
            print(f"  页面：{dash}")
            print(f"  仓库：{ROOT}")
            for r in report.oks:
                print(f"  ok   [{r['code']}] {r['msg']}")
        for r in report.fails:
            print(f"  FAIL [{r['code']}] {r['msg']}", file=sys.stderr)
        print(f"\n复算：{computed['v2_internal']}/{len(CASES)} · "
              f"{computed['external_independent']}/{len(CASES)} · "
              f"{computed['backend_course_ready']}/{len(CASES)}"
              f"（V2 内部 / 第三方 / 后端 course_ready）")
        print(f"页面：{page.get('v2_internal')}/{len(CASES)} · "
              f"{page.get('external_independent')}/{len(CASES)} · "
              f"{page.get('backend_course_ready')}/{len(CASES)}")
        print(f"断言 {len(report.rows)} 条：通过 {len(report.oks)}，失败 {len(report.fails)}"
              f"｜{'PASS' if not report.fails else 'FAIL'}")

    return 0 if not report.fails else 2


if __name__ == "__main__":
    raise SystemExit(main())
