#!/usr/bin/env python3
"""新版仪表盘「课程三指标」检查器（只读）。

断言四类：
  A. 快照与产物一致 —— dashboard.js 内 COURSE_METRICS 的 denominator/metrics/cases/verdict
     必须等于 `experiments/course-review-cg01/course_metrics_snapshot.py` 现算结果（页面不许手填数）。
  B. 结构与口径 —— 三张卡片、三种 data-caliber（internal/external/backend）、分母 8、
     逐例 8 行；三个标签文案在；空值不退化显示 0。
  C. 不覆盖旧内容 —— 新版其它文件（app.js / index.html / style.css / cases.html / …）与
     `前端收口_20261125.sv8KTO/modified.sha256` 逐件一致（只有 dashboard.js / dashboard.css 变了）；
     首页仍含 hero / dash-kpis / 赛道条 / 发现记录 / 图示四个区块。
  D. 无后端改动 —— 静态目录仍是指向 MODIFIED_FILE 的软链；后端 API 代码里没有课程指标逻辑；
     仓库根不是 git 工作区（未 commit）。

用法：
    python3 docs/frontend_course_metrics_v2_check.py          # 断言 + 渲染冒烟（需 node）
    python3 docs/frontend_course_metrics_v2_check.py --quiet   # 只打印结论
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLOSURE = ROOT.parent / "前端收口_20261125.sv8KTO"
FRONT = CLOSURE / "MODIFIED_FILE"
STATIC_LINK = ROOT / "vulnmap_platform" / "static"
API = ROOT / "vulnmap_platform" / "api" / "app.py"

sys.path.insert(0, str(ROOT / "experiments" / "course-review-cg01"))
import course_metrics_snapshot as snap_mod  # noqa: E402

BEGIN, END = snap_mod.BEGIN, snap_mod.END
FAILS: list[str] = []
OKS: list[str] = []


def check(cond: bool, msg: str) -> None:
    (OKS if cond else FAILS).append(msg)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def block_text(js: str) -> str | None:
    i, j = js.find(BEGIN), js.find(END)
    return js[i:j + len(END)] if i >= 0 and j >= 0 else None


def snapshot_in_page(js: str) -> dict | None:
    b = block_text(js)
    if not b:
        return None
    try:
        return json.loads(b[b.find("{"):b.rfind("}") + 1])
    except Exception:                                            # noqa: BLE001
        return None


def check_snapshot() -> dict | None:
    js = (FRONT / "dashboard.js").read_text(encoding="utf-8")
    page = snapshot_in_page(js)
    want = snap_mod.build()
    if page is None:
        check(False, "A: dashboard.js 的 COURSE_METRICS 块缺失或不是合法 JSON")
        return None
    for key in ("denominator", "metrics", "cases", "verdict"):
        check(page.get(key) == want.get(key), f"A: 快照 {key} 与产物一致")
    check(page.get("schema") == "vulnmap.course_metrics.v2", "A: schema = vulnmap.course_metrics.v2")

    m = {x["id"]: x for x in page.get("metrics", [])}
    check(len(m) == 3, "A: 恰好三个指标")
    total = page.get("denominator", {}).get("value")
    check(total == 8, f"A: 分母 = 8（实际 {total}）")
    check(len(page.get("cases", [])) == total, "A: 逐例行数 = 分母")
    # 数字必须能被产物复算（防「页面上写死一个更好看的数」）
    cg01 = snap_mod.load(snap_mod.CG01_EVID / "judgments.v2.json")
    batch = snap_mod.load(snap_mod.BATCH)["counts"]
    expect_v2 = int(cg01["strict_submittable"] is True) + len(batch["strict_true_cases"])
    check(m.get("v2_internal", {}).get("value") == expect_v2,
          f"A: V2 内部可提交 = 复算值 {expect_v2}（页面 {m.get('v2_internal', {}).get('value')}）")
    check(m.get("external_independent", {}).get("value") == 0, "A: 第三方独立复核 = 0")
    check(m.get("backend_course_ready", {}).get("value") == 0, "A: 后端 course_ready = 0")
    # 每个指标都要有口径标签、不等于什么、来源
    for k, v in m.items():
        check(v.get("caliber") in ("internal", "external", "backend"), f"B: {k} caliber 合法")
        check(bool(v.get("caliberLabel")), f"B: {k} 有口径中文标签")
        check(bool(v.get("notEqual")), f"B: {k} 写了「不等于什么」")
        check(len(v.get("sources") or []) >= 2, f"B: {k} 至少 2 条来源")
    return page


def check_template() -> None:
    js = (FRONT / "dashboard.js").read_text(encoding="utf-8")
    css = (FRONT / "dashboard.css").read_text(encoding="utf-8")
    for t in ("V2 内部复核可提交", "第三方独立复核", "后端 course_ready"):
        check(t in js, f"B: 页面模板含标签「{t}」")
    for c in ("internal", "external", "backend"):
        check(f'data-caliber="${{esc(caliber)}}"' in js or f'data-caliber="{c}"' in js,
              f"B: 卡片带 data-caliber（{c}）")
    check("cm-card" in js and "cm-cards" in css, "B: 卡片结构 + 样式齐备")
    check(bool(re.search(r"\.cm-cards\{[^}]*grid-template-columns:repeat\(3,minmax\(0,1fr\)\)", css)),
          "B: 三列布局")
    check("@media(max-width:1100px)" in css and "@media(max-width:690px)" in css, "B: 两个响应式断点")
    check("口径快照未载入" in js and "不是零" in js, "B: 快照缺失时显示「未载入」，不回退成 0")
    check("courseMetricsSection()" in js, "B: 区块由 courseMetricsSection() 渲染")
    # 旧区块必须还在（模板层）
    for marker in ('dash-hero', 'dash-kpis', '按评测轨道查看', '发现记录', '架构和流程图', 'dash-score'):
        check(marker in js, f"C: 原区块仍在（{marker}）")
    # 导航不被改（导航在 app.js）
    app = (FRONT / "app.js").read_text(encoding="utf-8")
    check("const VIEWS=[" in app and "'总览'" in app, "C: 导航定义未被改（仍在 app.js）")
    idx = (FRONT / "index.html").read_text(encoding="utf-8")
    check('href="dashboard.css"' in idx and 'src="dashboard.js"' in idx, "C: index.html 仍只挂 css/js")


def check_untouched() -> None:
    ref = CLOSURE / "modified.sha256"
    if not ref.exists():
        check(False, f"C: 缺基线清单 {ref.name}")
        return
    rows = {}
    for line in ref.read_text().splitlines():
        if line.strip():
            h, p = line.split(None, 1)
            rows[p.strip().lstrip("./")] = h
    changed = []
    for p, h in rows.items():
        f = FRONT / p
        if not f.is_file():
            changed.append((p, "MISSING"))
        elif sha(f) != h:
            changed.append((p, "DIFF"))
    only = sorted(x for x, _ in changed)
    check(only == ["dashboard.css", "dashboard.js"],
          f"C: 相对闭包基线只改这两个文件（实际 {only}）")


def check_backend() -> None:
    check(STATIC_LINK.is_symlink() and STATIC_LINK.resolve() == FRONT,
          "D: 8102 静态目录仍是指向 MODIFIED_FILE 的软链")
    if API.exists():
        txt = API.read_text(encoding="utf-8", errors="ignore")
        check("course_metrics" not in txt and "courseMetrics" not in txt,
              "D: 后端 API 代码无课程指标逻辑（未改后端）")
    git = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT,
                         capture_output=True, text=True)
    check(git.returncode != 0, "D: 仓库根不是 git 工作区（未 commit）")


HARNESS = r"""
const fs=require('fs'),vm=require('vm'),http=require('http');
const DIR=process.argv[2];
function get(path){return new Promise((res,rej)=>{const r=http.get({host:'127.0.0.1',port:8102,path,timeout:800},x=>{let b='';x.on('data',d=>b+=d);x.on('end',()=>res({ok:x.statusCode<400,status:x.statusCode,json:()=>Promise.resolve(JSON.parse(b))}));});r.on('error',rej);r.on('timeout',()=>{r.destroy();rej(new Error('timeout'))});});}
const store=new Map();
function el(id){if(!store.has(id))store.set(id,{id,innerHTML:'',textContent:'',classList:{add(){},remove(){},toggle(){return false},contains(){return false}},dataset:{},setAttribute(){},getAttribute(){return null},addEventListener(){},appendChild(){},showModal(){},close(){},style:{}});return store.get(id);}
const document={body:{dataset:{},classList:{add(){},remove(){},toggle(){return false},contains(){return false}},appendChild(){}},querySelector:s=>el(s),querySelectorAll:()=>[],createElement:()=>el('c'+Math.random()),addEventListener(){},getElementById:id=>el('#'+id)};
const window={addEventListener(){},location:{reload(){}}};
const ctx={console,document,window,matchMedia:q=>({matches:false,media:q,addEventListener(){},removeEventListener(){}}),fetch:get,setTimeout,clearTimeout,AbortController,Promise,JSON,Number,String,Array,Math,encodeURIComponent,alert(){},localStorage:{getItem(){return null},setItem(){}}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(DIR+'/app.js','utf8'),ctx,{filename:'app.js'});
vm.runInContext(fs.readFileSync(DIR+'/dashboard.js','utf8'),ctx,{filename:'dashboard.js'});
setTimeout(()=>{const h=el('#content').innerHTML;
console.log(JSON.stringify({len:h.length,cards:(h.match(/class="cm-card"/g)||[]).length,
 values:[...h.matchAll(/<strong>(\d+)<\/strong><span>\/ (\d+) 例<\/span>/g)].map(m=>m[1]+'/'+m[2]),
 calibers:[...h.matchAll(/data-caliber="(\w+)"/g)].map(m=>m[1]),
 rows:(h.match(/<tr><th scope="row">/g)||[]).length,
 labels:['V2 内部复核可提交','第三方独立复核','后端 course_ready'].every(t=>h.includes(t)),
 tracks:(h.match(/class="dash-bench"/g)||[]).length,
 hero:h.includes('Benchmark 验证通过率'),kpis:(h.match(/class="dash-kpis"/g)||[]).length,
 discovery:h.includes('发现记录'),diagrams:h.includes('架构和流程图'),
 unclosed:(h.match(/<div/g)||[]).length-(h.match(/<\/div>/g)||[]).length}));},2500);
"""


# 批次目录不在本任务写范围内；这两处 18:58 的重写让 18:41 生成的清单过期（已知、已登记，不算本轮失败）
BATCH_KNOWN_STALE = {
    "experiments/course-review-batch/evidence/CG-07/model_params.json",
    "experiments/course-review-batch/evidence/CG-18/model_params.json",
    "workspace/CG-07-arvo-10096/review.json",
    "workspace/S7-CG18-arvo-12420/review.json",
}


def check_batch_manifest() -> None:
    man = ROOT / "experiments" / "course-review-batch" / "MANIFEST.sha256"
    if not man.exists():
        check(False, "C: 缺批次清单 experiments/course-review-batch/MANIFEST.sha256")
        return
    bad = []
    for line in man.read_text().splitlines():
        if not line.strip():
            continue
        h, rel = line.split(None, 1)
        f = ROOT / rel.strip()
        if not f.is_file() or sha(f) != h:
            bad.append(rel.strip())
    unknown = sorted(set(bad) - BATCH_KNOWN_STALE)
    check(not unknown,
          f"C: 批次清单过期项仅限已登记的 4 件（实际 {len(bad)} 件，未登记 {unknown}）")
    if bad:
        print(f"[check] 注意：批次清单 {len(bad)} 件过期 → {sorted(bad)}")
        print("[check]       原因：清单 18:41:45 生成，这 4 件 18:58:22 被重写；"
              "批次目录不在本轮写范围，未刷新（见 FRONTEND-COURSE-METRICS-V2.md §6）")


def check_render(expect: list[str] | None = None) -> None:
    node = shutil.which("node")
    if not node:
        print("[check] 跳过渲染冒烟：找不到 node")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(HARNESS)
        path = fh.name
    try:
        out = subprocess.run([node, path, str(FRONT)], capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            check(False, f"B: 渲染冒烟失败：{out.stderr.strip().splitlines()[-1] if out.stderr else 'unknown'}")
            return
        data = json.loads(out.stdout.strip().splitlines()[-1])
        check(data["cards"] == 3, f"B: 渲染出 3 张卡片（实际 {data['cards']}）")
        want_vals = expect or ["5/8", "0/8", "0/8"]      # 期望值由产物现算后传入，不写死
        check(data["values"] == want_vals,
              f"B: 三卡数字 = {' · '.join(want_vals)}（实际 {data['values']}）")
        check(data["calibers"] == ["internal", "external", "backend"], "B: 口径顺序 internal → external → backend")
        check(data["rows"] == 8, f"B: 逐例表 8 行（实际 {data['rows']}）")
        check(data["labels"] is True, "B: 渲染结果含三个标签文案")
        check(data["hero"] and data["kpis"] == 1, "C: hero 与 KPI 卡片区仍在")
        check(data["discovery"] and data["diagrams"], "C: 发现记录与图示区仍在")
        check(data["tracks"] in (0, 3), f"C: 赛道条未被破坏（实际 {data['tracks']}，0 = 接口离线）")
        check(data["unclosed"] == 0, "B: 生成的 HTML div 配平")
    finally:
        Path(path).unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    page = check_snapshot()
    check_template()
    check_untouched()
    check_backend()
    check_batch_manifest()
    want = snap_mod.build()                                # 产物现值 → 渲染断言期望
    expect = [f"{x['value']}/{x['denominator']}" for x in want["metrics"]]
    check_render(expect)

    if not args.quiet:
        for m in OKS:
            print(f"  ok   {m}")
    for m in FAILS:
        print(f"  FAIL {m}", file=sys.stderr)
    m = {x["id"]: x["value"] for x in (page or {}).get("metrics", [])}
    print(f"\n[check] 断言 {len(OKS) + len(FAILS)} 条：通过 {len(OKS)}，失败 {len(FAILS)}"
          f"｜页面快照 V2 内部 {m.get('v2_internal')}/{((page or {}).get('denominator') or {}).get('value')}"
          f"、第三方 {m.get('external_independent')}、course_ready {m.get('backend_course_ready')}")
    return 0 if not FAILS else 2


if __name__ == "__main__":
    raise SystemExit(main())
