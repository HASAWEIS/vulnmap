"""vulnmap 平台后端：把已有工件暴露为只读 API。

设计约束：
- **只读**：展示层不修改任何验收状态，避免"页面点一下就把 case 判过了"
- **单一数据源**：一律从 workspace/*/artifacts 与 experiments/ 读取，不另存一份
- **不隐藏失败**：所有案例都在列表里，包括 unsupported / withdrawn
"""
from __future__ import annotations
import json
import pathlib
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WS = ROOT / "workspace"
EXP = ROOT / "experiments"
STATIC = ROOT / "vulnmap_platform" / "static"
try:
    _GEN_PATH = json.loads((ROOT / "docs" / "generation-path.json").read_text(encoding="utf-8"))
except Exception:
    _GEN_PATH = {}


def _gen_path(case_id: str, dir_name: str) -> str:
    import re as _re
    for k in (case_id, dir_name):
        if k and k in _GEN_PATH:
            return _GEN_PATH[k]
    m = _re.search(r"(CG-?\d+|VG-\d+)", case_id or dir_name or "")
    if m:
        key = m.group(1)
        if not key.startswith("CG-") and key.startswith("CG"):
            key = "CG-" + key[2:]
        if key in _GEN_PATH:
            return _GEN_PATH[key]
    return "未记录"

app = FastAPI(title="vulnmap platform", docs_url="/api/docs", redoc_url=None)


def _read(p: pathlib.Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _task(d: pathlib.Path) -> dict:
    return _read(d / "task.json") or {}


def _case(d: pathlib.Path) -> dict | None:
    return _read(d / "artifacts" / "report" / "case.json")


def _case_dirs() -> list[pathlib.Path]:
    out = []
    for d in sorted(WS.iterdir()):
        if d.is_dir() and (d / "task.json").exists():
            out.append(d)
    return out


def _workspace_dirs() -> list[pathlib.Path]:
    """workspace/ 下的**全部**目录，含没有 task.json 的实验复跑目录。

    这些目录是"运行"，不是"案例"：同一个漏洞可能被复跑多次
    （S2-*/S4-*/S5*-* 等），把它们数进案例会虚增样本量。
    """
    if not WS.is_dir():
        return []
    return sorted(d for d in WS.iterdir() if d.is_dir())


def _run_count() -> int:
    """流水线运行次数 = 各运行库 runs 表的行数之和。

    一个目录可能跑过多次（runs 多行），也可能一个库都没有；
    取不到库/表时按 0 计，不抛异常（展示层不该因脏数据 500）。
    """
    import sqlite3

    n = 0
    for rt in WS.glob("*/.runtime"):
        for db in sorted(rt.glob("*.db")):
            try:
                con = sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True)
            except Exception:
                continue
            try:
                row = con.execute("SELECT COUNT(*) FROM runs").fetchone()
                if row:
                    n += int(row[0])
            except Exception:
                pass
            finally:
                con.close()
    return n


def _ledger_rows(led: dict) -> list[dict]:
    return [r for r in (led.get("rows") or []) if isinstance(r, dict)]


def _ledger_dir_names(led: dict) -> list[str]:
    """台账条目对应的 workspace 目录名（row["source"] = workspace/<dir>/...）。"""
    out = []
    for r in _ledger_rows(led):
        parts = pathlib.PurePosixPath(str(r.get("source") or "")).parts
        if len(parts) >= 2 and parts[0] == "workspace":
            out.append(parts[1])
    return out


def _stats(ledger_totals: dict) -> dict:
    """四个口径分开给，禁止合并成一个"完成率"。

    - workspaces：workspace/ 下目录数（运行载体，含实验复跑目录）
    - runs：流水线运行次数（runs 表行数）
    - ledger_cases：台账条目数（= 正式案例数，唯一可用于"案例量"的口径）
    - independent_high：台账里"独立高危"数（已论证且非同源）
    """
    rows = _ledger_rows(_read(EXP / "LEDGER.json") or {})
    # 案例量以台账 rows 为准：totals 可能滞后（历史遗留），rows 是逐条证据。
    ledger_cases = len(rows) if rows else ledger_totals.get("cases")
    independent_high = (sum(1 for r in rows if r.get("high_severity_confirmed"))
                        if rows else ledger_totals.get("high_severity_confirmed"))
    totals_high = ledger_totals.get("high_severity_confirmed")
    return {
        "workspaces": len(_workspace_dirs()),
        "runs": _run_count(),
        "ledger_cases": ledger_cases,
        "independent_high": independent_high,
        "ledger_totals_high": totals_high,
        "ledger_totals_stale": bool(rows) and totals_high != independent_high,
        "note": "workspaces/runs 是运行量；ledger_cases/independent_high 是案例量"
                "（由 LEDGER.rows 逐条统计，totals 滞后时以 rows 为准）。四者不可合并。",
    }


def _summary(d: pathlib.Path) -> dict:
    t = _task(d)
    c = _case(d) or {}
    acc = c.get("acceptance") or {}
    st = c.get("stage_status") or {}
    mc = c.get("model_contribution") or {}
    return {
        "dir": d.name,
        "case_id": c.get("case_id") or t.get("case_id") or d.name,
        "task_id": c.get("task_id") or t.get("task_id"),
        "benchmark": c.get("benchmark") or t.get("benchmark"),
        "project": t.get("project") or "",
        "component": t.get("component") or "",
        "cwe": c.get("cwe") or t.get("target_cwe") or "",
        "has_report": bool(c),
        "verdict": c.get("verdict"),
        "vul_exit": c.get("vul_exit"),
        "fix_exit": c.get("fix_exit"),
        "stage": acc.get("stage"),
        "generation_path": c.get("generation_path") or _gen_path(c.get("case_id") or t.get("case_id") or d.name, d.name),
        "local_verified": bool(acc.get("local_verified")),
        "causal_chain_verified": bool(acc.get("causal_chain_verified")),
        "high_severity_confirmed": bool(acc.get("high_severity_confirmed")),
        "course_ready": bool(acc.get("course_ready")),
        "defect_class": acc.get("defect_class"),
        "counts_as_target_defect": acc.get("counts_as_target_defect"),
        "blockers": acc.get("course_ready_blocked_by") or [],
        "root_cause": (st.get("root_cause") or {}).get("confidence"),
        "model": {
            "llm_calls": mc.get("llm_calls", 0),
            "pinpoint": bool(mc.get("verified_pinpoint")),
            "generation": bool(mc.get("verified_generation")),
            "from": mc.get("final_subject_from") or "rule",
        },
    }


def _totals(items: list[dict]) -> dict:
    rep = [i for i in items if i["has_report"]]
    return {
        "cases": len(items),
        "with_report": len(rep),
        "local_dual_run_pass": sum(1 for i in rep if i["local_verified"]),
        "causal_chain_verified": sum(1 for i in rep if i["causal_chain_verified"]),
        "high_severity_confirmed": sum(1 for i in rep if i["high_severity_confirmed"]),
        "course_ready": sum(1 for i in rep if i["course_ready"]),
        "model_contribution": sum(1 for i in rep
                                   if i["model"]["pinpoint"] or i["model"]["generation"]),
        "harness_ub": sum(1 for i in rep if i["defect_class"] == "harness_ub"),
        "withdrawn": sum(1 for i in rep if i["verdict"] == "withdrawn"),
    }


# ---------- API ----------

@app.get("/api/overview")
def overview():
    items = [_summary(d) for d in _case_dirs()]
    led = _read(EXP / "LEDGER.json") or {}
    led_totals = led.get("totals") or {}
    totals = _totals(items)
    return {
        "stats": _stats(led_totals),
        # totals 保留向后兼容：它统计"有报告的工作区"，含实验复跑目录，
        # 不等于案例数。新代码请读 stats.*。
        "totals": {**totals, "_deprecated": True,
                   "_replaced_by": "stats",
                   "_note": "totals 按工作区计数，含 S2-/S4-/S5* 实验复跑目录；"
                            "案例口径请用 stats.ledger_cases"},
        "totals_deprecated": True,
        "ledger_totals": led_totals,
        "benchmarks": _by(items, "benchmark"),
        "layers": [
            {"key": "local_verified", "name": "本地双端通过",
             "desc": "vul 镜像崩溃、fix 镜像干净"},
            {"key": "causal_chain_verified", "name": "因果链闭合",
             "desc": "输入→汇聚点→缺失检查三要素齐备"},
            {"key": "high_severity_confirmed", "name": "高危且属目标缺陷",
             "desc": "严重性已论证，且排除 harness 自身 UB"},
            {"key": "course_ready", "name": "课程可交付",
             "desc": "另需人工复核签字与官方回执"},
        ],
    }


def _by(items: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for i in items:
        k = i.get(key) or "unknown"
        out[k] = out.get(k, 0) + 1
    return out


@app.get("/api/cases")
def cases(include_experiments: int = 0):
    """默认只返回台账案例（与 LEDGER.rows 对齐）。

    复跑/诊断目录（S2-*/S4-*/S5*-*）默认隐藏；确需全量时显式传
    ?include_experiments=1，数量差异在响应里如实给出。
    """
    all_dirs = _case_dirs()
    led = _read(EXP / "LEDGER.json") or {}
    keep = all_dirs
    if not include_experiments:
        names = set(_ledger_dir_names(led))
        keep = [d for d in all_dirs if d.name in names]
    items = [_summary(d) for d in keep]
    return {
        "items": items,
        "totals": _totals(items),
        "scope": "experiments" if include_experiments else "ledger",
        "hidden_experiments": len(all_dirs) - len(items),
        "include_experiments": bool(include_experiments),
    }


@app.get("/api/cases/{cid}")
def case_detail(cid: str):
    d = next((x for x in _case_dirs() if x.name == cid), None)
    if d is None:
        raise HTTPException(404, "case not found")
    t = _task(d)
    c = _case(d) or {}
    files = []
    for p in sorted((d / "artifacts").rglob("*.json")) if (d / "artifacts").exists() else []:
        files.append({"path": str(p.relative_to(d)), "size": p.stat().st_size})
    verify = _read(d / "artifacts" / "verify" / "result.json") or {}
    locate = _read(d / "artifacts" / "locate" / "findings.json") or {}
    return {
        "summary": _summary(d),
        "task": t,
        "case": c,
        "verify": {
            "verdict": verify.get("verdict"),
            "reason": verify.get("reason"),
            "root_cause": verify.get("root_cause"),
            "candidates": [
                {"name": x.get("name"), "verdict": x.get("verdict"),
                 "proposed_by": x.get("proposed_by"),
                 "vul_exit": x.get("vul_exit"), "fix_exit": x.get("fix_exit")}
                for x in (verify.get("candidates") or [])
            ],
            "model_loop": {
                "rounds": (verify.get("model_loop") or {}).get("total_rounds"),
                "succeeded": (verify.get("model_loop") or {}).get("succeeded"),
                "detail": [
                    {"round": r.get("round"), "verdict": r.get("verdict"),
                     "encoding": r.get("encoding"), "size": r.get("size"),
                     "vul_exit": r.get("vul_exit"), "crash_line": r.get("crash_line")}
                    for r in ((verify.get("model_loop") or {}).get("rounds") or [])
                ],
            },
        },
        "locate": {
            "claims": len(locate.get("claims") or []),
            "claims_llm": len(locate.get("claims_llm") or []),
            "pinpoint": locate.get("pinpoint") or {},
        },
        "artifacts": files,
    }


@app.get("/api/packages")
def packages():
    idx = _read(ROOT / "deliverables" / "INDEX.json") or {}
    out = []
    for p in idx.get("packages", []):
        d = ROOT / "deliverables" / p["case"]
        files = []
        mp = d / "materials.sha256"
        if mp.exists():
            for line in mp.read_text().splitlines():
                if line.strip():
                    sha, name = line.split(None, 1)
                    files.append({"name": name.strip(), "sha256": sha})
        out.append({**p, "files_detail": files})
    return {"items": out}


def _exp_summary(data: dict) -> str:
    """从实验记录里抽一句话摘要。

    各 RESULT.json 结构不一：有的只有 phase，有的用 goal/motivation。
    统一按优先级取值，都没有就返回空串（前端显示"无摘要"，不编造）。
    """
    for k in ("goal", "motivation", "conclusion", "summary", "what",
              "note", "source", "label", "detail", "problem"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()[:240]
    # 嵌套结构：取 result/outcome 的首个字符串值
    for k in ("result", "outcome", "ledger_after"):
        v = data.get(k)
        if isinstance(v, dict):
            for kk, vv in v.items():
                if isinstance(vv, str) and vv.strip():
                    return f"{kk}: {vv.strip()}"[:240]
        elif isinstance(v, str) and v.strip():
            return v.strip()[:240]
    return ""


@app.get("/api/experiments")
def experiments():
    out = []
    for p in sorted(EXP.glob("*/RESULT.json")):
        data = _read(p) or {}
        out.append({
            "dir": p.parent.name,
            "phase": data.get("phase") or p.parent.name,
            "summary": _exp_summary(data),
        })
    ab = _read(EXP / "ab" / "COMPARE.json")
    return {"items": out, "ab": ab}



@app.get("/api/report")
def report():
    """分析报告：完整性、风险统计、逐例条目（只读，数据来自台账与 case.json）。"""
    led = _read(EXP / "LEDGER.json") or {}
    names = set(_ledger_dir_names(led))
    dirs = [d for d in _case_dirs() if d.name in names]
    items = [_summary(d) for d in dirs]
    rep = [i for i in items if i["has_report"]]
    high = [i for i in rep if i["high_severity_confirmed"]]
    local = [i for i in rep if i["local_verified"]]
    def status(uncovered: int) -> str:
        return "完整" if uncovered == 0 else ("部分" if uncovered < 0 else "未完成")
    planned = len(items)
    completeness = [
        {"scope": "案例接入（task.json / 镜像）", "planned": planned,
         "covered": len(items), "uncovered": 0, "status": status(0)},
        {"scope": "双端复现（vul 崩 / fix 干净）", "planned": planned,
         "covered": len(local), "uncovered": planned - len(local),
         "status": status(planned - len(local))},
        {"scope": "高危定级（六维 + CVSS）", "planned": len(rep),
         "covered": len(high), "uncovered": len(rep) - len(high),
         "status": status(len(rep) - len(high))},
        {"scope": "报告生成（case.json / report.md）", "planned": planned,
         "covered": len(rep), "uncovered": planned - len(rep),
         "status": status(planned - len(rep))},
    ]
    verdicts: dict[str, int] = {}
    for i in rep:
        k = i.get("verdict") or "unknown"
        verdicts[k] = verdicts.get(k, 0) + 1
    entries = []
    for i in rep:
        d = WS / i["dir"]
        c = _read(d / "artifacts" / "report" / "case.json") or {}
        sev = c.get("severity") or {}
        poc = c.get("poc") or {}
        entries.append({
            "case_id": i["case_id"], "task_id": i.get("task_id") or "",
            "project": i.get("project") or "", "cwe": i.get("cwe") or "",
            "verdict": i.get("verdict"), "path": i.get("generation_path"),
            "local": i["local_verified"], "high": i["high_severity_confirmed"],
            "severity": sev.get("state"), "cvss": sev.get("cvss_vector") or "",
            "poc_sha256": poc.get("sha256") or "", "poc_size": poc.get("size") or 0,
            "dir": i["dir"],
        })
    return {
        "title": "vulnmap 分析报告",
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "counts": {"cases": len(items), "with_report": len(rep),
                   "local": len(local), "high": len(high)},
        "completeness": completeness,
        "conclusion": {
            "flow": f"{len(rep)}/{planned} 个案例完成报告生成；{len(local)} 个双端通过。",
            "security": f"已确认高危 {len(high)} 例；本地通过但未达高危 {len(local)-len(high)} 例。",
            "depth": "验证阶段结合构造器与模型循环；构造器路径与模型路径分开统计。",
        },
        "risk": {"severity": {"high": len(high), "other": len(rep) - len(high)},
                 "verdict": verdicts},
        "entries": entries,
    }

@app.get("/api/health")
def health():
    return {"ok": True, "workspace": str(WS), "cases": len(_case_dirs())}


SHOTS = ROOT / "screenshots"
if SHOTS.exists():
    app.mount("/shots", StaticFiles(directory=SHOTS), name="shots")

@app.middleware("http")
async def _no_cache(request, call_next):
    """静态资源禁止缓存：改完前端立刻生效，避免用户看到旧版本。"""
    if request.url.path.startswith("/_server"):
        return JSONResponse({"detail":"Not found"}, status_code=404)
    resp = await call_next(request)
    if request.url.path.endswith((".html", ".js", ".css")) or request.url.path == "/":
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


from .report_documents import register_routes
register_routes(app, ROOT)

app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
