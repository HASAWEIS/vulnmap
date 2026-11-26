#!/usr/bin/env python3
"""生成 Discovery v1.0 流程图（SVG），替代旧的五阶段复现流程图。"""
from __future__ import annotations
from pathlib import Path

W, H = 1440, 1960
FONT = "Noto Sans CJK SC, Microsoft YaHei, sans-serif"
BG = "#f7f8fa"
INK = "#17202a"
MUTED = "#5b6b7c"
STROKE = "#4a5568"

parts: list[str] = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">']
parts.append('<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#555"/></marker></defs>')
parts.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')


def text(x, y, s, size=15, weight="normal", anchor="middle", fill=INK):
    s = (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    parts.append(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
                 f'text-anchor="{anchor}" font-weight="{weight}" fill="{fill}">{s}</text>')


def box(x, y, w, h, lines, fill="#ffffff", stroke=STROKE, size=14, title=None, rx=10):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>')
    cy = y + 26 if title else y + h / 2 - (len(lines) - 1) * 10
    if title:
        text(x + w / 2, cy, title, size + 1, "bold")
        cy += 22
    for line in lines:
        text(x + w / 2, cy, line, size)
        cy += 20


def diamond(cx, cy, w, h, label, fill="#fff7d6"):
    pts = f"{cx},{cy-h/2} {cx+w/2},{cy} {cx},{cy+h/2} {cx-w/2},{cy}"
    parts.append(f'<polygon points="{pts}" fill="{fill}" stroke="{STROKE}" stroke-width="1.6"/>')
    lines = label.split("\n")
    start = cy - (len(lines) - 1) * 9
    for i, line in enumerate(lines):
        text(cx, start + i * 18, line, 13)


def arrow(x1, y1, x2, y2, label=None, dash=False):
    d = ' stroke-dasharray="6 4"' if dash else ""
    parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#555" stroke-width="1.6" marker-end="url(#arrow)"{d}/>')
    if label:
        text((x1 + x2) / 2 + 8, (y1 + y2) / 2 - 4, label, 12, fill=MUTED, anchor="start")


# title
text(W / 2, 44, "Discovery v1.0：源码优先发现流程", 26, "bold")
text(W / 2, 74, "输入只有源码/二进制 + 构建方式；Agent 只指路，Fuzz 证明，Triage/Review 判定。", 14, fill=MUTED)

# input
box(420, 100, 600, 64, ["源码 / 二进制 + target.yaml（构建方式）", "不读 error.txt / patch.diff / 官方 PoC"],
    fill="#eaf2ff")
arrow(W / 2, 164, W / 2, 196)

# D0/D1/D1.5
box(390, 196, 660, 70, ["suffix .c/.cc/.cpp/.h/.hpp · ELF magic · main( · 函数 · 格式 → target.json"],
    title="D0 静态档案")
arrow(W / 2, 266, W / 2, 296)
box(370, 296, 700, 78, ["memcpy/strcpy/sprintf/malloc/read… 权重 3/2/1 + 近似可达 + 参数可控 → score", "planned / covered / uncovered 台账 → callsites.json"],
    title="D1 危险调用点排序")
arrow(W / 2, 374, W / 2, 404)
box(340, 404, 760, 88, ["只读源码、不执行目标、不产 verdict；默认 LLM，无 key/异常回退 heuristic", "30 行窗口 + citations 校验 → hypothesis.json；假设文本 → 定向种子 + 字典"],
    title="D1.5 并行分析 Worker")
arrow(W / 2, 492, W / 2, 524)

# D2 group
GX, GY, GW, GH = 60, 524, 1320, 360
parts.append(f'<rect x="{GX}" y="{GY}" width="{GW}" height="{GH}" rx="14" fill="#fbfdff" stroke="#8aa4bf" stroke-width="1.8" stroke-dasharray="8 5"/>')
text(GX + 24, GY + 30, "D2 覆盖率引导 Fuzz（通用本地目标，不绑定 benchmark）", 17, "bold", anchor="start")

box(90, 570, 330, 118, ["gcc -g -O1 -no-pie", "-fsanitize=address", "-fsanitize-coverage=trace-pc,trace-cmp", "cov_rt.c 单独编译；内置/自定义 harness"],
    title="构建 fuzz_target")
box(450, 570, 300, 118, ["假设种子 + 格式模板", "SHA 去重，写 corpus/", "同时生成源码/比较常量字典"],
    title="初始语料 + 字典")

# loop boxes
box(800, 566, 220, 74, ["字节 / 长度 / 字典", "PNG/TIFF 结构变异"], title="变异")
box(1060, 566, 280, 74, ["bwrap（默认）/ unshare", "网络 none · 只读根 · cap-drop", "超时 2s，kill 进程组"], title="隔离执行")
diamond(1200, 700, 180, 70, "ASAN 崩溃？")
box(1060, 760, 280, 70, ["保存 crash-*.bin + .log", "停止该 worker"], fill="#ffe8e8")
diamond(920, 700, 190, 70, "新 bitmap 位 / cmp？")
box(800, 760, 220, 70, ["加入 corpus（≤300）", "更新字典（≤96）"], fill="#e8f7ee")

arrow(750, 640, 800, 603, "喂输入")
arrow(1020, 603, 1060, 603)
arrow(1200, 640, 1200, 665)
arrow(1200, 735, 1200, 760, "是")
arrow(1200, 735, 1015, 700, "否", dash=True)
arrow(920, 735, 920, 760, "是", dash=True)
arrow(800, 795, 760, 700, "循环", dash=True)
arrow(1015, 700, 1060, 700, "否", dash=True)

text(90, 730, "覆盖反馈：只保留“走到新代码”的输入；", 13, fill=MUTED, anchor="start")
text(90, 752, "崩溃是搜索副产品，不是高危结论。", 13, fill=MUTED, anchor="start")
text(90, 790, "覆盖率归属：COV_PCS → addr2line -f -C", 13, fill=MUTED, anchor="start")
text(90, 812, "→ file:line / function → 回写 callsites.json", 13, fill=MUTED, anchor="start")

# D3
arrow(1200, 830, 1200, 900)
arrow(1200, 900, 720, 900)
arrow(720, 900, 720, 930)
box(330, 930, 780, 100, ["有效诊断（非 unknown/allocator）+ 干净重建 3/3", "WRITE→confirmed · READ/UB→weakened · 0/3→excluded · 不稳定→needs_human"],
    title="D3 分诊门禁", fill="#fff7d6")
arrow(720, 1030, 720, 1062)
box(390, 1062, 660, 74, ["规则复核，或显式开启单次 LLM 复核；不得超过门禁上限"], title="D3.5 复核")
arrow(720, 1136, 720, 1168)
box(360, 1168, 720, 84, ["分析完整性 · 风险统计 · 发现条目 → report.json / report.md", "SQLite campaign.db：campaign/binary/call_site/candidate/review/finding/coverage"],
    title="D4 报告 + 台账")
arrow(720, 1252, 720, 1284)
box(360, 1284, 720, 84, ["ranked vs random；Agent 种子 vs 纯 fuzz", "指标：覆盖率 / confirmed / time-to-first-crash；负结果保留"],
    title="D5 对照实验")
arrow(720, 1368, 720, 1400)
box(390, 1400, 660, 66, ["只读 API / UI：/api/discovery/campaigns … 五个 Discovery 页面"],
    title="展示层（只读）", fill="#eef6ff")

# boundary
parts.append('<rect x="90" y="1510" width="1260" height="150" rx="12" fill="#f3f4f6" stroke="#9aa7b4" stroke-width="1.4"/>')
text(114, 1540, "边界与当前结论", 16, "bold", anchor="start")
for i, line in enumerate([
    "• 每个输入起一个进程，约 500–1000 exec/s；没有 persistent mode / fork server。",
    "• 覆盖率以函数级为主；bitmap 64K、字典 96 条、比较操作 512 条有上限。",
    "• 真实目标 cJSON 只到 weakened READ；libpng/libtiff 结构化 Fuzz 仍 0 崩溃。",
    "• 受控 PNG/TIFF fixture 有 confirmed WRITE；不能当作真实目标战果。",
    "• 负结果与 0 覆盖一律保留；崩溃数不等于高危数。",
]):
    text(120, 1568 + i * 22, line, 13, fill=INK, anchor="start")

parts.append("</svg>")
out = Path(__file__).resolve().parent.parent / "docs" / "assets" / "flowchart.svg"
out.write_text("\n".join(parts), encoding="utf-8")
print(out)
