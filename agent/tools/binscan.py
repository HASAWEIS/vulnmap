"""静态取证：符号、行号、调用者、magic 探测。纯文本实现，避免外部依赖。"""
from __future__ import annotations

import re
from pathlib import Path

from ..policy import check_tool

FUNC_DEF = re.compile(r"^[A-Za-z_][\w \t\*]*\b([A-Za-z_]\w{2,})\s*\([^;]*$")
MAGIC = (
    (b"\x8aMNG\r\n\x1a\n", "mng"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"<?xml", "xml"),
    (b"\x7fELF", "elf"),
)
SRC_SUFFIXES = (".c", ".cc", ".cpp", ".h")


def read_lines(path: Path) -> list[str]:
    """按编辑器口径分行：**只有 \\n 是换行**。

    Python 的 `str.splitlines()` 还会在 \\x0c(FF)、\\u2028、\\u2029、\\x85 处切分，
    而 grep / awk / 编辑器 / ASAN 只认 \\n。graphicsmagick 的 png.c 里有 10 个
    \\x0c，用 splitlines() 会让行号整体漂移 10 行 —— 证据链直接对不上源码。
    """
    import io
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def detect_magic(data: bytes) -> str:
    head = data[:64]
    for magic, name in MAGIC:
        if head.startswith(magic):
            return name
    if head.lstrip().startswith(b"<?xml"):
        return "xml"
    return "unknown"


def _gate(stage: str | None) -> None:
    """静态取证属于 Read/Grep 能力；无 stage 视为未授权调用。"""
    if not stage:
        raise PermissionError("binscan call without stage: tool policy cannot be enforced")
    check_tool(stage, "Read")


def grep(root: Path, pattern: str, *, limit: int = 200, stage: str | None = None) -> list[dict]:
    _gate(stage)
    rx = re.compile(pattern)
    hits = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SRC_SUFFIXES:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    if rx.search(line):
                        hits.append({"file": str(path.relative_to(root)), "line": lineno,
                                     "text": line.rstrip()[:400]})
                        if len(hits) >= limit:
                            return hits
        except OSError:
            continue
    return hits


def find_function(root: Path, name: str, *, limit: int = 20, stage: str | None = None) -> list[dict]:
    """定位函数**定义**的首行。

    兼容两种排版（ghostpdl 属于第二种）：
        int foo(int a) {                    ← 名字与左括号同行
        static int
        foo(pdf_context *ctx, ...)          ← 返回类型独占一行，名字在下行
    排除原型声明（行尾分号）。
    """
    _gate(stage)
    # 前缀要覆盖：static Image *foo( / extern "C" int foo( / static inline char* foo( / foo(
    # 关键：`*` 可以紧贴函数名（static Image *ReadMNGImage），不能强制要求空格
    prefix = r'(?:extern\s+"C"\s+)?(?:[A-Za-z_][\w \t]*[ \t\*]+)?'
    rx_same = re.compile(r"^" + prefix + re.escape(name) + r"\s*\(")
    rx_own = re.compile(r"^" + prefix + re.escape(name) + r"\s*\($")
    hits = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in SRC_SUFFIXES:
            continue
        try:
            lines = read_lines(path)
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.rstrip()
            # 只排除原型声明（行尾分号）；行尾逗号是跨行参数列表，属于定义
            if stripped.endswith(";") and not stripped.startswith(name):
                continue
            matched = bool(rx_same.search(stripped))
            if not matched:
                # 名字独占一行时，整行就是 "name(args...)" 开头
                matched = bool(re.match(r"^" + re.escape(name) + r"\s*\(", stripped))
            if matched:
                hits.append({"file": str(path.relative_to(root)), "line": i,
                             "text": stripped.strip()[:300]})
                if len(hits) >= limit:
                    return hits
    return hits


def callers(root: Path, name: str, *, limit: int = 50, stage: str | None = None) -> list[dict]:
    return grep(root, r"\b" + re.escape(name) + r"\s*\(", limit=limit, stage=stage)


def enclosing_function(path: Path, line: int, *, stage: str | None = None):
    try:
        lines = read_lines(path)
    except OSError:
        return None
    for i in range(min(line, len(lines)) - 1, -1, -1):
        text = lines[i]
        if text.startswith(" ") or text.startswith("\t"):
            continue
        m = re.match(r"^[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w{2,})\s*\(", text)
        if m and not text.rstrip().endswith(";"):
            return m.group(1), i + 1
    return None


def line_window(path: Path, line: int, before: int = 4, after: int = 8) -> str:
    try:
        lines = read_lines(path)
    except OSError:
        return ""
    lo = max(0, line - 1 - before)
    hi = min(len(lines), line - 1 + after)
    out = []
    for i in range(lo, hi):
        mark = ">>" if i == line - 1 else "  "
        out.append(f"{mark}{i+1:5d}  {lines[i]}")
    return "\n".join(out)


def function_body(path: Path, def_line: int, *, stage: str | None = None,
                  max_lines: int = 3000) -> list[int]:
    """返回函数定义 def_line 起、到匹配右花括号为止的行号列表。

    用花括号计数近似函数边界：从定义行开始累计 { 与 }，回到 0 即结束。
    """
    if stage:
        _gate(stage)
    try:
        lines = read_lines(path)
    except OSError:
        return []
    out, depth, started = [], 0, False
    for i in range(max(0, def_line - 1), min(len(lines), def_line - 1 + max_lines)):
        line = lines[i]
        out.append(i + 1)
        # 粗略忽略字符串与注释中的花括号（够用：只用于圈定函数体）
        cleaned = re.sub(r'"[^"]*"|\'[^\']*\'', "", line.split("//")[0])
        for ch in cleaned:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            break
    return out


# ---- 同名函数消歧 ----

def _signature_at(lines: list[str], idx: int, name: str) -> str:
    """把跨行签名拼成一行（最多取 6 行，遇到 '{' 或 ')' 收尾）。"""
    parts = []
    for k in range(idx, min(len(lines), idx + 6)):
        parts.append(lines[k].strip())
        if "{" in lines[k] or ";" in lines[k]:
            break
    return " ".join(parts)[:400]


def _branch_chain(lines: list[str], idx: int, window: int = 400) -> list[str]:
    """返回该定义所处的 #if/#elif/#else/#endif 分支链（栈式配对）。

    用于识别「同一函数的 #if / #else 两支」：它们签名相同但**只会编译一份**，
    不能当成两个并列的歧义实例。
    """
    stack: list[str] = []
    for k in range(0, idx):
        line = lines[k].strip()
        if line.startswith(("#if", "#ifdef", "#ifndef")):
            stack.append(f"if:{line[3:].strip()[:60]}")
        elif line.startswith(("#elif", "#else")):
            if stack:
                stack[-1] = f"else:{line[4:].strip()[:60]}"
        elif line.startswith("#endif"):
            if stack:
                stack.pop()
    return stack[-3:]


def _preprocessor_context(lines: list[str], idx: int, window: int = 12) -> list[str]:
    """取该定义上方最近的 #if/#ifdef 条件（条件编译下的重复定义要保留条件信息）。"""
    conds = []
    for k in range(max(0, idx - window), idx):
        line = lines[k].strip()
        if line.startswith(("#ifdef", "#ifndef", "#if", "#elif")):
            conds.append(line[:120])
    return conds[-2:]


def disambiguate(name: str, candidates: list[dict], *, file_hint: str = "",
                 signature_hint: str = "", descr: str = "",
                 root: Path | None = None) -> dict:
    """在多个同名定义中挑出目标实例，或明确判定 ambiguous。

    相关性排序**只决定检查顺序，不代替正确性**。因此：
    - 有唯一最高分且高于次高 → 选中，附理由
    - 多个并列最高分 → `ambiguous`，保留全部候选，不强行选一个
    """
    if not candidates:
        return {"status": "none", "picked": None, "candidates": [], "reason": "no_definition"}
    if len(candidates) == 1:
        c = candidates[0]
        return {"status": "unique", "picked": c, "candidates": candidates,
                "reason": "only_one_definition", "confidence": "structural",
                "needs_confirmation": False}

    scored = []
    for c in candidates:
        score, why = 0.0, []
        path = c["file"]
        base = path.split("/")[-1]
        # 1) 模型/描述点名了文件
        if file_hint:
            if file_hint == path or path.endswith(file_hint):
                score += 1.0
                why.append("file_hint_exact")
            elif file_hint.split("/")[-1] == base:
                score += 0.8
                why.append("file_hint_basename")
        # 2) 描述里出现的文件名或它的词根（rules_fuzzer.cc -> "rules fuzzer"）
        if descr:
            stem_words = base.replace(".cc", "").replace(".c", "").split("_")
            tokens = {base, path, " ".join(stem_words), stem_words[0] if stem_words else ""}
            for token in tokens:
                if token and len(token) > 3 and token in descr:
                    score += 0.5
                    why.append(f"descr_mentions:{token}")
                    break
        # 3) 签名与提示的吻合度
        if signature_hint:
            if signature_hint in (c.get("signature") or ""):
                score += 0.9
                why.append("signature_matches_hint")
        # 4) 条件编译上下文
        if c.get("conditions"):
            why.append("conditional:" + ";".join(c["conditions"]))
        scored.append({**c, "score": round(score, 3), "why": why})

    # 条件编译互斥组：同一文件、签名相同、但分处 #if / #else 两支 → 实际只编译一份
    exclusive = _exclusive_alternatives(scored)
    if exclusive:
        keep = exclusive[0]
        # 互斥已被识别，但"该构建编译了哪一支"尚未确认：
        # 需要宏值 / 预处理结果 / 二进制调试信息才能升级为确认。
        return {"status": "conditional_unresolved", "picked": None,
                "provisional": keep,
                "candidates": scored,
                "reason": "mutually_exclusive_branches; active_definition_unconfirmed; "
                          + ";".join(keep.get("branches") or []),
                "needs_confirmation": True}

    scored.sort(key=lambda x: x["score"], reverse=True)
    top, second = scored[0], (scored[1] if len(scored) > 1 else None)
    if second is None or top["score"] > second["score"]:
        if top["score"] <= 0:
            return {"status": "ambiguous", "picked": None, "candidates": scored,
                    "reason": "no_discriminating_evidence"}
        # 启发式领先**只说明排序靠前，不说明选对了**。
        # 例如"模型指定了文件"能让 score 领先，但模型指定本身可能是错的（3938 就是）。
        # 因此这里只给 ranked_candidate，需外部证据（预处理器/调试信息/执行验证）才升级。
        return {"status": "ranked_candidate", "picked": top, "candidates": scored,
                "reason": ";".join(top["why"]) or "highest_score",
                "confidence": "heuristic_only",
                "needs_confirmation": True}
    return {"status": "ambiguous", "picked": None, "candidates": scored,
            "reason": f"tie_at_score_{top['score']}"}


def find_function_enriched(root: Path, name: str, *, limit: int = 20,
                           stage: str | None = None) -> list[dict]:
    """在 find_function 基础上补齐签名、条件编译上下文，供消歧使用。"""
    hits = find_function(root, name, limit=limit, stage=stage)
    out = []
    for h in hits:
        lines = read_lines(root / h["file"])
        idx = h["line"] - 1
        out.append({**h,
                    "signature": _signature_at(lines, idx, name),
                    "conditions": _preprocessor_context(lines, idx),
                    "branches": _branch_chain(lines, idx)})
    return out


def confirm_by_debuginfo(diag_lines: list[str], sink_file: str, *,
                         provenances: list[dict] | None = None) -> dict:
    """用调试信息确认"活动的定义"是哪一处——**必须绑定身份**。

    一道诊断要能证明"当前构建编译了哪一支"，必须同时满足：
    1. 诊断来自与该源码快照、该二进制一致的运行（provenance 匹配）；
    2. 栈帧在容差内命中某一处定义。

    `provenances` 是本轮可接受的运行身份列表（run_id / binary_sha256 /
    source_sha256 / image_digest）。为空或全部不匹配 → `unconfirmed`。
    **旧日志配新二进制必须被拒绝**，不能凭行号巧合就升级。
    """
    if not provenances:
        return {"confirmed": False, "basis": "no_provenance",
                "reason": "缺少运行身份（run_id/binary/source/image），不能确认"}

    ok_prov = [p for p in provenances if p.get("matches") is not False]
    if not ok_prov:
        return {"confirmed": False, "basis": "provenance_mismatch",
                "reason": "诊断来源与当前构建不一致（旧日志或不同二进制）"}

    target = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+\S+\s+(\S+):(\d+):")
    for line in diag_lines:
        m = target.search(line)
        if not m:
            continue
        f, ln = m.group(1), int(m.group(2))
        same = (sink_file.endswith(f) or f.endswith(sink_file)
                or sink_file.split("/")[-1] == f.split("/")[-1])
        if sink_file and same:
            prov = ok_prov[0]
            return {"confirmed": True, "file": f, "line": ln,
                    "basis": "asan_frame_line",
                    "provenance": {k: prov.get(k) for k in
                                   ("run_id", "binary_sha256", "source_sha256",
                                    "image_digest")}}
    return {"confirmed": False, "basis": "no_debuginfo_evidence"}


def _exclusive_alternatives(scored: list[dict]) -> list[dict]:
    """若所有候选同文件、同签名、且分支链互不相同（#if vs #else），
    说明它们是同一函数在不同编译条件下的两版，只保留先出现的一处。"""
    if len(scored) < 2:
        return []
    files = {c["file"] for c in scored}
    sigs = {(c.get("signature") or "") for c in scored}
    if len(files) != 1 or len(sigs) != 1:
        return []
    chains = [(c.get("branches") or []) for c in scored]
    if not all(chains):
        return []
    if len({tuple(ch) for ch in chains}) == len(chains):
        return [dict(scored[0], alternatives=[c["line"] for c in scored[1:]],
                     note="同一函数的条件编译分支，仅当前构建的一份生效")]
    return []


_WRITE_RE = re.compile(
    r"^\s*(?:\w[\w\s\*]*?\s+)?(?P<base>\w+)\s*(?:\[[^\]]+\])+"
    r"(?:\s*\.\s*\w+)*\s*=\s*(?!=)")


def write_candidates(lines: list[str], start: int, end: int, *,
                     stage: str | None = None) -> list[dict]:
    """枚举 [start, end] 行内的「数组/结构体写入」候选。

    存在理由：REGEX_FUNCS 只匹配 memcpy/strcpy 等库调用，
    而真实缺陷常是 `buf[i].field = v;` 这种直接写入
    （如 GraphicsMagick render.c:942 的 ghost line 越界写）。
    这里只做机械枚举，不做取舍——取舍交给模型，并对结果做独立校验。
    """
    _gate(stage)
    out = []
    for i in range(max(1, start), min(len(lines), end) + 1):
        raw = lines[i - 1]
        code = raw.split("/*")[0].rstrip()
        if not code or code.lstrip().startswith(("//", "*")):
            continue
        m = _WRITE_RE.match(code)
        if not m:
            continue
        out.append({
            "line": i,
            "base": m.group("base"),
            "text": code.strip()[:120],
            "indices": code.count("["),
        })
    return out
