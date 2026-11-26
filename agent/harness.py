"""harness 输入契约提取：长度窗口 + 输入通道。

S4-b 的 B1 根因（docs/ACCEPTANCE-S4b.md）：模型闭环只拿到缺陷函数源码，
不知道 harness 在入口就丢弃窗口外输入——Fuzz_chpw.c 里

    if (Size < kMinInputLength || Size > kMaxInputLength) { return 0; }

第 3 轮给了 1 字节（< 20），容器跑完 exit=0，等价空转。
本模块只做文本解析（不执行、不联网、不依赖靶子），把这份契约结构化：

    {source_file, min_size, max_size, channel, confidence}

约定：
- 解析不到 -> confidence="unknown"，min/max 为 None，check() 放行；
  宁可放行也不能因为解析失败把候选拦掉（否则会把"未知"伪装成"拒绝"）。
- 只认 LLVMFuzzerTestOneInput 函数体里的比较，避免把相邻无关代码的
  length > 0 之类误当成窗口。
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp")
MAX_FILE_BYTES = 4 << 20
MAX_SCAN_BYTES = 48 << 20
MAX_HARNESS_FILES = 40

FUZZER_SYMBOL = "LLVMFuzzerTestOneInput"
SIZE_TOKENS = ("Size", "size", "DataLen", "dataLen", "DataSize", "dataSize",
               "Len", "len", "length", "BufSize", "bufSize", "InputLen", "inputLen")

CHANNELS = ("fuzzer_data_arg", "stdin", "argv_file", "unknown")
CONFIDENCES = ("exact", "partial", "unknown")
_THIRD_PARTY = ("libfuzzer/", "compiler-rt/", "/afl/", "afl/", "third_party/")

CONTRACT_FIELDS = ("source_file", "min_size", "max_size", "channel", "confidence")

_LITERAL = r"(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*"
_CONST_DEFINE = re.compile(
    r"#\s*define\s+([A-Za-z_]\w*)\s+\(?\s*(" + _LITERAL + r")\s*\)?\s*(?=$|//|/\*)", re.M)
_CONST_ASSIGN = re.compile(
    r"\b(?:const|constexpr)\b[^=;\n]{0,80}?\b([A-Za-z_]\w*)\s*=\s*(" + _LITERAL + r")\s*;")
_ENUM_BLOCK = re.compile(r"\benum\b[^{;]*\{([^}]*)\}")
_ENUM_ITEM = re.compile(r"([A-Za-z_]\w*)\s*=\s*(" + _LITERAL + r")")

_SIZE_ALT = "|".join(SIZE_TOKENS)
_CMP_FWD = re.compile(
    r"\b(" + _SIZE_ALT + r")\b\s*(<=|>=|==|<|>)\s*([A-Za-z_]\w*|" + _LITERAL + r")")
_CMP_REV = re.compile(
    r"\b([A-Za-z_]\w*|" + _LITERAL + r")\s*(<=|>=|<|>)\s*\b(" + _SIZE_ALT + r")\b")

_STDIN_MARKERS = re.compile(r"\b(?:stdin|STDIN_FILENO)\b|\bread\s*\(\s*0\s*,")
_ARGV_FILE_MARKERS = re.compile(r"\bfopen\s*\(\s*argv\s*\[|\bargv\s*\[\s*1\s*\]")


def _int_of(tok: str) -> int | None:
    tok = (tok or "").strip()
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        return int(tok.rstrip("uUlL"))
    except (TypeError, ValueError):
        return None


def unknown_contract(reason: str = "not_found") -> dict:
    """解析失败时的契约：不设限制，并写明为什么没解析到。"""
    return {
        "source_file": "",
        "min_size": None,
        "max_size": None,
        "channel": "unknown",
        "confidence": "unknown",
        "confidence_reason": reason,
        "conditions": [],
    }



def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def constants(text: str) -> dict:
    """解析 #define / const|constexpr 赋值 / enum 里的整数常量。"""
    out = {}
    for name, val in _CONST_DEFINE.findall(text):
        iv = _int_of(val)
        if iv is not None:
            out.setdefault(name, iv)
    for name, val in _CONST_ASSIGN.findall(text):
        iv = _int_of(val)
        if iv is not None:
            out.setdefault(name, iv)
    for block in _ENUM_BLOCK.findall(text):
        for name, val in _ENUM_ITEM.findall(block):
            iv = _int_of(val)
            if iv is not None:
                out.setdefault(name, iv)
    return out


def _function_span(text: str, symbol: str = FUZZER_SYMBOL) -> tuple:
    """返回 symbol 定义体在 text 中的 [start, end)；找不到返回 (0, len(text))。"""
    idx = text.find(symbol)
    if idx < 0:
        return 0, len(text)
    brace = text.find("{", idx)
    if brace < 0:
        return idx, len(text)
    depth = 0
    for i in range(brace, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx, i + 1
    return idx, len(text)


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def detect_channel(text: str, span: tuple) -> str:
    body = text[span[0]:span[1]]
    if _STDIN_MARKERS.search(body):
        return "stdin"
    if _ARGV_FILE_MARKERS.search(body):
        return "argv_file"
    if FUZZER_SYMBOL in text:
        return "fuzzer_data_arg"
    return "unknown"


def _bounds_from(op, value, invert):
    """单条比较 -> 允许区间 (lo, hi)。invert=True 表示这是「拒绝条件」。"""
    accept = {
        "<": (None, value - 1), "<=": (None, value),
        ">": (value + 1, None), ">=": (value, None), "==": (value, value),
    }
    reject = {
        "<": (value, None), "<=": (value + 1, None),
        ">": (None, value), ">=": (None, value - 1), "==": (None, None),
    }
    return (reject if invert else accept)[op]


def _merge(bound, lo, hi):
    if lo is not None:
        bound['min'] = lo if bound['min'] is None else max(bound['min'], lo)
    if hi is not None:
        bound['max'] = hi if bound['max'] is None else min(bound['max'], hi)


_REJECT_STMT = re.compile(r"\breturn\s*(?:0|1|-1|false|true)?\s*;|\babort\s*\(|\bgoto\s+\w|\bbreak\s*;")
_ACCEPT_CMP = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _is_reject_guard(text, span, pos):
    """比较所在条件是不是「拒绝门」：条件成立就 return/abort/goto。

    例：if (Size < kMin || Size > kMax) return 0; —— 条件描述的是被拒绝的区间，
    允许区间要取补集；不识别会把 20..100 解析成 101..19（方向整体反了）。
    """
    body = text[span[0]:span[1]]
    rel = pos - span[0]
    window = body[max(0, rel - 120):min(len(body), rel + 200)]
    if re.search(r"if\s*\(\s*!\s*\(", window):
        return False
    return bool(_REJECT_STMT.search(window))


def extract_bounds(text):
    """从 LLVMFuzzerTestOneInput 体内提取 (min, max, conditions, unresolved)。"""
    span = _function_span(text)
    body = text[span[0]:span[1]]
    consts = constants(text)
    bound = {"min": None, "max": None}
    conditions = []
    unresolved = []
    lines = text.splitlines()

    def _operand(tok):
        iv = _int_of(tok)
        return iv if iv is not None else consts.get(tok)

    def _record(pos):
        n = _line_no(text, pos)
        txt = lines[n - 1].strip()[:200] if 0 < n <= len(lines) else ""
        conditions.append({"line": n, "text": txt})

    def _handle(token, op, operand, pos):
        _record(pos)
        value = _operand(operand)
        if value is None:
            unresolved.append(token + " " + op + " " + operand)
            return
        invert = _is_reject_guard(text, span, pos)
        lo, hi = _bounds_from(op, value, invert)
        _merge(bound, lo, hi)

    for m in _CMP_FWD.finditer(body):
        _handle(m.group(1), m.group(2), m.group(3), span[0] + m.start())
    for m in _CMP_REV.finditer(body):
        operand, op, token = m.group(1), m.group(2), m.group(3)
        value = _operand(operand)
        if value is None:
            unresolved.append(operand + " " + op + " " + token)
            continue
        _handle(token, _ACCEPT_CMP.get(op, op), operand, span[0] + m.start())

    seen, uniq = set(), []
    for c in conditions:
        key = (c["line"], c["text"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return bound["min"], bound["max"], uniq[:6], unresolved

def extract_from_text(text, *, source_file=""):
    lo, hi, conditions, unresolved = extract_bounds(text)
    span = _function_span(text)
    channel = detect_channel(text, span)
    reason = ""
    if lo is not None and hi is not None and lo > hi:
        # 解析出反向区间（例如把拒绝门当成了接受条件）：不可信，按未知处理，绝不拦候选
        return unknown_contract("bounds_inconsistent:min=%s>max=%s sec" % (lo, hi))
    if lo is not None and lo < 1 and hi is not None:
        return unknown_contract("bounds_inconsistent:min_below_zero")
    if lo is None and hi is None:
        conf = "unknown"
        reason = "; ".join(unresolved) if unresolved else "no_size_comparison"
    elif lo is None or hi is None:
        conf = "partial"
        reason = "one_bound_only"
        if unresolved:
            reason += ";unresolved:" + "; ".join(unresolved)
    elif unresolved:
        conf = "partial"
        reason = "unresolved_operands:" + "; ".join(unresolved)
    else:
        conf = "exact"
        reason = "both_bounds_resolved"
    return {
        "source_file": source_file,
        "min_size": lo,
        "max_size": hi,
        "channel": channel,
        "confidence": conf,
        "confidence_reason": reason,
        "conditions": conditions,
    }


def _hint_hits(rel, text, hints):
    low_text = text.lower()
    low_rel = rel.lower()
    hits = 0
    for hint in hints or ():
        h = str(hint).strip().lower()
        if len(h) < 4:
            continue
        if h in low_text or h in low_rel:
            hits += 1
    return hits


def extract(src_root, *, hints=(), max_files=MAX_HARNESS_FILES):
    """在源码树里找 fuzz harness 并提取契约；找不到返回 confidence=unknown。

    hints 用来在多个 harness 之间选对那个：给缺陷函数名（如 krb5_chpw_message）
    或靶子二进制名（如 Fuzz_chpw），命中者优先。选错 harness 会拿到别处的窗口。
    """
    root = Path(src_root)
    if not root.is_dir():
        return unknown_contract("src_missing")
    files = find_harness_files(root)
    if not files:
        return unknown_contract("no_LLVMFuzzerTestOneInput")
    best, best_score = None, ()
    for path in files[:max_files]:
        text = _read_text(path)
        if not text:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        cand = extract_from_text(text, source_file=rel)
        score = (
            _hint_hits(rel, text, hints),
            0 if any(t in rel.lower() for t in _THIRD_PARTY) else 1,
            1 if cand["confidence"] == "exact" else 0,
            1 if cand["confidence"] in ("exact", "partial") else 0,
            1 if "fuzz" in rel.lower() else 0,
            -len(rel),
        )
        if best is None or score > best_score:
            best, best_score = cand, score
    return best or unknown_contract("unreadable_harness")

def window_text(contract: dict) -> str:
    """窗口的紧凑写法：20..100 / >=20 / <=100 / 空串。"""
    lo, hi = contract.get("min_size"), contract.get("max_size")
    if lo is not None and hi is not None:
        return str(lo) + ".." + str(hi)
    if lo is not None:
        return ">=" + str(lo)
    if hi is not None:
        return "<=" + str(hi)
    return ""


def check(contract: dict, size: int) -> dict:
    """长度是否落在 harness 窗口内。confidence=unknown 时一律放行。"""
    lo = contract.get("min_size")
    hi = contract.get("max_size")
    conf = contract.get("confidence") or "unknown"
    base = {"size": size, "min": lo, "max": hi, "confidence": conf,
            "window": window_text(contract),
            "source_file": contract.get("source_file", "")}
    if conf == "unknown" or (lo is None and hi is None):
        return dict(base, ok=True, reason="contract_unknown")
    too_small = lo is not None and size < lo
    too_big = hi is not None and size > hi
    if too_small or too_big:
        which = "below_min" if too_small else "above_max"
        reason = ("size=" + str(size) + " is outside the harness window "
                  + window_text(contract) + " (" + which + "; hard gate in "
                  + (contract.get("source_file") or "harness")
                  + " drops such input before the defect can be reached)")
        return dict(base, ok=False, reason=reason)
    return dict(base, ok=True, reason="in_window")


def describe(contract: dict, *, heading: str = "--- HARNESS INPUT CONTRACT ---") -> str:
    """给模型看的契约文本：必须写明允许区间，并说明窗口外会被执行前拒绝。"""
    conf = contract.get("confidence") or "unknown"
    src = contract.get("source_file") or "(not found)"
    if conf == "unknown":
        return "\n".join([
            heading,
            "source: " + src,
            "confidence: unknown",
            "No input-length window could be parsed from the harness, so no size "
            "restriction is applied. Keep the input small and self-contained.",
        ])
    chan = contract.get("channel") or "unknown"
    if chan == "fuzzer_data_arg":
        chan = chan + " (bytes arrive as " + FUZZER_SYMBOL + "(Data, Size))"
    win = window_text(contract)
    lines = [
        heading,
        "source: " + src,
        "channel: " + chan,
        "size window: len(input) in " + win + "   (min=" + str(contract.get("min_size"))
        + ", max=" + str(contract.get("max_size")) + ", confidence=" + conf + ")",
    ]
    conds = contract.get("conditions") or []
    if conds:
        lines.append("gate: " + " | ".join("L" + str(c["line"]) + ": " + c["text"]
                                           for c in conds[:3]))
    lines.append("RULE: the input length MUST be within " + win + ". Candidates outside "
                 "this window are rejected BEFORE execution, so they can never trigger "
                 "the defect; a reply of that size is a wasted round.")
    return "\n".join(lines)



def _candidate_files(src_root):
    """先找路径里带 fuzz 的文件，找不到再全树扫；有总字节上限。"""
    fuzz_like, others = [], []
    budget = MAX_SCAN_BYTES
    for dirpath, dirnames, filenames in os.walk(src_root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "build", "node_modules", "__pycache__")]
        for name in filenames:
            if not name.endswith(SRC_SUFFIXES):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            budget -= size
            if budget < 0:
                return fuzz_like or others
            low = str(path).lower()
            (fuzz_like if "fuzz" in low else others).append(path)
    return fuzz_like + others


def find_harness_files(src_root):
    """含 LLVMFuzzerTestOneInput 的源文件（按 fuzz 优先排序）。"""
    hits = []
    for path in _candidate_files(Path(src_root)):
        text = _read_text(path)
        if text and FUZZER_SYMBOL in text:
            hits.append(path)
    return hits


# ---- 种子语料提取（S5-c B2/B3）------------------------------------------------
SEED_LIMIT = 8
SEED_MAX_BYTES = 4096
_CORPUS_DIRS = ("corpus", "testdata", "seeds")
_C_DATA_INIT = re.compile(r"\bkrb5_data\s+([A-Za-z_]\w*)\s*=\s*\{(.*?)\}\s*;", re.S)
_C_DECL_LEN = re.compile(
    r"\s*(?:0[xX][0-9a-fA-F]+|\d+)\s*,\s*(0[xX][0-9a-fA-F]+|\d+)\s*,")
_C_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_C_ESCAPES = {"n": 10, "r": 13, "t": 9, "v": 11, "f": 12, "b": 8, "a": 7,
              "\\": 92, '"': 34, "'": 39, "?": 63}
_HEX = "0123456789abcdefABCDEF"
OCTAL = "01234567"

AD_POLICY_30 = ("AD password-policy struct: zero_bytes(2)/min_length(4)/history(4)"
                "/properties(4)/expire(8)/min_age(8)")


def unescape_c_string(chunk: str) -> bytes:
    """C 字符串字面量 -> 字节。支持 反斜杠0 / 反斜杠xNN / 八进制 / 常见转义。

    必须按字节还原而不是按 Python 字符串：AD 策略向量里大量 反斜杠0 与
    "反斜杠0反斜杠0反斜杠0反斜杠x0d" 这类长度字段，转成 str 会把边界弄丢。
    """
    out = bytearray()
    i, n = 0, len(chunk or "")
    while i < n:
        ch = chunk[i]
        if ch != "\\":
            out.extend(ch.encode("latin-1", "ignore"))
            i += 1
            continue
        i += 1
        if i >= n:
            break
        esc = chunk[i]
        if esc in OCTAL:
            j, val = i, 0
            while j < n and j < i + 3 and chunk[j] in OCTAL:
                val = val * 8 + int(chunk[j])
                j += 1
            out.append(val & 0xFF)
            i = j
        elif esc == "x":
            j, val, digits = i + 1, 0, 0
            while j < n and digits < 2 and chunk[j] in _HEX:
                val = val * 16 + int(chunk[j], 16)
                j += 1
                digits += 1
            if digits == 0:
                out.extend(b"x")
                i += 1
            else:
                out.append(val & 0xFF)
                i = j
        elif esc == "\n":
            i += 1
        else:
            byte = _C_ESCAPES.get(esc)
            if byte is None:
                out.extend(esc.encode("latin-1", "ignore"))
            else:
                out.append(byte)
            i += 1
    return bytes(out)


def literal_bytes(body: str) -> bytes:
    """初始化体里的相邻字符串字面量按出现顺序拼起来（C 的隐式拼接）。"""
    return b"".join(unescape_c_string(p) for p in _C_STRING.findall(body or ""))


def seeds_from_c_text(text: str, *, source: str = "") -> list:
    """抓 krb5_data name = {0, LEN, "..."} 这类结构化向量。"""
    out = []
    for m in _C_DATA_INIT.finditer(text or ""):
        name, body = m.group(1), m.group(2)
        data = literal_bytes(body)
        if not data:
            continue
        dm = _C_DECL_LEN.match(body)
        declared = _int_of(dm.group(1)) if dm else None
        out.append({"name": name, "data": data, "declared": declared,
                    "source": source})
    return out


def annotate(data: bytes) -> str:
    """结构注释：让模型知道字节落在哪个字段，而不是只知道长度。"""
    n = len(data)
    if n >= 30 and data[:2] == b"\x00\x00":
        note = AD_POLICY_30
        if n > 30:
            note += " + %d extra byte(s)" % (n - 30)
        return note
    if b"\x00" in data:
        return "contains a NUL byte; not a plain UTF-8 string"
    if n and all(32 <= b < 127 for b in data):
        return "printable ASCII string, no NUL"
    return "raw bytes"


def _fit_window(data: bytes, contract: dict | None):
    """按 harness 窗口修正种子：过短补齐（空格），过长丢弃。"""
    lo = (contract or {}).get("min_size")
    hi = (contract or {}).get("max_size")
    padded = False
    if lo is not None and len(data) < lo:
        data = data + b" " * (lo - len(data))
        padded = True
    if hi is not None and len(data) > hi:
        return None, False, "above_max_%s" % hi
    if lo is not None and len(data) < lo:
        return None, False, "below_min_%s" % lo
    return data, padded, ""


def _corpus_files(root: Path):
    """源码树里的 corpus/测试二进制种子（有就收，没有就空）。"""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "build", "node_modules", "__pycache__")]
        base = Path(dirpath).name.lower()
        for name in filenames:
            low = name.lower()
            is_corpus = base in _CORPUS_DIRS
            is_bin = low.endswith((".bin", ".seed", ".input")) and "test" in dirpath.lower()
            if not (is_corpus or is_bin):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if not 0 < size <= SEED_MAX_BYTES:
                continue
            found.append(path)
    return found


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def seeds(src_root, *, contract: dict | None = None, hints=(), limit: int = SEED_LIMIT) -> list:
    """从源码树提取可用作起点的种子，最多 limit 条。

    来源优先级：提到 hint 函数的 C 单元测试向量 > 其他测试向量 > corpus 二进制。
    给了 hints 时，与目标无关的 krb5_data 初始化（pkinit / pac / ccache 里的
    业务结构）一律不冒充种子：它们既没调用缺陷函数，也只会把提示带偏。
    返回 [{name,size,sha256,bytes_hex,source,...}]；窗口外且无法补齐的丢弃。
    """
    root = Path(src_root)
    if not root.is_dir():
        return []
    hint_list = [str(h).strip() for h in (hints or ()) if str(h).strip()]
    raw = []
    for path in _candidate_files(root):
        text = _read_text(path)
        if not text or "krb5_data" not in text:
            continue
        rel = _rel(path, root)
        hits = _hint_hits(rel, text, hint_list)
        low = rel.lower()
        in_tests = bool("test" in low)
        if hint_list and not hits and not in_tests:
            continue
        for item in seeds_from_c_text(text, source=rel):
            item["hits"] = hits
            item["in_tests"] = 1 if in_tests else 0
            raw.append(item)
    raw.sort(key=lambda it: (-it.get("hits", 0), -it.get("in_tests", 0),
                             0 if it.get("declared") == len(it["data"]) else 1))
    for path in _corpus_files(root):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        raw.append({"name": path.name, "data": data, "declared": None,
                    "source": _rel(path, root)})
    out, seen = [], set()
    for item in raw:
        data = item["data"]
        declared = item.get("declared")
        if declared and 0 < declared <= len(data):
            data = data[:declared]
        data, padded, why = _fit_window(data, contract)
        if data is None:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        out.append({
            "name": item["name"],
            "size": len(data),
            "sha256": digest,
            "bytes_hex": data.hex(),
            "source": item.get("source", ""),
            "declared_length": declared,
            "padded_to_min": padded,
            "drop_reason": why,
            "structure": annotate(data),
        })
        if len(out) >= limit:
            break
    return out


def seed_prompt(seed_list, contract: dict | None = None, *, max_show: int = 3,
                heading: str = "--- SEED CORPUS (extracted from repository tests, not the answer) ---") -> str:
    """给模型看的种子块：hex + 结构注释 + 「改结构不改长度」的硬要求。"""
    win = window_text(contract or {})
    if not seed_list:
        return "\n".join([
            heading,
            "No repository seed could be extracted for this target.",
            "Work from the source evidence above; keep len(input) in "
            + (win or "a small self-contained size") + ".",
        ])
    # 结构化种子（AD 策略布局）优先展示：它们才说明"字节落在哪个字段"
    ordered = sorted(
        list(seed_list),
        key=lambda s: (0 if str(s.get("structure") or "").startswith("AD password-policy") else 1,
                       -int(s.get("size") or 0)))
    lines = [heading]
    for i, s in enumerate(ordered[:max_show], 1):
        lines.append("seed %d: %s  size=%dB  sha256=%s  source=%s"
                     % (i, s["name"], s["size"], s["sha256"][:16], s.get("source", "")))
        lines.append("  structure: " + (s.get("structure") or "raw bytes"))
        lines.append("  hex: " + (s.get("bytes_hex") or ""))
        if s.get("padded_to_min"):
            lines.append("  note: padded with spaces to satisfy the harness minimum length")
    lines.append(
        "HOW TO USE THESE SEEDS: they already pass the harness gate and are accepted by "
        "the target, so they reach the defect function. MUTATE A SEED'S STRUCTURE - which "
        "bytes sit in which field, field magnitudes (length / history / properties / "
        "expire / min_age), truncated vs full struct, one field pushed to 0 or to max - "
        "instead of only changing the total length. Keep len(input) inside "
        + (win or "the harness window") + ".")
    return "\n".join(lines)
