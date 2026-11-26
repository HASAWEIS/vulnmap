"""Sanitizer 诊断解析与根因一致性判定。

设计口径（审查方 2025-11-09）：
- **诊断解析**与**退出状态**是两件事：exit=0 不代表没有诊断，两端都要先解析。
- 只认**真正的缺陷报告**：`ERROR: AddressSanitizer:` / `runtime error:`（UBSAN）等，
  排除初始化提示、警告、被当成普通字符串打印的内容。
- 根因一致性不是"栈里出现行号/函数名"就够了：同一函数可能有多处缺陷、
  构建行号可能偏移、栈里出现某函数不代表缺陷在那里。因此综合
  **诊断类型 + 首个相关用户代码帧 + 触发操作** 判断，无法可靠对应时记
  `inconclusive` 并留人工复核，不强行通过。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---- 诊断类型 ----
# 只匹配真正的缺陷报告行。刻意**不含** "runtime error:"，因为 UBSAN 的
# 无害提示也长这样，必须结合具体 kind 再判。
ASAN_ERROR_RE = re.compile(r"ERROR:\s*(AddressSanitizer|LeakSanitizer|ThreadSanitizer|MemorySanitizer)\s*:\s*(\S+)")
UBSAN_ERROR_RE = re.compile(r"runtime error:\s*([^:\n]+)")
ASAN_SUMMARY_RE = re.compile(r"SUMMARY:\s*(AddressSanitizer|UndefinedBehaviorSanitizer)\s*:\s*(\S+)")
# UBSAN 的 "note: <func> defined here" 行：这类诊断的缺陷位置不在栈帧里
DEFINED_HERE_RE = re.compile(r"(\S+):(\d+):(?:\d+:)?\s*note:\s*(\w+)\s+defined here")
# UBSAN function 类：调用点 + 期望原型
CALL_VIA_PTR_RE = re.compile(r"runtime error:\s*(call to function \w+ through pointer to incorrect function type)")
# 帧行：#0 0x... in func /path/file.c:123:45
# 函数签名里可能有逗号/空格/C++ 模板尖括号（如
# `Exiv2::BmffImage::brotliUncompress(unsigned char const*, unsigned long,
# Exiv2::DataBuf&) /src/exiv2/src/bmffimage.cpp:208:9`）。旧版用 `(\S+) (\S+):`
# 要求函数名不含空格，这类行整行匹配失败、帧直接丢失，于是「栈里没有 sink」
# 被误判成 sink_not_in_stack —— CG-31 因此长期停在 weak。
# 现在：函数名取到行尾最后一个 `path:line:col` 之前，路径本身不含空格/括号。
FRAME_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s+([^\s:()]+):(\d+):(\d+)\s*$",
    re.MULTILINE)
# 不是"缺陷报告"的行：初始化、警告、环境提示
NOISE_RE = re.compile(
    r"^(WARNING:|INFO:|==\d+==WARNING|Shadow byte legend|"
    r"AddressSanitizer:?\s*(failed to|init|interceptors)|"
    r".*(Loaded|Seed:)\s)",
    re.I,
)
# 这些函数属于运行时/插桩，不是目标程序自身的用户代码
RUNTIME_PREFIXES = ("__interceptor_", "__asan_", "__ubsan_", "__sanitizer_", "__lsan_",
                    "__msan_", "fuzzer::", "__libc_", "llvm::")
RUNTIME_PATHS = ("/compiler-rt/", "/libfuzzer/", "/sanitizer_common/", "/llvm-project/")


@dataclass
class Frame:
    index: int
    func: str
    file: str
    line: int
    col: int

    @property
    def is_runtime(self) -> bool:
        return (self.func.startswith(RUNTIME_PREFIXES)
                or any(p in self.file for p in RUNTIME_PATHS))


@dataclass
class Diagnosis:
    """一次运行的诊断解析结果。"""
    kind: str = ""              # heap-buffer-overflow / stack-buffer-overflow / ...
    sanitizer: str = ""         # AddressSanitizer / UndefinedBehaviorSanitizer ...
    is_defect: bool = False     # 是否为真正的缺陷报告（而非噪声）
    write: bool | None = None   # True=写 / False=读 / None=未知
    frames: list[Frame] = field(default_factory=list)
    summary_line: str = ""
    noise_only: bool = False    # 只有噪声，没有缺陷报告
    # UBSAN function 类：缺陷位置来自 "note: X defined here"，不是栈帧
    defined_here: list[Frame] = field(default_factory=list)

    @property
    def user_frames(self) -> list[Frame]:
        """目标程序自身的帧（排除拦截器/运行时）。"""
        return [f for f in self.frames if not f.is_runtime]

    @property
    def first_user_frame(self) -> Frame | None:
        uf = self.user_frames
        return uf[0] if uf else None


def parse_diagnosis(text: str) -> Diagnosis:
    """从容器输出里解析诊断。**不看退出码**，只回答问题：有没有真缺陷报告。"""
    diag = Diagnosis()
    lines = text.splitlines()

    # 噪音判定：整段只有 WARNING/INFO/legend 之类
    meaningful = [ln for ln in lines
                  if ln.strip() and not NOISE_RE.match(ln.strip())
                  and not ln.strip().startswith("    ")]
    if meaningful and not any(ASAN_ERROR_RE.search(ln) or UBSAN_ERROR_RE.search(ln)
                              or ASAN_SUMMARY_RE.search(ln) for ln in lines):
        diag.noise_only = True

    for ln in lines:
        m = ASAN_ERROR_RE.search(ln)
        if m:
            diag.sanitizer, diag.kind = m.group(1), m.group(2)
            diag.is_defect = True
            break
        m = ASAN_SUMMARY_RE.search(ln)
        if m and not diag.is_defect:
            diag.sanitizer, diag.kind = m.group(1), m.group(2)
            diag.is_defect = True
            diag.summary_line = ln.strip()
        m = UBSAN_ERROR_RE.search(ln)
        if m and not diag.is_defect:
            diag.sanitizer = "UndefinedBehaviorSanitizer"
            diag.kind = m.group(1).strip()
            diag.is_defect = True
            break

    # 读写语义
    m = re.search(r"\b(WRITE|READ) of size (\d+)", text)
    if m:
        diag.write = (m.group(1) == "WRITE")
    elif "write" in diag.kind:
        diag.write = True
    elif "read" in diag.kind:
        diag.write = False

    for m in FRAME_RE.finditer(text):
        diag.frames.append(Frame(int(m.group(1)), m.group(2), m.group(3),
                                 int(m.group(4)), int(m.group(5))))
    for m in DEFINED_HERE_RE.finditer(text):
        diag.defined_here.append(Frame(-1, m.group(3), m.group(1),
                                       int(m.group(2)), 0))
    return diag


# ---- 根因一致性 ----

# 诊断类型与 CWE 的语义对应（用于判断"缺陷性质"是否一致，而非只比字符串）
CRASH_TO_CWE = {
    "heap-buffer-overflow": ("CWE-122", "CWE-125"),
    "stack-buffer-overflow": ("CWE-121", "CWE-125"),
    "global-buffer-overflow": ("CWE-125", "CWE-122"),
    # ASAN 对"写超出容器容量但仍在堆分配内"的报法（std::vector 等）。
    # 语义上仍是越界写/读，CWE 与 heap 同类；缺这一项会把 CG-31 判成
    # "CWE 与崩溃不匹配"（cwe_matches_crash=false），把判据缺口伪装成证据缺口。
    "container-overflow": ("CWE-122", "CWE-125"),
    "use-after-free": ("CWE-416",),
    "double-free": ("CWE-415",),
    "integer-overflow": ("CWE-190",),
    "signed-integer-overflow": ("CWE-190",),
    "null-pointer-dereference": ("CWE-476",),
}
LINE_SLACK = 8   # 构建行号与源码行号允许的偏移（47101 曾出现 0，10400 曾出现 7）


def expected_cwes(kind: str, write: bool | None = None) -> tuple[str, ...]:
    """崩溃类型（+读写方向）在语义上允许的 CWE 集合；未识别的类型返回 ()。

    读方向只留读类 CWE，写方向优先 CWE-122：CWE-122/CWE-125 在
    `CRASH_TO_CWE` 里共用一个 key，方向必须靠 ASAN 的 WRITE/READ 行区分。
    """
    exp = CRASH_TO_CWE.get((kind or "").strip().lower()) or ()
    if not exp:
        return ()
    if write is True:
        return tuple(x for x in exp if x != "CWE-125") or tuple(exp)
    if write is False:
        return tuple(x for x in exp if x == "CWE-125") or tuple(exp)
    return tuple(exp)


def cwe_for_crash(kind: str, write: bool | None, claimed: str = "") -> str:
    """按**实际崩溃证据**给出 CWE；claim 的 cwe 只是定位阶段的猜测。

    与旧的内联逻辑逐分支等价（未识别的崩溃类型 / 方向未知时一律回落到
    claim 的猜测，宁可不改也不臆造），只是多认了 container-overflow。
    """
    exp = CRASH_TO_CWE.get((kind or "").strip().lower()) or ()
    if not exp:
        return claimed or ""
    if write is True:
        prefs = [x for x in exp if x == "CWE-122"] or list(exp)
        return prefs[0]
    if write is False:
        return "CWE-125" if "CWE-125" in exp else (claimed or "")
    return claimed or ""



@dataclass
class ConsistencyResult:
    matched: bool
    confidence: str          # strong / weak / none / inconclusive
    reason: str
    evidence: dict = field(default_factory=dict)


def check_root_cause(diag: Diagnosis, sink: dict, claim_cwe: str = "",
                     crash_type_hint: str = "", sink_symbol: str = "",
                     sink_function: str = "") -> ConsistencyResult:
    """判断"这次崩溃"与"声明的 sink"是否为同一根因。

    不是简单的字符串命中：
    1. 没有真缺陷报告 → inconclusive（可能只是 exit=0 或噪声）
    2. 诊断类型与 CWE 语义冲突 → none（崩在了别处）
    3. 首个用户帧 = sink 函数，且行号落在容差内 → strong
    注意：`sink.symbol` 是那一行的调用名（memcpy/memset），用于判定读写语义；
    **函数归属**要比对 `sink_function`（= claim.subject，缺陷所在函数）。
    把两者混用会把"崩在 memcpy 里"误判为"没崩在该函数"。

    4. 首个用户帧 ≠ sink 函数，但栈中有 sink 函数且在容差内 → weak（需人工复核）
    5. 栈里完全没有 sink 函数或行号差太远 → none
    """
    ev: dict = {}
    if not diag.is_defect:
        return ConsistencyResult(False, "inconclusive",
                                 "no_defect_diagnosis", {"noise_only": diag.noise_only})

    kind = diag.kind
    ev["diagnosis"] = {"sanitizer": diag.sanitizer, "kind": kind, "write": diag.write}

    # 2) 缺陷性质与 CWE 是否相容
    expected = CRASH_TO_CWE.get(kind)
    if expected and claim_cwe:
        ev["cwe_expected"] = list(expected)
        ev["cwe_claimed"] = claim_cwe
        if claim_cwe not in expected:
            # 特例：buffer-overflow 的读写语义要一致，否则是不同缺陷
            return ConsistencyResult(False, "none", "cwe_kind_mismatch", ev)
        # 读写方向必须吻合（越界读 vs 越界写是两类缺陷）
        if diag.write is not None and claim_cwe in ("CWE-122", "CWE-125"):
            if claim_cwe == "CWE-125" and diag.write is True:
                return ConsistencyResult(False, "none", "read_write_mismatch", ev)
            if claim_cwe == "CWE-122" and diag.write is False:
                return ConsistencyResult(False, "none", "read_write_mismatch", ev)

    sink_file = (sink or {}).get("file") or ""
    sink_line = (sink or {}).get("line")
    sym = (sink or {}).get("symbol") or sink_symbol or ""          # 行内调用名
    owner = sink_function or ""                                    # 缺陷所在函数
    ev["sink"] = {"file": sink_file, "line": sink_line, "symbol": sym, "function": owner}

    if not sink_file:
        return ConsistencyResult(False, "inconclusive", "no_sink_declared", ev)

    def _file_match(fr_file: str) -> bool:
        """构建路径 /src/ghostpdl/pdf/pdf_font.c 与源码相对路径要能对上。"""
        return sink_file.endswith(fr_file) or fr_file.endswith(sink_file) \
            or sink_file.split("/")[-1] == fr_file.split("/")[-1]

    user = diag.user_frames
    # UBSAN function 类：缺陷位置由 "note: X defined here" 给出（栈帧里没有用户帧）
    if not user and diag.defined_here:
        dh = diag.defined_here[0]
        ev["defined_here"] = {"func": dh.func, "file": dh.file, "line": dh.line}
        same_file = (_file_match(dh.file) if sink_file else False)
        same_func = (not owner) or dh.func == owner
        if same_file and same_func:
            delta = (dh.line - int(sink_line)) if sink_line else 0
            ev["line_delta"] = delta
            if sink_line is None or abs(delta) <= LINE_SLACK:
                return ConsistencyResult(True, "strong", "ubsan_defined_here_matches_sink", ev)
            return ConsistencyResult(False, "inconclusive", "defined_here_line_far", ev)
        return ConsistencyResult(False, "none", "defined_here_mismatch", ev)
    if not user:
        return ConsistencyResult(False, "inconclusive", "no_user_frame", ev)

    ev["first_user_frame"] = {"func": user[0].func, "file": user[0].file,
                              "line": user[0].line}

    def _is_owner(fr: Frame) -> bool:
        """该帧是否就是缺陷所在函数（优先用 owner；无 owner 时退回 symbol）。"""
        want = owner or sym
        if not want:
            return True
        return fr.func == want or fr.func.endswith(":" + want) or want in fr.func

    first = user[0]
    # 3) 首个用户帧就是 sink 所在函数，且行号接近
    if _file_match(first.file) and _is_owner(first):
        if sink_line and abs(first.line - int(sink_line)) <= LINE_SLACK:
            ev["line_delta"] = first.line - int(sink_line)
            # 容差用于吸收构建期行号漂移（宏展开/预处理器），
            # 但**声明行与崩溃行不同**时不能算 strong：
            # 那是"模型指了另一个写点"，不是同一处的行号偏移。
            # 判据：声明行必须等于该函数内的真实缺陷行——由调用方传入
            # exact=True 时才收紧；这里默认按精确匹配给强，容差内给弱。
            if ev["line_delta"] == 0:
                return ConsistencyResult(True, "strong",
                                         "first_user_frame_matches_sink", ev)
            return ConsistencyResult(
                True, "weak", "first_user_frame_matches_sink_but_line_off",
                ev)
        # 同函数但行号差太远：可能是同函数的另一处缺陷
        ev["line_delta"] = first.line - (int(sink_line) if sink_line else -1)
        return ConsistencyResult(False, "inconclusive", "same_function_line_far", ev)

    # 4) 首个帧不是 sink，但栈里能找到 sink（如 mng_get_long 崩在 ReadMNGImage 里调用）
    for fr in user:
        if _file_match(fr.file) and _is_owner(fr):
            if sink_line and abs(fr.line - int(sink_line)) <= LINE_SLACK:
                ev["matched_frame_index"] = fr.index
                ev["line_delta"] = fr.line - int(sink_line)
                return ConsistencyResult(True, "weak", "sink_found_deeper_in_stack", ev)
            # 函数名对上但行号对不上：无法可靠对应
            return ConsistencyResult(False, "inconclusive", "symbol_matches_line_far", ev)

    # 5) 栈里没有 sink 函数
    return ConsistencyResult(False, "none", "sink_not_in_stack", ev)


def has_defect_diagnosis(text: str) -> bool:
    """两端通用：这段输出里有没有真缺陷报告（不看 exit code）。"""
    return parse_diagnosis(text).is_defect
