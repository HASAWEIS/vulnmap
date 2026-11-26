"""诊断解析与根因一致性：不能只做字符串命中。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.tools import binscan
from agent.diagnostics import (check_root_cause, has_defect_diagnosis,
                               parse_diagnosis)

ASAN_10400 = """==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000151 at pc 0x1
READ of size 1 at 0x602000000151 thread T0
    #0 0x1 in mng_get_long /src/graphicsmagick/coders/png.c:1018:38
    #1 0x2 in ReadMNGImage /src/graphicsmagick/coders/png.c:4920:30
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/graphicsmagick/coders/png.c:1018:38 in mng_get_long
"""

ASAN_44034 = """==14==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f at pc 0x2
WRITE of size 5575 at 0x7f thread T0
    #0 0x4bf1e2 in __interceptor_memcpy /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:827:5
    #1 0xf5fcbf in pdfi_open_CIDFont_substitute_file /src/ghostpdl/./pdf/pdf_font.c:332:9
"""

SINK_10400 = {"file": "graphicsmagick/coders/png.c", "line": 4920, "symbol": "mng_get_long"}


# ---- 解析 ----
def test_parses_asan_kind_and_frames():
    d = parse_diagnosis(ASAN_10400)
    assert d.is_defect and d.kind == "heap-buffer-overflow"
    assert d.write is False
    assert d.first_user_frame.func == "mng_get_long"


def test_runtime_frames_are_excluded():
    d = parse_diagnosis(ASAN_44034)
    assert d.first_user_frame.func == "pdfi_open_CIDFont_substitute_file"
    assert d.frames[0].is_runtime      # __interceptor_memcpy 属运行时


def test_warning_only_is_not_a_defect():
    noise = ("==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
             "Shadow byte legend (one shadow byte represents 8 application bytes):\n")
    assert not has_defect_diagnosis(noise)


def test_plain_program_output_is_not_a_defect():
    assert not parse_diagnosis("Execution successful\n").is_defect
    # 目标自己打印的、恰好含 "AddressSanitizer" 字样的普通字符串不算
    assert not parse_diagnosis("note: sanitizer disabled by config\n").is_defect


# ---- 根因一致性 ----
def test_first_user_frame_matches_sink_is_strong():
    r = check_root_cause(parse_diagnosis(ASAN_44034),
                         {"file": "ghostpdl/pdf/pdf_font.c", "line": 332, "symbol": "memcpy"},
                         "CWE-121", sink_function="pdfi_open_CIDFont_substitute_file")
    assert r.matched and r.confidence == "strong"


def test_sink_deeper_in_stack_is_weak_not_strong():
    r = check_root_cause(parse_diagnosis(ASAN_10400), SINK_10400, "CWE-125",
                         sink_function="ReadMNGImage")
    assert r.matched and r.confidence == "weak"


def test_wrong_function_is_rejected():
    """崩在完全无关的函数里 → 不是这个漏洞。"""
    r = check_root_cause(parse_diagnosis(ASAN_10400),
                         {"file": "graphicsmagick/coders/png.c", "line": 4920,
                          "symbol": "mng_get_long"},
                         "CWE-125", sink_function="SomeOtherFunction")
    assert not r.matched
    assert r.confidence in ("none", "inconclusive")


def test_read_write_mismatch_is_rejected():
    """越界读的 PoC 不能用来证明越界写。"""
    r = check_root_cause(parse_diagnosis(ASAN_10400), SINK_10400, "CWE-122",
                         sink_function="ReadMNGImage")
    assert not r.matched
    assert r.reason in ("read_write_mismatch", "cwe_kind_mismatch")


def test_noisy_but_no_defect_is_inconclusive():
    d = parse_diagnosis("==1==WARNING: something\n")
    r = check_root_cause(d, SINK_10400, "CWE-125")
    assert not r.matched and r.confidence == "inconclusive"


def test_line_drift_within_slack_is_accepted():
    """构建行号与源码行号有偏移时不应直接否决。"""
    text = ASAN_10400.replace(":4920:30", ":4925:30")
    r = check_root_cause(parse_diagnosis(text), SINK_10400, "CWE-125",
                         sink_function="ReadMNGImage")
    assert r.matched and r.evidence.get("line_delta") == 5


def test_line_drift_beyond_slack_is_inconclusive():
    text = ASAN_10400.replace(":4920:30", ":1999:30")
    r = check_root_cause(parse_diagnosis(text), SINK_10400, "CWE-125",
                         sink_function="ReadMNGImage")
    assert not r.matched and r.confidence == "inconclusive"


# ---- UBSAN function 类：缺陷位置在 note: 行，不在栈帧 ----
UBSAN_FUNC = """INFO: Seed: 1
/out/rules_fuzzer: Running 1 inputs
/src/libfuzzer/FuzzerLoop.cpp:471:13: runtime error: call to function LLVMFuzzerTestOneInput through pointer to incorrect function type 'int (*)(const unsigned char *, unsigned long)'
/src/yara/tests/oss-fuzz/rules_fuzzer.cc:45: note: LLVMFuzzerTestOneInput defined here
    #0 0x484667 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/libfuzzer/FuzzerLoop.cpp:471:13
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/libfuzzer/FuzzerLoop.cpp:471:13 in
"""


def test_ubsan_function_class_is_parsed():
    d = parse_diagnosis(UBSAN_FUNC)
    assert d.is_defect and d.sanitizer == "UndefinedBehaviorSanitizer"
    assert d.defined_here and d.defined_here[0].func == "LLVMFuzzerTestOneInput"
    assert d.defined_here[0].line == 45
    assert d.user_frames == []          # 栈帧全是运行时，没有用户帧


def test_ubsan_defined_here_matches_correct_instance():
    d = parse_diagnosis(UBSAN_FUNC)
    r = check_root_cause(d, {"file": "tests/oss-fuzz/rules_fuzzer.cc", "line": 44},
                         "CWE-704", sink_function="LLVMFuzzerTestOneInput")
    assert r.matched and r.confidence == "strong"
    assert r.reason == "ubsan_defined_here_matches_sink"


def test_ubsan_rejects_wrong_instance():
    """3938 的真实场景：同名函数 3 处，指错文件必须被拒。"""
    d = parse_diagnosis(UBSAN_FUNC)
    r = check_root_cause(d, {"file": "tests/oss-fuzz/elf_fuzzer.cc", "line": 67},
                         "CWE-704", sink_function="LLVMFuzzerTestOneInput")
    assert not r.matched
    assert r.reason == "defined_here_mismatch"


# ---- 身份绑定：旧日志配新构建必须拒绝 ----
def test_debuginfo_requires_provenance():
    frame = "    #1 0x1 in foo /src/a.c:10:1"
    r = binscan.confirm_by_debuginfo([frame], "a.c")
    assert not r["confirmed"] and r["basis"] == "no_provenance"


def test_debuginfo_rejects_mismatched_provenance():
    """旧日志 + 新二进制：即使行号命中也不能确认。"""
    frame = "    #1 0x1 in foo /src/a.c:10:1"
    r = binscan.confirm_by_debuginfo([frame], "a.c", provenances=[
        {"run_id": "r-old", "binary_sha256": "old", "source_sha256": "old",
         "image_digest": "old", "matches": False}])
    assert not r["confirmed"] and r["basis"] == "provenance_mismatch"


def test_debuginfo_confirms_with_full_provenance():
    frame = "    #1 0x1 in foo /src/a.c:10:1"
    r = binscan.confirm_by_debuginfo([frame], "a.c", provenances=[
        {"run_id": "r1", "binary_sha256": "b", "source_sha256": "s",
         "image_digest": "sha256:x", "matches": True}])
    assert r["confirmed"]
    assert r["provenance"]["binary_sha256"] == "b"
