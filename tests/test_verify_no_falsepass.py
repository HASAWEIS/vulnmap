"""verify 误报路径：基础设施失败绝不能被判成漏洞触发。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agent.contracts import Budget
from agent.runtime.orchestrator import Orchestrator
from agent.stages.verify import VerifyStage

WS = Path(__file__).resolve().parent.parent / "workspace" / "CG-04-arvo-10400"


def _stage():
    orch = Orchestrator(WS, budget=Budget(max_turns=40, timeout_seconds=900))
    st = VerifyStage(orch.store, orch.task["run_id"], WS, orch._request("verify"))
    # 真实 claim 上下文：root-cause 判定需要 sink / cwe / subject
    st._current_claim = {
        "subject": "ReadMNGImage", "cwe": "CWE-125",
        "sink": {"file": "graphicsmagick/coders/png.c", "line": 4920,
                 "symbol": "mng_get_long"},
    }
    st._current_sink = st._current_claim["sink"]
    return st


def _run(label, vul, fix):
    st = _stage()

    def fake(image, poc, name):
        # 不带 class：强制 _try 用真实 _classify_run 重新分类
        out = dict(fix if "fix" in image else vul)
        out.pop("class", None)
        out.pop("defect", None)
        out.pop("diagnosis", None)
        return out

    st._run_container = fake
    return st._try({"name": "p", "data": b"AAAA", "format": "raw"},
                   {"vul": "n132/arvo:1-vul", "fix": "n132/arvo:1-fix"})


ERR = {"exit_code": 125, "crash": "", "timed_out": False, "class": "infra",
       "infra": "docker_error:docker: Error", "log": "l", "tail": "docker: Error"}
TO = {"exit_code": 124, "crash": "", "timed_out": True, "class": "infra",
      "infra": "timeout", "log": "l", "tail": "x"}
NOSAN = {"exit_code": 1, "crash": "", "timed_out": False, "infra": "", "log": "l", "tail": "x"}
OK0 = {"exit_code": 0, "crash": "", "timed_out": False, "class": "ok", "infra": "", "log": "l", "tail": "ok"}
ASAN = {"exit_code": 1, "crash": "ERROR: AddressSanitizer: heap-buffer-overflow",
        "timed_out": False, "class": "ok", "infra": "", "log": "l",
        "tail": ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                 "READ of size 1 at 0x1 thread T0\n"
                 "    #0 0x1 in mng_get_long /src/graphicsmagick/coders/png.c:1018:38\n"
                 "    #1 0x2 in ReadMNGImage /src/graphicsmagick/coders/png.c:4920:30\n")}


def test_docker_failure_is_not_a_pass():
    """审查方给的场景：vul=125 且 fix=0，旧实现判 pass。"""
    r = _run("docker-fail", ERR, OK0)
    assert r["verdict"] == "infra_error"
    assert "docker" in r["reason"] or "125" in r["reason"]


def test_timeout_is_not_a_pass():
    assert _run("timeout", TO, OK0)["verdict"] == "infra_error"


def test_nonzero_without_sanitizer_is_inconclusive_not_pass():
    """非零但无 sanitizer 证据：无法分类，记 inconclusive，绝不给 pass。"""
    r = _run("nosan", NOSAN, OK0)
    assert r["verdict"] == "inconclusive"


def test_exit_77_is_program_rejection_not_crash():
    """77 = MagickFatalError 一类"程序拒绝输入"，不是崩溃也不是环境故障。"""
    r = _run("reject77", dict(OK0, exit_code=77, crash=""), OK0)
    assert r["verdict"] == "not_triggered"
    assert "program_rejected" in r["reason"]


def test_exit_137_with_oom_is_infra():
    r = _run("oom", dict(OK0, exit_code=137, tail="Killed\nout of memory"), OK0)
    assert r["verdict"] == "infra_error"


def test_exit_137_without_evidence_is_inconclusive():
    r = _run("137", dict(OK0, exit_code=137, tail=""), OK0)
    assert r["verdict"] == "inconclusive"


def test_fix_nonzero_without_sanitizer_is_not_fail_both():
    """fix 非零但没有 sanitizer：不能算"两边都崩"。"""
    r = _run("fixnosan", ASAN, dict(OK0, exit_code=1, crash=""))
    assert r["verdict"] == "inconclusive"


def test_fix_side_infra_failure_is_not_fail_both():
    r = _run("fix-infra", ASAN, ERR)
    assert r["verdict"] == "infra_error"
    assert r["reason"].startswith("fix_side:")


def test_real_crash_still_passes():
    assert _run("ok", ASAN, OK0)["verdict"] == "pass"


def test_both_sides_crash_is_fail_both():
    """两侧都报同一缺陷 → fail_both。"""
    r = _run("both", ASAN, ASAN)
    assert r["verdict"] == "fail_both"


def test_clean_run_is_not_triggered():
    assert _run("clean", OK0, OK0)["verdict"] == "not_triggered"


def test_infra_failure_classification():
    st = _stage()
    assert st._classify_run({"exit_code": 125, "crash": "", "timed_out": False},
                            "docker: Error response from daemon") == "infra"
    asan_text = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                 "READ of size 1 at 0x1 thread T0\n"
                 "    #0 0x1 in f /src/a.c:10:1\n")
    assert st._classify_run({"exit_code": 1, "crash": "x", "timed_out": False},
                            asan_text) == "ok"
    # exit=0 但带真缺陷报告（halt_on_error=0）→ 仍是 ok，不能当 clean
    assert st._classify_run({"exit_code": 0, "crash": "", "timed_out": False},
                            asan_text) == "ok"
    assert st._classify_run({"exit_code": 77, "crash": "", "timed_out": False},
                            "MagickFatalError") == "ok"
    assert st._classify_run({"exit_code": 137, "crash": "", "timed_out": False},
                            "Killed out of memory") == "infra"
    assert st._classify_run({"exit_code": 137, "crash": "", "timed_out": False}, "") == "inconclusive"
    assert st._classify_run({"exit_code": 3, "crash": "", "timed_out": False}, "") == "inconclusive"
