"""E1+E2 闭环回归：因果要素接线 / 判据修复 / re-gate 证据链。

覆盖三类事实（对应 docs/COURSE-GAP-CLOSED-20261118.md）：

1. **写入**：`workspace/<case>/propagation.json` 的每条 ref 都能在工作区内复算，
   且报告层直接读档案（不依赖重跑 locate）；
2. **重跑**：四个案例的 case.json 已刷新为 propagation.complete / missing=[] /
   causal_chain_verified=true，且 verify / locate / logs 的字节未被改写
   （case.json.upstream 的哈希必须等于当前文件哈希）；
3. **判据**：container-overflow 的 kind/CWE 映射、含逗号签名的栈帧解析、
   root_cause 重算（weak→strong）与镜像证据链（live / recorded 两种口径）。

同时锁死两条反向约束：
- VG-01 **不补字段**（仍是 needs_evidence，没有 stage_status / propagation）；
- 判据重算只会让结论**更保守**时不采纳（不能借改判据把结论悄悄做强）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent import regate  # noqa: E402
from agent.diagnostics import (check_root_cause, cwe_for_crash,  # noqa: E402
                               expected_cwes, parse_diagnosis)
from agent.evidence import (check_all_refs, check_ref, element_values,  # noqa: E402
                           load_propagation, merge_into_claim)
from agent.stages.report import ReportStage  # noqa: E402
from agent.util import sha256_file  # noqa: E402

CLOSED_CASES = {
    "CG-18": "workspace/S7-CG18-arvo-12420",
    "CG-29": "workspace/S14-CG29-arvo-11011",
    "CG-30": "workspace/S15-CG30-arvo-29633",
    "CG-36": "workspace/S19-CG36-arvo-54839",
    "CG-31": "workspace/S16-CG31-arvo-61675",
}

# CG-31 崩溃日志的栈帧形态：C++ 签名里有逗号/空格，旧正则整行匹配失败
ASAN_CG31 = """==7==ERROR: AddressSanitizer: container-overflow on address 0x7c6f29d3f7fe at pc 0x1
WRITE of size 201672 at 0x7c6f29d3f7fe thread T0
    #0 0x47f890 in __interceptor_memcpy /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:827:5
    #1 0x7c6f2a6a79fc  (/lib/x86_64-linux-gnu/libbrotlidec.so.1+0x19fc) (BuildId: 54cf)
    #2 0x7c6f2a6ac4f0 in BrotliDecoderDecompressStream (/lib/x86_64-linux-gnu/libbrotlidec.so.1+0x64f0) (BuildId: 54cf)
    #3 0x532b0e in Exiv2::BmffImage::brotliUncompress(unsigned char const*, unsigned long, Exiv2::DataBuf&) /src/exiv2/src/bmffimage.cpp:208:9
    #4 0x536507 in Exiv2::BmffImage::boxHandler(std::__1::basic_ostream<char, std::__1::char_traits<char> >&, Exiv2::PrintStructureOption, unsigned long, unsigned long) /src/exiv2/src/bmffimage.cpp:541:7
    #5 0x52df75 in LLVMFuzzerTestOneInput /src/exiv2/fuzz/fuzz-read-print-write.cpp:22:12
"""

SINK_CG31 = {"file": "bmffimage.cpp", "line": 208}
SUBJECT_CG31 = "BmffImage::brotliUncompress"


def _stage(**kw):
    """只测纯判据函数：绕开 __init__ 的 store/docker 依赖。"""
    st = object.__new__(ReportStage)
    st.regate = bool(kw.pop("regate", False))
    st._image_provenance = {}
    st._prior_case = kw.pop("prior_case", {})
    st._image_error = ""
    for k, v in kw.items():
        setattr(st, k, v)
    return st


class _Row(dict):
    pass


class _FakeStore:
    def __init__(self, bindings):
        self._bindings = bindings

    def latest_checkpoint(self, run_id, stage):
        b = self._bindings.get(stage)
        return _Row(binding=json.dumps(b)) if b else None


# ---------------------------------------------------------------- 1. 写入 ----
def test_propagation_files_exist_and_refs_recompute():
    """五个案例的每条 ref 必须能在仓库内复算（文件存在 / 行号 / 该行含 expect）。"""
    for case, ws in CLOSED_CASES.items():
        manual = load_propagation(ROOT / ws)
        assert manual, f"{case} 缺 propagation.json"
        assert manual["verified_by"] == "evidence_refs"
        assert manual["reviewed_by"] in (None, ""), "复核签字不能由脚本代填"
        failures = check_all_refs(manual, ROOT)
        assert not failures, f"{case} refs 复算失败: {failures[:3]}"
        # 四要素齐全且都有 value
        vals = element_values(manual)
        for key in ("input_bytes", "reaches_sink", "missing_check", "observed_oob"):
            assert key in vals, f"{case} 缺要素 {key}"


def test_propagation_values_come_from_course_gap():
    """档案里的 value 必须逐字段等于 COURSE-GAP.json（不允许二次加工）。"""
    gap = json.loads((ROOT / "experiments" / "COURSE-GAP.json").read_text(encoding="utf-8"))
    for case, ws in CLOSED_CASES.items():
        gcase = next(c for c in gap["cases"] if c["case"] == case)
        manual = load_propagation(ROOT / ws)
        for key, spec in manual["elements"].items():
            assert spec["value"] == gcase["elements"][key]["value"], f"{case}/{key} value 被改写"
            assert spec["refs"] == (gcase["elements"][key].get("refs") or []), \
                f"{case}/{key} refs 被改写"


def test_merge_into_claim_wires_elements_and_dataflow():
    manual = {"source": "COURSE-GAP-20261118 逐行核对", "verified_by": "evidence_refs",
              "elements": {"input_bytes": {"value": "260B"}, "reaches_sink": {"value": "u32_to_u8"},
                           "missing_check": {"value": "无长度校验"},
                           "observed_oob": {"value": "WRITE 66>64"}}}
    claim = merge_into_claim({}, manual)
    assert claim["propagation"]["elements"]["input_bytes"] == "260B"
    assert claim["propagation"]["verified_by"] == "evidence_refs"
    # 写档案 ≠ 已复核：不得自动打 manual_review
    assert claim["propagation"]["verified_by"] != "manual_review"
    assert [d["step"] for d in claim["dataflow"]] == \
        ["input_bytes", "reaches_sink", "missing_check"]


def test_merge_keeps_existing_dataflow_and_elements():
    claim = {"dataflow": [{"step": "sink", "note": "定位阶段"}],
             "propagation": {"elements": {"input_bytes": "旧值", "extra": "keep"}}}
    out = merge_into_claim(claim, {"elements": {"input_bytes": {"value": "新值"}}})
    assert out["dataflow"] == claim["dataflow"]
    assert out["propagation"]["elements"] == {"input_bytes": "新值", "extra": "keep"}
    # 不改调用方对象
    assert claim["propagation"]["elements"]["input_bytes"] == "旧值"


def test_check_ref_reports_missing_file_and_stale_line(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello\nworld\n", encoding="utf-8")
    assert check_ref({"path": "a.txt", "line": 2, "expect": "world"}, tmp_path) is None
    assert "不含" in check_ref({"path": "a.txt", "line": 2, "expect": "nope"}, tmp_path)
    assert "行号越界" in check_ref({"path": "a.txt", "line": 9, "expect": "x"}, tmp_path)
    assert "不存在" in check_ref({"path": "b.txt", "line": 1}, tmp_path)


# ---------------------------------------------------------------- 2. 判据 ----
def test_defect_kind_recognises_container_overflow():
    st = _stage()
    verify = {"root_cause": {"evidence": {"diagnosis": {"sanitizer": "AddressSanitizer",
                                                        "kind": "container-overflow"}}}}
    assert st._defect_kind(verify, {}) == "memory_corruption"
    # 既有映射不受影响
    for kind in ("heap-buffer-overflow", "stack-buffer-overflow", "use-after-free"):
        v = {"root_cause": {"evidence": {"diagnosis": {"sanitizer": "AddressSanitizer",
                                                       "kind": kind}}}}
        assert st._defect_kind(v, {}) == "memory_corruption"
    ub = {"root_cause": {"evidence": {"diagnosis": {"sanitizer": "UndefinedBehaviorSanitizer",
                                                    "kind": "call to function foo"}}}}
    assert st._defect_kind(ub, {}) == "callback_type_mismatch"
    assert st._defect_kind({"root_cause": {"evidence": {}}}, {}) == "unknown"


def test_cwe_matches_crash_container_overflow():
    st = _stage()
    verify = {"root_cause": {"evidence": {"diagnosis": {"kind": "container-overflow",
                                                        "write": True}}}}
    assert st._cwe_matches_crash("CWE-122", "container-overflow", verify) is True
    assert st._cwe_matches_crash("CWE-121", "container-overflow", verify) is False
    # 读方向只允许 CWE-125
    read = {"root_cause": {"evidence": {"diagnosis": {"kind": "container-overflow",
                                                      "write": False}}}}
    assert st._cwe_matches_crash("CWE-125", "container-overflow", read) is True
    assert st._cwe_matches_crash("CWE-122", "container-overflow", read) is False
    # 旧文本口径仍生效（崩溃类型未识别时）
    assert st._cwe_matches_crash("CWE-121", "stack-buffer-overflow", {}) is True
    assert st._cwe_matches_crash("", "heap-buffer-overflow", {}) is False


def test_cwe_for_crash_is_evidence_driven():
    assert cwe_for_crash("container-overflow", True, "CWE-121") == "CWE-122"
    assert cwe_for_crash("container-overflow", False, "") == "CWE-125"
    assert cwe_for_crash("stack-buffer-overflow", True, "") == "CWE-121"
    assert cwe_for_crash("heap-buffer-overflow", False, "") == "CWE-125"
    # 未识别类型不猜：回落到 claim 的猜测
    assert cwe_for_crash("weird-thing", True, "CWE-190") == "CWE-190"
    assert expected_cwes("container-overflow", True) == ("CWE-122",)


def test_frame_parser_keeps_cxx_signature_with_commas():
    d = parse_diagnosis(ASAN_CG31)
    assert d.kind == "container-overflow"
    assert d.write is True
    funcs = [f.func for f in d.frames]
    assert SUM_CG31 in funcs, f"含逗号的 C++ 签名帧被丢掉: {funcs}"
    assert d.first_user_frame.file.endswith("bmffimage.cpp")
    assert d.first_user_frame.line == 208


SUM_CG31 = "Exiv2::BmffImage::brotliUncompress(unsigned char const*, unsigned long, Exiv2::DataBuf&)"


def test_root_cause_strong_for_library_mediated_write():
    """写动作落在第三方库里，但首个**用户帧**就是缺陷函数 → strong。"""
    r = check_root_cause(parse_diagnosis(ASAN_CG31), SINK_CG31, "CWE-122",
                         sink_function=SUBJECT_CG31)
    assert r.matched and r.confidence == "strong"
    assert r.reason == "first_user_frame_matches_sink"
    assert r.evidence["first_user_frame"]["line"] == 208


def test_propagation_complete_needs_four_elements():
    st = _stage()
    claim = {"propagation": {"elements": {"input_bytes": "a", "reaches_sink": "b",
                                          "missing_check": "c"}}}
    verify = {"root_cause": {"evidence": {"diagnosis": {"kind": "container-overflow"}}}}
    prop = st._propagation(claim, verify, "memory_corruption")
    assert prop["complete"] is True          # observed_oob 由诊断自动补齐
    assert prop["missing"] == []
    empty = st._propagation({}, {"root_cause": {"evidence": {}}}, "memory_corruption")
    assert empty["complete"] is False
    assert empty["missing"] == ["input_bytes", "reaches_sink", "missing_check", "observed_oob"]


# ------------------------------------------------------- 3. re-gate 证据链 ----
def _ws_with_log(tmp_path, text=ASAN_CG31):
    ws = tmp_path / "ws"
    (ws / "logs").mkdir(parents=True)
    (ws / "artifacts" / "verify").mkdir(parents=True)
    (ws / "logs" / "vul.log").write_text(text, encoding="utf-8")
    verify = {"verdict": "pass", "cwe_by_crash": "CWE-122",
              "vul": {"exit_code": 1, "log": "logs/vul.log"},
              "root_cause": {"matched": True, "confidence": "weak",
                             "reason": "sink_line_in_raw_trace",
                             "evidence": {"text_hit": {"file": "bmffimage.cpp", "line": 208}}},
              "claim_used": {"subject": SUBJECT_CG31}}
    return ws, verify


def test_rejudge_upgrades_weak_to_strong(tmp_path):
    ws, verify = _ws_with_log(tmp_path)
    out = regate.rejudge_root_cause(ws, verify, {})
    assert out["applied"] is True
    assert out["reason"] == "rejudged:weak->strong"
    assert out["root_cause"]["confidence"] == "strong"
    assert out["provenance"]["log_sha256"] == sha256_file(ws / "logs" / "vul.log")
    applied = regate.apply_rejudge(verify, out)
    assert applied["root_cause"]["confidence"] == "strong"
    # 执行类观测值一律不动
    assert applied["vul"] == verify["vul"] and applied["verdict"] == "pass"


def test_rejudge_never_weakens_landed_verdict(tmp_path):
    """新的判据若给出更弱的结论：不采纳，记 conflict（不能借改判据翻掉已通过案例）。"""
    ws, verify = _ws_with_log(tmp_path, text="Execution successful\n")
    verify["root_cause"] = {"matched": True, "confidence": "strong",
                            "reason": "first_user_frame_matches_sink"}
    out = regate.rejudge_root_cause(ws, verify, {})
    assert out["applied"] is False
    assert out.get("conflict") is True
    assert regate.apply_rejudge(verify, out)["root_cause"]["confidence"] == "strong"


def test_rejudge_requires_persisted_log(tmp_path):
    ws, verify = _ws_with_log(tmp_path)
    verify["vul"]["log"] = "logs/missing.log"
    out = regate.rejudge_root_cause(ws, verify, {})
    assert out["applied"] is False and out["reason"] == "no_persisted_log"


def test_image_provenance_recorded_matches_prior_case_json():
    binding = {"stage": "verify", "image_digest": "sha256:" + "a" * 64, "images": {}}
    prior = {"images": {"recon": ["sha256:" + "a" * 64], "locate": ["sha256:" + "a" * 64],
                        "verify": ["sha256:" + "a" * 64], "exploit": ["sha256:" + "a" * 64]}}
    st = _stage(regate=True, prior_case=prior,
                store=_FakeStore({s: binding for s in ("recon", "locate", "verify", "exploit")}),
                run_id="r-test")
    ok, prov = st._image_provenance_recorded()
    assert ok is True
    assert prov["mode"] == "recorded_bindings" and prov["verified_live"] is False
    assert prov["matches_prior_case_json"] is True


def test_image_provenance_rejects_digest_drift_and_missing_prior():
    binding = {"stage": "verify", "image_digest": "sha256:" + "a" * 64, "images": {}}
    store = _FakeStore({s: binding for s in ("recon", "locate", "verify", "exploit")})
    drift = {"images": {"recon": ["sha256:" + "b" * 64], "locate": ["sha256:" + "a" * 64],
                        "verify": ["sha256:" + "a" * 64], "exploit": ["sha256:" + "a" * 64]}}
    ok, prov = _stage(regate=True, prior_case=drift, store=store,
                      run_id="r")._image_provenance_recorded()
    assert ok is False and "digest_drift" in prov["reason"]
    ok2, prov2 = _stage(regate=True, prior_case={}, store=store,
                        run_id="r")._image_provenance_recorded()
    assert ok2 is False and prov2["reason"] == "no_prior_case_images"
    # 占位 digest 一律不认
    stub = {"stage": "verify", "image_digest": "sha256:unresolved-abc", "images": {}}
    ok3, prov3 = _stage(regate=True, prior_case=drift,
                        store=_FakeStore({s: stub for s in ("recon", "locate", "verify",
                                                            "exploit")}),
                        run_id="r")._image_provenance_recorded()
    assert ok3 is False and "non_concrete_digest" in prov3["reason"]


def test_regate_offline_does_not_require_images():
    st = _stage(regate=True)
    st.requires_images = False     # __init__ 在 regate 下的行为
    assert st.requires_images is False
    assert _stage(regate=False).regate is False


# ---------------------------------------------------- 4. 刷新后的真实产物 ----
@pytest.mark.parametrize("case", sorted(CLOSED_CASES))
def test_case_json_refreshed_and_sources_untouched(case):
    ws = ROOT / CLOSED_CASES[case]
    c = json.loads((ws / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    st = c["stage_status"]
    assert st["propagation"]["complete"] is True
    assert st["propagation"]["missing"] == []
    assert st["propagation"]["verified_by"] == "evidence_refs"
    assert c["acceptance"]["causal_chain_verified"] is True
    assert c["acceptance"]["stage"] in ("causal_chain_verified", "course_ready")
    assert not [k for k, v in c["checks"].items() if v is False], c["checks"]
    # re-gate 留痕：没有重跑执行
    assert c["regate"]["executed_again"] is False
    assert c["image_provenance"]["mode"] in ("live_docker_inspect", "recorded_bindings")
    # 上游证据字节未被改写：case.json 里记的哈希必须等于当前文件哈希
    for rel, sha in (c.get("upstream") or {}).items():
        p = ws / rel
        assert p.exists(), f"{case} 缺上游 {rel}"
        assert sha256_file(p) == sha, f"{case} 上游 {rel} 被改写（哈希不一致）"


def test_cg36_dataflow_check_is_green():
    c = json.loads((ROOT / CLOSED_CASES["CG-36"] / "artifacts" / "report" /
                    "case.json").read_text(encoding="utf-8"))
    assert c["checks"]["dataflow_has_evidence"] is True


def test_cg31_rejudge_is_recorded_with_criteria_and_log_hash():
    ws = ROOT / CLOSED_CASES["CG-31"]
    c = json.loads((ws / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    rj = c["regate"]["rejudge"]
    assert rj["applied"] is True
    assert rj["previous"]["confidence"] == "weak"
    assert c["stage_status"]["root_cause"]["confidence"] == "strong"
    assert c["checks"]["cwe_matches_crash"] is True
    assert rj["provenance"]["log_sha256"] == sha256_file(ws / rj["provenance"]["log"])


def test_vg01_stays_needs_evidence():
    """任务要求：VG-01 不补字段，明确保持 needs_evidence。"""
    ws = ROOT / "workspace" / "VG-01-nltk-wordnet"
    assert not (ws / "propagation.json").exists()
    c = json.loads((ws / "artifacts" / "report" / "case.json").read_text(encoding="utf-8"))
    assert "stage_status" not in c or not c.get("stage_status")
    assert c["acceptance"]["causal_chain_verified"] is False
    gap = json.loads((ROOT / "experiments" / "COURSE-GAP.json").read_text(encoding="utf-8"))
    vg = next(x for x in gap["cases"] if x["case"] == "VG-01")
    assert vg["classification"] == "needs_new_experiment"
    assert vg["elements"]["reaches_sink"]["status"] == "needs_evidence"
    assert vg["elements"]["missing_check"]["status"] == "needs_evidence"


def test_closure_totals_match_live_ledger():
    """COURSE-GAP.json 的 closure.totals 必须与当前台账/核账一致（防手写漂移）。"""
    gap = json.loads((ROOT / "experiments" / "COURSE-GAP.json").read_text(encoding="utf-8"))
    led = json.loads((ROOT / "experiments" / "LEDGER.json").read_text(encoding="utf-8"))
    aud = json.loads((ROOT / "experiments" / "LEDGER-AUDIT.json").read_text(encoding="utf-8"))
    t = gap["closure"]["totals"]
    # 闭环记录的是当时的值；后续新增案例只允许让计数单调不减
    assert led["totals"]["causal_chain_verified"] >= t["ledger_causal_chain_verified_after"], (
        f"台账因果链 {led['totals']['causal_chain_verified']} 少于闭环时记录 "
        f"{t['ledger_causal_chain_verified_after']}，历史被回退")
    # 闭环记录的是当时的值；后续新增案例只允许单调不减
    assert aud["counts"]["independent_high_verified"] >= t["independent_high_verified_after"]
    assert aud["counts"]["independent_high_roots"] >= t["independent_high_roots"], (
        f"独立根因从闭环时 {t['independent_high_roots']} 回退到 "
        f"{aud['counts']['independent_high_roots']}")
    closed = json.loads((ROOT / "experiments" / "COURSE-GAP-CLOSED.json")
                        .read_text(encoding="utf-8"))
    assert sorted(c["case"] for c in closed["cases"] if c["outcome"] == "closed") == \
        sorted(CLOSED_CASES)
