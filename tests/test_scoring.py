"""三层评分器：可执行、不合成单一分数、不做关键词打分。"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("scoring", ROOT / "experiments" / "scoring.py")
sc = importlib.util.module_from_spec(spec)
sys.modules["scoring"] = sc
spec.loader.exec_module(sc)

ANSWER = {
    "target_function": "LLVMFuzzerTestOneInput",
    "defect_file": "yara/tests/oss-fuzz/rules_fuzzer.cc",
    "defect_line": 44,
    "line_slack": 2,
    "conditional_branches": False,
    "required_elements": ["callback_signature_mismatch", "wrong_pointer_type"],
}


def test_function_recall_hit_does_not_mean_located():
    r = sc.score_function_recall(ANSWER, {"functions": ["LLVMFuzzerTestOneInput"]})
    assert r.verdict == "correct"
    assert "not proof of localization" in r.detail["note"]


def test_function_recall_miss():
    r = sc.score_function_recall(ANSWER, {"functions": ["OtherFunc"]})
    assert r.verdict == "incorrect"


def test_instance_locate_wrong_file_is_incorrect():
    r = sc.score_instance_locate(ANSWER, {"file": "yara/tests/oss-fuzz/elf_fuzzer.cc",
                                          "line": 67})
    assert r.verdict == "incorrect"


def test_instance_locate_correct():
    r = sc.score_instance_locate(ANSWER, {"file": "yara/tests/oss-fuzz/rules_fuzzer.cc",
                                          "line": 44})
    assert r.verdict == "correct"


def test_instance_locate_line_within_slack():
    r = sc.score_instance_locate(ANSWER, {"file": "yara/tests/oss-fuzz/rules_fuzzer.cc",
                                          "line": 45})
    assert r.verdict == "correct" and r.detail["line_delta"] == 1


def test_instance_locate_line_beyond_slack():
    r = sc.score_instance_locate(ANSWER, {"file": "yara/tests/oss-fuzz/rules_fuzzer.cc",
                                          "line": 99})
    assert r.verdict == "incorrect"


def test_instance_locate_without_line_is_insufficient():
    r = sc.score_instance_locate(ANSWER, {"file": "yara/tests/oss-fuzz/rules_fuzzer.cc",
                                          "line": None})
    assert r.verdict == "insufficient_evidence"


def test_root_cause_requires_all_elements():
    ok = sc.score_root_cause(ANSWER, {"elements": {"callback_signature_mismatch": True,
                                                   "wrong_pointer_type": True}})
    assert ok.verdict == "correct"
    partial = sc.score_root_cause(ANSWER, {"elements": {"callback_signature_mismatch": True,
                                                        "wrong_pointer_type": False}})
    assert partial.verdict == "incorrect"


def test_root_cause_none_element_is_insufficient():
    r = sc.score_root_cause(ANSWER, {"elements": {"callback_signature_mismatch": True,
                                                  "wrong_pointer_type": None}})
    assert r.verdict == "insufficient_evidence"


def test_no_partial_score_and_no_single_number():
    r = sc.score_case(ANSWER, {"functions": ["LLVMFuzzerTestOneInput"],
                               "file": "yara/tests/oss-fuzz/elf_fuzzer.cc",
                               "line": 67,
                               "root_cause": {"elements": {"callback_signature_mismatch": True,
                                                           "wrong_pointer_type": True}}})
    assert set(r) == {"function_recall", "instance_locate", "root_cause", "all_layers_correct"}
    assert r["all_layers_correct"] is False
    assert not any(isinstance(v, float) for k, v in r.items() if k != "all_layers_correct")


def test_invalid_verdict_rejected():
    import pytest
    with pytest.raises(ValueError):
        sc.LayerResult("probably")
