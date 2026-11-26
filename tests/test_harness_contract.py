"""harness 输入契约（S4-b B1）：解析 / 越界拒绝 / 未知放行 / verify 注入。

根因回顾（docs/ACCEPTANCE-S4b.md）：Fuzz_chpw.c 里
    if (Size < kMinInputLength || Size > kMaxInputLength) { return 0; }
窗口外输入在入口就被丢弃；模型闭环却只拿缺陷函数源码，
第 3 轮给 1 字节直接空转（vul_exit=0）。本测试钉住三件事：
1) 契约能被解析成 {min,max,channel,confidence}；
2) verify 在执行前拒绝窗口外候选（rejected_by_contract），并把允许区间写进提示；
3) 解析不到时 confidence=unknown 且一律放行，绝不因解析失败拦候选。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import harness

ROOT = Path(__file__).resolve().parent.parent
CG09_SRC = ROOT / "workspace" / "CG-09-arvo-53666" / "src"


FUZZER_HEAD = "#include <stdint.h>\n"


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


DEFINE_HARNESS = "\n".join([
    "#include <stdint.h>",
    "#define kMinInputLength 20",
    "#define kMaxInputLength 100",
    "extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)",
    "{",
    "    if (Size < kMinInputLength || Size > kMaxInputLength){",
    "        return 0;",
    "    }",
    "    return 0;",
    "}",
])


def test_extract_define_constants():
    c = harness.extract_from_text(DEFINE_HARNESS, source_file="Fuzz_chpw.c")
    assert (c["min_size"], c["max_size"]) == (20, 100)
    assert c["confidence"] == "exact"
    assert c["channel"] == "fuzzer_data_arg"
    assert c["conditions"] and "kMinInputLength" in c["conditions"][0]["text"]


def test_extract_const_and_enum_constants(tmp_path):
    body = "\n".join([
        "#include <stdint.h>",
        "enum limits { MAX_LEN = 64 };",
        "const size_t MIN_LEN = 8;",
        "int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size) {",
        "  if (Size < MIN_LEN || Size > MAX_LEN) return 0;",
        "  return 0;",
        "}",
    ])
    c = harness.extract_from_text(body, source_file="Fuzz_x.c")
    assert (c["min_size"], c["max_size"]) == (8, 64)
    assert c["confidence"] == "exact"


def test_extract_partial_single_bound():
    body = "\n".join([
        "int LLVMFuzzerTestOneInput(const unsigned char *D, size_t Size) {",
        "  if (Size < 4) return 0;",
        "  return 0;",
        "}",
    ])
    c = harness.extract_from_text(body, source_file="Fuzz_y.c")
    assert c["min_size"] == 4 and c["max_size"] is None
    assert c["confidence"] == "partial"
    assert harness.check(c, 3)["ok"] is False
    assert harness.check(c, 4)["ok"] is True


def test_unknown_contract_allows_everything():
    c = harness.extract_from_text("int main(void){return 0;}", source_file="x.c")
    assert c["confidence"] == "unknown"
    assert (c["min_size"], c["max_size"]) == (None, None)
    for size in (0, 1, 10, 10**6):
        v = harness.check(c, size)
        assert v["ok"] is True and v["reason"] == "contract_unknown"
    assert "confidence: unknown" in harness.describe(c)
    assert "MUST" not in harness.describe(c)


def test_check_rejects_out_of_window_with_interval_in_reason():
    c = harness.extract_from_text(DEFINE_HARNESS, source_file="Fuzz_chpw.c")
    for size, which in ((0, "below_min"), (1, "below_min"), (19, "below_min"),
                        (101, "above_max"), (5000, "above_max")):
        v = harness.check(c, size)
        assert v["ok"] is False
        assert "20..100" in v["reason"] and which in v["reason"]
        assert v["window"] == "20..100"
    for size in (20, 59, 100):
        assert harness.check(c, size)["ok"] is True


def test_describe_states_allowed_interval():
    c = harness.extract_from_text(DEFINE_HARNESS, source_file="krb5/fuzzing/Fuzz_chpw.c")
    text = harness.describe(c)
    assert "HARNESS INPUT CONTRACT" in text
    assert "20..100" in text and "Fuzz_chpw.c" in text
    assert "MUST be within 20..100" in text
    assert "rejected BEFORE execution" in text


def test_extract_picks_hinted_harness(tmp_path):
    src = tmp_path / "src"
    _write(src / "fuzzing" / "Fuzz_json.c", DEFINE_HARNESS.replace("20", "10"))
    _write(src / "fuzzing" / "Fuzz_chpw.c",
           DEFINE_HARNESS.replace("kMinInputLength 20", "kMinInputLength 20")
           + "\n/* calls krb5_chpw_message */\n")
    c = harness.extract(src, hints=["krb5_chpw_message"])
    assert c["source_file"].endswith("Fuzz_chpw.c")
    assert (c["min_size"], c["max_size"]) == (20, 100)


@pytest.mark.skipif(not CG09_SRC.is_dir(), reason="CG-09 源码树不在本机")
def test_real_cg09_contract_from_source():
    """真实 krb5 树：必须靠 hint 选中 Fuzz_chpw.c（20..100），不是别的 fuzzer。"""
    c = harness.extract(CG09_SRC, hints=["krb5_chpw_message", "Fuzz_chpw"])
    assert c["source_file"].endswith("Fuzz_chpw.c"), c["source_file"]
    assert (c["min_size"], c["max_size"]) == (20, 100)
    assert c["confidence"] == "exact"
    assert harness.check(c, 1)["ok"] is False


class _Store:
    def __init__(self):
        self.attempts = []
        self.notes = []

    def add_blackboard(self, *a, **kw):
        self.notes.append((a, kw))

    def record_attempt(self, *a, **kw):
        self.attempts.append((a, kw))


def _fake_stage(tmp_path):
    from agent.stages.verify import VerifyStage
    from agent.paths import ensure_layout

    st = object.__new__(VerifyStage)
    st.ws = tmp_path
    st.layout = ensure_layout(tmp_path)
    st.run_id = "test-run"
    st.store = _Store()
    st._current_claim = {"subject": "krb5_chpw_message", "claim_id": "llm-1"}
    st._locate_data = {"claims_llm": [{"subject": "krb5_chpw_message"}]}
    st._detected_format = "unknown"
    return st


def test_verify_injects_contract_and_rejects_before_execution(tmp_path, monkeypatch):
    """窗口外候选必须在执行前被拒绝：_execute_generated 一次都不能被调到。"""
    from agent import llm as llm_mod
    from agent.stages import verify as verify_mod

    _write(tmp_path / "src" / "fuzzing" / "Fuzz_chpw.c", DEFINE_HARNESS)
    _write(tmp_path / "task.json", json.dumps({"binary": "/out/Fuzz_chpw"}))
    st = _fake_stage(tmp_path)
    st._loop_context = lambda claim: "--- source evidence ---"
    st._llm_config = lambda: llm_mod.LlmConfig()

    def _boom(*a, **kw):
        raise AssertionError("out-of-window candidate must not be executed")

    st._execute_generated = _boom

    captured = {}

    def fake_loop(**kw):
        captured.update(kw)
        return {"rounds": [], "distinct_inputs": 0, "succeeded": False}

    monkeypatch.setattr(verify_mod, "run_diverse_loop", fake_loop)
    result = st._model_loop({"vul": "img", "fix": "img"})

    # 1) 契约被解析并注入 prompt context
    assert captured["context"].count("HARNESS INPUT CONTRACT") == 1
    assert "20..100" in captured["context"]
    # 2) 窗口外输入：执行前拒绝，反馈里写明允许区间
    rej = captured["execute"](b"\x00")
    assert rej["verdict"] == "rejected_by_contract"
    assert rej["rejected_by_contract"] is True
    assert rej["vul_exit"] is None
    assert "20..100" in rej["feedback"]
    assert "REJECTED_BY_CONTRACT" in rej["feedback"]
    # 3) 契约写进 loop 结果，供 RESULT/报告引用
    assert result["harness_contract"]["min_size"] == 20
    assert result["harness_contract"]["max_size"] == 100


def test_verify_passes_in_window_candidate_to_executor(tmp_path, monkeypatch):
    from agent import llm as llm_mod
    from agent.stages import verify as verify_mod

    _write(tmp_path / "src" / "fuzzing" / "Fuzz_chpw.c", DEFINE_HARNESS)
    _write(tmp_path / "task.json", json.dumps({"binary": "/out/Fuzz_chpw"}))
    st = _fake_stage(tmp_path)
    st._loop_context = lambda claim: "ctx"
    st._llm_config = lambda: llm_mod.LlmConfig()
    calls = []

    def _record(data, image, claim):
        calls.append(len(data))
        return {"verdict": "not_triggered", "vul_exit": 0, "feedback": "no_defect"}

    st._execute_generated = _record
    captured = {}

    def fake_loop(**kw):
        captured.update(kw)
        return {"rounds": [], "distinct_inputs": 0, "succeeded": False}

    monkeypatch.setattr(verify_mod, "run_diverse_loop", fake_loop)
    st._model_loop({"vul": "img", "fix": "img"})
    out = captured["execute"](b"A" * 40)
    assert calls == [40] and out["verdict"] == "not_triggered"
    assert out["in_harness_window"] is True


def test_verify_unknown_contract_does_not_block(tmp_path, monkeypatch):
    from agent import llm as llm_mod
    from agent.stages import verify as verify_mod

    _write(tmp_path / "src" / "plain.c", "int main(void){return 0;}")
    _write(tmp_path / "task.json", json.dumps({"binary": "/out/plain"}))
    st = _fake_stage(tmp_path)
    st._loop_context = lambda claim: "ctx"
    st._llm_config = lambda: llm_mod.LlmConfig()
    calls = []

    def _record(data, image, claim):
        calls.append(len(data))
        return {"verdict": "not_triggered", "vul_exit": 0, "feedback": "no_defect"}

    st._execute_generated = _record
    captured = {}

    def fake_loop(**kw):
        captured.update(kw)
        return {"rounds": [], "succeeded": False}

    monkeypatch.setattr(verify_mod, "run_diverse_loop", fake_loop)
    result = st._model_loop({"vul": "i", "fix": "i"})
    assert result["harness_contract"]["confidence"] == "unknown"
    assert captured["execute"](b"\x00")["verdict"] == "not_triggered"
    assert calls == [1]


def test_emit_reports_contract_and_rejections(tmp_path):
    """verify 落盘必须带 harness_contract 与 rejected_by_contract，便于复核。"""
    st = _fake_stage(tmp_path)
    payloads = {}

    def _capture(logical, obj, schema="", guards=None):
        payloads[logical] = obj
        return {"uri": logical}

    st.emit = _capture
    st.input_hashes = lambda: {}
    loop_result = {
        "rounds": [
            {"round": 1, "size": 59, "sha256": "a" * 64, "verdict": "not_triggered"},
            {"round": 2, "size": 1, "sha256": "b" * 64, "verdict": "rejected_by_contract"},
        ],
        "harness_contract": {"source_file": "Fuzz_chpw.c", "min_size": 20,
                             "max_size": 100, "channel": "fuzzer_data_arg",
                             "confidence": "exact", "conditions": []},
        "rejected_by_contract": 1,
        "rejected_by_contract_rounds": [2],
    }
    st._emit_loop_only(loop_result)
    payload = payloads["verify/result.json"]
    assert payload["verdict"] == "generated_but_unverified"
    assert payload["harness_contract"]["min_size"] == 20
    assert payload["harness_contract"]["max_size"] == 100
    assert payload["rejected_by_contract"] == 1
    assert payload["rejected_by_contract_rounds"] == [2]


def test_rounds_annotated_with_window(tmp_path, monkeypatch):
    """每轮记录要能看出是否落在窗口内（审计口径，不靠推断）。"""
    from agent import llm as llm_mod
    from agent.stages import verify as verify_mod

    _write(tmp_path / "src" / "fuzzing" / "Fuzz_chpw.c", DEFINE_HARNESS)
    _write(tmp_path / "task.json", json.dumps({"binary": "/out/Fuzz_chpw"}))
    st = _fake_stage(tmp_path)
    st._loop_context = lambda claim: "ctx"
    st._llm_config = lambda: llm_mod.LlmConfig()
    st._execute_generated = lambda *a, **kw: {"verdict": "not_triggered"}

    def fake_loop(**kw):
        return {"rounds": [
            {"round": 1, "size": 59, "sha256": "a" * 64, "verdict": "not_triggered"},
            {"round": 2, "size": 1, "sha256": "b" * 64, "verdict": "rejected_by_contract"},
            {"round": 3, "size": 0, "sha256": "", "verdict": "invalid_model_output"},
        ], "succeeded": False}

    monkeypatch.setattr(verify_mod, "run_diverse_loop", fake_loop)
    result = st._model_loop({"vul": "i", "fix": "i"})
    r1, r2, r3 = result["rounds"]
    assert r1["in_harness_window"] is True and r1["harness_window"] == "20..100"
    assert r2["in_harness_window"] is False
    assert "in_harness_window" not in r3          # 没产出输入，不做窗口判定
    assert result["rejected_by_contract"] == 1
    assert result["rejected_by_contract_rounds"] == [2]

