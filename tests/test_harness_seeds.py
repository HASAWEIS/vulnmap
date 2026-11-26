r"""harness 种子提取（S5-c B2/B3）与「未进分支」反馈。

S4-b 之后 CG-09 已经拿到长度契约（20..100），但 3 轮候选结构不对、全都没进缺陷分支。
这里的验收点：
1. 能从 krb5 单元测试的 krb5_data 初始化里还原真实字节（\0 / \xNN / 八进制）；
2. 与目标无关的 krb5_data（pkinit / pac / ccache 业务结构）不得冒充种子；
3. 长度不在 harness 窗口内的种子：过短补齐、过长丢弃，且不伪装成"原样"；
4. 种子块必须给 hex + 结构注释 + 「改结构不改长度」的硬要求；
5. 候选执行后无崩溃时，下一轮提示必须是「改结构」而不是只回 no_defect_diagnosis。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import harness, llm
from agent.stages.verify import run_diverse_loop

REPO = Path(__file__).resolve().parent.parent
CG09_SRC = REPO / "workspace" / "CG-09-arvo-53666" / "src"

CHPW_TEST = r'''
#include "krb5.h"

static krb5_data result_utf8 = {
    0, 23, "This is a valid string.",
};

static krb5_data result_invalid_utf8 = {
    0, 19, "\0This is not valid.",
};

static krb5_data result_ad_complex = {
    0, 30,
    "\0\0"             /* zero bytes */
    "\0\0\0\0"         /* min length */
    "\0\0\0\0"         /* history */
    "\0\0\0\1"         /* properties, complex */
    "\0\0\0\0\0\0\0\0" /* expire */
    "\0\0\0\0\0\0\0\0" /* min age */
};
'''


def _write(tmp_path, rel, text):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_c_escapes_decode_to_bytes():
    assert harness.unescape_c_string(r"\0") == b"\x00"
    assert harness.unescape_c_string(r"\x0d") == b"\x0d"
    assert harness.unescape_c_string(r"\101") == b"A"
    assert harness.unescape_c_string(r"a\\b\"c") == b'a\\b"c'
    # 相邻字面量的隐式拼接
    assert harness.literal_bytes(r'"\0\0" "\0\x01"') == b"\x00\x00\x00\x01"


def test_seeds_from_c_text_respects_declared_length():
    items = harness.seeds_from_c_text(CHPW_TEST, source="t.c")
    by_name = {i["name"]: i for i in items}
    assert by_name["result_utf8"]["data"] == b"This is a valid string."
    assert by_name["result_invalid_utf8"]["data"] == b"\x00This is not valid."
    ad = by_name["result_ad_complex"]["data"]
    assert len(ad) == 30
    assert ad[:2] == b"\x00\x00"
    assert ad[10:14] == b"\x00\x00\x00\x01"      # properties
    # 解析阶段保留字面量原样 + 声明长度；截断由 seeds() 按声明长度执行
    truncated = harness.seeds_from_c_text(
        'static krb5_data x = {0, 3, "abcdef"};', source="t.c")
    assert truncated[0]["declared"] == 3
    assert truncated[0]["data"] == b"abcdef"


def test_seeds_truncates_to_declared_length(tmp_path):
    _write(tmp_path, "tests/vec.c",
           'static krb5_data x = {0, 3, "abcdef"};\n')
    seeds = harness.seeds(tmp_path, contract={"min_size": 3, "max_size": 100},
                          hints=["vec"])
    assert seeds[0]["size"] == 3
    assert bytes.fromhex(seeds[0]["bytes_hex"]) == b"abc"


def test_annotate_names_the_ad_policy_fields():
    data = b"\x00\x00" + b"\x00" * 28
    note = harness.annotate(data)
    assert note.startswith("AD password-policy struct")
    for field in ("zero_bytes", "min_length", "history", "properties",
                  "expire", "min_age"):
        assert field in note
    assert "NUL" in harness.annotate(b"\x00abc")
    assert "ASCII" in harness.annotate(b"abc")


def test_window_pads_short_and_drops_long():
    contract = {"min_size": 20, "max_size": 100, "confidence": "exact"}
    short, padded, why = harness._fit_window(b"\x00short", contract)
    assert len(short) == 20 and padded is True and why == ""
    long_data = b"A" * 101
    out, _padded, why = harness._fit_window(long_data, contract)
    assert out is None and why == "above_max_100"


def test_seeds_filters_unrelated_initializers(tmp_path):
    _write(tmp_path, "src/tests/misc/test_chpw_message.c", CHPW_TEST)
    # 业务代码里的 krb5_data：既不在 test 路径，也没提到 hint，不得冒充种子
    _write(tmp_path, "src/lib/krb5/pkinit_lib.c",
           'static krb5_data dh_oid = {0, 9, "\\x2a\\x86\\x48"};')
    contract = {"min_size": 20, "max_size": 100, "confidence": "exact"}
    seeds = harness.seeds(tmp_path, contract=contract, hints=["krb5_chpw_message"])
    names = [s["name"] for s in seeds]
    assert "dh_oid" not in names
    assert "result_ad_complex" in names
    assert seeds[0]["size"] >= 20
    assert all(20 <= s["size"] <= 100 for s in seeds)
    for s in seeds:
        assert len(s["sha256"]) == 64
        assert bytes.fromhex(s["bytes_hex"]).__len__() == s["size"]


def test_seeds_dedups_and_caps_at_eight(tmp_path):
    body = "".join('static krb5_data v%d = {0, 4, "AAAA"};\n' % i for i in range(12))
    _write(tmp_path, "tests/vec.c", body)
    seeds = harness.seeds(tmp_path, contract={"min_size": 4, "max_size": 100},
                          hints=["vec"])
    assert len(seeds) == 1          # 12 条同字节 -> 去重成 1


def test_seeds_limit_is_honoured(tmp_path):
    body = "".join('static krb5_data v%d = {0, 4, "%04d"};\n' % (i, i)
                   for i in range(12))
    _write(tmp_path, "tests/vec.c", body)
    seeds = harness.seeds(tmp_path, contract={"min_size": 4, "max_size": 100},
                          hints=["vec"], limit=8)
    assert len(seeds) == 8


def test_seed_prompt_has_hex_structure_and_structure_rule(tmp_path):
    _write(tmp_path, "tests/test_chpw_message.c", CHPW_TEST)
    contract = {"min_size": 20, "max_size": 100, "confidence": "exact"}
    seeds = harness.seeds(tmp_path, contract=contract, hints=["krb5_chpw_message"])
    text = harness.seed_prompt(seeds, contract, max_show=3)
    # 30B 的 AD 策略向量优先展示，且必须带 hex 与字段注释
    assert "result_ad_complex" in text
    assert "AD password-policy struct" in text
    assert "hex: 000000000000000000000000000100000000000000000000000000000000" in text
    assert "20..100" in text
    assert "MUTATE A SEED'S STRUCTURE" in text
    assert "instead of only changing the total length" in text
    # 最多展示 3 条
    assert text.count("seed ") - text.count("HOW TO USE") <= 3


def test_seed_prompt_empty_seed_list_is_honest():
    text = harness.seed_prompt([], {"min_size": 20, "max_size": 100})
    assert "No repository seed" in text
    assert "20..100" in text


class FakeLlm:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def __call__(self, *, system, user, prompt_version):
        self.prompts.append(user)
        n = len(self.prompts) - 1
        return llm.LlmResult(status="ok",
                             content=self.responses[min(n, len(self.responses) - 1)],
                             model="m", prompt_version=prompt_version, tokens=5,
                             finish_reason="stop")


def _text_case(size, ch="A"):
    return json.dumps({"encoding": "text", "content": ch * size, "rationale": "r"})


def test_no_crash_feedback_tells_model_to_change_structure():
    fake = FakeLlm([_text_case(30), _text_case(30, "B")])

    def execute(data):
        return {"vul_exit": 0, "fix_exit": None, "verdict": "not_triggered",
                "feedback": "vul_exit=0 fix_exit=None | reason=no_defect_diagnosis"}

    seeds = [{"name": "result_ad_complex", "size": 30, "sha256": "a" * 64,
              "source": "t.c", "structure": harness.AD_POLICY_30}]
    seed_block = harness.seed_prompt(seeds, {"min_size": 20, "max_size": 100})
    result = run_diverse_loop(
        claim={"subject": "krb5_chpw_message"}, context="ctx", fmt="unknown",
        execute=execute, call_llm=fake, max_rounds=2, seed_block=seed_block,
        seeds=seeds, contract={"min_size": 20, "max_size": 100})
    # 种子块进了第一次提示
    assert "SEED CORPUS" in fake.prompts[0]
    assert "result_ad_complex" in fake.prompts[0]
    # 第 1 轮无崩溃 -> 第 2 轮提示必须要求「改结构」，而不是只重复历史
    assert "NO_CRASH_NEXT_ACTION" in fake.prompts[1]
    assert "改结构而非改长度" in fake.prompts[1]
    assert "20..100" in fake.prompts[1]
    # 汇总里落种子来源，可审计
    assert result["seed_count"] == 1
    assert result["seeds_used"][0]["name"] == "result_ad_complex"
    assert any(r.get("next_action") == "change_structure" for r in result["rounds"])


def test_pass_round_does_not_emit_structure_directive():
    fake = FakeLlm([_text_case(30)])

    def execute(data):
        return {"vul_exit": 1, "fix_exit": 0, "verdict": "pass",
                "feedback": "vul_exit=1 fix_exit=0 | ASAN"}

    result = run_diverse_loop(
        claim={"subject": "krb5_chpw_message"}, context="ctx", fmt="unknown",
        execute=execute, call_llm=fake, max_rounds=3, seed_block="SEED",
        seeds=[], contract={})
    assert result["succeeded"] is True
    assert len(fake.prompts) == 1
    assert not any(r.get("next_action") for r in result["rounds"])


def test_real_krb5_tree_yields_chpw_policy_seeds():
    if not CG09_SRC.is_dir():
        return
    contract = harness.extract(CG09_SRC, hints=["krb5_chpw_message", "Fuzz_chpw"])
    assert contract["min_size"] == 20 and contract["max_size"] == 100
    seeds = harness.seeds(CG09_SRC, contract=contract,
                          hints=["krb5_chpw_message", "Fuzz_chpw"])
    names = {s["name"] for s in seeds}
    assert "result_ad_all" in names
    assert "result_ad_complex" in names
    assert len(seeds) <= 8
    assert all(20 <= s["size"] <= 100 for s in seeds)
    ad = next(s for s in seeds if s["name"] == "result_ad_all")
    assert ad["size"] == 30
    assert ad["structure"].startswith("AD password-policy")
    assert "tests/misc/test_chpw_message.c" in ad["source"]
