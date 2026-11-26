r"""CG-18（arvo:12420 / libidn2）构造器与 verify 接线测试。

验收点：
1. 默认产物是 65 字符域名的 UCS-4 小端字节串（260B），字节可逐位核对；
2. 两个 label 是必要条件：单 label 65 字符会被构造器/库拒掉，打不到缺陷；
3. 字段校验（left/right 上限 63、labels 范围、未知字段）；
4. 注册表可用，且 verify 的 claim/sink 指向 lib/lookup.c:621。
"""
import importlib.util
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location("libidn2_builder",
                                                  ROOT / "agent" / "builders" / "libidn2.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["libidn2_builder"] = mod
    spec.loader.exec_module(mod)
    return mod


idn2 = _load()


def test_default_is_65_char_ucs4_domain():
    r = idn2.build({})
    assert r.ok
    assert r.size == 260                     # 65 字符 × 4 字节
    assert r.fields_used["domain_chars"] == 65
    domain = "a" * 32 + "." + "b" * 32
    expected = b"".join(struct.pack("<I", ord(ch)) for ch in domain)
    assert r.data == expected


def test_single_label_is_rejected_or_warned():
    # 单 label 65 字符：构造器直接拒绝（>63 会被 libidn2 自己挡掉）
    assert idn2.build({"labels": 1, "left": 65}).ok is False
    # 单 label 32 字符：能构造，但明确提示打不到缺陷
    r = idn2.build({"labels": 1, "left": 32})
    assert r.ok
    assert "warning" in r.fields_used
    assert r.fields_used["domain_chars"] == 32


def test_two_labels_are_required_for_the_overflow():
    one = idn2.build({"labels": 1, "left": 32, "right": 32})
    two = idn2.build({"labels": 2, "left": 32, "right": 32})
    assert one.fields_used["domain_chars"] == 32
    assert two.fields_used["domain_chars"] == 65
    assert len(two.data) - len(one.data) == 33 * 4      # '.' + 32 字符


def test_ascii66_single_label_does_not_overflow():
    # 记一笔历史坑：单标签 66 字符被 libidn2 拒绝，反而不崩
    r = idn2.build({"labels": 1, "left": 66})
    assert r.ok is False


def test_field_bounds_and_unknown_fields():
    assert idn2.build({"left": 64}).ok is False
    assert idn2.build({"right": -1}).ok is False
    assert idn2.build({"labels": 99}).ok is False
    assert idn2.build({"left": "x"}).ok is False
    r = idn2.build({"unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"


def test_registered_and_claim_points_at_lookup_621():
    import agent.builders as builders
    assert "libidn2" in builders.BUILDERS
    via = builders.build("libidn2", {})
    assert via.ok and via.size == 260
    claim = idn2.declared_claim()
    assert claim["subject"] == "idn2_to_ascii_4i"
    assert claim["cwe"] == "CWE-122"
    assert claim["sink"]["file"].endswith("lib/lookup.c")
    assert claim["sink"]["line"] == 621

    from agent.stages.verify import VerifyStage

    class _Fake(VerifyStage):
        def __init__(self):
            self.ws = ROOT / "workspace" / "S7-CG18-arvo-12420"
            self.name = "verify"
            self.layout = {"src": self.ws / "src"}

    got = VerifyStage._libidn2_claim(_Fake())
    assert got["sink"]["line"] == 621
    assert got["proposed_by"] == "builder"
    assert got["test_plan"]["format"] == "libidn2"
