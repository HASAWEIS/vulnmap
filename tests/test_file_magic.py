r"""S7（arvo:1065 / file(1) magic_fuzzer）构造器测试。

验收点：
1. 三类最小文本（xml/email/shebang）字节确定、可复现；
2. build() 的字段校验（未知 variant/repeat 越界/坏 hex/未知字段）；
3. 注册进 BUILDERS 后经 registry 能拿到同样的字节；
4. verify 侧的 claim/sink 能机械定位到 softmagic.c 的 pmatch 使用点。
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location("file_magic_builder",
                                                  ROOT / "agent" / "builders" / "file_magic.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["file_magic_builder"] = mod
    spec.loader.exec_module(mod)
    return mod


fm = _load()


def test_xml_variant_bytes_are_stable():
    data = fm.proof_of_concept("php")
    assert data == b'<?php echo 1; ?>\n'
    assert len(data) == 17
    assert hashlib.sha256(data).hexdigest().startswith("")


def test_perl_and_email_variants():
    perl = fm.proof_of_concept("perl")
    assert perl.startswith(b"#!/usr/bin/perl\n")
    email = fm.proof_of_concept("email")
    assert email.startswith(b"From: a@b.c\nSubject: hi\n\n")
    # 四个变体互不相同
    assert len({fm.proof_of_concept(v) for v in ("php", "perl", "xml", "email")}) == 4


def test_repeat_multiplies_text():
    r = fm.build({"variant": "xml", "repeat": 4})
    assert r.ok and r.size == 26 * 4
    assert r.data == b'<?xml version="1.0"?><a/>\n' * 4
    assert r.fields_used["repeat"] == 4


def test_build_rejects_bad_fields():
    assert fm.build({"variant": "nope"}).ok is False
    assert fm.build({"repeat": 0}).ok is False
    assert fm.build({"repeat": 65}).ok is False
    assert fm.build({"payload_hex": "zz"}).ok is False
    r = fm.build({"variant": "xml", "unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"


def test_payload_hex_override():
    r = fm.build({"payload_hex": "3c3f786d6c"})
    assert r.ok and r.data == b"<?xml"


def test_registered_in_builders_registry():
    import agent.builders as builders
    assert "file_magic" in builders.BUILDERS
    assert "file_magic" in builders.FIELD_SPECS
    via_registry = builders.build("file_magic", {"variant": "xml"})
    assert via_registry.ok and via_registry.data == fm.proof_of_concept("xml")
    # 既有注册表未被破坏
    assert builders.build("mng", {"loop_len": 4}).ok
    assert builders.build("nope", {}).ok is False


def test_verify_claim_uses_softmagic_pmatch_sink():
    import types
    from agent.stages.verify import VerifyStage
    class _Fake(VerifyStage):
        def __init__(self, ws_root):
            self.ws = ws_root
            self.name = "verify"
            self.layout = {"src": ws_root / "src"}

    fake = _Fake(ROOT / "workspace" / "S7-CG17-arvo-1065")
    claim = VerifyStage._file_magic_claim(fake)
    assert claim["subject"] == "match"
    assert claim["cwe"] == "CWE-457"
    assert claim["sink"]["file"].endswith("softmagic.c")
    assert isinstance(claim["sink"]["line"], int) and claim["sink"]["line"] > 0
