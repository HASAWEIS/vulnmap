r"""CG-12（arvo:11081 / harfbuzz）构造器与端到端验证。

验收点：
1. 构造器产出确定性 sfnt（只有 GSUB 表），内联触发表自检 sha256；
2. 表目录偏移/长度自洽，GSUB 数据等于解压后的 838B 触发串；
3. 端到端：vul 镜像在 OT::Script::subset 的 langSys 写入处 ASAN heap-buffer-overflow，
   fix 镜像干净退出。
"""
import hashlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILDER_PATH = ROOT / "agent" / "builders" / "harfbuzz.py"
VUL_IMG = "n132/arvo:11081-vul"
FIX_IMG = "n132/arvo:11081-fix"


def _load_builder():
    spec = importlib.util.spec_from_file_location("hb_builder", BUILDER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hb_builder"] = mod
    spec.loader.exec_module(mod)
    return mod


hb = _load_builder()


def test_sfnt_header_and_table_directory():
    import struct
    data = hb.proof_of_concept()
    assert len(data) == 868
    version, num_tables = struct.unpack(">IH", data[:6])
    assert version == 0x00010000
    assert num_tables == 1
    tag = data[12:16]
    checksum, offset, length = struct.unpack(">III", data[16:28])
    assert tag == b"GSUB"
    assert offset == 28
    assert length == 838
    assert len(data) >= offset + length


def test_gsub_payload_matches_inline_trigger():
    data = hb.proof_of_concept()
    trigger = hb.gsub_trigger()
    assert len(trigger) == 838
    assert hashlib.sha256(trigger).hexdigest() == hb.GSUB_TRIGGER_SHA256
    assert data[28:28 + 838] == trigger
    # Script 记录存在（ScriptList offset 0x3a，DFLT/记录 + 空 langSys 数组）
    assert data[28:32] == b"\x00\x01\x00\x01"


def test_proof_of_concept_is_deterministic():
    a = hb.proof_of_concept()
    b = hb.proof_of_concept()
    assert a == b
    assert hashlib.sha256(a).hexdigest() == (
        "3df6625bba74f3efdbd164f5abbbea9b17871ff7a15f10463c3cf6e110c134ac")


def test_build_rejects_non_gsub_and_bad_pad():
    assert hb.build({"tag": "GPOS"}).ok is False
    assert hb.build({"tag": "GSU"}).ok is False
    assert hb.build({"pad_to": 10}).ok is False        # 小于当前长度
    r = hb.build({"pad_to": 1024, "unknown": 1})
    assert r.ok and len(r.data) == 1024
    assert r.dropped and r.dropped[0]["field"] == "unknown"


def test_build_accepts_override_table():
    import base64, zlib
    tiny = b"\x00\x01\x00\x00\x00\x00"
    r = hb.build({"gsub_b64": base64.b64encode(zlib.compress(tiny)).decode()})
    assert r.ok
    assert r.data[28:28 + len(tiny)] == tiny


def _docker_ready():
    if shutil.which("docker") is None:
        return False
    for img in (VUL_IMG, FIX_IMG):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


def _run(image, poc_path, attempts=1):
    out = []
    for _ in range(attempts):
        p = subprocess.run(
            ["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc_path, image, "/bin/arvo"],
            capture_output=True, text=True, timeout=300)
        out.append((p.returncode, p.stdout + p.stderr))
    return out


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo 11081 vul/fix 镜像")
def test_e2e_vuln_overflows_in_script_subset_and_fix_is_clean(tmp_path):
    poc = tmp_path / "poc.ttf"
    poc.write_bytes(hb.proof_of_concept())

    vul = _run(VUL_IMG, poc, attempts=2)
    hits = [(rc, txt) for rc, txt in vul
            if "AddressSanitizer" in txt and "heap-buffer-overflow" in txt]
    assert hits, "vul 侧没有 heap-buffer-overflow: %s" % [rc for rc, _ in vul]
    rc, txt = hits[0]
    assert rc != 0
    assert "Script::subset" in txt or "hb-ot-layout-common.hh:289" in txt

    fix = _run(FIX_IMG, poc, attempts=2)
    assert all(rc == 0 for rc, _ in fix), "fix 侧不应崩溃: %s" % [rc for rc, _ in fix]
    assert not any("AddressSanitizer" in txt for _rc, txt in fix)


# ---- 接线（s5h-harfbuzzb）：registry + verify 分支 + 文本级根因兜底 ----

def test_harfbuzz_registered_in_builders_registry():
    import agent.builders as builders
    assert "harfbuzz" in builders.BUILDERS
    assert "harfbuzz" in builders.FIELD_SPECS
    r = builders.build("harfbuzz", {})
    assert r.ok and len(r.data) == 868
    # 老注册表仍然完整（包重导出没丢东西）
    assert builders.build("mng", {"loop_len": 4}).ok
    assert builders.build("nope", {}).ok is False


def test_verify_harfbuzz_sink_is_located(tmp_path):
    import types
    src = tmp_path / "src" / "hb-ot-layout-common.hh"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join([
        "struct Script {",
        "  inline bool subset (hb_subset_context_t *c) const {",
        "    struct Script *out = c->serializer->embed (*this);",
        "    out->langSys.arrayZ[i].offset.serialize_subset (c, this+langSys[i].offset, out);",
        "  }",
        "};",
    ]), encoding="utf-8")
    from agent.stages.verify import VerifyStage
    fake = types.SimpleNamespace(layout={"src": tmp_path / "src"}, name="verify",
                                 MSAN_MARKERS=VerifyStage.MSAN_MARKERS)
    sink = VerifyStage._harfbuzz_sink(fake)
    assert sink["file"].endswith("hb-ot-layout-common.hh")
    assert sink["line"] == 4


def test_text_sink_hit_reads_raw_trace(tmp_path):
    import types
    from agent.stages.verify import VerifyStage
    ws = tmp_path / "ws"
    logs = ws / "logs"
    logs.mkdir(parents=True)
    (logs / "V4.x.11081-vul.log").write_text(
        "  #1 0x560b22 in OT::Script::subset(...) /src/harfbuzz/src/./hb-ot-layout-common.hh:289:37\n",
        encoding="utf-8")
    fake = types.SimpleNamespace(ws=ws)
    hit = VerifyStage._text_sink_hit(
        fake, {"file": "hb-ot-layout-common.hh", "line": 289}, "logs/V4.x.11081-vul.log")
    assert hit and hit["line"] == 289 and hit["delta"] == 0
    # 行号超出容差不认
    assert VerifyStage._text_sink_hit(
        fake, {"file": "hb-ot-layout-common.hh", "line": 400}, "logs/V4.x.11081-vul.log") is None

