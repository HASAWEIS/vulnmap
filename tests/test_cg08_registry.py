r"""CG-08 构造器接入 registry（S5E-CG08b）。

验收点：
1. agent.builders 现在是包，但 agent/builders.py 的原注册表行为原样保留
   （build / BUILDERS / FIELD_SPECS / supported_formats / describe / BuildResult）；
2. jnx 构造器已注册进**同一份**注册表，build("jnx", ...) 产出 278B 的 PoC；
3. verify 侧认 MSan 报告（diagnostics 模块不覆盖它），并能机械定位 CG-08 的 sink
   （ExtractTileJPG 里的 BlobToImage 调用点），不依赖模型或崩溃栈。
"""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent.builders as builders
from agent.diagnostics import parse_diagnosis
from agent.stages.verify import VerifyStage

ROOT = Path(__file__).resolve().parent.parent
CG08_SRC = ROOT / "workspace" / "S5E-CG08" / "src"

MSAN_TEXT = """==6==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0xa02d6a in funcDCM_PhotometricInterpretation /src/graphicsmagick/coders/dcm.c:3051:7
    #1 0x9edc19 in ReadDCMImage /src/graphicsmagick/coders/dcm.c:4805:16
    #4 0xc9d729 in ExtractTileJPG /src/graphicsmagick/coders/jnx.c:128:29
SUMMARY: MemorySanitizer: use-of-uninitialized-value
"""


def test_package_reexports_legacy_registry():
    assert builders.__file__.endswith("__init__.py")
    # 老格式仍在，且行为不变
    assert "mng" in builders.BUILDERS and "pdf" in builders.BUILDERS
    assert builders.build("mng", {"loop_len": 4}).ok
    assert builders.build("nope", {}).ok is False
    assert "unsupported_format" in builders.build("nope", {}).reason
    assert builders.supported_formats() == sorted(builders.BUILDERS)
    assert isinstance(builders.describe(b"1234"), dict)


def test_jnx_registered_in_same_registry():
    assert "jnx" in builders.BUILDERS
    assert "jnx" in builders.FIELD_SPECS
    r = builders.build("jnx", {"payload": "dicom"})
    assert r.ok and r.format == "jnx" and len(r.data) == 278


def test_jnx_build_matches_cg08_builder_module():
    from agent.builders import cg08
    direct = cg08.build({"payload": "dicom"})
    via_registry = builders.build("jnx", {"payload": "dicom"})
    assert direct.data == via_registry.data
    assert direct.data == cg08.proof_of_concept()


def test_jnx_magic_lands_on_blob_offset_128_via_registry():
    data = builders.build("jnx", {}).data
    import struct
    _, _, _, _, _, _, pic_size, pic_offset = struct.unpack_from("<iiiiHHII", data, 60)
    payload = data[pic_offset:pic_offset + pic_size]
    assert (b"\xff\xd8" + payload)[128:132] == b"DICM"


def test_jnx_rejects_bad_fields_through_registry():
    assert builders.build("jnx", {"payload": "bogus"}).ok is False
    assert builders.build("jnx", {"width": 70000}).ok is False


def _fake_stage():
    return types.SimpleNamespace(MSAN_MARKERS=VerifyStage.MSAN_MARKERS,
                                 name="verify",
                                 layout={"src": CG08_SRC})


def test_msan_report_is_recognised_as_defect():
    diag = parse_diagnosis(MSAN_TEXT)
    assert diag.is_defect is False                 # diagnostics 本身不认 MSan
    aug = VerifyStage._augment_sanitizer(_fake_stage(), diag, MSAN_TEXT)
    assert aug.is_defect is True
    assert aug.sanitizer == "MemorySanitizer"
    assert aug.kind == "use-of-uninitialized-value"
    assert aug.user_frames and aug.user_frames[0].file.endswith("dcm.c")


def test_augment_keeps_existing_asan_diagnosis_untouched():
    text = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1"
    diag = parse_diagnosis(text)
    aug = VerifyStage._augment_sanitizer(_fake_stage(), diag, text)
    assert aug.kind == "heap-buffer-overflow"
    assert aug.sanitizer == "AddressSanitizer"


@pytest.mark.skipif(not CG08_SRC.is_dir(), reason="需要 workspace/S5E-CG08/src")
def test_jnx_sink_is_located_mechanically():
    sink = VerifyStage._jnx_sink(_fake_stage())
    assert sink["file"].endswith("coders/jnx.c")
    assert sink["symbol"] == "BlobToImage"
    lines = (CG08_SRC / "graphicsmagick/coders/jnx.c").read_text(
        errors="ignore").splitlines()
    assert "BlobToImage(" in lines[sink["line"] - 1]


@pytest.mark.skipif(not CG08_SRC.is_dir(), reason="需要 workspace/S5E-CG08/src")
def test_jnx_sink_line_matches_crash_frame_within_slack():
    sink = VerifyStage._jnx_sink(_fake_stage())
    crash_line = 128                                 # vul 镜像里的栈帧行号
    assert abs(sink["line"] - crash_line) <= 8       # 构建期行号漂移容差
