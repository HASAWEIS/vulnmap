r"""CG-08（arvo:10147 / GraphicsMagick JNX）构造器与端到端验证。

验收点：
1. JNX 二进制布局正确（48B 头 + 12B level + 28B tile + payload），字段偏移可解析；
2. tile payload 前面被 ExtractTileJPG 补 2 字节 JPEG SOI，所以 "DICM" 必须落在
   payload 偏移 126（= blob 偏移 128），否则 DCM 解码器根本不会被选中；
3. 端到端：vul 镜像里 JNX tile 被 DCM 解码器吃掉 → MSan use-of-uninitialized-value
   @ funcDCM_PhotometricInterpretation；fix 镜像强制 JPEG 解码器 → 不出现 MSan 报告。
"""
import hashlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILDER_PATH = ROOT / "agent" / "builders" / "cg08.py"

VUL_IMG = "n132/arvo:10147-vul"
FIX_IMG = "n132/arvo:10147-fix"


def _load_builder():
    spec = importlib.util.spec_from_file_location("cg08_builder", BUILDER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cg08_builder"] = mod
    spec.loader.exec_module(mod)
    return mod


cg08 = _load_builder()


def test_header_layout_is_48_bytes_with_levels_at_24():
    data = cg08.build({"payload": "dicom"}).data
    assert len(data) == 278
    import struct
    version = struct.unpack_from("<I", data, 0)[0]
    levels = struct.unpack_from("<I", data, 24)[0]
    assert version == 3
    assert levels == 1
    # level info 紧跟 48B 头：tile_count / tiles_offset / scale
    tile_count, tiles_offset, scale = struct.unpack_from("<3I", data, 48)
    assert tile_count == 1
    assert tiles_offset == 60
    assert scale == 38218


def test_tile_entry_points_at_payload():
    import struct
    data = cg08.build({"payload": "dicom"}).data
    (ne_lat, ne_lon, sw_lat, sw_lon, w, h, pic_size, pic_offset) = struct.unpack_from(
        "<iiiiHHII", data, 60)
    payload_start = 60 + 28
    assert (w, h) == (256, 256)
    assert pic_offset == payload_start
    assert pic_size == len(data) - payload_start
    assert ne_lat == 0x133DF6A9 and ne_lon == 0x000000C7
    assert sw_lat == 0x12CBA882 and sw_lon == 0x000080C6


def test_dicom_magic_lands_on_blob_offset_128():
    import struct
    data = cg08.build({"payload": "dicom"}).data
    _, _, _, _, _, _, pic_size, pic_offset = struct.unpack_from("<iiiiHHII", data, 60)
    payload = data[pic_offset:pic_offset + pic_size]
    # ExtractTileJPG 先写 blob[0..1]=FF D8，再把 payload 复制到 blob+2
    blob = b"\xff\xd8" + payload
    assert blob[128:132] == b"DICM"
    assert blob[12:16] != b"DICM"          # 只有 128 这个位置能命中 IsDCM


def test_dicom_dataset_contains_photometric_and_geometry_tags():
    ds = cg08.dicom_dataset()
    assert ds[0:4] == b"\x28\x00\x04\x00"          # (0028,0004)
    assert b"RGB\x00" in ds
    # (0028,0010) rows、(0028,0011) columns 都在
    assert b"\x28\x00\x10\x00" in ds
    assert b"\x28\x00\x11\x00" in ds


def test_proof_of_concept_is_deterministic():
    a = cg08.proof_of_concept()
    b = cg08.proof_of_concept()
    assert a == b
    assert hashlib.sha256(a).hexdigest() == (
        "1e15f16d7725a183323a62ba870f667de5e8b4c3f4905d3ca851e703280d18b6")
    assert len(a) == 278


def test_build_rejects_bad_fields():
    assert cg08.build({"payload": "bogus"}).ok is False
    assert cg08.build({"width": 70000}).ok is False
    assert cg08.build({"version": 9}).ok is False
    assert cg08.build({"pic_size": 999999}).ok is False     # 超出文件长度
    assert cg08.build({"pic_offset": -1}).ok is False


def test_build_accepts_raw_and_jpeg_payloads_and_drops_unknown_fields():
    raw = cg08.build({"payload": "raw", "tile_hex": "0011", "nonsense": 1})
    assert raw.ok
    assert raw.data.endswith(b"\x00\x11")
    assert raw.dropped and raw.dropped[0]["field"] == "nonsense"

    jpeg = cg08.build({"payload": "jpeg", "tile_hex": "ffd8ffe00010"})
    assert jpeg.ok
    payload = jpeg.data[88:]
    assert payload.startswith(b"\xff\xe0")       # SOI 被剥掉，交给 ExtractTileJPG 自己补


def test_pic_size_can_truncate_payload():
    full = cg08.build({"payload": "dicom"})
    trimmed = cg08.build({"payload": "dicom", "pic_size": 20})
    assert trimmed.ok
    assert trimmed.size == full.size                  # 容器长度不变
    assert trimmed.fields_used["pic_size"] == 20      # 只改 tile 表里的长度


def _docker_ready():
    if shutil.which("docker") is None:
        return False
    for img in (VUL_IMG, FIX_IMG):
        p = subprocess.run(["docker", "image", "inspect", img],
                           capture_output=True, text=True)
        if p.returncode != 0:
            return False
    return True


def _run_image(image, poc_path, attempts=1):
    out = []
    for _ in range(attempts):
        p = subprocess.run(
            ["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc_path, image, "/bin/arvo"],
            capture_output=True, text=True, timeout=300)
        out.append((p.returncode, p.stdout + p.stderr))
    return out


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo 10147 vul/fix 镜像")
def test_e2e_vuln_hits_dcm_uninit_and_fix_does_not(tmp_path):
    poc = tmp_path / "poc.jnx"
    poc.write_bytes(cg08.proof_of_concept())

    vul = _run_image(VUL_IMG, poc, attempts=3)
    hits = [(rc, txt) for rc, txt in vul
            if "MemorySanitizer" in txt and "funcDCM_PhotometricInterpretation" in txt]
    assert hits, "vul 侧没有命中 dcm.c 的未初始化读取: %s" % [rc for rc, _ in vul]
    rc, txt = hits[0]
    assert rc != 0
    assert "ReadDCMImage" in txt and "ExtractTileJPG" in txt

    fix = _run_image(FIX_IMG, poc, attempts=3)
    assert not any("MemorySanitizer" in txt for _rc, txt in fix), (
        "fix 侧不应再走 DCM 解码器: %s" % [rc for rc, _ in fix])
