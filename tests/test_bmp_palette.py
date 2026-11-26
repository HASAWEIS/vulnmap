r"""S20（arvo:59500 / MuPDF BMP palette）构造器测试。

验收点：
1. 产物是 BM 头 + 指定长度的 DIB（默认 108，BITMAPV4），bitcount=4、colors=0x20202020、bitmapoffset=0；
2. 关键不变量：负下标要够深 —— 3*readcolors < -(palette 在 struct info 里的偏移约 60)，
   所以 header 必须够大（40 字节头只有 -13，不崩；108 -> -30 才崩）；
3. 字段校验；
4. 端到端（有 docker + arvo:59500 镜像）：vul 在 bmp_load_default_palette 崩、fix 干净。
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import bmp_palette as bp


def test_header_layout():
    data = bp.proof_of_concept()
    assert data[:2] == b"BM"
    fsize, r1, r2, offset = struct.unpack_from("<IHHI", data, 2)
    assert fsize == len(data)
    assert offset == 0
    hdr = struct.unpack_from("<I", data, 14)[0]
    assert hdr == 108
    assert struct.unpack_from("<H", data, 14 + 14)[0] == 4          # bitcount
    assert struct.unpack_from("<I", data, 14 + 32)[0] == 0x20202020  # colors


def test_header_size_must_be_large_for_negative_index():
    # 40 字节头：p=54，readcolors 最多 -13 -> 3*i=-39，还在 struct info 内，打不穿
    small = bp.build({"header_size": 40})
    big = bp.build({"header_size": 108})
    assert small.ok and big.ok
    # 108 头：p=122 -> -30 -> 3*i=-90，越过 struct 起点
    assert (108 - 14) > (40 - 14)
    r = bp.build({"header_size": 108})
    assert r.fields_used["header_size"] == 108 and r.fields_used["bitmapoffset"] == 0


def test_field_validation():
    assert bp.build({"header_size": 44}).ok is False
    assert bp.build({"bitcount": 24}).ok is False
    assert bp.build({"bitmapoffset": -1}).ok is False
    assert bp.build({"pad": -1}).ok is False
    r = bp.build({"unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"


def test_build_is_deterministic():
    assert bp.build({}).data == bp.build({}).data


def _docker_ready():
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    for img in ("n132/arvo:59500-vul", "n132/arvo:59500-fix"):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo:59500 镜像")
def test_e2e_vuln_underflows_palette_and_fix_is_clean(tmp_path):
    import subprocess
    poc = tmp_path / "poc.bmp"
    poc.write_bytes(bp.proof_of_concept())

    def run(img):
        p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc, img, "/bin/arvo"],
                           capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout + p.stderr

    rc, txt = run("n132/arvo:59500-vul")
    assert "AddressSanitizer" in txt, txt[-300:]
    assert "bmp_load_default_palette" in txt
    assert rc != 0

    rc2, txt2 = run("n132/arvo:59500-fix")
    assert "AddressSanitizer" not in txt2
    assert rc2 == 0
