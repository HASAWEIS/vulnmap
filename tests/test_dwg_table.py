r"""S19（arvo:54839 / libredwg pre-R13）构造器测试。

验收点：
1. 产物是 AC1009（R11）头，num_sections=0，5 个 section hdr 齐全；
2. 关键不变量：num_sections=0 时 calloc 只给 2 个槽位，而固定写 5 个 id（1..5）才越界；
3. 字段校验与未知字段记录；
4. 端到端（有 docker + arvo:54839 镜像）：vul 崩在 decode_preR13_section_hdr、fix 干净。
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import dwg_table as dt


def test_header_layout_and_magic():
    data = dt.proof_of_concept()
    assert data[:6] == b"AC1009"
    assert len(data) == 606
    assert struct.unpack_from("<H", data, 0x0F)[0] == 0        # num_sections
    assert struct.unpack_from("<H", data, 0x0D)[0] == 3        # unknown_3
    # 0x14 起 6 个 RL，随后 5 个 section hdr（每个 10 字节）
    assert len(data) >= 0x14 + 24 + 5 * 10


def test_num_sections_zero_is_the_trigger():
    r = dt.build({})
    assert r.ok
    assert r.fields_used["num_sections"] == 0
    assert r.fields_used["sections"] == 5
    # num_sections=2 时槽位够用，不该越界（构造器应支持对照参数）
    ok2 = dt.build({"num_sections": 5})
    assert ok2.ok and struct.unpack_from("<H", ok2.data, 0x0F)[0] == 5


def test_field_validation():
    assert dt.build({"num_sections": -1}).ok is False
    assert dt.build({"sections": 0}).ok is False
    assert dt.build({"num_sections": "x"}).ok is False
    r = dt.build({"unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"


def test_build_is_deterministic():
    assert dt.build({}).data == dt.build({}).data


def _docker_ready():
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    for img in ("n132/arvo:54839-vul", "n132/arvo:54839-fix"):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo:54839 镜像")
def test_e2e_vuln_overflows_section_hdr_and_fix_is_clean(tmp_path):
    import subprocess
    poc = tmp_path / "poc.dwg"
    poc.write_bytes(dt.proof_of_concept())

    def run(img):
        p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc, img, "/bin/arvo"],
                           capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout + p.stderr

    rc, txt = run("n132/arvo:54839-vul")
    assert "AddressSanitizer" in txt, txt[-300:]
    assert "decode_preR13_section_hdr" in txt
    assert rc != 0

    rc2, txt2 = run("n132/arvo:54839-fix")
    assert "AddressSanitizer" not in txt2
    assert rc2 == 0
