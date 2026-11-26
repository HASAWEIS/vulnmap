r"""S16（arvo:61675 / Exiv2 BMFF brob）构造器测试。

验收点：
1. 产物是合法 BMFF（ftyp + brob），可用 struct 解出 box 链；
2. 关键不变量：2*comp_target > 131072（否则首次 alloc 会被 DoS 上限截断，打不到下溢）；
3. 同参数可复现，字节一致；
4. 字段校验（comp_target<=0 / zeros<0 / 非整数 / 未知字段）；
5. 端到端（有 docker + arvo:61675 镜像）：vul 崩、fix 干净。
"""
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import avail as av


def _boxes(data):
    out, off = [], 0
    while off + 8 <= len(data):
        size, tag = struct.unpack_from(">I4s", data, off)
        out.append((tag, size))
        if size < 8:
            break
        off += size
    return out


def test_output_is_bmff_with_ftyp_and_brob():
    data = av.proof_of_concept()
    boxes = _boxes(data)
    assert [t for t, _ in boxes] == [b"ftyp", b"brob"]
    assert boxes[0][1] == 24 and boxes[1][1] == len(data) - 24
    assert data[8:12] == b"heic"
    # brob 负载前 4 字节是 realType
    assert data[24 + 8:24 + 12] == b"exif"


def test_compressed_size_invariant():
    r = av.build({})
    assert r.ok
    comp = r.fields_used["comp_target"]
    assert 2 * comp > 131072, "2*comp_target 必须大于 DoS 上限，否则首次 alloc 就被截断"
    assert r.fields_used["zeros"] > 2 * comp, "解压总量要明显大于首次 alloc 的长度"


def test_build_is_deterministic():
    a = av.build({}).data
    b = av.build({}).data
    assert a == b and len(a) > 1000


def test_field_validation():
    assert av.build({"comp_target": 0}).ok is False
    assert av.build({"zeros": -1}).ok is False
    assert av.build({"comp_target": "x"}).ok is False
    r = av.build({"unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"
    assert "warning" in av.build({"comp_target": 60000}).fields_used


def test_small_comp_target_is_flagged_but_still_builds():
    r = av.build({"comp_target": 1000})
    assert r.ok
    assert "2*comp_target <= 131072" in r.fields_used["warning"]


def _docker_ready():
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    for img in ("n132/arvo:61675-vul", "n132/arvo:61675-fix"):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo:61675 镜像")
def test_e2e_vuln_overflows_and_fix_is_clean(tmp_path):
    import subprocess
    poc = tmp_path / "poc.heic"
    poc.write_bytes(av.proof_of_concept())

    def run(img):
        p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc, img, "/bin/arvo"],
                           capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout + p.stderr

    rc, txt = run("n132/arvo:61675-vul")
    assert "AddressSanitizer" in txt, txt[-300:]
    assert "brotli" in txt.lower()
    assert rc != 0

    rc2, txt2 = run("n132/arvo:61675-fix")
    assert "AddressSanitizer" not in txt2
    assert rc2 == 0
