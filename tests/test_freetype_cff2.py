r"""S8e（arvo:368 / freetype2）CFF2 可变字体构造器测试。

验收点：
1. 生成物是 OTTO 容器，能被 fontTools TTFont 重新打开，含 CFF2 / fvar / VarStore；
2. 轴数与 regions/blends/values 字段生效，字节可复现（同参数同字节）；
3. 字段越界被拒；
4. 端到端（有 docker + arvo:368 镜像时）：vul 崩溃、fix 干净。

fontTools 装在 /usr/bin/python3，仓库默认 python3 可能没有；
所以需要 fontTools 的断言都走子进程，缺失时 skip 而不是失败。
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load():
    spec = importlib.util.spec_from_file_location("freetype_cff2_builder",
                                                  ROOT / "agent" / "builders" / "freetype_cff2.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["freetype_cff2_builder"] = mod
    spec.loader.exec_module(mod)
    return mod


cff2 = _load()
HAVE_FT = cff2.fonttools_available()


@pytest.mark.skipif(not HAVE_FT, reason="需要 /usr/bin/python3 上有 fontTools")
def test_build_is_valid_otto_with_cff2_and_fvar():
    res = cff2.build({})
    assert res.ok, res.reason
    assert res.data.startswith(b"OTTO")
    info = cff2.inspect(res.data)
    assert info["ok"], info.get("error")
    assert "CFF2" in info["tables"] and "fvar" in info["tables"]
    assert [a[0] for a in info["axes"]] == ["wght", "wdth"]


@pytest.mark.skipif(not HAVE_FT, reason="需要 fontTools")
def test_axes_and_blend_fields_take_effect():
    one = cff2.build({"axes": 2, "regions": 1, "blends": 1, "values": 7})
    two = cff2.build({"axes": 2, "regions": 2, "blends": 8, "values": 7})
    assert one.ok and two.ok
    assert two.size > one.size                      # 更多 blend/区域 -> 更大
    info = cff2.inspect(one.data)
    assert len(info["axes"]) == 2
    info1 = cff2.inspect(cff2.build({"axes": 1}).data)
    assert len(info1["axes"]) == 1


@pytest.mark.skipif(not HAVE_FT, reason="需要 fontTools")
def test_build_is_deterministic():
    a = cff2.build({"blends": 3}).data
    b = cff2.build({"blends": 3}).data
    assert a == b and len(a) > 0


def test_field_validation_without_fonttools():
    assert cff2.build({"axes": 9}).ok is False
    assert cff2.build({"regions": 0}).ok is False
    assert cff2.build({"blends": 0}).ok is False
    assert cff2.build({"values": 999}).ok is False
    assert cff2.build({"blends": "x"}).ok is False
    r = cff2.build({"unknown": 1})
    # 未知字段只记 dropped；是否 ok 取决于 fontTools 是否可用
    assert r.dropped and r.dropped[0]["field"] == "unknown"


@pytest.mark.skipif(not HAVE_FT, reason="需要 fontTools")
def test_unknown_field_is_recorded_but_font_still_builds():
    r = cff2.build({"unknown": 1})
    assert r.ok
    assert r.data.startswith(b"OTTO")


def _docker_ready():
    import shutil
    if not shutil.which("docker"):
        return False
    for img in ("n132/arvo:368-vul", "n132/arvo:368-fix"):
        if subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode != 0:
            return False
    return True


@pytest.mark.skipif(not HAVE_FT or not _docker_ready(),
                    reason="需要 fontTools + docker + arvo:368 镜像")
def test_e2e_font_is_accepted_and_does_not_crash(tmp_path):
    """s8f 结论：补上 Private DICT 之后，字体是"合法 CFF2"，两端都能正常加载。

    s8e 那次 vul 3/3 SEGV 是**缺 Private DICT 导致的假崩溃**
    （freetype 的 cff_load_private_dict 在没有 Private 时直接返回，blend.font 保持 NULL，
    随后 cff_blend_build_vector 解引用它），不是案卷的 cff_blend_doBlend UAF。
    """
    poc = tmp_path / "cff2.otf"
    poc.write_bytes(cff2.build({}).data)

    def run(img):
        p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/tmp/poc:ro" % poc, img, "/bin/arvo"],
                           capture_output=True, text=True, timeout=300)
        return p.returncode, p.stdout + p.stderr

    for img in ("n132/arvo:368-vul", "n132/arvo:368-fix"):
        rc, txt = run(img)
        assert "AddressSanitizer" not in txt, (img, txt[-300:])
        assert rc == 0, (img, rc)


# ---- s8f：Private DICT 与 DICT blend（把崩点从 build_vector 挪开）----

@pytest.mark.skipif(not HAVE_FT, reason="需要 fontTools")
def test_private_dict_present_and_dict_blends_compile():
    plain = cff2.build({})
    with_dict = cff2.build({"dict_blends": 32})
    assert plain.ok and with_dict.ok
    assert with_dict.size > plain.size          # 带 DICT blend 的字体更大
    assert cff2.inspect(plain.data)["ok"]
    assert cff2.inspect(with_dict.data)["ok"]


@pytest.mark.skipif(not HAVE_FT, reason="需要 fontTools")
def test_private_dict_exists_in_cff2(tmp_path):
    """没有 Private DICT 时 freetype 的 cff_load_private_dict 会跳过 blend.font 初始化，
    导致 cff_blend_build_vector 解引用 NULL —— 这正是 s8e 那次 SEGV 的成因。"""
    import json as _json
    import subprocess as _sp
    p = tmp_path / "f.otf"
    p.write_bytes(cff2.build({}).data)
    code = ("import sys, json; from fontTools.ttLib import TTFont; "
            "f=TTFont(sys.argv[1]); td=f['CFF2'].cff.topDictIndex[0]; "
            "print(json.dumps({'priv':[bool(getattr(fd,'Private',None)) for fd in td.FDArray]}))")
    r = _sp.run([cff2.FONTTOOLS_PYTHON, "-c", code, str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    info = _json.loads(r.stdout.strip().splitlines()[-1])
    assert info["priv"] and all(info["priv"])


def test_dict_blends_field_validation():
    assert cff2.build({"dict_blends": -1}).ok is False
    assert cff2.build({"dict_blends": 5000}).ok is False
    assert cff2.build({"dict_blends": "x"}).ok is False
