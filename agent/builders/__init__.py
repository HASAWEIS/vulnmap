"""构造器注册表（包形态）：把 agent/builders.py 的注册表原样暴露，并挂上 CG-08 的 JNX 构造器。

为什么要有这一层：仓库里原本是单文件 agent/builders.py，而 S5E 的 JNX 构造器
在 agent/builders/cg08.py。一旦 agent/builders/ 变成包，Python 会优先导入包，
agent/builders.py 就"看不见"了。因此这里用文件路径把原来的模块加载进来，
逐个重导出它的公开名字，再把 jnx 注册进**同一个** BUILDERS/FIELD_SPECS 字典，
保证所有既有 import（build / BUILDERS / FIELD_SPECS / supported_formats / describe）
行为不变。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_IMPL_NAME = "_vulnmap_builders_impl"
_IMPL_PATH = Path(__file__).resolve().parent.parent / "builders.py"

if _IMPL_NAME in sys.modules:                       # pragma: no cover
    _impl = sys.modules[_IMPL_NAME]
else:
    _spec = importlib.util.spec_from_file_location(_IMPL_NAME, _IMPL_PATH)
    _impl = importlib.util.module_from_spec(_spec)
    sys.modules[_IMPL_NAME] = _impl
    _spec.loader.exec_module(_impl)

from . import cg08 as _cg08
from . import libredwg as _libredwg
from . import harfbuzz as _harfbuzz
from . import file_magic as _file_magic
from . import libidn2 as _libidn2
from . import ovn_lex as _ovn_lex
from . import gm_token as _gm_token
from . import aom_lr as _aom_lr
from . import ot_ip6 as _ot_ip6
from . import vax_mode as _vax_mode
from . import tga as _tga
from . import zstd_legacy as _zstd_legacy
from . import rar5 as _rar5
from . import maxpath as _maxpath
from . import hdf5_memcpy as _hdf5_memcpy
from . import libraw_arq as _libraw_arq
from . import codegen_args as _codegen_args
from . import dynapi as _dynapi
from . import snmp_oid as _snmp_oid

# 原模块的公开名字全部重导出
for _name in dir(_impl):
    if _name.startswith("__"):
        continue
    globals()[_name] = getattr(_impl, _name)

# 注册 JNX 构造器（同一份注册表，所以 build()/supported_formats() 立刻可见）
_impl.BUILDERS["jnx"] = _cg08.build
_impl.FIELD_SPECS["jnx"] = dict(_cg08.FIELDS)
# 注册 CG-10（arvo:54625 / libredwg）的 DWG 构造器。
# 用独立的 "libredwg" 键而不是覆盖 "dwg"：老的 build_dwg 只认 version 字段，
# 其他调用方与既有测试仍按老行为走；需要 entities_* 字段时显式用新键。
# 注册 CG-12（arvo:11081 / harfbuzz）的 GSUB 构造器
# 注册 S7（arvo:1065 / file(1) magic_fuzzer）的文本构造器
_impl.BUILDERS["file_magic"] = _file_magic.build
_impl.FIELD_SPECS["file_magic"] = dict(_file_magic.FIELDS)
_impl.BUILDERS["harfbuzz"] = _harfbuzz.build
_impl.FIELD_SPECS["harfbuzz"] = dict(_harfbuzz.FIELDS)
_impl.BUILDERS["libredwg"] = _libredwg.build
_impl.FIELD_SPECS["libredwg"] = dict(_libredwg.FIELD_SPEC)

# 注册 CG-18（arvo:12420 / libidn2）的 UCS-4 域名字节串构造器。
# 它已用真实双端验证过触发形（vul exit=1 / fix exit=0），但这只是构造器接线：
# verify 还没有 "libidn2" 分支，要等那边加了分支才会真正被调用。
_impl.BUILDERS["libidn2"] = _libidn2.build
_impl.FIELD_SPECS["libidn2"] = dict(_libidn2.FIELDS)

_impl.BUILDERS["ovn_lex"] = _ovn_lex.build
_impl.FIELD_SPECS["ovn_lex"] = dict(_ovn_lex.FIELDS)

_impl.BUILDERS["gm_token"] = _gm_token.build
_impl.FIELD_SPECS["gm_token"] = dict(_gm_token.FIELDS)

_impl.BUILDERS["aom_lr"] = _aom_lr.build
_impl.FIELD_SPECS["aom_lr"] = dict(_aom_lr.FIELDS)

_impl.BUILDERS["ot_ip6"] = _ot_ip6.build
_impl.FIELD_SPECS["ot_ip6"] = dict(_ot_ip6.FIELDS)

_impl.BUILDERS["vax_mode"] = _vax_mode.build
_impl.FIELD_SPECS["vax_mode"] = dict(_vax_mode.FIELDS)

_impl.BUILDERS["tga"] = _tga.build
_impl.FIELD_SPECS["tga"] = dict(_tga.FIELDS)

_impl.BUILDERS["zstd_legacy"] = _zstd_legacy.build
_impl.FIELD_SPECS["zstd_legacy"] = dict(_zstd_legacy.FIELDS)

_impl.BUILDERS["rar5_dir"] = _rar5.build
_impl.FIELD_SPECS["rar5_dir"] = dict(_rar5.FIELDS)

_impl.BUILDERS["maxpath"] = _maxpath.build
_impl.FIELD_SPECS["maxpath"] = dict(_maxpath.FIELDS)

_impl.BUILDERS["hdf5_memcpy"] = _hdf5_memcpy.build
_impl.FIELD_SPECS["hdf5_memcpy"] = dict(_hdf5_memcpy.FIELDS)

_impl.BUILDERS["libraw_arq"] = _libraw_arq.build
_impl.FIELD_SPECS["libraw_arq"] = dict(_libraw_arq.FIELDS)

_impl.BUILDERS["mruby_codegen"] = _codegen_args.build
_impl.FIELD_SPECS["mruby_codegen"] = dict(_codegen_args.FIELDS)

_impl.BUILDERS["dynapi"] = _dynapi.build
_impl.FIELD_SPECS["dynapi"] = dict(_dynapi.FIELDS)

_impl.BUILDERS["snmp_oid"] = _snmp_oid.build
_impl.FIELD_SPECS["snmp_oid"] = dict(_snmp_oid.FIELDS)

BUILDERS = _impl.BUILDERS
FIELD_SPECS = _impl.FIELD_SPECS

JNX_BUILDER = _cg08
LIBREDWG_BUILDER = _libredwg
HARFBUZZ_BUILDER = _harfbuzz
FILE_MAGIC_BUILDER = _file_magic
LIBIDN2_BUILDER = _libidn2
OVN_LEX_BUILDER = _ovn_lex
GM_TOKEN_BUILDER = _gm_token
AOM_LR_BUILDER = _aom_lr
OT_IP6_BUILDER = _ot_ip6
VAX_MODE_BUILDER = _vax_mode
TGA_BUILDER = _tga
ZSTD_LEGACY_BUILDER = _zstd_legacy
RAR5_DIR_BUILDER = _rar5
MAXPATH_BUILDER = _maxpath
HDF5_MEMCPY_BUILDER = _hdf5_memcpy
LIBRAW_ARQ_BUILDER = _libraw_arq
CODEGEN_ARGS_BUILDER = _codegen_args
DYNAPI_BUILDER = _dynapi
SNMP_OID_BUILDER = _snmp_oid
