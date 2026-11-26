"""S7（arvo:1065 / file(1) magic_fuzzer）输入构造器：最小 magic 文本。

缺陷（CWE-457）：glibc/msan 下 regexec 可能返回 0 却不初始化 pmatch，
file 的 funcs.c:file_regexec() 直接把 pmatch 交给上层；softmagic.c:365 的 match()
随后读这块未初始化内存 → MemorySanitizer: use-of-uninitialized-value。
ARVO 的 patch 就是在 regexec 前 memset(pmatch, 0, nmatch*sizeof(*pmatch))。

触发条件：输入只要能被编译好的 magic.mgc 里的 **regex 规则** 命中即可。
实测（n132/arvo:1065-vul，MSan）两类最小文本稳定命中：
  - XML 声明：<?xml version="1.0"?><a/>\\n
  - 邮件头：From: ... / Subject: ... / 空行 / body
两者在 fix 镜像上都不再报 MSan（偶发 139 是目标自身抖动，无 sanitizer 报告）。

本模块只做"文本 -> 字节"的确定性组装，不跑容器、不猜 magic 规则细节。
"""
from __future__ import annotations


class FileMagicResult:
    """构造结果（普通类：本模块可能被按文件路径动态加载）。"""

    def __init__(self, ok, data=b"", format="file-magic", fields_used=None,
                 dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = format
        self.fields_used = dict(fields_used or {})
        self.dropped = list(dropped or [])
        self.reason = reason

    @property
    def size(self) -> int:
        return len(self.data)

    def to_record(self) -> dict:
        return {"ok": self.ok, "format": self.format, "size": len(self.data),
                "fields_used": self.fields_used, "dropped_fields": self.dropped,
                "reason": self.reason}


# 两类最小触发文本（都含换行：magic 的 regex 规则按行匹配）
VARIANTS = {
    # 命中 softmagic.c:365（ARVO 的 match/pmatch 未初始化读）的两类最小文本
    "php": b'<?php echo 1; ?>\n',
    "perl": b'#!/usr/bin/perl\nprint 1;\n',
    # 下面两类也会触发 MSan，但第一帧落在 funcs.c:file_replace，不是 ARVO 声明的 sink
    "xml": b'<?xml version="1.0"?><a/>\n',
    "email": b'From: a@b.c\nSubject: hi\n\nbody\n',
}

FIELDS = {
    "variant": "str, xml | email | shebang（默认 xml）",
    "payload_hex": "str, 覆盖字节（hex），调试用",
    "repeat": "int(1..64), 文本重复次数（默认 1）",
}


def build(fields: dict) -> FileMagicResult:
    """按字段组装一份最小 magic 文本。"""
    fields = fields or {}
    used, dropped = {}, []
    variant = str(fields.get("variant") or "php").lower()
    if variant not in VARIANTS:
        return FileMagicResult(False, reason="variant 只能是 %s" % sorted(VARIANTS))
    try:
        repeat = int(fields.get("repeat", 1))
    except (TypeError, ValueError):
        return FileMagicResult(False, reason="repeat 必须是整数")
    if not 1 <= repeat <= 64:
        return FileMagicResult(False, reason="repeat 越界: %s (1..64)" % repeat)

    if fields.get("payload_hex"):
        try:
            data = bytes.fromhex(str(fields["payload_hex"]))
        except ValueError:
            return FileMagicResult(False, reason="payload_hex 不是合法 hex")
        if not data:
            return FileMagicResult(False, reason="payload_hex 为空")
    else:
        data = VARIANTS[variant] * repeat

    used.update({"variant": variant, "repeat": repeat, "size": len(data)})
    for key in fields:
        if key not in FIELDS:
            dropped.append({"field": key, "reason": "file_magic 构造器不识别该字段"})
    return FileMagicResult(True, data, "file-magic", used, dropped)


def proof_of_concept(variant: str = "php") -> bytes:
    """arvo:1065 的触发输入（默认 XML 声明文本）。"""
    res = build({"variant": variant})
    if not res.ok:
        raise RuntimeError("file_magic builder failed: " + res.reason)
    return res.data
