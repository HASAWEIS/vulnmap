"""CG-34（arvo:49259 / mruby）codegen block 参数栈空间构造器。

**缺陷**：mrbgems/mruby-compiler/core/codegen.c 的 gen_assignment()，NODE_CALL /
NODE_SCALL 分支在生成"赋值目标是方法调用"的字节码时，没有维护块参数占用的栈槽，
导致 mrb_vm_exec 里 OP_SEND 写块槽时越过 1024 字节的 VM 栈区：

    #0 mrb_vm_exec vm.c <- mrb_vm_run <- mrb_top_run <- mrb_load_string（fuzzer 执行编译后的代码）
    WRITE of size 8，0 bytes to the right of 1024-byte region

patch 在该分支 sp 赋值之前补了 push(); pop();（把 sp 记账对齐）。

**输入**：Ruby 源代码文本（/out/mruby_fuzzer 直接 mrb_load_string 执行）。

**本构造器**：按"赋值目标 + RHS 带块/参数"的组合生成小 Ruby 程序；默认取一组最贴近
patch 位置的形态。实测这条缺陷对语法形态很挑（见 EVIDENCE 里的 390 例扫描）。
"""
from __future__ import annotations

FIELDS = {
    "shape": "int(0..15), 预置的语法形态下标（默认 3 = o.m = f(1, k: 2) { }）",
    "prelude": "int(0|1), 是否带上 f/C 的定义（默认 1）",
    "locals": "int(0..200), 额外声明多少局部变量（默认 0，用来把 VM 栈顶到边界）",
}

PRELUDE = ("def f(*a, **k, &b); 1; end\n"
           "class C\n"
           "  def []=(i, v); v; end\n"
           "  def m=(v); v; end\n"
           "  def m(*a); 1; end\n"
           "  def n; self; end\n"
           "end\n"
           "o = C.new\n"
           "h = {}\n")

SHAPES = (
    "o.m = f { }",
    "o.m = f(1) { }",
    "o.m = f(*[1]) { }",
    "o.m = f(1, k: 2) { }",
    "o[:k] = f { }",
    "o[:k] = f(1, k: 2) { }",
    "x = f(1, k: 2) { }",
    "@x = f(*[1]) { }",
    "a, b = f { }",
    "o.n.m = f { }",
    "o.m += f { }",
    "o.m ||= f(1) { }",
    "h[:k] += f { }",
    "3.times { |i| o.m = f(i) { } }",
    "def g(&b); b.call; end\ng { o.m = f { } }",
    "x = [1].map { |a, b, c| o.m = f { } }",
)

DECLARED_SINK = {
    "file": "mrbgems/mruby-compiler/core/codegen.c",
    "line": 1809,
    "symbol": "gen_assignment",
    "note": "NODE_CALL/SCALL 分支缺 push()/pop()，块参数栈槽没记账，VM 栈越界写 8 字节",
}


class MrubyResult:
    def __init__(self, ok, data=b"", fields_used=None, dropped=None, reason=""):
        self.ok = ok
        self.data = data
        self.format = "mruby_codegen"
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


def build(fields: dict) -> MrubyResult:
    fields = dict(fields or {})
    try:
        shape = int(fields.get("shape", 3))
        use_prelude = int(fields.get("prelude", 1))
        locals_ = int(fields.get("locals", 0))
    except (TypeError, ValueError):
        return MrubyResult(False, reason="shape/prelude/locals 必须是整数")
    if not 0 <= shape < len(SHAPES):
        return MrubyResult(False, reason="shape 越界（0..%d）: %d" % (len(SHAPES) - 1, shape))
    if not 0 <= locals_ <= 200:
        return MrubyResult(False, reason="locals 越界（0..200）: %d" % locals_)

    parts = []
    if use_prelude:
        parts.append(PRELUDE.rstrip("\n"))
    if locals_:
        parts.append("; ".join("v%d = %d" % (i, i) for i in range(locals_)))
    parts.append(SHAPES[shape])
    text = "\n".join(parts) + "\n"
    used = {"shape": shape, "shape_src": SHAPES[shape], "prelude": bool(use_prelude),
            "locals": locals_, "bytes": len(text)}
    known = set(FIELDS)
    dropped = [{"field": k, "reason": "mruby_codegen 构造器不识别该字段"}
               for k in fields if k not in known]
    return MrubyResult(True, text.encode(), used, dropped, "")


def declared_claim() -> dict:
    """构造器自带主张：gen_assignment 的 CALL 分支块槽未记账，VM 栈越界写。"""
    return {
        "claim_id": "cg34-mruby-codegen-blockargs",
        "subject": "mrb_vm_exec",
        "proposed_by": "builder",
        "subject_source": "builder",
        "evidence_source": "agent/builders/codegen_args.py + arvo error.txt",
        "cwe": "CWE-122",
        "sink": dict(DECLARED_SINK),
        "test_plan": {"format": "mruby_codegen"},
    }


def fields_spec() -> dict:
    return dict(FIELDS)


if __name__ == "__main__":
    r = build({})
    assert r.ok, r.reason
    assert "o.m = f(1, k: 2) { }" in r.data.decode()
    assert build({"shape": 15}).ok
    assert not build({"shape": 99}).ok
    assert not build({"locals": 999}).ok
    assert build({"unknown": 1}).dropped
    c = declared_claim()
    assert c["subject"] == "mrb_vm_exec" and c["sink"]["line"] == 1809
    print("mruby_codegen builder self-check OK:", r.to_record())
