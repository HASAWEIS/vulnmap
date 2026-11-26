"""本地 gadget / 符号地址解析（不依赖 pwntools / ROPgadget）。

用于把 exploit 脚本的占位地址替换为真实值。所有解析都在**本地二进制**
上进行，信息来自 `objdump` / `readelf`，不访问网络。
"""
from __future__ import annotations
import re
import subprocess
from dataclasses import dataclass, field


@dataclass
class Gadgets:
    pop_rdi: int = 0            # pop rdi; ret
    ret: int = 0                # 纯 ret（16 字节栈对齐）
    symbols: dict = field(default_factory=dict)   # name -> addr（库函数）
    base: int = 0               # 二进制装载基址（非 PIE 时为 0x400000 附近）

    def addrs_for(self, chain: list[str]) -> dict:
        """按 chain 描述返回可用地址；缺项则不返回，由调用方判 assembled=False。"""
        out = {}
        for step in chain:
            # 键必须用 chain 原样字符串，否则模板按 chain 取地址会取不到
            if step.startswith("pop rdi") and self.pop_rdi:
                out[step] = self.pop_rdi
            elif step.startswith("ret (16B align)") and self.ret:
                out[step] = self.ret
            elif step.startswith("system@plt") and self.symbols.get("system"):
                out[step] = self.symbols["system"]
        return out


def _run(argv: list[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def find_gadgets(binary: str) -> Gadgets:
    """在给定 ELF 上找 pop rdi; ret 与纯 ret。

    只在**真实指令边界**上确认：objdump 反汇编出的指令序列中相邻两条为
    `pop %rdi` 与 `ret`，避免把跨指令的字节巧合当 gadget。
    """
    g = Gadgets()
    out = _run(["objdump", "-d", binary])
    if not out:
        return g
    # 只解析「指令」行：地址 + 字节 + 助记符
    insns = []          # (addr, mnemonic_line)
    for ln in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(\S.*)$", ln)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))
    if insns:
        g.base = insns[0][0]
    for i, (addr, text) in enumerate(insns):
        # 必须是真正的 `pop %rdi`（排除 popcnt / popf 等前缀相同的指令）
        if re.match(r"^pop\s+%rdi$", text):
            if i + 1 < len(insns) and insns[i + 1][1].startswith("ret"):
                g.pop_rdi = addr
                break
    for addr, text in insns:
        if text == "ret":
            g.ret = addr
            break
    return g


def find_dynamic_symbols(elf: str, names: tuple[str, ...]) -> dict:
    """从动态符号表取函数地址（对象是 PLT 时返回 plt 项）。"""
    out = _run(["readelf", "-sW", elf])
    found = {}
    for ln in out.splitlines():
        for name in names:
            if re.search(rf"\b{re.escape(name)}@@|\b{re.escape(name)}$", ln):
                parts = ln.split()
                if len(parts) >= 2:
                    try:
                        found.setdefault(name, int(parts[1], 16))
                    except ValueError:
                        pass
    return found


def find_string(elf: str, needle: bytes) -> int:
    """在文件里定位字符串，返回其文件偏移（非 PIE 时可近似作地址）。"""
    try:
        with open(elf, "rb") as fh:
            blob = fh.read()
    except OSError:
        return 0
    idx = blob.find(needle)
    return idx if idx >= 0 else 0
