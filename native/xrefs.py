#!/usr/bin/env python3
"""xrefs.py —— 在 .text 里找对指定地址（立即数）的引用，并反汇编引用点。

支持定位三类目标：
    * 数据表地址（例如 0x5250e0 那张命令码表）
    * 字符串常量（日志模板）
    * 函数地址（谁调用了它）

用法：
    python xrefs.py 0x5250e0              # 找对某地址的立即数引用
    python xrefs.py --string "remove"     # 先按子串找字符串，再找引用
    python xrefs.py --va 0x51cb78 -n 6    # 每个引用点反汇编 6 条
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from pe import PE  # noqa: E402

PATH = r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe"


def setup():
    pe = PE(PATH)
    text = next(s for s in pe.sections if s["name"] == ".text")
    tlo = text["rawptr"]
    thi = tlo + text["rawsize"]
    lo_va = pe.image_base + text["vaddr"]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return pe, tlo, thi, lo_va, md


def find_imm_refs(pe, tlo, thi, target):
    """在 .text 里找 4 字节小端等于 target 的位置（即 imm32 引用）。"""
    needle = struct.pack("<I", target & 0xFFFFFFFF)
    out = []
    start = tlo
    while True:
        i = pe.data.find(needle, start, thi)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def find_string(pe, substr):
    """在文件里找 UTF-16LE 字符串，返回 (文件偏移, VA, 文本)。"""
    res = []
    needle = substr.encode("utf-16-le")
    start = 0
    while True:
        i = pe.data.find(needle, start)
        if i < 0:
            break
        va = pe.off_to_va(i)
        if va:
            # 取整串
            j = i
            while j >= 0 and pe.data[j - 2:j] != b"\x00\x00":
                j -= 2
            res.append((i, va, substr))
        start = i + 1
    return res


def show(pe, md, off, n=8):
    """从引用点前若干字节开始反汇编，便于看上下文。"""
    start = max(0, off - 24)
    va = pe.off_to_va(start)
    if va is None:
        return
    code = pe.data[start:off + 24]
    marks = 0
    for ins in md.disasm(code, va):
        mark = " <== 引用点" if ins.address <= (pe.off_to_va(off) or 0) < ins.address + len(ins.bytes) else ""
        print(f"      0x{ins.address:08x}  {ins.bytes.hex():<16} {ins.mnemonic:<7} {ins.op_str}{mark}")
        marks += 1
        if marks > n + 4:
            break


def main(argv):
    pe, tlo, thi, lo_va, md = setup()

    if not argv or argv[0].startswith("--string"):
        sub = argv[1] if len(argv) > 1 else "remove"
        hits = find_string(pe, sub)
        print(f"字符串 '{sub}' 命中 {len(hits)} 处：")
        for off, va, t in hits:
            print(f"  文件 0x{off:08x}  VA 0x{va:08x}")
            refs = find_imm_refs(pe, tlo, thi, va)
            print(f"    被引用 {len(refs)} 次：{[hex(pe.off_to_va(r)) for r in refs]}")
            for r in refs[:3]:
                show(pe, md, r)
            print()
        return

    target = int(argv[0], 0)
    refs = find_imm_refs(pe, tlo, thi, target)
    print(f"0x{target:08x} 被立即数引用 {len(refs)} 次：")
    for r in refs:
        print(f"  引用点 文件 0x{r:08x}  VA 0x{pe.off_to_va(r):08x}")
        show(pe, md, r)


if __name__ == "__main__":
    main(sys.argv[1:])
