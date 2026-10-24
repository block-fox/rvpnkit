"""在 .text 里找所有 call/jmp 到指定 VA 的位置（相对位移解析）。"""

import re
import struct
import sys

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
TEXT_VA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x1cda00


def find_callers(target_va):
    data = open(EXE, "rb").read()
    text = data[TEXT_RAW:TEXT_RAW + TEXT_SIZE]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    hits = []

    # 只扫 0xE8/0xE9 开头的可能调用，先粗筛再逐条解码
    for m in re.finditer(rb"[\xe8\xe9]", text):
        i = m.start()
        if i + 5 > len(text):
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        va = TEXT_VA + i
        tgt = va + 5 + rel
        if tgt == target_va:
            hits.append((va, "call" if text[i] == 0xE8 else "jmp"))
    return hits


def disasm_around(va, before=64, after=64):
    data = open(EXE, "rb").read()
    off = va - TEXT_VA + TEXT_RAW - before
    code = data[off:off + before + after]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    out = []
    for insn in md.disasm(code, TEXT_VA + (off - TEXT_RAW)):
        mark = "->" if insn.address == va else "  "
        out.append(f"{mark} {insn.address:08x}  {insn.mnemonic:<7} {insn.op_str}")
    return out


if __name__ == "__main__":
    targets = [int(a, 16) for a in sys.argv[1:]] or [0xF5F70]
    for t in targets:
        hits = find_callers(t)
        print(f"\n=== 0x{t:x} 的调用点：{len(hits)} 处 ===")
        for va, kind in hits[:20]:
            print(f"  {kind}  @ 0x{va:x}")
        for va, kind in hits[:5]:
            print(f"\n--- 上下文 0x{va:x} ---")
            for line in disasm_around(va, 48, 48):
                print("   " + line)
