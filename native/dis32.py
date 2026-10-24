"""按 32 位模式反汇编 PE 里任意 VA 处的代码。

RvRvpnGui.exe 是 PE32（32 位），.text 的 va=0x1000 / file=0x400，
即 file = va - 0xC00。
"""

import struct
import sys

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
TEXT_VA = 0x1000
TEXT_RAW = 0x400


def va_to_file(va):
    return va - TEXT_VA + TEXT_RAW


def disasm(va, count=200, start_back=0):
    data = open(EXE, "rb").read()
    off = va_to_file(va)
    code = data[off:off + 4096]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    lines = []
    for insn in md.disasm(code, va):
        mark = "->" if len(lines) == start_back else "  "
        lines.append(f"{mark} {insn.address:08x}  {insn.bytes.hex():<20} {insn.mnemonic:<7} {insn.op_str}")
        if len(lines) >= count:
            break
    return lines


if __name__ == "__main__":
    va = int(sys.argv[1], 16)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    print(f"=== VA 0x{va:x} (file 0x{va_to_file(va):x}) ===")
    for line in disasm(va, n):
        print(line)
