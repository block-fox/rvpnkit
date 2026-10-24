"""顺着 QRandomGenerator 封装函数找令牌生成点。

0x62214 调用 QRandomGenerator64::global()，0x62224 调用 _fillRange。
说明 0x62xxx 附近有个小封装（大概率是 CRandom::Next / RandomUInt32）。
找到它的函数起点，再找谁调用它 —— 那里就是令牌生成。
"""

import struct
import sys

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
TEXT_VA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x1cda00


def va2f(va):
    return va - TEXT_VA + TEXT_RAW


def f2va(f):
    return f - TEXT_RAW + TEXT_VA


def load():
    return open(EXE, "rb").read()


def func_start(data, va, back=0x800):
    off = va2f(va)
    i = off
    while i > off - back and i > 0:
        if data[i - 4:i] == b"\xcc\xcc\xcc\xcc":
            return f2va(i)
        i -= 1
    return None


def disasm(data, va, count=60):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    code = data[va2f(va):va2f(va) + 0x300]
    out = []
    for insn in md.disasm(code, va):
        out.append(f"   {insn.address:08x}  {insn.mnemonic:<7} {insn.op_str}")
        if len(out) >= count:
            break
    return out


def callers(data, target_va):
    text = data[TEXT_RAW:TEXT_RAW + TEXT_SIZE]
    hits = []
    for op, kind in ((b"\xe8", "call"), (b"\xe9", "jmp")):
        start = 0
        while True:
            i = text.find(op, start)
            if i < 0:
                break
            if i + 5 <= len(text):
                rel = struct.unpack_from("<i", text, i + 1)[0]
                if TEXT_VA + i + 5 + rel == target_va:
                    hits.append((TEXT_VA + i, kind))
            start = i + 1
    return hits


def main():
    data = load()
    for anchor in (0x62214, 0x62224):
        st = func_start(data, anchor)
        print(f"\n锚点 0x{anchor:x} 所属函数起点 = 0x{st:x}")
        for line in disasm(data, st, 30):
            print(line)
        cs = callers(data, st)
        print(f"   → 调用点 {len(cs)} 处: {[hex(a) for a, _ in cs[:12]]}")
        for va, _ in cs[:6]:
            print(f"\n   --- 上下文 0x{va:x} ---")
            s2 = func_start(data, va)
            for line in disasm(data, s2 or (va - 0x40), 40):
                mark = "->" if line.strip().startswith(f"{va:08x}") else "  "
                print("   " + mark + line.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
