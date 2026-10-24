#!/usr/bin/env python3
"""find_class.py —— 通过 RTTI 找到某个 C++ 类的 vtable 和构造点。

MSVC 的布局：
    type descriptor  : [vfptr][spare][name*]  名字就是 ".?AVCSwitchPower@cmd@msg@ControlSvc@@"
    complete obj loc : 指向 TD 的指针在第 3 个字段
    vtable           : 第一个槽指向 COL，后面是虚函数

所以链路是：名字 -> TD -> 找指向 TD 的指针(COL) -> 找指向 COL 的指针(vtable)
-> 找引用 vtable 的代码(构造函数里会写入 vtable)。

用法：
    python find_class.py CSwitchPower
    python find_class.py CUpdateNetwork
"""
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from pe import PE  # noqa: E402

BINARIES = [
    r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe",
    r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe",
]


def find_all(data, needle):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def analyze(path, cls):
    pe = PE(path)
    name = f".?AV{cls}@".encode("ascii")
    hits = find_all(pe.data, name)
    if not hits:
        return

    print("=" * 84)
    print(f"{path.split(chr(92))[-1]}  类 {cls}  名字出现 {len(hits)} 次")
    print("=" * 84)

    for off in hits[:2]:
        # 名字在 type descriptor 里的偏移是 8（x86）
        td_va = None
        # 向前找 8 字节对齐的位置
        for delta in (8,):
            cand = off - delta
            va = pe.off_to_va(cand)
            if va:
                td_va = va
        print(f"\n  TD 猜测 VA = 0x{td_va:08x}（名字 @0x{off:08x}）")

        # 找指向 TD 的指针（COL 第 3 字段）
        needle = struct.pack("<I", td_va)
        cols = find_all(pe.data, needle)
        print(f"  指向 TD 的指针 {len(cols)} 处 -> COL 候选")
        for c in cols[:4]:
            col_va = pe.off_to_va(c - 12)
            if col_va is None:
                continue
            print(f"    COL 猜测 VA 0x{col_va:08x}（文件 0x{c:08x}）")
            # 找指向 COL 的指针 -> vtable
            n2 = struct.pack("<I", col_va)
            vts = find_all(pe.data, n2)
            print(f"      指向 COL 的指针 {len(vts)} 处 -> vtable 候选")
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            text = next(s for s in pe.sections if s["name"] == ".text")
            tlo, thi = text["rawptr"], text["rawptr"] + text["rawsize"]
            for v in vts[:3]:
                vt_va = pe.off_to_va(v)
                print(f"        vtable VA 0x{vt_va:08x}")
                # 找引用该 vtable 的代码
                n3 = struct.pack("<I", vt_va)
                refs = []
                start = tlo
                while True:
                    i = pe.data.find(n3, start, thi)
                    if i < 0:
                        break
                    refs.append(i)
                    start = i + 1
                print(f"          代码引用 {len(refs)} 处："
                      f"{[hex(pe.off_to_va(r)) for r in refs][:6]}")
                for r in refs[:2]:
                    va = pe.off_to_va(r)
                    lo = max(0, r - 96)
                    code = pe.data[lo:r + 160]
                    print(f"          --- 构造点附近 0x{va:08x} ---")
                    cnt = 0
                    for ins in md.disasm(code, pe.off_to_va(lo)):
                        mark = "  <== 写 vtable" if abs(ins.address - va) < 8 else ""
                        print(f"            0x{ins.address:08x}  {ins.bytes.hex():<16} "
                              f"{ins.mnemonic:<7} {ins.op_str}{mark}")
                        cnt += 1
                        if cnt > 26:
                            break
    print()


if __name__ == "__main__":
    cls = sys.argv[1] if len(sys.argv) > 1 else "CSwitchPower"
    for b in BINARIES:
        analyze(b, cls)
