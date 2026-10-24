#!/usr/bin/env python3
"""pe.py —— 极简 PE 解析：机器类型、映像基址、节表、VA<->文件偏移换算。

只依赖标准库。供 disasm.py 等分析脚本复用。
"""
import struct


class PE:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("不是 PE 文件")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("缺少 PE 签名")
        coff = e_lfanew + 4
        self.machine, self.nsections = struct.unpack_from("<HH", d, coff)
        (self.timestamp,) = struct.unpack_from("<I", d, coff + 4)
        (self.opt_size,) = struct.unpack_from("<H", d, coff + 16)
        (self.characteristics,) = struct.unpack_from("<H", d, coff + 18)

        opt = coff + 20
        (self.magic,) = struct.unpack_from("<H", d, opt)
        self.is64 = self.magic == 0x20B
        if self.is64:
            (self.image_base,) = struct.unpack_from("<Q", d, opt + 24)
            (self.entry,) = struct.unpack_from("<I", d, opt + 16)
        else:
            (self.image_base,) = struct.unpack_from("<I", d, opt + 28)
            (self.entry,) = struct.unpack_from("<I", d, opt + 16)

        self.sections = []
        sec = opt + self.opt_size
        for i in range(self.nsections):
            off = sec + i * 40
            name = d[off:off + 8].rstrip(b"\0").decode("ascii", "ignore")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            chars, = struct.unpack_from("<I", d, off + 36)
            self.sections.append({
                "name": name, "vaddr": vaddr, "vsize": vsize,
                "rawptr": rawptr, "rawsize": rawsize, "chars": chars,
            })

    @property
    def bits(self):
        return 64 if self.is64 else 32

    def machine_name(self):
        return {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(self.machine, hex(self.machine))

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                delta = rva - s["vaddr"]
                if delta < s["rawsize"]:
                    return s["rawptr"] + delta
                return None
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return s["vaddr"] + (off - s["rawptr"])
        return None

    def off_to_va(self, off):
        rva = self.off_to_rva(off)
        return None if rva is None else self.image_base + rva

    def va_to_off(self, va):
        rva = va - self.image_base
        if rva < 0:
            return None
        return self.rva_to_off(rva)

    def describe(self):
        lines = [
            f"文件        : {self.path}",
            f"大小        : {len(self.data):,} 字节",
            f"机器类型    : {self.machine_name()} ({self.bits} 位)",
            f"映像基址    : 0x{self.image_base:08x}",
            f"入口点 RVA  : 0x{self.entry:08x}",
            f"节数        : {self.nsections}",
            "",
            f"{'节名':<10} {'虚拟地址':>10} {'虚拟大小':>10} {'文件偏移':>10} {'文件大小':>10}",
        ]
        for s in self.sections:
            lines.append(f"{s['name']:<10} 0x{s['vaddr']:08x} {s['vsize']:>10,} "
                         f"0x{s['rawptr']:08x} {s['rawsize']:>10,}")
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    p = PE(sys.argv[1] if len(sys.argv) > 1 else
           r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe")
    print(p.describe())
