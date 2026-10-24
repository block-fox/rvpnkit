"""定位密码令牌生成函数。

已知：
  * 令牌长度 = 4 + 4*字符数
  * 结构 = 4 字节 IV + 每字符 4 字节（链式）
  * 二进制里只有两个可疑常量：0x9E3779B9 @ 0xF5381、16777619 @ 0x12984A

先做两件事：
  1. 把这两个偏移反汇编，看是不是在「处理宽字符」的循环里
  2. 全二进制搜 `lea reg, [reg*4 + 4]` —— 长度公式 4n+4 的直接痕迹
"""

import re
import struct
import sys

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"


def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        sys.exit("不是 PE")
    coff = e + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    sec = opt + optsz
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, va = struct.unpack_from("<II", data, o + 8)
        rsize, rptr = struct.unpack_from("<II", data, o + 16)
        flags = struct.unpack_from("<I", data, o + 36)[0]
        out.append({
            "name": name, "va": va, "vsize": vsize,
            "rptr": rptr, "rsize": rsize, "flags": flags,
            "image_base": struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0],
        })
    return out, is64


def disasm_at(data, secs, file_off, before=96, count=60):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if len(secs) else capstone.CS_MODE_32)
    md.detail = False
    start = max(0, file_off - before)
    code = data[start:start + before + 400]
    va = None
    for s in secs:
        if s["rptr"] <= file_off < s["rptr"] + s["rsize"]:
            va = s["va"] + (file_off - s["rptr"]) + s["image_base"] if False else s["va"] + (file_off - s["rptr"])
            break
    if va is None:
        return []
    lines = []
    addr = va - (file_off - start)
    for insn in md.disasm(code, addr):
        mark = "==>" if (start + (insn.address - addr)) == file_off else "   "
        lines.append(f"{mark} {insn.address:08x}  {insn.mnemonic:<8} {insn.op_str}")
        if len(lines) >= count:
            break
    return lines


def main():
    data = open(EXE, "rb").read()
    secs, is64 = sections(data)
    print(f"PE {'x64' if is64 else 'x86'}，{len(secs)} 个节\n")
    for s in secs:
        mark = "  <-- 代码" if s["flags"] & 0x20000020 else ""
        print(f"  {s['name']:<8} va=0x{s['va']:08x} rptr=0x{s['rptr']:08x} "
              f"size=0x{s['rsize']:08x}{mark}")

    for target, label in ((0xF5381, "0x9E3779B9 黄金比例"), (0x12984A, "16777619 FNV 素数")):
        print(f"\n\n=== {label} @ 0x{target:x} ===")
        for line in disasm_at(data, secs, target, before=120, count=70):
            print("  " + line)

    # 搜 lea reg, [reg*4 + 4]
    print("\n\n=== 搜索 lea reg, [reg*4+4] （长度公式 4n+4 的痕迹）===")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    text = next((s for s in secs if s["name"] == ".text"), secs[0])
    blob = data[text["rptr"]:text["rptr"] + text["rsize"]]
    hits = []
    # 常见编码：48 8D 04 8D 04 00 00 00 (lea rax,[rcx*4+4]) 等
    pat = re.compile(rb"\x48\x8d[\x04\x44\x84\x8c]\x8d?\x04\x00\x00\x00")
    for m in pat.finditer(blob):
        off = text["rptr"] + m.start()
        for insn in md.disasm(blob[m.start():m.start() + 12], text["va"] + m.start()):
            if insn.mnemonic == "lea" and ("*4" in insn.op_str) and insn.op_str.rstrip().endswith(("4", "+4", "0x4")):
                hits.append((off, insn.address, insn.op_str))
            break
    print(f"  命中 {len(hits)} 处")
    for off, va, ops in hits[:30]:
        print(f"    file=0x{off:x}  va=0x{va:x}  lea {ops}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
