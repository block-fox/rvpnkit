"""解析导入表，找随机数来源，并定位它们的调用点。

思路：令牌开头是 4 字节随机 IV，所以生成函数的必经之路是取随机数。
找到随机源 → 找调用点 → 从调用点往回追。

用法：
    python find_rng.py            # 列出随机相关导入 + 调用点
    python find_rng.py <iat_va>   # 只看某个导入的调用点
"""

import re
import struct
import sys

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"

SECTIONS = [
    # (va, rptr, rsize, name)
    (0x1000, 0x400, 0x1cda00, ".text"),
    (0x1cf000, 0x1cde00, 0xb42e00, ".rdata"),
    (0xd12000, 0xd10c00, 0x1bc00, ".data"),
    (0xd7a000, 0xd2c800, 0x5e200, ".rsrc"),
    (0xdd9000, 0xd8aa00, 0x2e200, ".reloc"),
]

RNG_HINTS = [
    "rand", "Rand", "RAND", "random", "Random", "RANDOM",
    "CryptGenRandom", "RtlGenRandom", "BCryptGenRandom", "SystemFunction036",
    "getrandom", "urandom", "seed", "Seed", "SEED",
]


def rva_to_file(rva):
    for va, rp, rs, _ in SECTIONS:
        if va <= rva < va + rs:
            return rp + (rva - va)
    return None


def file_to_rva(off):
    for va, rp, rs, _ in SECTIONS:
        if rp <= off < rp + rs:
            return va + (off - rp)
    return None


def cstr(data, rva, limit=200):
    off = rva_to_file(rva)
    if off is None:
        return None
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        return None
    return data[off:end].decode("latin1", "ignore")


def parse_imports(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e + 4
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    ddir = opt + 96
    imp_rva, imp_size = struct.unpack_from("<II", data, ddir + 1 * 8)

    out = []
    off = rva_to_file(imp_rva)
    if off is None:
        return out, image_base

    i = 0
    while True:
        o = off + i * 20
        oft, tds, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, o)
        if oft == 0 and name_rva == 0:
            break
        dll = cstr(data, name_rva) or "?"
        thunk_rva = oft if oft else ft
        toff = rva_to_file(thunk_rva)
        k = 0
        while toff is not None:
            val = struct.unpack_from("<I", data, toff + k * 4)[0]
            if val == 0:
                break
            if val & 0x80000000:
                fname = f"#{val & 0x7FFFFFFF}"
            else:
                fname = cstr(data, val + 2) or "?"
            iat_va = image_base + ft + k * 4
            out.append({"dll": dll, "name": fname, "iat": iat_va})
            k += 1
        i += 1
        if i > 2000:
            break
    return out, image_base


def find_calls_to(data, iat_va, text_va=0x1000, text_raw=0x400, text_size=0x1cda00):
    """找 call dword ptr [iat] (FF 15 xx xx xx xx) 与 jmp (FF 25)。"""
    text = data[text_raw:text_raw + text_size]
    pat = struct.pack("<I", iat_va)
    hits = []
    for op in (b"\xff\x15", b"\xff\x25"):
        start = 0
        while True:
            i = text.find(op, start)
            if i < 0:
                break
            if struct.unpack_from("<I", text, i + 2)[0] == iat_va:
                hits.append((text_va + i, "call" if op == b"\xff\x15" else "jmp"))
            start = i + 1
    return hits


def main():
    data = open(EXE, "rb").read()
    imports, image_base = parse_imports(data)
    print(f"导入函数共 {len(imports)} 个，ImageBase=0x{image_base:x}\n")

    want = sys.argv[1] if len(sys.argv) > 1 else None
    shown = 0
    for imp in imports:
        name = imp["name"]
        if want:
            if want.lower() not in name.lower():
                continue
        else:
            if not any(h in name for h in RNG_HINTS):
                continue
        hits = find_calls_to(data, imp["iat"])
        print(f"{imp['dll']}!{name}   iat=0x{imp['iat']:x}   调用点 {len(hits)}")
        for va, kind in hits[:8]:
            print(f"    {kind} @ 0x{va:x}")
        shown += 1
        if shown > 40:
            break

    if shown == 0 and not want:
        print("没找到名字里带随机关键字的导入，列出全部 DLL：")
        dlls = sorted({i["dll"] for i in imports})
        for d in dlls:
            print("   ", d)


if __name__ == "__main__":
    raise SystemExit(main())
