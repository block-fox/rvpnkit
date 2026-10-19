"""Locate the RTTI structures for the ServiceCommand classes and their vtables.

MSVC layout:
    TypeDescriptor : [vftable][spare][name: ".?AVCJoinNetworkServiceCommand@@"]
    CompleteObjectLocator -> {signature, offset, cdOffset, pTypeDescriptor, ...}
    vtable[-1]     -> CompleteObjectLocator

Finding the vtable for a class gives us the class's implementation, and from
there we can walk to the serializer.
"""
import struct
import sys

PATH = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"

data = open(PATH, "rb").read()
print(f"文件: {PATH}")
print(f"大小: {len(data):,} 字节\n")

# ── 解析 PE 头
if data[:2] != b"MZ":
    raise SystemExit("not MZ")
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not PE"
fh = e_lfanew + 4
machine, nsec = struct.unpack_from("<HH", data, fh)
opt_size = struct.unpack_from("<H", data, fh + 16)[0]
opt = fh + 20
magic = struct.unpack_from("<H", data, opt)[0]
is64 = magic == 0x20B

image_base = struct.unpack_from("<I" if not is64 else "<Q", data, opt + 28)[0]
sec_off = opt + opt_size

sections = []
for i in range(nsec):
    s = sec_off + i * 40
    name = data[s:s + 8].rstrip(b"\0").decode("ascii", "ignore")
    vsize, vaddr, rawsize, raw = struct.unpack_from("<IIII", data, s + 8)
    sections.append((name, vaddr, vsize, raw, rawsize))

print(f"machine=0x{machine:04x}  {'x64' if is64 else 'x86'}  "
      f"映像基址=0x{image_base:x}  节数={nsec}")
for name, va, vs, raw, rs in sections:
    print(f"  {name:10} VA=0x{va:08x} VSize=0x{vs:08x} Raw=0x{raw:08x} RawSize=0x{rs:08x}")


def rva_to_off(rva):
    for name, va, vs, raw, rs in sections:
        span = max(vs, rs)
        if va <= rva < va + span:
            return raw + (rva - va)
    return None


def off_to_rva(off):
    for name, va, vs, raw, rs in sections:
        if raw <= off < raw + rs:
            return va + (off - raw)
    return None


# ── 找 TypeDescriptor 名称
TARGETS = [
    b".?AVCJoinNetworkServiceCommand@@",
    b".?AVCAbstractNetworkServiceCommand@@",
    b".?AVCCreateNetworkServiceCommand@@",
    b".?AVCEnumPublicNetworksServiceCommand@@",
    b".?AVCEnableNetworkServiceCommand@@",
    b".?AVCUpdateVisibleNodesServiceCommand@@",
    b".?AVCUpdateNetworkServiceCommand@@",
    b".?AVCChatGetNodesServiceCommand@@",
    b".?AVCAbstractNodeServiceCommand@@",
]

print("\n=== TypeDescriptor 位置（.rdata 中的类型名）===")
found = {}
for t in TARGETS:
    idx = data.find(t)
    if idx < 0:
        print(f"  未找到: {t.decode('ascii', 'ignore')}")
        continue
    rva = off_to_rva(idx)
    found[t] = (idx, rva)
    print(f"  0x{idx:08x} (RVA 0x{rva:08x})  {t.decode('ascii', 'ignore')}")

# TypeDescriptor 结构：vftable(4) + spare(4) + name(...)
# 所以描述符起点 = 名字偏移 - 8
print("\n=== TypeDescriptor 结构起点（名字前 8 字节）===")
td_offsets = {}
for t, (name_off, name_rva) in found.items():
    td = name_off - 8
    td_rva = off_to_rva(td)
    td_offsets[t] = (td, td_rva)
    prefix = data[td:td + 8]
    print(f"  TD@0x{td:08x} (RVA 0x{td_rva:08x})  前缀={prefix.hex(' ')}  "
          f"{t.decode('ascii', 'ignore')}")

# ── 找 CompleteObjectLocator：其中包含指向 TypeDescriptor 的指针
# x86 下 pTypeDescriptor 存的是绝对虚拟地址 = image_base + RVA
print("\n=== 搜索 CompleteObjectLocator ===")
print(f"（x86 下存绝对 VA，image_base=0x{image_base:x}）\n")

hits = []
for t, (td, td_rva) in td_offsets.items():
    if td_rva is None:
        continue
    abs_va = image_base + td_rva
    needle = struct.pack("<I", abs_va)

    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        # COL layout: vftable(4) signature(4) offset(4) cdOffset(4)
        #             pTypeDescriptor(4) pClassDescriptor(4) pSelf(4)
        # 所以 COL 起点 = 指针位置 - 16
        col = idx - 16
        if col >= 0:
            sig = struct.unpack_from("<I", data, col + 4)[0]
            off = struct.unpack_from("<I", data, col + 8)[0]
            cdo = struct.unpack_from("<I", data, col + 12)[0]
            pcls = struct.unpack_from("<I", data, col + 20)[0]
            hits.append((t.decode("ascii", "ignore"), col, sig, off, cdo, pcls))
        start = idx + 1

seen = set()
for name, col, sig, off, cdo, pcls in hits:
    if col in seen:
        continue
    seen.add(col)
    flag = "✓" if sig == 0 else "?"
    print(f"  {flag} COL@0x{col:08x} (RVA 0x{off_to_rva(col):08x})  "
          f"sig=0x{sig:x} offset=0x{off:x} cd=0x{cdo:x}  {name}")

# ── 由 COL 反查虚表：搜索指向 COL 的绝对指针
# 虚表布局：vtable[-1] = &COL，所以 vtable 起点 = 指针位置 + 4
print("\n=== 由 COL 反查虚表 ===")
col_offsets = {}
for name, col, sig, off, cdo, pcls in hits:
    if sig == 0:                       # 只保留签名正确的主 COL
        col_offsets.setdefault(name, col)

col_rvas = {}
for name, col in col_offsets.items():
    r = off_to_rva(col)
    if r is not None:
        col_rvas[col] = r

print(f"主 COL 数量: {len(col_rvas)}\n")

vtables = {}
for col, col_rva in sorted(col_rvas.items()):
    needle = struct.pack("<I", image_base + col_rva)
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        vt_off = idx + 4
        vt_rva = off_to_rva(vt_off)
        if vt_rva is not None:
            # 读前 8 个虚函数指针，过滤明显不合理的值
            funcs = []
            for k in range(8):
                fn = struct.unpack_from("<I", data, vt_off + k * 4)[0]
                funcs.append(fn)
            sane = all(0x1000 <= f < 0x1cf000 for f in funcs[:4])
            vtables.setdefault(col, []).append((vt_off, vt_rva, funcs, sane))
        start = idx + 1

for name, col in sorted(col_offsets.items(), key=lambda x: x[1]):
    entries = vtables.get(col, [])
    print(f"{name}")
    print(f"  COL RVA = 0x{off_to_rva(col):08x}")
    if not entries:
        print("    （未找到引用）")
        continue
    for vt_off, vt_rva, funcs, sane in entries:
        mark = "✓" if sane else "?"
        print(f"    {mark} vtable RVA 0x{vt_rva:08x}  "
              f"vf[0..3] = {', '.join(f'0x{f:x}' for f in funcs[:4])}")
    print()
