"""Scan for vtables by structural pattern, then map them back to RTTI names.

A vtable looks like:  vtable[-1] = &CompleteObjectLocator (points into the COL
cluster), vtable[0..] = function pointers (point into .text).  Scanning for that
shape finds the vtables without needing to guess relocation behaviour.
"""
import struct

PATH = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
data = open(PATH, "rb").read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
fh = e_lfanew + 4
machine, nsec = struct.unpack_from("<HH", data, fh)
opt_size = struct.unpack_from("<H", data, fh + 16)[0]
opt = fh + 20
image_base = struct.unpack_from("<I", data, opt + 28)[0]
sec_off = opt + opt_size

sections = []
for i in range(nsec):
    s = sec_off + i * 40
    name = data[s:s + 8].rstrip(b"\0").decode("ascii", "ignore")
    vsize, vaddr, rawsize, raw = struct.unpack_from("<IIII", data, s + 8)
    sections.append((name, vaddr, vsize, raw, rawsize))

TEXT_LO, TEXT_HI = 0x1000, 0x1cf000
COL_LO, COL_HI = 0xcc0000, 0xcc0c00


def off_to_rva(off):
    for name, va, vs, raw, rs in sections:
        if raw <= off < raw + rs:
            return va + (off - raw)
    return None


# 收集所有 COL 的 RVA，便于反查类名
col_name = {}
for i in range(len(data) - 8):
    pass  # 占位：改为直接解析已知 COL

# 已知的主 COL（来自上一步分析）
KNOWN_COL = {
    0xcc024c: "CAbstractNetworkServiceCommand",
    0xcc030c: "CAbstractNodeServiceCommand",
    0xcc05bc: "CChatGetNodesServiceCommand",
    0xcc0624: "CCreateNetworkServiceCommand",
    0xcc068c: "CEnableNetworkServiceCommand",
    0xcc06f8: "CEnumPublicNetworksServiceCommand",
    0xcc0760: "CJoinNetworkServiceCommand",
    0xcc0968: "CUpdateNetworkServiceCommand",
    0xcc09d4: "CUpdateVisibleNodesServiceCommand",
    # 次 COL（多继承/虚继承情形）
    0xcc0278: "CAbstractNetworkServiceCommand*",
    0xcc033c: "CAbstractNodeServiceCommand*",
    0xcc05e8: "CChatGetNodesServiceCommand*",
    0xcc0650: "CCreateNetworkServiceCommand*",
    0xcc06bc: "CEnableNetworkServiceCommand*",
    0xcc0724: "CEnumPublicNetworksServiceCommand*",
    0xcc078c: "CJoinNetworkServiceCommand*",
    0xcc0998: "CUpdateNetworkServiceCommand*",
    0xcc0a00: "CUpdateVisibleNodesServiceCommand*",
}

print("=== 按结构模式扫描虚表 ===")
print(f"映像基址: 0x{image_base:08x}")
print(f".text 节 RVA 区间:   0x{TEXT_LO:x} .. 0x{TEXT_HI:x}")
print(f"COL 节 RVA 区间:     0x{COL_LO:x} .. 0x{COL_HI:x}")
print("注意：虚表项存的是绝对 VA = image_base + RVA\n")

# 关键：文件里存的是绝对 VA，不是 RVA
TEXT_VA_LO, TEXT_VA_HI = image_base + TEXT_LO, image_base + TEXT_HI
COL_VA_LO, COL_VA_HI = image_base + COL_LO, image_base + COL_HI

found = []
step = 4
for off in range(step, len(data) - 8 * step, step):
    prev = struct.unpack_from("<I", data, off - step)[0]
    first = struct.unpack_from("<I", data, off)[0]

    if not (COL_VA_LO <= prev < COL_VA_HI):
        continue
    if not (TEXT_VA_LO <= first < TEXT_VA_HI):
        continue

    funcs = []
    ok = True
    for k in range(6):
        f = struct.unpack_from("<I", data, off + k * step)[0]
        if not (TEXT_VA_LO <= f < TEXT_VA_HI):
            ok = False
            break
        funcs.append(f - image_base)     # 转回 RVA 便于阅读
    if not ok or len(funcs) < 4:
        continue

    vt_rva = off_to_rva(off)
    if vt_rva is None:
        continue

    n = 0
    while n < 32:
        f = struct.unpack_from("<I", data, off + n * step)[0]
        if not (TEXT_VA_LO <= f < TEXT_VA_HI):
            break
        n += 1

    found.append((vt_rva, prev - image_base, funcs, n))

print(f"共找到 {len(found)} 个候选虚表\n")

named = []
for vt_rva, col_rva, funcs, n in found:
    name = KNOWN_COL.get(col_rva)
    if name:
        named.append((name, vt_rva, col_rva, funcs, n))

print("=== 与已知命令类对应的虚表 ===")
for name, vt_rva, col_rva, funcs, n in sorted(named):
    print(f"  {name}")
    print(f"    虚表 RVA = 0x{vt_rva:08x}   COL RVA = 0x{col_rva:08x}   虚函数数 = {n}")
    print(f"    vf[0..3] RVA: {', '.join(f'0x{f:x}' for f in funcs[:4])}")

print(f"\n匹配到 {len(named)} 个命令类的虚表")
if not named:
    print("未匹配 —— 下一步改用直接反汇编搜索序列化代码")
