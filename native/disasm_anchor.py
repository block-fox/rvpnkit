"""Disassemble around candidate field-id immediates to reveal the record writer.

Known anchor: fid 0x01c9 (node connection IP string) occurs exactly ONCE in
RvRvpnGui.exe's .text, at RVA 0x0cd6fa.  If the wire record is
    03 | fid:u16 | len:u16 | utf16
then the code nearby should also emit 0x03 and manipulate a length.

We disassemble a window around each anchor and print it, plus a scan for the
literal 3-byte pattern `03 <fid_lo> <fid_hi>` which would be a direct
type+fid write.
"""
import struct
import capstone

BIN = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
data = open(BIN, "rb").read()

# ── PE 辅助
e = struct.unpack_from("<I", data, 0x3C)[0]
fh = e + 4
nsec = struct.unpack_from("<H", data, fh + 2)[0]
opt_size = struct.unpack_from("<H", data, fh + 16)[0]
opt = fh + 20
base = struct.unpack_from("<I", data, opt + 28)[0]
sec_off = opt + opt_size
secs = []
for i in range(nsec):
    s = sec_off + i * 40
    name = data[s:s + 8].rstrip(b"\0").decode("ascii", "ignore")
    vsize, vaddr, rawsize, raw = struct.unpack_from("<IIII", data, s + 8)
    secs.append((name, vaddr, vsize, raw, rawsize))


def rva2off(rva):
    for name, va, vs, raw, rs in secs:
        if va <= rva < va + max(vs, rs):
            return raw + (rva - va)
    return None


def off2rva(off):
    for name, va, vs, raw, rs in secs:
        if raw <= off < raw + rs:
            return va + (off - raw)
    return None


text = next(s for s in secs if s[0] == ".text")
_, t_va, t_vs, t_raw, t_rs = text
t_end = t_raw + t_rs

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

ANCHORS = [
    (0x0CD6FA, "fid 0x01c9 (节点连接IP str) —— GUI 中唯一一处"),
]

for rva, label in ANCHORS:
    off = rva2off(rva)
    if off is None:
        print(f"{label}: RVA 无法映射")
        continue

    print("=" * 74)
    print(f"{label}")
    print(f"  RVA 0x{rva:x}  文件偏移 0x{off:x}")
    print("=" * 74)

    # 打印周边原始字节
    lo = max(t_raw, off - 64)
    hi = min(t_end, off + 128)
    print("\n  原始字节：")
    for k in range(lo, hi, 16):
        chunk = data[k:k + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        mark = "  <== fid 0x01c9" if k <= off < k + 16 else ""
        print(f"    0x{off2rva(k):06x}  {hexs:<48}{mark}")

    # 反汇编一个较大窗口
    start = max(t_raw, off - 0x60)
    code = data[start:min(t_end, off + 0x80)]
    print(f"\n  反汇编（RVA 0x{off2rva(start):x} 起）：")
    for ins in md.disasm(code, base + off2rva(start)):
        rva_ins = ins.address - base
        mark = " ★" if abs(rva_ins - rva) <= 24 else ""
        print(f"    0x{rva_ins:06x}  {ins.mnemonic:<8} {ins.op_str}{mark}")
    print()

# ── 搜索「type=0x03 + fid 小端」的直接写入模式
print("=" * 74)
print("搜索字节模式 `03 <fid_lo> <fid_hi>`（type 与 fid 相邻写入）")
print("=" * 74)

FIDS = {
    0x01C9: "节点连接IP",
    0x01E1: "节点ID",
    0x01E9: "节点别名",
    0x01ED: "版本号",
    0x0105: "虚拟IP",
    0x00D6: "帧序号",
}

for fid, desc in FIDS.items():
    pat = bytes([0x03, fid & 0xFF, (fid >> 8) & 0xFF])
    hits = []
    pos = t_raw
    while True:
        i = data.find(pat, pos, t_end)
        if i < 0:
            break
        hits.append(off2rva(i))
        pos = i + 1
    if hits:
        print(f"  fid 0x{fid:04x} ({desc}): {len(hits)} 处 -> "
              + ", ".join(f"0x{h:x}" for h in hits[:6]))
    else:
        print(f"  fid 0x{fid:04x} ({desc}): 0 处")

# ── 也搜一下 0x04 + fid（u32 记录）
print()
for fid, desc in FIDS.items():
    pat = bytes([0x04, fid & 0xFF, (fid >> 8) & 0xFF])
    hits = []
    pos = t_raw
    while True:
        i = data.find(pat, pos, t_end)
        if i < 0:
            break
        hits.append(off2rva(i))
        pos = i + 1
    if hits:
        print(f"  [u32] fid 0x{fid:04x} ({desc}): {len(hits)} 处 -> "
              + ", ".join(f"0x{h:x}" for h in hits[:4]))
