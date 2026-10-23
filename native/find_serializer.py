"""Hunt for the command serializer by looking for known field-id immediates.

Idea: the code that builds wire records must materialise the field ids we have
already confirmed from captures (0x01c9 = node IP, 0x01e9 = alias, 0x0400 =
network name, 0x01ed = version).  In x86 machine code those appear as 32-bit
little-endian immediates, usually via `mov eax, imm32` (B8+r) or
`mov [mem], imm32` (C7 ...).

We also expect the type byte writes: 0x03 = string, 0x04 = u32.
Finding a function that contains several of these ids is almost certainly the
record writer.

Outputs the .text offsets of every hit so they can be disassembled next.
"""
import struct
import sys

BINARIES = [
    (r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe", "GUI"),
    (r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe", "Svc"),
]

# 已从真实抓包确认的字段号
KNOWN_FIDS = {
    0x01C9: "节点连接IP(str)",
    0x01E1: "节点ID(u64)",
    0x01E9: "节点别名(str)",
    0x01ED: "版本号(str)",
    0x0400: "网络名(str)",
    0x0105: "节点虚拟IP(16B)",
    0x00D6: "帧序号(u32)",
    0x005D: "超时15000",
    0x005E: "超时60000",
    0x005F: "超时300000",
}


def parse_pe(data):
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
    return base, secs


def rva_of(secs, off):
    for name, va, vs, raw, rs in secs:
        if raw <= off < raw + rs:
            return va + (off - raw)
    return None


for path, tag in BINARIES:
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        print(f"{tag}: 读取失败 {exc}")
        continue

    base, secs = parse_pe(data)
    text = next((s for s in secs if s[0] == ".text"), None)
    if not text:
        print(f"{tag}: 无 .text")
        continue
    _, t_va, t_vs, t_raw, t_rs = text
    t_end = t_raw + t_rs

    print("=" * 72)
    print(f"{tag}  {path}")
    print(f"  映像基址 0x{base:x}  .text raw 0x{t_raw:x}..0x{t_end:x}")
    print("=" * 72)

    # 对每个已知 fid，搜索其在 .text 中的 32 位立即数出现
    for fid, desc in sorted(KNOWN_FIDS.items()):
        imm = struct.pack("<I", fid)
        hits = []
        pos = t_raw
        while True:
            i = data.find(imm, pos, t_end)
            if i < 0:
                break
            hits.append(i)
            pos = i + 1
        if hits:
            rvas = [rva_of(secs, h) for h in hits]
            rva_txt = ", ".join(f"0x{r:x}" for r in rvas[:8] if r)
            print(f"  fid 0x{fid:04x} ({desc:<14}) {len(hits):>3} 处   RVA: {rva_txt}")
        else:
            print(f"  fid 0x{fid:04x} ({desc:<14})   0 处")

    # 找「同一函数内出现多个已知 fid」的聚集区
    print(f"\n  --- 聚集分析：以 256 字节窗口统计已知 fid 出现密度 ---")
    all_hits = []
    for fid in KNOWN_FIDS:
        imm = struct.pack("<I", fid)
        pos = t_raw
        while True:
            i = data.find(imm, pos, t_end)
            if i < 0:
                break
            all_hits.append((i, fid))
            pos = i + 1

    all_hits.sort()
    # 滑动窗口找密集区
    best = []
    win = 256
    for idx in range(len(all_hits)):
        start = all_hits[idx][0]
        cluster = [h for h in all_hits if start <= h[0] < start + win]
        if len(cluster) >= 2:
            best.append((len(cluster), start, cluster))

    best.sort(key=lambda x: (-x[0], x[1]))
    seen_windows = []
    for cnt, start, cluster in best[:6]:
        if any(abs(start - w) < 128 for w in seen_windows):
            continue
        seen_windows.append(start)
        rva = rva_of(secs, start)
        ids = ", ".join(f"0x{f:04x}" for _, f in cluster)
        print(f"    窗口 RVA 0x{rva:x}: {cnt} 个已知 fid  ({ids})")

    print()
