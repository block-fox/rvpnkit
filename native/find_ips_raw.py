"""Locate virtual IPs in the raw pipe stream by byte pattern, bypassing text
decoding entirely.

The neighbour table gives us the authoritative set of live virtual IPs.  Each
IPv4 (e.g. 26.169.61.178) may appear in the stream as:
    - 4 raw bytes:            1a a9 3d b2
    - UTF-16LE text:          32 00 36 00 2e 00 ...
    - inside a 16-byte blob:  usually 00*12 + the 4 bytes

Searching for the raw 4-byte form across the whole stream tells us definitively
whether the snapshot carries per-node virtual addresses at all.
"""
import ctypes
import ctypes.wintypes as wt
import struct
import time
import subprocess

# ── 1. 从网卡邻居表拿当前活跃的虚拟 IP（权威来源）
r = subprocess.run(
    ["powershell", "-NoProfile", "-Command",
     "Get-NetNeighbor -InterfaceAlias 'Radmin VPN' -ErrorAction SilentlyContinue | "
     "Where-Object { $_.IPAddress -like '26.*' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } | "
     "Select-Object -ExpandProperty IPAddress"],
    capture_output=True, text=True, errors="ignore")
live_ips = [ln.strip() for ln in r.stdout.splitlines() if ln.strip().count(".") == 3]
print(f"=== 邻居表中的活跃虚拟 IP: {len(live_ips)} 个 ===")
for ip in live_ips[:10]:
    print("   ", ip)

# ── 2. 抓管道流
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                         ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
GENERIC_READ, OPEN_EXISTING = 0x80000000, 3

print("\n=== 抓取管道流 ===")
h = None
for _ in range(8):
    h = k32.CreateFileW(PIPE, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    if h not in (INV, None):
        break
    time.sleep(0.5)
if h in (INV, None):
    raise SystemExit("连接失败")
chunks, buf = [], ctypes.create_string_buffer(65536)
deadline = time.time() + 7
while time.time() < deadline:
    got = wt.DWORD(0)
    if k32.ReadFile(h, buf, 65536, ctypes.byref(got), None) and got.value:
        chunks.append(buf.raw[:got.value])
    else:
        break
k32.CloseHandle(h)
data = b"".join(chunks)
print(f"  读到 {len(data):,} 字节")

# ── 3. 对每个活跃 IP，搜索三种形态
print("\n=== 逐个活跃 IP 在流中的出现形态 ===")
print(f"  {'IP':<17} {'原始4字节':>10} {'UTF16文本':>10} {'blob尾部':>10}")
print(f"  {'-'*16} {'-'*10} {'-'*10} {'-'*10}")

found_raw = 0
found_txt = 0
found_blob = 0
details = []

for ip in live_ips[:60]:
    parts = [int(x) for x in ip.split(".")]
    raw = bytes(parts)
    txt = ip.encode("utf-16-le")
    blob = b"\x00" * 12 + raw

    n_raw = data.count(raw)
    n_txt = data.count(txt)
    n_blob = data.count(blob)

    if n_raw or n_txt or n_blob:
        details.append((ip, n_raw, n_txt, n_blob))
    found_raw += 1 if n_raw else 0
    found_txt += 1 if n_txt else 0
    found_blob += 1 if n_blob else 0

for ip, a, b, c in details[:30]:
    print(f"  {ip:<17} {a:>10} {b:>10} {c:>10}")

print(f"\n汇总（前 60 个活跃 IP 中）：")
print(f"  以原始 4 字节出现: {found_raw} 个")
print(f"  以 UTF-16 文本出现: {found_txt} 个")
print(f"  以 16 字节 blob 出现: {found_blob} 个")

# ── 4. 不管活跃与否，流里到底有没有 26.x 的 4 字节形态
print("\n=== 流中所有形如 26.x.x.x 的 4 字节序列 ===")
hits = []
i = 0
while i < len(data) - 3:
    if data[i] == 26:
        b1, b2, b3 = data[i + 1], data[i + 2], data[i + 3]
        if b1 <= 255 and b2 <= 255 and b3 <= 255:
            # 排除明显的非地址（如全 0 或多字节可打印）
            candidate = f"26.{b1}.{b2}.{b3}"
            hits.append((i, candidate))
    i += 1

# 去重前 40 个
seen = set()
uniq = []
for off, c in hits:
    if c not in seen:
        seen.add(c)
        uniq.append((off, c))

print(f"  共 {len(hits)} 处，{len(uniq)} 个唯一值（前 30）")
for off, c in uniq[:30]:
    print(f"     0x{off:06x}  {c}")
