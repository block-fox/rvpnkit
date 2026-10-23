"""Refine the alias<->IP map using the observed delta clustering.

Observation: many correct-looking pairs have delta in 57..97, which suggests a
stable record layout where the alias precedes the 4-byte IP by a fixed-ish
amount.  Pairs whose delta falls outside the dominant cluster are likely noise
(adjacent record's alias, or a garbled UTF-16 decode).

This script:
  1. histograms the delta values to find the dominant cluster
  2. keeps only pairs inside it
  3. reports the resulting map with a confidence marker
"""
import bisect
import collections
import ctypes
import ctypes.wintypes as wt
import re
import time
import unicodedata

# ── 抓流
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                         ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
R, OPEN_EXISTING = 0x80000000, 3

h = None
for _ in range(8):
    h = k32.CreateFileW(PIPE, R, 0, None, OPEN_EXISTING, 0, None)
    if h not in (INV, None):
        break
    time.sleep(0.5)
if h in (INV, None):
    raise SystemExit("连接失败")

chunks, buf = [], ctypes.create_string_buffer(65536)
deadline = time.time() + 8
while time.time() < deadline:
    got = wt.DWORD(0)
    if k32.ReadFile(h, buf, 65536, ctypes.byref(got), None) and got.value:
        chunks.append(buf.raw[:got.value])
    else:
        break
k32.CloseHandle(h)
data = b"".join(chunks)
print(f"管道流: {len(data):,} 字节\n")


def printable(cp):
    if cp < 0x20 or cp == 0x7F:
        return False
    ch = chr(cp)
    if ch in "\t\r\n":
        return True
    cat = unicodedata.category(ch)
    return not (cat.startswith("C") or cat.startswith("Z"))


def utf16_runs(b, minlen=2, maxlen=80):
    out = []
    for phase in (0, 1):
        i, n = phase, len(b)
        while i + 2 <= n:
            chars, j = [], i
            while j + 2 <= n and len(chars) < maxlen:
                cp = b[j] | (b[j + 1] << 8)
                if printable(cp):
                    chars.append(chr(cp)); j += 2
                else:
                    break
            s = "".join(chars).strip()
            if len(s) >= minlen:
                out.append((i, s)); i = j if j > i else i + 2
            else:
                i += 2
    out.sort()
    return out


strings = utf16_runs(data)

# 别名：必须含 ASCII 字母数字或常见中文，且不是纯乱码
GOOD = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fff\u0400-\u04ff\-\. \[\]\(\)!！?，。、~§]{2,60}$")
names = [(o, s) for o, s in strings
         if GOOD.match(s)
         and not re.fullmatch(r"[0-9a-fA-F:\.]+", s)
         and any(c.isalnum() for c in s)]
print(f"别名候选: {len(names)}")

# 4 字节虚拟 IP
ip_pos = []
i = 0
while i < len(data) - 3:
    if data[i] == 26:
        ip = f"26.{data[i+1]}.{data[i+2]}.{data[i+3]}"
        if not (data[i+1] == data[i+2] == data[i+3] == 0):
            ip_pos.append((i, ip))
    i += 1
print(f"虚拟 IP 锚点: {len(ip_pos)}\n")

name_offsets = [o for o, _ in names]

# ── 收集所有候选配对及其 delta
cands = []
for ip_off, ip in ip_pos:
    k = bisect.bisect_left(name_offsets, ip_off)
    for idx in range(max(0, k - 4), min(len(names), k + 4)):
        off, s = names[idx]
        d = abs(off - ip_off)
        if d <= 300:
            cands.append((ip, s, off, ip_off, d, off < ip_off))

print(f"候选配对: {len(cands)}")

# ── delta 直方图，找主簇
hist = collections.Counter()
for *_, d, _rel in cands:
    hist[d // 5 * 5] += 1

print("\n=== delta 分布（5 字节分桶，前 12）===")
for bucket, cnt in hist.most_common(12):
    bar = "█" * min(60, cnt // 2)
    print(f"  {bucket:>4}-{bucket+4:<4} {cnt:>5}  {bar}")

# 主簇：取出现最多的桶及其邻域
if not hist:
    raise SystemExit("无候选")

top_bucket = hist.most_common(1)[0][0]
lo, hi = max(0, top_bucket - 10), top_bucket + 15
print(f"\n主簇区间: {lo}..{hi} 字节")

filtered = [c for c in cands if lo <= c[4] <= hi]
print(f"主簇内配对: {len(filtered)}")

# ── 每个 IP 只保留 delta 最接近主簇中心的一条
center = sum(c[4] for c in filtered) / max(1, len(filtered))
print(f"主簇中心 delta ≈ {center:.0f}\n")

best = {}
for ip, s, off, ip_off, d, rel in filtered:
    score = abs(d - center)
    if ip not in best or score < best[ip][0]:
        best[ip] = (score, s, off, d, rel)

print("=== 高置信度 IP ←→ 别名 映射 ===")
print(f"  {'虚拟 IP':<17} {'别名':<28} {'delta':>6}  位置")
print(f"  {'-'*16} {'-'*27} {'-'*6}  {'-'*6}")
for ip in sorted(best, key=lambda x: [int(p) for p in x.split(".")]):
    score, s, off, d, rel = best[ip]
    where = "别名先" if rel else "IP 先"
    print(f"  {ip:<17} {s:<28} {d:>6}  {where}")

print(f"\n共建立 {len(best)} 条映射")

# ── 输出成便于程序使用的格式
print("\n=== 可嵌入客户端的映射（Python dict 字面量）===")
print("IP_TO_ALIAS = {")
for ip in sorted(best, key=lambda x: [int(p) for p in x.split(".")])[:40]:
    _, s, _, _, _ = best[ip]
    esc = s.replace('"', '\\"')
    print(f'    "{ip}": "{esc}",')
print("}")
