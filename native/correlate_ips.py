"""Extract all readable UTF-16LE strings from a live pipe snapshot, then try to
correlate node aliases with virtual IPs.

Earlier attempt found 0 strings because the character filter was too narrow
(ASCII only).  The snapshot actually contains CJK aliases, so the filter must
accept any printable Unicode code unit.
"""
import ctypes
import ctypes.wintypes as wt
import re
import time
import unicodedata

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

print("=== 抓取控制管道状态流 ===")
h = None
for _ in range(8):
    h = k32.CreateFileW(PIPE, R, 0, None, OPEN_EXISTING, 0, None)
    if h not in (INV, None):
        break
    time.sleep(0.5)
if h in (INV, None):
    raise SystemExit("连接失败 err=%d" % ctypes.get_last_error())
print("  ✓ 已连接")

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
print(f"  读到 {len(data):,} 字节\n")


def printable(cp: int) -> bool:
    """是否可出现在正常文本里（排除控制符、私用区、未分配）。"""
    if cp == 0:
        return False
    ch = chr(cp)
    if ch in "\t\r\n":
        return True
    cat = unicodedata.category(ch)
    if cat.startswith("C"):          # Cc/Cf/Cs/Co/Cn 一律排除
        return False
    return True


def utf16_runs(b, minlen=4, maxlen=200):
    """扫描所有 UTF-16LE 可读游程。"""
    out = []
    i = 0
    n = len(b)
    while i + 2 <= n:
        chars = []
        j = i
        while j + 2 <= n and len(chars) < maxlen:
            cp = b[j] | (b[j + 1] << 8)
            if printable(cp):
                chars.append(chr(cp))
                j += 2
            else:
                break
        s = "".join(chars).strip()
        if len(s) >= minlen:
            out.append((i, s))
            i = j if j > i else i + 2
        else:
            i += 2
    return out


strings = utf16_runs(data)
print(f"=== 提取到 {len(strings)} 条 UTF-16 字符串 ===\n")

IPV4 = re.compile(r"\b(26\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
CONN = re.compile(r"([\[\]\d\.:]+):(\d+)\s*->\s*([\[\]\d\.:]+):(\d+)")
HOST = re.compile(r"^[A-Za-z0-9_\-\.\u4e00-\u9fff \[\]\(\)!！?，。、~]{3,60}$")

ips = {}
conns = []
hosts = []
for off, s in strings:
    for m in IPV4.finditer(s):
        ips.setdefault(m.group(1), []).append(off)
    m = CONN.search(s)
    if m:
        conns.append((off, m.group(1), int(m.group(2)), m.group(3), int(m.group(4)), s))
    if HOST.match(s) and not s.replace(".", "").isdigit():
        hosts.append((off, s))

print(f"虚拟 IP (26.x)：{len(ips)} 个唯一值")
for ip in sorted(ips, key=lambda x: [int(p) for p in x.split(".")])[:25]:
    print(f"   {ip:<18} 出现 {len(ips[ip])} 次 @ " +
          ", ".join(f"0x{o:x}" for o in ips[ip][:3]))

print(f"\n连接元组：{len(conns)} 条")
for off, a, ap, b2, bp, raw in conns[:15]:
    print(f"   @0x{off:06x}  {a}:{ap} -> {b2}:{bp}")

print(f"\n疑似别名/主机名：{len(hosts)} 条")
for off, s in hosts[:25]:
    print(f"   @0x{off:06x}  {s}")

# ── 关键：检查是否存在「别名与 26.x IP 在同一小窗口内」的强关联
print("\n" + "=" * 70)
print("关联分析：别名 与 26.x IP 在 512 字节窗口内共现")
print("=" * 70)

ip_positions = []
for ip, offs in ips.items():
    for o in offs:
        ip_positions.append((o, ip))
ip_positions.sort()

pairs = []
for off, host in hosts:
    near = [(o, ip) for o, ip in ip_positions if abs(o - off) <= 512]
    if near:
        pairs.append((host, off, near[:3]))

if pairs:
    print(f"发现 {len(pairs)} 组共现：")
    for host, off, near in pairs[:20]:
        locs = ", ".join(f"{ip}@0x{o:x}" for o, ip in near)
        print(f"   '{host}' @0x{off:06x}  ←→  {locs}")
    print("\n★ 若共现稳定，即可用「邻近性」建立 别名↔IP 映射。")
else:
    print("未发现别名与 26.x IP 在 512 字节内共现。")
    print("→ 说明别名与 IP 在报文里相距很远，需要完整解析容器才能配对。")
