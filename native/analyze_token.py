"""分析密码令牌的结构。

已知两组样本：
  sky的网络          密码 "123456"    → 28 字节
  东北雨姐四十八码大汗脚  密码 "Aa022033" → 36 字节

28 = 4 + 6*4
36 = 4 + 8*4

所以结构像是：[4 字节初始值] + 每个字符 4 字节（链式）。
如果每步是 CRC32 之类的 4 字节函数，就能完整复现。
"""

import struct
import zlib

S1 = bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")
P1 = "123456"
N1 = "sky的网络"

S2 = bytes.fromhex(
    "4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c"
)
P2 = "Aa022033"
N2 = "东北雨姐四十八码大汗脚"


def blocks(tok):
    """切成 [头 4 字节] + 每 4 字节一块"""
    return tok[:4], [tok[4 + i * 4: 8 + i * 4] for i in range((len(tok) - 4) // 4)]


h1, b1 = blocks(S1)
h2, b2 = blocks(S2)
print(f"样本1 头={h1.hex()}  块数={len(b1)}  密码 {P1!r}")
print(f"样本2 头={h2.hex()}  块数={len(b2)}  密码 {P2!r}\n")


def crc32_variants(prev: bytes, ch: str):
    """给定上一块和字符，产出各种 CRC32 组合的候选值"""
    c = ch.encode()
    c_le = ch.encode("utf-16-le")
    c_be = ch.encode("utf-16-be")
    outs = {}
    for hname, hb in (("prev_be", prev), ("prev_le", prev[::-1])):
        for cname, cb in (("ascii", c), ("u16le", c_le), ("u16be", c_be), ("none", b"")):
            outs[f"crc32({hname}+{cname})"] = zlib.crc32(hb + cb) & 0xFFFFFFFF
            outs[f"crc32({cname}+{hname})"] = zlib.crc32(cb + hb) & 0xFFFFFFFF
            outs[f"crc32({hname}^{cname})"] = zlib.crc32(bytes(a ^ b for a, b in
                                                              zip(hb.ljust(4, b"\0"), cb.ljust(4, b"\0"))))
    return outs


def check_chain(pw, head, blks, label):
    print(f"--- {label} 首步 ---")
    want = blks[0].hex()
    print(f"  目标: {want}")
    cands = crc32_variants(head, pw[0])
    for name, v in cands.items():
        got = struct.pack(">I", v)
        if got == blks[0] or got[::-1] == blks[0]:
            print(f"  ★ HIT {name} -> {got.hex()}{' (字节序反转)' if got[::-1]==blks[0] else ''}")
    # 全链验证
    for name, v in crc32_variants(head, pw[0]).items():
        for endian in ("big", "little"):
            prev = head
            ok = True
            for i, ch in enumerate(pw):
                val = zlib.crc32(
                    (prev if "prev_le" not in name else prev[::-1])
                    + {"ascii": ch.encode(),
                       "u16le": ch.encode("utf-16-le"),
                       "u16be": ch.encode("utf-16-be"),
                       "none": b""}[name.split("+")[1].rstrip(")") if False else "ascii"]
                ) if False else None
                break
            break
    print()


check_chain(P1, h1, b1, "样本1 (123456)")
check_chain(P2, h2, b2, "样本2 (Aa022033)")

# 先把最朴素的几种按整条链验证一遍
def try_scheme(name, fn):
    for pw, head, blks in ((P1, h1, b1), (P2, h2, b2)):
        prev = head
        ok = True
        for i, ch in enumerate(pw):
            val = fn(prev, ch)
            got = struct.pack(">I", val & 0xFFFFFFFF)
            alt = got[::-1]
            if got != blks[i] and alt != blks[i]:
                ok = False
                break
            prev = blks[i]
        if not ok:
            return
    print(f"  ★★★ 完整命中: {name}")


print("=== 整链验证 ===")
combos = []
for cname, cb_of in (
    ("ascii", lambda ch: ch.encode()),
    ("u16le", lambda ch: ch.encode("utf-16-le")),
    ("u16be", lambda ch: ch.encode("utf-16-be")),
):
    for order in ("prev+ch", "ch+prev"):
        for endian in ("big", "little"):
            def mk(cb_of=cb_of, order=order, endian=endian):
                def fn(prev, ch):
                    cb = cb_of(ch)
                    pv = prev if endian == "big" else prev[::-1]
                    data = pv + cb if order == "prev+ch" else cb + pv
                    return zlib.crc32(data)
                return fn
            combos.append((f"crc32 {order} {endian} {cname}", mk()))

for name, fn in combos:
    try_scheme(name, fn)

print("\n=== 其他 4 字节函数 ===")


def adler(prev, ch, endian="big", order="prev+ch", enc="ascii"):
    cb = ch.encode(enc)
    pv = prev if endian == "big" else prev[::-1]
    data = pv + cb if order == "prev+ch" else cb + pv
    return zlib.adler32(data)


for enc in ("ascii", "utf-16-le", "utf-16-be"):
    for order in ("prev+ch", "ch+prev"):
        for endian in ("big", "little"):
            try_scheme(f"adler32 {order} {endian} {enc}",
                       lambda p, c, e=endian, o=order, n=enc: adler(p, c, e, o, n))

# 头是怎么来的？试着看它是否与网络名/密码相关
print("\n=== 头部尝试 ===")
for hname, hv in (
    ("crc32(网络名 ascii)", zlib.crc32(N1.encode()) & 0xFFFFFFFF),
    ("crc32(网络名 utf16be)", zlib.crc32(N1.encode("utf-16-be")) & 0xFFFFFFFF),
    ("crc32(密码)", zlib.crc32(P1.encode()) & 0xFFFFFFFF),
    ("crc32(空)", 0),
):
    print(f"  {hname:<24} {struct.pack('>I', hv).hex()}   期望 {h1.hex()}"
          f"  {'★' if struct.pack('>I', hv) == h1 else ''}")
