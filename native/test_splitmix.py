"""用三组样本测试：令牌是不是 splitmix64 链。

二进制里确认存在 splitmix64（0xf5f70，常量与标准实现完全一致）：
    z = x + 0x9E3779B97F4A7C15
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    return z ^ (z >> 31)

令牌 = 4 字节 IV + 每字符 4 字节。试探各种「把字符喂进 splitmix64」的方式。
"""

import struct

M64 = (1 << 64) - 1

SAMPLES = [
    ("123456",
     bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")),
    ("Aa022033",
     bytes.fromhex("4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c")),
    ("deepseektester",
     bytes.fromhex("cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941ab37a9151b902273"
                   "4e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37")),
]


def splitmix64(x):
    z = (x + 0x9E3779B97F4A7C15) & M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


def mix32_plain(z):
    """不加减法，只做混合（如果调用方已经自己加了 gamma）"""
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return (z ^ (z >> 31)) & M64


CHAINS = []
for pw, tok in SAMPLES:
    assert len(tok) == 4 * len(pw) + 4
    CHAINS.append((pw, tok[:4], [tok[4 + i * 4:8 + i * 4] for i in range(len(pw))]))

TRANS = []
for pw, head, blks in CHAINS:
    prev = head
    for ch, b in zip(pw, blks):
        TRANS.append((prev, ch, b))
        prev = b


def test(name, fn):
    for endian in ("big", "little"):
        ok = True
        for prev, ch, want in TRANS:
            try:
                v = fn(prev, ch) & 0xFFFFFFFF
            except Exception:
                ok = False
                break
            got = struct.pack(">I" if endian == "big" else "<I", v)
            if got != want:
                ok = False
                break
        if ok:
            print(f"  ★★★ 命中: {name}   字节序={endian}")
            return True
    return False


def u32(b):
    return int.from_bytes(b, "big")


def u32le(b):
    return int.from_bytes(b, "little")


CH = {
    "ord": lambda c: ord(c),
    "u16le": lambda c: int.from_bytes(c.encode("utf-16-le"), "little"),
    "u16be": lambda c: int.from_bytes(c.encode("utf-16-be"), "big"),
}

hits = 0
for cname, cf in CH.items():
    cases = {
        "sm64(prev+c)": lambda p, c, cf=cf: splitmix64(u32(p) + cf(c)),
        "sm64(prev+c) hi": lambda p, c, cf=cf: splitmix64(u32(p) + cf(c)) >> 32,
        "sm64(prev^c)": lambda p, c, cf=cf: splitmix64(u32(p) ^ cf(c)),
        "sm64(prev^c) hi": lambda p, c, cf=cf: splitmix64(u32(p) ^ cf(c)) >> 32,
        "sm64((prev<<8)+c)": lambda p, c, cf=cf: splitmix64((u32(p) << 8) + cf(c)),
        "sm64(prev*C+c)": lambda p, c, cf=cf: splitmix64((u32(p) * 0x9E3779B1 + cf(c)) & M64),
        "sm64(c<<32|prev)": lambda p, c, cf=cf: splitmix64((cf(c) << 32) | u32(p)),
        "sm64(prev+ch) le": lambda p, c, cf=cf: splitmix64(u32le(p) + cf(c)),
    }
    for name, fn in cases.items():
        hits += test(f"{name} [{cname}]", fn)

    # 两轮 splitmix
    cases2 = {
        "sm64(sm64(prev+c))": lambda p, c, cf=cf: splitmix64(splitmix64(u32(p) + cf(c))),
        "sm64(sm64(prev+c)) hi": lambda p, c, cf=cf: splitmix64(splitmix64(u32(p) + cf(c))) >> 32,
    }
    for name, fn in cases2.items():
        hits += test(f"{name} [{cname}]", fn)

print(f"\n共 {len(TRANS)} 个转移，命中 {hits} 个")
