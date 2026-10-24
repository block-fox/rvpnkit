"""用三组样本（共 28 个转移）暴力测试链式函数。

已知结构：令牌 = [4 字节头] + 每字符 4 字节
  样本1  "123456"        → 6 块
  样本2  "Aa022033"      → 8 块
  样本3  "deepseektester" → 14 块  （来自创建请求的 60 字节块）

头每次不同，说明它是随机 IV / 盐；链函数 F(prev, char) 应当一致。
只要找对 F，就能从密码算出令牌。
"""

import struct
import zlib

SAMPLES = [
    ("123456",
     bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")),
    ("Aa022033",
     bytes.fromhex("4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c")),
    ("deepseektester",
     bytes.fromhex("cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941ab37a9151b902273"
                   "4e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37")),
]

CHAINS = []
for pw, tok in SAMPLES:
    assert len(tok) == 4 * len(pw) + 4, f"{pw!r} 长度不符: {len(tok)} vs {4*len(pw)+4}"
    CHAINS.append((pw, tok[:4], [tok[4 + i * 4:8 + i * 4] for i in range(len(pw))]))

print("样本校验通过：")
for pw, head, blks in CHAINS:
    print(f"  {pw!r:<18} 头={head.hex()}  块数={len(blks)}")

TRANSITIONS = []
for pw, head, blks in CHAINS:
    prev = head
    for ch, b in zip(pw, blks):
        TRANSITIONS.append((prev, ch, b))
        prev = b
print(f"\n共 {len(TRANSITIONS)} 个转移\n")

M = 0xFFFFFFFF


def test(name, fn):
    """对全部 28 个转移验证 fn(prev, char) == 块（允许大端/小端两种字节序）"""
    for endian in ("big", "little"):
        ok = True
        for prev, ch, want in TRANSITIONS:
            try:
                v = fn(prev, ch) & M
            except Exception:
                ok = False
                break
            got = struct.pack(">I" if endian == "big" else "<I", v & 0xFFFFFFFF)
            if got != want:
                ok = False
                break
        if ok:
            print(f"  ★★★ 完整命中: {name}  字节序={endian}")
            return True
    return False


ENCODINGS = {
    "ascii": lambda ch: ord(ch) & 0xFF,
    "utf16le": lambda ch: struct.unpack("<H", ch.encode("utf-16-le"))[0],
    "utf16be": lambda ch: struct.unpack(">H", ch.encode("utf-16-be"))[0],
    "index": None,  # 占位
}

PRIMES = [31, 33, 37, 131, 1313, 65599, 16777619, 2654435761, 2246822519, 3266489917]

hits = 0

# 1) 乘法 + 加法 / 异或
for enc_name, enc in ENCODINGS.items():
    if enc is None:
        continue
    for mul in PRIMES:
        def f_add(prev, ch, mul=mul, enc=enc):
            return int.from_bytes(prev, "big") * mul + enc(ch)

        def f_xor(prev, ch, mul=mul, enc=enc):
            return (int.from_bytes(prev, "big") ^ enc(ch)) * mul

        def f_sub(prev, ch, mul=mul, enc=enc):
            return int.from_bytes(prev, "big") * mul - enc(ch)

        def f_fnv(prev, ch, mul=mul, enc=enc):
            return (int.from_bytes(prev, "big") * mul) ^ enc(ch)

        for nm, fn in (("mul+add", f_add), ("(x^c)*mul", f_xor),
                       ("mul-sub", f_sub), ("mul^c", f_fnv)):
            hits += test(f"{nm} mul={mul} enc={enc_name}", fn)

# 2) CRC32 / adler
for enc_name, enc in ENCODINGS.items():
    if enc is None:
        continue
    def mk_crc(enc=enc, order="prev+ch"):
        def fn(prev, ch):
            c = bytes([enc(ch) & 0xFF]) if enc_name == "ascii" else struct.pack(">H", enc(ch))
            data = prev + c if order == "prev+ch" else c + prev
            return zlib.crc32(data)
        return fn
    hits += test(f"crc32 prev+ch enc={enc_name}", mk_crc(order="prev+ch"))
    hits += test(f"crc32 ch+prev enc={enc_name}", mk_crc(order="ch+prev"))

# 3) 简单移位/旋转
for k in range(1, 32):
    def f_rot(prev, ch, k=k):
        v = int.from_bytes(prev, "big")
        r = ((v << k) | (v >> (32 - k))) & M
        return r ^ ord(ch)

    hits += test(f"rotl({k})^c", f_rot)

    def f_shr(prev, ch, k=k):
        return (int.from_bytes(prev, "big") >> k) ^ ord(ch)

    hits += test(f">>{k}^c", f_shr)

print(f"\n共试 {len(TRANSITIONS)} 个转移 × 多种函数，命中 {hits} 个")
