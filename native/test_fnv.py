"""验证：令牌 = FNV-1a 滚动哈希，每个字符后输出一次 32 位状态。

结构完全对得上：
  * 令牌 = 4 字节 IV + 每字符 4 字节
  * FNV-1a 的状态是 32 位
  * 每喂入一个字符（UTF-16 的 2 个字节）后取一次状态
  * 同一字符在不同位置结果不同 —— 因为状态是滚动的

二进制里确实有 FNV-1a（0x811c9dc5 基数 + 0x1000193 乘数）。
"""

import struct

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193
M32 = 0xFFFFFFFF

SAMPLES = [
    ("123456",
     bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")),
    ("Aa022033",
     bytes.fromhex("4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c")),
    ("deepseektester",
     bytes.fromhex("cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941ab37a9151b902273"
                   "4e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37")),
]


def fnv1a_bytes(h, data):
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & M32
    return h


def fnv1_bytes(h, data):
    for b in data:
        h = ((h * FNV_PRIME) & M32) ^ b
    return h


def token(pw, iv, *, seed_mode, char_bytes, fn, out_endian):
    h = iv
    if seed_mode == "xor_basis":
        h = (iv ^ FNV_OFFSET) & M32
    elif seed_mode == "basis_xor":
        h = (FNV_OFFSET ^ iv) & M32
    elif seed_mode == "add_basis":
        h = (iv + FNV_OFFSET) & M32

    out = bytearray()
    out += struct.pack(">I" if out_endian == "big" else "<I", iv)
    for ch in pw:
        h = fn(h, ch.encode(char_bytes))
        out += struct.pack(">I" if out_endian == "big" else "<I", h)
    return bytes(out)


def main():
    variants = []
    for fn_name, fn in (("fnv1a", fnv1a_bytes), ("fnv1", fnv1_bytes)):
        for cb in ("utf-16-le", "utf-16-be"):
            for sm in ("direct", "xor_basis", "add_basis"):
                for oe in ("big", "little"):
                    variants.append((f"{fn_name} {cb} seed={sm} out={oe}", fn, cb, sm, oe))

    hit = 0
    for name, fn, cb, sm, oe in variants:
        ok = True
        for pw, tok in SAMPLES:
            iv = tok[:4]
            got = token(pw, int.from_bytes(iv, "big"), seed_mode=sm,
                        char_bytes=cb, fn=fn, out_endian=oe)
            if got != tok:
                ok = False
                break
        if ok:
            print(f"  ★★★ 命中: {name}")
            hit += 1

    if not hit:
        print(f"没命中（试了 {len(variants)} 种）\n")
        # 打印第一个样本的第一步，方便人工看差在哪
        pw, tok = SAMPLES[0]
        iv = int.from_bytes(tok[:4], "big")
        want = tok[4:8]
        print(f'样本 "{pw}"  IV={tok[:4].hex()}  第一块 {want.hex()}')
        guesses = {
            "fnv1a(iv, '1' u16le)": fnv1a_bytes(iv, "1".encode("utf-16-le")),
            "fnv1a(iv, '1' u16be)": fnv1a_bytes(iv, "1".encode("utf-16-be")),
            "fnv1a(iv, '1' ascii)": fnv1a_bytes(iv, b"1"),
            "fnv1a(basis, iv||'1')": fnv1a_bytes(FNV_OFFSET, tok[:4] + b"1"),
            "fnv1a(iv^basis, '1')": fnv1a_bytes(iv ^ FNV_OFFSET, b"1"),
        }
        for k, v in guesses.items():
            print(f"  {k:<28} {struct.pack('>I', v).hex()}  {struct.pack('<I', v).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
