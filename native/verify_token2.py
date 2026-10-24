"""统一模型验证：令牌 = A || R，A = R XOR UTF-16LE(密码) 补齐。

之前从 ASCII 样本得出的「只异或 u16 高字节」其实是特例：
ASCII 的 UTF-16LE 是 (字符, 0x00)，所以只有每两个字节中的第一个被异或。

中文样本（发 = U+53D1，UTF-16LE = D1 53）把这一点暴露出来了。
"""

SAMPLES = [
    # (密码, 网络, 令牌 hex)
    ("123456", "sky的网络",
     "7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874"),
    ("Aa022033", "东北雨姐四十八码大汗脚",
     "4fca0aa935436abb397116db166b857b3c6c0eca6ba9054358bb0b7126db256bb67b3c6c"),
    ("deepseektester", "deepseektester(create)",
     "cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941ab37a9151b902273"
     "4e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37"),
    ("123456", "deepseektester(join)",
     "8b3787dee468438689f68a59dc84ba37b5ded7687786bcf6bc59dc84"),
    ("deepseektester", "deepseektester(join2)",
     "cb27da578b2cda52a2c2929ffcba1bc4ce069a97ba1bfbc4bf9f51225fce"
     "af27bf57ee2caa52d1c2f79f99ba70c4ba06ff97c91b8fc4da9f23225fce"),
    ("发发发发发发", "发发发发发发发发发",
     "a8973035e8dab8b6778b09a9eb29"
     "79c4e166398969e5a6d8d8faeb29"),
]


def pw_bytes(pw: str) -> bytes:
    """密码按 UTF-16LE 编码，并补到 2*(n+1) 字节（末尾一个 u16 的 0）。"""
    raw = pw.encode("utf-16-le")
    n = len(pw.encode("utf-16-le")) // 2
    return raw + b"\x00" * (2 * (n + 1) - len(raw))


def token_from(password: str, rnd: bytes) -> bytes:
    pw = pw_bytes(password)
    assert len(pw) == len(rnd), f"长度不符: pw={len(pw)} rnd={len(rnd)}"
    a = bytes(x ^ y for x, y in zip(rnd, pw))
    return a + rnd


def password_from(token: bytes) -> str:
    half = token.len // 2 if False else len(token) // 2
    a, b = token[:half], token[half:]
    x = bytes(p ^ q for p, q in zip(a, b))
    # 去掉末尾补齐的一个 u16
    x = x[:-2]
    return x.decode("utf-16-le", "ignore")


def main():
    ok = True
    print("=== 反推密码 ===")
    for pw, net, hexs in SAMPLES:
        tok = bytes.fromhex(hexs)
        got = password_from(tok)
        good = got == pw
        ok &= good
        print(f"  {net:<28} 长度{len(tok):3d}  反推={got!r:<18} {'✓' if good else '✗'}")

    print("\n=== 用后半段的随机数重新生成，逐字节比对 ===")
    for pw, net, hexs in SAMPLES:
        tok = bytes.fromhex(hexs)
        half = len(tok) // 2
        rnd = tok[half:]
        gen = token_from(pw, rnd)
        good = gen == tok
        ok &= good
        print(f"  {net:<28} {'✓ 完全一致' if good else '✗ 不一致'}")

    print(f"\n总体: {'全部通过' if ok else '有失败'}")

    # 顺带看一眼中文样本的逐字节异或
    tok = bytes.fromhex(SAMPLES[5][2])
    half = len(tok) // 2
    xor = bytes(p ^ q for p, q in zip(tok[:half], tok[half:]))
    print(f"\n中文样本的异或结果: {xor.hex()}")
    print(f"  期望 UTF-16LE + 补齐: {pw_bytes('发发发发发发').hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
