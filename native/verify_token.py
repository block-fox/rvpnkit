"""验证破解出来的令牌算法。

结构（已由动态抓包确认）：
    n = 密码长度
    R = (n+1) 个 16 位随机数
    token = 前半 + 后半
        前半第 i 个 u16 = (R[i].高字节 ^ 密码[i], R[i].低字节)
        后半第 i 个 u16 = 原文 R[i]
    最后一位（i == n）密码字节按 0 处理，所以两半完全相同。

反过来说：token 里直接泄露了密码 —— 把前半和后半的高字节异或就能还原。
"""

import struct

SAMPLES = [
    # (密码, 网络, token hex)
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
]


def decode(token: bytes):
    """从令牌里还原密码。"""
    n2 = len(token) // 2          # u16 个数
    half = n2 // 2
    A = [token[i * 2:i * 2 + 2] for i in range(half)]
    B = [token[(half + i) * 2:(half + i) * 2 + 2] for i in range(half)]
    out = bytearray()
    for i in range(half):
        out.append(A[i][0] ^ B[i][0])
    return bytes(out).rstrip(b"\x00"), A, B


def main():
    print("=== 从令牌反推密码 ===")
    ok = True
    for pw, net, hexs in SAMPLES:
        tok = bytes.fromhex(hexs)
        rec, A, B = decode(tok)
        good = rec.decode("latin1") == pw
        ok &= good
        print(f"  {net:<28} 长度{len(tok):3d}  还原={rec!r:<20} 期望={pw!r:<18} {'✓' if good else '✗'}")

    print("\n=== 用「随机数 + 密码」正向生成，验证逐字节一致 ===")
    import random
    random.seed(1)
    for pw, net, hexs in SAMPLES:
        tok = bytes.fromhex(hexs)
        n = len(pw)
        # 从令牌后半取出真实的 R
        half = n + 1
        R = [tok[(half + i) * 2:(half + i) * 2 + 2] for i in range(half)]
        # 用算法正向生成
        gen = bytearray()
        for i in range(half):
            ch = ord(pw[i]) if i < n else 0
            gen.append(R[i][0] ^ ch)
            gen.append(R[i][1])
        for i in range(half):
            gen += R[i]
        same = bytes(gen) == tok
        ok &= same
        print(f"  {net:<28} {'✓ 完全一致' if same else '✗ 不一致'}")

    print("\n=== 用随机 R 生成一个新令牌 ===")
    pw = "123456"
    n = len(pw)
    R = [bytes([random.randrange(256), random.randrange(256)]) for _ in range(n + 1)]
    tok = bytearray()
    for i in range(n + 1):
        ch = ord(pw[i]) if i < n else 0
        tok.append(R[i][0] ^ ch)
        tok.append(R[i][1])
    for i in range(n + 1):
        tok += R[i]
    print(f"  密码 {pw!r} → 令牌 {bytes(tok).hex()}")
    rec, _, _ = decode(bytes(tok))
    print(f"  反推回密码 {rec!r}  {'✓' if rec.decode() == pw else '✗'}")

    print(f"\n总体: {'全部通过' if ok else '有失败'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
