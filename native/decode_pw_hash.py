"""对抓到的 32 字节尾巴做更宽的哈希猜测。"""

import hashlib
import hmac
import struct

KEY = bytes.fromhex("cd157e9047733e8b5e4bf75fab3e5bd4984e4e57d97b0874c7e1f941")
TAIL = bytes.fromhex("ab37a9151b9022734e8b2d4b925fce3e30d4ec4e2b57aa7b7c74a2e18b41ab37")
PW = "deepseektester"
NAME = "deepseektester"


def wire(s):
    """协议里的字符串编码：UTF-16BE + 00 01"""
    return s.encode("utf-16-be") + b"\x00\x01"


def h(name, data):
    return (name, hashlib.sha256(data).digest())


variants = []
for pw_label, pw_bytes in {
    "ascii": PW.encode(),
    "utf16le": PW.encode("utf-16-le"),
    "utf16be": PW.encode("utf-16-be"),
    "wire": wire(PW),
    "lower": PW.lower().encode(),
    "utf8+bom": b"\xef\xbb\xbf" + PW.encode(),
}.items():
    variants.append(h(f"sha256(pw/{pw_label})", pw_bytes))
    variants.append(h(f"sha256(pw/{pw_label}+key)", pw_bytes + KEY))
    variants.append(h(f"sha256(key+pw/{pw_label})", KEY + pw_bytes))
    variants.append(h(f"sha256(name+pw/{pw_label})", NAME.encode() + pw_bytes))
    variants.append((f"hmac-key-pw/{pw_label}", hmac.new(KEY, pw_bytes, hashlib.sha256).digest()))
    variants.append((f"hmac-pw-name/{pw_label}", hmac.new(pw_bytes, NAME.encode(), hashlib.sha256).digest()))

# 双 sha256
variants.append(h("sha256(sha256(pw))", hashlib.sha256(PW.encode()).digest()))
# sha256 前 32 字节 of key||pw 用 key 的前 16/28 字节
variants.append(h("sha256(key[:16]+pw)", KEY[:16] + PW.encode()))
variants.append(h("sha256(key[:28]+wire(pw))", KEY + wire(PW)))

print(f"目标尾巴: {TAIL.hex()}\n")
hit = None
for label, digest in variants:
    if digest == TAIL:
        hit = label
        print(f"  ★★★ 命中: {label}")
print(f"\n共试 {len(variants)} 种派生，命中: {hit or '无'}")

if not hit:
    # 看看尾巴里有没有明显结构：是否等于某段的重复/倒序
    print("\n结构观察：")
    print(f"  尾巴前 4 字节 {TAIL[:4].hex()}   后 4 字节 {TAIL[-4:].hex()}")
    print(f"  密钥后 4 字节 {KEY[-4:].hex()}")
    print(f"  尾巴里 'ab37' 出现次数: {TAIL.hex().count('ab37')}")
    # 尝试：尾巴是否是 16 字节的两半重复
    print(f"  前16 == 后16 ? {TAIL[:16] == TAIL[16:]}")
    # 尝试：是否是 guid 的某种哈希
    guid = bytes.fromhex("8235528cf604481aaf14623b0a69f391")
    for label, data in {
        "sha256(guid)": guid,
        "sha256(guid+key)": guid + KEY,
        "sha256(key+guid)": KEY + guid,
        "sha256(guid+pw)": guid + PW.encode(),
    }.items():
        d = hashlib.sha256(data).digest()
        if d == TAIL:
            print(f"  ★★★ 命中: {label}")
