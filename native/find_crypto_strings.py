"""在二进制里搜密码/哈希相关的字符串与 RTTI 类名。

思路：与其盲猜算法，不如先找到负责这件事的代码叫什么。
"""

import re

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"

KEYS = [
    "password", "Password", "PASSWORD",
    "passwd", "Passwd",
    "hash", "Hash", "HASH",
    "crypt", "Crypt", "CRYPT",
    "salt", "Salt",
    "md5", "MD5", "sha1", "SHA1", "sha256", "SHA256",
    "token", "Token",
    "key", "Key",
    "encrypt", "Encrypt", "decrypt", "Decrypt",
]

RTTI = re.compile(rb"\.\?AV[0-9A-Za-z_@?$]{3,80}@@")
ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,120}")


def main():
    data = open(EXE, "rb").read()
    print(f"{len(data)} 字节\n")

    print("=== 含 password/passwd 的字符串 ===")
    seen = set()
    for m in re.finditer(rb"[\x20-\x7e]{4,120}", data):
        s = m.group().decode("latin1")
        low = s.lower()
        if ("password" in low or "passwd" in low) and s not in seen:
            seen.add(s)
            print(f"  0x{m.start():08x}  {s}")
        if len(seen) > 40:
            break

    print("\n=== RTTI 类名里含 Pass/Crypt/Hash/Key/Token 的 ===")
    names = set()
    for m in RTTI.finditer(data):
        s = m.group().decode("latin1")
        low = s.lower()
        if any(k in low for k in ("pass", "crypt", "hash", "key", "token", "secure", "cred")):
            names.add(s)
    for n in sorted(names)[:40]:
        print(f"  {n}")
    if not names:
        print("  无")

    print("\n=== 含 crypt/hash 的 ASCII 串（去重、限长）===")
    seen2 = set()
    for m in ASCII_RUN.finditer(data):
        s = m.group().decode("latin1")
        low = s.lower()
        if ("crypt" in low or "hash" in low) and s not in seen2 and len(s) < 70:
            seen2.add(s)
            print(f"  0x{m.start():08x}  {s}")
        if len(seen2) > 30:
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
