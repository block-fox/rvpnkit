"""活体验证：用自己算的令牌加入密码网络。

步骤：
  1. 找到 sky的网络
  2. 退出
  3. 按破解出来的算法生成令牌，用我们自己的客户端加入
  4. 确认真的进去了

如果成功，说明令牌算法完全正确 —— 不再依赖官方客户端。
"""

import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, r"D:\工作区\workspace1\RvpnKit\native")
import rvpncmd as R  # noqa: E402
from probe_commands import send  # noqa: E402

RVPNKIT = r"C:\rtools\rvpn-target\release\rvpnkit.exe"
DUMP = r"C:\rtools\live_snap.bin"
TARGET = "sky的网络"
PASSWORD = "123456"


def password_token(password: str) -> bytes:
    pw = password.encode()
    n = len(pw)
    rnd = os.urandom(2 * (n + 1))
    out = bytearray()
    for i in range(n + 1):
        hi = rnd[2 * i]
        lo = rnd[2 * i + 1]
        ch = pw[i] if i < n else 0
        out.append(hi ^ ch)
        out.append(lo)
    out += rnd
    return bytes(out)


def decode_str(payload):
    body = payload
    if len(body) >= 2 and body[-2:] == b"\x00\x01":
        body = body[:-2]
    if not body or len(body) % 2:
        return None
    try:
        s = body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    return s if s and all(ord(c) >= 0x20 for c in s) else None


def parse(data):
    out, off = [], 0
    while off + 8 <= len(data):
        size = struct.unpack_from(">I", data, off)[0]
        ty, tag, field = data[off + 4], data[off + 6], data[off + 7]
        if size > len(data) - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        kids = parse(payload) if (ty == 0 and tag == 0x13) else None
        out.append((field, ty, payload, kids))
        off += 8 + size
    return out


def split_frames(stream):
    frames, off = [], 0
    while off + 4 <= len(stream):
        n = struct.unpack_from("<I", stream, off)[0]
        if n == 0 or n > len(stream) - off - 4:
            break
        frames.append(stream[off + 4:off + 4 + n])
        off += 4 + n
    return frames


def networks():
    subprocess.run([RVPNKIT, "--dump", DUMP], capture_output=True, timeout=30)
    raw = open(DUMP, "rb").read()
    frames = split_frames(raw) or [raw]
    out = []

    def walk(recs):
        for field, ty, payload, kids in recs:
            if kids:
                if field == 0x23:
                    name = guid = None
                    for f2, t2, p2, k2 in kids:
                        if k2 is None and f2 == 0x06 and t2 == 3:
                            name = decode_str(p2)
                        elif k2 is None and f2 == 0x09 and t2 == 0x0D:
                            guid = p2
                    if name and guid:
                        out.append((name, guid))
                walk(kids)

    for f in frames:
        walk(parse(f))
    return out


def build_join_pw(name, token):
    inner = R.rec_u32(0, 0x3F) + R.rec_str(name, 0x06)
    inner += struct.pack(">I", len(token)) + bytes([0x08, 0x00, 0x03, 0x0D]) + token
    return (R.head(R.new_req_id(), 0x03)
            + struct.pack(">I", len(inner))
            + struct.pack(">I", 0x0000131B)
            + inner)


def main():
    nets = networks()
    hit = next(((n, g) for n, g in nets if n == TARGET), None)
    if not hit:
        print(f"没找到 {TARGET}，当前 {len(nets)} 个网络")
        return 1
    name, guid = hit
    print(f"目标 {name}  guid={guid.hex()}")

    print("\n[1] 退出网络 …")
    send(R.head(R.new_req_id(), 0x05) + R.rec_guid(guid, 0x09))
    time.sleep(2.0)
    if any(n == name for n, _ in networks()):
        print("    退出失败，终止")
        return 2
    print("    已退出")

    tok = password_token(PASSWORD)
    print(f"\n[2] 用自算令牌加入（密码 {PASSWORD!r}）")
    print(f"    令牌 {tok.hex()}")
    send(build_join_pw(name, tok))
    time.sleep(3.0)

    ok = any(n == name for n, _ in networks())
    print(f"\n[3] 结果: {'★ 加入成功' if ok else '✗ 加入失败'}")

    if ok:
        # 再验证反推
        half = PASSWORD.__len__() + 1
        pw = bytes(tok[i * 2] ^ tok[(half + i) * 2] for i in range(half)).rstrip(b"\x00")
        print(f"    从令牌反推密码: {pw!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
