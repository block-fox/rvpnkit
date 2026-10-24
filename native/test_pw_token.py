"""验证「带密码加入」里的 28 字节是不是静态令牌。

步骤：
  1. 从快照里找到 sky的网络 的 GUID
  2. 用我们的客户端离开它
  3. 把抓到的原始加入帧（同样名字 + 同样 28 字节）重放出去
  4. 看重放后网络是否回来 —— 回来就说明这 28 字节是静态的、可复用的
"""

import struct
import subprocess
import sys
import time

sys.path.insert(0, r"D:\工作区\workspace1\RvpnKit\native")
import rvpncmd as R  # noqa: E402
from probe_commands import send  # noqa: E402

RVPNKIT = r"C:\rtools\rvpn-target\release\rvpnkit.exe"
DUMP = r"C:\rtools\join_snap.bin"
TARGET = "sky的网络"
BLOB = bytes.fromhex("7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874")


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


def snapshot_networks():
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


def build_join_with_blob(name, blob):
    inner = R.rec_u32(0, 0x3F) + R.rec_str(name, 0x06)
    inner += struct.pack(">I", len(blob)) + bytes([0x08, 0x00, 0x03, 0x0D]) + blob
    return (
        R.head(R.new_req_id(), 0x03)
        + struct.pack(">I", len(inner))
        + struct.pack(">I", 0x0000131B)
        + inner
    )


def main():
    nets = snapshot_networks()
    print(f"当前 {len(nets)} 个网络")
    hit = next(((n, g) for n, g in nets if n == TARGET), None)
    if not hit:
        print(f"没找到 {TARGET}")
        for n, _ in nets:
            print("   ", n)
        return 1

    name, guid = hit
    print(f"目标: {name}  guid={guid.hex()}")

    print("\n[1] 离开网络 …")
    send(R.head(R.new_req_id(), 0x05) + R.rec_guid(guid, 0x09))
    time.sleep(2.0)
    after = [n for n, _ in snapshot_networks()]
    print(f"    剩余网络 {len(after)} 个, 还在? {name in after}")
    if name in after:
        print("    离开没生效，终止（不敢乱试）")
        return 2

    print("\n[2] 重放抓到的原始加入帧（同样名字 + 同样 28 字节）…")
    send(build_join_with_blob(name, BLOB))
    time.sleep(3.0)
    after2 = snapshot_networks()
    back = any(n == name for n, _ in after2)
    print(f"    网络数 {len(after2)}, 回来了? {back}")

    if back:
        print("\n  ★★★ 重放成功 —— 这 28 字节是【静态可复用令牌】")
        print("      意味着：不需要知道密码算法，存下这 28 字节就能反复加入")
    else:
        print("\n  重放失败 —— 说明它可能是和挑战/时间绑定的，或者需要真实密码算法")

    return 0


if __name__ == "__main__":
    sys.exit(main())
