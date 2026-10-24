"""解析抓到的那条「创建带密码网络」请求，验证 0x0d 块是不是 密钥+密码哈希。"""

import glob
import hashlib
import os
import re
import struct

CAP = os.path.join(os.environ.get("TEMP", r"C:\Users\冯乐潇\AppData\Local\Temp"), "rvpn_capture")
PASSWORD = "deepseektester"
NAME = "deepseektester"


def load_frames():
    """从抓包日志里取出所有 HEX: 段，拼成字节串，再按长度前缀切帧。"""
    frames = []
    for path in glob.glob(os.path.join(CAP, "*.log")):
        raw = open(path, "rb").read().decode("utf-8", "ignore")
        for block in re.split(r"=== .*? ===\n", raw):
            hexpart = []
            in_hex = False
            for line in block.splitlines():
                if line.strip() == "HEX:":
                    in_hex = True
                    continue
                if line.strip() == "ASCII:":
                    in_hex = False
                    continue
                if in_hex:
                    hexpart.append(line.strip())
            if not hexpart:
                continue
            try:
                data = bytes.fromhex("".join(hexpart))
            except ValueError:
                continue
            frames.append((path, data))
    return frames


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


def decode_str(payload):
    body = payload
    if len(body) >= 2 and body[-2:] == b"\x00\x01":
        body = body[:-2]
    if not body or len(body) % 2:
        return None
    try:
        return body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None


def walk(recs, out):
    for field, ty, payload, kids in recs:
        out.append((field, ty, payload))
        if kids:
            walk(kids, out)
    return out


def main():
    frames = load_frames()
    print(f"抓到 {len(frames)} 帧\n")

    for path, data in frames:
        recs = walk(parse(data), [])
        name = None
        blob = None
        cmd = None
        for field, ty, payload in recs:
            if field == 0x06 and ty == 0x03:
                s = decode_str(payload)
                if s:
                    name = s
            if field == 0x0D and ty == 0x08 and len(payload) > 40:
                blob = payload
            if field == 0x00 and ty == 0x01:
                cmd = struct.unpack_from(">I", payload)[0]

        if blob is None or cmd != 0x02:
            continue

        print(f"命中创建请求：名字={name!r}  0x0d 块 {len(blob)} 字节")
        print(f"  前 28 字节（网络密钥）: {blob[:28].hex()}")
        tail = blob[28:]
        print(f"  之后 {len(tail)} 字节      : {tail.hex()}")

        cands = {
            'sha256("deepseektester")': hashlib.sha256(PASSWORD.encode()).digest(),
            'sha256(name+"deepseektester")': hashlib.sha256((NAME + PASSWORD).encode()).digest(),
            'sha256(utf16le(password))': hashlib.sha256(PASSWORD.encode("utf-16-le")).digest(),
            'sha256(utf16be(password))': hashlib.sha256(PASSWORD.encode("utf-16-be")).digest(),
            'md5(password)x2': hashlib.md5(PASSWORD.encode()).digest() * 2,
            'sha256(blob[:28]+password)': hashlib.sha256(blob[:28] + PASSWORD.encode()).digest(),
            'sha256(password+blob[:28])': hashlib.sha256(PASSWORD.encode() + blob[:28]).digest(),
        }

        print("\n  候选哈希比对：")
        hit = False
        for label, digest in cands.items():
            ok = digest == tail[:len(digest)] and len(tail) >= len(digest)
            mark = "  ★★★ 命中" if ok else ""
            print(f"    {label:<34} {digest.hex()[:40]}…{mark}")
            if ok:
                hit = True

        if not hit:
            print("\n  没直接命中。尝试：把整个 tail 当作 名称/密码 的其他组合…")
            for label, data2 in {
                "sha256(utf16be password)": hashlib.sha256(
                    b"".join(struct.pack(">H", ord(c)) for c in PASSWORD)
                ).digest(),
                "sha256(name+password utf16be)": hashlib.sha256(
                    b"".join(struct.pack(">H", ord(c)) for c in (NAME + PASSWORD))
                ).digest(),
                "sha512(password)[:32]": hashlib.sha512(PASSWORD.encode()).digest()[:32],
                "sha256(password)[:16]+salt": None,
            }.items():
                if data2 is None:
                    continue
                ok = data2 == tail[:32]
                print(f"    {label:<34} {data2.hex()[:40]}…{'  ★★★ 命中' if ok else ''}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
