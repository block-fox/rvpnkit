"""分析中文密码的令牌，确定长度口径与逐字节异或方式。

用户给的样本：
  网络名 发发发发发发发发发（9 个「发」）
  密码   发发发发发发（6 个「发」）

「发」= U+53D1
  UTF-8 : e5 8f 91       （3 字节/字）
  UTF-16: 53 d1          （2 字节/字）

令牌长度 4*(n+1)：
  若 n = UTF-8 字节数 18 → 76 字节
  若 n = UTF-16 码元数 6  → 28 字节
两种口径差别很大，一看长度就能定。
"""

import glob
import os
import struct

CAP = os.path.join(os.environ.get("TEMP", r"C:\Users\冯乐潇\AppData\Local\Temp"), "rvpn_capture")
NAME = "发发发发发发发发发"
NEEDLE = NAME.encode("utf-16-be")


def load_frames():
    out = []
    for path in glob.glob(os.path.join(CAP, "*.log")):
        raw = open(path, "rb").read().decode("utf-8", "ignore")
        for m in __import__("re").finditer(
            r"=== (\S+ \S+) (\w+) len=(\d+) ===\s*\nHEX:\n(.*?)ASCII:", raw, __import__("re").S
        ):
            try:
                data = bytes.fromhex("".join(m.group(4).split()))
            except ValueError:
                continue
            out.append((m.group(1), data))
    return out


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


def walk(recs, out):
    for field, ty, payload, kids in recs:
        out.append((field, ty, payload))
        if kids:
            walk(kids, out)
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


def main():
    frames = load_frames()
    print(f"共 {len(frames)} 帧\n")

    hits = [(ts, d) for ts, d in frames if NEEDLE in d]
    print(f"含「{NAME}」的帧：{len(hits)} 条")
    for ts, d in hits:
        recs = walk(parse(d), [])
        cmd = None
        blob = None
        pwd_field = None
        for field, ty, payload in recs:
            if field == 0x00 and ty == 0x01 and cmd is None and len(payload) >= 4:
                cmd = struct.unpack_from(">I", payload)[0]
            if field == 0x0D and ty == 0x08:
                blob = payload
        print(f"\n--- {ts}  cmd=0x{cmd:02x} ---" if cmd else f"\n--- {ts} ---")
        print(f"    0x0d 块: {len(blob) if blob else 0} 字节")
        if blob:
            print(f"    {blob.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
