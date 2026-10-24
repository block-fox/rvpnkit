"""离线分析快照字段：找虚拟 IPv4 / IPv6、角色、通道类型。"""

import collections
import re
import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else r"C:\rtools\snap.bin"

RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
RE_IPV6 = re.compile(r"^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$")


def decode_str(payload: bytes):
    body = payload
    if len(body) >= 2 and body[-2:] == b"\x00\x01":
        body = body[:-2]
    if not body or len(body) % 2:
        return None
    try:
        s = body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 for c in s):
        return None
    return s


def parse(data: bytes):
    out = []
    off = 0
    while off + 8 <= len(data):
        size = struct.unpack_from(">I", data, off)[0]
        ty = data[off + 4]
        tag_byte = data[off + 6]
        field = data[off + 7]
        if size > len(data) - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        children = parse(payload) if (ty == 0x00 and tag_byte == 0x13) else None
        out.append((field, ty, payload, children))
        off += 8 + size
    return out


def split_frames(stream: bytes):
    frames = []
    off = 0
    while off + 4 <= len(stream):
        n = struct.unpack_from("<I", stream, off)[0]
        if n == 0 or n > len(stream) - off - 4:
            break
        frames.append(stream[off + 4:off + 4 + n])
        off += 4 + n
    return frames


def collect(recs, strings, numbers):
    for field, ty, payload, kids in recs:
        if ty == 0x03:
            s = decode_str(payload)
            if s:
                strings.append((field, s))
        elif ty in (0x01, 0x0B) and len(payload) >= 4:
            numbers.append((field, struct.unpack_from(">I", payload, 0)[0]))
        if kids:
            collect(kids, strings, numbers)
    return strings, numbers


def main():
    raw = open(PATH, "rb").read()
    frames = split_frames(raw) or [raw]
    strings, numbers = [], []
    for f in frames:
        collect(parse(f), strings, numbers)

    print(f"快照 {len(raw)} 字节 / {len(frames)} 帧 / {len(strings)} 字符串 / {len(numbers)} 数字\n")

    v4 = collections.defaultdict(set)
    v6 = collections.defaultdict(set)
    for field, s in strings:
        if RE_IPV4.match(s):
            v4[field].add(s)
        elif RE_IPV6.match(s) and "::" in s:
            v6[field].add(s)

    print("IPv4 字段：")
    for field, vals in sorted(v4.items()):
        n26 = sum(1 for v in vals if v.startswith("26."))
        print(f"  0x{field:02x}  {len(vals):5d} 个, 26.* {n26:5d}, 样例 {sorted(vals)[:3]}")

    print("\n含 '::' 的字段：")
    for field, vals in sorted(v6.items()):
        fdd = [v for v in vals if v.lower().startswith("fd") or v.lower().startswith("fe80")]
        print(f"  0x{field:02x}  {len(vals):5d} 个, fd/fe80 {len(fdd):4d}, 样例 {sorted(vals)[:2]}")

    # 数字字段取值范围，找像「角色 / 通道 / 状态」的小整数
    print("\n小整数数字字段（可能是角色/状态/通道类型）：")
    by_field = collections.defaultdict(collections.Counter)
    for field, v in numbers:
        if v <= 64:
            by_field[field][v] += 1
    for field, ctr in sorted(by_field.items()):
        if len(ctr) <= 8:
            print(f"  0x{field:02x}  {dict(ctr)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
