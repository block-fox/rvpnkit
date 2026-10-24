"""在真实快照里找虚拟 IPv4 / IPv6，以及可能的角色、通道类型字段。

不依赖 rvpnstate 的内部结构，直接按线格式自己解析：
    [u32 BE 大小][类型][0x00][tag|field][payload]
"""

import collections
import re
import struct
import sys

sys.path.insert(0, r"D:\工作区\workspace1\RvpnKit\native")

import rvpncmd as R  # noqa: E402

RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


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
    """返回 [(field, ty, payload, children)] 的扁平列表。"""
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
        children = None
        if ty == 0x00 and tag_byte == 0x13:
            children = parse(payload)
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


def collect(recs, out):
    for field, ty, payload, kids in recs:
        if ty == 0x03:
            s = decode_str(payload)
            if s:
                out.append((field, s))
        if kids:
            collect(kids, out)
    return out


def main():
    pipe = R.open_pipe()
    if pipe is None:
        print("打不开管道")
        return 1
    raw = R.read_all(pipe)
    R.close_pipe(pipe)

    frames = split_frames(raw) or [raw]
    strings = []
    for f in frames:
        collect(parse(f), strings)

    v4 = collections.defaultdict(set)
    v6 = collections.defaultdict(set)
    for field, s in strings:
        if RE_IPV4.match(s):
            v4[field].add(s)
        elif s.count(":") >= 2 and re.fullmatch(r"[0-9a-fA-F:]{6,45}", s):
            v6[field].add(s)

    print(f"快照 {len(raw)} 字节 / {len(frames)} 帧 / {len(strings)} 条字符串\n")

    print("IPv4 字段：")
    for field, vals in sorted(v4.items()):
        n26 = sum(1 for v in vals if v.startswith("26."))
        print(f"  0x{field:02x}  {len(vals):5d} 个值, 26.* {n26:5d}, 样例 {sorted(vals)[:2]}")

    print("\nfdfd:* 字段：")
    found = False
    for field, vals in sorted(v6.items()):
        fdd = [v for v in vals if v.lower().startswith("fdfd")]
        if fdd:
            found = True
            print(f"  0x{field:02x}  {len(fdd)} 个, 样例 {fdd[:2]}")
    if not found:
        print("  没有 —— 快照里不含虚拟 IPv6")

    if not any(v for v in v4.values() if any(x.startswith("26.") for x in v)):
        print("\n注意：快照里没有任何 26.* 地址 —— 虚拟 IPv4 不在控制面快照里")
    return 0


if __name__ == "__main__":
    sys.exit(main())
