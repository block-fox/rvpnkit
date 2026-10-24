"""对比带密码网络与免密码网络的快照字段。

思路：网络容器（field 0x23）里如果某个字段编码了「有没有密码」，
那 deepseektester 这个带密码网络该字段一定和其他网络不同。
"""

import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else r"C:\rtools\snap2.bin"
TARGET = "deepseektester"


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
        tag = data[off + 6]
        field = data[off + 7]
        if size > len(data) - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        children = parse(payload) if (ty == 0x00 and tag == 0x13) else None
        out.append((field, ty, tag, payload, children))
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


def collect_networks(recs, out):
    for field, ty, tag, payload, kids in recs:
        if field == 0x23 and kids:
            out.append(kids)
        elif kids:
            collect_networks(kids, out)
    return out


def net_name(children):
    for field, ty, tag, payload, kids in children:
        if field == 0x06 and ty == 0x03:
            return decode_str(payload)
    return None


def describe(children):
    """把网络容器的字段整理成 {field: 可读值}"""
    d = {}
    for field, ty, tag, payload, kids in children:
        if kids is not None:
            d.setdefault(field, []).append(f"<container {len(kids)} children>")
        elif ty == 0x03:
            s = decode_str(payload)
            d.setdefault(field, []).append(f"str:{s!r}" if s else f"raw:{payload[:16].hex()}")
        elif ty in (0x01, 0x0B) and len(payload) >= 4:
            d.setdefault(field, []).append(f"u32:{struct.unpack_from('>I', payload)[0]}")
        elif ty == 0x0D:
            d.setdefault(field, []).append(f"guid:{payload.hex()}")
        else:
            d.setdefault(field, []).append(f"t{ty:02x}:{payload[:24].hex()}")
    return d


def main():
    raw = open(PATH, "rb").read()
    frames = split_frames(raw) or [raw]
    nets = []
    for f in frames:
        collect_networks(parse(f), nets)

    print(f"快照里 {len(nets)} 个网络容器\n")

    named = []
    for ch in nets:
        nm = net_name(ch)
        if nm:
            named.append((nm, describe(ch)))

    target = None
    for nm, d in named:
        if nm.lower() == TARGET.lower():
            target = d
            print(f"★ 找到目标网络: {nm!r}")
            break

    if target is None:
        print(f"没找到 {TARGET}，当前网络：")
        for nm, _ in named[:30]:
            print("   ", nm)
        return 1

    others = [(nm, d) for nm, d in named if nm.lower() != TARGET.lower()]
    print(f"可对比的免密码网络: {len(others)} 个\n")

    print("=== 目标网络的字段 ===")
    for k in sorted(target):
        vals = target[k]
        short = vals[0]
        if len(short) > 60:
            short = short[:60] + "…"
        print(f"  0x{k:02x}  {short}")

    print("\n=== 与其他网络的差异（只列目标有、或取值不同的字段）===")
    for k in sorted(target):
        tv = target[k]
        diffs = []
        for nm, d in others:
            ov = d.get(k)
            if ov is None:
                diffs.append(f"{nm}: 无此字段")
            elif ov != tv:
                diffs.append(f"{nm}: {ov[0][:40]}")
        if diffs:
            print(f"\n  字段 0x{k:02x}")
            print(f"    目标: {tv[0][:70]}")
            for line in diffs[:4]:
                print(f"    其他: {line}")
            if len(diffs) > 4:
                print(f"    … 还有 {len(diffs)-4} 个不同")

    print("\n=== 只出现在目标里的字段 ===")
    other_keys = set()
    for _, d in others:
        other_keys |= set(d.keys())
    only = sorted(set(target) - other_keys)
    print("  ", [hex(x) for x in only] if only else "无")

    return 0


if __name__ == "__main__":
    sys.exit(main())
