"""从抓包日志里找出「带密码的加入请求」，并与普通加入请求对比。"""

import glob
import os
import re
import struct

CAP = os.path.join(os.environ.get("TEMP", r"C:\Users\冯乐潇\AppData\Local\Temp"), "rvpn_capture")


def load_blocks():
    """返回 [(时间戳, 字节)]"""
    out = []
    for path in glob.glob(os.path.join(CAP, "*.log")):
        raw = open(path, "rb").read().decode("utf-8", "ignore")
        # 每段以 "=== 时间 len=N ===" 开头
        for m in re.finditer(r"=== (\S+ \S+) len=(\d+) ===\s*\nHEX:\n(.*?)ASCII:", raw, re.S):
            ts, _ln, hexbody = m.group(1), m.group(2), m.group(3)
            try:
                data = bytes.fromhex("".join(hexbody.split()))
            except ValueError:
                continue
            out.append((ts, data))
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


def walk(recs, out):
    for field, ty, payload, kids in recs:
        out.append((field, ty, payload, kids))
        if kids:
            walk(kids, out)
    return out


def describe(data):
    recs = walk(parse(data), [])
    cmd = None
    for field, ty, payload, kids in recs:
        if field == 0x00 and ty == 0x01 and len(payload) >= 4:
            cmd = struct.unpack_from(">I", payload)[0]
            break
    return cmd, recs


def main():
    blocks = load_blocks()
    print(f"共 {len(blocks)} 段抓包\n")

    joins = []
    for ts, data in blocks:
        cmd, recs = describe(data)
        if cmd != 0x03:
            continue
        name = None
        extras = []
        for field, ty, payload, kids in recs:
            if field == 0x06 and ty == 0x03 and kids is None:
                s = decode_str(payload)
                if s:
                    name = s
            elif kids is None and not (field == 0x00 and ty == 0x01) and not (field == 0x4A and ty == 0x01):
                extras.append((field, ty, payload))
        joins.append((ts, name, extras, data))

    print(f"加入请求 {len(joins)} 条\n")

    # 按结构分组
    shapes = {}
    for ts, name, extras, data in joins:
        shape = tuple((f, t, len(p)) for f, t, p in extras)
        shapes.setdefault(shape, []).append((ts, name, extras))

    print("=== 按结构分组 ===")
    for shape, items in shapes.items():
        print(f"\n结构 {shape}   共 {len(items)} 条")
        for ts, name, extras in items[:4]:
            print(f"   {ts}  {name!r}")
        if any(len(items) > 1 for _ in [0]) and len(items) > 4:
            print(f"   … 还有 {len(items)-4} 条")

    # 重点：字段多的那种
    print("\n=== 字段最多的那几条详查 ===")
    joins.sort(key=lambda x: len(x[2]), reverse=True)
    for ts, name, extras, data in joins[:5]:
        print(f"\n{ts}  name={name!r}  帧长 {len(data)}")
        for field, ty, payload in extras:
            s = decode_str(payload) if ty == 0x03 else None
            print(f"   field 0x{field:02x}  type 0x{ty:02x}  {len(payload)} 字节"
                  f"  {('= ' + repr(s)) if s else payload[:32].hex()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
