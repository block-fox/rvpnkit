"""验证密码令牌是否「只由密码决定」。

做法：把抓包日志里所有带 0x0d 令牌的加入帧都列出来，
如果同一个密码在不同时间产生同样的 28 字节，那就是纯函数 F(password)。
"""

import glob
import os
import re
import struct

CAP = os.path.join(os.environ.get("TEMP", r"C:\Users\冯乐潇\AppData\Local\Temp"), "rvpn_capture")


def load_blocks():
    out = []
    for path in glob.glob(os.path.join(CAP, "*.log")):
        raw = open(path, "rb").read().decode("utf-8", "ignore")
        for m in re.finditer(r"=== (\S+ \S+) len=(\d+) ===\s*\nHEX:\n(.*?)ASCII:", raw, re.S):
            try:
                data = bytes.fromhex("".join(m.group(3).split()))
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
        out.append((field, ty, payload, kids))
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
        s = body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    return s if s and all(ord(c) >= 0x20 for c in s) else None


def main():
    rows = []
    for ts, data in load_blocks():
        recs = walk(parse(data), [])
        cmd = None
        name = None
        tokens = []
        for field, ty, payload, kids in recs:
            if field == 0x00 and ty == 0x01 and cmd is None and len(payload) >= 4:
                cmd = struct.unpack_from(">I", payload)[0]
            if field == 0x06 and ty == 0x03 and decode_str(payload):
                name = decode_str(payload)
            if field == 0x0D and ty == 0x08 and 20 <= len(payload) <= 64:
                tokens.append(payload)

        if cmd in (0x03, 0x02) and tokens:
            rows.append((ts, hex(cmd), name, tokens[0]))

    print(f"带 0x0d 块的创建/加入请求：{len(rows)} 条\n")
    seen = {}
    for ts, cmd, name, tok in rows:
        print(f"  {ts}  cmd={cmd}  {name!r}")
        print(f"      0x0d = {len(tok)} 字节  {tok.hex()}")
        seen.setdefault((name, tok.hex()), []).append(ts)

    print("\n=== 同网络同令牌出现次数 ===")
    for (name, tok), tss in seen.items():
        if len(tss) > 1:
            print(f"  {name!r}: {len(tss)} 次，令牌完全相同 → 纯函数")

    print("\n=== 不同网络同密码的令牌比对（若你用过同一密码）===")
    bylen = {}
    for ts, cmd, name, tok in rows:
        bylen.setdefault((name, len(tok)), []).append(tok.hex())
    for k, v in bylen.items():
        print(f"  {k[0]!r} 长度 {k[1]}: {len(set(v))} 种取值")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
