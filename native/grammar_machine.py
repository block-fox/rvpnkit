"""Recover the record grammar from the captured frames by machine search.

We have ~20 real frames from the service.  Instead of hand-deriving the layout,
enumerate candidate grammars and require a candidate to consume EVERY frame
exactly (no leftover bytes, no resync).  For short frames (52-56 bytes) that is
a very strong constraint, so the true grammar should stand out.

Candidate axes:
  fid_w      1/2/3 bytes for the field id
  fid_endian BE / LE
  len_w      1/2/3/4 bytes for a string length
  len_endian BE / LE
  len_unit   bytes / chars
  pad        bytes between length and payload
"""
import os
import struct

CAP = r"D:\工作区\workspace1\recon\captures\snap.bin"
data = open(CAP, "rb").read()

STR, U32, U64, U8, U16, F32 = 0x03, 0x04, 0x08, 0x0B, 0x0C, 0x02
BLOBS = {0x09, 0x0D, 0x10}


def frames(d):
    off, out = 0, []
    while off + 4 <= len(d):
        n = int.from_bytes(d[off:off + 4], "little")
        if n <= 0 or off + 4 + n > len(d):
            break
        out.append(d[off + 4:off + 4 + n])
        off += 4 + n
    return out


FR = frames(data)
SMALL = [f for f in FR if len(f) <= 64]
print(f"帧总数 {len(FR)}，其中短帧 {len(SMALL)} 个")
print(f"长度分布: {sorted({len(f) for f in FR})[:12]}\n")


def parse(b, g, start):
    """Try to parse one record at `start`. Return next offset or None."""
    typ_w, typ_be, fid_w, fid_be, len_w, len_be, unit, pad = g
    if start + typ_w + fid_w > len(b):
        return None
    t = b[start]
    p = start + typ_w + fid_w

    if t == U32:
        return p + 4 if p + 4 <= len(b) else None
    if t == U64:
        return p + 8 if p + 8 <= len(b) else None
    if t == U8:
        return p + 1 if p + 1 <= len(b) else None
    if t == U16:
        return p + 2 if p + 2 <= len(b) else None
    if t == F32:
        return p + 4 if p + 4 <= len(b) else None
    if t in BLOBS:
        return p + 16 if p + 16 <= len(b) else None
    if t == STR:
        if p + len_w > len(b):
            return None
        ln = int.from_bytes(b[p:p + len_w], "big" if len_be else "little")
        if ln <= 0 or ln > 8192:
            return None
        n = ln * unit
        body = p + len_w + pad
        if n % 2 or body + n > len(b):
            return None
        raw = b[body:body + n]
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if any(ord(c) < 0x20 and c not in "\t\r\n" for c in s):
            return None
        return body + n
    return None


def try_frame(b, g, start=0):
    i = start
    n = 0
    while i < len(b):
        nxt = parse(b, g, i)
        if nxt is None or nxt <= i:
            return False, n
        i = nxt
        n += 1
        if n > 500:
            return False, n
    return i == len(b), n


print("═══ 穷举语法（要求完全消费短帧）═══")
winners = []
tried = 0
for typ_w in (1, 2):
    for typ_be in (True, False):
        for fid_w in (0, 1, 2, 3):
            for fid_be in (True, False):
                for len_w in (1, 2, 3, 4):
                    for len_be in (True, False):
                        for unit in (1, 2):
                            for pad in (0, 1, 2):
                                g = (typ_w, typ_be, fid_w, fid_be,
                                     len_w, len_be, unit, pad)
                                tried += 1
                                ok = sum(1 for b in SMALL if try_frame(b, g)[0])
                                if ok == len(SMALL):
                                    winners.append(g)
                                elif ok >= len(SMALL) - 1:
                                    print(f"  {ok}/{len(SMALL)}  {g}")

print(f"尝试 {tried} 组\n")
if winners:
    print(f"★ 完全通过 {len(winners)} 组：")
    for g in winners:
        print("   ", g)
else:
    print("无完全通过的语法 → 短帧里也有变长/嵌套结构")

# ── 退一步：检查服务是否把候选帧记进了日志（验证之前的发送）
print("\n═══ 检查服务是否记录了我们的候选帧 ═══")
LOG_DIR = r"C:\ProgramData\Famatech\Radmin VPN"
import glob
reqs = []
for f in glob.glob(os.path.join(LOG_DIR, "service*.log")):
    try:
        raw = open(f, "rb").read()
    except OSError:
        continue
    text = raw.decode("utf-16-le", "ignore")
    for line in text.splitlines():
        if "[req:" in line:
            reqs.append(line.strip())
print(f"全部日志中 [req: 行总数 = {len(reqs)}")
for r in reqs[-12:]:
    print("   ", r[:120])
