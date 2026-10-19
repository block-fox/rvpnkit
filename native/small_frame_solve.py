"""Brute-force the record grammar on the smallest real frames.

The big snapshot frame clearly contains containers, but the short delta frames
(52-56 bytes) look flat.  If a grammar parses one of those completely, that
grammar is the ground truth and can be extended to containers afterwards.

For each candidate (field-id width, endianness, string length encoding,
alignment offset) we require *exact* consumption of the whole frame.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
# 抓包产物在 recon/captures 下（已被 .gitignore 排除）
CANDIDATES = [
    os.path.join(HERE, "..", "..", "..", "recon", "captures", "snap.bin"),
    r"D:\工作区\workspace1\recon\captures\snap.bin",
]
CAP = next(p for p in CANDIDATES if os.path.isfile(p))
data = open(CAP, "rb").read()


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
print(f"小帧数量: {len(SMALL)}，长度: {sorted({len(f) for f in SMALL})}")
print(f"首个 52 字节帧: {SMALL[0].hex(' ')}\n")

STR, U32, U64, U8, U16, F32 = 0x03, 0x04, 0x08, 0x0B, 0x0C, 0x02
BLOBS = {0x09, 0x0D, 0x10}

print("帧 #4 的逐字节：")
f0 = SMALL[0]
for i in range(0, len(f0), 8):
    chunk = f0[i:i + 8]
    print(f"  {i:3d}  " + " ".join(f"{b:02x}" for b in chunk))
print()


def parse_flat(b, start, fid_w, fid_be, len_w, len_be, units, skip, nul):
    """Return next offset after one record, or None on failure."""
    if start + 1 + fid_w > len(b):
        return None
    t = b[start]
    p = start + 1 + fid_w

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
        ln = int.from_bytes(b[p:p + len_w], "little" if not len_be else "big")
        if ln <= 0:
            return None
        nbytes = ln * units
        if nbytes % 2 or nbytes > 8192:
            return None
        body = p + len_w + skip
        if body + nbytes > len(b):
            return None
        if nul and b[body] != 0:
            return None
        raw = b[body:body + nbytes]
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if any((ord(c) < 0x20 and c not in "\t\r\n") for c in s):
            return None
        return body + nbytes
    return None


def try_frame(b, fid_w, fid_be, len_w, len_be, units, skip, nul, start):
    i = start
    n = 0
    while i < len(b):
        nx = parse_flat(b, i, fid_w, fid_be, len_w, len_be, units, skip, nul)
        if nx is None or nx <= i:
            return False, n
        i = nx
        n += 1
        if n > 200:
            return False, n
    return i == len(b), n


print("═══ 穷举（要求完全消费整个小帧）═══")
winners = []
for fid_w in (1, 2):
    for fid_be in (True, False):
        for len_w in (1, 2, 3, 4):
            for len_be in (True, False):
                for units in (2, 1):
                    for skip in (0, 1, 2):
                        for nul in (True, False):
                            for start in (0, 1, 2, 3):
                                okall = 0
                                for b in SMALL:
                                    ok, _ = try_frame(b, fid_w, fid_be, len_w, len_be,
                                                      units, skip, nul, start)
                                    if ok:
                                        okall += 1
                                if okall == len(SMALL):
                                    winners.append((fid_w, fid_be, len_w, len_be,
                                                    units, skip, nul, start))
                                elif okall >= len(SMALL) - 1:
                                    print(f"  {okall}/{len(SMALL)}  "
                                          f"fid={fid_w}b{'BE' if fid_be else 'LE'} "
                                          f"len={len_w}b{'BE' if len_be else 'LE'}/{units} "
                                          f"skip={skip} nul={nul} start={start}")

if winners:
    print(f"\n★ 完全通过的小帧语法有 {len(winners)} 组：")
    for w in winners:
        print("   ", w)
    w = winners[0]
    print("\n── 用该语法逐记录展开首个 52 字节帧 ──")
    i = w[7]
    while i < len(SMALL[0]):
        t = SMALL[0][i]
        nx = parse_flat(SMALL[0], i, *w[:7])
        fid = int.from_bytes(SMALL[0][i + 1:i + 1 + w[0]],
                             "big" if w[1] else "little")
        payload = SMALL[0][i + 1 + w[0]:nx]
        print(f"  @{i:3d}  type=0x{t:02x}  fid=0x{fid:04x}  payload={payload.hex(' ')}")
        i = nx
else:
    print("\n没有语法能完全消费小帧 —— 说明小帧里也有容器/变长结构。")
