"""Definitively determine the string-record layout by testing every alignment
against known ground-truth strings, using computed offsets only.

Ground truth: we know the exact UTF-16 payload offsets of several strings from
an earlier verified dump.  For each candidate layout we ask: "if we start
parsing a record at (payload_offset - k), does the decoded string equal the
known value?"  The layout that succeeds for every sample is the answer.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = [
    os.path.join(HERE, "captures", "snap.bin"),
    r"D:\工作区\workspace1\recon\captures\snap.bin",
]
CAP = next(p for p in CANDIDATES if os.path.isfile(p))
data = open(CAP, "rb").read()
print(f"数据: {CAP}  ({len(data):,} 字节)\n")

# 先用程序定位每个已知字符串的 UTF-16 正文起点
SAMPLES = [
    "FORSAKEN",
    "DESKTOP-41MCISL",
    "198.244.203.247",
    "148.113.190.78",
    "2.1.1",
]

print("=== 已知字符串的正文起算偏移（程序计算）===")
found = []
for s in SAMPLES:
    key = s.encode("utf-16-le")
    idx = data.find(key)
    if idx < 0:
        print(f"  {s!r}: 未找到")
        continue
    found.append((s, idx))
    print(f"  {s!r:<20} 正文起始 = {idx} (0x{idx:x})")

print()
print("=== 穷举布局 ===")
print("    记录 = [type:1] [fid:W] [len:L] [填充:S] [UTF-16LE 正文]")
print("    长度单位同时试「字节数」与「字符数」\n")

winners = []

for fid_w in (1, 2, 3):
    for fid_be in (True, False):
        for len_w in (1, 2, 3, 4):
            for len_be in (True, False):
                for pad in (0, 1, 2):          # 长度字段与正文之间的填充
                    for k in range(3, 16):     # 记录起点 = 正文起点 - k
                        ok_all = True

                        for s, body_off in found:
                            start = body_off - k
                            if start < 0:
                                ok_all = False
                                break

                            p = start + 1 + fid_w
                            if p + len_w > len(data):
                                ok_all = False
                                break

                            ln = int.from_bytes(data[p:p + len_w],
                                                "big" if len_be else "little")
                            if ln <= 0 or ln > 8192:
                                ok_all = False
                                break

                            # 两种单位各试一次，任一能还原即可
                            matched = False
                            for nbytes in (ln, ln * 2):
                                body = p + len_w + pad
                                if body + nbytes > len(data) or nbytes % 2:
                                    continue
                                try:
                                    s2 = data[body:body + nbytes].decode("utf-16-le")
                                except UnicodeDecodeError:
                                    continue
                                s2 = s2.lstrip("\x00")
                                if s2.startswith(s):
                                    matched = True
                                    break

                            if not matched:
                                ok_all = False
                                break

                        if ok_all:
                            winners.append((fid_w, fid_be, len_w, len_be, pad, k))
                            fid_txt = f"fid={fid_w}b{'BE' if fid_be else 'LE'}"
                            len_txt = f"len={len_w}b{'BE' if len_be else 'LE'}"
                            print(f"  ★ 通过: {fid_txt} {len_txt} pad={pad} 记录起点=正文-{k}")

print()
if winners:
    fid_w, fid_be, len_w, len_be, pad, k = winners[0]
    print("═══ 确定的布局 ═══")
    print(f"  记录 = [type:1] [fid:{fid_w}b {'BE' if fid_be else 'LE'}] "
          f"[len:{len_w}b {'BE' if len_be else 'LE'}] [pad:{pad}] [UTF-16LE]")
    print(f"  正文起点 = 记录起点 + {k}")
    print()
    print("  各样本解析：")
    for s, body_off in found:
        start = body_off - k
        typ = data[start]
        p = start + 1 + fid_w
        fid = int.from_bytes(data[start + 1:p], "big" if fid_be else "little")
        ln = int.from_bytes(data[p:p + len_w], "big" if len_be else "little")
        print(f"    type=0x{typ:02x}  fid=0x{fid:04x}  len={ln:<4} '{s}'")
else:
    print("仍无布局通过。")
    print("说明我对正文起点的假设有误，需要重新采集精确样本。")
