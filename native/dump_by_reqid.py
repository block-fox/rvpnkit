#!/usr/bin/env python3
"""dump_by_reqid.py —— 按请求编号打印完整帧字节，用于对比不同命令的差异。

用法：
    python dump_by_reqid.py 33 35 51 26 68 67 47
    python dump_by_reqid.py --all-known
"""
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_capture import parse_capture, records, utf16_strings, req_id  # noqa: E402

CAPTURE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpn_capture")
SVC_LOG = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

# 从服务日志里挑出的、语义已知的请求
KNOWN = {
    26: "改别名 -> 快乐狐狸1",
    27: "改别名 -> 快乐狐狸",
    33: "创建网络 '111'",
    35: "离开网络 'Minecraft [Português 10]'",
    38: "创建网络 '114455667788'",
    41: "创建网络 '91919191免费'",
    44: "创建网络 '91919191免费'(重试)",
    47: "??? Succeeded（60字节）",
    48: "??? Succeeded（60字节）",
    51: "删除网络 '91919191免费'",
    56: "创建网络 '221321312321sdwa'",
    63: "删除网络 '221321312321sdwa'",
    67: "???（60字节，紧跟 join 之前）",
    68: "加入网络 'Minecraft [中文 2]'",
    71: "???（60字节）",
    72: "加入网络 'Minecraft [中文 3]'",
    75: "创建网络 'flex123213'",
    76: "删除网络 'flex123213'",
}


def load_all():
    frames = []
    for f in sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.log"))):
        for ts, data in parse_capture(f):
            frames.append((ts, data))
    return frames


def svc_desc():
    idx = {}
    if not os.path.exists(SVC_LOG):
        return idx
    raw = open(SVC_LOG, "rb").read()
    for line in raw.decode("utf-16-le", "ignore").splitlines():
        m = re.search(r"\[req:(\d+)\]\s*(.+)$", line)
        if m:
            rid, desc = int(m.group(1)), m.group(2).strip()
            if idx.get(rid) in (None, "Succeeded") and desc != "Succeeded":
                idx[rid] = desc
            idx.setdefault(rid, desc)
    return idx


def dump(ts, data, label):
    print("=" * 78)
    print(f"reqId={req_id(data)}  len={len(data)}  {ts}")
    if label:
        print(f"语义: {label}")
    strs = utf16_strings(data)
    if strs:
        print(f"字符串: {[s for _, s in strs][:5]}")
    print("-" * 78)
    for k in range(0, len(data), 16):
        chunk = data[k:k + 16]
        print(f"  {k:04x}  " + " ".join(f"{b:02x}" for b in chunk))
    print("  记录:")
    for field, t, size, payload in records(data):
        print(f"    field=0x{field:02x} type=0x{t:02x} size={size:<4} "
              f"payload={payload.hex(' ')[:80]}")
    print()


def main(argv):
    frames = load_all()
    svc = svc_desc()

    if "--all-known" in argv:
        wanted = sorted(KNOWN)
    else:
        wanted = [int(a) for a in argv[1:] if a.isdigit()]

    if not wanted:
        print(__doc__)
        return 2

    for rid in wanted:
        hit = [f for f in frames if req_id(f[1]) == rid]
        if not hit:
            print(f"--- reqId={rid}: 未找到 ---\n")
            continue
        ts, data = hit[0]
        label = KNOWN.get(rid) or svc.get(rid, "")
        dump(ts, data, label)
    return 0


sys.exit(main(sys.argv))
