#!/usr/bin/env python3
"""analyze_capture.py —— 分析抓到的命令报文。

做三件事
--------
1. 把每条帧拆成「记录」序列，输出结构签名，便于按形状归类
2. 抽取内嵌的 UTF-16LE 字符串（网络名、别名等）
3. 用帧里的请求编号去服务日志里查 [req:N] 行，得到该命令的语义描述

这样即使命令码是未知的，也能靠服务端的日志知道它做了什么。

用法：
    python analyze_capture.py              # 全部分析
    python analyze_capture.py --raw        # 额外打印每条帧的十六进制
    python analyze_capture.py --file X.log # 只分析指定文件
"""
import glob
import os
import re
import struct
import sys

CAPTURE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpn_capture")
SVC_LOG = r"C:\ProgramData\Famatech\Radmin VPN\service.log"
MAGIC = bytes.fromhex("00000004 0100".replace(" ", ""))


def parse_capture(path):
    """返回 [(时间戳, 字节串)]。"""
    out = []
    text = open(path, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r"^=== (\S+ \S+) len=(\d+)[^=]*===\s*\nHEX:\n(.*?)\nASCII:",
                         text, re.S | re.M):
        ts, declared, hexbody = m.group(1), int(m.group(2)), m.group(3)
        try:
            data = bytes.fromhex(hexbody.replace("\n", " ").replace(" ", ""))
        except ValueError:
            continue
        if len(data) == declared:
            out.append((ts, data))
    return out


def records(data):
    """按 [size:u32 BE][type:u8][00][03][field:u8][payload] 拆记录。"""
    res = []
    off = 0
    while off + 8 <= len(data):
        size = int.from_bytes(data[off:off + 4], "big")
        type_code, pad, three, field = data[off + 4:off + 8]
        if size > len(data) - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        res.append((field, type_code, size, payload))
        off += 8 + size
    return res


def utf16_strings(data, min_chars=3):
    """从字节里捞出可读的 UTF-16LE 字符串。"""
    found = []
    i = 0
    n = len(data)
    while i + 2 <= n:
        # 尝试从当前位置按 UTF-16LE 读一段
        chars = []
        j = i
        while j + 1 < n:
            cp = data[j] | (data[j + 1] << 8)
            if 32 <= cp < 127 or 0x4E00 <= cp <= 0x9FFF or cp in (0x2013, 0x2014, 0x00B7):
                chars.append(chr(cp))
                j += 2
            else:
                break
        if len(chars) >= min_chars:
            found.append((i, "".join(chars)))
            i = j
        else:
            i += 1
    return found


def req_id(data):
    """请求编号位于魔数记录的值域，即 offset 8..12（u32 BE）。"""
    if len(data) >= 12 and data[:6] == MAGIC:
        return int.from_bytes(data[8:12], "big")
    return None


def svc_index():
    """从服务日志建 请求编号 -> 描述 的索引。"""
    idx = {}
    if not os.path.exists(SVC_LOG):
        return idx
    raw = open(SVC_LOG, "rb").read()
    text = raw.decode("utf-16-le", "ignore")
    for line in text.splitlines():
        m = re.search(r"\[req:(\d+)\]\s*(.+)$", line)
        if m:
            rid = int(m.group(1))
            desc = m.group(2).strip()
            got = idx.get(rid)
            # 优先保留非 Succeeded 的描述性文字
            if got is None or (got == "Succeeded" and desc != "Succeeded"):
                idx[rid] = desc
    return idx


def signature(data):
    """结构签名：记录字段号 + 类型码，用于归类不同命令。"""
    recs = records(data)
    if recs:
        return " | ".join(f"f{f:02x}/t{t:02x}/s{s}" for f, t, s, _ in recs)
    return f"raw len={len(data)}"


def main(argv):
    only = None
    show_raw = "--raw" in argv
    if "--file" in argv:
        only = argv[argv.index("--file") + 1]

    files = [only] if only else sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.log")))
    if not files:
        print("没有抓包文件。先运行 capture.py start，然后在 Radmin 里操作。")
        return 1

    svc = svc_index()
    print(f"服务日志索引: {len(svc)} 条 [req:N] 记录\n")

    all_frames = []
    for f in files:
        frames = parse_capture(f)
        all_frames.extend((os.path.basename(f), ts, d) for ts, d in frames)
        print(f"{os.path.basename(f)}: {len(frames)} 帧")

    print(f"\n合计 {len(all_frames)} 帧\n")

    # 按结构签名归类
    groups = {}
    for src, ts, data in all_frames:
        groups.setdefault(signature(data), []).append((src, ts, data))

    print("=" * 78)
    print("按结构归类")
    print("=" * 78)
    for i, (sig, items) in enumerate(sorted(groups.items(), key=lambda kv: -len(kv[1])), 1):
        print(f"\n[{i}] {len(items)} 帧   签名: {sig[:110]}")
        src, ts, data = items[0]
        rid = req_id(data)
        desc = svc.get(rid) if rid is not None else None
        print(f"    首帧 {ts}  len={len(data)}  reqId={rid}  {('服务日志: ' + desc) if desc else ''}")
        strs = utf16_strings(data)
        if strs:
            print(f"    内嵌字符串: {[s for _, s in strs][:4]}")
        if show_raw:
            for k in range(0, len(data), 16):
                print("      " + " ".join(f"{b:02x}" for b in data[k:k + 16]))

    # 按时间列出所有帧及其语义
    print("\n" + "=" * 78)
    print("时间线（请求编号 → 服务日志语义）")
    print("=" * 78)
    for src, ts, data in sorted(all_frames, key=lambda x: x[1]):
        rid = req_id(data)
        desc = svc.get(rid, "") if rid is not None else ""
        strs = utf16_strings(data)
        extra = f"  «{strs[0][1]}»" if strs else ""
        print(f"  {ts}  len={len(data):<5} reqId={rid!s:<7} {desc[:60]}{extra}")

    return 0


sys.exit(main(sys.argv))
