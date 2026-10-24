#!/usr/bin/env python3
"""correlate.py —— 用「时间戳 + reqId」双重条件把抓到的帧和服务日志精确对上。

为什么不能只用 reqId
--------------------
服务重启或日志轮转后，请求编号会从头计数。实测同一个 reqId=35：
- 早先的日志里是 `Requested to leave network 'Minecraft [Português 10]'`
- 当前日志里是   `Requested to create network '111111111'`
只按 reqId 关联会张冠李戴。因此这里要求 **reqId 相同且时间差在阈值内**。
"""
import glob
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_capture import parse_capture, req_id  # noqa: E402

CAPTURE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpn_capture")
LOG_DIR = r"C:\ProgramData\Famatech\Radmin VPN"
WINDOW = 4.0   # 秒


def svc_events():
    """返回 [(时间, reqId, 描述)]，覆盖所有历史日志。"""
    out = []
    for f in glob.glob(os.path.join(LOG_DIR, "service*.log")):
        try:
            raw = open(f, "rb").read()
        except OSError:
            continue
        for line in raw.decode("utf-16-le", "ignore").splitlines():
            m = re.match(r"(\d{4})\.(\d{2})\.(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})\s+\w+\s+(.*)$",
                         line.strip())
            if not m:
                continue
            ts = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), int(m.group(6)),
                          int(m.group(7)) * 1000)
            msg = m.group(8)
            rm = re.search(r"\[req:(\d+)\]\s*(.+)$", msg)
            if rm:
                out.append((ts, int(rm.group(1)), rm.group(2).strip()))
    out.sort(key=lambda x: x[0])
    return out


def frames():
    out = []
    for f in sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.log"))):
        for ts_str, data in parse_capture(f):
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                continue
            out.append((ts, data))
    out.sort(key=lambda x: x[0])
    return out


def main():
    evs = svc_events()
    frs = frames()
    print(f"服务日志事件 {len(evs)} 条，抓包帧 {len(frs)} 条\n")

    # 建立 (时间, reqId) -> 描述
    print("=" * 100)
    print(f"{'时间':<23} {'len':>5} {'reqId':>7}  {'时间差':>7}  描述")
    print("=" * 100)

    for ts, data in frs:
        rid = req_id(data)
        if rid in (None, 0xFFFFFFFF):
            # GUI 的周期性上报，不产生请求编号
            continue
        best = None
        for ets, erid, desc in evs:
            if erid != rid:
                continue
            delta = abs((ets - ts).total_seconds())
            if delta <= WINDOW and (best is None or delta < best[0]):
                best = (delta, ets, desc)
        delta_s = f"{best[0]:.2f}s" if best else "-"
        desc = best[2] if best else "（未匹配到服务日志）"
        tss = ts.strftime("%H:%M:%S.%f")[:-3]
        print(f"{tss:<23} {len(data):>5} {rid:>7}  {delta_s:>7}  {desc[:60]}")

    print("\n" + "=" * 100)
    print("按语义归类（同名命令的不同调用会合并）")
    print("=" * 100)
    groups = {}
    for ts, data in frs:
        rid = req_id(data)
        if rid in (None, 0xFFFFFFFF):
            continue
        best = None
        for ets, erid, desc in evs:
            if erid != rid:
                continue
            delta = abs((ets - ts).total_seconds())
            if delta <= WINDOW and (best is None or delta < best[0]):
                best = (delta, ets, desc)
        if not best:
            continue
        key = re.sub(r"'[^']*'", "'…'", best[2])
        key = re.sub(r"\d+", "N", key)
        groups.setdefault(key, []).append((len(data), data))
    for key, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        lens = sorted({l for l, _ in items})
        sample = items[0][1]
        hdr = sample[:28].hex(" ")
        print(f"  {len(items):>2} 次  长度 {lens}  {key}")
        print(f"        头部: {hdr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
