"""用一个不存在的网络名撞「密码字段号」。

服务端日志的模板是：
    Requested to join network '%ls' %hs password
其中 %hs 会是 "with" 或 "without"。所以只要构造
    [u32(1, 0x3f)] [str(名字, 0x06)] [str(密码, <候选字段>)]
发过去，看日志变成 "with password" 就说明命中了。

用不存在的网络名，所以不会有任何副作用。
"""

import glob
import os
import re
import struct
import sys
import time

sys.path.insert(0, r"D:\工作区\workspace1\RvpnKit\native")
import rvpncmd as R  # noqa: E402
from probe_commands import send  # noqa: E402

LOG_DIR = r"C:\ProgramData\Famatech\Radmin VPN"
NAME = "rvpnkit-pw-probe-does-not-exist"
PASSWORD = "secret123"


def join_with_password(field: int, req_id: int) -> bytes:
    inner = (
        R.rec_u32(1, 0x3F)
        + R.rec_str(NAME, 0x06)
        + R.rec_str(PASSWORD, field)
    )
    return (
        R.head(req_id, 0x03)
        + struct.pack(">I", len(inner))
        + struct.pack(">I", 0x0000131B)
        + inner
    )


def recent_req_lines(since_rid: int):
    out = []
    for f in glob.glob(os.path.join(LOG_DIR, "service*.log")):
        try:
            raw = open(f, "rb").read()
        except OSError:
            continue
        for line in raw.decode("utf-16-le", "ignore").splitlines():
            m = re.search(r"\[req:(\d+)\]\s*(.+)$", line.strip())
            if m and int(m.group(1)) >= since_rid:
                out.append((int(m.group(1)), m.group(2).strip()))
    return out


def main():
    base = 91000
    fields = [f for f in range(0x00, 0x40) if f not in (0x4A, 0x00, 0x06, 0x3F)]
    print(f"探测 {len(fields)} 个候选字段号，每个带密码 '{PASSWORD}'")

    results = {}
    for i, field in enumerate(fields):
        rid = base + i
        try:
            send(join_with_password(field, rid))
        except Exception as e:
            print(f"  字段 0x{field:02x} 发送失败: {e}")
            continue
        time.sleep(0.09)

    time.sleep(3.0)

    for rid, desc in recent_req_lines(base):
        idx = rid - base
        if 0 <= idx < len(fields):
            results[fields[idx]] = desc

    print()
    print("=" * 78)
    with_pw = []
    without_pw = []
    for field in fields:
        d = results.get(field)
        if not d:
            continue
        if "with password" in d and "without" not in d:
            with_pw.append(field)
            print(f"  字段 0x{field:02x}  ★ {d[:90]}")
        elif "without password" in d:
            without_pw.append(field)

    print()
    print(f"  变成 'with password' 的字段: {[hex(f) for f in with_pw]}")
    print(f"  仍是 'without password' 的字段数: {len(without_pw)}")
    print(f"  完全没日志（解析失败）的字段数: {len(fields) - len(results)}")

    if not results:
        print("\n  一条日志都没有 —— 可能服务对该形状的帧静默丢弃")
    return 0


if __name__ == "__main__":
    sys.exit(main())
