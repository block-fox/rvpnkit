"""更大范围地找密码字段。

上次只扫了 join 容器内 0x00..0x3f 的字符串字段，全部是 "without password"。
这次：
  1. 扫 0x40..0xff（有些字段号是复合的，比如网络 token 就是 0x47）
  2. 试把密码记录放在**容器外**（顶层）
  3. 试不同的记录类型（0x03 字符串 / 0x08 大块）

判据仍是服务端日志里的 "with password" / "without password"。
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
PASSWORD = "deepseektester"


def build(inner_extra: bytes, top_extra: bytes, req_id: int) -> bytes:
    inner = R.rec_u32(1, 0x3F) + R.rec_str(NAME, 0x06) + inner_extra
    frame = (
        R.head(req_id, 0x03)
        + struct.pack(">I", len(inner))
        + struct.pack(">I", 0x0000131B)
        + inner
    )
    return frame + top_extra


def recent_lines(since_rid: int):
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


def sweep(label, cases, base):
    """cases: [(描述, 请求编号偏移)] -> 发送并看日志"""
    for i, (desc, inner_extra, top_extra) in enumerate(cases):
        rid = base + i
        try:
            send(build(inner_extra, top_extra, rid))
        except Exception as e:
            print(f"  {desc} 发送失败: {e}")
        time.sleep(0.085)
    time.sleep(2.5)

    hits = []
    for rid, text in recent_lines(base):
        idx = rid - base
        if 0 <= idx < len(cases):
            if "with password" in text and "without" not in text:
                hits.append((cases[idx][0], text))
    print(f"\n[{label}] 命中 {len(hits)} 个")
    for d, t in hits:
        print(f"   ★ {d}  ->  {t[:90]}")
    return hits


def main():
    P = PASSWORD

    # 1) 容器内字符串字段 0x40..0xff
    cases = []
    for field in range(0x40, 0x100):
        if field in (0x4A,):
            continue
        cases.append((f"容器内 str 字段 0x{field:02x}", R.rec_str(P, field), b""))
    sweep("容器内 0x40..0xff", cases, 92000)

    # 2) 顶层字符串字段 0x00..0xff
    cases = [("", b"", b"")]
    cases = [
        (f"顶层 str 字段 0x{field:02x}", b"", R.rec_str(P, field))
        for field in range(0x00, 0x100)
        if field != 0x4A
    ]
    sweep("顶层 0x00..0xff", cases, 93000)

    # 3) 不同记录类型（容器内）
    cases = []
    for field in (0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x0E, 0x47, 0x48, 0x49):
        cases.append((f"容器内 type08 字段 0x{field:02x}", R.rec(len(P.encode()), 0x08, field) + P.encode(), b""))
    sweep("容器内 type08", cases, 94000)

    return 0


if __name__ == "__main__":
    sys.exit(main())
