#!/usr/bin/env python3
"""probe_commands.py —— 用命令码扫描反推完整的命令表。

原理
----
服务对每个**解析成功**的请求都会写一行 `[req:N] <描述>`，即使操作最终失败。
所以我们不需要真的触发 UI，只要发一帧结构正确、但**目标不存在**的命令，
服务就会把它的语义写进日志。

安全性
------
载荷里用的 GUID 是随机生成的、不存在的目标。任何删除/踢人/启用操作都会
因为「找不到对象」而失败，不会影响真实网络。这也是为什么这一步不需要人工
在界面上操作。

用法
----
    python probe_commands.py sweep-guid            # GUID 载荷，扫 0x00..0x40
    python probe_commands.py sweep-guid --range 0 255
    python probe_commands.py sweep-str "probe"     # 字符串载荷
"""
import ctypes
import ctypes.wintypes as wt
import glob
import os
import re
import struct
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rvpncmd as R  # noqa: E402

LOG_DIR = r"C:\ProgramData\Famatech\Radmin VPN"


def svc_describe_all():
    """把服务日志里 请求编号 -> 描述 全部收集起来（跨所有历史日志）。"""
    out = {}
    for f in glob.glob(os.path.join(LOG_DIR, "service*.log")):
        try:
            raw = open(f, "rb").read()
        except OSError:
            continue
        for line in raw.decode("utf-16-le", "ignore").splitlines():
            m = re.search(r"\[req:(\d+)\]\s*(.+)$", line.strip())
            if m:
                rid, desc = int(m.group(1)), m.group(2).strip()
                if desc != "Succeeded":
                    out[rid] = desc
                out.setdefault(rid, desc)
    return out


def send(body: bytes) -> bool:
    h, err = R.open_pipe()
    if not h:
        print(f"  管道打开失败 err={err}")
        return False
    try:
        R.write_frame(h, body)
        return True
    except OSError as e:
        print(f"  写入失败 {e}")
        return False
    finally:
        R.k32.CloseHandle(h)


def frame_guid(code: int, req_id: int, guid: bytes, with_flag: bool) -> bytes:
    body = R.head(req_id, code) + R.rec_guid(guid)
    if with_flag:
        body += R.rec_u32(0, 0x16)
    return body


def frame_str(code: int, req_id: int, text: str, field: int) -> bytes:
    return R.head(req_id, code) + R.rec_str(text, field)


def sweep_guid(start: int, end: int):
    """用一个不存在的随机 GUID 遍历命令码，看服务把每个码解释成什么。"""
    guid = os.urandom(16)
    print(f"使用不存在的随机 GUID: {guid.hex()}")
    print(f"扫描命令码 0x{start:02x}..0x{end:02x}，每种码试两种载荷形态\n")

    found = {}
    base = 40000
    before = set(svc_describe_all().keys())

    for code in range(start, end + 1):
        for with_flag in (False, True):
            rid = base + code * 2 + (1 if with_flag else 0)
            body = frame_guid(code, rid, guid, with_flag)
            if not send(body):
                continue
            time.sleep(0.18)

    time.sleep(2.0)
    after = svc_describe_all()

    print("=" * 88)
    print("扫描结果（只列出服务确实解析并记录了描述的命令码）")
    print("=" * 88)
    for code in range(start, end + 1):
        descs = []
        for k in (0, 1):
            rid = base + code * 2 + k
            d = after.get(rid)
            if d:
                descs.append(("带u32" if k else "仅GUID", d))
        if descs:
            found[code] = descs
            for shape, d in descs:
                print(f"  0x{code:02x} ({code:>3})  [{shape:<7}]  {d[:80]}")
    print()
    print(f"共命中 {len(found)} 个命令码")
    return found


def sweep_str(text: str, start: int = 0, end: int = 0x40):
    """用字符串载荷遍历命令码，找出收字符串的那类命令。"""
    print(f"字符串载荷 '{text}'，扫描命令码 0x{start:02x}..0x{end:02x}\n")
    base = 50000
    for code in range(start, end + 1):
        rid = base + code
        send(frame_str(code, rid, text, 0x06))
        time.sleep(0.18)
    time.sleep(2.0)
    after = svc_describe_all()
    print("=" * 88)
    for code in range(start, end + 1):
        d = after.get(base + code)
        if d:
            print(f"  0x{code:02x} ({code:>3})  {d[:80]}")
    print()


def frame_u64(code: int, req_id: int, value: int) -> bytes:
    """节点类命令的载荷：u64 节点 ID。

    注意这条记录的头是 `02 00 01 e1`，不是通用的 `01 00 03 xx`：
    抓包里的节点记录是
        00 00 00 08 02 00 01 e1 00 00 00 00 04 1f d3 74
    即 [size=8][类型码=0x02][0x00][0x01][字段=0xe1][u64 节点ID]。
    一开始照通用形状构造，扫描全程无命中，就是这里弄错了。
    """
    return (R.head(req_id, code)
            + struct.pack(">I", 8) + bytes([0x02, 0x00, 0x01, 0xE1])
            + struct.pack(">Q", value))


def frame_u64_container(code: int, req_id: int, value: int) -> bytes:
    """把节点 ID 包进容器里 —— 可见性上报就是这种形状。"""
    inner = (struct.pack(">I", 8) + bytes([0x02, 0x00, 0x01, 0xE1])
             + struct.pack(">Q", value)
             + R.rec_u32(1, 0x76))
    return (R.head(req_id, code) + struct.pack(">I", len(inner))
            + struct.pack(">I", 0x00001344) + inner)


def sweep_tag(start: int, end: int, code: int = 2):
    """遍历容器标签 0x13XX，找网络/节点类的子命令。

    观察到的容器标签：
        0x131b = 加入网络
        0x1323 = 网络信息（GUID + 名字）
        0x132b = 创建网络（名字 + 28 字节密钥）
        0x1344 = 节点可见性更新
    可见 0x13XX 的 XX 部分就是子消息类型编号。踢人很可能藏在这里面。
    """
    guid = os.urandom(16)
    node = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFFFFFFFFFF
    print(f"命令码固定 0x{code:02x}，遍历容器标签 0x{start:04x}..0x{end:04x}")
    print(f"载荷用不存在的 GUID {guid.hex()[:16]}… 与节点 {node}\n")

    base = 70000
    payloads = [
        ("guid", R.rec_guid(guid)),
        ("node", struct.pack(">I", 8) + bytes([0x02, 0x00, 0x01, 0xE1])
                 + struct.pack(">Q", node)),
    ]

    for tag in range(start, end + 1):
        for k, (label, inner) in enumerate(payloads):
            rid = base + (tag - start) * 2 + k
            body = (R.head(rid, code) + struct.pack(">I", len(inner))
                    + struct.pack(">I", tag) + inner)
            send(body)
            time.sleep(0.12)

    time.sleep(2.0)
    after = svc_describe_all()
    print("=" * 88)
    hits = 0
    for tag in range(start, end + 1):
        for k, (label, _) in enumerate(payloads):
            d = after.get(base + (tag - start) * 2 + k)
            if d:
                print(f"  标签 0x{tag:04x}  [{label:<4}]  {d[:74]}")
                hits += 1
    print(f"\n共命中 {hits} 个\n")


def sweep_u64(start: int, end: int):
    """用不存在的节点 ID 遍历命令码，找节点类命令（踢人 / 可见性等）。"""
    node = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFFFFFFFFFF
    print(f"使用不存在的随机节点 ID: {node}")
    print(f"扫描命令码 0x{start:02x}..0x{end:02x}，裸载荷 + 容器载荷\n")

    base = 60000
    for code in range(start, end + 1):
        send(frame_u64(code, base + code * 2, node))
        time.sleep(0.15)
        send(frame_u64_container(code, base + code * 2 + 1, node))
        time.sleep(0.15)
    time.sleep(2.0)

    after = svc_describe_all()
    print("=" * 88)
    hits = 0
    for code in range(start, end + 1):
        for k, shape in ((0, "裸"), (1, "容器")):
            d = after.get(base + code * 2 + k)
            if d:
                print(f"  0x{code:02x} ({code:>3})  [{shape}]  {d[:76]}")
                hits += 1
    print(f"\n共命中 {hits} 个\n")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    action = argv[1]

    if action == "sweep-guid":
        start, end = 0, 0x40
        if "--range" in argv:
            i = argv.index("--range")
            start, end = int(argv[i + 1]), int(argv[i + 2])
        sweep_guid(start, end)
        return 0

    if action == "sweep-tag":
        start, end = 0x1300, 0x1360
        if "--range" in argv:
            i = argv.index("--range")
            start, end = int(argv[i + 1], 0), int(argv[i + 2], 0)
        code = 2
        if "--code" in argv:
            code = int(argv[argv.index("--code") + 1], 0)
        sweep_tag(start, end, code)
        return 0

    if action == "sweep-u64":
        start, end = 0, 0x40
        if "--range" in argv:
            i = argv.index("--range")
            start, end = int(argv[i + 1]), int(argv[i + 2])
        sweep_u64(start, end)
        return 0

    if action == "sweep-str":
        text = argv[2] if len(argv) > 2 else "probe"
        sweep_str(text)
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
