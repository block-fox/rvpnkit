#!/usr/bin/env python3
"""rvpnstate.py —— 从控制管道快照里解析网络与成员，供命令下发使用。

为什么要它
----------
启用/禁用、删除、踢人、授管这些命令的载荷是 **GUID 或节点 ID**，而不是名字。
这些 ID 只在管道快照里出现，所以必须先把快照解析出来。

快照里的结构（逆向所得）
------------------------
容器记录：`[size:u32 BE][0x00][0x00][0x13][tag]  <子记录>`
    tag = 0x23  网络条目：里面有一条 16 字节 GUID（字段 0x09）和一个名字（字段 0x06）
    tag = 0x44  节点/可见性更新：里面是若干 28 字节的节点块

普通记录：`[size:u32 BE][类型码][0x00][0x03][字段]  <payload>`
    类型 0x0d + 16 字节  -> GUID
    类型 0x03            -> UTF-16BE 字符串（尾部 00 01）
    类型 0x0b / 0x01     -> u32
节点块：  `00 00 00 08 02 00 01 e1 <u64 节点ID>`

用法
----
    python rvpnstate.py              # 列出网络和成员
    python rvpnstate.py --json       # JSON 输出
"""
import ctypes
import ctypes.wintypes as wt
import json
import re
import struct
import sys

PIPE = r"\\.\pipe\RadminVpnGuiChannel"
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                         ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
INVALID = ctypes.c_void_p(-1).value


def read_snapshot(timeout=6.0):
    """连上管道把快照读出来。只读即可，不会干扰 GUI。"""
    import time
    h = None
    for _ in range(10):
        h = k32.CreateFileW(PIPE, 0x80000000, 0, None, 3, 0, None)
        if h not in (INVALID, None):
            break
        time.sleep(0.3)
    if h in (INVALID, None):
        raise OSError(ctypes.get_last_error(), "打不开控制管道")

    buf = ctypes.create_string_buffer(1 << 20)
    n = wt.DWORD(0)
    data = bytearray()
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if k32.ReadFile(h, buf, 1 << 20, ctypes.byref(n), None):
                if n.value == 0:
                    break
                data += buf.raw[:n.value]
            else:
                break
    finally:
        k32.CloseHandle(h)
    return bytes(data)


def walk(data, start=0, end=None):
    """把字节流切成记录，遇到容器就递归。返回 [(field, type, payload, children)]。"""
    end = len(data) if end is None else end
    out = []
    off = start
    while off + 8 <= end:
        size = int.from_bytes(data[off:off + 4], "big")
        t, pad, three, field = data[off + 4:off + 8]
        if size > end - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        children = None
        # 容器：类型码 0x00 且第 3 字节是 0x13（观察到的 0x1323 / 0x132b / 0x1344）
        if t == 0x00 and three == 0x13:
            children = walk(payload, 0, len(payload))
        out.append((field, t, payload, children))
        off += 8 + size
    return out


def dec_str(payload):
    """字符串载荷：UTF-16BE，尾部 00 01。"""
    body = payload
    if body.endswith(b"\x00\x01"):
        body = body[:-2]
    try:
        s = body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    # 过滤掉明显不是文本的
    if not s or any(ord(c) < 32 for c in s):
        return None
    return s


def dec_node_id(payload):
    """节点块 payload：00 00 00 08 02 00 01 e1 <u64>。"""
    if len(payload) >= 16 and payload[4:8] == bytes([0x02, 0x00, 0x01, 0xE1]):
        return int.from_bytes(payload[8:16], "big")
    return None


def split_frames(data):
    """快照是多帧拼接：每帧 = [u32 LE 长度][正文]。拆开后逐帧解析。"""
    frames = []
    off = 0
    n = len(data)
    while off + 4 <= n:
        ln = int.from_bytes(data[off:off + 4], "little")
        if ln == 0 or ln > n - off - 4:
            break
        frames.append(data[off + 4:off + 4 + ln])
        off += 4 + ln
    return frames


def parse(data):
    """返回 {networks: [...], nodes: [...]}。"""
    networks = []
    nodes = {}

    def visit(recs):
        guid = None
        name = None
        for field, t, payload, children in recs:
            if t == 0x0D and len(payload) == 16:
                guid = payload
            elif t == 0x03:
                s = dec_str(payload)
                if s and name is None and len(s) >= 1:
                    name = s
            nid = dec_node_id(payload)
            if nid is not None:
                nodes.setdefault(nid, {})
            if children:
                visit(children)
        if guid is not None and name is not None:
            networks.append({"guid": guid.hex(), "name": name})

    frames = split_frames(data)
    # 拆不开就整段当一帧试
    bodies = frames if frames else [data]
    for body in bodies:
        visit(walk(body))

    # 去重
    seen = set()
    uniq = []
    for n in networks:
        if n["guid"] in seen:
            continue
        seen.add(n["guid"])
        uniq.append(n)

    node_list = [{"nodeId": k} for k in sorted(nodes)]
    return {"networks": uniq, "nodes": node_list}


def main(argv):
    try:
        data = read_snapshot()
    except OSError as e:
        print(f"✗ {e}")
        return 1
    print(f"快照 {len(data):,} 字节")

    st = parse(data)
    if "--json" in argv:
        print(json.dumps(st, ensure_ascii=False, indent=2))
        return 0

    print(f"\n=== 网络 {len(st['networks'])} 个 ===")
    for n in st["networks"]:
        print(f"  {n['name'][:40]:<42} {n['guid']}")

    print(f"\n=== 节点 {len(st['nodes'])} 个（前 20）===")
    for nd in st["nodes"][:20]:
        print(f"  {nd['nodeId']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
