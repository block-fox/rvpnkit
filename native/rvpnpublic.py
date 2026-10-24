#!/usr/bin/env python3
"""rvpnpublic.py —— 枚举公共网络（快捷加入公共网络的数据源）。

思路
----
`CEnumPublicNetworks`（命令码 0x13）不写日志、也不在快照里 ——
它的结果是作为**管道响应**回来的。所以必须「发命令 + 同时读响应」，
再从响应帧里把网络名和 ID 解析出来。

用法：
    python rvpnpublic.py            # 列出公共网络
    python rvpnpublic.py --json
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
import rvpncmd as R  # noqa: E402
from rvpnstate import split_frames, walk, dec_str  # noqa: E402

PIPE = R.PIPE
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                         ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
INVALID = ctypes.c_void_p(-1).value


def collect(timeout=4.0, send_enum=True):
    """连上管道，可选地先发一条枚举请求，然后把这段时间的响应都收下来。"""
    h = None
    for _ in range(10):
        h = k32.CreateFileW(PIPE, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
        if h not in (INVALID, None):
            break
        time.sleep(0.3)
    if h in (INVALID, None):
        raise OSError(ctypes.get_last_error(), "打不开管道（读写）")

    if send_enum:
        rid = int.from_bytes(os.urandom(2), "big")
        body = R.build_enum("", rid)
        buf = struct.pack("<I", len(body)) + body
        arr = ctypes.create_string_buffer(buf, len(buf))
        n = wt.DWORD(0)
        k32.WriteFile(h, arr, len(buf), ctypes.byref(n), None)

    rb = ctypes.create_string_buffer(1 << 20)
    rd = wt.DWORD(0)
    data = bytearray()
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if k32.ReadFile(h, rb, 1 << 20, ctypes.byref(rd), None):
                if rd.value == 0:
                    break
                data += rb.raw[:rd.value]
            else:
                break
    finally:
        k32.CloseHandle(h)
    return bytes(data)


def extract(data):
    """从响应里抽 (名字, 可能的前置数字ID)。"""
    names = []
    seen = set()

    def visit(recs):
        for field, t, payload, children in recs:
            if t == 0x03:
                s = dec_str(payload)
                if s and 3 <= len(s) <= 64 and s not in seen:
                    seen.add(s)
                    names.append((field, s))
            if children:
                visit(children)

    for body in split_frames(data):
        visit(walk(body))
    return names


def public_networks():
    """返回 [(名字)]：可用但尚未加入的网络。"""
    from rvpnstate import read_snapshot, parse
    data = collect(timeout=4.0)
    names = extract(data)
    f6 = []
    seen = set()
    for f, s in names:
        if f == 0x06 and s not in seen:
            seen.add(s)
            f6.append(s)
    st = parse(read_snapshot())
    joined = {n["name"] for n in st["networks"]}
    return [s for s in f6 if s not in joined], joined


def main(argv):
    if len(argv) > 1 and argv[1] in ("join", "add"):
        keyword = argv[2] if len(argv) > 2 else ""
        if not keyword:
            print("用法: rvpnpublic.py join <关键字>")
            return 2
        lst, _ = public_networks()
        matches = [s for s in lst if keyword.lower() in s.lower()]
        if not matches:
            print(f"没有匹配 '{keyword}' 的公共网络")
            return 1
        print(f"匹配 {len(matches)} 个，取第一个: {matches[0]}")
        rid = R.new_req_id()
        return R.dispatch(R.build_join(matches[0], rid), rid,
                          f"快捷加入公共网络 '{matches[0]}'")

    print("发送 CEnumPublicNetworks 并收集响应…")
    lst, joined = public_networks()

    if "--json" in argv:
        print(json.dumps({"public": lst, "joined": sorted(joined)},
                         ensure_ascii=False, indent=2))
        return 0

    keyword = None
    if "--search" in argv:
        keyword = argv[argv.index("--search") + 1].lower()
        lst = [s for s in lst if keyword in s.lower()]

    print(f"\n=== 可加入的公共网络 {len(lst)} 个"
          + (f"（过滤 '{keyword}'）" if keyword else "") + " ===")
    for s in lst[:80]:
        print(f"  {s}")
    if len(lst) > 80:
        print(f"  … 还有 {len(lst) - 80} 个，用 --search 过滤")
    print(f"\n加入: python rvpnpublic.py join <关键字>")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
