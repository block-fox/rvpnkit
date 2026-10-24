#!/usr/bin/env python3
"""rvpncmd —— 向 Radmin VPN 控制服务下发命令（逆向自官方 GUI 的真实报文）。

字符串编码：UTF-16 **大端**，后面固定跟 2 字节 `00 01`
-----------------------------------------------------
这条最初判错了。别名「快乐狐狸1」的记录是
    5f eb 4e 50 72 d0 72 f8 00 31 00 01
而 5f eb 正是 U+5FEB「快」的大端编码。之前按 UTF-16LE 处理之所以
还能成功，是因为网络名恰好几乎全是 ASCII：ASCII 在 LE 下是 <char>00，
前面补一个 00 就和 BE 的 00<char> 逐字节重合了。名字含非 ASCII 或长度为
奇数时两种写法就会分叉，所以这里统一按 BE。

命令表（命令码 = 第二条记录里的 u32）
-----------------------------------
  0x02 (2)   创建 / 离开网络（容器 0x2b，含 28 字节随机块，语义待定）
  0x03 (3)   加入网络（容器 0x1b，只有网络名）
  0x08 (8)   离开网络（按 GUID，后面跟一个 u32=0 字段 0x16）
  0x0f (15)  删除网络（按 GUID）
  0x12 (18)  改别名
  0x13 (19)  枚举公共网络（字段 0x06 是过滤前缀，空串=全部）

记录格式
--------
    [size:u32 BE][类型码:u8][0x00][0x03][字段:u8][payload]

用法
----
    python rvpncmd.py join "网络名"
    python rvpncmd.py leave <guid-hex>        # 16 字节 GUID
    python rvpncmd.py delete <guid-hex>
    python rvpncmd.py alias "新别名"
    python rvpncmd.py enum                    # 枚举公共网络
    python rvpncmd.py send <hex>              # 发送任意帧正文
    python rvpncmd.py build "网络名"           # 只打印不发送
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys
import time

PIPE = r"\\.\pipe\RadminVpnGuiChannel"
SVC = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

CMD_CREATE_OR_LEAVE = 0x02
CMD_JOIN = 0x03
CMD_LEAVE = 0x08
CMD_DELETE = 0x0F
CMD_ALIAS = 0x12
CMD_ENUM = 0x13

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

INVALID = ctypes.c_void_p(-1).value
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3


# ---------------------------------------------------------------- 基础构件

def rec(size: int, type_code: int, field: int) -> bytes:
    return struct.pack(">I", size) + bytes([type_code, 0x00, 0x03, field])


def str_be(text: str) -> bytes:
    """字符串载荷：UTF-16BE + 00 01。"""
    return text.encode("utf-16-be") + b"\x00\x01"


def rec_str(text: str, field: int) -> bytes:
    payload = str_be(text)
    return rec(len(payload), 0x03, field) + payload


def rec_u32(value: int, field: int, type_code: int = 0x0B) -> bytes:
    return rec(4, type_code, field) + struct.pack(">I", value)


def rec_guid(guid: bytes, field: int = 0x09) -> bytes:
    assert len(guid) == 16, f"GUID 必须 16 字节，实际 {len(guid)}"
    return rec(16, 0x0D, field) + guid


def head(req_id: int, command: int) -> bytes:
    return (rec(4, 0x01, 0x4A) + struct.pack(">I", req_id)
            + rec(4, 0x01, 0x00) + struct.pack(">I", command))


# ---------------------------------------------------------------- 各命令

def build_join(name: str, req_id: int) -> bytes:
    """加入网络：容器 0x1b = u32(1) + 网络名。"""
    inner = rec_u32(1, 0x3F) + rec_str(name, 0x06)
    return (head(req_id, CMD_JOIN) + struct.pack(">I", len(inner))
            + struct.pack(">I", 0x0000131B) + inner)


def build_alias(name: str, req_id: int) -> bytes:
    """改别名：命令码 0x12，单条字符串记录（字段 0x04）。"""
    return head(req_id, CMD_ALIAS) + rec_str(name, 0x04)


def build_delete(guid: bytes, req_id: int) -> bytes:
    """删除网络：命令码 0x0f，单条 16 字节 GUID 记录。"""
    return head(req_id, CMD_DELETE) + rec_guid(guid)


def build_leave(guid: bytes, req_id: int) -> bytes:
    """离开网络：命令码 0x08，GUID + u32=0（字段 0x16）。"""
    return head(req_id, CMD_LEAVE) + rec_guid(guid) + rec_u32(0, 0x16)


def build_enum(prefix: str, req_id: int) -> bytes:
    """枚举公共网络：命令码 0x13，字段 0x06 是过滤前缀（空串=全部）。"""
    return head(req_id, CMD_ENUM) + rec_str(prefix, 0x06)


# ---------------------------------------------------------------- 管道

def open_pipe():
    for _ in range(6):
        h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None,
                            OPEN_EXISTING, 0, None)
        if h not in (INVALID, None):
            return h, 0
        err = ctypes.get_last_error()
        if err != 231:
            return None, err
        time.sleep(0.4)
    return None, 231


def write_frame(h, body: bytes) -> int:
    buf = struct.pack("<I", len(body)) + body
    arr = ctypes.create_string_buffer(buf, len(buf))
    n = wt.DWORD(0)
    if not k32.WriteFile(h, arr, len(buf), ctypes.byref(n), None):
        raise OSError(ctypes.get_last_error(), "WriteFile 失败")
    return n.value


def svc_reqs():
    if not os.path.exists(SVC):
        return {}
    raw = open(SVC, "rb").read()
    out = {}
    for line in raw.decode("utf-16-le", "ignore").splitlines():
        m = re.search(r"\[req:(\d+)\]\s*(.+)$", line)
        if m:
            rid, desc = int(m.group(1)), m.group(2).strip()
            if out.get(rid) in (None, "Succeeded") and desc != "Succeeded":
                out[rid] = desc
            out.setdefault(rid, desc)
    return out


def dispatch(body: bytes, req_id: int, label: str, wait: float = 6.0) -> int:
    print(f"命令     : {label}")
    print(f"请求编号 : {req_id} (0x{req_id:x})")
    print(f"帧长度   : {len(body)} 字节（正文）")

    h, err = open_pipe()
    if not h:
        print(f"✗ 打开管道失败 err={err}")
        return 1
    try:
        print(f"✓ 已写入 {write_frame(h, body)} 字节")
    except OSError as e:
        print(f"✗ 写入失败: {e}")
        return 2
    finally:
        k32.CloseHandle(h)

    print("等待服务处理…")
    deadline = time.time() + wait
    shown = set()          # 已经打印过的描述，避免每轮重复刷同一行
    accepted = False
    succeeded = False

    while time.time() < deadline:
        time.sleep(0.3)
        # 一次性取出该 reqId 的所有记录，而不是只看最新一条
        if not os.path.exists(SVC):
            continue
        raw = open(SVC, "rb").read()
        for line in raw.decode("utf-16-le", "ignore").splitlines():
            if f"[req:{req_id}]" not in line:
                continue
            desc = line.split(f"[req:{req_id}]", 1)[1].strip()
            if desc in shown:
                continue
            shown.add(desc)
            print(f"  服务端: {desc[:110]}")
            if desc == "Succeeded":
                succeeded = True
            else:
                accepted = True
        if succeeded:
            break

    if succeeded:
        print("\n★ 成功（服务返回 Succeeded）")
        return 0
    if accepted:
        print("\n★ 已受理（该命令本就不回 Succeeded，服务已记录请求）")
        return 0
    print("⚠ 服务日志里没看到该请求，命令可能被丢弃")
    return 4


def new_req_id() -> int:
    return int.from_bytes(os.urandom(2), "big")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    a = argv[1]

    if a == "join" and len(argv) > 2:
        rid = new_req_id()
        return dispatch(build_join(argv[2], rid), rid, f"加入网络 '{argv[2]}'")

    if a in ("leave", "delete") and len(argv) > 2:
        try:
            guid = bytes.fromhex(re.sub(r"[\s\-]", "", argv[2]))
        except ValueError:
            print("GUID 需要是十六进制")
            return 2
        rid = new_req_id()
        body = build_leave(guid, rid) if a == "leave" else build_delete(guid, rid)
        return dispatch(body, rid,
                        f"{'离开' if a == 'leave' else '删除'}网络 GUID={guid.hex()}")

    if a == "alias" and len(argv) > 2:
        rid = new_req_id()
        return dispatch(build_alias(argv[2], rid), rid, f"改别名 -> '{argv[2]}'")

    if a == "enum":
        rid = new_req_id()
        prefix = argv[2] if len(argv) > 2 else ""
        return dispatch(build_enum(prefix, rid), rid,
                        f"枚举公共网络（前缀 '{prefix}'）", wait=4)

    if a == "send" and len(argv) > 2:
        body = bytes.fromhex(re.sub(r"[\s,]", "", argv[2]))
        rid = int.from_bytes(body[8:12], "big") if len(body) >= 12 else 0
        return dispatch(body, rid, "自定义帧")

    if a == "build" and len(argv) > 2:
        body = build_join(argv[2], 0x17)
        print(f"长度 {len(body)} 字节：")
        for i in range(0, len(body), 16):
            print(f"  {i:04x}  " + " ".join(f"{b:02x}" for b in body[i:i + 16]))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
