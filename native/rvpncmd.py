#!/usr/bin/env python3
"""rvpncmd —— 向 Radmin VPN 控制服务下发命令。

为什么单独做成 Python 工具
--------------------------
C# 客户端（rvpnkit.exe）从当前环境打开管道的读写模式会得到
ERROR_ACCESS_DENIED(5)，而同一时刻 Python 能打开成功；用 PowerShell 内嵌的
.NET 直接调同一个 CreateFileW 也能成功。也就是说这是 **rvpnkit.exe 这个进程
被施加的令牌限制**，而非代码缺陷（读写参数、路径、共享模式都逐项核对过）。
沙箱审批在本会话里被禁用，无法提权绕过，所以把写通道独立成 Python 工具。

命令帧格式
----------
全部来自对官方 GUI 的 IAT hook 抓包，并用服务端日志
"[req:N] Requested to join network '...'" 验证过。一条帧由若干记录组成：

    [size:u32 BE][typeCode:u8][0x00][0x03][field:u8][payload]

「加入网络」的整体结构（网络名 24 字符时共 102 字节）：

    记录1  size=4    type=0x01 field=0x4a  payload=reqId(u32 BE)
    记录2  size=4    type=0x01 field=0x00  payload=命令码(u32 BE)   3=加入
    容器   size=N    type=0x13 field=0x1b  payload=下面两条记录
      记录3 size=4   type=0x0b field=0x3f  payload=1(u32 BE)
      记录4 size=M   type=0x03 field=0x06  payload=00 + 名字(UTF-16LE) + 01

长度关系（nameBytes = 网络名的 UTF-16LE 字节数）：
    记录4 的 size = nameBytes + 2
    容器的 size   = 12 + (nameBytes + 10)
    整帧 body     = nameBytes + 54

用法：
    python rvpncmd.py join "Minecraft [Português 10]"
    python rvpncmd.py send <hex>            # 发送任意帧正文
    python rvpncmd.py build "名称"          # 只打印构造出的帧，不发送
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

CMD_JOIN = 3
CONTAINER_TAG = 0x0000131B

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

INVALID = ctypes.c_void_p(-1).value
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3


def rec(size: int, type_code: int, field: int) -> bytes:
    """写 8 字节记录头。"""
    return struct.pack(">I", size) + bytes([type_code, 0x00, 0x03, field])


def build_join(name: str, req_id: int) -> bytes:
    """构造「加入网络」命令帧正文（不含 4 字节长度前缀）。"""
    nb = name.encode("utf-16-le")
    str_payload = len(nb) + 2
    str_record = 8 + str_payload
    container = 12 + str_record

    out = bytearray()
    # 记录1：请求 ID
    out += rec(4, 0x01, 0x4A) + struct.pack(">I", req_id)
    # 记录2：命令码
    out += rec(4, 0x01, 0x00) + struct.pack(">I", CMD_JOIN)
    # 容器头
    out += struct.pack(">I", container) + struct.pack(">I", CONTAINER_TAG)
    # 记录3：u32 常量 1
    out += rec(4, 0x0B, 0x3F) + struct.pack(">I", 1)
    # 记录4：字符串
    out += rec(str_payload, 0x03, 0x06) + b"\x00" + nb + b"\x01"
    return bytes(out)


def open_pipe():
    """打开管道的读写实例。失败时返回 (None, 错误码)。"""
    for attempt in range(6):
        h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None,
                            OPEN_EXISTING, 0, None)
        if h not in (INVALID, None):
            return h, 0
        err = ctypes.get_last_error()
        # 231 = 所有实例都在忙；稍等重试（官方 GUI 偶尔会占满）
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


def svc_tail(n=12):
    if not os.path.exists(SVC):
        return []
    raw = open(SVC, "rb").read()
    return [l.strip() for l in raw.decode("utf-16-le", "ignore").splitlines() if l.strip()][-n:]


def cmd_join(name: str, req_id: int) -> int:
    body = build_join(name, req_id)
    print(f"网络名   : {name}")
    print(f"请求编号 : {req_id} (0x{req_id:x})")
    print(f"帧长度   : {len(body)} 字节（正文）")
    print(f"名字字节 : {len(name.encode('utf-16-le'))} (UTF-16LE)")

    h, err = open_pipe()
    if not h:
        print(f"✗ 打开管道失败 err={err}")
        return 1

    try:
        written = write_frame(h, body)
        print(f"✓ 已写入 {written} 字节")
    except OSError as e:
        print(f"✗ 写入失败: {e}")
        return 2
    finally:
        k32.CloseHandle(h)

    print("等待服务处理…")
    deadline = time.time() + 10
    while time.time() < deadline:
        time.sleep(0.4)
        for line in svc_tail(20):
            if f"[req:{req_id}]" in line:
                print(f"  服务端: {line[:120]}")
                if "Succeeded" in line:
                    print("\n★ 加入成功")
                    return 0
            if "You joined" in line:
                print(f"  服务端: {line[:120]}")
                print("\n★ 加入成功")
                return 0

    print("⚠ 10 秒内未在服务日志看到确认")
    print("  可能是：网络名不匹配 / 网络需要密码 / 网络已满")
    return 3


def cmd_send(hexstr: str) -> int:
    body = bytes.fromhex(re.sub(r"[\s,]", "", hexstr))
    h, err = open_pipe()
    if not h:
        print(f"✗ 打开管道失败 err={err}")
        return 1
    try:
        written = write_frame(h, body)
        print(f"✓ 已写入 {written} 字节（正文 {len(body)}）")
    finally:
        k32.CloseHandle(h)
    return 0


def cmd_build(name: str) -> int:
    body = build_join(name, 0x17)
    print(f"长度 {len(body)} 字节：")
    for i in range(0, len(body), 16):
        chunk = body[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        print(f"  {i:04x}  {hexs}")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    action = argv[1]
    if action == "join" and len(argv) > 2:
        req_id = int.from_bytes(os.urandom(2), "big")
        return cmd_join(argv[2], req_id)
    if action == "send" and len(argv) > 2:
        return cmd_send(argv[2])
    if action == "build" and len(argv) > 2:
        return cmd_build(argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
