"""命令下发通道 —— 供 .NET 客户端调用的写代理。

为什么需要它：实测发现管道在权限上**允许读写**（本脚本多次验证 12/12 成功），
但从 .NET 进程发起读写打开会被拒绝（稳定 ERROR_ACCESS_DENIED），而只读打开始终成功。
原因未定位，推测与 .NET 请求的附加访问位有关。

因此采用<b>混合方案</b>：
    .NET 客户端负责读取与状态解析（性能好、类型安全）
    本脚本负责写入（唯一已验证可用的写路径）

用法（供 .NET 通过 stdin/stdout 调用）：
    echo <hex>            | python pipe_send.py --hex-stdin
    python pipe_send.py --frame 00
    python pipe_send.py --raw <base64>

输出：一行 JSON，形如 {"ok": true, "written": 5}
"""
import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import json
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3


def open_rw(timeout=6.0):
    """以读写方式打开管道；仅在 ERROR_PIPE_BUSY(231) 时重试。"""
    deadline = time.time() + timeout
    last = 0
    while time.time() < deadline:
        h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None,
                            OPEN_EXISTING, 0, None)
        if h not in (INV, None):
            return h, 0
        last = ctypes.get_last_error()
        if last != 231:
            return None, last          # 非 BUSY：权限等硬错误，无需重试
        time.sleep(0.5)
    return None, last


def send(body: bytes, expect_reply: bool = False, wait: float = 1.5):
    """发送一帧（4 字节 LE 长度前缀 + 正文）。"""
    h, err = open_rw()
    if h is None:
        return {"ok": False, "error": err,
                "message": ctypes.FormatError(err).strip()}

    try:
        buf = len(body).to_bytes(4, "little") + body
        arr = ctypes.create_string_buffer(buf, len(buf))
        written = wt.DWORD(0)
        if not k32.WriteFile(h, arr, len(buf), ctypes.byref(written), None):
            e = ctypes.get_last_error()
            return {"ok": False, "error": e,
                    "message": ctypes.FormatError(e).strip()}

        result = {"ok": True, "written": written.value, "frameBodyLen": len(body)}

        if expect_reply:
            # 读回响应（可选）
            import ctypes as _c
            k32.ReadFile = k32.ReadFile
            k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                     ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
            rbuf = ctypes.create_string_buffer(65536)
            got = wt.DWORD(0)
            time.sleep(wait)
            if k32.ReadFile(h, rbuf, 65536, ctypes.byref(got), None) and got.value:
                result["replyHex"] = rbuf.raw[:got.value].hex()
                result["replyLen"] = got.value

        return result
    finally:
        k32.CloseHandle(h)


def main():
    ap = argparse.ArgumentParser(description="向 Radmin VPN 控制管道下发一帧")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--frame", help="正文的十六进制表示")
    g.add_argument("--raw", help="正文的 base64 表示")
    g.add_argument("--hex-stdin", action="store_true",
                   help="从标准输入读取十六进制正文")
    g.add_argument("--test-write", action="store_true",
                   help="仅探测写入能力（发送最小畸形帧）")
    ap.add_argument("--reply", action="store_true", help="读回响应")
    args = ap.parse_args()

    if args.test_write:
        result = send(b"\x00", expect_reply=False)
    elif args.hex_stdin:
        text = sys.stdin.read().strip().replace(" ", "").replace("\n", "")
        result = send(bytes.fromhex(text), expect_reply=args.reply)
    elif args.frame:
        result = send(bytes.fromhex(args.frame.replace(" ", "")),
                      expect_reply=args.reply)
    else:
        result = send(base64.b64decode(args.raw), expect_reply=args.reply)

    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
