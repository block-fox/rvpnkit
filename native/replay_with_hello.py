"""Send the GUI hello frame first, then the captured toggle command.

Hypothesis: the service tracks per-connection context.  The GUI identifies
itself with a fixed 48-byte frame right after connecting (captured earlier),
and only then are its commands honoured.  A stranger connection sending a
command directly gets silently dropped -- which is exactly what we observed.

Test: on ONE connection, send hello, wait briefly, then send the toggle, and
watch the service log for "Enabled/Disabled network" style lines.
"""
import ctypes
import ctypes.wintypes as wt
import os
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
R, W, OPEN_EXISTING = 0x80000000, 0x40000000, 3
SVC = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

HELLO = bytes.fromhex(
    "000000040100034a" "ffffffff"
    "0000000401000300" "0000001c"
    "000000040100025a" "00000804"
    "000000040100025a" "00000804")

TOGGLE_A = bytes.fromhex(
    "00000004 0100 034a ffffffff"
    "00000004 0100 0300 00000014"
    "0000001c 00001344"
    "00000008 0200 01e1 00000000 026bd639"
    "00000004 0100 0376 fffffffe".replace(" ", ""))

TOGGLE_B = bytes.fromhex(
    "00000004 0100 034a ffffffff"
    "00000004 0100 0300 00000014"
    "0000001c 00001344"
    "00000008 0200 01e1 00000000 026bd639"
    "00000004 0100 0376 00000000".replace(" ", ""))


def open_pipe():
    for _ in range(10):
        h = k32.CreateFileW(PIPE, R | W, 0, None, OPEN_EXISTING, 0, None)
        if h not in (INV, None):
            return h
        if ctypes.get_last_error() != 231:
            return None
        time.sleep(0.5)
    return None


def write_frame(h, body):
    buf = len(body).to_bytes(4, "little") + body
    arr = ctypes.create_string_buffer(buf, len(buf))
    n = wt.DWORD(0)
    ok = k32.WriteFile(h, arr, len(buf), ctypes.byref(n), None)
    return bool(ok), n.value


def svc_lines():
    if not os.path.exists(SVC):
        return []
    raw = open(SVC, "rb").read()
    return [l.strip() for l in raw.decode("utf-16-le", "ignore").splitlines() if l.strip()]


def interesting(lines):
    keys = ("Enable", "Disable", "network", "Network", "role", "kick", "Kick",
            "remove", "Remove", "approve", "Approve", "alias", "Alias", "[req:")
    return [l for l in lines if any(k in l for k in keys)]


def main():
    print("=== 握手 + 命令（同一连接）===\n")

    before = svc_lines()
    before_marks = interesting(before)
    print(f"日志行数 {len(before)}，其中关注行 {len(before_marks)}")
    print()

    h = open_pipe()
    if not h:
        raise SystemExit("无法连接管道")
    print("✓ 已连接管道")

    try:
        ok, n = write_frame(h, HELLO)
        print(f"  发送握手帧 {len(HELLO)} 字节 -> ok={ok} written={n}")
        time.sleep(1.2)

        for label, frame in (("帧A fffffffe", TOGGLE_A), ("帧B 00000000", TOGGLE_B)):
            ok, n = write_frame(h, frame)
            print(f"  发送 {label} ({len(frame)} 字节) -> ok={ok} written={n}")
            time.sleep(2.5)

            after = svc_lines()
            new = interesting(after)[len(before_marks):] if len(after) > len(before) else []
            if new:
                print("    ★ 服务日志出现新记录：")
                for l in new[-6:]:
                    print("       ", l[:130])
            else:
                print("    （关注行无新增）")
    finally:
        k32.CloseHandle(h)

    print("\n=== 最新日志尾部 ===")
    for l in svc_lines()[-8:]:
        print("   ", l[:130])

    return 0


sys.exit(main())
