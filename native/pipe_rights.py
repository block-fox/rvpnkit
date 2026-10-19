"""Isolate the exact pipe access rights, one mode at a time.

Earlier probes tested modes back-to-back, so an ERROR_PIPE_BUSY caused by the
previous handle could be misread as an access-denied.  This version spaces the
cases out and confirms a free instance before each attempt.
"""
import ctypes
import ctypes.wintypes as wt
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

print(f"目标管道: {PIPE}")


def probe_free_instance():
    """Try to grab one instance with read-only access to see if any is free."""
    h = k32.CreateFileW(PIPE, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    if h in (INV, None):
        return False, ctypes.get_last_error()
    k32.CloseHandle(h)
    return True, 0


cases = [
    ("仅读  GENERIC_READ ", GENERIC_READ),
    ("仅写  GENERIC_WRITE", GENERIC_WRITE),
    ("读写  RW           ", GENERIC_READ | GENERIC_WRITE),
    ("零权  0（只查询）   ", 0),
]

print("\n=== 逐例测试（每例前探测可用实例，例间间隔 1.5s）===")
for label, access in cases:
    time.sleep(1.5)
    free, ferr = probe_free_instance()

    h = k32.CreateFileW(PIPE, access, 0, None, OPEN_EXISTING, 0, None)
    err = ctypes.get_last_error()

    if h in (INV, None):
        msg = ctypes.FormatError(err).strip()
        print(f"  ✗ err={err:<5} {msg:<24} {label}   [测试前可用实例={free}"
              + (f", 探测错误={ferr}" if not free else "") + "]")
    else:
        print(f"  ✓ OK     {'':<24} {label}   [测试前可用实例={free}]")
        k32.CloseHandle(h)

print("\n判读：")
print("  · 仅写 OK      -> 管道允许写入，之前的“错误 5”是时序假象，可做写路径")
print("  · 仅写 err=5   -> ACL 确实拒绝写权限")
print("  · err=231      -> 实例被占用（不是权限问题）")
