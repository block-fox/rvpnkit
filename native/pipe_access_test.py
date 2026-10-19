"""Side-by-side pipe access test: enumerate the access modes that work.

The C# client gets ERROR_ACCESS_DENIED on this pipe while an earlier Python
probe succeeded, so this script tries every plausible combination to find the
set the service actually accepts.
"""
import ctypes
import ctypes.wintypes as wt
import os

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID = ctypes.c_void_p(-1).value

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"

print("=== 枚举匹配的管道 ===")
for entry in sorted(os.listdir("\\\\.\\pipe\\")):
    if "radmin" in entry.lower() or "rvpn" in entry.lower():
        print("   ", entry)

cases = [
    ("GENERIC_READ|WRITE, share=0,        sync", GENERIC_READ | GENERIC_WRITE, 0, 0),
    ("GENERIC_READ|WRITE, share=0,        overlapped", GENERIC_READ | GENERIC_WRITE, 0, FILE_FLAG_OVERLAPPED),
    ("GENERIC_READ|WRITE, share=R|W,      sync", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0),
    ("GENERIC_READ only,  share=0,        sync", GENERIC_READ, 0, 0),
    ("GENERIC_WRITE only, share=0,        sync", GENERIC_WRITE, 0, 0),
    ("0 (query only),     share=0,        sync", 0, 0, 0),
]

print("\n=== 逐个尝试打开 ===")
for label, access, share, flags in cases:
    h = k32.CreateFileW(PIPE, access, share, None, OPEN_EXISTING, flags, None)
    err = ctypes.get_last_error()
    if h == INVALID or h is None:
        print(f"  ✗ {err:>5}  {ctypes.FormatError(err).strip():<28} {label}")
    else:
        print(f"  ✓ OK     {'':<28} {label}")
        k32.CloseHandle(h)

print("\n=== 当前进程信息 ===")
import subprocess
print("  python 位数:", 64 if ctypes.sizeof(ctypes.c_void_p) == 8 else 32)
try:
    import win32api  # noqa: F401
    has_pywin32 = True
except ImportError:
    has_pywin32 = False
print("  pywin32:", has_pywin32)

# 检查进程完整性级别，判断是否被降权
try:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    hproc = k32.GetCurrentProcess()
    htok = ctypes.c_void_p()
    advapi.OpenProcessToken(hproc, 0x0008, ctypes.byref(htok))
    # TokenIntegrityLevel = 25
    buf = ctypes.create_string_buffer(256)
    ret = wt.DWORD(0)
    advapi.GetTokenInformation(htok, 25, buf, 256, ctypes.byref(ret))
    # TOKEN_MANDATORY_LABEL: SID 指针 + attributes，取 SID 最后一位作为 RID
    sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
    advapi.GetSidSubAuthorityCount.restype = ctypes.c_void_p
    cnt_ptr = advapi.GetSidSubAuthorityCount(ctypes.c_void_p(sid_ptr))
    n = ctypes.cast(cnt_ptr, ctypes.POINTER(ctypes.c_ubyte))[0]
    advapi.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
    rid = advapi.GetSidSubAuthority(ctypes.c_void_p(sid_ptr), n - 1).contents.value
    level = {0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
             0x2100: "Medium-Plus", 0x3000: "High", 0x4000: "System"}.get(rid, hex(rid))
    print("  完整性级别:", level)
except Exception as e:
    print("  完整性级别: 查询失败", e)
