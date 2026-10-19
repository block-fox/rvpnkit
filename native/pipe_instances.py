"""Report how many pipe instances are free, and identify what holds them.

The service appears to expose a single pipe instance, so any leaked client
handle blocks everyone else (including the official GUI).  This script counts
available instances and lists processes that may be holding one.
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.WaitNamedPipeW.restype = wt.BOOL
k32.WaitNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD]

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID = ctypes.c_void_p(-1).value
PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"

print("=== 探测可用实例数 ===")
handles = []
for i in range(12):
    h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None,
                        OPEN_EXISTING, 0, None)
    if h == INVALID or h is None:
        err = ctypes.get_last_error()
        print(f"  第 {i+1} 次: 失败 err={err} ({ctypes.FormatError(err).strip()})")
        break
    handles.append(h)
    print(f"  第 {i+1} 次: 成功")

print(f"\n可用实例数 = {len(handles)}")
for h in handles:
    k32.CloseHandle(h)

print("\n=== 占用管道的进程（按句柄搜索）===")
# 列出可能持有句柄的进程：官方 GUI、此前运行的 python
for name in ("RvRvpnGui.exe", "python.exe", "python3.exe", "rvpnkit.exe"):
    r = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, errors="ignore")
    for line in r.stdout.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == name.lower():
            print(f"  {parts[0]}  pid={parts[1]}  内存={parts[-1]}")

print("\n提示：若可用实例数为 1 但 C# 客户端拿到 ERROR_ACCESS_DENIED/ERROR_PIPE_BUSY，")
print("      通常是有其他进程已占用该实例。")
