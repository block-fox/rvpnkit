"""Determine why the .NET client gets ACCESS_DENIED on the pipe while the
Python process (started the same way) succeeds.

Hypothesis: the .NET executable is launched with a restricted token by the
harness, so the pipe's DACL denies it.  We test by:
  1. opening the pipe from this Python process (known to work)
  2. launching the .NET client AS A CHILD of this Python process and seeing
     whether the error changes
  3. probing a plain file read/write to see whether the restriction is
     pipe-specific or general
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
INVALID = ctypes.c_void_p(-1).value

PIPE = r"\\.\pipe\RadminVpnGuiChannel"
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

print("=== ① Python 直接开管道 ===")
h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
if h == INVALID or h is None:
    print(f"   失败 err={ctypes.get_last_error()}")
else:
    print("   成功")
    k32.CloseHandle(h)

print("\n=== ② 以 Python 为父进程启动 .NET 客户端 ===")
exe = r"D:\工作区\workspace1\RvpnKit\src\RvpnKit.Client\bin\Debug\net10.0\rvpnkit.exe"
if os.path.isfile(exe):
    r = subprocess.run([exe], capture_output=True, text=True, errors="ignore", timeout=30,
                       env={**os.environ, "DOTNET_NOLOGO": "1"})
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines()[:8]:
        print("   |", line)
    if "访问被拒绝" in out or "error 5" in out.lower():
        print("   => 仍然 ACCESS_DENIED（限制跟随 .NET 进程本身）")
    elif "已连接" in out:
        print("   => 成功！说明原来的失败与启动方式有关")
else:
    print("   找不到 exe:", exe)

print("\n=== ③ 普通文件读写（判断限制是否只针对管道）===")
tmp = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpn_filetest.txt")
try:
    with open(tmp, "w") as f:
        f.write("ok")
    with open(tmp) as f:
        print("   文件读写正常:", f.read())
    os.remove(tmp)
except OSError as e:
    print("   文件读写失败:", e)

print("\n=== ④ 进程权限差异 ===")
print("   python 完整性/权限: 见下")
try:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    hp = k32.GetCurrentProcess()
    tok = ctypes.c_void_p()
    adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    if adv.OpenProcessToken(hp, 0x0008, ctypes.byref(tok)):
        buf = ctypes.create_string_buffer(512)
        ret = wt.DWORD(0)
        adv.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                            ctypes.c_void_p, wt.DWORD,
                                            ctypes.POINTER(wt.DWORD)]
        if adv.GetTokenInformation(tok, 25, buf, 512, ctypes.byref(ret)):  # TokenIntegrityLevel
            sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
            adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
            n = adv.GetSidSubAuthorityCount(ctypes.c_void_p(sid_ptr))[0]
            adv.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
            adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, ctypes.c_ubyte]
            rid = adv.GetSidSubAuthority(ctypes.c_void_p(sid_ptr), n - 1)[0]
            lvl = {0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
                   0x2100: "Medium-Plus", 0x3000: "High", 0x4000: "System"}.get(rid, hex(rid))
            print("   Python 完整性级别:", lvl)
        else:
            print("   GetTokenInformation 失败 err=", ctypes.get_last_error())
    else:
        print("   OpenProcessToken 失败 err=", ctypes.get_last_error())
except Exception as e:  # noqa: BLE001
    print("   查询失败:", e)
