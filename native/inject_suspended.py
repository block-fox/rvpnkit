"""Launch RvRvpnGui.exe suspended, inject the hook DLL, then resume.

Why suspended start is required
-------------------------------
The hook can only see requests that happen *after* it is installed.  The GUI
connects to the control pipe during startup and sends its registration /
snapshot requests immediately, then goes quiet (verified: the service log has
zero "[req:" lines while the GUI merely sits idle).  Injecting into an already
running GUI therefore captures nothing.

By creating the process with CREATE_SUSPENDED, the DLL is mapped before the
first instruction runs, so every startup request is captured.

Note: the process is 32-bit, so LoadLibraryW must be the 32-bit address, which
we obtain from inject32.exe --addr-only.
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

CREATE_SUSPENDED = 0x00000004
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

k32.CreateProcessW.restype = wt.BOOL
k32.CreateProcessW.argtypes = [wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                               wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
                               ctypes.c_void_p, ctypes.c_void_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.c_void_p]
k32.ResumeThread.argtypes = [ctypes.c_void_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.TerminateProcess.argtypes = [ctypes.c_void_p, wt.UINT]

HERE = os.path.dirname(os.path.abspath(__file__))
GUI = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
LOG = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpipe_hook.log")


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR),
                ("lpDesktop", wt.LPWSTR), ("lpTitle", wt.LPWSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", ctypes.c_void_p), ("hStdOutput", ctypes.c_void_p),
                ("hStdError", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


def addr32():
    r = subprocess.run([os.path.join(HERE, "inject32.exe"), "--addr-only"],
                       capture_output=True, text=True, timeout=20)
    lib = None
    for line in r.stdout.splitlines():
        m = re.match(r"LOADLIBRARYW=0x([0-9a-fA-F]+)", line)
        if m:
            lib = int(m.group(1), 16)
    return lib


def main():
    dll = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                          os.path.join(HERE, "rvpipe_hook32.dll"))
    if not os.path.isfile(dll):
        raise SystemExit(f"DLL 不存在: {dll}")

    # 1. 关掉已在运行的 GUI（单实例约束）
    subprocess.run(["taskkill", "/F", "/IM", "RvRvpnGui.exe"],
                   capture_output=True)
    time.sleep(2)

    loadlib = addr32()
    if not loadlib:
        raise SystemExit("无法获取 32 位 LoadLibraryW 地址")
    print(f"32 位 LoadLibraryW = 0x{loadlib:08x}")

    if os.path.exists(LOG):
        os.remove(LOG)

    # 2. 挂起启动
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(GUI, None, None, None, False,
                            CREATE_SUSPENDED, None, None,
                            ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        raise SystemExit(f"CreateProcess 失败 err={ctypes.get_last_error()}")

    pid = pi.dwProcessId
    print(f"✓ 已挂起启动 pid={pid}")

    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        k32.TerminateProcess(pi.hProcess, 1)
        raise SystemExit(f"OpenProcess 失败 err={ctypes.get_last_error()}")

    try:
        # 3. 写入 DLL 路径
        buf = dll.encode("utf-16-le") + b"\x00\x00"
        remote = k32.VirtualAllocEx(h, None, len(buf), MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE)
        if not remote:
            raise SystemExit(f"VirtualAllocEx 失败 err={ctypes.get_last_error()}")
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, buf, len(buf), ctypes.byref(written)):
            raise SystemExit(f"WriteProcessMemory 失败 err={ctypes.get_last_error()}")

        # 4. 注入（此时进程还没跑任何指令，创建远程线程是安全的）
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(loadlib),
                                    ctypes.c_void_p(remote), 0, None)
        if not th:
            raise SystemExit(f"CreateRemoteThread 失败 err={ctypes.get_last_error()}")

        k32.WaitForSingleObject(th, 8000)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        k32.CloseHandle(th)

        if code.value == 0:
            k32.TerminateProcess(pi.hProcess, 1)
            raise SystemExit("LoadLibraryW 返回 0 —— DLL 未能载入")

        print(f"✓ DLL 已载入（模块基址 0x{code.value:x}）")

        # 5. 恢复主线程，让 GUI 开始初始化
        k32.ResumeThread(pi.hThread)
        print("✓ 已恢复运行，等待 GUI 初始化…\n")

        # 6. 等日志产生内容
        deadline = time.time() + 30
        last = -1
        while time.time() < deadline:
            time.sleep(1)
            if os.path.exists(LOG):
                size = os.path.getsize(LOG)
                if size != last:
                    print(f"  日志 {size} 字节")
                    last = size
                if b"=== OUT" in open(LOG, "rb").read():
                    print("\n★ 已抓到 OUT 帧")
                    break
            # GUI 是否还活着
            if not any(p.name.lower() == "rvrvpngui.exe"
                       for p in []):  # placeholder
                pass

        print("\n=== 日志内容 ===")
        if os.path.exists(LOG):
            print(open(LOG, encoding="utf-8", errors="ignore").read())
        return 0
    finally:
        k32.CloseHandle(h)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)


sys.exit(main())
