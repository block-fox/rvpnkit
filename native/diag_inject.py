"""Diagnose remote-thread injection: distinguish 'CreateRemoteThread failed'
from 'LoadLibraryW returned 0'.

Technique: call kernel32!GetModuleHandleW(L"kernel32.dll") inside the target.
That call must succeed in any process, so a zero result proves the *mechanism*
is broken rather than the DLL being injected.  We also report the wait status
and the thread exit code, which is the decisive evidence.

Note: ctypes defaults an undeclared restype to c_int, which truncates 64-bit
handles.  Every handle-returning API below declares restype/argtypes as
c_void_p -- getting this wrong is what broke the first run of this script.
"""
import ctypes
import ctypes.wintypes as wt
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE = ctypes.c_void_p(-1).value

# ── 所有返回句柄/指针的 API 必须声明为 c_void_p，否则 64 位下会截断
k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32First.restype = wt.BOOL
k32.Process32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.Process32Next.restype = wt.BOOL
k32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, wt.LPCSTR]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.c_void_p]
k32.WaitForSingleObject.restype = wt.DWORD
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.GetExitCodeThread.restype = wt.BOOL
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.CloseHandle.restype = wt.BOOL
k32.CloseHandle.argtypes = [ctypes.c_void_p]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_char * 260)]


def find_pid(name):
    want = name.lower()
    if not want.endswith(".exe"):
        want += ".exe"
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE:
        return None
    try:
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not k32.Process32First(snap, ctypes.byref(e)):
            return None
        while True:
            if e.szExeFile.decode("ascii", "ignore").lower() == want:
                return e.th32ProcessID
            if not k32.Process32Next(snap, ctypes.byref(e)):
                return None
    finally:
        k32.CloseHandle(snap)


def call_remote(pid, func_name, label, write_payload=None):
    """Run kernel32!func_name(arg) on a remote thread; report every outcome."""
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        err = ctypes.get_last_error()
        print(f"  [{label}] OpenProcess 失败 err={err} "
              f"({ctypes.FormatError(err).strip()})")
        return None

    remote = None
    try:
        if write_payload is not None:
            remote = k32.VirtualAllocEx(h, None, len(write_payload),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not remote:
                err = ctypes.get_last_error()
                print(f"  [{label}] VirtualAllocEx 失败 err={err}")
                return None
            written = ctypes.c_size_t(0)
            if not k32.WriteProcessMemory(h, remote, write_payload,
                                          len(write_payload), ctypes.byref(written)):
                err = ctypes.get_last_error()
                print(f"  [{label}] WriteProcessMemory 失败 err={err}")
                return None

        kern = k32.GetModuleHandleW("kernel32.dll")
        if not kern:
            print(f"  [{label}] GetModuleHandleW 失败")
            return None
        fn = k32.GetProcAddress(kern, func_name.encode())
        if not fn:
            print(f"  [{label}] GetProcAddress({func_name}) 失败")
            return None

        ctypes.set_last_error(0)
        th = k32.CreateRemoteThread(h, None, 0, fn, remote, 0, None)
        create_err = ctypes.get_last_error()
        if not th:
            print(f"  [{label}] ✗ CreateRemoteThread 失败 err={create_err} "
                  f"({ctypes.FormatError(create_err).strip()})")
            return None

        rc = k32.WaitForSingleObject(th, 10000)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        k32.CloseHandle(th)

        wname = {0: "WAIT_OBJECT_0(已完成)", 0x102: "WAIT_TIMEOUT(超时)",
                 0xFFFFFFFF: "WAIT_FAILED"}.get(rc, hex(rc))
        print(f"  [{label}] CreateRemoteThread OK, wait={wname}, "
              f"返回码={code.value} (0x{code.value:x})")
        return code.value
    finally:
        k32.CloseHandle(h)


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid("RvRvpnGui")
    if not pid:
        print("找不到 RvRvpnGui 进程")
        return 1

    print(f"目标进程: pid={pid}\n")

    print("① kernel32!GetCurrentProcessId() —— 无参数，任何进程都必须成功：")
    call_remote(pid, "GetCurrentProcessId", "GetCurrentProcessId")

    print("\n② kernel32!GetModuleHandleW(L\"kernel32.dll\") —— 必须返回非零：")
    payload = "kernel32.dll".encode("utf-16-le") + b"\x00\x00"
    call_remote(pid, "GetModuleHandleW", "GetModuleHandleW",
                write_payload=payload)

    print("\n判读方法：")
    print("  · 两个都失败      -> CreateRemoteThread 机制被阻断（注入不可行）")
    print("  · ① OK ② 非零    -> 机制正常，问题出在 LoadLibrary 或 DLL 本身")
    print("  · ① OK ② 为 0    -> 进程环境异常")
    return 0


sys.exit(main())
