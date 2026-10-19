"""Diagnose remote-thread injection: distinguish 'CreateRemoteThread failed'
from 'LoadLibraryW returned 0'.

Technique: call kernel32!GetModuleHandleW(L"kernel32.dll") in the target.  That
call must succeed in any process, so a zero result proves the *mechanism* is
broken, not the DLL.  We also report the wait status and the thread exit code.
"""
import ctypes
import ctypes.wintypes as wt
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 0x102
WAIT_FAILED = 0xFFFFFFFF

k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_char * 260)]


def find_pid(name):
    want = name.lower()
    if not want.endswith(".exe"):
        want += ".exe"
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    e = PROCESSENTRY32()
    e.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if k32.Process32First(snap, ctypes.byref(e)):
        while True:
            if e.szExeFile.decode("ascii", "ignore").lower() == want:
                k32.CloseHandle(snap)
                return e.th32ProcessID
            if not k32.Process32Next(snap, ctypes.byref(e)):
                break
    k32.CloseHandle(snap)
    return None


def call_remote(pid, func_name, arg_ptr, label, write_payload=None):
    """Run func_name(arg_ptr) on a remote thread and report everything."""
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print(f"  [{label}] OpenProcess 失败 err={ctypes.get_last_error()}")
        return None
    try:
        remote = None
        if write_payload is not None:
            remote = k32.VirtualAllocEx(h, None, len(write_payload),
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not remote:
                print(f"  [{label}] VirtualAllocEx 失败 err={ctypes.get_last_error()}")
                return None
            written = ctypes.c_size_t(0)
            if not k32.WriteProcessMemory(h, remote, write_payload, len(write_payload),
                                          ctypes.byref(written)):
                print(f"  [{label}] WriteProcessMemory 失败 err={ctypes.get_last_error()}")
                return None
        else:
            remote = arg_ptr

        kern = k32.GetModuleHandleW("kernel32.dll")
        fn = k32.GetProcAddress(kern, func_name.encode())
        if not fn:
            print(f"  [{label}] GetProcAddress({func_name}) 失败")
            return None

        ctypes.set_last_error(0)
        th = k32.CreateRemoteThread(h, None, 0, fn, remote, 0, None)
        create_err = ctypes.get_last_error()

        if not th:
            print(f"  [{label}] CreateRemoteThread 失败 err={create_err} "
                  f"({ctypes.FormatError(create_err).strip()})")
            return None

        rc = k32.WaitForSingleObject(th, 10000)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        k32.CloseHandle(th)

        wname = {0: "WAIT_OBJECT_0(已完成)", 0x102: "WAIT_TIMEOUT(超时)",
                 0xFFFFFFFF: "WAIT_FAILED"}.get(rc, hex(rc))
        print(f"  [{label}] CreateRemoteThread OK, wait={wname}, 返回码={code.value} "
              f"(0x{code.value:x})")
        return code.value
    finally:
        k32.CloseHandle(h)


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid("RvRvpnGui")
    if not pid:
        print("找不到 RvRvpnGui")
        return 1

    print(f"目标进程 pid={pid}\n")

    print("① 调用 GetCurrentProcessId() —— 无参数，必须成功：")
    call_remote(pid, "GetCurrentProcessId", None, "GetCurrentProcessId")

    print("\n② 调用 GetModuleHandleW(L\"kernel32.dll\") —— 必须返回非零：")
    payload = "kernel32.dll".encode("utf-16-le") + b"\x00\x00"
    call_remote(pid, "GetModuleHandleW", None, "GetModuleHandleW", write_payload=payload)

    return 0


sys.exit(main())
