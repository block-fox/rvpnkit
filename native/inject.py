"""Inject a 32-bit DLL into a running process via CreateRemoteThread + LoadLibraryW.

Uses the Win32 snapshot API directly (no tasklist subprocess) so it is immune to
console code-page issues on localized Windows.

Usage:
    python inject.py <dll_path> <process_name>
    python inject.py <dll_path> --pid <pid>
    python inject.py <dll_path> --launch <exe_path> <process_name>
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32First.restype = wt.BOOL
k32.Process32Next.restype = wt.BOOL
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.restype = wt.BOOL
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, wt.LPCSTR]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.c_void_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


def list_processes():
    """Return [(pid, exe_name), ...] via the toolhelp snapshot."""
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return out
    try:
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if k32.Process32First(snap, ctypes.byref(e)):
            while True:
                out.append((e.th32ProcessID, e.szExeFile.decode("ascii", "ignore")))
                if not k32.Process32Next(snap, ctypes.byref(e)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


def find_pid(name):
    want = name.lower()
    if not want.endswith(".exe"):
        want += ".exe"
    for pid, exe in list_processes():
        if exe.lower() == want:
            return pid
    return None


def wait_for_pid(name, timeout=25.0):
    end = time.time() + timeout
    while time.time() < end:
        pid = find_pid(name)
        if pid:
            return pid
        time.sleep(0.4)
    return None


def inject(pid, dll_path):
    dll_path = os.path.abspath(dll_path)
    if not os.path.isfile(dll_path):
        raise FileNotFoundError(dll_path)

    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise OSError(f"OpenProcess(pid={pid}) 失败: {ctypes.get_last_error()}")

    try:
        buf = dll_path.encode("utf-16-le") + b"\x00\x00"
        remote = k32.VirtualAllocEx(h, None, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote:
            raise OSError(f"VirtualAllocEx 失败: {ctypes.get_last_error()}")

        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, buf, len(buf), ctypes.byref(written)):
            raise OSError(f"WriteProcessMemory 失败: {ctypes.get_last_error()}")

        kern = k32.GetModuleHandleW("kernel32.dll")
        load_lib = k32.GetProcAddress(kern, b"LoadLibraryW")
        if not load_lib:
            raise OSError("GetProcAddress(LoadLibraryW) 失败")

        th = k32.CreateRemoteThread(h, None, 0, load_lib, remote, 0, None)
        if not th:
            raise OSError(f"CreateRemoteThread 失败: {ctypes.get_last_error()}")

        # The thread's exit code IS LoadLibraryW's return value (the module
        # handle).  A zero result means the DLL was rejected -- usually a
        # bitness mismatch or a dependency that could not be resolved.
        rc = k32.WaitForSingleObject(th, 15000)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        k32.CloseHandle(th)
        k32.VirtualFreeEx(h, remote, 0, 0x8000)

        if code.value == 0:
            raise OSError(
                "LoadLibraryW 在目标进程内返回 0（DLL 未被加载）。\n"
                "  常见原因：位数不匹配、DLL 依赖缺失、或目标进程被保护。\n"
                f"  wait={rc} threadExitCode=0"
            )
        return code.value
    finally:
        k32.CloseHandle(h)


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        return 1

    dll = args[0]

    if args[1] == "--pid":
        pid = int(args[2])
        print(f"目标 pid={pid}")
        inject(pid, dll)
        print("注入完成")
        return 0

    if args[1] == "--launch":
        exe, name = args[2], args[3]
        print(f"启动 {exe}")
        subprocess.Popen([exe], close_fds=True)
        pid = wait_for_pid(name)
        if not pid:
            print("超时未找到进程")
            return 1
        print(f"已启动 pid={pid}")
        time.sleep(1.5)
    else:
        name = args[1]
        pid = find_pid(name)
        if not pid:
            print(f"进程 {name} 未运行。当前存在的相关进程：")
            for p, e in list_processes():
                if "rv" in e.lower():
                    print(f"   {p}  {e}")
            return 1

    print(f"注入 {os.path.abspath(dll)} -> pid {pid}")
    inject(pid, dll)
    print("注入完成")
    return 0


sys.exit(main())
