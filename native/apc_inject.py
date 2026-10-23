"""APC injection: queue LoadLibraryW into an alertable thread of the target.

Why: the HIPS driver on this machine blocks CreateRemoteThread (the remote
thread is created but never executes).  QueueUserAPC uses a completely
different kernel path -- the APC runs when the target thread next enters an
alertable wait, which GUI threads do constantly (MsgWaitForMultipleObjectsEx).
Many HIPS products hook only CreateRemoteThread.

The APC routine is kernel32!LoadLibraryW and the single argument is the DLL
path (allocated in the target).  LoadLibraryW's signature on x86 is
stdcall(LPCWSTR) -> HMODULE, which matches APC's void CALLBACK(ULONG_PTR)
convention closely enough: the APC dispatcher calls with one argument in the
stack slot, so LoadLibraryW reads it as its parameter.
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPPROCESS = 0x00000002

k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = ctypes.c_void_p
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, wt.LPCSTR]
k32.QueueUserAPC.restype = wt.DWORD
k32.QueueUserAPC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.CloseHandle.argtypes = [ctypes.c_void_p]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ThreadID", wt.DWORD), ("th32OwnerProcessID", wt.DWORD),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wt.DWORD)]


def find_pid(name):
    want = name.lower()
    if not want.endswith(".exe"):
        want += ".exe"
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, ctypes.c_void_p(-1).value):
        return None
    from ctypes import wintypes
    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]
    e = PE()
    e.dwSize = ctypes.sizeof(PE)
    try:
        if k32.Process32First(snap, ctypes.byref(e)):
            while True:
                if e.szExeFile.decode("ascii", "ignore").lower() == want:
                    return e.th32ProcessID
                if not k32.Process32Next(snap, ctypes.byref(e)):
                    break
    finally:
        k32.CloseHandle(snap)
    return None


def thread_ids_of(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap in (None, ctypes.c_void_p(-1).value):
        return []
    ids = []
    e = THREADENTRY32()
    e.dwSize = ctypes.sizeof(THREADENTRY32)
    try:
        if k32.Thread32First(snap, ctypes.byref(e)):
            while True:
                if e.th32OwnerProcessID == pid:
                    ids.append(e.th32ThreadID)
                if not k32.Thread32Next(snap, ctypes.byref(e)):
                    break
    finally:
        k32.CloseHandle(snap)
    return ids


def main():
    dll = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "probe32.dll")
    if not os.path.isfile(dll):
        raise SystemExit(f"DLL 不存在: {dll}")

    pid = find_pid("RvRvpnGui")
    if not pid:
        raise SystemExit("找不到 RvRvpnGui")
    print(f"目标 pid={pid}")
    print(f"DLL  {dll}")

    # 1. 拿 LoadLibraryW 地址（各进程的 kernel32 基址一致，32 位目标需 32 位值）
    kern = k32.GetModuleHandleW("kernel32.dll")
    load_lib = k32.GetProcAddress(kern, b"LoadLibraryW")
    print(f"LoadLibraryW = 0x{load_lib:x}（本进程 kernel32 基址 0x{kern:x}）")

    # 2. 打开进程并写入 DLL 路径
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise SystemExit(f"OpenProcess 失败 err={ctypes.get_last_error()}")

    try:
        buf = dll.encode("utf-16-le") + b"\x00\x00"
        remote = k32.VirtualAllocEx(h, None, len(buf), MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE)
        if not remote:
            raise SystemExit(f"VirtualAllocEx 失败 err={ctypes.get_last_error()}")
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, buf, len(buf), ctypes.byref(written)):
            raise SystemExit(f"WriteProcessMemory 失败 err={ctypes.get_last_error()}")
        print(f"已将路径写入目标内存 0x{remote:x}（{written.value} 字节）")

        # 3. 对每个线程排队 APC
        tids = thread_ids_of(pid)
        print(f"目标线程数: {len(tids)}")

        queued = 0
        for tid in tids:
            hth = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
            if not hth:
                continue
            try:
                if k32.QueueUserAPC(load_lib, hth, remote):
                    queued += 1
            finally:
                k32.CloseHandle(hth)

        print(f"已向 {queued} 个线程排队 APC")
        print("等待 APC 执行（最多 15 秒）…")

        marker = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvprobe.log")
        deadline = time.time() + 15
        while time.time() < deadline:
            if os.path.exists(marker):
                print("\n★ 成功！DllMain 已执行，标记文件：")
                print(open(marker, encoding="utf-8", errors="ignore").read())
                return 0
            time.sleep(0.5)

        print("\n✗ 15 秒内未见标记文件 —— APC 也未执行")
        print("  可能原因：目标线程都未进入 alertable 等待状态，或驱动同样拦截了 APC")
        return 1
    finally:
        k32.CloseHandle(h)


sys.exit(main())
