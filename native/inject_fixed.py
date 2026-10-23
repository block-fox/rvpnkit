"""Inject a 32-bit DLL into RvRvpnGui using the CORRECT 32-bit LoadLibraryW address.

Root cause of every earlier injection failure
---------------------------------------------
`ctypes.windll.kernel32.GetProcAddress(kernel32, "LoadLibraryW")` inside a
64-bit Python returns the address inside the **64-bit** kernel32 (e.g.
0x7ff8_22a7_f6c0).  The target RvRvpnGui.exe is **32-bit**, so that address is
unmapped there.  Executing it made the remote thread die instantly (exit code 0)
-- which I previously misread as "HIPS blocks remote threads".  In one case it
crashed the GUI outright.

Fix: obtain the 32-bit LoadLibraryW from a helper 32-bit process
(`inject32.exe --addr-only`).  System DLLs are relocated once per boot, so the
address is identical in every 32-bit process on this machine.  We verify it by
reading the "MZ" signature at the reported kernel32 base inside the target.

Then inject with CreateRemoteThread, and fall back to APC if needed.
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import subprocess
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
TH32CS_SNAPTHREAD = 0x00000004

k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.c_void_p]
k32.OpenThread.restype = ctypes.c_void_p
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.QueueUserAPC.restype = wt.DWORD
k32.QueueUserAPC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]

HERE = os.path.dirname(os.path.abspath(__file__))
MARKER = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvprobe.log")


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ThreadID", wt.DWORD), ("th32OwnerProcessID", wt.DWORD),
                ("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wt.DWORD)]


def find_pid(name="RvRvpnGui.exe"):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, errors="ignore")
    for line in out.stdout.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == name.lower():
            return int(parts[1])
    return None


def addr32():
    """从 32 位辅助进程读取 kernel32 基址与 LoadLibraryW 地址。"""
    r = subprocess.run([os.path.join(HERE, "inject32.exe"), "--addr-only"],
                       capture_output=True, text=True, timeout=20)
    base = lib = None
    for line in r.stdout.splitlines():
        m = re.match(r"KERNEL32_BASE=0x([0-9a-fA-F]+)", line)
        if m: base = int(m.group(1), 16)
        m = re.match(r"LOADLIBRARYW=0x([0-9a-fA-F]+)", line)
        if m: lib = int(m.group(1), 16)
    return base, lib


def verify_mapped(h, addr, label):
    """确认 addr 在目标进程里可读且像 PE 头。"""
    buf = ctypes.create_string_buffer(2)
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, 2, ctypes.byref(got))
    if not ok or got.value < 2:
        print(f"    {label} 0x{addr:08x}: 不可读 (err={ctypes.get_last_error()})")
        return False
    magic = buf.raw[:2]
    print(f"    {label} 0x{addr:08x}: {magic!r}")
    return magic == b"MZ"


def main():
    dll = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                          os.path.join(HERE, "probe32.dll"))
    pid = find_pid()
    if not pid:
        raise SystemExit("找不到 RvRvpnGui.exe")

    print("=== 修正后的 32 位注入 ===\n")
    print(f"  目标 pid : {pid}")
    print(f"  DLL      : {dll}")

    base, loadlib = addr32()
    if not base or not loadlib:
        raise SystemExit("无法获取 32 位 kernel32 地址")
    print(f"  32位 kernel32 基址 : 0x{base:08x}")
    print(f"  32位 LoadLibraryW  : 0x{loadlib:08x}")
    print("  （系统 DLL 每次开机只重定位一次，40 位以内地址对同机所有 32 位进程一致）")

    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise SystemExit(f"OpenProcess 失败 err={ctypes.get_last_error()}")

    try:
        print("\n  校验这些地址在目标进程内是否真实可读：")
        ok_base = verify_mapped(h, base, "kernel32")
        ok_lib = verify_mapped(h, loadlib, "LoadLibraryW")

        if not ok_base:
            print("\n  ✗ kernel32 基址在目标内不可读 —— 地址假设不成立，终止")
            return 2
        if not ok_lib:
            print("\n  ! LoadLibraryW 处不是可读内存，仍尝试（可能是 stub 页）")

        # 写入 DLL 路径
        buf = dll.encode("utf-16-le") + b"\x00\x00"
        remote = k32.VirtualAllocEx(h, None, len(buf), MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE)
        if not remote:
            raise SystemExit(f"VirtualAllocEx 失败 err={ctypes.get_last_error()}")
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, buf, len(buf), ctypes.byref(written)):
            raise SystemExit(f"WriteProcessMemory 失败 err={ctypes.get_last_error()}")
        print(f"\n  ✓ 路径已写入目标 0x{remote:x}（{written.value} 字节）")

        if os.path.exists(MARKER):
            os.remove(MARKER)

        # 方式 1：CreateRemoteThread
        #
        # 判据：LoadLibraryW 的返回值就是模块基址。只要线程返回码非 0，
        # 就说明 DLL 已经载入 —— 不需要再去检查标记文件（不同 DLL 写的标记
        # 名字不同，用标记文件判断会误判为失败，进而多余地触发 APC 注入，
        # 而 APC 中执行 LoadLibraryW 有 loader 锁风险，可能把目标进程搞崩）。
        print("\n  [1] CreateRemoteThread(LoadLibraryW) …")
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(loadlib),
                                    ctypes.c_void_p(remote), 0, None)
        if not th:
            print(f"      失败 err={ctypes.get_last_error()}")
        else:
            k32.WaitForSingleObject(th, 8000)
            code = wt.DWORD(0)
            k32.GetExitCodeThread(th, ctypes.byref(code))
            k32.CloseHandle(th)

            if code.value != 0:
                print(f"      ✓ 返回模块基址 0x{code.value:x} —— DLL 已载入")
                # 若该 DLL 会写标记文件，顺带展示
                for _ in range(6):
                    if os.path.exists(MARKER):
                        print("\n  标记文件:")
                        print(open(MARKER, encoding="utf-8", errors="ignore").read())
                        break
                    time.sleep(0.5)
                print("\n★ 注入成功（CreateRemoteThread）")
                return 0

            print(f"      返回码为 0 —— DLL 未载入，转 APC 尝试")

        # 方式 2：APC
        print("\n  [2] QueueUserAPC 到所有线程 …")
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)
        queued = 0
        if snap not in (None, ctypes.c_void_p(-1).value):
            if k32.Thread32First(snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        hth = k32.OpenThread(0x1F03FF, False, te.th32ThreadID)
                        if hth:
                            if k32.QueueUserAPC(ctypes.c_void_p(loadlib), hth, remote):
                                queued += 1
                            k32.CloseHandle(hth)
                    if not k32.Thread32Next(snap, ctypes.byref(te)):
                        break
            k32.CloseHandle(snap)
        print(f"      已排队 {queued} 个线程")
        for _ in range(20):
            if os.path.exists(MARKER):
                print("\n★ 成功（APC）！")
                print(open(MARKER, encoding="utf-8", errors="ignore").read())
                return 0
            time.sleep(0.5)

        print("\n✗ 两种方式都未生效")
        return 1
    finally:
        k32.CloseHandle(h)


sys.exit(main())
