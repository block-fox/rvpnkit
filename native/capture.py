#!/usr/bin/env python3
"""capture.py —— 常驻抓取 Radmin VPN 的命令报文。

用法
----
    python capture.py start             # 注入并持续跟随（GUI 重启会自动重注入）
    python capture.py status            # 查看当前状态与日志文件
    python capture.py list              # 列出所有抓包文件
    python capture.py mark "描述"        # 在当前日志里插一条标记，便于事后对齐动作

产物
----
    %TEMP%\\rvpn_capture\\<时间>_pid<pid>.log

每条记录形如：
    === 2026-10-24 13:20:11.123 len=102 ===
    HEX:
    00 00 00 04 ...

分析时把 HEX 还原成字节，再和服务日志 service.log 里的 [req:N] 行按
请求编号对应，就能知道每条命令做了什么。
"""
import ctypes
import ctypes.wintypes as wt
import glob
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpn_capture")
DLL = os.path.join(HERE, "rvpn_capture32.dll")
HELPER = os.path.join(HERE, "inject32.exe")
GUI_EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE = 0x1000, 0x2000, 0x04

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
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wt.DWORD]
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
k32.CloseHandle.argtypes = [ctypes.c_void_p]


def gui_pid():
    """返回 RvRvpnGui.exe 的 pid，未运行则返回 None。"""
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq RvRvpnGui.exe",
                          "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, errors="ignore")
    for line in out.stdout.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == "rvrvpngui.exe":
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def loadlib_addr():
    """从 32 位辅助进程取 32 位 kernel32!LoadLibraryW 地址。

    必须用 32 位地址：从 64 位 Python 直接取会得到 64 位地址，在 32 位目标
    里无效，注入会「成功」但毫无作用（本项目踩过的最大的坑）。
    """
    r = subprocess.run([HELPER, "--addr-only"], capture_output=True,
                       text=True, timeout=20)
    for line in r.stdout.splitlines():
        m = re.match(r"LOADLIBRARYW=0x([0-9a-fA-F]+)", line)
        if m:
            return int(m.group(1), 16)
    return None


def inject(pid):
    """把 hook DLL 注入指定进程，成功返回 True。"""
    loadlib = loadlib_addr()
    if not loadlib:
        print("✗ 无法获取 32 位 LoadLibraryW 地址（inject32.exe 缺失？）")
        return False

    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print(f"✗ OpenProcess 失败 err={ctypes.get_last_error()}")
        return False

    try:
        buf = DLL.encode("utf-16-le") + b"\x00\x00"
        remote = k32.VirtualAllocEx(h, None, len(buf), MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE)
        if not remote:
            print(f"✗ VirtualAllocEx 失败 err={ctypes.get_last_error()}")
            return False

        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, buf, len(buf), ctypes.byref(written)):
            print(f"✗ WriteProcessMemory 失败 err={ctypes.get_last_error()}")
            return False

        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(loadlib),
                                    ctypes.c_void_p(remote), 0, None)
        if not th:
            print(f"✗ CreateRemoteThread 失败 err={ctypes.get_last_error()}")
            return False

        k32.WaitForSingleObject(th, 8000)
        code = wt.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(code))
        k32.CloseHandle(th)

        if code.value == 0:
            print("✗ LoadLibraryW 返回 0，DLL 未载入")
            return False
        return True
    finally:
        k32.CloseHandle(h)


def capture_files():
    return sorted(glob.glob(os.path.join(CAPTURE_DIR, "*.log")))


def latest_file():
    files = capture_files()
    return files[-1] if files else None


def count_frames(path):
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
        return len(re.findall(r"^=== \d{4}-", text, re.M))
    except OSError:
        return 0


def cmd_start():
    if not os.path.isfile(DLL):
        print(f"✗ 找不到 {os.path.basename(DLL)}，请先编译：")
        print("  zig cc -target x86-windows-gnu -shared -O2 -s "
              "-o native/rvpn_capture32.dll native/rvpn_capture.c")
        return 1
    if not os.path.isfile(HELPER):
        print(f"✗ 找不到 {os.path.basename(HELPER)}，请先编译 inject32.exe")
        return 1

    os.makedirs(CAPTURE_DIR, exist_ok=True)
    print(f"抓包目录: {CAPTURE_DIR}")
    print("开始跟随 RvRvpnGui.exe（GUI 重启会自动重新注入）…")
    print("按 Ctrl+C 停止。\n")

    injected = set()
    quiet_until = 0.0
    try:
        while True:
            pid = gui_pid()
            if pid is None:
                if time.time() > quiet_until:
                    print("  … 等待 Radmin VPN 启动")
                    quiet_until = time.time() + 10
            elif pid not in injected:
                if inject(pid):
                    injected.add(pid)
                    print(f"  ✓ 已注入 pid={pid}")
                    time.sleep(0.6)
                    f = latest_file()
                    if f:
                        print(f"    日志: {f}")
                else:
                    quiet_until = time.time() + 5
            else:
                # 已注入，定期报告帧数
                f = latest_file()
                if f and time.time() > quiet_until:
                    print(f"  · pid={pid} 已捕获 {count_frames(f)} 帧  ({os.path.basename(f)})")
                    quiet_until = time.time() + 30
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n已停止。")
        return 0


def cmd_status():
    pid = gui_pid()
    print(f"Radmin GUI : {pid if pid else '未运行'}")
    files = capture_files()
    if not files:
        print(f"抓包文件   : 无（目录 {CAPTURE_DIR}）")
        return 0
    print(f"抓包目录   : {CAPTURE_DIR}")
    print(f"文件数     : {len(files)}")
    for f in files[-6:]:
        size = os.path.getsize(f)
        print(f"  {os.path.basename(f):<44} {size:>9,} 字节  {count_frames(f):>5} 帧")
    return 0


def cmd_list():
    for f in capture_files():
        print(f)
    return 0


def cmd_mark(text):
    f = latest_file()
    if not f:
        print("还没有抓包文件")
        return 1
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(f, "a", encoding="utf-8") as fh:
        fh.write(f"\n##### MARK {stamp} {text}\n")
    print(f"✓ 已写入标记到 {os.path.basename(f)}: {text}")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    action = argv[1]
    if action == "start":
        return cmd_start()
    if action == "status":
        return cmd_status()
    if action == "list":
        return cmd_list()
    if action == "mark" and len(argv) > 2:
        return cmd_mark(" ".join(argv[2:]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
