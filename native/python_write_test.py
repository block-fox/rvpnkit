"""Decisive test: can this Python process write to the control pipe?

Two things are checked in one run:
  1. open the pipe with read+write, reporting the exact Win32 error
  2. actually WRITE a malformed frame and watch the service log for a new
     "[req:N] ..." line -- that line is proof the service received our bytes

A malformed frame is deliberate: it is the least likely payload to be
misinterpreted as a valid command, so the risk to real network state is minimal.
"""
import ctypes
import ctypes.wintypes as wt
import glob
import os
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
R, W, OPEN_EXISTING = 0x80000000, 0x40000000, 3
LOGDIR = r"C:\ProgramData\Famatech\Radmin VPN"

print("=== ① 打开管道（读写）===")
h = None
for attempt in range(8):
    h = k32.CreateFileW(PIPE, R | W, 0, None, OPEN_EXISTING, 0, None)
    if h not in (INV, None):
        print(f"  ✓ 读写打开成功（第 {attempt + 1} 次尝试）")
        break
    err = ctypes.get_last_error()
    print(f"  第 {attempt + 1} 次: err={err} ({ctypes.FormatError(err).strip()})")
    if err != 231:
        break
    time.sleep(0.8)

if h in (INV, None):
    print("\n✗ 读写打开失败，无法继续写入测试")
    raise SystemExit(1)

print("\n=== ② 记录日志现状 ===")
before = {}
for f in glob.glob(os.path.join(LOGDIR, "service*.log")):
    try:
        before[f] = os.path.getsize(f)
    except OSError:
        pass
print(f"  跟踪 {len(before)} 个日志文件")

print("\n=== ③ 写入畸形帧（长度=1，正文=0x00）===")
body = b"\x00"
buf = (1).to_bytes(4, "little") + body
arr = ctypes.create_string_buffer(buf, len(buf))
written = wt.DWORD(0)
ok = k32.WriteFile(h, arr, len(buf), ctypes.byref(written), None)
if ok:
    print(f"  ✓ WriteFile 成功，写入 {written.value} 字节")
else:
    err = ctypes.get_last_error()
    print(f"  ✗ WriteFile 失败 err={err} ({ctypes.FormatError(err).strip()})")

print("\n=== ④ 观察服务日志变化（最多 10 秒）===")
deadline = time.time() + 10
saw = False
while time.time() < deadline and not saw:
    time.sleep(0.6)
    for f, old in list(before.items()):
        try:
            new = os.path.getsize(f)
        except OSError:
            continue
        if new > old:
            with open(f, "rb") as fh:
                fh.seek(old)
                added = fh.read(new - old).decode("utf-8", "ignore")
            for line in added.splitlines():
                if "[req:" in line:
                    print(f"  ★ 服务记录: {line.strip()}")
                    saw = True
            before[f] = new

k32.CloseHandle(h)

print()
if saw:
    print("═══ 结论 ═══")
    print("✓ 写入路径完全打通：服务接收并处理了我们的数据。")
    print("  Python 侧可用 → 可先在 Python 中试出命令格式，再移植回 .NET。")
else:
    print("═══ 结论 ═══")
    print("写入已发出，但 10 秒内未见服务记录新请求。")
    print("可能：服务丢弃了无法解析的帧、日志有缓冲延迟、或帧格式要求更严。")
