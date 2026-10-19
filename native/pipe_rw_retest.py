"""Carefully re-test whether the control pipe accepts a read+write open.

Earlier results were noisy: probes raced each other and produced a mix of
ERROR_ACCESS_DENIED (5) and ERROR_PIPE_BUSY (231).  This version retries on
BUSY, tries several times, and reports the distribution so the real answer is
unambiguous.
"""
import ctypes
import ctypes.wintypes as wt
import time
from collections import Counter

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

PIPE = "\\\\.\\pipe\\RadminVpnGuiChannel"
INV = ctypes.c_void_p(-1).value
R, W, OPEN_EXISTING = 0x80000000, 0x40000000, 3

ATTEMPTS = 12
results = Counter()
success_rw = 0

print(f"目标: {PIPE}")
print(f"对每种权限尝试 {ATTEMPTS} 次，遇 BUSY 则短暂等待重试\n")


def try_open(access, attempts=ATTEMPTS):
    codes = Counter()
    ok = 0
    for i in range(attempts):
        h = k32.CreateFileW(PIPE, access, 0, None, OPEN_EXISTING, 0, None)
        if h in (INV, None):
            codes[ctypes.get_last_error()] += 1
            time.sleep(0.35)
        else:
            ok += 1
            k32.CloseHandle(h)
            time.sleep(0.35)
    return ok, codes


for label, access in (("RW 读写", R | W), ("R  只读", R)):
    ok, codes = try_open(access)
    detail = ", ".join(f"err={e}×{n}" for e, n in codes.most_common())
    print(f"{label}: 成功 {ok}/{ATTEMPTS}   {detail if detail else '全部成功'}")
    if label.startswith("RW"):
        success_rw = ok

print()
if success_rw > 0:
    print("★ 结论：管道【接受读写打开】—— 写路径在权限层面可行。")
    print("  之前观察到的 ERROR_ACCESS_DENIED 是探测竞争造成的假象。")
else:
    print("结论：读写打开从未成功 —— 需要进一步确认 ACL。")
