#!/usr/bin/env python3
"""dump_table.py —— 解析 RvControlSvc.exe 里疑似「命令码表」的 .rdata 区域。

之前用「连续小整数」扫到 0x001244e0 处疑似 (命令码, 任务类型) 配对表。
这里把它前后一大段都 dump 出来，并尝试识别指针（落在 .text 里的值），
因为很多 C++ 实现会用 { 码, 处理函数指针 } 或 { 码, 工厂函数指针 }。
"""
import struct
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from pe import PE  # noqa: E402

PATH = r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe"


def main():
    pe = PE(PATH)
    text = next(s for s in pe.sections if s["name"] == ".text")
    text_lo = pe.image_base + text["vaddr"]
    text_hi = text_lo + text["rawsize"]

    # 0x001244e0 是文件偏移（之前脚本用的是 open().read() 的下标）
    off = 0x001244E0
    va = pe.off_to_va(off)
    print(f"表起始：文件偏移 0x{off:08x}  VA 0x{va:08x}")
    print(f".text 范围：0x{text_lo:08x} .. 0x{text_hi:08x}\n")

    print("=== 前后 0x200 字节，按 u32 解读 ===")
    start = off - 0x80
    for i in range(0, 0x200, 4):
        o = start + i
        (v,) = struct.unpack_from("<I", pe.data, o)
        tag = ""
        if text_lo <= v < text_hi:
            tag = "  <-- 代码指针"
        elif 0x400000 <= v < 0x401000:
            tag = "  <-- ?"
        print(f"  0x{o:08x} (VA 0x{pe.off_to_va(o) or 0:08x})  {v:>12}  0x{v:08x}{tag}")

    print("\n=== 尝试按 {u32,u32} 配对解读（从表起始） ===")
    pairs = []
    for i in range(0, 0x100, 8):
        a, b = struct.unpack_from("<II", pe.data, off + i)
        pairs.append((a, b))
        note = ""
        if text_lo <= b < text_hi:
            note = "  b 是代码指针"
        print(f"  ({a:>3}, 0x{b:08x}){note}")

    print("\n=== 换成指针宽度扫描：找 .rdata 里指向 .text 的密集指针区 ===")
    rdata = next(s for s in pe.sections if s["name"] == ".rdata")
    lo = rdata["rawptr"]
    hi = lo + rdata["rawsize"]
    runs = []
    cur = []
    for o in range(lo, hi - 4, 4):
        (v,) = struct.unpack_from("<I", pe.data, o)
        if text_lo <= v < text_hi:
            cur.append((o, v))
        else:
            if len(cur) >= 6:
                runs.append((cur[0][0], cur[-1][0], len(cur)))
            cur = []
    if len(cur) >= 6:
        runs.append((cur[0][0], cur[-1][0], len(cur)))
    print(f"  找到 {len(runs)} 段连续代码指针区：")
    for a, b, n in runs[:15]:
        print(f"    文件偏移 0x{a:08x}..0x{b:08x}  共 {n} 个指针  "
              f"(VA 0x{pe.off_to_va(a):08x})")


if __name__ == "__main__":
    main()
