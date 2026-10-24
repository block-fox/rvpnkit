"""在客户端二进制里搜常见的 32 位混合常量，定位密码处理代码。

结构已确认：令牌 = 4 字节 IV + 每字符 4 字节的链式状态。
所以实现里一定有一个「循环处理宽字符、每轮产出 4 字节」的函数。
这类函数通常带一个特征常量（黄金比例、Murmur 的 fmix、xxHash 素数等）。
"""

import os
import struct

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"

CONSTS = {
    "golden 0x9E3779B9": 0x9E3779B9,
    "golden 0x9E3779B1": 0x9E3779B1,
    "murmur3 c1 0x85EBCA6B": 0x85EBCA6B,
    "murmur3 c2 0xC2B2AE35": 0xC2B2AE35,
    "wang 0x45D9F3B": 0x045D9F3B,
    "prospector c1 0x7FEB352D": 0x7FEB352D,
    "prospector c2 0x846CA68B": 0x846CA68B,
    "0x27D4EB2F": 0x27D4EB2F,
    "xxhash p2 0x165667B1": 0x165667B1,
    "xxhash p3 0x9E3779B1": 0x9E3779B1,
    "fnv 16777619": 16777619,
    "0xCC9E2D51 (city/murmur)": 0xCC9E2D51,
    "0x1B873593": 0x1B873593,
    "sha256 K[0] 0x428A2F98": 0x428A2F98,
    "md5 T[1] 0xD76AA478": 0xD76AA478,
    "crc32 poly 0xEDB88320": 0xEDB88320,
}


def main():
    data = open(EXE, "rb").read()
    print(f"{EXE}\n大小 {len(data)} 字节\n")

    for name, val in CONSTS.items():
        for endian, fmt in (("LE", "<I"), ("BE", ">I")):
            pat = struct.pack(fmt, val)
            offs = []
            start = 0
            while True:
                i = data.find(pat, start)
                if i < 0:
                    break
                offs.append(i)
                start = i + 1
                if len(offs) > 12:
                    break
            if offs:
                shown = ", ".join(hex(o) for o in offs[:8])
                print(f"  {name:<26} {endian}  出现 {len(offs)} 处: {shown}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
