"""从协议立即数倒推序列化代码。

join 容器的标签 0x131b、create 的 0x132b 都会以立即数出现在 .text 里。
找到写入这些标签的函数，就能顺着找到同函数里写 field 0x0d 的地方，
再往回追「这个 blob 是谁算出来的」。
"""

import re
import struct

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
TEXT_VA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x1cda00

TAGS = {
    0x131B: "join 容器",
    0x132B: "create 容器",
    0x1323: "网络容器",
    0x1322: "节点容器",
}


def main():
    data = open(EXE, "rb").read()
    text = data[TEXT_RAW:TEXT_RAW + TEXT_SIZE]

    for tag, label in TAGS.items():
        pat = struct.pack("<I", tag)
        offs = [m.start() for m in re.finditer(re.escape(pat), text)]
        print(f"\n=== 0x{tag:04x} ({label}) 出现 {len(offs)} 处 ===")
        for off in offs[:10]:
            va = TEXT_VA + off
            # 往前退 8 字节，看看是不是 push imm32 (68 xx xx xx xx) 或 mov
            ctx = text[max(0, off - 8):off + 12]
            print(f"  file=0x{TEXT_RAW+off:x}  va=0x{va:x}  "
                  f"前文={ctx[:8].hex()}  立即数后={ctx[12:].hex()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
