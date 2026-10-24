"""启发式扫描：找出「既读 UTF-16 宽字符、又乘 32 位常量」的函数。

令牌生成循环必然同时具备：
  * movzx r32, word ptr [...]   (0F B7)   读一个宽字符
  * imul r32, r/m32, imm32      (69 /r)    乘一个常量（混淆用的魔数）

把两个特征在同一个函数里都出现的候选挑出来，再逐个用样本验证。
"""

import re
import struct

import capstone

EXE = r"C:\Program Files (x86)\Radmin VPN\RvRvpnGui.exe"
TEXT_VA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x1cda00


def main():
    data = open(EXE, "rb").read()
    text = data[TEXT_RAW:TEXT_RAW + TEXT_SIZE]

    T0 = TEXT_VA
    # 收集 imul r32, r/m32, imm32
    imuls = []
    for m in re.finditer(rb"\x69[\x00-\xff]{5}", text):
        i = m.start()
        imm = struct.unpack_from("<I", text, i + 2)[0]
        imuls.append((T0 + i, imm))
    print(f"imul reg,reg,imm32 共 {len(imuls)} 处")

    # 收集 movzx r32, word ptr
    movzxs = [T0 + m.start() for m in re.finditer(rb"\x0f\xb7", text)]
    print(f"movzx r32, word ptr 共 {len(movzxs)} 处")

    # 按 0x400 窗口聚类
    WINDOW = 0x400
    candidates = {}
    for va, imm in imuls:
        near = [m for m in movzxs if abs(m - va) < WINDOW]
        if near:
            key = (va // WINDOW)
            candidates.setdefault(key, {"imul": [], "movzx": len(near), "lo": key * WINDOW})
            candidates[key]["imul"].append((va, imm))

    print(f"\n同时含两种特征的窗口：{len(candidates)} 个\n")
    out = []
    for key, info in sorted(candidates.items()):
        lo = info["lo"]
        for va, imm in info["imul"]:
            out.append((va, imm, info["movzx"]))
    out.sort()

    for va, imm, nz in out:
        print(f"  imul @ 0x{va:08x}  常量=0x{imm:08x} ({imm})  附近 movzx {nz} 处")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
