"""Parse the captured join command byte-by-byte and reverse the record layout.

The join frame embeds the network name in UTF-16LE, which makes the structure
tractable: we can locate the string, work out the surrounding length fields, and
then rebuild a byte-identical frame to prove the model is right.

Success criterion: rebuild the frame for the same network name and get exactly
the same bytes back.
"""
import sys

FRAME = bytes.fromhex(
    "00000004 0100 034a 00000017"
    "00000004 0100 0300 00000003"
    "00000046 0000131b"
    "00000004 0b00 033f 00000001"
    "00000032 0300 0306"
    "00 4d0069006e0065006300720061006600740020005b0050006f0072007400750067007500ea0073002000310030005d 0001"
    .replace(" ", ""))

NAME = "Minecraft [Português 10]"


def show():
    print(f"整帧长度 = {len(FRAME)}\n")
    print("逐字节：")
    for i in range(0, len(FRAME), 16):
        chunk = FRAME[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hexs:<47}  {asc}")


def locate_name():
    nb = NAME.encode("utf-16-le")
    idx = FRAME.find(nb)
    print(f"\n网络名 UTF-16LE（{len(nb)} 字节）出现在偏移 {idx}")
    return idx, nb


def main():
    show()
    idx, nb = locate_name()

    print("\n=== 围绕字符串的字节 ===")
    print("  前 12 字节:", FRAME[idx - 12:idx].hex(" "))
    print("  字符串    :", nb.hex(" "))
    print("  后 8 字节 :", FRAME[idx + len(nb):idx + len(nb) + 8].hex(" "))

    # 记录头在字符串前 8 字节处？
    hdr = FRAME[idx - 8:idx]
    print(f"\n字符串前 8 字节 = {hdr.hex(' ')}")
    if hdr[:4] == bytes.fromhex("00000032"):
        size = int.from_bytes(hdr[:4], "big")
        print(f"  前 4 字节是大端长度 = {size}")
        print(f"  字符串长度 {len(nb)}；记录剩余 = {size - len(nb)}")
        print(f"  记录若是 [size][4字节头][name][2字节尾]: {size} vs {4 + len(nb) + 2}")

    # 检查整帧尾部
    print(f"\n整帧末尾 4 字节: {FRAME[-4:].hex(' ')}")

    # 尝试建模：尾部固定 2 字节 00 01，字符串前有 4 字节记录头
    print("\n=== 建模验证 ===")
    tail = FRAME[idx + len(nb):]
    print(f"  字符串之后剩余 {len(tail)} 字节: {tail.hex(' ')}")
    head4 = FRAME[idx - 4:idx]
    print(f"  字符串之前紧邻的 4 字节: {head4.hex(' ')}")

    # 重建整帧
    prefix = FRAME[:idx]
    rebuilt = prefix + nb + tail
    print(f"\n重建结果 == 原始 ? {rebuilt == FRAME}")

    return 0


sys.exit(main())
