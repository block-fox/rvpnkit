"""Extract Radmin command frames from the hook log and look for the search string.

Typing into the "join network" search box produced ~93 frames, one per query.
Those frames embed a user-visible string ("minecraft" or its prefixes), which
makes them the best possible samples for reverse-engineering the string
encoding used by the command protocol.
"""
import os
import re
import sys

LOG = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpipe_hook.log")
MAGIC = bytes.fromhex("00000004 0100".replace(" ", ""))


def frames():
    text = open(LOG, encoding="utf-8", errors="ignore").read()
    out = []
    for m in re.finditer(r"=== OUT \([^)]*\) len=(\d+) ===\s*\nHEX:\n(.*?)\nASCII:",
                         text, re.S):
        declared = int(m.group(1))
        try:
            data = bytes.fromhex(m.group(2).replace("\n", " ").replace(" ", ""))
        except ValueError:
            continue
        if len(data) == declared:
            out.append(data)
    return out


def main():
    all_frames = frames()
    radmin = [f for f in all_frames if f.startswith(MAGIC)]

    print(f"全部 OUT 帧: {len(all_frames)}")
    print(f"其中 Radmin 帧（以魔数开头）: {len(radmin)}\n")

    # 找含用户输入字符串的帧
    needle = b"minecraft"
    hits = [f for f in radmin if needle in f]
    print(f"含 ASCII 'minecraft' 的帧: {len(hits)}\n")

    if hits:
        print("=== 样本（前 5 条）===")
        for f in hits[:5]:
            print(f"len={len(f)}")
            print("  hex:", f.hex(" "))
            idx = f.find(needle)
            print(f"  'minecraft' 出现在偏移 {idx}")
            print(f"  前后上下文: {f[max(0,idx-12):idx+len(needle)+8].hex(' ')}")
            print()

    # 按长度归类，看看命令种类
    print("=== Radmin 帧按长度分布 ===")
    from collections import Counter
    for ln, cnt in sorted(Counter(len(f) for f in radmin).items()):
        print(f"  len={ln:4d}  x{cnt}")

    # 找出长度变化最大的几帧（很可能是查询）
    print("\n=== 最长的 6 条 Radmin 帧 ===")
    for f in sorted(radmin, key=len, reverse=True)[:6]:
        print(f"len={len(f)}")
        print("  ", f.hex(" ")[:400])
        # 尝试提取可打印 ASCII 串
        runs = re.findall(rb"[\x20-\x7e]{4,}", f)
        if runs:
            print("   ASCII 串:", [r.decode() for r in runs][:6])
        print()

    return 0


sys.exit(main())
