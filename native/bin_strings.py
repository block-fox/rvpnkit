#!/usr/bin/env python3
"""bin_strings.py —— 在 Radmin 二进制里搜关键字，定位命令名表。

思路
----
服务端日志里的 "Requested to create network"、"Disabled network" 这类句子
一定来自某个二进制的字符串常量。同一张字符串表里通常还躺着**所有**命令的
描述，包括我们还没在界面上触发过的（比如踢人）。直接搜比去点界面快得多。

用法：
    python bin_strings.py                      # 默认扫描并输出关键字命中
    python bin_strings.py --pattern kick       # 自定义关键字
    python bin_strings.py --near "Requested"   # 打印 "Requested" 附近的字符串
"""
import os
import re
import sys

DIRS = [
    r"C:\Program Files (x86)\Radmin VPN",
    r"C:\Windows\System32",
]

TARGETS = [
    "RvControlSvc.exe",
    "RvRvpnGui.exe",
    "RvROLClient.dll",
    "RvRVpnNet.dll",
    "RvRvpnService.exe",
]

DEFAULT_PATTERNS = [
    "kick", "Kick", "KICK",
    "remove", "Remove",
    "ban", "Ban",
    "exclude", "Exclude",
    "role", "Role",
    "admin", "Admin",
    "grant", "Grant",
    "requested to", "Requested to",
    "network", "Network",
]


def iter_files():
    for d in DIRS:
        for name in TARGETS:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                yield p
        # 顺带扫 Radmin 目录下所有 dll/exe
        if os.path.isdir(d) and "Radmin" in d:
            for f in os.listdir(d):
                if f.lower().endswith((".dll", ".exe")):
                    p = os.path.join(d, f)
                    if os.path.isfile(p):
                        yield p


def strings_of(path, min_len=4):
    """提取 ASCII 与 UTF-16LE 字符串。"""
    try:
        data = open(path, "rb").read()
    except OSError:
        return
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        yield m.start(), "ascii", m.group().decode("ascii", "ignore")
    # UTF-16LE
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        yield m.start() // 2, "utf16", m.group().decode("utf-16-le", "ignore")


def main(argv):
    pats = DEFAULT_PATTERNS
    if "--pattern" in argv:
        pats = [argv[argv.index("--pattern") + 1]]
    near = argv[argv.index("--near") + 1] if "--near" in argv else None

    seen_files = set()
    for path in iter_files():
        if path in seen_files:
            continue
        seen_files.add(path)
        hits = []
        for off, enc, s in strings_of(path):
            for p in pats:
                if p in s:
                    hits.append((off, enc, s))
                    break
        if not hits:
            continue
        print("=" * 82)
        print(f"{path}   命中 {len(hits)} 条")
        print("=" * 82)
        for off, enc, s in hits[:60]:
            print(f"  @0x{off:08x} [{enc:<5}] {s[:96]}")

        if near:
            print(f"\n  —— 包含 '{near}' 的条目 ——")
            for off, enc, s in strings_of(path):
                if near in s:
                    print(f"  @0x{off:08x} [{enc:<5}] {s[:110]}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
