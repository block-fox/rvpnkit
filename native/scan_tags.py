#!/usr/bin/env python3
"""scan_tags.py —— 统计快照里各类容器标签及其内容，定位公共网络列表。

快照里同一个容器标签往往对应同一类实体（0x1323 = 已加入的网络等）。
把每种标签下的样本字符串打出来，就能认出「公共网络列表」存在哪。
"""
import os
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from rvpnstate import read_snapshot, split_frames, walk, dec_str  # noqa: E402


def main():
    data = read_snapshot()
    print(f"快照 {len(data):,} 字节，帧数 {len(split_frames(data))}\n")

    tags = defaultdict(lambda: {"count": 0, "strings": [], "guids": 0, "nodes": 0})

    def visit(recs, depth=0):
        for field, t, payload, children in recs:
            if children is not None:
                key = f"0x13{field:02x}"
                tags[key]["count"] += 1
                visit(children, depth + 1)
            if t == 0x0D and len(payload) == 16:
                tags[f"field{field:02x}"]["guids"] += 1
            elif t == 0x03:
                s = dec_str(payload)
                if s and len(s) <= 64:
                    e = tags[f"str{field:02x}"]
                    e["count"] += 1
                    if len(e["strings"]) < 6 and s not in e["strings"]:
                        e["strings"].append(s)

    for body in split_frames(data):
        visit(walk(body))

    print("=== 容器标签 ===")
    for k, v in sorted(tags.items()):
        if k.startswith("0x13"):
            print(f"  {k}  出现 {v['count']} 次")

    print("\n=== 字符串字段 ===")
    for k, v in sorted(tags.items()):
        if k.startswith("str"):
            print(f"  {k}  {v['count']} 条  样本: {v['strings']}")

    print("\n=== GUID 字段 ===")
    for k, v in sorted(tags.items()):
        if k.startswith("field") and v["guids"]:
            print(f"  {k}  {v['guids']} 个 16 字节块")


if __name__ == "__main__":
    main()
