#!/usr/bin/env python3
"""disasm.py —— 反汇编 RvControlSvc.exe 的 .text，定位命令分派 switch。

思路
----
我们已经从服务日志和命令码扫描得知这些码是真实存在的：
    2 创建网络   3 加入网络   5 离开网络   6 踢人   8 启停网络
   10 批准加入  15 删除网络  16 授管     17 撤管  18 改别名

反序列化器一定有一个 switch(code) 把它们分到各个 CMessage 子类。MSVC 在这种
switch 上通常生成「cmp reg, imm / je」链或跳转表。所以只要反汇编全文、按函数
切分、统计哪段代码里同时出现了足够多的已知码，就能锁定分派函数，再读出
「码 -> 分支地址」，最后把分支地址落到具体类。

用法：
    python disasm.py find-switch        # 找候选分派函数
    python disasm.py dump <VA> [长度]    # 反汇编指定地址
    python disasm.py funcs              # 列出所有函数起始与规模
"""
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, CS_OP_REG

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from pe import PE  # noqa: E402

PATH = r"C:\Program Files (x86)\Radmin VPN\RvControlSvc.exe"
KNOWN_CODES = {2, 3, 5, 6, 8, 10, 15, 16, 17, 18}


def load():
    pe = PE(PATH)
    text = next(s for s in pe.sections if s["name"] == ".text")
    lo = pe.image_base + text["vaddr"]
    data = pe.data[text["rawptr"]:text["rawptr"] + text["rawsize"]]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return pe, text, lo, data, md


def split_functions(insns):
    """按 ret/int3 填充切分函数（启发式，够用）。"""
    funcs = []
    cur = []
    gap = 0
    for ins in insns:
        cur.append(ins)
        if ins.mnemonic == "int3":
            gap += 1
            if gap >= 2 and len(cur) > 8:
                funcs.append(cur)
                cur = []
                gap = 0
        else:
            gap = 0
    if cur:
        funcs.append(cur)
    return funcs


def find_switch():
    pe, text, lo, data, md = load()
    insns = list(md.disasm(data, lo))
    print(f".text 反汇编：{len(insns):,} 条指令\n")

    funcs = split_functions(insns)
    print(f"按 int3 切出 {len(funcs):,} 个候选函数段")

    scored = []
    for f in funcs:
        imms = set()
        for ins in f:
            if ins.mnemonic == "cmp" and ins.operands:
                # cmp reg, imm 或 cmp [mem], imm
                for op in ins.operands:
                    if op.type == CS_OP_IMM:
                        imms.add(op.imm)
        cover = KNOWN_CODES & imms
        if len(cover) >= 5:
            scored.append((len(cover), f[0].address, f[-1].address, len(f), sorted(cover), sorted(imms)))

    scored.sort(reverse=True)
    print(f"\n=== 候选分派函数（覆盖已知码 >= 5 个）：{len(scored)} 个 ===\n")
    for cover, start, end, n, codes, allimms in scored[:12]:
        print(f"  0x{start:08x}..0x{end:08x}  {n:>4} 条  覆盖 {cover}/10")
        print(f"      命中的已知码: {codes}")
        small = [x for x in allimms if 0 <= x < 0x2000]
        print(f"      该段所有小立即数: {small}")
        print()


def dump_func(va, length=0x200):
    pe, text, lo, data, md = load()
    off = pe.va_to_off(va)
    if off is None:
        print("地址不在任何节里")
        return
    code = pe.data[off:off + length]
    print(f"=== 反汇编 0x{va:08x} 起 {length} 字节 ===")
    for ins in md.disasm(code, va):
        line = f"  0x{ins.address:08x}  {ins.bytes.hex():<18} {ins.mnemonic:<8} {ins.op_str}"
        print(line)


def list_funcs():
    pe, text, lo, data, md = load()
    insns = list(md.disasm(data, lo))
    funcs = split_functions(insns)
    funcs.sort(key=lambda f: len(f), reverse=True)
    print(f"最大的 25 个函数：")
    for f in funcs[:25]:
        print(f"  0x{f[0].address:08x}   {len(f):>5} 条   ..0x{f[-1].address:08x}")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "find-switch":
        find_switch()
    elif sys.argv[1] == "dump":
        va = int(sys.argv[2], 0)
        n = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x200
        dump_func(va, n)
    elif sys.argv[1] == "funcs":
        list_funcs()
