"""Replay the captured enable/disable frames and read the service's own log.

We captured two 60-byte command frames differing only in the final u32
(0xfffffffe vs 0x00000000), which is the classic shape of a toggle.  The service
logs every request it accepts as "[req:N] <description>", so replaying these
frames and diffing the log tells us both:
  * whether our frame is accepted at all
  * which value means "enable" and which means "disable"

Safety: the operation only flips a network's enabled state, and the two frames
are exact inverses, so replaying both restores the original state.
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
SVC = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

# 抓到的两条 60 字节命令（仅末尾 u32 不同）
FRAME_A = bytes.fromhex(
    "00000004 0100 034a ffffffff"
    "00000004 0100 0300 00000014"
    "0000001c 00001344"
    "00000008 0200 01e1 00000000 026bd639"
    "00000004 0100 0376 fffffffe".replace(" ", ""))

FRAME_B = bytes.fromhex(
    "00000004 0100 034a ffffffff"
    "00000004 0100 0300 00000014"
    "0000001c 00001344"
    "00000008 0200 01e1 00000000 026bd639"
    "00000004 0100 0376 00000000".replace(" ", ""))

assert len(FRAME_A) == 60, len(FRAME_A)
assert len(FRAME_B) == 60, len(FRAME_B)


def read_reqs():
    """返回服务日志里所有 [req: 行。"""
    if not os.path.exists(SVC):
        return []
    raw = open(SVC, "rb").read()
    text = raw.decode("utf-16-le", "ignore")
    return [l.strip() for l in text.splitlines() if "[req:" in l]


def read_tail(n=40):
    raw = open(SVC, "rb").read()
    text = raw.decode("utf-16-le", "ignore")
    return [l.strip() for l in text.splitlines()[-n:]]


def send(body, label):
    print(f"--- 回放 {label}（{len(body)} 字节，末 4 字节 {body[-4:].hex(' ')}）---")
    before = read_reqs()
    before_tail = read_tail(10)

    r = subprocess.run([PY, os.path.join(HERE, "pipe_send.py"), "--frame", body.hex()],
                       capture_output=True, text=True, timeout=30)
    print("  写入结果:", r.stdout.strip())

    time.sleep(2.5)

    after = read_reqs()
    if len(after) > len(before):
        new = after[len(before):]
        print(f"  ★ 服务接受了！新增 {len(new)} 条请求记录：")
        for line in new:
            print("     ", line[:140])
        return True

    print(f"  （服务未记录新请求，[req: 仍为 {len(after)}）")
    tail = read_tail(10)
    if tail != before_tail:
        print("  日志尾部有其它变化：")
        for line in tail[-4:]:
            print("     ", line[:140])
    return False


def main():
    print("=== 回放开关命令 ===\n")
    reqs = read_reqs()
    print(f"当前 [req: 总数 = {len(reqs)}")
    if reqs:
        print("最近 3 条：")
        for l in reqs[-3:]:
            print("   ", l[:120])
    print()

    ok_a = send(FRAME_A, "帧 A（末尾 fffffffe）")
    print()
    ok_b = send(FRAME_B, "帧 B（末尾 00000000）")

    print("\n=== 结论 ===")
    if ok_a or ok_b:
        print("✓ 至少有一条被服务接受 —— 命令格式打通！")
        print("  接下来依据服务日志的描述，即可确定哪个值对应启用、哪个对应禁用。")
        return 0
    print("✗ 两条都未被接受。可能缺少前置会话状态，或该命令需要先注册为 UI 客户端。")
    return 1


sys.exit(main())
