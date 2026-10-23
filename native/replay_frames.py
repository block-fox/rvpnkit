"""Replay captured OUT frames to the service to confirm the envelope works.

We now have real command frames captured from the GUI.  Step one is proving we
can send a byte-identical frame ourselves and have the service accept it — the
service logs "[req:N] Succeeded" for every request it parses, so a new [req:
line is definitive proof.

If replay works, the remaining task is purely to work out which field selects
the command, which can then be done by mutating one field at a time.
"""
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "rvpipe_hook.log")
SVC = r"C:\ProgramData\Famatech\Radmin VPN\service.log"
PY = sys.executable


def parse_out_frames(path):
    """从 hook 日志里提取所有 OUT 帧的字节。"""
    if not os.path.exists(path):
        raise SystemExit(f"日志不存在: {path}")

    text = open(path, encoding="utf-8", errors="ignore").read()
    frames = []
    # 每个 OUT 段：=== OUT (xxx) len=N ===\nHEX:\n<hh hh ...>
    for m in re.finditer(r"=== OUT \([^)]*\) len=(\d+) ===\s*\nHEX:\n(.*?)\nASCII:",
                         text, re.S):
        declared = int(m.group(1))
        hexbody = m.group(2)
        try:
            data = bytes.fromhex(hexbody.replace("\n", " ").replace(" ", ""))
        except ValueError:
            continue
        if len(data) == declared and declared > 0:
            frames.append(data)
    return frames


def service_req_count():
    """统计服务日志里 [req: 的行数（日志为 UTF-16LE）。"""
    if not os.path.exists(SVC):
        return -1
    raw = open(SVC, "rb").read()
    text = raw.decode("utf-16-le", "ignore")
    return text.count("[req:")


def send(body):
    r = subprocess.run([PY, os.path.join(HERE, "pipe_send.py"), "--frame", body.hex()],
                       capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def main():
    frames = parse_out_frames(LOG)
    print(f"从 hook 日志解析出 {len(frames)} 个 OUT 帧\n")

    if not frames:
        raise SystemExit("没有可回放的帧")

    for i, f in enumerate(frames):
        print(f"  帧 {i}: {len(f)} 字节  {f[:40].hex(' ')}{' …' if len(f) > 40 else ''}")

    # 长度前缀与正文配对：GUI 是先写 4 字节长度，再写正文
    bodies = [f for f in frames if len(f) > 4]

    before = service_req_count()
    print(f"\n回放前 [req: 计数 = {before}\n")

    for i, body in enumerate(bodies):
        print(f"--- 回放帧 {i}（{len(body)} 字节）---")
        print("   结果:", send(body))
        time.sleep(1.5)

        after = service_req_count()
        if after > before:
            print(f"   ★ 服务已记录新请求！([req: {before} → {after})")
            # 打印最新的 req 行
            raw = open(SVC, "rb").read().decode("utf-16-le", "ignore")
            lines = [l for l in raw.splitlines() if "[req:" in l]
            for l in lines[-3:]:
                print("     ", l.strip()[:110])
            print("\n结论：帧信封格式正确，可以开始逐字段试验。")
            return 0
        print(f"   （服务未记录，[req: 仍为 {after}）")

    print("\n结论：帧未被接受 —— 可能需要额外的会话前置状态。")
    return 1


sys.exit(main())
