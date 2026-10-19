"""Build candidate command frames from the observed snapshot structure.

Rather than guessing, we replicate the *observable* shape of frames the service
already sends us, then trim them down to the minimum and let the service log
tell us whether a candidate is accepted.

Observed shape of every captured frame body:
    00 00 00 04 01 00 03 01 00 00 00 ... 
    └─────┬─────┘ └──┬──┘ └───┬───┘
      u32 LE:3      type   child count (u16 BE)
"""
import json
import subprocess
import sys

HERE = r"D:\工作区\workspace1\RvpnKit\native"
PY = sys.executable


def send(body_hex, reply=False):
    """Invoke the write proxy and parse its JSON result."""
    cmd = [PY, f"{HERE}\\pipe_send.py", "--frame", body_hex]
    if reply:
        cmd.append("--reply")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    try:
        return json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return {"ok": False, "raw": r.stdout.strip(), "err": r.stderr.strip()}


print("=== 候选命令帧生成与发送 ===\n")

# 观察到的头部形态：u32 LE 长度指示 + 类型 + 子元素数
# 未知字段号，先用 0x0000 占位；重点是让服务能解析出合法结构
CANDIDATES = [
    ("最小容器（0 子元素）",
     "00 00 00 04 01 00 00 00"),
    ("容器 + 1 个空 u32 字段",
     "00 00 00 04 01 00 01 00 04 00 00 00 00 00 00"),
    ("容器 + 1 个 u8 字段",
     "00 00 00 04 01 00 01 00 0b 00 00 00"),
    ("容器 + UpdateVisibleNodes 候选(fid=0x0001)",
     "00 00 00 04 01 00 01 00 04 01 00 01 00 00 00"),
    ("容器 + EnumPublicNetworks 候选(fid=0x0005)",
     "00 00 00 04 01 00 01 00 04 05 00 01 00 00 00"),
    ("空容器（0 长度）",
     "00 00 00 04 01 00"),
]

results = []
for label, hexstr in CANDIDATES:
    hex_clean = hexstr.replace(" ", "")
    body = bytes.fromhex(hex_clean)
    print(f"候选: {label}")
    print(f"  正文 {len(body)} 字节: {hexstr}")

    res = send(hex_clean, reply=False)
    print(f"  结果: {json.dumps(res, ensure_ascii=False)}")
    results.append((label, hexstr, res))
    print()

print("=" * 70)
ok = [r for r in results if r[2].get("ok")]
print(f"\n写入成功 {len(ok)}/{len(results)} 个候选")
print()
print("说明：写入成功只表示字节已送达服务端；是否被解析为有效命令，")
print("      需要检查服务日志是否出现新的 [req:N] 记录。")
print()
print("接下来应观察日志：")
print(r"  C:\ProgramData\Famatech\Radmin VPN\service*.log")
