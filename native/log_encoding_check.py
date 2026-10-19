"""Check the service log's encoding and whether any "[req:" lines exist.

This decides whether the log can serve as an oracle for command testing: if the
service writes request records, we can use them to tell accepted candidates from
rejected ones.  If it stays silent, blind format guessing is not viable.
"""
import os

LOG = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

if not os.path.isfile(LOG):
    print("日志不存在:", LOG)
    raise SystemExit(1)

raw = open(LOG, "rb").read()
print(f"文件: {LOG}")
print(f"大小: {len(raw):,} 字节")
print(f"前 64 字节 hex: {raw[:64].hex(' ')}")
print()

# 判断编码
looks_utf16 = raw[1:2] == b"\x00" and raw[3:4] == b"\x00"
print(f"疑似 UTF-16LE: {looks_utf16}")
print()

for enc in ("utf-8", "utf-16-le", "utf-16"):
    try:
        text = raw.decode(enc, "ignore")
    except Exception as exc:  # noqa: BLE001
        print(f"{enc:10} 解码异常: {exc}")
        continue

    req_lines = [l for l in text.splitlines() if "[req:" in l]
    connected = [l for l in text.splitlines() if "Connected to" in l]
    print(f"{enc:10} 行数={len(text.splitlines()):>8,}  "
          f"[req: 行={len(req_lines):>6}  Connected to 行={len(connected):>6}")

    if req_lines:
        print(f"  → 日志可作为命令测试的判据！最近 3 条：")
        for l in req_lines[-3:]:
            print("      ", l.strip()[:110])

    # 只对能正确解码的编码显示样例
    if connected and len(text.splitlines()) > 100:
        print("  样例（最后 3 行）:")
        for l in text.splitlines()[-3:]:
            print("      ", l.strip()[:110])
    print()

print("判读：")
print("  若 [req: 行数 > 0  → 服务会记录请求，可作为命令格式的判据")
print("  若 [req: 行数 = 0  → 服务不记录普通请求，盲猜格式不可行")
