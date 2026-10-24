"""用创建请求反推「密码 / 网络类型」的编码。

已知：
  * 免密码网络的创建帧是  容器[u32(0x08)=0, str(0x06)=名字, type08(0x0d)=28字节]
  * 快照里网络容器有 field 0x0a：免密码=1，deepseektester（带密码）=2

于是逐个假设去创建，创建完直接 dump 快照看 0x0a 是否变成 2：
  * 若变成 2，说明该组合真的生成了带密码网络 —— 这就解出来了
  * 测完立刻删掉，不留垃圾

用法：python probe_create.py <阶段>
  A  改 0x08 的取值（0/1/2/3），不带密码
  B  0x08=1 或 2，密码放候选字段
"""

import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, r"D:\工作区\workspace1\RvpnKit\native")
import rvpncmd as R  # noqa: E402
from probe_commands import send  # noqa: E402

RVPNKIT = r"C:\rtools\rvpn-target\release\rvpnkit.exe"
DUMP = r"C:\rtools\probe_snap.bin"
TAG = "rvpnkit-probe"


# ── 解析快照（只取网络名 + field 0x0a）
def decode_str(payload):
    body = payload
    if len(body) >= 2 and body[-2:] == b"\x00\x01":
        body = body[:-2]
    if not body or len(body) % 2:
        return None
    try:
        s = body.decode("utf-16-be")
    except UnicodeDecodeError:
        return None
    return s if s and all(ord(c) >= 0x20 for c in s) else None


def parse(data):
    out, off = [], 0
    while off + 8 <= len(data):
        size = struct.unpack_from(">I", data, off)[0]
        ty, tag, field = data[off + 4], data[off + 6], data[off + 7]
        if size > len(data) - off - 8:
            break
        payload = data[off + 8:off + 8 + size]
        kids = parse(payload) if (ty == 0 and tag == 0x13) else None
        out.append((field, ty, payload, kids))
        off += 8 + size
    return out


def split_frames(stream):
    frames, off = [], 0
    while off + 4 <= len(stream):
        n = struct.unpack_from("<I", stream, off)[0]
        if n == 0 or n > len(stream) - off - 4:
            break
        frames.append(stream[off + 4:off + 4 + n])
        off += 4 + n
    return frames


def networks():
    """返回 [(名字, guid_hex, field0x0a)]"""
    raw = open(DUMP, "rb").read()
    frames = split_frames(raw) or [raw]
    found = []

    def walk(recs):
        for field, ty, payload, kids in recs:
            if kids:
                if field == 0x23:
                    name = None
                    guid = None
                    typ = None
                    for f2, t2, p2, k2 in kids:
                        if k2 is None:
                            if f2 == 0x06 and t2 == 3:
                                name = decode_str(p2)
                            elif f2 == 0x09 and t2 == 0x0D:
                                guid = p2.hex()
                            elif f2 == 0x0A and t2 in (0x01, 0x0B) and len(p2) >= 4:
                                typ = struct.unpack_from(">I", p2)[0]
                    if name:
                        found.append((name, guid, typ))
                walk(kids)

    for f in frames:
        walk(parse(f))
    return found


def dump():
    subprocess.run([RVPNKIT, "--dump", DUMP], capture_output=True, timeout=30)


def build_create(name, flag, pw_field=None, password=None):
    inner = R.rec_u32(flag, 0x08)
    inner += R.rec_str(name, 0x06)
    if pw_field is not None and password is not None:
        inner += R.rec_str(password, pw_field)
    key = bytes(range(28))
    inner += struct.pack(">I", len(key)) + bytes([0x08, 0x00, 0x03, 0x0D]) + key

    return (
        R.head(R.new_req_id(), 0x02)
        + struct.pack(">I", len(inner))
        + struct.pack(">I", 0x0000132B)
        + inner
    )


def delete(guid_hex):
    try:
        g = bytes.fromhex(guid_hex)
    except (TypeError, ValueError):
        return
    frame = R.head(R.new_req_id(), 0x0F) + R.rec_guid(g, 0x09)
    try:
        send(frame)
    except Exception as e:
        print(f"      删除失败: {e}")


def one_case(label, flag, pw_field=None, password=None):
    name = f"{TAG}-{int(time.time()*1000) % 1000000}"
    print(f"\n[{label}] 创建 {name} …")
    try:
        send(build_create(name, flag, pw_field, password))
    except Exception as e:
        print(f"    发送失败: {e}")
        return None
    time.sleep(1.6)
    dump()
    nets = networks()
    hit = next((n for n in nets if n[0] == name), None)
    if hit is None:
        print("    创建后快照里没有该网络（可能被拒绝）")
        return None
    _, guid, typ = hit
    print(f"    创建成功，field 0x0a = {typ}")
    delete(guid)
    time.sleep(0.6)
    return typ


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "A"
    results = []

    if phase == "A":
        for flag in (0, 1, 2, 3):
            t = one_case(f"flag={flag}", flag)
            results.append((f"flag={flag}", t))
    elif phase == "B":
        # 0x08=1 或 2，密码依次放到几个候选字段
        for flag in (1, 2):
            for pf in (0x07, 0x08, 0x0A, 0x0B, 0x0E, 0x05, 0x47):
                t = one_case(f"flag={flag} pw@0x{pf:02x}", flag, pf, "deepseektester")
                results.append((f"flag={flag} pw@0x{pf:02x}", t))
                time.sleep(0.4)

    print("\n=== 汇总 ===")
    for label, typ in results:
        mark = "  ★ 带密码!" if typ == 2 else ""
        print(f"  {label:<24} 0x0a={typ}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
