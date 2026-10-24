#!/usr/bin/env python3
"""rvpncmd —— 向 Radmin VPN 控制服务下发命令（逆向自官方 GUI 的真实报文）。

字符串编码：UTF-16 **大端**，后面固定跟 2 字节 `00 01`
-----------------------------------------------------
这条最初判错了。别名「快乐狐狸1」的记录是
    5f eb 4e 50 72 d0 72 f8 00 31 00 01
而 5f eb 正是 U+5FEB「快」的大端编码。之前按 UTF-16LE 处理之所以
还能成功，是因为网络名恰好几乎全是 ASCII：ASCII 在 LE 下是 <char>00，
前面补一个 00 就和 BE 的 00<char> 逐字节重合了。名字含非 ASCII 或长度为
奇数时两种写法就会分叉，所以这里统一按 BE。

命令表（命令码 = 第二条记录里的 u32）
-----------------------------------
  0x02 (2)   创建 / 离开网络（容器 0x2b，含 28 字节随机块，语义待定）
  0x03 (3)   加入网络（容器 0x1b，只有网络名）
  0x08 (8)   离开网络（按 GUID，后面跟一个 u32=0 字段 0x16）
  0x0f (15)  删除网络（按 GUID）
  0x12 (18)  改别名
  0x13 (19)  枚举公共网络（字段 0x06 是过滤前缀，空串=全部）

记录格式
--------
    [size:u32 BE][类型码:u8][0x00][0x03][字段:u8][payload]

用法
----
    python rvpncmd.py join "网络名"
    python rvpncmd.py leave <guid-hex>        # 16 字节 GUID
    python rvpncmd.py delete <guid-hex>
    python rvpncmd.py alias "新别名"
    python rvpncmd.py enum                    # 枚举公共网络
    python rvpncmd.py send <hex>              # 发送任意帧正文
    python rvpncmd.py build "网络名"           # 只打印不发送
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys
import time

PIPE = r"\\.\pipe\RadminVpnGuiChannel"
SVC = r"C:\ProgramData\Famatech\Radmin VPN\service.log"

CMD_CREATE = 0x02
CMD_JOIN = 0x03
CMD_SWITCH_POWER = 0x04
CMD_LEAVE = 0x05
CMD_KICK = 0x06
CMD_SET_ENABLED = 0x08
CMD_APPROVE_JOIN = 0x0A
CMD_DELETE = 0x0F
CMD_GRANT_ADMIN = 0x10
CMD_REVOKE_ADMIN = 0x11
CMD_ALIAS = 0x12
CMD_ENUM = 0x13

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                          ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [ctypes.c_void_p]

INVALID = ctypes.c_void_p(-1).value
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3


# ---------------------------------------------------------------- 基础构件

def rec(size: int, type_code: int, field: int) -> bytes:
    return struct.pack(">I", size) + bytes([type_code, 0x00, 0x03, field])


def str_be(text: str) -> bytes:
    """字符串载荷：UTF-16BE + 00 01。"""
    return text.encode("utf-16-be") + b"\x00\x01"


def rec_str(text: str, field: int) -> bytes:
    payload = str_be(text)
    return rec(len(payload), 0x03, field) + payload


def rec_u32(value: int, field: int, type_code: int = 0x0B) -> bytes:
    return rec(4, type_code, field) + struct.pack(">I", value)


def rec_guid(guid: bytes, field: int = 0x09) -> bytes:
    assert len(guid) == 16, f"GUID 必须 16 字节，实际 {len(guid)}"
    return rec(16, 0x0D, field) + guid


def head(req_id: int, command: int) -> bytes:
    return (rec(4, 0x01, 0x4A) + struct.pack(">I", req_id)
            + rec(4, 0x01, 0x00) + struct.pack(">I", command))


# ---------------------------------------------------------------- 各命令

def build_join(name: str, req_id: int) -> bytes:
    """加入网络：容器 0x1b = u32(1) + 网络名。"""
    inner = rec_u32(1, 0x3F) + rec_str(name, 0x06)
    return (head(req_id, CMD_JOIN) + struct.pack(">I", len(inner))
            + struct.pack(">I", 0x0000131B) + inner)


def build_alias(name: str, req_id: int) -> bytes:
    """改别名：命令码 0x12，单条字符串记录（字段 0x04）。"""
    return head(req_id, CMD_ALIAS) + rec_str(name, 0x04)


def build_delete(guid: bytes, req_id: int) -> bytes:
    """删除网络：命令码 0x0f，单条 16 字节 GUID 记录。"""
    return head(req_id, CMD_DELETE) + rec_guid(guid)


def build_enum(prefix: str, req_id: int) -> bytes:
    """枚举公共网络：命令码 0x13，字段 0x06 是过滤前缀（空串=全部）。"""
    return head(req_id, CMD_ENUM) + rec_str(prefix, 0x06)


def rec_node(node_id: int) -> bytes:
    """节点 ID 记录。

    注意这条的头是 `02 00 01 e1`，不是通用的 `01 00 03 xx`：
        00 00 00 08 02 00 01 e1 <u64 节点ID>
    """
    return (struct.pack(">I", 8) + bytes([0x02, 0x00, 0x01, 0xE1])
            + struct.pack(">Q", node_id))


def build_member_op(code: int, guid: bytes, node_id: int, name: str,
                    req_id: int) -> bytes:
    """成员类操作：踢人 / 批准加入 / 授予管理员 / 撤销管理员。

    这四条用同一种载荷形状（GUID + 节点 ID + 网络名），是从命令码扫描里
    确定的：服务日志分别写出
        Requested to remove <node> from network '<unknown>'
        Requested to approve join <node> into '<unknown>'
        Requested to grant admin to <node> in network '<unknown>'
        Requested to revoke admin from <node> in network '<unknown>'
    """
    return (head(req_id, code) + rec_guid(guid) + rec_node(node_id)
            + rec_str(name, 0x06))


def build_power(on: bool, req_id: int) -> bytes:
    """VPN 总开关（CSwitchPower）：命令码 0x04，字段 0x11，1=开 0=关。

    这条是通过「按码分组 + 逐字段二分」扫出来的：码 0x04 下的
    字段 0x11、类型 0x0b 一触发，服务日志立刻出现
        Switched Off → Disconnected from server(code:4)
        Switched On  → Connected to server (15)
    """
    return head(req_id, CMD_SWITCH_POWER) + rec_u32(1 if on else 0, 0x11)


def build_set_enabled(guid: bytes, enabled: bool, req_id: int) -> bytes:
    """启用 / 禁用网络：命令码 0x08，GUID + 字段 0x16（0=禁用 1=启用）。

    这条是从服务日志确认的：
        13:13:35 Disabled network '91919191免费'  ← 帧里 0x16 的值是 0
        13:13:36 Enabled  network '91919191免费'  ← 帧里 0x16 的值是 1
    两条帧的 GUID 完全相同，只有末尾 u32 不同。
    """
    return head(req_id, CMD_SET_ENABLED) + rec_guid(guid) + rec_u32(1 if enabled else 0, 0x16)


def build_create(name: str, req_id: int, key: bytes | None = None) -> bytes:
    """创建网络：命令码 0x02，容器 0x2b = u32(0) + 名字 + 28 字节网络密钥。

    28 字节块由客户端随机生成：同名网络两次创建（reqId 41/44），块内容完全
    不同，所以它不是名字的哈希。这里默认用 os.urandom(28) 生成。
    """
    if key is None:
        key = os.urandom(28)
    assert len(key) == 28, f"网络密钥必须 28 字节，实际 {len(key)}"
    inner = (rec_u32(0, 0x08) + rec_str(name, 0x06)
             + rec(len(key), 0x08, 0x0D) + key)
    return (head(req_id, CMD_CREATE) + struct.pack(">I", len(inner))
            + struct.pack(">I", 0x0000132B) + inner)


# ---------------------------------------------------------------- 管道

def open_pipe():
    for _ in range(6):
        h = k32.CreateFileW(PIPE, GENERIC_READ | GENERIC_WRITE, 0, None,
                            OPEN_EXISTING, 0, None)
        if h not in (INVALID, None):
            return h, 0
        err = ctypes.get_last_error()
        if err != 231:
            return None, err
        time.sleep(0.4)
    return None, 231


def write_frame(h, body: bytes) -> int:
    buf = struct.pack("<I", len(body)) + body
    arr = ctypes.create_string_buffer(buf, len(buf))
    n = wt.DWORD(0)
    if not k32.WriteFile(h, arr, len(buf), ctypes.byref(n), None):
        raise OSError(ctypes.get_last_error(), "WriteFile 失败")
    return n.value


def svc_reqs():
    if not os.path.exists(SVC):
        return {}
    raw = open(SVC, "rb").read()
    out = {}
    for line in raw.decode("utf-16-le", "ignore").splitlines():
        m = re.search(r"\[req:(\d+)\]\s*(.+)$", line)
        if m:
            rid, desc = int(m.group(1)), m.group(2).strip()
            if out.get(rid) in (None, "Succeeded") and desc != "Succeeded":
                out[rid] = desc
            out.setdefault(rid, desc)
    return out


def dispatch(body: bytes, req_id: int, label: str, wait: float = 6.0,
             watch: str | None = None) -> int:
    print(f"命令     : {label}")
    print(f"请求编号 : {req_id} (0x{req_id:x})")
    print(f"帧长度   : {len(body)} 字节（正文）")

    h, err = open_pipe()
    if not h:
        print(f"✗ 打开管道失败 err={err}")
        return 1
    try:
        print(f"✓ 已写入 {write_frame(h, body)} 字节")
    except OSError as e:
        print(f"✗ 写入失败: {e}")
        return 2
    finally:
        k32.CloseHandle(h)

    print("等待服务处理…")
    deadline = time.time() + wait
    shown = set()
    accepted = False
    succeeded = False
    watched = False

    while time.time() < deadline:
        time.sleep(0.3)
        if not os.path.exists(SVC):
            continue
        raw = open(SVC, "rb").read()
        for line in raw.decode("utf-16-le", "ignore").splitlines():
            if f"[req:{req_id}]" in line:
                desc = line.split(f"[req:{req_id}]", 1)[1].strip()
                if desc in shown:
                    continue
                shown.add(desc)
                print(f"  服务端: {desc[:110]}")
                if desc == "Succeeded":
                    succeeded = True
                else:
                    accepted = True
            elif watch and watch in line and line not in shown:
                shown.add(line)
                print(f"  服务端: {line.strip()[-60:]}")
                watched = True
        if succeeded or (watch and watched):
            break

    if succeeded:
        print("\n★ 成功（服务返回 Succeeded）")
        return 0
    if watched:
        print("\n★ 成功（状态已切换）")
        return 0
    if accepted:
        print("\n★ 已受理（该命令本就不回 Succeeded，服务已记录请求）")
        return 0
    print("⚠ 服务日志里没看到该请求，命令可能被丢弃")
    return 4


def new_req_id() -> int:
    return int.from_bytes(os.urandom(2), "big")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    a = argv[1]

    if a == "join" and len(argv) > 2:
        rid = new_req_id()
        return dispatch(build_join(argv[2], rid), rid, f"加入网络 '{argv[2]}'")

    if a in ("enable", "disable", "delete") and len(argv) > 2:
        try:
            guid = bytes.fromhex(re.sub(r"[\s\-]", "", argv[2]))
        except ValueError:
            print("GUID 需要是十六进制")
            return 2
        rid = new_req_id()
        if a == "delete":
            body, label = build_delete(guid, rid), f"删除网络 GUID={guid.hex()}"
        else:
            body = build_set_enabled(guid, a == "enable", rid)
            label = f"{'启用' if a == 'enable' else '禁用'}网络 GUID={guid.hex()}"
        return dispatch(body, rid, label)

    if a in ("power", "on", "off"):
        on = a != "off"
        if a == "power":
            if len(argv) < 3:
                print("用法: rvpncmd.py power on|off")
                return 2
            on = argv[2].lower() in ("on", "1", "true", "yes")
        rid = new_req_id()
        return dispatch(build_power(on, rid), rid,
                        f"VPN 总开关 -> {'开启' if on else '关闭'}", wait=8,
                        watch="Switched")

    if a == "create" and len(argv) > 2:
        rid = new_req_id()
        body = build_create(argv[2], rid)
        return dispatch(body, rid, f"创建网络 '{argv[2]}'")

    if a in ("kick", "approve", "grant", "revoke") and len(argv) > 3:
        # 用法：kick <网络GUID> <节点ID> [网络名]
        try:
            guid = bytes.fromhex(re.sub(r"[\s\-]", "", argv[2]))
        except ValueError:
            print("GUID 需要是十六进制")
            return 2
        try:
            node = int(argv[3], 0)
        except ValueError:
            print("节点 ID 需要是十进制或 0x 十六进制")
            return 2
        name = argv[4] if len(argv) > 4 else ""
        table = {
            "kick": (CMD_KICK, "踢出成员"),
            "approve": (CMD_APPROVE_JOIN, "批准加入"),
            "grant": (CMD_GRANT_ADMIN, "授予管理员"),
            "revoke": (CMD_REVOKE_ADMIN, "撤销管理员"),
        }
        code, label = table[a]
        rid = new_req_id()
        body = build_member_op(code, guid, node, name, rid)
        return dispatch(body, rid, f"{label} 节点={node} 网络={guid.hex()}")

    if a == "leave" and len(argv) > 2:
        try:
            guid = bytes.fromhex(re.sub(r"[\s\-]", "", argv[2]))
        except ValueError:
            print("GUID 需要是十六进制")
            return 2
        rid = new_req_id()
        return dispatch(head(rid, CMD_LEAVE) + rec_guid(guid), rid,
                        f"离开网络 GUID={guid.hex()}")

    if a == "alias" and len(argv) > 2:
        rid = new_req_id()
        return dispatch(build_alias(argv[2], rid), rid, f"改别名 -> '{argv[2]}'")

    if a == "enum":
        rid = new_req_id()
        prefix = argv[2] if len(argv) > 2 else ""
        return dispatch(build_enum(prefix, rid), rid,
                        f"枚举公共网络（前缀 '{prefix}'）", wait=4)

    if a == "send" and len(argv) > 2:
        body = bytes.fromhex(re.sub(r"[\s,]", "", argv[2]))
        rid = int.from_bytes(body[8:12], "big") if len(body) >= 12 else 0
        return dispatch(body, rid, "自定义帧")

    if a == "build" and len(argv) > 2:
        body = build_join(argv[2], 0x17)
        print(f"长度 {len(body)} 字节：")
        for i in range(0, len(body), 16):
            print(f"  {i:04x}  " + " ".join(f"{b:02x}" for b in body[i:i + 16]))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
