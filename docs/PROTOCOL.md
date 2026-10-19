# Radmin VPN 控制管道协议 —— 逆向笔记（已验证）

> 目标：`\\.\pipe\RadminVpnGuiChannel`（`RvControlSvc.exe` 以 SYSTEM 权限创建）
> 客户端角色：`RvRvpnGui.exe` 通过 `TransactNamedPipe` 收发
> **服务允许多客户端并发连接，且连接后会主动推送完整状态快照**

状态：线格式**已用 5 组真实样本交叉验证**；容器头与部分类型语义仍在收敛中。

---

## 1. 系统架构（已确认）

```
RvRvpnGui.exe (Qt5, x86, 用户态 UI)
      │  命名管道：TLV 记录流
      ▼
RvControlSvc.exe (x86, SYSTEM)  ←── 真正的客户端主体
      ├── RvROLClient.dll      云端会话 / ENet 可靠 UDP / NAT 打洞 / 中继
      ├── RvNetMP60.sys        虚拟网卡（Famatech Radmin VPN Ethernet Adapter）
      └── 配置虚拟 IP 26.x.x.x
      ▼
   radminte.com 后端池
      ├── ServerAddress  198.244.203.247     注册/信令
      ├── ProxyServers   23 个中继节点        流量中继
      └── fail.radminte.com / upload.radminte.com
```

传输：**ENet**（UDP 可靠传输）→ 直连打洞；失败回退 **TcpRelay**。

---

## 2. 线格式（经真实数据验证）

### 2.1 帧边界
```
[frame_len : u32 LE][记录流…]
```

### 2.2 记录结构 —— **字段号一律大端（BE）**，类型 1 字节

| 类型 | 结构 | 说明 |
|---|---|---|
| `0x04` | `04 \| fid:u16 BE \| value:u32 LE` | 无符号 32 位 |
| `0x08` | `08 \| fid:u16 BE \| value:u64 LE` | 无符号 64 位 |
| `0x0B` | `0b \| fid:u16 BE \| value:u8` | 无符号 8 位 |
| `0x0C` | `0c \| fid:u16 BE \| value:u16 LE` | 无符号 16 位 |
| `0x03` | `03 \| fid:u16 BE \| len:u16 BE \| payload` | UTF-16LE 字符串 |
| `0x09`/`0x0D`/`0x10` | `.. \| fid:u16 BE \| 16 字节` | GUID / 地址块 |
| `0x02` | `02 \| fid:u16 BE \| f32 LE` | 单精度浮点 |

### 2.3 字符串记录（关键，已严格验证）

```
03 | fid:2 BE | len:2 BE | 正文(len 字节)
```

- `len` = **正文字节数**
- 正文**固定以 U+0000 起头**（前导空字符），因此 `len == 2 × (字符数 + 1)`

**交叉验证记录：**

| 字符串 | fid | 头部字节 | len | 校验 |
|---|---|---|---|---|
| `FORSAKEN` | `0x0400` | `03 04 00 00 12` | 18 | (1+8)×2 ✓ |
| `DESKTOP-41MCISL` | `0x0400` | `03 04 00 00 20` | 32 | (1+15)×2 ✓ |
| `198.244.203.247` | `0x01c9` | `03 01 c9 00 20` | 32 | (1+15)×2 ✓ |
| `148.113.190.78` | `0x01c9` | `03 01 c9 00 1e` | 30 | (1+14)×2 ✓ |
| `2.1.1` | `0x01ed` | `03 01 ed 00 0c` | 12 | (1+5)×2 ✓ |

> 曾被误读为「标记 `04 01 00 03`」的字节序列，实为相邻记录字段号的大端编码
> （如 `… 00 04 | 01 00 …` 中 `0x0400` 恰好跨过 4 字节边界）。

### 2.4 16 字节块
- 前 12 字节为 0 → 末 4 字节是 **IPv4**
  例：`03 05 fd fd 00…00 1a a9 3d b2` → `26.169.61.178`
- 否则多为 **GUID**

---

## 3. 已确认的字段号

| field id | 类型 | 语义 | 证据 |
|---|---|---|---|
| `0x01c9` | str | **节点连接 IP** | `198.244.203.247`、`148.113.190.78` |
| `0x01e1` | u64 | **节点 ID** | `0x0C2BF171`、`0x1008BACD` |
| `0x01e9` | str | **节点别名 / 主机名** | `:::57162 -> 2408:820c:…` |
| `0x01ed` | str | **版本号** | `2.1.1`、`2.0.9` |
| `0x0304` | str | **网络名** | `FORSAKEN`、`DESKTOP-41MCISL` |
| `0x0105` | blob16 | **节点虚拟 IP** | `26.169.61.178` |
| `0x05d` `0x5e` `0x5f` | u32 | 超时 15000 / 60000 / 300000 ms | 首帧配置表 |
| `0x073` `0x074` `0x075` | u32 | 10000 / 30000 / 30000 ms | 首帧配置表 |
| `0x095` `0x09b` | u32 | 4000 / 3999 ms | 首帧配置表 |
| `0x0ad` `0x0ae` | u32 | 阈值对 (1000,1) (3000,3) (5000,4) … | 首帧配置表 |
| `0x0d6` | u32 | **帧序号**（逐帧递增） | `0xa85c`→`a85d`→… |
| `0x0d7` | u32 | 100 | 首帧 |

---

## 4. 帧的构造（实测）

| 帧 | 长度 | 内容 |
|---|---|---|
| #1 | 112 | 握手 / 能力协商 |
| #2 | 384 | **配置参数表**（全部超时与阈值） |
| #3 | ~206 KB | **完整状态快照**：全部网络 + 全部节点 |
| #4+ | 52~56 | **增量事件**（`0x0d6` 序号递增）→ 实时推送 |

> 连接后即收到全量快照，之后是增量事件流 —— 意味着**无需轮询**即可实时监控。

---

## 5. 服务端命令与事件（来自二进制符号表）

### 5.1 GUI → 服务（命令）
```
CApproveJoin        CChatGetNodes      CCreateNetwork     CDeleteNetwork
CEnableNetwork      CEnumPublicNetworks                  CJoinNetwork
CKickNode           CLeaveNetwork      CManageNetwork     CUpdateNetwork
CUpdateVisibleNodes GetNodeRegionSupport
IManageNetwork
```

### 5.2 服务 → GUI（事件推送）
```
CNetworksChanged    CNodeConnectedIn   CNodeConnectedOut  CNodeDisconnected
CNodeConnectFailed  CNodeNetworks      CNodeProductVersion
CNodeRegionSupport  CPublicNetworks    CServerSettings
CFailServerList     CProxyServerList   CLocalRServerPort  CRemoteRServerPort
CChatNodes          CJoinFinished      CInstallRadminShim
CTaskCompleted_{Register,CreateNetwork,DeleteNetwork,EnableNetwork,
                JoinNetwork,LeaveNetwork,KickNode,ApproveJoin,
                UpdateNetwork,AbstractManageNetwork}
```

---

## 6. 官方内置的代理能力

- 注册表 `ProxyServers` = 23 个中继候选；`ServerAddress` = 当前信令服务器
- 服务会通过 `CServerSettings` / `CProxyServerList` 下发服务器与中继列表
- 二进制含 `ProxyLogin` / `ProxyPassword` / `ProxyServers` / `ServerAddress`
  → **服务侧原生支持代理认证**

## 7. 传输层与本地信息

- 虚拟网卡：`Radmin VPN`（`Famatech Radmin VPN Ethernet Adapter`），ifIndex 可查
- 驱动：`RvNetMP60.sys`
- 本机虚拟 IP `26.169.61.178/8`，IPv6 `fdfd::1aa9:3db2/64`
- 节点 ID `204206449`，别名 `快乐狐狸`
- 连接方式枚举：`Connections Relay`、`Connections TCP/nat`、
  `Connections UDP/nat`、`Connections UDP/nat/random`、`TcpRelay`
- 服务日志：`C:\ProgramData\Famatech\Radmin VPN\service*.log`
  （含每个节点的 `Connected to <id>/'<alias>' via <方式>` 实时记录）

## 8. 本地地址库（用于识别/限速）

| 网段 | 位置 |
|---|---|
| Radmin VPN 适配器 | `Session.Initialize` |
| 以太网 | `Function` |
