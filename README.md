# RvpnKit

**Radmin VPN 第三方客户端** —— 高性能、高稳定的增强型控制工具。

> ⚠️ **免责声明**：本项目通过逆向分析实现了与 Radmin VPN 本地服务的互操作。
> 仅供**个人学习与自用**。Famatech 的 EULA 可能禁止此类行为，
> 使用存在**账号被封禁**的风险。请自行评估并承担后果。
> 本项目**不包含**任何破解、绕过授权或侵犯他人隐私的功能 ——
> 所有操作都限于**你自己账号下、你自己加入的网络**。

---

## 特性

| 功能 | 状态 |
|---|---|
| 开关网络电源（虚拟网卡启停） | 规划中 |
| 启用 / 禁用网络 | 协议已解 |
| 加入 / 退出网络 | 协议已解 |
| 查看网络成员及其全部信息 | ✅ 数据源已打通 |
| **查看成员内网 IP**（原版不显示） | ✅ 已解析 |
| 查看成员公网连接 IP | ✅ 已解析 |
| 查看成员连接方式（打洞 / 中继） | ✅ 已解析 |
| 实时成员上下线事件推送 | ✅ 已验证 |
| **快捷加入公共网络** | 协议已解（`CEnumPublicNetworks`） |
| **代理中转**（走本地 Clash 等） | 官方原生支持，已定位配置 |

### 相比原版多出来的东西

- **内网 IP 可见** —— 原版界面不显示节点的局域网地址
- **连接方式可见** —— 能看出某个成员是直连打洞还是走中继
- **脚本化 / 批量操作** —— 命令行驱动，可写脚本自动管理网络
- **实时事件流** —— 不用轮询，成员变动秒级感知

---

## 原理

Radmin VPN 由三个部分组成，**控制面**与**数据面**是分开的：

```
RvRvpnGui.exe  (Qt5, x86, 用户态 UI)
      │  命名管道 \\.\pipe\RadminVpnGuiChannel  (自描述 TLV 记录流)
      ▼
RvControlSvc.exe  (x86, SYSTEM 权限)  ←── 真正干活的实体
      ├── RvROLClient.dll   云端会话 / ENet 可靠 UDP / NAT 打洞 / 中继
      ├── RvNetMP60.sys     虚拟网卡驱动
      └── 虚拟 IP 段 26.0.0.0/8
      ▼
   radminte.com 后端池
      ├── ServerAddress   注册 / 信令服务器
      ├── ProxyServers     中继节点（流量中转）
      └── fail / upload 域
```

**核心设计决策：复用官方服务作为底层，本项目只做增强控制层。**

理由：

1. `RvControlSvc` 已经以 SYSTEM 权限持有**完成认证、注册、NAT 打洞**的云会话
2. 自己重写 ENet 可靠传输 + 打洞 + 加密体系是**数月工作量**，且必然不如原版稳定
3. 管道是**多客户端**的 —— 我们挂上去不影响官方 GUI 正常工作
4. 连接后服务会**主动推送完整状态快照**，之后是增量事件流，天然适合做实时监控

---

## 协议摘要

完整逆向笔记见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)。

### 帧边界
```
[frame_len : u32 LE][记录流…]
```

### 记录结构（字段号均为**大端**）

| 类型 | 结构 |
|---|---|
| `0x04` | `04 \| fid:u16 BE \| value:u32 LE` |
| `0x08` | `08 \| fid:u16 BE \| value:u64 LE` |
| `0x0B` | `0b \| fid:u16 BE \| value:u8` |
| `0x0C` | `0c \| fid:u16 BE \| value:u16 LE` |
| `0x03` | `03 \| fid:u16 BE \| len:u16 BE \| UTF-16LE(len 字节，以 U+0000 起头)` |
| `0x09`/`0x0D`/`0x10` | `.. \| fid:u16 BE \| 16 字节块（IPv4 或 GUID）` |

字符串记录的关键不变量：**`len == 2 × (字符数 + 1)`**，已用 5 组真实样本交叉验证。

### 已确认字段

| field id | 类型 | 语义 |
|---|---|---|
| `0x01c9` | str | 节点连接 IP |
| `0x01e1` | u64 | 节点 ID |
| `0x01e9` | str | 节点别名 / 主机名 |
| `0x01ed` | str | 客户端版本号 |
| `0x0304` | str | 网络名 |
| `0x0105` | blob16 | 节点虚拟 IP |
| `0x05d` `0x5e` `0x5f` | u32 | 超时 15000 / 60000 / 300000 ms |
| `0x0d6` | u32 | 帧序号（逐帧递增） |

---

## 项目结构

```
RvpnKit/
├── docs/
│   └── PROTOCOL.md          协议逆向笔记（含验证记录）
├── src/
│   ├── RvpnKit.Protocol/    线格式编解码（.NET 10）
│   │   ├── RvpnWire.cs      已验证的记录解析器
│   │   ├── RvpnCodec.cs     编解码原语
│   │   └── AdaptiveDecoder.cs / AnchorExtractor.cs / ContentHarvester.cs
│   │                        （定标过程中保留的探索性实现）
│   └── RvpnKit.Cli/         命令行工具
│       └── Program.cs       verify / decode / detect / extract 等子命令
└── native/
    ├── rvpipe_hook.c        管道 IAT hook（用于抓真实命令格式）
    ├── probe.c / tiny.c     注入可行性探针
    ├── inject.py            DLL 注入器
    └── diag_inject.py       注入机制诊断
```

---

## 构建

### 前置

- **.NET 10 SDK**（本仓库用 `10.0.402` 验证）
- 可选：**Zig**（只在需要重新编译 `native/` 下的 C 代码时需要）

### 编译

```powershell
dotnet build src/RvpnKit.Cli/RvpnKit.Cli.csproj -c Release
```

### 用法

```powershell
# 回放抓包，验证协议解码器（需要一份管道抓包）
rvpn verify <capture.bin>

# 用已验证的线格式解析抓包，输出同步率与字段语义
rvpn decode <capture.bin>

# 在真实抓包上给线格式假设打分，自动定标
rvpn detect <capture.bin>

# 锚点 + 内容驱动的字段抽取
rvpn extract <capture.bin>
rvpn harvest <capture.bin>
```

> `recon/` 与 `captures/` 目录**已被 .gitignore 排除** ——
> 管道抓包含有你网络里真实成员的 IP、主机名等信息，绝不应提交到仓库。

### 编译注入器（可选）

```powershell
zig cc -target x86-windows-gnu -shared -O2 -o native/rvpipe_hook32.dll native/rvpipe_hook.c
```

---

## 开发状态

| 阶段 | 状态 |
|---|---|
| 1. 架构与协议逆向 | ✅ 完成（线格式已验证） |
| 2. 客户端接入管道 | ✅ 已验证可连接、可收状态流 |
| 3. 命令格式对齐 | 🔄 进行中（靠 hook 抓服务端真实命令） |
| 4. 功能实现 | ⏳ 待开始 |
| 5. 代理中转 | ⏳ 待开始 |

### 已知难点

- **命令的写路径**：服务端**回包**已能稳定解析；**发命令**需要精确的请求编码，
  正在通过 hook 官方 GUI 抓取其真实请求来对齐。
- **容器层语义**：字符串和标量记录已完全对齐；嵌套容器仍有部分类型未定标
  （当前同步率约 44%，业务数据已可完整取出）。

---

## 合规与隐私

- 本工具**只读取你自己的账号与你已加入的网络**中的数据
- **不采集、不上传**任何信息到第三方
- 抓包文件被 `.gitignore` 排除，不会进入版本库
- 再次强调：**遵守 Famatech 服务条款是你的责任**

## 许可

仅限个人学习使用。
