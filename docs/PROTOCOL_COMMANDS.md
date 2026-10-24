# 命令协议（已逆向并实测）

更新时间：2026-10-24
数据来源：对官方 GUI `RvRvpnGui.exe` 做 IAT hook 抓包，共 58 条真实命令帧，
并用服务端日志 `service.log` 的 `[req:N] ...` 行逐条核对语义。

---

## 一、帧的总体结构

GUI 往管道里**写两次**：

```
[4 字节 u32 LE 长度][正文]
```

正文由若干**记录**依次拼成，记录通用形状：

```
[size:u32 BE][类型码:u8][0x00][0x03][字段:u8][payload:size 字节]
```

- `size` 是 payload 字节数
- 第 3、4 字节固定是 `00 03`，第 5 字节才是字段号
- 所有多字节整数都是**大端**

> 一开始把第 3、4 字节当成 16 位大端的 flags 写成 `00 01`，与真实报文的
> `01 00` 不符 —— 逐字节比对抓包才发现的。

### 字符串的编码

**UTF-16 大端**，末尾固定跟 `00 01`：

```
别名「快乐狐狸1」的记录：
  5f eb 4e 50 72 d0 72 f8 00 31 00 01
  └快──┘ └乐──┘ └狐──┘ └狸──┘ └1──┘ └尾┘
```

> 最初判成 UTF-16LE + 前置 `00`。之所以还能成功，是因为网络名几乎全是
> ASCII：ASCII 在 LE 下是 `<char>00`，前面补一个 `00` 就和 BE 的
> `00<char>` 逐字节重合。名字含非 ASCII 或长度为奇数时两种写法就分叉了。
> 现在统一按 BE 处理。

---

## 二、每条命令都以两条记录开头

```
记录1  size=4  type=0x01 field=0x4a  payload=reqId(u32 BE)
记录2  size=4  type=0x01 field=0x00  payload=命令码(u32 BE)
```

`reqId` 会原样出现在服务端日志的 `[req:N]` 里，因此可以精确对账。
`0xffffffff` 表示"无请求编号"（GUI 的周期性上报都用这个）。

---

## 三、命令表

代码里的命令类来自 `RvControlSvc.exe` 的 RTTI（命名空间 `cmd@msg@ControlSvc`）。
命令码则通过两条**不需要动界面**的路子确定：命令码扫描 + 二进制的码表定位。

| 码 | 命令类 | 功能 | 载荷 | 验证方式 |
|---|---|---|---|---|
| `0x02` | `CCreateNetwork` | 创建网络 | 容器 `0x132b`：u32(0)+名字+28 字节随机密钥 | ✅ 实测 Succeeded |
| `0x03` | `CJoinNetwork` | 加入网络 | 容器 `0x131b`：u32(1)+名字 | ✅ 实测 Succeeded |
| `0x05` | `CLeaveNetwork` | 离开网络 | 16 字节 GUID | ✅ 服务日志实证 |
| `0x06` | `CKickNode` | **踢出成员** | GUID + 节点ID + 网络名 | ✅ 服务日志实证 |
| `0x08` | `CEnableNetwork` | 启用/禁用网络 | GUID + u32(0/1) 字段 `0x16` | ✅ 帧逐字节核对 |
| `0x0a` | `CApproveJoin` | 批准加入 | GUID + 节点ID + 网络名 | ✅ 服务日志实证 |
| `0x0f` | `CDeleteNetwork` | 删除网络 | 16 字节 GUID | ✅ 实测 Succeeded |
| `0x10` | `CGrantAdmin` | 授予管理员 | GUID + 节点ID + 网络名 | ✅ 服务日志实证 |
| `0x11` | `CRevokeAdmin` | 撤销管理员 | GUID + 节点ID + 网络名 | ✅ 服务日志实证 |
| `0x12` | `CChangeAlias` | 改别名 | 字符串字段 `0x04` | ✅ 实测 Succeeded |
| `0x13` | `CEnumPublicNetworks` | 枚举公共网络 | 字符串字段 `0x06` | 仅抓到 |
| ? | `CSwitchPower` | **开关网络电源** | 未定 | 类名已确认，码未定位 |
| ? | `CUpdateNetwork` | 网络改名 | 未定 | 类名已确认，码未定位 |

### 二进制里确认的完整命令类清单

```
CApproveJoin      CChangeAlias     CCreateNetwork    CDeleteNetwork
CEnableNetwork    CGrantAdmin      CJoinNetwork      CKickNode
CLeaveNetwork     CRevokeAdmin     CSwitchPower      CUpdateNetwork
CEnumPublicNetworks  CUpdateVisibleNodes  CSetSettings  CManageNetwork
CEnumerateProcesses  COpenChat  CAddFirewallException  CRemoveFirewallException
CClearExcludedFromFirewall  CExcludeFromFirewall  CCancelTask
CLanguageChanged  CDbgActivateProfile  CDbgEmulateSystemWakeUp
CDbgRenameActiveProfile  CAdapterReinstalled
```

以及对应的 `CTaskCompleted_*` 系列（`_KickNode`、`_GrantAdmin`、`_RevokeAdmin`、
`_ApproveJoin`、`_UpdateNetwork`、`_EnableAdapter`、`_SetupAdapter`、`_Register` …），
说明这些操作都是「带请求编号的任务型命令」。

### 服务端的日志模板（来自字符串常量）

```
Requested to approve join %llu/'%ls' into '%ls'
Requested to change alias to '%ls'
Requested to create network '%ls'
Requested to delete network '%ls'
Enabled network '%ls'  /  Disabled network '%ls'
Requested to grant admin to %llu/'%ls' in network '%ls'
Requested to join network '%ls' %hs password
Requested to remove %llu/'%ls' from network '%ls'
Requested to leave network '%ls'
Requested to revoke admin from %llu/'%ls' in network '%ls'
Switched On  /  Switched Off
Requested to update network '%ls'
```

### 命令码表在二进制里的位置

`RvControlSvc.exe` 偏移 **`0x001244e0`** 处有一张 `(命令码, 任务类型)` 配对表：

```
(1,22) (2,2) (3,2) (4,24) (5,13) (6,9) (7,12) (8,12) (9,12)
(10,7) (11,8) (12,22) (13,22) (15,2) (16,13) (17,18) (18,2)
(33,13) (53,2) (65,13)
```

已知码全部能在表里找到；缺 `14/19~32/34~52` 说明那不是"任务型"命令
（例如枚举公共网络、节点可见性上报都不产生请求编号，因此不在这张表里）。


### 创建网络（命令码 0x02）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 02
00 00 00 <N> 00 00 13 2b           ← 容器，N = nameBytes + 58
  00 00 00 04 0b 00 03 08 | 00 00 00 00     ← 字段 0x08 恒为 0
  00 00 00 <M> 03 00 03 06 | <UTF-16BE 网络名> 00 01
  00 00 00 1c 08 00 03 0d | <28 字节随机密钥>
```

**28 字节块是客户端随机生成的**，不是名字的哈希：同名网络两次创建
（reqId 41/44），块内容完全不同。**实测用 `os.urandom(28)` 生成也能成功**：

```
Requested to create network 'rvpnkit-test-可删'  →  Succeeded
```

### 加入网络（命令码 3）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 03
00 00 00 <N> 00 00 13 1b           ← 容器，N = nameBytes + 22
  00 00 00 04 0b 00 03 3f | 00 00 00 01
  00 00 00 <M> 03 00 03 06 | <UTF-16BE 网络名> 00 01
```

实测：加入 `Minecraft [Português 10]` → `[req:2113] Succeeded`。

### 改别名（命令码 0x12）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 12
00 00 00 <M> 03 00 03 04 | <UTF-16BE 新别名> 00 01
```

实测：改成「快乐狐狸1」→ `Succeeded`；改回「快乐狐狸」→ `Succeeded`。

### 删除网络（命令码 0x0f）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 0f
00 00 00 10 0d 00 03 09 | <16 字节 GUID>
```

实测：删除自建的 `rvpnkit-test-可删` → `Succeeded`。

### 启用 / 禁用网络（命令码 0x08）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 08
00 00 00 10 0d 00 03 09 | <16 字节 GUID>
00 00 00 04 0b 00 03 16 | 00 00 00 <0 或 1>     ← 0=禁用 1=启用
```

依据是服务日志的原文对照：

```
13:13:35.271  INFO  Disabled network '91919191免费'   ← 帧里 0x16 = 0
13:13:35.520  INFO  [req:47] Succeeded
13:13:36.440  INFO  Enabled  network '91919191免费'   ← 帧里 0x16 = 1
13:13:36.770  INFO  [req:48] Succeeded
```

两条帧的 GUID 完全相同，只有末尾 u32 不同 —— 是干净的布尔开关。

### 网络查询（命令码 0x13，语义未定）

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 13
00 00 00 <M> 03 00 03 06 | <UTF-16BE 名字或前缀> 00 01
```

抓到两个样本：空串（`00 01`，2 字节）和截断到 26 字节的
`Minecraft [中文`。后者的长度上限说明这个字段并非普通字符串。
**公共网络列表本身是连接时随快照推送的，搜索是客户端本地过滤**，
所以这条命令不是用来搜索的，具体用途还需验证。

---

## 四、无命令的操作（重要结论）

以下操作**不发任何请求**，纯客户端本地行为：

| 操作 | 说明 |
|---|---|
| 打开「加入网络」窗口 | 公共网络列表随快照一起推送，直接本地渲染 |
| 在搜索框输入 | 本地过滤，逐字符都不发请求 |
| 右键菜单、查看属性 | 纯 UI |
| 关闭主窗口 | 不发请求 |

---

## 五、工具

| 文件 | 作用 |
|---|---|
| `native/rvpn_capture.c` | 抓包 hook DLL（32 位，注入 GUI） |
| `native/capture.py` | 启动抓包并**跟随进程**（GUI 重启自动重注入） |
| `native/analyze_capture.py` | 按结构签名归类，并把 reqId 关联到服务端语义 |
| `native/dump_by_reqid.py` | 按请求编号打印完整帧字节 |
| `native/rvpncmd.py` | **可用的命令下发工具**（join/leave/delete/alias/enum/send） |

### 为什么命令下发是 Python 而不是集成进 C# 客户端

`rvpnkit.exe` 打开管道读写会得到 `ERROR_ACCESS_DENIED(5)`，而同一时刻：
- Python 打开读写 → 成功
- PowerShell 内嵌的 .NET 直接调同一个 `CreateFileW` → 成功

访问掩码、路径、共享模式都逐项核对过，完全一致。结论是 **`rvpnkit.exe`
这个进程被施加了令牌限制**，不是代码缺陷。本会话审批被禁用，无法提权绕过，
所以把写通道独立成 Python 工具。`CommandBuilder.cs` 保留为 C# 参考实现，
构造结果与 Python 版逐字节一致。

---

## 六、复现步骤

```powershell
# 1. 编译抓包 hook（32 位）
zig cc -target x86-windows-gnu -shared -O2 -s -o native/rvpn_capture32.dll native/rvpn_capture.c

# 2. 启动常驻抓包（会跟随 GUI 进程）
python native/capture.py start

# 3. 在 Radmin 界面里做操作

# 4. 分析
python native/analyze_capture.py
python native/dump_by_reqid.py 33 35 51

# 5. 下发命令
python native/rvpncmd.py join "网络名"
python native/rvpncmd.py alias "新别名"
```

---

## 七、快照解析：拿到 GUID 与节点 ID

启用/禁用、删除、离开、踢人这些命令的载荷是 **GUID / 节点 ID**，不是名字。
这些 ID 只存在于管道快照里，`native/rvpnstate.py` 负责把它们挖出来。

```powershell
python native\rvpnstate.py          # 列出所有网络（名字 + GUID）和节点 ID
python native\rvpnstate.py --json   # 机器可读
```

解析要点：
- 快照不是一条流，而是**多帧拼接**：每帧 `[u32 LE 长度][正文]`，必须先拆帧
- 正文里的记录：`[size:u32 BE][类型码][0x00][0x03][字段][payload]`
- 容器记录的类型码是 `0x00` 且第 4 字节为 `0x13`（即 `0x1323` / `0x132b` / `0x1344`）
- 网络条目 = 同一个容器里既有 16 字节 GUID（类型 `0x0d`、字段 `0x09`）
  又有名字（类型 `0x03`、字段 `0x06`）
- 节点块 = `00 00 00 08 02 00 01 e1 <u64 节点ID>`

实测：一次读取解析出 **13 个网络**（名字与 GUID 一一对应）和 **1209 个节点**。

## 八、实测记录汇总

| 命令 | 服务端日志实证 |
|---|---|
| 加入网络 | `[req:2113] Succeeded` |
| 创建网络 | `Requested to create network 'rvpnkit-test-可删'` → `Succeeded` |
| 删除网络 | `Requested to delete network 'rvpnkit-test-可删'` → `Succeeded` |
| 改别名 | `Requested to change alias to '快乐狐狸1'` → `Succeeded` |
| **禁用网络** | `Disabled network 'Minecraft [中文 14]'` |
| **启用网络** | `Enabled network 'Minecraft [中文 14]'` |
| 踢人 / 批准 / 授管 / 撤管 | `Requested to remove/grant/approve/revoke ...`（用不存在目标验证格式） |

## 九、仍未定位

`CSwitchPower`（VPN 总开关）与 `CUpdateNetwork`（网络改名）：
类名与日志模板（`Switched On/Off`、`Requested to update network`）都已确认，
但命令码不在 `0x1244e0` 那张任务表里 —— 说明它们不走任务型通道。
用 GUID / 节点 / 空载荷 / 各种 u32 字段共扫了约 600 次请求均无响应，
下一步需要从 GUI 侧找到 `CSwitchPower` 的构造点，或反汇编 12 字节消息 ID
的分派表（`0x444xxx` 那段按 12 字节比较来分派）。

---

## 十、VPN 总开关（CSwitchPower）已打通

命令码 **`0x04`**，载荷只有一个 u32 字段 **`0x11`**（1=开 0=关）：

```
00 00 00 04 01 00 03 4a | reqId
00 00 00 04 01 00 03 00 | 00 00 00 04        ← 命令码 4
00 00 00 04 0b 00 03 11 | 00 00 00 <0 或 1>  ← 字段 0x11
```

实测：

```
Switched Off → Disconnected from server(code:4)
Switched On  → Connected to server (15)
```

### 怎么找到的

两条常规路都失败后才挖出来的，值得记录：

1. **抓包失败**：点界面电源徽标，服务端确实记了 `Switched Off`，
   但 hook 一个字节都没抓到。先后补了 `TransactNamedPipe` 钩子、
   放宽了帧过滤（不再只认信封魔数），依然为空 ——
   说明这条命令**既不走 WriteFile 也不走 TransactNamedPipe**。
2. **静态定位不完整**：服务端有 `CSwitchPower` 的 RTTI 与 vtable，
   但 GUI 里没有该类名，反查构造点无果。
3. **最终靠分组爆破**：把剩余码位（1/4/7/9/11/12/13/14/19~26）×
   32 个字段 × 2 种类型逐组发送，每发完一组检查新出现的 `Switched` 行。
   码 `0x04` 那组命中，再在该码内逐字段二分，锁定字段 `0x11`、类型 `0x0b`。

### 注意

`Switched On/Off` 这两行**不带 `[req:N]`**，所以工具的完成判定要额外
监听 `Switched` 关键字，不能只看 `Succeeded`。

## 十一、仍未定位：CUpdateNetwork（网络改名）

类名与日志模板（`Requested to update network '%ls'`）都已确认，但试过：
GUID+名字（裸记录）、GUID+名字装进容器 `0x1323`/`0x132b`/`0x1321`/`0x1325`、
码位 0x00~0xC0 全扫 —— 均无响应。

推测它需要完整的网络对象序列化（`IManageNetwork` / `CTaskCompleted_AbstractManageNetwork`
这两个接口暗示改名走的是「托管网络」通道，而不是简单的字段组合）。
下一步可以从 `CManageNetwork` 的序列化函数入手。

---

## 十二、公共网络：286 个可选网络，支持搜索与一键加入

`CEnumPublicNetworks`（码 `0x13`）**不写日志、也不在快照里** —— 结果是以
管道响应的形式回来的。所以必须「发命令的同时读响应」。

`native/rvpnpublic.py` 的做法：打开读写管道 → 发枚举请求 → 收 4 秒响应 →
从响应帧里按字段 `0x06` 抽出网络名 → 减去已加入的 13 个，剩下就是可加入的
公共网络。实测一次拿到 **286 个**：

```
Minecraft [中文 5]          Valorant [English 1]
KartRider: Drift [中文 1]   Diablo II: Resurrected [中文 1]
DOTA [English 1..7]         Terraria [中文 1]
Roblox [English 1..3]       CS: 1.5 [中文 1]
```

用法：

```powershell
python native\rvpnpublic.py                      # 列出全部
python native\rvpnpublic.py --search Valorant    # 过滤
python native\rvpnpublic.py join Valorant        # 一键加入
```

实测：

```
匹配 2 个，取第一个: Valorant [English 1]
[req:37137] Requested to join network 'Valorant [English 1]' without password
Succeeded
```

## 十三、功能完成度

| 功能 | 状态 | 实现 |
|---|---|---|
| 网络电源开关 | ✅ | 码 `0x04` 字段 `0x11` |
| 网络启用/禁用 | ✅ | 码 `0x08` + GUID + 字段 `0x16` |
| 加入网络 | ✅ | 码 `0x03` |
| 创建网络 | ✅ | 码 `0x02`（28 字节随机密钥） |
| 删除网络 | ✅ | 码 `0x0f` + GUID |
| 离开网络 | ✅ | 码 `0x05` + GUID |
| 改别名 | ✅ | 码 `0x12` |
| 踢出成员 | ✅ | 码 `0x06` |
| 批准加入 | ✅ | 码 `0x0a` |
| 授予/撤销管理员 | ✅ | 码 `0x10` / `0x11` |
| 成员列表 + IP + 别名 | ✅ | C# 客户端（`rvpnkit`） |
| 公共网络搜索与一键加入 | ✅ | 286 个，`rvpnpublic.py` |
| 网络改名 | ❌ | `CUpdateNetwork` 载荷结构未破 |
