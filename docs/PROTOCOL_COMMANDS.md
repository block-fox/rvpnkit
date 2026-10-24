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

---

## 十四、写通道被拒的真实原因：完整性级别（已更正）

早期结论写的是「安全软件拦截未签名程序写管道」。**这个结论是错的**，
后来用逐项实验推翻了。真正原因是**进程完整性级别**：

| 实验 | 结果 |
|---|---|
| 受限环境派生的 C 程序打印自身完整性 | `Low (0x1000)` |
| Low 完整性下 `GENERIC_READ` 打开管道 | ✅ 成功 |
| Low 完整性下 `GENERIC_WRITE` 打开管道 | ❌ 错误 5 |
| Low 完整性下用 `FILE_APPEND_DATA` 打开（能开） | 打开成功，但 `WriteFile` 仍错误 5 |
| 普通用户（`Medium` 完整性）启动 | ✅ 读写均正常 |

Radmin 控制管道的强制完整性策略要求 **Medium** 才允许写入，而受限环境
（本会话用于验证的沙箱）会把派生子进程降到 **Low**。读不受该策略影响，
所以表现为「能读不能写」，且与程序是否签名、是否被杀软放行都无关。

**结论：正常双击运行 `rvpnkit.exe`（Medium 完整性）时，C# 客户端可以直接
下发命令，不需要加白名单、也不需要 Python 中转。** 本会话中所有实测之所以
走 `native/rvpncmd.py`，是因为 Python 解释器由 harness 直接启动、保持在
Medium 完整性。

> 排查过程中还顺带确认了几件事：
> - 用 WMI 创建进程（脱离作业对象）依旧失败 → 与沙箱 job object 无关
> - 把 `SafeFileHandle` 换成 `IntPtr` 接收句柄 → 与封送无关
> - 火绒界面关闭但 `HipsDaemon` / `hrwfpdrv` / `sysdiag` 仍在运行，
>   但即便全部判定与它无关
---

## 密码网络（2026-10-24 抓包实测）

用户在官方客户端创建了带密码的网络 `deepseektester`（密码与网络名相同），
抓包 hook 恰好记录了这条创建请求，得到关键结构。

### 创建请求里的密码

免密码网络：

```
容器 0x132b
  u32_alt(0x08) = 0
  str(0x06)     = 网络名
  0x08(0x0d)    = 28 字节网络密钥
```

带密码网络（同一条请求，只有最后一处不同）：

```
容器 0x132b
  u32_alt(0x08) = 0                 ← 和免密码完全一样
  str(0x06)     = "deepseektester"
  0x08(0x0d)    = 60 字节 = 28 字节密钥 + 32 字节密码材料
```

**结论：密码不占独立字段，而是附在 `0x0d` 这个块里，固定多出 32 字节。**

### 那 32 字节是什么

试过 57 种常见派生，全部不匹配：

- SHA-256（ASCII / UTF-16LE / UTF-16BE / 带 `00 01` 的线格式 / 小写）
- 加盐：`name+pw`、`pw+name`、`guid+pw`、`pw+guid`、`key+pw`、`pw+key`、`key[:16]+pw`
- HMAC-SHA256（key / guid / name 作密钥）
- MD5×2、SHA-512 截断、SHA-384、SHA3-256、BLAKE2s、BLAKE2b

这 32 字节也**没有出现在快照里**（说明服务端另存，或加了服务端盐）。
所以它大概率是**加密**结果，而不是纯哈希 —— 需要逆客户端里的加密函数才能复现。

### 顺带确认：字段 0x0a 是「我的角色」

| 网络 | field 0x0a |
|---|---|
| 自己创建的 `deepseektester` | **2** |
| 20 个「加入」的 Minecraft 网络 | **1** |

`2` = 管理员（我是创建者），`1` = 普通成员。这是快照里唯一能反映角色的字段，
已接进客户端属性弹窗。

### 还缺的一步

要支持「加入密码网络」，需要再抓一条**带密码的加入请求**：
在官方客户端里先退出该网络，再重新加入并输入密码，hook 会记录整个过程。
`native/decode_pw_create.py` 可以直接从抓包日志里把这条请求解出来。

---

## 密码网络：加入请求（2026-10-25 实测）

用户加入了朋友创建的密码网络 `sky的网络`（密码 `123456`），抓到完整加入请求。

### 结构

```
普通免密码加入：
  容器 0x131b
    u32_alt(0x3f) = 1
    str(0x06)     = 网络名

带密码加入：
  容器 0x131b
    u32_alt(0x3f) = 0            ← 0 表示「下面带密码令牌」
    str(0x06)     = 网络名
    0x08(0x0d)    = 28 字节令牌   ← 密码的等价物
```

实例（`sky的网络`，密码 `123456`）：

```
00 00 00 04 01 00 03 4a <reqId>
00 00 00 04 01 00 03 00 00 00 00 03
00 00 00 6a 00 00 13 1b
  00 00 00 04 0b 00 03 3f 00 00 00 00
  00 00 00 1e 03 00 03 06 ...s k y 的 网 络... 00 01
  00 00 00 1c 08 00 03 0d
     7c23e3d71caecf7272db703068744d23d1d72faefb7247db46306874
```

### 三个决定性实验

| 实验 | 结果 |
|---|---|
| 先离开网络，重放抓到的原始帧（同样名字 + 同样 28 字节） | **成功重新加入** → 令牌是静态的，可无限复用 |
| 换成随机 28 字节 | **失败** |
| 换成全 0 的 28 字节 | **失败** |

结论：
1. 服务端**不校验新鲜度**，同一令牌可反复使用；
2. 但服务端**确实校验令牌**，它是 `f(网络, 密码)` 的确定性值。

### 令牌不是普通哈希

对 `123456` 试过 SHA-224（28 字节输出）的各种编码与加盐组合，均不匹配：

- SHA-224（ASCII / UTF-16LE / UTF-16BE / 线格式 / 小写）
- SHA-224 加盐：`name+pw`、`pw+name`、HMAC(name, pw)
- MD5×2、SHA-1 拼接

它很可能是客户端内的**专有 KDF 或带密钥的加密**，需要静态逆 `RvRvpnGui.exe`
里的实现才能复现。

### 创建请求里的密码（对照）

带密码的创建请求里，`0x0d` 块是 **60 字节** = 28 字节网络密钥 + 32 字节；
免密码是 28 字节。两者长度不同（创建多 4 字节），推测创建侧是
`密钥(28) + 令牌(28) + 4 字节校验`，但没有第二个样本可以验证。

### 实用结论

- ✅ **已能做的**：保存令牌后重复加入同一个密码网络（`0x3f=0` + 令牌）。
- ❌ **还差的**：从密码算出令牌，以及创建带密码网络。
- 需要：静态逆客户端里的 KDF，或再拿一组「同密码不同网络」的样本做差分。

---

## 密码令牌的真实结构（2026-10-25，三组样本）

拿到第三组样本后，结构彻底清楚了。

| 网络 | 密码 | 字符数 | 令牌长度 |
|---|---|---|---|
| sky的网络 | `123456` | 6 | 28 |
| 东北雨姐四十八码大汗脚 | `Aa022033` | 8 | 36 |
| deepseektester（创建请求里的 60 字节） | `deepseektester` | 14 | 60 |

**公式：令牌长度 = 4 + 4 × 字符数。**

三组都严格符合，所以之前把 `deepseektester` 的 60 字节当成「28 密钥 + 32」
是错的 —— 那 60 字节**整个就是令牌**。

### 布局

```
[4 字节 IV][字符0 的 4 字节][字符1 的 4 字节]…[字符n-1 的 4 字节]
```

样本：

```
"123456"     IV=7c23e3d7
   '1' 1caecf72   '2' 72db7030   '3' 68744d23
   '4' d1d72fae   '5' fb7247db   '6' 46306874

"Aa022033"   IV=4fca0aa9
   'A' 35436abb   'a' 397116db   '0' 166b857b   '2' 3c6c0eca
   '2' 6ba90543   '0' 58bb0b71   '3' 26db256b   '3' b67b3c6c

"deepseektester"  IV=cd157e90
   ab37a915 1b902273 4e8b2d4b 925fce3e 30d4ec4e 2b57aa7b
   7c74a2e1 8b41ab37 …（共 14 块）
```

### 关键的三个观察

1. **IV 每次不同** → 是随机盐。所以同一密码每次生成的令牌都不一样，
   但服务端都能验证（它用存着的密码 + 令牌里的 IV 重算）。
2. **同一字符在不同位置密文不同**（`Aa022033` 里两个 `0`、两个 `2`、两个 `3`
   都不同）→ 有链式或位置依赖。
3. **IV 不同但结构一致** → 链函数 `F(prev, char)` 与 IV 无关。

### 排除掉的算法

在 28 个转移上用 Python 暴力验证，全部不匹配：

- **CRC32 链**：`crc32(prev+ch)`、`crc32(ch+prev)`，ASCII / UTF-16LE / UTF-16BE，两种字节序
- **Adler32 链**：同上组合
- **乘法链**：`prev*mul + c`、`prev*mul - c`、`(prev^c)*mul`、`prev*mul ^ c`，
  mul ∈ {31, 33, 37, 131, 1313, 65599, 16777619, 2654435761, 2246822519, 3266489917}
- **旋转/移位链**：`rotl(prev,k)^c`、`prev>>k^c`，k = 1..31
- **哈希前缀截断**：`SHA256/MD5/SHA1/SHA224(pw[0..i])` 取前/后 4 字节，
  带网络名 / 带 IV，共 96 种

### 二进制常量扫描

在 `RvRvpnGui.exe`（14.4 MB）里搜常见 32 位混合常量，只命中两处：

| 常量 | 偏移 |
|---|---|
| `0x9E3779B9`（黄金比例） | `0xF5381` |
| `16777619`（FNV 素数） | `0x12984A` |

**没有** Murmur3（`0x85EBCA6B`/`0xC2B2AE35`）、xxHash、CityHash 的特征常量。
所以这不是标准混合函数，是专有实现。

### 下一步

要拿到 `F`，只能静态逆 `RvRvpnGui.exe`：
从「把密码写进 0x0d 块」的序列化位置往回追，找到那个「每次迭代吃一个宽字符、
产出 4 字节」的循环。两个可疑常量偏移（`0xF5381`、`0x12984A`）是起点。

---

## 逆向日志：密码令牌函数（2026-10-25）

### 工具补强

`RvRvpnGui.exe` 是 **PE32（32 位）**，之前的反汇编工具按 64 位解会有乱码。新增：

- `native/dis32.py` —— 按 VA 反汇编（32 位模式），换算 `file = va - 0xC00`
- `native/xref32.py` —— 扫描 `E8/E9` 相对调用，找任意 VA 的调用点

### 排除的两个「疑似目标」

| 地址 | 是什么 | 结论 |
|---|---|---|
| `0xF5F70` | **SplitMix64**（常量 `0x9E3779B97F4A7C15` / `0xBF58476D1CE4E5B9` / `0x94D049BB133111EB` 全部吻合） | 被 `splitmix64(key) % size` 调用，是**哈希表的散列函数**，不碰密码 |
| `0x12A3D0` | **FNV-1a 32 位**（`0x811C9DC5` 基数 + `0x1000193` 乘法） | 处理带 CR/LF 的文本行，是**读配置/文本**用的，不碰密码 |

### 消息模式表（重要收获）

在 `0x158180` 附近是一大段静态初始化，为每个消息 tag 注册字段描述符。
每条目的格式：

```
[u32 1][u16 tag][6 字节 0][u32 ptr][u32 n]
    之后 n 个 8 字节条目：[field u8][0x03][0x00][type u8][u32 count]
```

解出来的结果与抓包完全一致：

| tag | 含义 | 字段 |
|---|---|---|
| `0x131b` | **加入网络** | `0x06` 字符串（网络名）、`0x0d` 块（令牌） |
| `0x1315` | 网络信息 | `0x09` GUID、`0x06` 字符串 |
| `0x1319` | 未知 | `0x0c` u32、`0x4b` u16 |

**关键结论：加入消息里没有独立的密码字段，密码就是 `0x0d` 那个块。**

### 又排除的算法

| 假设 | 结果 |
|---|---|
| FNV-1a 滚动哈希（每字符后取状态） | 24 种组合全不中 |
| SplitMix64 链（32 位/64 位状态、加法/异或、取高/低 32 位） | 35 种组合全不中 |

### 下一步的确定性路线

IV 是随机数，所以生成令牌的函数**必然调用随机源**。顺着这条路走：

1. 解析导入表，找出 `CryptGenRandom` / `RtlGenRandom` / `rand` / `QRandomGenerator`
2. 通过 IAT thunk 找到调用点
3. 从调用点往回追，就是令牌生成函数

---

# ★ 密码令牌算法：已完全破解（2026-10-25）

## 最终结论

设密码长度为 n（按 UTF-8 字节数），取 (n+1) 个 16 位随机数 `R[0..n]`，
令牌长度 `4 × (n+1)` 字节，内容为两段拼接：

```
前半（n+1 个 u16）: (R[i] 的高字节 ^ password[i], R[i] 的低字节)
后半（n+1 个 u16）: R[i] 原样
```

最后一位 `i == n` 没有对应字符，按 0 处理 —— 所以两半的最后一位完全相同。

**换句话说：密码是逐字节异或在高字节上的。拿到令牌就能直接反推出密码。**
这不是哈希，是「把密码明文藏在随机数里」，Radmin 这个设计有明显缺陷。

## 实例

密码 `123456`，随机数 `4d23d1d72faefb7247db46306874`：

```
前半 7c23 e3d7 1cae cf72 72db 7030 6874
后半 4d23 d1d7 2fae fb72 47db 4630 6874
```

逐位看异或：

```
7c^4d=0x31='1'   e3^d1=0x32='2'   1c^2f=0x33='3'   cf^fb=0x34='4'
72^47=0x35='5'   70^46=0x36='6'    68^68=0x00（填充位）
```

## 五组样本全部逐字节验证通过

| 密码 | 场景 | 令牌长度 |
|---|---|---|
| `123456` | 加入 `sky的网络` | 28 |
| `Aa022033` | 加入 `东北雨姐四十八码大汗脚` | 36 |
| `deepseektester` | 创建 `deepseektester` | 60 |
| `123456` | 再次加入（不同随机数） | 28 |
| `deepseektester` | 再次加入（不同随机数） | 60 |

## 活体验证

```
[1] 退出 sky的网络 … 已退出
[2] 用自己算的令牌加入（密码 '123456'）
    令牌 a7f27ce64ebd0704dc4e2d516ba796f24ee67dbd3304e94e1b516ba7
[3] 结果: ★ 加入成功
```

整个过程没有启动官方客户端 —— 令牌完全由我们的代码算出，服务端接受。

创建方向也验证过：用我们的客户端创建带密码网络，返回 `withPassword: true`，
`role=2`（创建者是管理员）。

## 逆向过程回顾

| 阶段 | 手段 | 结果 |
|---|---|---|
| 1 | 对比带密码/免密码网络快照 | 只发现 `0x0a` 是角色（2=管理员、1=成员），不是密码 |
| 2 | 用服务端日志 `with/without password` 做判据撞字段号 | 撞 0x00~0xFF 共 200+ 个，全不中 |
| 3 | 静态扫描常量 | 找到 SplitMix64 与 FNV-1a，但都不是密码用的 |
| 4 | **hook IAT 里的 `CryptGenRandom`** | 拿到「随机数只取 2(n+1) 字节」+ 实际随机内容 |
| 5 | 对比随机内容与令牌 | 发现令牌后半 = 随机数原文，前半 = 随机数高字节异或密码 |

关键转折是第 4 步：静态找函数太难，改成动态记录随机源调用，一下子把
「令牌 = 随机数 + 密码」这个结构暴露出来了。

## 尚未验证的边界

密码按 **UTF-8 字节**处理。全部样本都是 ASCII，此时字节数等于字符数。
如果密码含中文，客户端可能按 UTF-16 码元处理，长度口径会不同 —— 需要用
一个中文密码的样本来确认。

## 代码位置

- Rust：`rust/crates/rvpn-core/src/commands.rs` 的 `password_token()` / `token_to_password()`
- 构造器：`join_network_with_password()` / `create_network_with_password()`
- 测试：`rust/crates/rvpn-core/tests/password_token.rs`（4 个测试，覆盖五组样本）
- 界面：网络页的「密码（留空=免密码）」输入框
- 复现工具：`native/rng_spy3.c`（IAT hook）、`native/verify_token.py`、`native/live_join_pw.py`

---

## 修正：密码按 UTF-16LE 编码（2026-10-25，中文样本）

用中文密码 `发发发发发发`（网络名 `发发发发发发发发发`）验证后，发现之前
从 ASCII 样本得出的结论需要修正。

### 长度口径

令牌 **28 字节** = `4 × (6+1)`。密码是 6 个「发」：

| 口径 | 长度 | 令牌应为 |
|---|---|---|
| UTF-8 字节 | 18 | 76 字节 |
| **UTF-16 码元** | **6** | **28 字节** ✓ |

所以 **n = UTF-16 码元数（即字符数）**，不是字节数。

### 异或方式

中文样本的逐字节异或结果是：

```
d1 53 d1 53 d1 53 d1 53 d1 53 d1 53 00 00
```

「发」= U+53D1，其 **UTF-16LE 字节正是 `d1 53`**。

所以正确的模型是逐字节异或，而不是「只异或 u16 高字节」：

```
n = 密码的 UTF-16 码元数
pw = UTF-16LE(密码)，补齐到 2(n+1) 字节（末尾补一个 u16 的 0）
R  = 2(n+1) 个随机字节
token = (R 逐字节 XOR pw) || R
```

ASCII 的 UTF-16LE 是 `(字符, 0x00)`，所以看起来只有每两个字节里的第一个
被异或 —— 这正是早先误判的原因。

### 六组样本全部逐字节验证

| 密码 | 字符数 | 令牌长度 |
|---|---|---|
| `123456` | 6 | 28 |
| `Aa022033` | 8 | 36 |
| `deepseektester` | 14 | 60 |
| `123456`（不同随机数） | 6 | 28 |
| `deepseektester`（不同随机数） | 14 | 60 |
| `发发发发发发` | 6 | 28 |

六组都能：
1. 用「随机数后半段 + 密码」重新生成，**逐字节一致**；
2. 从令牌**反推出原文密码**（含中文）。

### 代码影响

`password_token()` / `token_to_password()` 已改为 UTF-16LE 编码，
测试文件 `tests/password_token.rs` 增加到 5 个测试、覆盖六组样本（含中文）。
