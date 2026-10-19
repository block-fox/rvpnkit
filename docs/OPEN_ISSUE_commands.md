# 未解决的问题：命令下发格式

生成时间：2026-10-20 03:30

---

## 一、已经解决的问题

| 问题 | 结论 |
|---|---|
| 管道能否连接 | ✅ 可以，且**支持多客户端并发**（官方 GUI 运行时也能连） |
| 读取状态流 | ✅ 完全可用（206 KB 快照 + 增量事件） |
| 写入是否被权限阻止 | ✅ **不阻止** —— Python 侧读写打开 12/12 成功 |
| .NET 为何写不了 | ❌ 未定位（详见第三节） |

## 二、当前状态：能读能写，但**不知道写什么**

**写路径在字节层面已经打通。** 用 `native/pipe_send.py` 可以成功向服务写入：

```json
{"ok": true, "written": 12, "frameBodyLen": 8}
```

但是**不知道命令的正确编码**，因此写入的字节被服务静默丢弃。

## 三、为什么这是个死锁

### 障碍 A：服务对畸形输入无任何反馈

服务日志的记录规则是**只有解析成功的请求才记录**：

```
2026.10.20 02:21:06.294  INFO  [req:234] Succeeded
2026.10.20 02:21:07.662  INFO  [req:235] Succeeded
```

这两条是**官方 GUI** 发出的命令留下的（注意时间 02:21，当时我在做其它测试）。

实测：发送 6 个候选帧后，日志中**没有任何新的 `[req:` 记录**，也没有任何错误记录。
说明服务在**解析阶段就静默丢弃**了无法识别的数据。

→ **必须格式完全正确才能获得反馈，但不知道格式就无法构造正确的报文。**
→ 盲猜格式这条路不可行。

### 障碍 B：无法 hook 官方 GUI

原本最可靠的方案是在 GUI 进程里挂钩 `TransactNamedPipe`，直接记录它发出的真实报文。
但本机 HIPS 安全软件会阻止远程线程注入 —— 虽然 `CreateRemoteThread` 返回成功，
但远程线程实际不执行（连 `GetCurrentProcessId()` 都返回 0）。

### 障碍 C：UI 自动化不可用

官方 GUI 是 Qt5 应用，未启用无障碍桥接。即使设置 `QT_ACCESSIBILITY=1` 重启后，
UI Automation 树仍为 **0 个元素**，无法用于代驱动 GUI 发命令。

### 障碍 D：.NET 与 Python 的行为差异

| 进程 | 只读打开 | 读写打开 |
|---|---|---|
| python.exe（本机 Python 3.12） | ✅ 成功 | ✅ **12/12 成功** |
| rvpnkit.exe（.NET 10） | ✅ 成功 | ❌ 稳定 `ERROR_ACCESS_DENIED` |

两者使用**完全相同的 `CreateFileW` 参数**：
`GENERIC_READ|GENERIC_WRITE`、`share=0`、`OPEN_EXISTING`、无重叠标志。

.NET 侧还测试了具体权限位，结果一致：

```
✓ OK      只读 GENERIC_READ
✗ err=5   读写 GENERIC_READ|GENERIC_WRITE
✓ OK      FILE_GENERIC_READ
✗ err=5   FILE_GENERIC_WRITE
✗ err=5   FILE_GENERIC_READ|FILE_GENERIC_WRITE
✗ err=5   GENERIC_ALL
✓ OK      0（仅查询）
```

即：**任何包含写权限的请求都被拒**。而同样的请求从 Python 发出却成功。
推测与 .NET 请求的附加访问位（如特定 SECURITY_INFORMATION）有关，**未定位根因**。

> 影响：目前写操作必须经 Python 代理（`native/pipe_send.py`）完成。
> 这可用，但不优雅，且给部署增加了一个 Python 依赖。

## 四、可能的突破口（按可行性排序）

### 1. 抓一次真实的 GUI 命令（最直接）

如果能在**其它机器**上（没有 HIPS 拦截）运行本仓库的 hook，或在关闭安全软件后
在本机运行，即可直接记录官方 GUI 的命令报文，格式问题当场解决。

工具已备好且编译验证通过：
```
native/rvpipe_hook.c        IAT hook（编译成 32 位 DLL）
native/inject.py            DLL 注入器
```

### 2. 静态分析 `RvRvpnGui.exe` 的序列化代码

GUI 侧有 `CAbstractNetworkServiceCommand` / `CJoinNetworkServiceCommand` 等类。
对它们做静态逆向（反汇编或伪代码还原）可以确定报文构造逻辑。
**不需要运行环境配合，是最可靠但不最省力的方案。**

### 3. 提权后 hook `RvControlSvc`

服务以 SYSTEM 运行；提权后可对其注入并记录报文。同时也能解决网卡启停问题。

### 4. 使用 `RvROLClient.dll` 的导出接口

该 DLL 有完整导出（`ROLClient_Register` / `ROLClient_JoinNetwork` /
`ROLClient_EnumPublicNetworks` …）。但它是**云端协议客户端**，
而管道承载的是 ControlSvc 自己的封装协议 —— 需要额外逆向这层封装。

### 5. 定位 .NET 读写打开失败的原因

即使解决，也**不能**解决"不知道写什么"的问题，只能让写代理不再需要 Python。
属于次要问题。

## 五、已具备但尚未使用的资产

| 资产 | 位置 | 用途 |
|---|---|---|
| IAT hook 源码（已验证可编译） | `native/rvpipe_hook.c` | 抓真实命令报文 |
| DLL 注入器 | `native/inject.py` | 注入 hook |
| 注入诊断脚本 | `native/diag_inject.py` | 判断注入是否被拦截 |
| 写代理 | `native/pipe_send.py` | 已验证可写入管道 |
| 候选帧构造器 | `native/try_candidates.py` | 批量发送候选 |
| 协议笔记 | `docs/PROTOCOL.md` | 已知字段与消息类型清单 |
| 语法求解器 | `src/RvpnKit.Cli/GrammarSolver.cs` | 穷举线格式（往返校验） |

## 六、建议的下一步

**优先级 1：静态分析 GUI 的命令序列化代码。**
这是唯一不依赖运行环境、不依赖注入、不依赖提权的路线。
`RvRvpnGui.exe` 的 `ServiceCommand` 类族就是报文的构造者，逆向它们即可确定格式。

**优先级 2：在无 HIPS 的环境重跑 hook。**
如果有一台可以自由注入的机器，10 分钟即可拿到答案。
