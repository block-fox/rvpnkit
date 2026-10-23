# 命令抓取：已完成的部分与最后一步

更新时间：2026-10-24 02:50

---

## 一、关键更正：注入从未被安全软件拦截

之前多轮判定「HIPS 拦截远程线程注入」，**这个结论是错的**。

真实原因是：我从 **64 位 Python** 调用
`GetProcAddress(kernel32, "LoadLibraryW")` 拿到的是 **64 位 kernel32**
里的地址（形如 `0x7ff8_22a7_f6c0`）。目标 `RvRvpnGui.exe` 是 **32 位**进程，
那个地址在它里面根本没有映射。远程线程一执行就跳到野地址 —— 表现为
"线程创建成功但返回码 0"，我误读成了"被拦截"。

**修复**：用一个 32 位辅助进程（`inject32.exe --addr-only`）取 32 位地址，
再注入。实测：

```
32位 kernel32 基址 : 0x76a00000   → 读出的头两字节是 'MZ'  ✓
32位 LoadLibraryW  : 0x76a1d870   → 读出 8b ff（mov edi,edi 序言）✓
CreateRemoteThread → 返回 0x64980000（模块基址，非 0）✓
DllMain            → 写出标记文件 "probe attached, pid=37772" ✓
```

**结论：注入完全可用，与杀软无关。**

## 二、已抓到的真实命令帧

以「挂起启动 + 先注入 + 再恢复」的方式，捕获到 GUI 启动时发出的命令：

```
=== OUT (WriteFile) len=4 ===
30 00 00 00                      ← 帧长度前缀（u32 LE = 48）

=== OUT (WriteFile) len=48 ===
00 00 00 04 01 00 03 4a ff ff ff ff
00 00 00 04 01 00 03 00 00 00 00 1c
00 00 00 04 01 00 02 5a 00 00 08 04
00 00 00 04 01 00 02 5a 00 00 08 04
```

### 已确认的写路径细节

1. **GUI 把帧分成两次 `WriteFile` 写**：先写 4 字节长度前缀，再写正文。
2. 正文开头的 `00 00 00 04 01 00` 与**服务端下发的帧完全相同** ——
   说明收发共用一个消息信封。
3. 48 字节正文可整齐切成 **4 条 12 字节记录**（推测）：

   | # | 类型 | 字段号 | 值 |
   |---|---|---|---|
   | 1 | `03` | `4a` | `ff ff ff ff` = -1 |
   | 2 | `03` | `00` | `00 00 00 1c` = 28 |
   | 3 | `02` | `5a` | `00 00 08 04` |
   | 4 | `02` | `5a` | `00 00 08 04` |

   但这只是**一种可能的切分**，还没有第二个样本可以交叉验证。

### 回放实验结果

把这段正文原样通过管道发给服务，**服务未记录任何 `[req:` 行**。
说明它要么是订阅/握手类消息（本就不产生 `[req:`），要么需要前置会话状态。

## 三、为什么还差最后一步

实测确认：**GUI 空闲时不发任何命令**。

| 观察 | 结果 |
|---|---|
| hook 装上后静置 60 秒 | 0 条 OUT 帧 |
| 服务日志同期 | 0 条 `[req:` |
| 物理点击窗口各区域 | 0 条 OUT |
| `PostMessage` 合成鼠标消息 | 0 条 OUT |
| `WM_CLOSE` 触发退出 | 0 条 OUT |

原因：服务在客户端一连上就**主动推送完整快照**，GUI 只管读，不需要发请求。
真正的命令（加入网络 / 启用禁用 / 踢人 / 改名）只在**用户操作**时产生。

而 Qt5 不响应合成的鼠标消息，也没有启用无障碍桥接（UIA 树为 0 元素），
所以**程序化触发 UI 操作这条路走不通**。

## 四、最后一步：手动点一下即可

当前 GUI 正带着 hook 稳定运行。**只要在界面上做一个动作**，命令就会被记录下来。

最省事的三种动作（任选其一）：

1. **打开「加入网络」窗口** —— 会触发 `CEnumPublicNetworks`
2. **右键某个网络 → 启用 / 禁用** —— 会触发 `CEnableNetwork`
3. **修改自己的别名** —— 会触发别名更新

抓完查看日志：

```powershell
notepad "$env:TEMP\rvpipe_hook.log"
```

日志里会出现新的 `=== OUT (WriteFile) len=N ===` 段落，
其中的十六进制就是该命令的**完整报文**。

> 注意：日志文件当前被 GUI 以共享方式打开，可以随时读取；
> 但每次重新注入会 `CREATE_ALWAYS` 清空，所以抓完先别重注入。

拿到 1~2 条不同命令后，做法就明确了：

- **差分**：对比两条命令的字节差异 → 定位"命令选择字段"
- **构造**：保留信封与公共字段，替换目标字段 → 拼出自己的命令
- **验证**：发送后看服务日志是否出现 `[req:N] Requested to ...`

## 五、工具清单

| 文件 | 作用 |
|---|---|
| `native/inject32.c` | 32 位注入器；`--addr-only` 输出正确的 32 位地址 |
| `native/inject_fixed.py` | 用 32 位地址注入（含地址校验） |
| `native/inject_suspended.py` | 挂起启动 + 先注入 + 再恢复，用于抓启动命令 |
| `native/rvpipe_hook.c` | hook DLL：拦 CreateFileW / WriteFile / TransactNamedPipe |
| `native/WinMsg.cs` | 窗口定位与点击辅助（物理点击 + `PostMessage` 两种方式） |
| `native/apc_inject.py` | APC 注入实验（已知风险：可能崩目标，仅作参考） |
| `native/replay_frames.py` | 把抓到的帧回放给服务并观察 `[req:` 变化 |

### 重新开始抓取的完整流程

```powershell
# 1. 关掉现有 GUI
Get-Process RvRvpnGui | Stop-Process -Force

# 2. 编译 hook（32 位）
zig cc -target x86-windows-gnu -shared -O2 -s -o native/rvpipe_hook32.dll native/rvpipe_hook.c

# 3. 挂起启动 + 注入 + 恢复
python native/inject_suspended.py native/rvpipe_hook32.dll

# 4. 手动在界面上点一下（加入网络 / 启用禁用 / 改别名）

# 5. 查看抓到的报文
notepad "$env:TEMP\rvpipe_hook.log"
```

## 六、踩过的坑（避免重复）

| 坑 | 现象 | 原因 |
|---|---|---|
| 64 位地址注入 32 位进程 | 线程返回 0，进程消失 | 地址在目标中未映射 |
| APC 注入当兜底 | GUI 崩溃，KERNEL32 访问违例 | APC 里跑 LoadLibraryW 撞 loader 锁 |
| hook 了 `ReadFile` | GUI 偶发崩溃 | 重叠 I/O 下 `*got` 未定义，按它读缓冲区越界 |
| 只补 EXE 的导入表 | 一帧都抓不到 | 真正的调用发生在后加载的 DLL 里 |
| `DllMain` 里只异步起线程 | 启动命令全漏 | 主线程恢复后立刻发请求，worker 还没补丁 |
| PowerShell `Add-Type` 加载含中文注释的 .cs | 编译错乱 | 按 GBK 读取导致多字节截断吞掉换行 |
| 直接 `Start-Process` 起 GUI | 命令结束时 GUI 消失 | DSH 的 job object 连带杀死子进程；改用 `explorer.exe` 启动 |
