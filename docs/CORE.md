# RvpnKit.Core —— 协议内核

跨平台的纯协议库：只处理「帧长什么样」，不碰任何 Windows 专有 API
（命名管道实现单独放在 `NamedPipeTransport`，通过 `IRvpnTransport` 抽象隔离）。

## 为什么单独做一层

目标是「替换官方客户端」并且「能被别的程序复用」（GUI、远程 Agent、
Minecraft mod）。要做到这点，协议编解码必须与传输方式解耦：

```
        ┌─────────────────┐
        │  RvpnKit.Core   │  帧编解码 / 命令构造 / 快照解析
        └────────┬────────┘
                 │ IRvpnTransport
     ┌───────────┼────────────┬──────────────┐
 命名管道      HTTP/WS      回放文件      内存管道
 (Windows)   (远程 Agent)   (离线调试)    (单元测试)
```

## 组成

| 文件 | 内容 |
|---|---|
| `Wire.cs` | 线格式常量、记录读写器、UTF-16BE 字符串编解码、记录流解析 |
| `Commands.cs` | 12 个命令的构造器 |
| `Snapshot.cs` | 快照解析：网络（名字 + GUID）、节点 ID |
| `Transport.cs` | `IRvpnTransport` 抽象 |
| `NamedPipeTransport.cs` | Windows 命名管道实现 |

## 自检

`src/RvpnKit.SelfTest` 用**抓包得到的真实字节**做逐字节比对：

```
✓ 加入网络 join          102 字节  与抓包完全一致
✓ 改别名 alias            44 字节
✓ 总开关 power off/on     36 字节
✓ 启用网络 enable         60 字节
✓ 删除网络 delete         48 字节
✓ 字符串往返（含中文/葡语/单字符）
✓ 活体快照：13 个网络 + 1361 个节点
═══ 通过 13 / 失败 0 ═══
```

跑法：

```powershell
dotnet run --project src\RvpnKit.SelfTest -c Release -- --live
```

## 用法

```csharp
using RvpnKit.Core;

// 活体：读快照
await using var tp = NamedPipeTransport.Connect();
byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(4));
var st = Snapshot.Parse(raw);
foreach (var n in st.Networks)
    Console.WriteLine($"{n.Name}  {n.GuidHex}");

// 下发命令
byte[] frame = Commands.SwitchPower(on: true, requestId: 1234);
await tp.SendAsync(frame);
```

## 解析要点（踩过的坑）

- 快照是**多帧拼接**：每帧 `[u32 LE 长度][正文]`，必须先拆帧
- 记录头是 `[size:u32 BE][类型码][0x00][0x03][字段]`，第 3、4 字节固定 `00 03`
- **节点记录例外**：`size=8`、类型 `0x02`、第 4 字节是 `0x01` 而不是 `0x03`
- 字符串是 **UTF-16BE + 00 01**（不是 LE；ASCII 名字下两种写法字节恰好相同，
  遇到非 ASCII 才会暴露）
- 容器判定：类型码 `0x00` 且第 4 字节 `0x13`
