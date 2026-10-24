# rvpnkit-agent —— 控制面 HTTP API

把 Radmin VPN 的本地控制能力暴露成 REST 接口，让**任何平台、任何语言**都能管理
Radmin 网络，而不再受官方那个 Qt 客户端的限制。

```
Windows 主机（装 Radmin 服务，从不启动官方 GUI）
   └─ rvpnkit-agent  ← 连本地命名管道，暴露 HTTP
          ↑ HTTP + X-Api-Token
   ├─ Linux / macOS 命令行
   ├─ Avalonia 图形客户端（计划）
   └─ Minecraft mod（Java，走 HTTP）
```

## 启动

```powershell
dotnet run --project src\RvpnKit.Agent -c Release
# 或直接
src\RvpnKit.Agent\bin\Release\net10.0\rvpnkit-agent.exe --port 8770
```

| 参数 | 说明 |
|---|---|
| `--host <地址>` | 监听地址，默认 `127.0.0.1` |
| `--port <端口>` | 端口，默认 `8770` |
| `--token <令牌>` | 指定 API 令牌（也可用环境变量 `RVPNKIT_TOKEN`） |
| `--no-auth` | 关闭鉴权，仅限本机调试 |

不给令牌时会随机生成一个并在启动时打印。请求用 `X-Api-Token` 头，
或查询串 `?token=`。

## 接口

### `GET /health`
服务信息，**不需要鉴权**，方便探活。

### `GET /api/state[?refresh=1]`
当前状态：本机信息、所有网络（含 GUID）、每个网络的成员（节点 ID / 别名 / 公网 IP）。
结果缓存 5 秒，`refresh=1` 强制重读。

```json
{
  "ok": true,
  "data": {
    "self": { "nodeId": 204206449, "alias": "快乐狐狸", "publicIp": "198.244.203.247" },
    "networkCount": 13, "memberCount": 2982, "nodeCount": 1445,
    "canWrite": true,
    "networks": [
      { "name": "Minecraft [中文 11]", "guid": "4c791750…", "memberCount": 158,
        "members": [ { "nodeId": 15187030, "alias": "姚翔耀", "publicIp": "198.244.203.247" } ] }
    ]
  }
}
```

> `canWrite=false` 说明管道只能只读打开。这通常不是代码问题，而是进程
> **完整性级别**：受限环境会把子进程降到 Low，而管道要求 Medium 才允许写。

### `GET /api/public[?search=关键词]`
枚举可加入的公共网络（已排除已加入的）。需要可写连接。

### 写操作

| 方法 | 路径 | 请求体 |
|---|---|---|
| POST | `/api/power` | `{"on": true}` |
| POST | `/api/alias` | `{"alias": "新名字"}` |
| POST | `/api/networks/join` | `{"name": "网络名"}` |
| POST | `/api/networks/create` | `{"name": "网络名"}` |
| POST | `/api/networks/{guid}/leave` | — |
| POST | `/api/networks/{guid}/delete` | — |
| POST | `/api/networks/{guid}/enabled` | `{"enabled": true}` |
| POST | `/api/networks/{guid}/members/{nodeId}/kick` | — |
| POST | `/api/networks/{guid}/members/{nodeId}/approve` | `?name=网络名` |
| POST | `/api/networks/{guid}/members/{nodeId}/grant` | `?name=网络名` |
| POST | `/api/networks/{guid}/members/{nodeId}/revoke` | `?name=网络名` |

所有写操作返回请求编号，可拿去和服务日志的 `[req:N]` 对账。

## 为什么这样设计

- **一次调用 = 一次管道连接**：Radmin 服务的管道实例数有限，长期占用会影响
  官方 GUI 重连；命令本身是毫秒级，重连成本可以接受。只读快照较慢
  （服务连上就推 ~600KB），所以加了 5 秒缓存。
- **只暴露控制面**：数据面（26.x 虚拟网卡、加密隧道）仍由 Radmin 自己的
  服务和驱动承担，agent 不碰。
- **协议逻辑全在 `RvpnKit.Core`**，agent 只是把它翻译成 HTTP，方便后续
  接 GUI、接 mod、接别的语言。

## 实测

```
GET /health               200
GET /api/state            13 个网络 / 2982 个成员 / 1445 个节点，别名与 IP 齐全
                          本机 快乐狐狸 #204206449 198.244.203.247
GET /api/public           需要可写连接；只读时返回 502 + 明确原因
```
