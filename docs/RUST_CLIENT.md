# Rust 客户端（rvpnkit）

用 Rust 重写的图形客户端：**Rust 后端 + 本地 Web UI**。

```
┌──────────────┬──────────────────────────────────────────────┐
│ RvpnKit      │  ⏻ 已开启   刷新    快乐狐狸 #204206449 IP   │
│              ├──────────────────────────────────────────────┤
│ 网络    14   │  网络                                        │
│ 成员   171   │  双击进入成员页；右键可启用/禁用/离开/删除    │
│ 公共网络     │  ┌────────────────────────────────────────┐  │
│ 设置         │  │ 网络名            成员    GUID          │  │
│              │  │ Minecraft [中文 11]  171   4c791750…    │  │
│ ● 直连管道   │  │ Minecraft [中文 9]   234   9315f557…    │  │
│ ● 可读写     │  └────────────────────────────────────────┘  │
├──────────────┴──────────────────────────────────────────────┤
│ 已刷新 · 17:35:07                        网络 14 · 成员 3461 │
└─────────────────────────────────────────────────────────────┘
```

## 为什么不是原生窗口（egui）

一开始按计划用 egui 写原生窗口。但本机只有 `x86_64-pc-windows-gnu` 工具链
（没装 MSVC），而 egui 的依赖链里 `parking_lot_core` / `libloading` /
`windows-sys` 都带 `raw-dylib` 链接属性 —— rustc 会调用 `dlltool` **现场生成
导入库**，而 Rust 自带的 dlltool 又需要 `as.exe` 才能汇编桩代码：

| 尝试 | 结果 |
|---|---|
| Rust 自带 `dlltool.exe` | 缺 `as.exe`，`CreateProcess` 失败 |
| MSYS2 binutils 的 `dlltool` / `as` | 缺 MSYS2 运行库，`STATUS_DLL_NOT_FOUND` |
| 降级 `parking_lot_core` 到 0.9.6 | `libloading`、`windows-sys` 同样要用 raw-dylib，绕不完 |
| `-C link-self-contained=yes` + `rust-lld` | 能修好 serde 这类普通依赖，但修不了 raw-dylib |

**换成 Web UI 反而更好**：

| 维度 | egui 原生窗口 | Rust + Web UI |
|---|---|---|
| 构建依赖 | 200+ crate，卡在 dlltool | 只有 `rvpn-core` + `serde_json` |
| 观感 | 默认样式偏朴素 | CSS 想怎么做怎么做 |
| 分页栏 / 右键菜单 | 要手写 | 浏览器原生能力 |
| 启动闪烁 | 有合成器透明帧问题 | 无 |
| 跨平台 | 需按平台编译 | 任何有浏览器的机器 |

界面 HTML/CSS/JS 全部内嵌在二进制里（`include_str!`），不依赖任何外部资源。

## 构建

```powershell
cd rust
$env:CARGO_TARGET_DIR = "C:\rtools\rvpn-target"   # 可选：放到 ASCII 路径更稳
cargo build -p rvpn-web --release
```

产物：`target/release/rvpnkit.exe`（约 600 KB，无运行时依赖）。

## 运行

```powershell
rvpnkit.exe                 # 自动打开浏览器
rvpnkit.exe --no-open       # 只起服务
rvpnkit.exe --addr 0.0.0.0:8788   # 允许局域网访问
```

默认监听 `127.0.0.1:8788`。启动时会打印管道路径与当前权限。

## 功能

| 页面 | 能力 |
|---|---|
| **网络** | 14 个网络（成员数 / GUID）；按名字加入、创建；右键：查看成员 / 启用 / 禁用 / 复制 GUID / 离开 / 删除 |
| **成员** | 选中网络的成员（节点 ID / 别名 / 公网 IP）；右键：授权 / 撤权 / 批准 / 复制节点 ID / **踢出** |
| **公共网络** | 搜索 → 列出约 300 个可加入网络；双击或右键加入 |
| **设置** | 改别名、管道路径、后端信息、权限状态、已知限制 |

顶部「⏻ 已开启」是 **VPN 总电源**，这一版是真的接到 `CSwitchPower`（命令码 `0x04`）上了。

## HTTP API

Web UI 和外部脚本走同一套接口：

```
GET  /api/state[?refresh=1]
GET  /api/public?search=关键词
POST /api/power                  {"on":true}
POST /api/alias                  {"alias":"新名字"}
POST /api/networks/join          {"name":"网络名"}
POST /api/networks/create        {"name":"网络名"}
POST /api/networks/{guid}/leave
POST /api/networks/{guid}/delete
POST /api/networks/{guid}/enabled     {"enabled":true}
POST /api/networks/{guid}/members/{nodeId}/kick|approve|grant|revoke
```

## 已知限制（都是诚实的「没解出来」，不是偷懒）

| 项 | 原因 |
|---|---|
| 创建网络时设密码 | 抓到的所有创建请求都是**免密码网络**，容器里 `field 0x08 = 0`，密码字段位置没有样本可对照 |
| 公共网络页不能踢人 | 公共网络只是「可加入的清单」，里面没有成员。踢人只能在**成员**页对**已加入**的网络做 |
| 网络改名 | `CUpdateNetwork` 类存在，但官方客户端也没有入口，码位与载荷都没解出来 |

## 与 .NET 版的关系

`src/RvpnKit.Core`（C#）与 `rust/crates/rvpn-core`（Rust）是同一套协议的
两份实现，都带**与抓包逐字节比对**的自检。Rust 版是后续主线，.NET 版保留作
参考与对照。

`rust/crates/rvpn-gui` 是 egui 原生窗口版本，**当前不参与构建**（工具链缺
dlltool/as）。等有 MSVC 工具链时可以直接接回去。

---

## 双后端（已打通）

```
rvpnkit --no-open                     直连管道（默认，最快）
rvpnkit --agent http://host:8770      转发给 agent（跨平台 / 远程）
```

直连模式下所有管道 I/O 在进程内完成；`--agent` 模式下整条 REST 路径原样透传，
agent 的 `{"ok":..,"data":..}` 信封与本地响应格式一致，所以前端代码完全不用改。

HTTP 客户端**没有引 reqwest/ureq** —— 那会带进 openssl/rustls 之类的重依赖，
而这里只需要对本机/局域网的明文 HTTP 说几句话，用 `std::net::TcpStream`
手写一个极简客户端（含 chunked 解码）反而更可控。

实测链路：

```
Rust 客户端 :8789  --agent http://127.0.0.1:8770
    ↓ HTTP
.NET agent :8770
    ↓ 命名管道
Radmin 服务
→ /api/state  HTTP 200 · 14 网络 · 3492 成员
```
