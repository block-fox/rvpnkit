# Rust 客户端与开发

当前 Rust workspace 包含 `rvpn-core`、`rvpn-web` 与 `rvpn-gui`。主线版本为 0.4.0；0.2 的环境排查记录见 [历史说明](legacy/RUST_CLIENT_0.2.md)。

## 构建

```powershell
cd rust
cargo build --workspace --release --locked
cargo test --workspace --release --locked
cargo fmt --all -- --check
```

离线环境可以加 `--offline`，前提是依赖已缓存。Windows GNU 工具链如缺少 binutils，参阅 [环境说明](WINDOWS_GNU_TOOLCHAIN.md)；不要将个人电脑上的编译目录写进发布脚本。

仓库根目录的 `dev.ps1` 封装了 build / test / web / gui / demo-web / demo-gui / package，自动进入正确目录，以加载 `rust/.cargo/config.toml`。

## 结构与职责

- **rvpn-core**：协议帧、密码令牌、命名管道、快照。`presentation.rs` 提供去除敏感令牌的快照 JSON、CSV 转义与明确标注的演示数据。
- **rvpn-web**：`main.rs` 路由与 API，`http.rs` 有界请求解析，`backend.rs` 可选 agent 客户端。`ui.html` / `ui.css` / `ui.js` 分离维护，编译时嵌入二进制。
- **rvpn-gui**：`main.rs` 生命周期与后台任务，`pages.rs` 管理页面，`workspace.rs` 总览与工具，`theme.rs` 配色与矢量图标，`preferences.rs` 配置，`backend.rs` 管道访问，`properties.rs` 成员属性。

服务写操作由现有协议构建器生成；没有重写 VPN 驱动或数据平面。刷新保留真实快照，界面不虚构缺失的成员状态。

## WebUI 行为

默认只监听 `127.0.0.1:8788`，无需 CDN 或 npm。服务未启动时仍可打开页面；手动刷新可恢复连接。自动刷新可设为关闭 / 5 / 10 / 30 秒，页面隐藏时暂停，同一页面不会重叠刷新。

HTTP 输入限制：请求行 4 KiB、请求头总量 16 KiB、JSON 体 64 KiB，最多 16 个并发连接；写操作要求 JSON 并拒绝跨来源 Origin。直连服务请求串行访问，快照短缓存 2 秒，手动刷新跳过缓存。agent 响应限制为 8 MiB，支持分块编码与被分块切开的 UTF-8。

`/api/state` 的节点 ID 使用十进制字符串，避免 JavaScript 丢失 64 位整数精度。响应不包含网络密码令牌。

## 回归测试

```powershell
# 已安装 Playwright 及本地 Chrome / Edge 时
node scripts\web-smoke.cjs
```

脚本启动只读演示后端，测试真实 HTTP 输入限制和浏览器交互；对可写 UI 的请求使用本地拦截响应，不操作实际 VPN。自定义路径可使用 `RVPNKIT_WEB_EXE`、`RVPNKIT_BROWSER`、`RVPNKIT_TEST_PORT`；已有 Playwright 安装可通过 `NODE_PATH` 复用。

GUI 真实渲染验收：`rvpnkit-gui.exe --screenshot-dir <目录>`。截图模式强制演示数据并自动退出。
