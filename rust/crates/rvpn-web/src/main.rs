//! Radmin VPN 图形客户端：Rust 后端 + 本地 Web UI。
//!
//! 为什么不是原生窗口
//! ------------------
//! 本来打算用 egui。但本机只有 `x86_64-pc-windows-gnu` 工具链（没装 MSVC），
//! 而 egui 的依赖链里 `parking_lot_core` / `libloading` / `windows-sys` 都用了
//! `raw-dylib` 链接属性，rustc 会调用 `dlltool` 现场生成导入库 —— 而 Rust 自带
//! 的 dlltool 又需要 `as.exe` 才能汇编桩代码，工具链里没有，MSYS2 的 as 又缺运行库。
//!
//! 与其在这上面耗，不如换成「Rust 后端 + 本地 Web UI」：
//!   * 零 GUI 依赖，构建只依赖 rvpn-core + serde_json（已验证可编译）
//!   * 界面用 HTML/CSS，比默认 egui 好看得多，分页栏和右键菜单是原生能力
//!   * 天然跨平台（Windows / Linux / macOS 都能跑，用浏览器看）
//!   * 不会出现「启动先透明一下」那种合成器问题
//!
//! 协议逻辑全部在 `rvpn-core` 里，这个 crate 只负责 HTTP 和界面。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rvpn_core::commands::next_request_id;
use rvpn_core::pipe::PipeClient;
use rvpn_core::{Commands, CommandCode, PublicNetworks, SnapshotState, DEFAULT_PIPE};

const DEFAULT_ADDR: &str = "127.0.0.1:8788";

fn main() {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut open_browser = true;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--no-open" => {
                open_browser = false;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "rvpnkit —— Radmin VPN 图形客户端（本地 Web UI）\n\n\
                     用法: rvpnkit [--addr 127.0.0.1:8788] [--no-open]\n\n\
                     \x20 --addr <地址>  监听地址，默认 {DEFAULT_ADDR}\n\
                     \x20 --no-open     不自动打开浏览器"
                );
                return;
            }
            _ => i += 1,
        }
    }

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("无法监听 {addr}：{e}");
            std::process::exit(1);
        }
    };

    let url = format!("http://{addr}");
    // 控制台横幅故意用 ASCII：中文 Windows 的控制台代码页是 GBK，
    // 打印制表符会变成一堆乱码。
    println!();
    println!("  +--------------------------------------------------+");
    println!("  |  rvpnkit  -  Radmin VPN client (Web UI)          |");
    println!("  +--------------------------------------------------+");
    println!();
    println!("  界面      {url}");
    println!("  管道      {DEFAULT_PIPE}");
    if let Ok(p) = PipeClient::connect(DEFAULT_PIPE) {
        println!(
            "  权限      {}",
            if p.can_write() { "可读写" } else { "只读（受限环境会降低完整性级别）" }
        );
    } else {
        println!("  权限      管道不可用");
    }
    println!();
    println!("  按 Ctrl+C 退出");
    println!();

    if open_browser {
        open_url(&url);
    }

    let shared = Arc::new(());
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let sh = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = sh; // 目前无共享可变状态，保留以便将来加缓存
                    handle(s);
                });
            }
            Err(_) => continue,
        }
    }
}

fn open_url(url: &str) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

// ───────────────────────────────────────────────────── HTTP 小框架

struct Request {
    method: String,
    path: String,
    query: String,
    body: String,
}

fn handle(mut stream: TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    // 请求行
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };

    // 头
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() {
            return;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    // 体
    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_err() {
            return;
        }
        body = String::from_utf8_lossy(&buf).to_string();
    }

    let req = Request {
        method,
        path,
        query,
        body,
    };

    let (status, ctype, payload) = route(&req);
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    };

    let mut out = Vec::new();
    let _ = write!(
        out,
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        payload.len()
    );
    out.extend_from_slice(&payload);
    let _ = stream.write_all(&out);
    let _ = stream.flush();
}

fn json_ok(data: serde_json::Value) -> (u16, &'static str, Vec<u8>) {
    let v = serde_json::json!({ "ok": true, "data": data });
    (200, "application/json; charset=utf-8", v.to_string().into_bytes())
}

fn json_err(status: u16, msg: impl Into<String>) -> (u16, &'static str, Vec<u8>) {
    let v = serde_json::json!({ "ok": false, "error": msg.into() });
    (status, "application/json; charset=utf-8", v.to_string().into_bytes())
}

fn route(req: &Request) -> (u16, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => (200, "text/html; charset=utf-8", UI.as_bytes().to_vec()),
        ("GET", "/api/state") => api_state(&req.query),
        ("GET", "/api/public") => api_public(&req.query),
        ("POST", "/api/power") => api_power(&req.body),
        ("POST", "/api/alias") => api_alias(&req.body),
        ("POST", "/api/networks/join") => api_join(&req.body),
        ("POST", "/api/networks/create") => api_create(&req.body),
        ("POST", p) if p.starts_with("/api/networks/") => api_network_op(p, &req.body),
        _ => (404, "text/plain; charset=utf-8", b"not found".to_vec()),
    }
}

// ───────────────────────────────────────────────────── API 实现

fn read_snapshot() -> Result<(SnapshotState, bool), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    let can_write = pipe.can_write();
    let raw = pipe
        .read_snapshot(Duration::from_millis(2200))
        .map_err(|e| e.to_string())?;
    Ok((SnapshotState::parse(&raw), can_write))
}

fn send(frame: Vec<u8>) -> Result<u32, String> {
    let rid = rvpn_core::Wire::request_id(&frame);
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("当前为只读连接，无法下发命令。若运行在受限环境（Low 完整性），\
                    请用普通用户身份直接启动本程序。"
            .into());
    }
    pipe.send(&frame).map_err(|e| e.to_string())?;
    Ok(rid)
}

fn api_state(query: &str) -> (u16, &'static str, Vec<u8>) {
    let refresh = query.split('&').any(|kv| kv == "refresh=1");
    let _ = refresh; // 目前每次都重读，没有缓存
    match read_snapshot() {
        Ok((st, can_write)) => {
            let nets: Vec<serde_json::Value> = st
                .networks
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "name": n.name,
                        "guid": n.guid_hex(),
                        "token": n.token,
                        "members": n.members.iter().map(|m| serde_json::json!({
                            "nodeId": m.node_id,
                            "alias": m.alias,
                            "publicIp": m.public_ip,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();

            json_ok(serde_json::json!({
                "canWrite": can_write,
                "self": st.me.as_ref().map(|m| serde_json::json!({
                    "nodeId": m.node_id,
                    "alias": m.alias,
                    "publicIp": m.public_ip,
                })),
                "networkCount": st.networks.len(),
                "memberCount": st.member_count(),
                "nodeCount": st.nodes.len(),
                "networks": nets,
            }))
        }
        Err(e) => json_err(502, format!("读取快照失败：{e}")),
    }
}

fn api_public(query: &str) -> (u16, &'static str, Vec<u8>) {
    let search = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("search="))
        .map(|s| urldecode(s));

    // 先拿已加入的网络名
    let joined = match read_snapshot() {
        Ok((st, _)) => st.networks.into_iter().map(|n| n.name).collect::<Vec<_>>(),
        Err(e) => return json_err(502, format!("读取状态失败：{e}")),
    };

    let mut pipe = match PipeClient::connect(DEFAULT_PIPE) {
        Ok(p) => p,
        Err(e) => return json_err(502, e.to_string()),
    };
    if !pipe.can_write() {
        return json_err(409, "只读连接无法枚举公共网络（需要可写）");
    }
    if let Err(e) = pipe.send(&Commands::enum_public_networks("", next_request_id())) {
        return json_err(502, e.to_string());
    }
    let raw = match pipe.read_snapshot(Duration::from_millis(2200)) {
        Ok(r) => r,
        Err(e) => return json_err(502, e.to_string()),
    };

    let list = PublicNetworks::available(&raw, &joined, search.as_deref());
    json_ok(serde_json::json!({ "count": list.len(), "networks": list }))
}

fn body_str(body: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get(key)?.as_str().map(|s| s.to_string())
}

fn api_power(body: &str) -> (u16, &'static str, Vec<u8>) {
    let on = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("on").and_then(|x| x.as_bool()))
        .unwrap_or(true);
    match send(Commands::switch_power(on, next_request_id())) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "power": on })),
        Err(e) => json_err(409, e),
    }
}

fn api_alias(body: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(alias) = body_str(body, "alias") else {
        return json_err(400, "缺少 alias");
    };
    if alias.trim().is_empty() {
        return json_err(400, "alias 不能为空");
    }
    match send(Commands::change_alias(alias.trim(), next_request_id())) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "alias": alias })),
        Err(e) => json_err(409, e),
    }
}

fn api_join(body: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(name) = body_str(body, "name") else {
        return json_err(400, "缺少 name");
    };
    match send(Commands::join_network(name.trim(), next_request_id())) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "joined": name })),
        Err(e) => json_err(409, e),
    }
}

fn api_create(body: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(name) = body_str(body, "name") else {
        return json_err(400, "缺少 name");
    };
    if let Some(pw) = body_str(body, "password") {
        if !pw.is_empty() {
            // 诚实告知：密码字段位置还没解出来
            return json_err(
                400,
                "暂不支持设置密码：抓到的创建请求都是免密码网络，密码字段的位置尚未解出",
            );
        }
    }
    match send(Commands::create_network(name.trim(), next_request_id(), None)) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "created": name })),
        Err(e) => json_err(409, e),
    }
}

/// `/api/networks/{guid}/leave|delete|enabled` 和
/// `/api/networks/{guid}/members/{node}/kick|...`
fn api_network_op(path: &str, body: &str) -> (u16, &'static str, Vec<u8>) {
    let rest = path.trim_start_matches("/api/networks/");
    let parts: Vec<&str> = rest.split('/').collect();

    let guid = match hex_to_bytes(parts.first().copied().unwrap_or("")) {
        Some(g) if g.len() == 16 => g,
        _ => return json_err(400, "guid 需要是 32 位十六进制"),
    };

    if parts.len() >= 2 && parts[1] == "members" && parts.len() >= 4 {
        let node_id: u64 = match parts[2].parse() {
            Ok(n) => n,
            Err(_) => return json_err(400, "nodeId 需要是数字"),
        };
        let op = parts[3];
        let code = match op {
            "kick" | "remove" => CommandCode::KickNode,
            "approve" => CommandCode::ApproveJoin,
            "grant" | "grantadmin" => CommandCode::GrantAdmin,
            "revoke" | "revokeadmin" => CommandCode::RevokeAdmin,
            _ => return json_err(400, "op 支持 kick / approve / grant / revoke"),
        };
        let name = body_str(body, "name").unwrap_or_default();
        return match send(Commands::member_operation(
            code,
            &guid,
            node_id,
            &name,
            next_request_id(),
        )) {
            Ok(rid) => json_ok(serde_json::json!({
                "requestId": rid, "guid": parts[0], "nodeId": node_id, "op": op
            })),
            Err(e) => json_err(409, e),
        };
    }

    let op = parts.get(1).copied().unwrap_or("");
    let frame = match op {
        "leave" => Commands::leave_network(&guid, next_request_id()),
        "delete" => Commands::delete_network(&guid, next_request_id()),
        "enabled" => {
            let on = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("enabled").and_then(|x| x.as_bool()))
                .unwrap_or(true);
            Commands::set_network_enabled(&guid, on, next_request_id())
        }
        _ => return json_err(404, format!("未知操作 {op}")),
    };

    match send(frame) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "op": op, "guid": parts[0] })),
        Err(e) => json_err(409, e),
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ───────────────────────────────────────────────────── 界面

const UI: &str = include_str!("ui.html");
