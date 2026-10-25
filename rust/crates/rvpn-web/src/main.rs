mod backend;
mod http;
use http::Request;

use backend::Backend;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rvpn_core::commands::next_request_id;
use rvpn_core::pipe::PipeClient;
use rvpn_core::{CommandCode, Commands, PublicNetworks, SnapshotState, DEFAULT_PIPE};

const DEFAULT_ADDR: &str = "127.0.0.1:8788";

static PIPE_GATE: Mutex<()> = Mutex::new(());
static STATE_CACHE: Mutex<Option<(std::time::Instant, serde_json::Value)>> = Mutex::new(None);
static PUBLIC_CACHE: Mutex<Option<(std::time::Instant, Vec<String>)>> = Mutex::new(None);
static READ_API: Mutex<Option<rvpn_core::api::ApiHandle>> = Mutex::new(None);
static READ_API_CONFIG: Mutex<Option<rvpn_core::api::ApiConfig>> = Mutex::new(None);
static BACKEND: OnceLock<Backend> = OnceLock::new();

fn backend() -> &'static Backend {
    BACKEND.get().expect("后端未初始化")
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    /// 把控制台输出代码页切成 UTF-8，否则中文在 GBK 控制台里是乱码。
    fn SetConsoleOutputCP(code_page: u32) -> i32;
}

fn win_utf8_console() {
    #[cfg(windows)]
    unsafe {
        SetConsoleOutputCP(65001);
    }
}

fn main() {
    win_utf8_console();
    let mut addr = DEFAULT_ADDR.to_string();
    let mut open_browser = true;
    let mut agent: Option<String> = None;
    let mut dump: Option<String> = None;
    let mut demo = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--agent" if i + 1 < args.len() => {
                agent = Some(args[i + 1].clone());
                i += 2;
            }
            "--dump" if i + 1 < args.len() => {
                dump = Some(args[i + 1].clone());
                i += 2;
            }
            "--demo" => {
                demo = true;
                i += 1;
            }
            "--no-open" => {
                open_browser = false;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "rvpnkit —— Radmin VPN 图形客户端（本地 Web UI）\n\n\
                     用法: rvpnkit [--addr 127.0.0.1:8788] [--agent http://host:port] [--demo] [--no-open]\n\n\
                     \x20 --addr <地址>  监听地址，默认 {DEFAULT_ADDR}\n\
                     \x20 --no-open     不自动打开浏览器"
                );
                return;
            }
            _ => i += 1,
        }
    }

    if !demo && agent.is_none() {
        match rvpn_core::desktop::maybe_relaunch_elevated() {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => eprintln!("{error}"),
        }
    }

    // 调试用：把原始快照写盘，方便离线分析字段结构
    if let Some(path) = &dump {
        match rvpn_core::pipe::PipeClient::connect(DEFAULT_PIPE) {
            Ok(mut pipe) => match pipe.read_snapshot(std::time::Duration::from_millis(3000)) {
                Ok(raw) => match std::fs::write(path, &raw) {
                    Ok(()) => println!("已写入 {} 字节到 {path}", raw.len()),
                    Err(e) => eprintln!("写文件失败：{e}"),
                },
                Err(e) => eprintln!("读快照失败：{e}"),
            },
            Err(e) => eprintln!("连不上管道：{e}"),
        }
        return;
    }

    let chosen = if demo {
        Backend::Demo
    } else {
        match &agent {
            Some(url) => match Backend::http(url) {
                Some(b) => b,
                None => {
                    eprintln!("--agent 需要形如 http://127.0.0.1:8770 的地址");
                    std::process::exit(2);
                }
            },
            None => Backend::Pipe,
        }
    };

    if !chosen.probe() {
        eprintln!(
            "后端不可用：{}\n  直连模式需要本机 Radmin 服务；HTTP 模式需要先启动 rvpnkit-agent。",
            chosen.label()
        );
        eprintln!("界面仍会启动，服务恢复后点击刷新即可重试。");
    }
    let _ = BACKEND.set(chosen);
    {
        let mut config = READ_API_CONFIG.lock().unwrap_or_else(|e| e.into_inner());
        *config = Some(rvpn_core::api::ApiConfig::default());
    }
    let backend_label = backend().label();

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
    println!("  后端      {backend_label}");
    println!("  管道      {DEFAULT_PIPE}");
    if matches!(backend(), Backend::Pipe) {
        // 管道实例数有限，刚断开时立刻重连可能失败，重试几次再下结论。
        let mut report = "管道不可用".to_string();
        for _ in 0..6 {
            if let Ok(p) = PipeClient::connect(DEFAULT_PIPE) {
                report = if p.can_write() {
                    "可读写".to_string()
                } else {
                    "只读（受限环境会降低完整性级别）".to_string()
                };
                drop(p);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        println!("  权限      {report}");
    }
    println!();
    println!("  按 Ctrl+C 退出");
    println!();

    if open_browser {
        open_url(&url);
    }

    let shared = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if shared.fetch_add(1, Ordering::AcqRel) >= 16 {
                    shared.fetch_sub(1, Ordering::AcqRel);
                    let mut s = s;
                    let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let sh = Arc::clone(&shared);
                std::thread::spawn(move || {
                    handle(s);
                    sh.fetch_sub(1, Ordering::AcqRel);
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

fn handle(mut stream: TcpStream) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let clone = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let (status, ctype, payload) = match http::read_request(&mut BufReader::new(clone)) {
        Ok(req) => route(&req),
        Err((status, message)) => json_err(status, message),
    };
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let headers = format!("HTTP/1.1 {status} {status_text}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n", payload.len());
    let _ = stream
        .write_all(headers.as_bytes())
        .and_then(|_| stream.write_all(&payload));
}

fn json_ok(data: serde_json::Value) -> (u16, &'static str, Vec<u8>) {
    let v = serde_json::json!({ "ok": true, "data": data });
    (
        200,
        "application/json; charset=utf-8",
        v.to_string().into_bytes(),
    )
}

fn json_err(status: u16, msg: impl Into<String>) -> (u16, &'static str, Vec<u8>) {
    let v = serde_json::json!({ "ok": false, "error": msg.into() });
    (
        status,
        "application/json; charset=utf-8",
        v.to_string().into_bytes(),
    )
}

fn route(req: &Request) -> (u16, &'static str, Vec<u8>) {
    if req.method == "GET" {
        match req.path.as_str() {
            "/" => return (200, "text/html; charset=utf-8", UI.as_bytes().to_vec()),
            "/assets/ui.css" => {
                return (
                    200,
                    "text/css; charset=utf-8",
                    include_bytes!("ui.css").to_vec(),
                )
            }
            "/assets/ui.js" => {
                return (
                    200,
                    "application/javascript; charset=utf-8",
                    include_bytes!("ui.js").to_vec(),
                )
            }
            "/health" => return json_ok(serde_json::json!({"version": env!("CARGO_PKG_VERSION")})),
            _ => {}
        }
    }
    if !req.path.starts_with("/api/") {
        return json_err(404, "未找到接口");
    }
    if matches!(backend(), Backend::Demo) {
        return match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/state") => json_ok(rvpn_core::presentation::state_json(
                &rvpn_core::presentation::demo_state(),
                false,
                true,
            )),
            ("GET", "/api/read-api") => api_read_api_get(),
            ("POST", "/api/read-api") => api_read_api_set(&req.body),
            ("GET", "/api/public") => {
                let search = req
                    .query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("search="))
                    .map(urldecode)
                    .unwrap_or_default()
                    .to_lowercase();
                let names: Vec<_> = [
                    "Minecraft · 像素之旅",
                    "Terraria · 新世界",
                    "周末游戏同好会",
                ]
                .into_iter()
                .filter(|s| s.to_lowercase().contains(&search))
                .collect();
                json_ok(serde_json::json!({"networks": names, "demo":true}))
            }
            ("POST", _) => json_err(403, "演示模式禁止写入真实服务"),
            _ => json_err(404, "未找到接口"),
        };
    }
    let _gate = if matches!(backend(), Backend::Pipe) {
        Some(PIPE_GATE.lock().unwrap_or_else(|e| e.into_inner()))
    } else {
        None
    };

    // HTTP 后端：除首页外整条路径原样转发给远程 agent。
    // agent 的响应本来就是同一套 {"ok":..,"data":..} 信封，直接透传即可。
    if matches!(backend(), Backend::Http { .. })
        && !matches!(req.path.as_str(), "/api/read-api" | "/api/firewall")
    {
        if req.path == "/" {
            return (200, "text/html; charset=utf-8", UI.as_bytes().to_vec());
        }
        let target = if req.query.is_empty() {
            req.path.clone()
        } else {
            format!(
                "{}?{}",
                req.path,
                req.query.replace("refresh=1", "refresh=true")
            )
        };
        let result = if req.method == "POST" {
            backend::http_post(backend(), &target, &req.body)
        } else {
            backend::http_get(backend(), &target)
        };
        return match result {
            Ok((status, body)) => {
                let mut value = match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(v) => v,
                    Err(_) => return json_err(502, "agent 返回的不是 JSON"),
                };
                if req.path == "/api/state" {
                    if let Some(data) = value.get_mut("data") {
                        sanitize_api_state(data);
                    }
                }
                (
                    status,
                    "application/json; charset=utf-8",
                    value.to_string().into_bytes(),
                )
            }
            Err(e) => json_err(502, format!("转发到 agent 失败：{e}")),
        };
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => (200, "text/html; charset=utf-8", UI.as_bytes().to_vec()),
        ("GET", "/api/state") => api_state(&req.query),
        ("GET", "/api/read-api") => api_read_api_get(),
        ("POST", "/api/read-api") => api_read_api_set(&req.body),
        ("GET", "/api/firewall") => api_firewall_get(),
        ("POST", "/api/firewall") => api_firewall_post(&req.body),
        ("GET", "/api/public") => api_public(&req.query),
        ("POST", "/api/probe") => api_probe(&req.body),
        ("POST", "/api/desktop") => api_desktop(&req.body),
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
        .read_snapshot(Duration::from_millis(1200))
        .map_err(|e| e.to_string())?;
    let mut state = SnapshotState::parse(&raw);
    rvpn_core::connections::enrich(&mut state);
    Ok((state, can_write))
}

fn send(frame: Vec<u8>) -> Result<u32, String> {
    let records = rvpn_core::Wire::parse(&frame);
    let code = records
        .iter()
        .find(|r| r.field == 0 && r.ty == 1)
        .map(|r| r.as_u32())
        .ok_or("命令缺少类型")?;
    if [5, 6, 8, 10, 14, 15, 16, 17].contains(&code) {
        let (state, _) = read_snapshot()?;
        rvpn_core::permissions::authorize(&frame, &state)?;
    }
    *STATE_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *PUBLIC_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let rid = rvpn_core::Wire::request_id(&frame);
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err(
            "当前为只读连接，无法下发命令。若运行在受限环境（Low 完整性），\
                    请用普通用户身份直接启动本程序。"
                .into(),
        );
    }
    pipe.transact(&frame, Duration::from_secs(8))
        .map_err(|e| e.to_string())?;
    Ok(rid)
}

fn api_state(query: &str) -> (u16, &'static str, Vec<u8>) {
    let mut cache = STATE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if !query.split('&').any(|kv| kv == "refresh=1") {
        if let Some((at, value)) = cache.as_ref() {
            if at.elapsed() < Duration::from_secs(2) {
                return json_ok(value.clone());
            }
        }
    }
    match read_snapshot() {
        Ok((st, can_write)) => {
            let value = rvpn_core::presentation::state_json(&st, can_write, false);
            *cache = Some((std::time::Instant::now(), value.clone()));
            json_ok(value)
        }
        Err(e) => json_err(502, format!("读取快照失败：{e}")),
    }
}

fn read_api_snapshot() -> Result<serde_json::Value, String> {
    match backend() {
        Backend::Demo => Ok(rvpn_core::presentation::state_json(
            &rvpn_core::presentation::demo_state(),
            false,
            true,
        )),
        Backend::Pipe => read_snapshot().map(|(state, can_write)| {
            rvpn_core::presentation::state_json(&state, can_write, false)
        }),
        Backend::Http { .. } => {
            let (_, body) = backend::http_get(backend(), "/api/state")?;
            let value: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| e.to_string())?;
            let mut data = value
                .get("data")
                .cloned()
                .ok_or_else(|| String::from("agent 响应缺少 data"))?;
            sanitize_api_state(&mut data);
            Ok(data)
        }
    }
}

fn sanitize_api_state(data: &mut serde_json::Value) {
    data["demo"] = serde_json::json!(false);
    if let Some(me) = data.get_mut("self").and_then(|v| v.as_object_mut()) {
        if let Some(id) = me.get("nodeId").and_then(|id| id.as_u64()) {
            me.insert("nodeId".into(), serde_json::json!(id.to_string()));
        }
    }
    if let Some(networks) = data.get_mut("networks").and_then(|v| v.as_array_mut()) {
        for network in networks {
            if let Some(object) = network.as_object_mut() {
                object.remove("token");
            }
            if let Some(members) = network.get_mut("members").and_then(|v| v.as_array_mut()) {
                for member in members {
                    if let Some(id) = member.get("nodeId").and_then(|id| id.as_u64()) {
                        member["nodeId"] = serde_json::json!(id.to_string());
                    }
                }
            }
        }
    }
}

fn restart_read_api(config: rvpn_core::api::ApiConfig) -> Result<Option<String>, String> {
    let mut slot = READ_API.lock().unwrap_or_else(|e| e.into_inner());
    let old = slot.take();
    if !config.enabled {
        return Ok(None);
    }
    let provider = std::sync::Arc::new(read_api_snapshot);
    let handle = match rvpn_core::api::ApiHandle::spawn(&config, provider) {
        Ok(handle) => handle,
        Err(error) => {
            *slot = old;
            return Err(error);
        }
    };
    let address = handle.address.clone();
    *slot = Some(handle);
    drop(slot);
    drop(old);
    Ok(Some(address))
}

fn api_read_api_get() -> (u16, &'static str, Vec<u8>) {
    let config = READ_API_CONFIG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default();
    let active = READ_API
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|handle| handle.address.clone());
    json_ok(serde_json::json!({
        "enabled": config.enabled,
        "bindIp": config.bind_ip,
        "port": config.port,
        "hasToken": !config.token.is_empty(),
        "active": active,
    }))
}

fn api_read_api_set(body: &str) -> (u16, &'static str, Vec<u8>) {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return json_err(400, "请求体必须为 JSON"),
    };
    let mut config = rvpn_core::api::ApiConfig::default();
    config.enabled = value
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    config.bind_ip = value
        .get("bindIp")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .trim()
        .to_string();
    config.port = value
        .get("port")
        .and_then(|v| v.as_u64())
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(8790);
    config.token = value
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Err(error) = config.socket_address() {
        return json_err(400, error);
    }
    match restart_read_api(config.clone()) {
        Ok(active) => {
            *READ_API_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
            json_ok(serde_json::json!({
                "enabled": config.enabled,
                "bindIp": config.bind_ip,
                "port": config.port,
                "hasToken": !config.token.is_empty(),
                "active": active,
            }))
        }
        Err(error) => json_err(409, error),
    }
}

fn api_firewall_get() -> (u16, &'static str, Vec<u8>) {
    match rvpn_core::firewall::list_rules() {
        Ok(rules) => json_ok(serde_json::json!({
            "rules": rules.into_iter().map(|rule| serde_json::json!({"ip":rule.ip,"name":rule.name})).collect::<Vec<_>>()
        })),
        Err(error) => json_err(409, error),
    }
}

fn api_firewall_post(body: &str) -> (u16, &'static str, Vec<u8>) {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return json_err(400, "请求体必须为 JSON"),
    };
    let action = value.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let ip = value.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let result = match action {
        "block" => rvpn_core::firewall::block_ip(ip),
        "unblock" => rvpn_core::firewall::unblock_ip(ip),
        _ => return json_err(400, "action 支持 block / unblock"),
    };
    match result {
        Ok(message) => json_ok(serde_json::json!({"message": message})),
        Err(error) => json_err(409, error),
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

    let cached = PUBLIC_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|(at, _)| at.elapsed() < Duration::from_secs(30))
        .map(|(_, list)| list.clone());
    let all = if let Some(list) = cached {
        list
    } else {
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
        let raw = match pipe.read_snapshot(Duration::from_millis(1200)) {
            Ok(r) => r,
            Err(e) => return json_err(502, e.to_string()),
        };
        let list = PublicNetworks::extract_names(&raw);
        *PUBLIC_CACHE.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((std::time::Instant::now(), list.clone()));
        list
    };
    let needle = search.unwrap_or_default().to_lowercase();
    let list: Vec<_> = all
        .into_iter()
        .filter(|name| {
            !joined.iter().any(|item| item == name)
                && (needle.is_empty()
                    || name.to_lowercase().contains(&needle)
                    || fuzzy_subsequence(&name.to_lowercase(), &needle))
        })
        .collect();
    json_ok(serde_json::json!({ "count": list.len(), "networks": list }))
}

fn fuzzy_subsequence(haystack: &str, needle: &str) -> bool {
    let mut cursor = 0;
    for ch in needle.chars() {
        let Some(offset) = haystack[cursor..].find(ch) else {
            return false;
        };
        cursor += offset + ch.len_utf8();
    }
    true
}

fn body_str(body: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get(key)?.as_str().map(|s| s.to_string())
}

fn password_field(body: &str) -> Result<String, &'static str> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|_| "请求体必须为 JSON")?;
    let password = match value.get("password") {
        None => "",
        Some(serde_json::Value::String(password)) => password,
        _ => return Err("password 必须为字符串"),
    };
    if password.encode_utf16().count() > 256 {
        return Err("密码过长");
    }
    Ok(password.to_owned())
}

fn api_power(body: &str) -> (u16, &'static str, Vec<u8>) {
    let on = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("on").and_then(|x| x.as_bool()));
    let Some(on) = on else {
        return json_err(400, "on 必须为布尔值");
    };
    match send(Commands::switch_power(on, next_request_id())) {
        Ok(rid) => json_ok(serde_json::json!({ "requestId": rid, "power": on })),
        Err(e) => json_err(409, e),
    }
}

fn api_probe(body: &str) -> (u16, &'static str, Vec<u8>) {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return json_err(400, "请求体必须为 JSON"),
    };
    let Some(items) = value.get("ips").and_then(|v| v.as_array()) else {
        return json_err(400, "ips 必须为数组");
    };
    let mut ips = Vec::new();
    for item in items.iter().take(48) {
        let Some(ip) = item.as_str() else {
            return json_err(400, "ips 只能包含字符串");
        };
        if ip.parse::<std::net::IpAddr>().is_err() {
            return json_err(400, "ips 包含无效地址");
        }
        ips.push(ip.to_owned());
    }
    let results = rvpn_core::desktop::probe_many(&ips)
        .into_iter()
        .map(|(ip, latency)| serde_json::json!({"ip": ip, "latencyMs": latency}))
        .collect::<Vec<_>>();
    json_ok(serde_json::json!({"results": results}))
}

fn api_desktop(body: &str) -> (u16, &'static str, Vec<u8>) {
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => return json_err(400, "请求体必须为 JSON"),
    };
    let action = match value.get("action").and_then(|v| v.as_str()) {
        Some("official") => rvpn_core::desktop::DesktopAction::Official,
        Some("chat") => rvpn_core::desktop::DesktopAction::Chat,
        Some("voice") => rvpn_core::desktop::DesktopAction::VoiceChat,
        Some("message") => rvpn_core::desktop::DesktopAction::SendMessage,
        Some("full_control") => rvpn_core::desktop::DesktopAction::FullControl,
        Some("view_only") => rvpn_core::desktop::DesktopAction::ViewOnly,
        Some("file_transfer") => rvpn_core::desktop::DesktopAction::FileTransfer,
        Some("telnet") => rvpn_core::desktop::DesktopAction::Telnet,
        _ => return json_err(400, "不支持的系统工具操作"),
    };
    let address = value.get("address").and_then(|v| v.as_str());
    match rvpn_core::desktop::execute(action, address) {
        Ok(message) => json_ok(serde_json::json!({"message": message})),
        Err(error) => json_err(409, error),
    }
}

fn api_alias(body: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(alias) = body_str(body, "alias") else {
        return json_err(400, "缺少 alias");
    };
    if alias.trim().is_empty()
        || alias.encode_utf16().count() > 64
        || alias.chars().any(char::is_control)
    {
        return json_err(400, "alias 须为 1–64 字符且不含控制字符");
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
    if let Err(error) = rvpn_core::operation::validate_name(name.trim()) {
        return json_err(400, error);
    }
    let password = match password_field(body) {
        Ok(password) => password,
        Err(error) => return json_err(400, error),
    };
    if !password.is_empty() {
        if let Err(error) = rvpn_core::operation::validate_password(&password) {
            return json_err(400, error);
        }
    }
    let frame = if password.is_empty() {
        Commands::join_network(name.trim(), next_request_id())
    } else {
        Commands::join_network_with_password(name.trim(), &password, next_request_id())
    };
    match send(frame) {
        Ok(rid) => json_ok(serde_json::json!({
            "requestId": rid, "joined": name, "withPassword": !password.is_empty()
        })),
        Err(e) => json_err(409, e),
    }
}

fn api_create(body: &str) -> (u16, &'static str, Vec<u8>) {
    let Some(name) = body_str(body, "name") else {
        return json_err(400, "缺少 name");
    };
    if let Err(error) = rvpn_core::operation::validate_name(name.trim()) {
        return json_err(400, error);
    }
    let password = match password_field(body) {
        Ok(password) => password,
        Err(error) => return json_err(400, error),
    };
    if let Err(error) = rvpn_core::operation::validate_password(&password) {
        return json_err(400, error);
    }
    if body_str(body, "confirmPassword").as_deref() != Some(password.as_str()) {
        return json_err(400, "两次密码输入不一致");
    }
    let frame = Commands::create_network_with_password(name.trim(), &password, next_request_id());
    match send(frame) {
        Ok(rid) => json_ok(serde_json::json!({
            "requestId": rid, "created": name, "withPassword": !password.is_empty()
        })),
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

    if parts.len() != 2 && !(parts.len() == 4 && parts[1] == "members") {
        return json_err(404, "未知网络操作路径");
    }
    if parts.len() == 4 {
        let node_id: u64 = match parts[2].parse() {
            Ok(n) if n > 0 => n,
            _ => return json_err(400, "nodeId 需要是正整数"),
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
                .and_then(|v| v.get("enabled").and_then(|x| x.as_bool()));
            let Some(on) = on else {
                return json_err(400, "enabled 必须为布尔值");
            };
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
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect()
}
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_commands_do_not_reach_the_service() {
        assert_eq!(api_power("{}").0, 400);
        assert_eq!(api_alias(r#"{"alias":"  "}"#).0, 400);
        assert_eq!(api_join(r#"{"name":""}"#).0, 400);
        assert_eq!(api_create(r#"{"name":"test","password":123}"#).0, 400);
        assert_eq!(
            api_network_op(
                "/api/networks/00112233445566778899aabbccddeeff/leave/extra",
                "{}"
            )
            .0,
            404
        );
        assert_eq!(
            api_network_op(
                "/api/networks/00112233445566778899aabbccddeeff/members/0/kick",
                "{}"
            )
            .0,
            400
        );
    }
    #[test]
    fn strict_guid() {
        assert_eq!(
            hex_to_bytes("00112233445566778899aabbccddeeff")
                .unwrap()
                .len(),
            16
        );
        assert!(hex_to_bytes("junk00112233445566778899aabbccddeeff").is_none());
        assert!(hex_to_bytes("中").is_none());
    }
    #[test]
    fn decode_handles_malformed_unicode() {
        assert_eq!(urldecode("%E4%B8%AD+abc"), "中 abc");
        assert_eq!(urldecode("%中%GG%"), "%中%GG%");
    }
}
// ───────────────────────────────────────────────────── 界面

const UI: &str = include_str!("ui.html");
