//! 后端抽象：直连管道 或 转发给远程 agent。
//!
//! 直连模式在进程内通过命名管道和 Radmin 服务通信，没有 HTTP、没有 JSON、
//! 没有中间进程，延迟最低。HTTP 模式则把同样的操作转发给 `rvpnkit-agent`
//! （.NET 版）或任何实现了同一套 REST 的服务，用于 Linux/macOS 或远程管理。
//!
//! HTTP 客户端没有引 reqwest/ureq —— 那会带来 openssl/rustls 之类的重依赖，
//! 而这里只需要对本机/局域网的明文 HTTP 说几句话，用 `std::net::TcpStream`
//! 手写一个极简客户端反而更可控。

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// 后端类型。
pub enum Backend {
    /// 进程内直连命名管道。
    Pipe,
    /// 转发到远程 agent 的 REST 接口。
    Http { base: String, host: String, port: u16 },
}

impl Backend {
    /// 解析 `--agent http://127.0.0.1:8770` 这类地址。
    pub fn http(base: &str) -> Option<Self> {
        let rest = base.strip_prefix("http://")?;
        let (hostport, _) = match rest.split_once('/') {
            Some((h, _)) => (h, ()),
            None => (rest, ()),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (hostport.to_string(), 80),
        };
        Some(Self::Http {
            base: format!("http://{hostport}"),
            host,
            port,
        })
    }

    /// 展示名。
    pub fn label(&self) -> String {
        match self {
            Backend::Pipe => "直连管道（最快）".to_string(),
            Backend::Http { base, .. } => format!("HTTP · {base}"),
        }
    }

    /// 探测后端可用性。
    pub fn probe(&self) -> bool {
        match self {
            Backend::Pipe => {
                rvpn_core::pipe::PipeClient::connect(rvpn_core::DEFAULT_PIPE).is_ok()
            }
            Backend::Http { .. } => http_get(self, "/health").map(|(s, _)| s == 200).unwrap_or(false),
        }
    }
}

/// 发一个 GET，返回 (状态码, 响应体)。
pub fn http_get(backend: &Backend, path: &str) -> Result<(u16, String), String> {
    let Backend::Http { host, port, .. } = backend else {
        return Err("不是 HTTP 后端".into());
    };
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("连接 {addr} 失败：{e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    read_response(stream)
}

/// 发一个 POST（JSON 体）。
pub fn http_post(backend: &Backend, path: &str, body: &str) -> Result<(u16, String), String> {
    let Backend::Http { host, port, .. } = backend else {
        return Err("不是 HTTP 后端".into());
    };
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("连接 {addr} 失败：{e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    read_response(stream)
}

fn read_response(stream: TcpStream) -> Result<(u16, String), String> {
    let mut reader = BufReader::new(stream);

    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(|e| e.to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("无法解析状态行：{status_line:?}"))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let mut body = String::new();
    if chunked {
        // 极简 chunked 解码
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).map_err(|e| e.to_string())? == 0 {
                break;
            }
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let mut buf = vec![0u8; size + 2];
            reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
            body.push_str(&String::from_utf8_lossy(&buf[..size]));
        }
    } else if let Some(n) = content_length {
        let mut buf = vec![0u8; n];
        reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        body = String::from_utf8_lossy(&buf).to_string();
    } else {
        let mut s = String::new();
        reader.read_to_string(&mut s).map_err(|e| e.to_string())?;
        body = s;
    }

    Ok((status, body))
}

/// 从 agent 的 `{"ok":true,"data":...}` 信封里取 data；失败则取 error。
pub fn unwrap_envelope(status: u16, body: &str) -> Result<serde_json::Value, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("响应不是 JSON：{e}"))?;

    if status == 200 {
        if let Some(d) = v.get("data") {
            return Ok(d.clone());
        }
    }
    let msg = v
        .get("error")
        .and_then(|e| e.as_str())
        .unwrap_or("未知错误");
    Err(format!("agent 返回 {status}：{msg}"))
}
