//! Small read-only HTTP API shared by the native GUI and WebUI.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind_ip: String,
    pub port: u16,
    pub token: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_ip: "127.0.0.1".into(),
            port: 8790,
            token: String::new(),
        }
    }
}

impl ApiConfig {
    pub fn socket_address(&self) -> Result<String, String> {
        let ip: IpAddr = self
            .bind_ip
            .trim()
            .parse()
            .map_err(|_| "API 绑定 IP 必须是有效的 IPv4 或 IPv6 地址".to_string())?;
        if self.port == 0 {
            return Err("API 端口必须在 1 到 65535 之间".into());
        }
        if self
            .token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err("API 令牌不能包含空白或控制字符".into());
        }
        Ok(match ip {
            IpAddr::V4(_) => format!("{ip}:{}", self.port),
            IpAddr::V6(_) => format!("[{ip}]:{}", self.port),
        })
    }
}

pub type SnapshotProvider = Arc<dyn Fn() -> Result<Value, String> + Send + Sync + 'static>;

pub struct ApiHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    pub address: String,
}

const MAX_CONNECTIONS: usize = 32;

impl ApiHandle {
    pub fn spawn(config: &ApiConfig, provider: SnapshotProvider) -> Result<Self, String> {
        let address = config.socket_address()?;
        let listener =
            TcpListener::bind(&address).map_err(|e| format!("无法监听 API {address}：{e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("无法配置 API 监听器：{e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let token = config.token.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let join = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                            active.fetch_sub(1, Ordering::AcqRel);
                            let mut stream = stream;
                            let _ = stream.write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                            continue;
                        }
                        let token = token.clone();
                        let provider = Arc::clone(&provider);
                        let active = Arc::clone(&active);
                        thread::spawn(move || {
                            handle_stream(stream, &token, &provider);
                            active.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(40));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            join: Some(join),
            address,
        })
    }
}

impl Drop for ApiHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(&self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_stream(stream: TcpStream, token: &str, provider: &SnapshotProvider) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() || first.len() > 4096 {
        return;
    }
    let parts: Vec<_> = first.split_whitespace().collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" || parts[0] != "GET" {
        write_response(
            reader.get_mut(),
            405,
            json!({"ok":false,"error":"只支持 GET /api/state 等只读接口"}),
        );
        return;
    }
    let target = parts[1];
    let mut provided_token = None;
    let mut headers = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.len() > 8192 {
            return;
        }
        headers += line.len();
        if headers > 16384 {
            write_response(
                reader.get_mut(),
                413,
                json!({"ok":false,"error":"请求头过大"}),
            );
            return;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            if name.eq_ignore_ascii_case("x-api-token") {
                provided_token = Some(value.trim().to_owned());
            }
        }
    }
    let (path, query_token) = target.split_once('?').unwrap_or((target, ""));
    if provided_token.is_none() {
        provided_token = query_token
            .split('&')
            .find_map(|item| item.strip_prefix("token="))
            .map(str::to_owned);
    }
    if !token.is_empty() && provided_token.as_deref() != Some(token) {
        write_response(
            reader.get_mut(),
            401,
            json!({"ok":false,"error":"API 令牌无效或缺失"}),
        );
        return;
    }
    let response = match path {
        "/health" => json!({"ok":true,"data":{"service":"rvpnkit-read-api","readOnly":true}}),
        "/api/state" => match provider() {
            Ok(data) => json!({"ok":true,"data":data}),
            Err(error) => json!({"ok":false,"error":error}),
        },
        "/api/schema" => json!({
            "ok": true,
            "data": {
                "version": "1",
                "readOnly": true,
                "endpoints": ["GET /health", "GET /api/state", "GET /api/schema"]
            }
        }),
        _ => json!({"ok":false,"error":"未找到只读 API 接口"}),
    };
    let status = if matches!(path, "/health" | "/api/state" | "/api/schema") {
        200
    } else {
        404
    };
    write_response(reader.get_mut(), status, response);
}

fn write_response(stream: &mut TcpStream, status: u16, body: Value) {
    let bytes = body.to_string().into_bytes();
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let _ = stream.write_all(&bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_bindings() {
        let mut config = ApiConfig::default();
        assert_eq!(config.socket_address().unwrap(), "127.0.0.1:8790");
        config.bind_ip = "not-an-ip".into();
        assert!(config.socket_address().is_err());
    }
}
