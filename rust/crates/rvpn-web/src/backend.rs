//! Tiny bounded HTTP client for the optional .NET agent. No TLS or CDN dependencies.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub enum Backend {
    Pipe,
    Demo,
    Http {
        base: String,
        authority: String,
        token: Option<String>,
    },
}
impl Backend {
    pub fn http(base: &str) -> Option<Self> {
        let authority = base.strip_prefix("http://")?.trim_end_matches('/');
        if authority.is_empty()
            || authority
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '@'))
        {
            return None;
        }
        let authority = if authority.starts_with('[') {
            let end = authority.find(']')?;
            authority[1..end].parse::<std::net::Ipv6Addr>().ok()?;
            if end + 1 == authority.len() {
                format!("{authority}:80")
            } else {
                authority
                    .get(end + 1..)?
                    .strip_prefix(':')?
                    .parse::<u16>()
                    .ok()?;
                authority.to_owned()
            }
        } else if authority.contains(':') {
            let (host, port) = authority.rsplit_once(':')?;
            if host.is_empty() || host.contains(':') {
                return None;
            }
            port.parse::<u16>().ok()?;
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        let token = std::env::var("RVPNKIT_TOKEN")
            .ok()
            .filter(|t| !t.contains(['\r', '\n']));
        Some(Self::Http {
            base: base.trim_end_matches('/').into(),
            authority,
            token,
        })
    }
    pub fn label(&self) -> String {
        match self {
            Self::Pipe => "直连命名管道".into(),
            Self::Demo => "只读演示工作空间".into(),
            Self::Http { base, .. } => format!("HTTP · {base}"),
        }
    }
    pub fn probe(&self) -> bool {
        match self {
            Self::Pipe => rvpn_core::pipe::PipeClient::connect(rvpn_core::DEFAULT_PIPE).is_ok(),
            Self::Demo => true,
            Self::Http { .. } => http_get(self, "/health").is_ok_and(|(status, _)| status == 200),
        }
    }
}

pub fn http_get(backend: &Backend, path: &str) -> Result<(u16, String), String> {
    request(backend, path, None)
}
pub fn http_post(backend: &Backend, path: &str, body: &str) -> Result<(u16, String), String> {
    request(backend, path, Some(body))
}
fn request(backend: &Backend, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let Backend::Http {
        authority, token, ..
    } = backend
    else {
        return Err("不是 HTTP 后端".into());
    };
    if !path.starts_with('/') || path.contains(['\r', '\n', ' ']) {
        return Err("无效请求路径".into());
    }
    let mut stream = None;
    for addr in authority.to_socket_addrs().map_err(|e| e.to_string())? {
        if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream.ok_or_else(|| format!("无法连接 agent {authority}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let method = if body.is_some() { "POST" } else { "GET" };
    let token = token
        .as_ref()
        .map(|t| format!("X-Api-Token: {t}\r\n"))
        .unwrap_or_default();
    let payload = body.unwrap_or("");
    write!(stream,"{method} {path} HTTP/1.1\r\nHost: {authority}\r\n{token}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",payload.len()).map_err(|e|e.to_string())?;
    read_response(&mut BufReader::new(stream))
}

const MAX_RESPONSE: usize = 8 * 1024 * 1024;
fn line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(8193)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > 8192 || bytes.last() != Some(&b'\n') {
        return Err("agent 响应头不完整或过长".into());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
fn read_response(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    let status_line = line(reader)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or("无效 agent 状态行")?;
    let (mut length, mut chunked, mut header_bytes) = (None, false, 0);
    loop {
        let h = line(reader)?;
        header_bytes += h.len();
        if header_bytes > 32768 {
            return Err("agent 响应头过大".into());
        }
        if h.trim().is_empty() {
            break;
        }
        let (key, value) = h.trim_end().split_once(':').ok_or("无效 agent 响应头")?;
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("重复 agent Content-Length".into());
            }
            let n = value
                .trim()
                .parse::<usize>()
                .map_err(|_| "无效 agent Content-Length")?;
            if n > MAX_RESPONSE {
                return Err("agent 响应体过大".into());
            }
            length = Some(n);
        }
        if key.eq_ignore_ascii_case("transfer-encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err("不支持该传输编码".into());
            }
            chunked = true;
        }
    }
    let mut bytes = Vec::new();
    if chunked {
        loop {
            let size_line = line(reader)?;
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| "无效 chunk 大小")?;
            if size == 0 {
                break;
            }
            if size > MAX_RESPONSE - bytes.len() {
                return Err("agent 分块响应过大".into());
            }
            let start = bytes.len();
            bytes.resize(start + size, 0);
            reader
                .read_exact(&mut bytes[start..])
                .map_err(|e| e.to_string())?;
            let mut crlf = [0; 2];
            reader.read_exact(&mut crlf).map_err(|e| e.to_string())?;
            if crlf != *b"\r\n" {
                return Err("无效 chunk 结尾".into());
            }
        }
    } else if let Some(n) = length {
        bytes.resize(n, 0);
        reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    } else {
        reader
            .take((MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_RESPONSE {
            return Err("agent 响应过大".into());
        }
    }
    let body = String::from_utf8(bytes).map_err(|e| format!("agent 响应不是 UTF-8：{e}"))?;
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_agent_urls() {
        for url in [
            "http://localhost:8770",
            "http://127.0.0.1:8770/",
            "http://[::1]:8770",
        ] {
            assert!(Backend::http(url).is_some());
        }
        for url in [
            "https://localhost",
            "http://",
            "http://a/path",
            "http://a:bad",
            "http://a\r\nX: y",
            "http://user@host",
        ] {
            assert!(Backend::http(url).is_none());
        }
    }
    #[test]
    fn decodes_utf8_split_between_chunks() {
        let response=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=yes\r\n\xe4\r\n2\r\n\xb8\xad\r\n0\r\n\r\n";
        assert_eq!(
            read_response(&mut std::io::Cursor::new(response))
                .unwrap()
                .1,
            "中"
        );
    }
    #[test]
    fn rejects_invalid_and_truncated_response() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\na",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nnope\r\n",
        ] {
            assert!(read_response(&mut std::io::Cursor::new(response)).is_err());
        }
    }
}
