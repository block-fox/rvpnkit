//! Bounded HTTP/1 request parsing for the small embedded server.
use std::io::{self, BufRead};

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: String,
}

const MAX_LINE: usize = 4096;
const MAX_HEADERS: usize = 16384;
const MAX_BODY: usize = 65536;

fn line(reader: &mut impl BufRead) -> Result<String, (u16, String)> {
    let mut buf = Vec::new();
    loop {
        let chunk = reader.fill_buf().map_err(|e| (400, e.to_string()))?;
        if chunk.is_empty() {
            return Err((400, "请求意外结束".into()));
        }
        let n = chunk
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(chunk.len());
        if buf.len() + n > MAX_LINE {
            return Err((413, "请求行过长".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        reader.consume(n);
        if buf.last() == Some(&b'\n') {
            break;
        }
    }
    String::from_utf8(buf).map_err(|_| (400, "请求头必须为 UTF-8".into()))
}

pub fn read_request(reader: &mut impl BufRead) -> Result<Request, (u16, String)> {
    let first = line(reader)?;
    let parts: Vec<_> = first.split_whitespace().collect();
    if parts.len() != 3
        || parts[2] != "HTTP/1.1"
        || !parts[1].starts_with('/')
        || parts[1].contains(['\r', '\n', '\0'])
    {
        return Err((400, "无效的 HTTP 请求".into()));
    }
    if !matches!(parts[0], "GET" | "POST") {
        return Err((405, "只支持 GET / POST".into()));
    }
    let (method, target) = (parts[0].to_owned(), parts[1].to_owned());
    let (mut length, mut host, mut origin, mut content_type) = (None, None, None, None);
    let mut total = 0;
    loop {
        let h = line(reader)?;
        total += h.len();
        if total > MAX_HEADERS {
            return Err((413, "请求头过大".into()));
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        let (k, v) = h
            .trim_end_matches(['\r', '\n'])
            .split_once(':')
            .ok_or((400, "无效请求头".into()))?;
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    return Err((400, "重复 Content-Length".into()));
                }
                let n = v
                    .parse::<usize>()
                    .map_err(|_| (400, "无效 Content-Length".into()))?;
                if n > MAX_BODY {
                    return Err((413, "请求体过大".into()));
                }
                length = Some(n);
            }
            "host" => {
                if host.replace(v.to_owned()).is_some() {
                    return Err((400, "重复 Host".into()));
                }
            }
            "origin" => {
                if origin.replace(v.to_owned()).is_some() {
                    return Err((400, "重复 Origin".into()));
                }
            }
            "content-type" => content_type = Some(v.to_ascii_lowercase()),
            "transfer-encoding" => return Err((400, "不支持分块请求体".into())),
            _ => {}
        }
    }
    let host = host
        .filter(|h| !h.is_empty())
        .ok_or((400, "缺少 Host".into()))?;
    // No CORS: browser writes must originate from this workspace and use JSON.
    if method == "POST" {
        if !content_type
            .as_deref()
            .is_some_and(|t| t.split(';').next() == Some("application/json"))
        {
            return Err((415, "写操作要求 application/json".into()));
        }
        if origin.is_some_and(|o| o != format!("http://{host}")) {
            return Err((403, "拒绝跨来源写操作".into()));
        }
    }
    let mut body = vec![0; length.unwrap_or(0)];
    io::Read::read_exact(reader, &mut body).map_err(|e| (400, e.to_string()))?;
    let body = String::from_utf8(body).map_err(|_| (400, "请求体必须为 UTF-8".into()))?;
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    Ok(Request {
        method,
        path: path.into(),
        query: query.into(),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> Result<Request, (u16, String)> {
        read_request(&mut io::Cursor::new(s))
    }
    #[test]
    fn accepts_json_and_unicode() {
        let req = parse("POST /api/alias HTTP/1.1\r\nHost: localhost:8788\r\nOrigin: http://localhost:8788\r\nContent-Type: application/json\r\nContent-Length: 6\r\n\r\n狐狸").unwrap();
        assert_eq!(req.body, "狐狸");
    }
    #[test]
    fn rejects_oversized_truncated_and_ambiguous_requests() {
        for request in [
            "GET / HTTP/1.1\r\nHost: localhost\r\n",
            "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(parse(request).is_err());
        }
    }
    #[test]
    fn rejects_cross_origin_and_form_posts() {
        assert_eq!(parse("POST /api/power HTTP/1.1\r\nHost: localhost:8788\r\nOrigin: http://evil.test\r\nContent-Type: application/json\r\n\r\n").err().unwrap().0,403);
        assert_eq!(
            parse("POST /api/power HTTP/1.1\r\nHost: localhost:8788\r\n\r\n")
                .err()
                .unwrap()
                .0,
            415
        );
    }
}
