//! Request-correlated service completion, separate from transport success.
use crate::{Record, Wire};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Completion {
    pub request_id: u32,
    pub command: u32,
    pub error_code: u32,
}
impl Completion {
    pub fn find(raw: &[u8], request_id: u32) -> Option<Self> {
        fn number(records: &[Record], field: u8) -> Option<u32> {
            records
                .iter()
                .find(|r| r.field == field && r.ty == 1 && r.payload.len() == 4)
                .map(Record::as_u32)
        }
        for frame in Wire::split_frames(raw) {
            let records = Wire::parse(&frame);
            if number(&records, 0x4a) == Some(request_id) {
                if let (Some(command), Some(error_code)) =
                    (number(&records, 0), number(&records, 0x10))
                {
                    return Some(Self {
                        request_id,
                        command,
                        error_code,
                    });
                }
            }
        }
        None
    }
    pub fn into_result(self) -> Result<Self, String> {
        if self.error_code == 0 {
            Ok(self)
        } else {
            Err(format!(
                "{}（服务代码 0x{:08x}，请求 #{}）",
                friendly_error(self.error_code),
                self.error_code,
                self.request_id
            ))
        }
    }
}
pub fn friendly_error(code: u32) -> &'static str {
    match code {
        0 => "操作完成",
        5 => "服务拒绝访问，请检查网络管理权限",
        87 => "请求参数无效",
        258 | 1460 => "等待服务响应超时",
        995 => "操作已取消",
        0x3f7 => "密码至少需要 6 个 UTF-16 字符",
        0x406 => "网络名称超过服务允许的长度",
        _ => "服务未能完成操作",
    }
}
pub fn validate_name(name: &str) -> Result<(), String> {
    let length = name.encode_utf16().count();
    if name.trim().is_empty() || length > 20 || name.chars().any(char::is_control) {
        Err("网络名称需要 1–20 个 UTF-16 字符，不能含控制字符".into())
    } else {
        Ok(())
    }
}
pub fn validate_password(password: &str) -> Result<(), String> {
    let length = password.encode_utf16().count();
    if !(6..=256).contains(&length) || password.contains('\0') {
        Err("密码需要 6–256 个 UTF-16 字符".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Frame;
    fn packet(request: u32, error: u32) -> Vec<u8> {
        let mut f = Frame::new();
        f.u32(0, 5).u32(0x10, error).u32(0x4a, request);
        let body = f.into_bytes();
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend(body);
        out
    }
    #[test]
    fn requires_matching_request_and_explicit_result() {
        assert!(Completion::find(&packet(9, 0), 10).is_none());
        assert!(Completion::find(&packet(9, 0), 9)
            .unwrap()
            .into_result()
            .is_ok());
        assert!(Completion::find(&packet(9, 5), 9)
            .unwrap()
            .into_result()
            .unwrap_err()
            .contains("权限"));
    }
    #[test]
    fn validates_unicode_length_and_password() {
        assert!(validate_name(&"狐".repeat(20)).is_ok());
        assert!(validate_name(&"🦊".repeat(11)).is_err());
        assert!(validate_password("12345").is_err());
        assert!(validate_password("密码1234").is_ok());
    }
}
