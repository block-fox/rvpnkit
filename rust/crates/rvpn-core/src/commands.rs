//! 命令构造。返回的是「正文」，发送时由传输层补 4 字节长度前缀。

use crate::wire::{field, tag, Frame, RecordType};

/// 命令码。数值来自抓包 + 服务端日志语义核对 + 命令码扫描。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CommandCode {
    /// 创建网络。`Requested to create network`
    CreateNetwork = 0x02,
    /// 加入网络。`Requested to join network`
    JoinNetwork = 0x03,
    /// VPN 总开关。`Switched On/Off`
    SwitchPower = 0x04,
    /// 离开网络。`Requested to leave network`
    LeaveNetwork = 0x05,
    /// 踢出成员。`Requested to remove ... from network`
    KickNode = 0x06,
    /// 启用/禁用网络。`Enabled/Disabled network`
    SetNetworkEnabled = 0x08,
    /// 批准加入。`Requested to approve join`
    ApproveJoin = 0x0a,
    /// 删除网络。`Requested to delete network`
    DeleteNetwork = 0x0f,
    /// 授予管理员。
    GrantAdmin = 0x10,
    /// 撤销管理员。
    RevokeAdmin = 0x11,
    /// 修改本机别名。
    ChangeAlias = 0x12,
    /// 枚举公共网络（结果以管道响应返回，不写日志）。
    EnumPublicNetworks = 0x13,
}

fn head(request_id: u32, code: CommandCode) -> Frame {
    let mut f = Frame::new();
    f.u32(field::REQUEST_ID, request_id)
        .u32(field::COMMAND, code as u32);
    f
}

/// 命令构造器。
pub struct Commands;

impl Commands {
    /// 创建网络。`key` 为 28 字节网络密钥，传 `None` 则随机生成（实测任意值均可）。
    pub fn create_network(name: &str, request_id: u32, key: Option<&[u8]>) -> Vec<u8> {
        let generated;
        let key = match key {
            Some(k) => k,
            None => {
                generated = random_bytes();
                &generated[..]
            }
        };
        assert_eq!(key.len(), 28, "网络密钥必须是 28 字节");

        let mut inner = Frame::new();
        inner
            .u32_alt(field::CREATE_FLAG, 0)
            .text(field::NETWORK_NAME, name)
            .blob(field::NETWORK_KEY, RecordType::UInt64, key);
        let inner = inner.into_bytes();

        let mut f = head(request_id, CommandCode::CreateNetwork);
        f.container(tag::CREATE, &inner);
        f.into_bytes()
    }

    /// 加入网络。
    pub fn join_network(name: &str, request_id: u32) -> Vec<u8> {
        let mut inner = Frame::new();
        inner
            .u32_alt(field::JOIN_FLAG, 1)
            .text(field::NETWORK_NAME, name);
        let inner = inner.into_bytes();

        let mut f = head(request_id, CommandCode::JoinNetwork);
        f.container(tag::JOIN, &inner);
        f.into_bytes()
    }

    /// VPN 总开关。
    pub fn switch_power(on: bool, request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::SwitchPower);
        f.u32_alt(field::POWER, if on { 1 } else { 0 });
        f.into_bytes()
    }

    /// 离开网络。
    pub fn leave_network(guid: &[u8], request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::LeaveNetwork);
        f.guid(field::NETWORK_GUID, guid);
        f.into_bytes()
    }

    /// 删除网络。
    pub fn delete_network(guid: &[u8], request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::DeleteNetwork);
        f.guid(field::NETWORK_GUID, guid);
        f.into_bytes()
    }

    /// 启用/禁用网络。
    pub fn set_network_enabled(guid: &[u8], enabled: bool, request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::SetNetworkEnabled);
        f.guid(field::NETWORK_GUID, guid)
            .u32_alt(field::ENABLED, if enabled { 1 } else { 0 });
        f.into_bytes()
    }

    /// 修改本机别名。
    pub fn change_alias(alias: &str, request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::ChangeAlias);
        f.text(field::ALIAS, alias);
        f.into_bytes()
    }

    /// 枚举公共网络；`prefix` 为空表示全部。
    pub fn enum_public_networks(prefix: &str, request_id: u32) -> Vec<u8> {
        let mut f = head(request_id, CommandCode::EnumPublicNetworks);
        f.text(field::NETWORK_NAME, prefix);
        f.into_bytes()
    }

    /// 成员类操作：踢人 / 批准 / 授管 / 撤管。载荷形状相同。
    pub fn member_operation(
        code: CommandCode,
        guid: &[u8],
        node_id: u64,
        network_name: &str,
        request_id: u32,
    ) -> Vec<u8> {
        assert!(
            matches!(
                code,
                CommandCode::KickNode
                    | CommandCode::ApproveJoin
                    | CommandCode::GrantAdmin
                    | CommandCode::RevokeAdmin
            ),
            "不支持的成员操作"
        );
        let mut f = head(request_id, code);
        f.guid(field::NETWORK_GUID, guid)
            .node_id(node_id)
            .text(field::NETWORK_NAME, network_name);
        f.into_bytes()
    }
}

/// 生成 28 字节随机密钥。
///
/// 不引 rand crate：用系统时间的纳秒 + 进程 id 混合，够用且零依赖。
/// 这个值只是给新网络当随机标识，不需要密码学强度。
fn random_bytes() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
        ^ (std::process::id() as u64) << 32;
    let mut out = Vec::with_capacity(28);
    for _ in 0..7 {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(28);
    out
}

/// 生成一个请求编号。
pub fn next_request_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345);
    (nanos % 0xFFFE) + 1
}
