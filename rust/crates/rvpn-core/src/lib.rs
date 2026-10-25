//! # rvpn-core
//!
//! Radmin VPN 控制协议的纯 Rust 实现：帧编解码、命令构造、快照解析。
//!
//! 这个 crate 只处理「字节长什么样」，不碰任何平台专有 API
//! （命名管道传输在 [`pipe`] 里，且用 `cfg(windows)` 隔离）。
//!
//! ## 线格式
//!
//! 一条消息由若干「记录」顺次拼成，记录形如：
//!
//! ```text
//! [size:u32 BE][类型码:u8][0x00][0x03][字段:u8][payload:size 字节]
//! ```
//!
//! 第 3、4 字节普通记录固定是 `00 03`；**节点 ID 记录例外**，是 `00 01`。
//!
//! 字符串是 **UTF-16 大端**，末尾跟 2 字节 `00 01`。
//!
//! 发送时最外层还要再套一个 `u32 LE` 长度前缀（由传输层负责）。

pub mod api;
pub mod commands;
pub mod connections;
pub mod desktop;
pub mod firewall;
pub mod operation;
pub mod permissions;
pub mod pipe;
pub mod presentation;
pub mod snapshot;
pub mod wire;

pub use commands::{CommandCode, Commands};
pub use snapshot::{MemberInfo, NetworkInfo, PublicNetworks, SelfInfo, SnapshotState};
pub use wire::{
    decode_string, encode_string, field, looks_like_frame, tag, Frame, Record, RecordType, Wire,
};

/// 默认管道路径。
pub const DEFAULT_PIPE: &str = r"\\.\pipe\RadminVpnGuiChannel";
