use rvpn_core::commands::next_request_id;
use rvpn_core::pipe::PipeClient;
use rvpn_core::{Commands, PublicNetworks, SnapshotState, DEFAULT_PIPE};
use std::time::Duration;

pub(super) fn read_state() -> Result<(SnapshotState, bool), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    let can_write = pipe.can_write();
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;
    Ok((SnapshotState::parse(&raw), can_write))
}

pub(super) fn read_public(search: &str) -> Result<Vec<String>, String> {
    let joined: Vec<String> = {
        let mut p = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
        let raw = p
            .read_snapshot(Duration::from_millis(1500))
            .map_err(|e| e.to_string())?;
        SnapshotState::parse(&raw)
            .networks
            .into_iter()
            .map(|n| n.name)
            .collect()
    };

    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("只读连接无法枚举公共网络（需要可写）".into());
    }
    pipe.send(&Commands::enum_public_networks("", next_request_id()))
        .map_err(|e| e.to_string())?;
    let raw = pipe
        .read_snapshot(Duration::from_millis(2500))
        .map_err(|e| e.to_string())?;
    Ok(PublicNetworks::available(&raw, &joined, Some(search)))
}

pub(super) fn send_frame(frame: &[u8]) -> Result<(), String> {
    let mut pipe = PipeClient::connect(DEFAULT_PIPE).map_err(|e| e.to_string())?;
    if !pipe.can_write() {
        return Err("当前为只读连接。若程序运行在受限环境（Low 完整性），\
                    请用普通用户身份直接启动。"
            .into());
    }
    pipe.transact(frame, Duration::from_secs(8))
        .map(|_| ())
        .map_err(|e| e.to_string())
}
