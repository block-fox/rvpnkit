//! The same authorization checks are used by both frontends.
use crate::{SnapshotState, Wire};
pub fn authorize(frame: &[u8], state: &SnapshotState) -> Result<(), String> {
    let records = Wire::parse(frame);
    let command = records
        .iter()
        .find(|r| r.field == 0 && r.ty == 1)
        .map(|r| r.as_u32())
        .ok_or("命令缺少类型")?;
    if ![5, 6, 8, 10, 14, 15, 16, 17].contains(&command) {
        return Ok(());
    }
    let guid = records
        .iter()
        .find(|r| r.field == 9 && r.ty == 13)
        .map(|r| r.payload.as_slice())
        .ok_or("命令缺少网络标识")?;
    let net = state
        .networks
        .iter()
        .find(|n| n.guid == guid)
        .ok_or("网络已经不存在，请刷新")?;
    let me = state.me.as_ref().map(|m| m.node_id);
    if command == 5 {
        if net.can_manage() && net.members.iter().filter(|m| m.role == Some(2)).count() <= 1 {
            return Err("你是最后一位管理员；请先移交管理权限，或删除网络".into());
        }
    } else if command != 8 && !net.can_manage() {
        return Err("此操作需要该网络的管理员权限".into());
    }
    if [6, 10, 16, 17].contains(&command) {
        let id = records
            .iter()
            .find(|r| r.field == 0xe1 && r.ty == 2)
            .map(|r| r.as_u64())
            .ok_or("命令缺少成员标识")?;
        if Some(id) == me {
            return Err("不能对本机执行此成员管理操作".into());
        }
        if !net.members.iter().any(|m| m.node_id == id) {
            return Err("成员已经不在当前网络".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandCode, Commands};
    #[test]
    fn protects_self_and_checks_actual_membership_role() {
        let mut state = crate::presentation::demo_state();
        let net = &state.networks[0];
        let guid = net.guid.clone();
        let id = state.me.as_ref().unwrap().node_id;
        assert!(authorize(
            &Commands::member_operation(CommandCode::KickNode, &guid, id, "", 1),
            &state
        )
        .is_err());
        assert!(authorize(&Commands::leave_network(&guid, 2), &state).is_err());
        assert!(authorize(&Commands::delete_network(&guid, 3), &state).is_ok());
        state.networks[0].role = Some(1);
        assert!(authorize(&Commands::delete_network(&guid, 4), &state).is_err());
        assert!(authorize(&Commands::set_network_enabled(&guid, false, 5), &state).is_ok());
    }
}
