//! Shared presentation helpers. Never export reversible password tokens.
use crate::{MemberInfo, NetworkInfo, SelfInfo, SnapshotState};
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn state_json(state: &SnapshotState, can_write: bool, demo: bool) -> Value {
    json!({
        "canWrite": can_write, "demo": demo, "power":state.power, "serviceState":state.service_state,
        "self": state.me.as_ref().map(|m| json!({
            "nodeId": m.node_id.to_string(), "alias": m.alias,
            "publicIp": m.public_ip, "virtualIp": m.virtual_ip, "virtualIpv6":m.virtual_ipv6,
        })),
        "networkCount": state.networks.len(), "memberCount": state.member_count(),
        "uniqueMemberCount": state.networks.iter().flat_map(|n| n.members.iter().map(|m| m.node_id)).collect::<HashSet<_>>().len(),
        "nodeCount": state.nodes.len(),
        "networks": state.networks.iter().map(|n| json!({
            "name": n.name, "guid": n.guid_hex(), "role": n.role, "networkType":n.network_type,
            "enabled":n.enabled,"blockNewMembers":n.block_new_members,"allowPasswordless":n.allow_passwordless,"community":n.community,
            "members": n.members.iter().map(|m| json!({
                "nodeId": m.node_id.to_string(), "alias": m.alias, "publicIp": m.public_ip,
                "virtualIp":m.virtual_ip,"virtualIpv6":m.virtual_ipv6,"role":m.role,
                "online":m.online(),"connectionStatus":m.connection_status,"channelType":m.channel_type,
                "latencyMs":m.latency_ms,"productVersion":m.product_version,
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })
}

/// Explicit read-only preview; public addresses use the documentation range.
pub fn demo_state() -> SnapshotState {
    let groups = [
        ("周末开黑小队", 8, 2),
        ("Minecraft · 建造日记", 12, 1),
        ("朋友们的星露谷", 5, 2),
        ("独立游戏实验室", 7, 1),
        ("Terraria · 远征世界", 6, 1),
        ("深夜联机俱乐部", 9, 1),
    ];
    let names = [
        "小狐狸",
        "NorthStar",
        "木木",
        "CloudWalker",
        "橘子汽水",
        "Pixel_01",
        "蓝莓",
        "Sunday",
        "半夏",
        "Luna",
        "Moss",
        "阿白",
    ];
    let networks = groups
        .iter()
        .enumerate()
        .map(|(i, (name, count, role))| NetworkInfo {
            name: (*name).into(),
            guid: vec![(i + 1) as u8; 16],
            token: None,
            role: Some(*role),
            members: (0..*count)
                .map(|j| MemberInfo {
                    node_id: 100_000 + j as u64,
                    alias: Some(names[j % names.len()].into()),
                    public_ip: Some(format!("192.0.2.{}", j + 10)),
                    virtual_ip: Some(format!("26.0.0.{}", j + 10)),
                    virtual_ipv6: Some(format!("fdfd::1a00:{:x}", j + 10)),
                    role: Some(if j == 0 { *role } else { 1 }),
                    connection_status: Some(if j % 4 == 3 { 0 } else { 1 }),
                    channel_type: Some(0),
                    latency_ms: Some(8 + j as u32 * 3),
                    product_version: Some("2.1.1".into()),
                })
                .collect(),
            network_type: Some(0),
            enabled: Some(true),
            block_new_members: Some(false),
            allow_passwordless: Some(true),
            ..Default::default()
        })
        .collect();
    SnapshotState {
        me: Some(SelfInfo {
            node_id: 100_000,
            alias: Some("我的游戏工作站".into()),
            public_ip: Some("192.0.2.10".into()),
            virtual_ip: Some("26.0.0.10".into()),
            virtual_ipv6: Some("fdfd::1a00:a".into()),
        }),
        networks,
        nodes: (100_000..100_012).collect(),
        power: Some(true),
        service_state: Some(4),
    }
}

/// Escape CSV and guard against spreadsheet formula execution.
pub fn csv_field(value: &str) -> String {
    let guarded = if value
        .trim_start()
        .starts_with(['=', '+', '-', '@', '\t', '\r'])
    {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", guarded.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_omits_tokens_and_preserves_large_ids() {
        let mut state = demo_state();
        state.networks[0].token = Some("sensitive".into());
        state.networks[0].members[0].node_id = u64::MAX;
        let value = state_json(&state, false, true);
        assert!(!value.to_string().contains("sensitive"));
        assert_eq!(
            value["networks"][0]["members"][0]["nodeId"],
            u64::MAX.to_string()
        );
        assert_eq!(value["uniqueMemberCount"], 13);
    }
    #[test]
    fn csv_escapes_cells() {
        assert_eq!(csv_field("a,\"b"), "\"a,\"\"b\"");
        assert_eq!(csv_field("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_field("中文"), "\"中文\"");
    }
}
