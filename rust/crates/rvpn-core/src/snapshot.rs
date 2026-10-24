//! Typed service snapshots, audited against the installed 2.1.4951.1 serializer.
use crate::wire::{field, Record, RecordType, Wire};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkInfo {
    pub name: String,
    pub guid: Vec<u8>,
    #[serde(skip_serializing)]
    pub token: Option<String>,
    /// Local membership role, never the network's type field.
    pub role: Option<u32>,
    pub network_type: Option<u32>,
    pub flags: Option<u32>,
    pub enabled: Option<bool>,
    pub block_new_members: Option<bool>,
    pub allow_passwordless: Option<bool>,
    pub community: Option<String>,
    pub members: Vec<MemberInfo>,
}
impl NetworkInfo {
    pub fn guid_hex(&self) -> String {
        self.guid.iter().map(|b| format!("{b:02x}")).collect()
    }
    pub fn can_manage(&self) -> bool {
        self.role == Some(2)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MemberInfo {
    pub node_id: u64,
    pub alias: Option<String>,
    pub public_ip: Option<String>,
    pub virtual_ip: Option<String>,
    pub virtual_ipv6: Option<String>,
    pub role: Option<u32>,
    pub connection_status: Option<u32>,
    pub channel_type: Option<u32>,
    pub latency_ms: Option<u32>,
    pub product_version: Option<String>,
}
impl MemberInfo {
    pub fn label(&self) -> String {
        self.alias
            .as_ref()
            .filter(|s| !s.is_empty())
            .or(self.virtual_ip.as_ref())
            .or(self.public_ip.as_ref())
            .cloned()
            .unwrap_or_else(|| format!("#{}", self.node_id))
    }
    pub fn online(&self) -> Option<bool> {
        match self.connection_status {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        }
    }
    pub fn status_text(&self) -> &'static str {
        match self.online() {
            Some(true) => "在线",
            Some(false) => "离线",
            None => "未知",
        }
    }
    pub fn role_text(&self) -> &'static str {
        match self.role {
            Some(0) => "无权限",
            Some(1) => "成员",
            Some(2) => "管理员",
            Some(3) => "申请人",
            _ => "未知",
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SelfInfo {
    pub node_id: u64,
    pub alias: Option<String>,
    pub public_ip: Option<String>,
    pub virtual_ip: Option<String>,
    pub virtual_ipv6: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotState {
    pub me: Option<SelfInfo>,
    pub networks: Vec<NetworkInfo>,
    pub nodes: Vec<u64>,
    pub power: Option<bool>,
    pub service_state: Option<u32>,
}
fn scalar(records: &[Record], id: u8) -> Option<u32> {
    records
        .iter()
        .find(|r| r.field == id && matches!(r.ty, 1 | 11) && r.payload.len() == 4)
        .map(Record::as_u32)
}
fn text(records: &[Record], id: u8) -> Option<String> {
    records
        .iter()
        .find(|r| r.field == id && r.ty == 3)
        .and_then(Record::as_string)
}
fn node(records: &[Record]) -> Option<u64> {
    records
        .iter()
        .find(|r| r.field == field::NODE_ID && r.ty == 2 && r.payload.len() == 8)
        .map(Record::as_u64)
        .filter(|id| *id != 0)
}
fn addresses(records: &[Record]) -> (Option<String>, Option<String>) {
    let v4 = scalar(records, 5)
        .map(Ipv4Addr::from)
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| ip.to_string());
    let v6 = records
        .iter()
        .find(|r| r.field == 5 && r.ty == 9 && r.payload.len() == 16)
        .and_then(|r| <[u8; 16]>::try_from(r.payload.as_slice()).ok())
        .map(Ipv6Addr::from)
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| ip.to_string());
    (v4, v6)
}
impl SnapshotState {
    pub fn member_count(&self) -> usize {
        self.networks.iter().map(|n| n.members.len()).sum()
    }
    pub fn parse(raw: &[u8]) -> Self {
        let mut result = Self::default();
        let mut profiles = HashMap::<u64, MemberInfo>::new();
        let mut frames = Wire::split_frames(raw);
        if frames.is_empty() {
            frames.push(raw.to_vec());
        }
        for frame in frames {
            collect(&Wire::parse(&frame), &mut result, &mut profiles);
        }
        let local_id = result.me.as_ref().map(|me| me.node_id);
        let mut ids = BTreeSet::new();
        if let Some(id) = local_id {
            ids.insert(id);
        }
        let mut seen = HashSet::new();
        result.networks.retain(|n| seen.insert(n.guid.clone()));
        for network in &mut result.networks {
            for member in &mut network.members {
                ids.insert(member.node_id);
                if let Some(profile) = profiles.get(&member.node_id) {
                    let role = member.role;
                    *member = profile.clone();
                    member.role = role;
                }
                if Some(member.node_id) == local_id {
                    network.role = member.role;
                }
            }
        }
        ids.extend(profiles.keys());
        result.nodes = ids.into_iter().collect();
        result
    }
}
fn collect(
    records: &[Record],
    result: &mut SnapshotState,
    profiles: &mut HashMap<u64, MemberInfo>,
) {
    for record in records {
        let Some(children) = record.children.as_ref() else {
            continue;
        };
        match record.field {
            0x20 => {
                if let Some(node_id) = node(children) {
                    let (mut virtual_ip, virtual_ipv6) = addresses(children);
                    let alias = text(children, 4);
                    if virtual_ip.is_none() {
                        virtual_ip = alias
                            .as_ref()
                            .and_then(|s| s.parse::<Ipv4Addr>().ok())
                            .map(|ip| ip.to_string());
                    }
                    result.me = Some(SelfInfo {
                        node_id,
                        alias,
                        public_ip: text(children, 0xc9),
                        virtual_ip,
                        virtual_ipv6,
                    });
                }
                result.power = scalar(children, 0x11).and_then(|v| match v {
                    0 => Some(false),
                    1 => Some(true),
                    _ => None,
                });
                result.service_state = scalar(children, 0x12);
                collect(children, result, profiles);
            }
            0x22 => {
                if let Some(node_id) = node(children) {
                    let (virtual_ip, virtual_ipv6) = addresses(children);
                    profiles.insert(
                        node_id,
                        MemberInfo {
                            node_id,
                            alias: text(children, 4),
                            public_ip: text(children, 0xc9),
                            virtual_ip,
                            virtual_ipv6,
                            product_version: text(children, 0xed),
                            connection_status: scalar(children, 0x21).filter(|v| *v != u32::MAX),
                            channel_type: scalar(children, 0x26),
                            latency_ms: scalar(children, 0x3e).filter(|v| *v != u32::MAX),
                            ..Default::default()
                        },
                    );
                }
            }
            0x23 => {
                let guid = children
                    .iter()
                    .find(|r| r.field == 9 && r.ty == 13 && r.payload.len() == 16)
                    .map(|r| r.payload.clone());
                if let (Some(name), Some(guid)) = (text(children, 6), guid) {
                    let flags = scalar(children, 0xa3);
                    let mut network = NetworkInfo {
                        name,
                        guid,
                        network_type: scalar(children, 10),
                        flags,
                        token: text(children, 0x47),
                        community: text(children, 0x48),
                        enabled: flags
                            .map(|v| v & 1 != 0)
                            .or_else(|| scalar(children, 8).map(|v| v != 0)),
                        block_new_members: flags
                            .map(|v| v & 2 != 0)
                            .or_else(|| scalar(children, 0x23).map(|v| v != 0)),
                        allow_passwordless: flags
                            .map(|v| v & 4 != 0)
                            .or_else(|| scalar(children, 0x3f).map(|v| v != 0)),
                        ..Default::default()
                    };
                    let mut seen = HashSet::new();
                    for entry in children.iter().filter(|r| r.field == 0x24) {
                        if let Some(items) = &entry.children {
                            if let Some(node_id) = node(items) {
                                if seen.insert(node_id) {
                                    network.members.push(MemberInfo {
                                        node_id,
                                        role: scalar(items, 10),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                    result.networks.push(network);
                }
            }
            _ => collect(children, result, profiles),
        }
    }
}
pub struct PublicNetworks;
impl PublicNetworks {
    pub fn extract_names(raw: &[u8]) -> Vec<String> {
        fn visit(records: &[Record], out: &mut Vec<String>, seen: &mut HashSet<String>) {
            for r in records {
                if r.ty == RecordType::Str as u8 && r.field == field::NETWORK_NAME {
                    if let Some(name) = r.as_string() {
                        if !name.is_empty()
                            && name.chars().count() <= 128
                            && seen.insert(name.clone())
                        {
                            out.push(name);
                        }
                    }
                }
                if let Some(children) = &r.children {
                    visit(children, out, seen);
                }
            }
        }
        let mut frames = Wire::split_frames(raw);
        if frames.is_empty() {
            frames.push(raw.to_vec());
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for frame in frames {
            visit(&Wire::parse(&frame), &mut out, &mut seen);
        }
        out
    }
    pub fn available(raw: &[u8], joined: &[String], search: Option<&str>) -> Vec<String> {
        let needle = search.unwrap_or_default().to_lowercase();
        let mut names: Vec<_> = Self::extract_names(raw)
            .into_iter()
            .filter(|n| !joined.contains(n) && n.to_lowercase().contains(&needle))
            .collect();
        names.sort();
        names.dedup();
        names
    }
}
