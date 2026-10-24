//! 快照解析。
//!
//! 快照是「多帧拼接」：每帧 `[u32 LE 长度][正文]`，正文是记录流。
//!
//! ## 关键结构（实测）
//!
//! 网络和成员档案**不在同一棵子树里**，需要靠节点 ID 关联：
//!
//! ```text
//! 网络      容器 field 0x23
//!              field 0x09 (type 0x0d) 16 字节 GUID
//!              field 0x06 名字    field 0x47 token
//!              field 0x24 容器 × N   ← 成员，每个含 field 0xe1 节点 ID
//!
//! 成员档案  容器 field 0x22
//!              field 0xe1 节点 ID / field 0x04 别名 / field 0xc9 公网 IP
//!
//! 本机      容器 field 0x20 顶层的 field 0xe1 + 0x04 + 0xc9
//! ```
//!
//! 所以：网络 → 子容器里的节点 ID（结构性，可靠）→ 再按节点 ID 合并档案。

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::wire::{field, Record, RecordType, Wire};

const F_CONTAINER_NETWORK: u8 = 0x23;
const F_CONTAINER_MEMBER: u8 = 0x24;
const F_CONTAINER_PROFILE: u8 = 0x22;

/// 一个 Radmin 网络。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// 网络名。
    pub name: String,
    /// 16 字节网络标识。
    pub guid: Vec<u8>,
    /// 快照字段 `0x47` 的字符串。含义未确认：多个网络取值相同，且其中多数是免密码
    /// 加入的，所以大概率不是密码，更像某种会话令牌。
    pub token: Option<String>,
    /// 该网络下的成员。
    pub members: Vec<MemberInfo>,
}

impl NetworkInfo {
    /// GUID 的十六进制表示（无连字符）。
    pub fn guid_hex(&self) -> String {
        self.guid.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// 网络成员。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    /// 节点 ID，踢人/授管等命令要用。
    pub node_id: u64,
    /// 对方别名。
    pub alias: Option<String>,
    /// 对方公网出口 IP。
    pub public_ip: Option<String>,
}

impl MemberInfo {
    /// 便于显示的标签。
    pub fn label(&self) -> String {
        match (&self.alias, &self.public_ip) {
            (Some(a), _) if !a.is_empty() => a.clone(),
            (_, Some(ip)) if !ip.is_empty() => ip.clone(),
            _ => format!("#{}", self.node_id),
        }
    }
}

/// 本机信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfInfo {
    /// 本机节点 ID。
    pub node_id: u64,
    /// 本机别名。
    pub alias: Option<String>,
    /// 本机公网出口 IP。
    pub public_ip: Option<String>,
}

/// 解析出来的整体状态。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotState {
    /// 本机信息。
    pub me: Option<SelfInfo>,
    /// 已加入的网络。
    pub networks: Vec<NetworkInfo>,
    /// 快照里出现过的所有节点 ID。
    pub nodes: Vec<u64>,
}

impl SnapshotState {
    /// 所有网络的成员总数。
    pub fn member_count(&self) -> usize {
        self.networks.iter().map(|n| n.members.len()).sum()
    }

    /// 解析快照。
    pub fn parse(raw: &[u8]) -> Self {
        let mut networks: Vec<(String, Vec<u8>, Option<String>, Vec<u64>)> = Vec::new();
        let mut profiles: HashMap<u64, (Option<String>, Option<String>)> = HashMap::new();
        let mut nodes: BTreeSet<u64> = BTreeSet::new();
        let mut me: Option<SelfInfo> = None;

        let mut frames = Wire::split_frames(raw);
        if frames.is_empty() {
            frames.push(raw.to_vec());
        }

        for frame in &frames {
            walk(
                &Wire::parse(frame),
                &mut networks,
                &mut profiles,
                &mut nodes,
                &mut me,
                0,
            );
        }

        let mut seen = HashSet::new();
        let nets = networks
            .into_iter()
            .filter(|(name, guid, _, _)| seen.insert((name.clone(), guid.clone())))
            .map(|(name, guid, token, member_ids)| {
                let members = member_ids
                    .into_iter()
                    .map(|id| {
                        let p = profiles.get(&id);
                        MemberInfo {
                            node_id: id,
                            alias: p.and_then(|x| x.0.clone()),
                            public_ip: p.and_then(|x| x.1.clone()),
                        }
                    })
                    .collect();
                NetworkInfo {
                    name,
                    guid,
                    token,
                    members,
                }
            })
            .collect();

        Self {
            me,
            networks: nets,
            nodes: nodes.into_iter().collect(),
        }
    }
}

fn walk(
    records: &[Record],
    networks: &mut Vec<(String, Vec<u8>, Option<String>, Vec<u64>)>,
    profiles: &mut HashMap<u64, (Option<String>, Option<String>)>,
    nodes: &mut BTreeSet<u64>,
    me: &mut Option<SelfInfo>,
    depth: usize,
) {
    // 先把这一层的标量字段聚起来（可能属于本机条目）
    let mut local_node: Option<u64> = None;
    let mut local_alias: Option<String> = None;
    let mut local_ip: Option<String> = None;

    for r in records {
        if r.ty == RecordType::Str as u8 {
            if let Some(s) = r.as_string() {
                if s.len() <= 256 {
                    if r.field == field::ALIAS {
                        local_alias.get_or_insert(s);
                    } else if r.field == field::PUBLIC_IP {
                        local_ip.get_or_insert(s);
                    }
                }
            }
        }
        if r.ty == RecordType::NodeId as u8 && r.field == field::NODE_ID && r.payload.len() == 8 {
            let id = r.as_u64();
            if id != 0 {
                local_node.get_or_insert(id);
                nodes.insert(id);
            }
        }
    }

    if depth <= 1 && me.is_none() {
        if let Some(id) = local_node {
            *me = Some(SelfInfo {
                node_id: id,
                alias: local_alias.clone(),
                public_ip: local_ip.clone(),
            });
        }
    }

    for r in records {
        let Some(children) = &r.children else { continue };
        match r.field {
            F_CONTAINER_NETWORK => parse_network(children, networks, nodes),
            F_CONTAINER_PROFILE => parse_profile(children, profiles, nodes),
            _ => walk(children, networks, profiles, nodes, me, depth + 1),
        }
    }
}

fn parse_network(
    children: &[Record],
    networks: &mut Vec<(String, Vec<u8>, Option<String>, Vec<u64>)>,
    nodes: &mut BTreeSet<u64>,
) {
    let mut name: Option<String> = None;
    let mut token: Option<String> = None;
    let mut guid: Option<Vec<u8>> = None;
    let mut members: Vec<u64> = Vec::new();

    for c in children {
        if c.ty == RecordType::Guid as u8
            && c.field == field::NETWORK_GUID
            && c.payload.len() == 16
        {
            guid.get_or_insert(c.payload.clone());
        }
        if c.ty == RecordType::Str as u8 {
            if let Some(s) = c.as_string() {
                if c.field == field::NETWORK_NAME {
                    name.get_or_insert(s);
                } else if c.field == field::NETWORK_TOKEN {
                    token.get_or_insert(s);
                }
            }
        }
        if c.field == F_CONTAINER_MEMBER {
            if let Some(grand) = &c.children {
                for m in grand {
                    if m.ty == RecordType::NodeId as u8
                        && m.field == field::NODE_ID
                        && m.payload.len() == 8
                    {
                        let id = m.as_u64();
                        if id != 0 {
                            members.push(id);
                            nodes.insert(id);
                        }
                    }
                }
            }
        }
    }

    if let (Some(name), Some(guid)) = (name, guid) {
        networks.push((name, guid, token, members));
    }
}

fn parse_profile(
    children: &[Record],
    profiles: &mut HashMap<u64, (Option<String>, Option<String>)>,
    nodes: &mut BTreeSet<u64>,
) {
    let mut node: Option<u64> = None;
    let mut alias: Option<String> = None;
    let mut ip: Option<String> = None;

    for c in children {
        if c.ty == RecordType::NodeId as u8 && c.field == field::NODE_ID && c.payload.len() == 8 {
            let id = c.as_u64();
            if id != 0 {
                node.get_or_insert(id);
                nodes.insert(id);
            }
        }
        if c.ty == RecordType::Str as u8 {
            if let Some(s) = c.as_string() {
                if s.len() <= 128 {
                    if c.field == field::ALIAS {
                        alias.get_or_insert(s);
                    } else if c.field == field::PUBLIC_IP {
                        ip.get_or_insert(s);
                    }
                }
            }
        }
    }

    if let Some(id) = node {
        profiles.entry(id).or_insert((alias, ip));
    }
}

/// 从枚举响应里抽出公共网络名。
///
/// 公共网络列表不在「网络容器（0x23）」里，所以 [`SnapshotState::parse`] 看不到；
/// 但它们的名字同样带字段 `0x06`，全量收集再减去已加入的即可。
pub struct PublicNetworks;

impl PublicNetworks {
    /// 抽出响应里所有字段 `0x06` 的字符串（去重、保序）。
    pub fn extract_names(raw: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        let mut frames = Wire::split_frames(raw);
        if frames.is_empty() {
            frames.push(raw.to_vec());
        }
        for frame in &frames {
            visit(&Wire::parse(frame), &mut out, &mut seen);
        }
        out
    }

    /// 从全量名字里减去已加入的，得到可加入的公共网络。
    pub fn available(raw: &[u8], joined: &[String], search: Option<&str>) -> Vec<String> {
        let joined: HashSet<&str> = joined.iter().map(|s| s.as_str()).collect();
        let needle = search.map(|s| s.to_lowercase());

        let mut out: Vec<String> = Self::extract_names(raw)
            .into_iter()
            .filter(|n| !joined.contains(n.as_str()))
            .filter(|n| match &needle {
                Some(k) if !k.is_empty() => n.to_lowercase().contains(k),
                _ => true,
            })
            .collect();

        out.sort();
        out.dedup();
        out
    }
}

fn visit(records: &[Record], out: &mut Vec<String>, seen: &mut HashSet<String>) {
    for r in records {
        if r.ty == RecordType::Str as u8 && r.field == field::NETWORK_NAME {
            if let Some(s) = r.as_string() {
                if !s.is_empty() && s.len() <= 128 && seen.insert(s.clone()) {
                    out.push(s);
                }
            }
        }
        if let Some(children) = &r.children {
            visit(children, out, seen);
        }
    }
}
