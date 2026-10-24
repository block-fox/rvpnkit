//! 线格式常量与基础编解码。

/// 记录类型码。数值来自对官方报文与二进制字符串表的核对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// 容器：payload 本身又是一串记录。
    Container = 0x00,
    /// u32 值记录（请求编号、命令码）。
    UInt32 = 0x01,
    /// 节点 ID 记录：头是 `02 00 01 e1`，载荷 8 字节大端。
    NodeId = 0x02,
    /// 字符串记录（UTF-16BE + `00 01`）。
    Str = 0x03,
    /// u64 记录。
    UInt64 = 0x08,
    /// u32 记录，多用于标志位。
    UInt32Alt = 0x0b,
    /// 16 字节 GUID（网络标识）。
    Guid = 0x0d,
}

/// 字段号。全部是实测报文里出现过的值。
pub mod field {
    /// 请求编号；服务端日志里显示为 `[req:N]`。
    pub const REQUEST_ID: u8 = 0x4a;
    /// 命令码。
    pub const COMMAND: u8 = 0x00;
    /// 别名字符串。
    pub const ALIAS: u8 = 0x04;
    /// 网络名字符串。
    pub const NETWORK_NAME: u8 = 0x06;
    /// 网络 GUID。
    pub const NETWORK_GUID: u8 = 0x09;
    /// 节点的 u64 ID。
    pub const NODE_ID: u8 = 0xe1;
    /// 网络启用/禁用（0=禁用 1=启用）。
    pub const ENABLED: u8 = 0x16;
    /// VPN 电源（0=关 1=开）。
    pub const POWER: u8 = 0x11;
    /// 加入网络的常量字段，实测恒为 1。
    pub const JOIN_FLAG: u8 = 0x3f;
    /// 创建网络的常量字段，实测恒为 0。
    pub const CREATE_FLAG: u8 = 0x08;
    /// 创建网络时 28 字节随机密钥。
    pub const NETWORK_KEY: u8 = 0x0d;
    /// 公网 IP 字符串。
    pub const PUBLIC_IP: u8 = 0xc9;
    /// 网络容器里的附加 token 字符串（含义未确认，很可能是会话令牌而非密码）。
    pub const NETWORK_TOKEN: u8 = 0x47;
}

/// 容器标签。高 3 字节固定 `00 00 13`，低字节区分类型。
pub mod tag {
    /// 加入网络。
    pub const JOIN: u32 = 0x0000_131b;
    /// 创建网络。
    pub const CREATE: u32 = 0x0000_132b;
    /// 网络条目。
    pub const NETWORK: u32 = 0x0000_1323;
    /// 节点条目。
    pub const NODE: u32 = 0x0000_1322;
    /// 节点更新。
    pub const NODE_UPDATE: u32 = 0x0000_1344;
}

/// 帧信封魔数。
pub const MAGIC: [u8; 6] = [0x00, 0x00, 0x00, 0x04, 0x01, 0x00];

/// 判断一段字节是否像控制帧。
pub fn looks_like_frame(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && data[..MAGIC.len()] == MAGIC
}

/// 编码字符串：UTF-16 **大端**，末尾追加 `00 01`。
///
/// 注意不是 UTF-16LE。ASCII 名字下两种写法字节恰好相同（`<char>00` 前面补 00
/// 等于 `00<char>`），所以早期判错过；遇到非 ASCII 字符才会分叉。
pub fn encode_string(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.push(0x00);
    out.push(0x01);
    out
}

/// 解码字符串载荷（去掉结尾 `00 01`）。
pub fn decode_string(payload: &[u8]) -> Option<String> {
    let body = if payload.len() >= 2 && payload[payload.len() - 2..] == [0x00, 0x01] {
        &payload[..payload.len() - 2]
    } else {
        payload
    };
    if body.is_empty() || body.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let s: String = char::decode_utf16(units.iter().copied())
        .collect::<Result<String, _>>()
        .ok()?;
    // 过滤控制字符：正常名字里不会有
    if s.chars().any(|c| (c as u32) < 0x20) {
        return None;
    }
    Some(s)
}

/// 流式构造一条消息。
#[derive(Default)]
pub struct Frame {
    buf: Vec<u8>,
}

impl Frame {
    /// 新建空帧。
    pub fn new() -> Self {
        Self::default()
    }

    /// 取字节。
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// 借用字节。
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    fn raw(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// 写 8 字节记录头。
    pub fn header(&mut self, size: u32, ty: RecordType, field: u8) -> &mut Self {
        self.raw(&size.to_be_bytes());
        self.raw(&[ty as u8, 0x00, 0x03, field]);
        self
    }

    /// 写一条 u32 记录（类型 `UInt32`）。
    pub fn u32(&mut self, field: u8, value: u32) -> &mut Self {
        self.header(4, RecordType::UInt32, field);
        self.raw(&value.to_be_bytes());
        self
    }

    /// 写一条 u32 记录（类型 `UInt32Alt`）。
    pub fn u32_alt(&mut self, field: u8, value: u32) -> &mut Self {
        self.header(4, RecordType::UInt32Alt, field);
        self.raw(&value.to_be_bytes());
        self
    }

    /// 写一条 GUID 记录。
    pub fn guid(&mut self, field: u8, guid: &[u8]) -> &mut Self {
        assert_eq!(guid.len(), 16, "GUID 必须是 16 字节");
        self.header(16, RecordType::Guid, field);
        self.raw(guid);
        self
    }

    /// 写一条字符串记录。
    pub fn text(&mut self, field: u8, text: &str) -> &mut Self {
        let payload = encode_string(text);
        self.header(payload.len() as u32, RecordType::Str, field);
        self.raw(&payload);
        self
    }

    /// 写一条节点 ID 记录（头为 `02 00 01 e1`）。
    pub fn node_id(&mut self, id: u64) -> &mut Self {
        self.raw(&8u32.to_be_bytes());
        self.raw(&[RecordType::NodeId as u8, 0x00, 0x01, field::NODE_ID]);
        self.raw(&id.to_be_bytes());
        self
    }

    /// 写一条任意字节块记录。
    pub fn blob(&mut self, field: u8, ty: RecordType, payload: &[u8]) -> &mut Self {
        self.header(payload.len() as u32, ty, field);
        self.raw(payload);
        self
    }

    /// 把已构造好的子记录整体包进容器。
    pub fn container(&mut self, tag: u32, inner: &[u8]) -> &mut Self {
        self.raw(&(inner.len() as u32).to_be_bytes());
        self.raw(&tag.to_be_bytes());
        self.raw(inner);
        self
    }
}

/// 从线上字节读回的一条记录。
#[derive(Debug, Clone)]
pub struct Record {
    /// 字段号。
    pub field: u8,
    /// 类型码。
    pub ty: u8,
    /// 载荷。
    pub payload: Vec<u8>,
    /// 容器记录的子记录；非容器为 `None`。
    pub children: Option<Vec<Record>>,
}

impl Record {
    /// 把载荷当 u32（大端）读。
    pub fn as_u32(&self) -> u32 {
        if self.payload.len() >= 4 {
            u32::from_be_bytes([
                self.payload[0],
                self.payload[1],
                self.payload[2],
                self.payload[3],
            ])
        } else {
            0
        }
    }

    /// 把载荷当 u64（大端）读。
    pub fn as_u64(&self) -> u64 {
        if self.payload.len() >= 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.payload[..8]);
            u64::from_be_bytes(b)
        } else {
            0
        }
    }

    /// 把载荷当字符串读。
    pub fn as_string(&self) -> Option<String> {
        decode_string(&self.payload)
    }

    /// 是否为容器。
    pub fn is_container(&self) -> bool {
        self.children.is_some()
    }
}

/// 解析工具。
pub struct Wire;

impl Wire {
    /// 把一段字节解析成记录序列，容器会递归展开。
    ///
    /// 容器判定：类型码 `0x00` 且记录头第 4 字节为 `0x13`。
    pub fn parse(data: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let size = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            let ty = data[off + 4];
            let tag_byte = data[off + 6];
            let field = data[off + 7];

            if size > data.len() - off - 8 {
                break; // 长度不合法，截断
            }

            let payload = data[off + 8..off + 8 + size].to_vec();
            let children = if ty == RecordType::Container as u8 && tag_byte == 0x13 {
                Some(Self::parse(&payload))
            } else {
                None
            };

            out.push(Record {
                field,
                ty,
                payload,
                children,
            });
            off += 8 + size;
        }
        out
    }

    /// 把管道流拆成帧。流是多帧拼接，每帧前有 4 字节**小端**长度。
    pub fn split_frames(stream: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut off = 0usize;
        while off + 4 <= stream.len() {
            let len = u32::from_le_bytes([
                stream[off],
                stream[off + 1],
                stream[off + 2],
                stream[off + 3],
            ]) as usize;
            if len == 0 || len > stream.len() - off - 4 {
                break;
            }
            frames.push(stream[off + 4..off + 4 + len].to_vec());
            off += 4 + len;
        }
        frames
    }

    /// 取出帧里的请求编号（字段 `0x4a` 的 u32 记录）。
    pub fn request_id(frame: &[u8]) -> u32 {
        for r in Self::parse(frame) {
            if r.field == field::REQUEST_ID && r.ty == RecordType::UInt32 as u8 {
                return r.as_u32();
            }
        }
        0xFFFF_FFFF
    }
}
