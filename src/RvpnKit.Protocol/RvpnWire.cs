using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace RvpnKit.Protocol;

/// <summary>
/// Radmin 控制管道线格式解析器（<b>经真实抓包与实时数据双重验证</b>）。
///
/// <para>记录结构 —— 类型 1 字节，字段号 <b>2 字节大端</b>：</para>
/// <code>
///   u32 : 04 | fid:u16 BE | value:u32 LE
///   u64 : 08 | fid:u16 BE | value:u64 LE
///   u8  : 0b | fid:u16 BE | value:u8
///   u16 : 0c | fid:u16 BE | value:u16 LE
///   str : 03 | fid:u16 BE | len:u16 BE | UTF-16LE(len 字节，以 U+0000 起头)
///   blob: 09/0d/10 | fid:u16 BE | 16 字节
///   cont: xx | count:u16 BE | 子记录…        (xx 的低 4 位观察为 0xE 或 0xF)
/// </code>
///
/// <para><b>字符串记录的关键不变量：</b><c>len == 2 × (字符数 + 1)</c>，
/// 因为正文固定以一个 U+0000 起头。已用 5 组真实样本交叉验证。</para>
///
/// <para>帧边界：<c>[frame_len:u32 LE][记录流]</c>。</para>
/// </summary>
public static class RvpnWire
{
    /// <summary>记录类型字节。</summary>
    public static class Type
    {
        /// <summary>UTF-16LE 字符串</summary>
        public const byte Str = 0x03;
        /// <summary>无符号 32 位</summary>
        public const byte U32 = 0x04;
        /// <summary>无符号 64 位</summary>
        public const byte U64 = 0x08;
        /// <summary>无符号 8 位</summary>
        public const byte U8 = 0x0B;
        /// <summary>无符号 16 位</summary>
        public const byte U16 = 0x0C;
        /// <summary>16 字节块（GUID / 地址）</summary>
        public const byte Blob = 0x09;
        /// <summary>16 字节块（变体）</summary>
        public const byte Blob2 = 0x0D;
        /// <summary>16 字节块（变体）</summary>
        public const byte Blob3 = 0x10;
        /// <summary>32 位浮点</summary>
        public const byte F32 = 0x02;
    }

    /// <summary>是否可能是容器类型（低 4 位为 E 或 F）。</summary>
    private static bool IsContainer(byte type) => (type & 0x0F) is 0x0E or 0x0F;

    /// <summary>解析出的一条记录。</summary>
    public sealed class Record
    {
        /// <summary>记录在本帧内的偏移</summary>
        public int Offset { get; init; }

        /// <summary>字段编号</summary>
        public ushort FieldId { get; init; }

        /// <summary>原始类型字节</summary>
        public byte RawType { get; init; }

        /// <summary>嵌套深度（顶级为 0）</summary>
        public int Depth { get; init; }

        /// <summary>值：整数 / 字符串 / 字节数组</summary>
        public object? Value { get; init; }

        /// <summary>字符串值</summary>
        public string? Str => Value as string;

        /// <summary>整数值</summary>
        public ulong? Num => Value switch
        {
            byte b => b,
            ushort s => s,
            uint u => u,
            ulong l => l,
            _ => null,
        };

        /// <summary>字节数组值</summary>
        public byte[]? Bytes => Value as byte[];

        /// <summary>展示用文本</summary>
        public override string ToString() => RawType switch
        {
            Type.Str => $"0x{FieldId:x4} \"{Str}\"",
            Type.Blob or Type.Blob2 or Type.Blob3 when Bytes is { Length: 16 } =>
                $"0x{FieldId:x4} [{Convert.ToHexString(Bytes)}]",
            _ => $"0x{FieldId:x4} {Num}",
        };
    }

    /// <summary>一帧的解析结果。</summary>
    public sealed class ParseResult
    {
        /// <summary>按解析顺序排列的记录</summary>
        public List<Record> Records { get; } = [];

        /// <summary>无法识别而被跳过的字节数</summary>
        public int Skipped { get; set; }

        /// <summary>本帧正文总字节数</summary>
        public int Total { get; set; }

        /// <summary>同步率 = 有效字节 / 总字节</summary>
        public double Coverage => Total == 0 ? 0 : 1.0 - (double)Skipped / Total;
    }

    /// <summary>从帧正文解析全部记录。</summary>
    public static ParseResult Parse(ReadOnlySpan<byte> body)
    {
        var res = new ParseResult { Total = body.Length };
        int i = 0;

        while (i < body.Length)
        {
            if (TryRead(body, i, 0, res.Records, out int next))
            {
                i = next;
                continue;
            }
            res.Skipped++;
            i++;
        }

        return res;
    }

    /// <summary>尝试读出一条记录（容器会递归展开，子记录同样写入 <paramref name="sink"/>）。</summary>
    private static bool TryRead(ReadOnlySpan<byte> b, int i, int depth,
                                List<Record> sink, out int next)
    {
        next = i;
        if (i + 3 > b.Length || depth > 32) return false;

        byte type = b[i];
        ushort fid = BinaryPrimitives.ReadUInt16BigEndian(b[(i + 1)..]);

        // ── 容器：type 的低 4 位为 E/F，后跟 u16 BE 子元素个数
        if (IsContainer(type))
        {
            if (i + 5 > b.Length) return false;
            int count = BinaryPrimitives.ReadUInt16BigEndian(b[(i + 3)..]);
            if (count == 0 || count > 4096) return false;

            int p = i + 5;
            // 先记录容器本身，再递归读子记录 —— 这样深度信息保留下来
            var container = new Record
            {
                Offset = i, FieldId = fid, RawType = type, Depth = depth,
            };
            sink.Add(container);

            for (int k = 0; k < count; k++)
            {
                if (!TryRead(b, p, depth + 1, sink, out p))
                    return false;   // 子元素解析失败则整个容器判为失败
            }

            next = p;
            return true;
        }

        int v = i + 3;

        switch (type)
        {
            case Type.U32:
                if (v + 4 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = BinaryPrimitives.ReadUInt32LittleEndian(b[v..]),
                });
                next = v + 4;
                return true;

            case Type.U64:
                if (v + 8 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = BinaryPrimitives.ReadUInt64LittleEndian(b[v..]),
                });
                next = v + 8;
                return true;

            case Type.U8:
                if (v + 1 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = b[v],
                });
                next = v + 1;
                return true;

            case Type.U16:
                if (v + 2 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = BinaryPrimitives.ReadUInt16LittleEndian(b[v..]),
                });
                next = v + 2;
                return true;

            case Type.Str:
            {
                if (v + 2 > b.Length) return false;
                int len = BinaryPrimitives.ReadUInt16BigEndian(b[v..]);
                int bodyOff = v + 2;

                // 不变量：偶数、合理范围、且正文以 U+0000 起头
                if (len < 2 || (len & 1) != 0 || len > 8192) return false;
                if (bodyOff + len > b.Length) return false;
                if (b[bodyOff] != 0x00) return false;

                string s = Encoding.Unicode.GetString(b.Slice(bodyOff, len)).TrimStart('\0');
                if (s.Length == 0 || !StrictlyPrintable(s)) return false;

                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth, Value = s,
                });
                next = bodyOff + len;
                return true;
            }

            case Type.Blob or Type.Blob2 or Type.Blob3:
                if (v + 16 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = b.Slice(v, 16).ToArray(),
                });
                next = v + 16;
                return true;

            case Type.F32:
                if (v + 4 > b.Length) return false;
                sink.Add(new Record
                {
                    Offset = i, FieldId = fid, RawType = type, Depth = depth,
                    Value = BinaryPrimitives.ReadSingleLittleEndian(b[v..]),
                });
                next = v + 4;
                return true;

            default:
                return false;
        }
    }

    /// <summary>严格可打印校验，用于剔除偶然对齐产生的假记录。</summary>
    private static bool StrictlyPrintable(string s)
    {
        int good = 0, total = 0;
        foreach (char c in s)
        {
            total++;
            if (c >= 0x20 && c <= 0x7E) good++;
            else if (c is '\t' or '\r' or '\n') good++;
            else if (c >= 0x4E00 && c <= 0x9FFF) good++;   // CJK 统一表意
            else if (c >= 0x3000 && c <= 0x303F) good++;   // CJK 标点
            else if (c >= 0xFF00 && c <= 0xFFEF) good++;   // 全角
            else if (c >= 0x0400 && c <= 0x04FF) good++;   // 西里尔
            else if (c >= 0x00C0 && c <= 0x024F) good++;   // 拉丁扩展
            else if (c >= 0x2600 && c <= 0x27BF) good++;   // 杂项符号
            else if (c >= 0x1F300 && c <= 0x1FAFF) good++; // emoji
        }
        return total > 0 && good * 10 >= total * 9;
    }

    /// <summary>把带 u32 LE 长度前缀的字节流切分成帧，返回每帧正文。</summary>
    public static List<byte[]> SplitFrames(byte[] data)
    {
        var frames = new List<byte[]>();
        int off = 0;
        while (off + 4 <= data.Length)
        {
            long len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(off));
            if (len <= 0 || off + 4 + len > data.Length) break;
            frames.Add(data.AsSpan(off + 4, (int)len).ToArray());
            off += 4 + (int)len;
        }
        return frames;
    }

    /// <summary>把 16 字节块还原成 IPv4（前 12 字节全零时）。</summary>
    public static string? TryBlobToIPv4(byte[]? blob)
    {
        if (blob is not { Length: 16 }) return null;
        for (int k = 0; k < 12; k++)
            if (blob[k] != 0) return null;
        return $"{blob[12]}.{blob[13]}.{blob[14]}.{blob[15]}";
    }

    /// <summary>把 16 字节块还原成 GUID。</summary>
    public static Guid? TryBlobToGuid(byte[]? blob)
        => blob is { Length: 16 } ? new Guid(blob) : null;

    // ───────────────────────────── 已知字段语义

    /// <summary>已知字段号的语义（随逆向推进持续补充）。</summary>
    public static class Fields
    {
        /// <summary>节点连接 IP（字符串）</summary>
        public const ushort NodeConnIp = 0x01c9;

        /// <summary>节点 ID（u64）</summary>
        public const ushort NodeId = 0x01e1;

        /// <summary>节点别名 / 主机名（字符串）</summary>
        public const ushort NodeAlias = 0x01e9;

        /// <summary>客户端版本号（字符串）</summary>
        public const ushort ProductVersion = 0x01ed;

        /// <summary>网络名（字符串）</summary>
        public const ushort NetworkName = 0x0400;

        /// <summary>节点虚拟 IP（16 字节块）</summary>
        public const ushort NodeVirtualIp = 0x0105;

        /// <summary>帧序号（u32）</summary>
        public const ushort Sequence = 0x00d6;

        /// <summary>字段号对应的可读名称。</summary>
        public static string Name(ushort fid) => fid switch
        {
            NodeConnIp => "节点连接IP",
            NodeId => "节点ID",
            NodeAlias => "节点别名",
            ProductVersion => "版本号",
            NetworkName => "网络名",
            NodeVirtualIp => "节点虚拟IP",
            Sequence => "帧序号",
            0x05d => "超时A(ms)",
            0x05e => "超时B(ms)",
            0x05f => "超时C(ms)",
            0x073 => "间隔A(ms)",
            0x074 => "间隔B(ms)",
            0x075 => "间隔C(ms)",
            0x095 => "超时D(ms)",
            0x09b => "超时E(ms)",
            0x0d7 => "常量100",
            _ => $"未知0x{fid:x4}",
        };
    }
}
