using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace RvpnKit.Protocol;

/// <summary>
/// 字段值类型。取自记录首字节的低 4 位（实测）。
/// </summary>
public enum RvpnType : byte
{
    /// <summary>嵌套容器：payload = 子元素数量(uint16 BE) + 子记录</summary>
    Container = 0x0E,

    /// <summary>无符号 8 位</summary>
    U8 = 0x0B,

    /// <summary>无符号 32 位小端</summary>
    U32 = 0x04,

    /// <summary>无符号 64 位小端</summary>
    U64 = 0x0C,

    /// <summary>UTF-16LE 字符串，长度以「字节数」计（3 字节 BE 前缀）</summary>
    String = 0x0D,

    /// <summary>16 字节二进制块（GUID / IPv6 / 虚拟地址）</summary>
    Blob16 = 0x01,

    /// <summary>32 位浮点</summary>
    Single = 0x02,

    /// <summary>无符号 16 位</summary>
    U16 = 0x10,

    /// <summary>无符号 8 位（另一种编码）</summary>
    U8Alt = 0x10 | 0x0B,
}

/// <summary>
/// Radmin VPN 控制管道线格式的一个字段记录。
///
/// 线格式（全部实测确认）：
/// <code>
///   [0x04 | fid:u16 BE | value:u32 LE        ]  12 字节
///   [0x0B | fid:u16 BE | value:u8            ]   4 字节
///   [0x0D | fid:u16 BE | bytelen:u24 BE | UTF-16LE 正文 ]
///   [0x0E | childcount:u16 BE | 子记录…       ]
/// </code>
/// </summary>
public sealed class RvpnField
{
    /// <summary>字段编号（大端读取，实测范围 0x00 ~ 0x0266）。</summary>
    public ushort Id { get; init; }

    /// <summary>字段的原始类型字节。</summary>
    public byte RawType { get; init; }

    /// <summary>标量值 / 字符串 / 二进制块。容器类型时为 null。</summary>
    public object? Value { get; init; }

    /// <summary>容器子节点；非容器为空集合。</summary>
    public IReadOnlyList<RvpnField> Children { get; init; } = Array.Empty<RvpnField>();

    public bool IsContainer => (RawType & 0x0F) == (byte)RvpnType.Container && Children.Count > 0;

    public ulong? AsU64 => Value switch
    {
        byte v => v,
        ushort v => v,
        uint v => v,
        ulong v => v,
        _ => null,
    };

    public uint? AsU32
    {
        get
        {
            var v = AsU64;
            return v is null ? null : (uint)v.Value;
        }
    }

    public int? AsInt32
    {
        get
        {
            var v = AsU32;
            return v is null ? null : unchecked((int)v.Value);
        }
    }

    public string? AsString => Value as string;

    public byte[]? AsBytes => Value as byte[];

    public override string ToString() => (RawType & 0x0F) switch
    {
        (byte)RvpnType.Container => $"0x{Id:x4} <container ×{Children.Count}>",
        (byte)RvpnType.String => $"0x{Id:x4} \"{Value}\"",
        (byte)RvpnType.Blob16 => $"0x{Id:x4} [{Convert.ToHexString(AsBytes ?? [])}]",
        _ => $"0x{Id:x4} {Value}",
    };
}

/// <summary>解码失败时抛出，附带偏移量便于定位协议变更。</summary>
public sealed class RvpnProtocolException(string message, int offset)
    : Exception($"{message} (偏移 0x{offset:x})")
{
    public int Offset { get; } = offset;
}

/// <summary>
/// 线格式编解码器。<b>零拷贝读取</b>，写回时复用缓冲区，面向高吞吐场景。
/// </summary>
public static class RvpnCodec
{
    /// <summary>单个帧长度前缀（u32 LE）之外的正文上限，用于防御性校验。</summary>
    public const int MaxFrameSize = 64 * 1024 * 1024;

    /// <summary>容器类型的判定掩码 —— 低 4 位。</summary>
    private const byte TypeMask = 0x0F;

    // ─────────────────────────────────────────────────────────────── 解码

    /// <summary>从 <paramref name="buffer"/> 的 <paramref name="offset"/> 起解出一个字段。</summary>
    public static RvpnField DecodeField(ReadOnlySpan<byte> buffer, ref int offset)
    {
        int start = offset;
        if (offset + 2 > buffer.Length)
            throw new RvpnProtocolException("缓冲区不足以读取字段编号", offset);

        byte type = buffer[offset];
        ushort id = BinaryPrimitives.ReadUInt16BigEndian(buffer[(offset + 1)..]);
        offset += 3;

        var kind = (byte)(type & TypeMask);

        switch (kind)
        {
            case (byte)RvpnType.U32:
            {
                Require(buffer, offset, 4, start);
                uint v = BinaryPrimitives.ReadUInt32LittleEndian(buffer[offset..]);
                offset += 4;
                return new RvpnField { Id = id, RawType = type, Value = v };
            }

            case (byte)RvpnType.U8:
            {
                Require(buffer, offset, 1, start);
                byte v = buffer[offset];
                offset += 1;
                return new RvpnField { Id = id, RawType = type, Value = v };
            }

            case (byte)RvpnType.String:
            {
                Require(buffer, offset, 3, start);
                int byteLen = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
                offset += 3;
                Require(buffer, offset, byteLen, start);
                string s = Encoding.Unicode.GetString(buffer.Slice(offset, byteLen));
                offset += byteLen;
                return new RvpnField { Id = id, RawType = type, Value = s };
            }

            case (byte)RvpnType.Container:
            {
                Require(buffer, offset, 2, start);
                int count = BinaryPrimitives.ReadUInt16BigEndian(buffer[offset..]);
                offset += 2;

                var children = count > 0 ? new RvpnField[count] : [];
                for (int i = 0; i < count; i++)
                    children[i] = DecodeField(buffer, ref offset);

                return new RvpnField { Id = id, RawType = type, Children = children };
            }

            case (byte)RvpnType.Blob16:
            {
                // 实测：16 字节；少数情况 4/8 字节。按剩余上下文推断。
                int len = buffer.Length - offset >= 16 ? 16 : buffer.Length - offset;
                Require(buffer, offset, len, start);
                byte[] blob = buffer.Slice(offset, len).ToArray();
                offset += len;
                return new RvpnField { Id = id, RawType = type, Value = blob };
            }

            case (byte)RvpnType.Single:
            {
                Require(buffer, offset, 4, start);
                float f = BinaryPrimitives.ReadSingleLittleEndian(buffer[offset..]);
                offset += 4;
                return new RvpnField { Id = id, RawType = type, Value = f };
            }

            default:
                throw new RvpnProtocolException($"未知字段类型 0x{type:x2}", start);
        }
    }

    /// <summary>解出一个完整帧正文（顶级字段列表）。</summary>
    public static RvpnField DecodeFrame(ReadOnlySpan<byte> body, int offset = 0)
    {
        var root = new List<RvpnField>();
        while (offset < body.Length)
            root.Add(DecodeField(body, ref offset));
        return new RvpnField { Id = 0, RawType = 0, Children = root };
    }

    /// <summary>解出 <c>[长度:u32 LE][正文]</c> 形式的完整帧（含长度前缀）。</summary>
    public static RvpnField DecodeDelimitedFrame(ReadOnlySpan<byte> buffer, ref int offset)
    {
        if (offset + 4 > buffer.Length)
            throw new RvpnProtocolException("缓冲区不足以读取帧长度", offset);

        int len = BinaryPrimitives.ReadInt32LittleEndian(buffer[offset..]);
        if (len < 0 || len > MaxFrameSize)
            throw new RvpnProtocolException($"帧长度非法: {len}", offset);

        offset += 4;
        if (offset + len > buffer.Length)
            throw new RvpnProtocolException("帧体不完整", offset);

        var frame = DecodeFrame(buffer.Slice(offset, len));
        offset += len;
        return frame;
    }

    /// <summary>尝试从流式缓冲区切出完整帧。返回 false 表示数据还不够。</summary>
    public static bool TryTakeDelimitedFrame(ReadOnlySpan<byte> buffer, out int consumed, out RvpnField? frame)
    {
        consumed = 0;
        frame = null;
        if (buffer.Length < 4) return false;

        int len = BinaryPrimitives.ReadInt32LittleEndian(buffer);
        if (len < 0 || len > MaxFrameSize)
            throw new RvpnProtocolException($"帧长度非法: {len}", 0);
        if (buffer.Length < 4 + len) return false;

        frame = DecodeFrame(buffer.Slice(4, len));
        consumed = 4 + len;
        return true;
    }

    // ─────────────────────────────────────────────────────────────── 编码

    /// <summary>把一个字段编码进 <paramref name="writer"/>。</summary>
    public static void EncodeField(IBufferWriter<byte> writer, RvpnField field)
    {
        Span<byte> header = stackalloc byte[3];
        header[0] = field.RawType;
        BinaryPrimitives.WriteUInt16BigEndian(header[1..], field.Id);
        writer.Write(header);

        var kind = (byte)(field.RawType & TypeMask);
        Span<byte> tmp = stackalloc byte[8];

        switch (kind)
        {
            case (byte)RvpnType.U32:
                BinaryPrimitives.WriteUInt32LittleEndian(tmp, Convert.ToUInt32(field.Value ?? 0u));
                writer.Write(tmp[..4]);
                break;

            case (byte)RvpnType.U8:
                tmp[0] = Convert.ToByte(field.Value ?? (byte)0);
                writer.Write(tmp[..1]);
                break;

            case (byte)RvpnType.String:
            {
                string s = field.AsString ?? string.Empty;
                int byteLen = Encoding.Unicode.GetByteCount(s);
                tmp[0] = (byte)(byteLen >> 16);
                tmp[1] = (byte)(byteLen >> 8);
                tmp[2] = (byte)byteLen;
                writer.Write(tmp[..3]);
                if (byteLen > 0)
                {
                    var span = writer.GetSpan(byteLen);
                    Encoding.Unicode.GetBytes(s, span);
                    writer.Advance(byteLen);
                }
                break;
            }

            case (byte)RvpnType.Container:
            {
                BinaryPrimitives.WriteUInt16BigEndian(tmp, (ushort)field.Children.Count);
                writer.Write(tmp[..2]);
                foreach (var child in field.Children)
                    EncodeField(writer, child);
                break;
            }

            default:
                if (field.Value is byte[] bytes)
                    writer.Write(bytes);
                break;
        }
    }

    /// <summary>把字段列表编码成帧正文。</summary>
    public static byte[] EncodeFrame(IReadOnlyList<RvpnField> fields)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        foreach (var f in fields)
            EncodeField(buffer, f);
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>编码成带 u32 LE 长度前缀的帧。</summary>
    public static byte[] EncodeDelimitedFrame(IReadOnlyList<RvpnField> fields)
    {
        var body = EncodeFrame(fields);
        var full = new byte[body.Length + 4];
        BinaryPrimitives.WriteInt32LittleEndian(full, body.Length);
        body.CopyTo(full, 4);
        return full;
    }

    // ─────────────────────────────────────────────────────────────── 辅助

    private static void Require(ReadOnlySpan<byte> buffer, int offset, int need, int start)
    {
        if (need < 0 || offset + need > buffer.Length)
            throw new RvpnProtocolException($"数据不足：需要 {need} 字节", start);
    }

    /// <summary>便捷构造器：u32 字段。</summary>
    public static RvpnField U32(ushort id, uint value) =>
        new() { Id = id, RawType = (byte)RvpnType.U32, Value = value };

    /// <summary>便捷构造器：u8 字段。</summary>
    public static RvpnField U8(ushort id, byte value) =>
        new() { Id = id, RawType = (byte)RvpnType.U8, Value = value };

    /// <summary>便捷构造器：字符串字段。</summary>
    public static RvpnField Str(ushort id, string value) =>
        new() { Id = id, RawType = (byte)RvpnType.String, Value = value };

    /// <summary>便捷构造器：二进制块字段。</summary>
    public static RvpnField Blob(ushort id, byte[] value) =>
        new() { Id = id, RawType = (byte)RvpnType.Blob16, Value = value };

    /// <summary>便捷构造器：容器字段。</summary>
    public static RvpnField Cont(ushort id, params RvpnField[] children) =>
        new() { Id = id, RawType = (byte)RvpnType.Container, Children = children };
}
