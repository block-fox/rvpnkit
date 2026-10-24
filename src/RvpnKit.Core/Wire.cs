using System.Buffers.Binary;
using System.Text;

namespace RvpnKit.Core;

/// <summary>
/// 线格式常量与基础编解码。
///
/// <para>Radmin 控制管道的每条消息由若干「记录」顺次拼成，记录形如：</para>
/// <code>
/// [size:u32 BE][类型码:u8][0x00][0x03][字段:u8][payload:size 字节]
/// </code>
///
/// <para>其中第 3、4 字节固定是 <c>00 03</c>（例外见 <see cref="RecordType.NodeId"/>），
/// 第 5 字节才是字段号。所有整数一律大端。</para>
///
/// <para>字符串的编码是 <b>UTF-16 大端</b>，末尾跟 2 字节 <c>00 01</c>。
/// 这一点早期判成 UTF-16LE 过：因为网络名几乎全是 ASCII，ASCII 在 LE 下是
/// <c>&lt;char&gt;00</c>，前面补一个 <c>00</c> 就和 BE 的 <c>00&lt;char&gt;</c> 逐字节重合，
/// 直到遇到非 ASCII 字符才暴露。</para>
/// </summary>
public static class Wire
{
    /// <summary>帧信封魔数。收发两个方向的消息都以它开头。</summary>
    public static ReadOnlySpan<byte> Magic => [0x00, 0x00, 0x00, 0x04, 0x01, 0x00];

    /// <summary>记录头的第 3 字节，普通记录恒为 0x03。</summary>
    public const byte Pad = 0x00;

    /// <summary>记录头的第 4 字节，普通记录恒为 0x03。</summary>
    public const byte Tag = 0x03;

    /// <summary>判断一段字节是否像一条控制帧。</summary>
    public static bool LooksLikeFrame(ReadOnlySpan<byte> data)
        => data.Length >= Magic.Length && data[..Magic.Length].SequenceEqual(Magic);

    /// <summary>UTF-16BE 编码，并追加结尾标记 <c>00 01</c>。</summary>
    public static byte[] EncodeString(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        byte[] body = Encoding.BigEndianUnicode.GetBytes(text);
        var buf = new byte[body.Length + 2];
        body.CopyTo(buf, 0);
        buf[^2] = 0x00;
        buf[^1] = 0x01;
        return buf;
    }

    /// <summary>解码字符串载荷（去掉结尾 <c>00 01</c>）。</summary>
    public static string? DecodeString(ReadOnlySpan<byte> payload)
    {
        if (payload.Length >= 2 && payload[^2] == 0x00 && payload[^1] == 0x01)
            payload = payload[..^2];
        if (payload.Length == 0 || (payload.Length & 1) != 0) return null;
        try
        {
            string s = Encoding.BigEndianUnicode.GetString(payload);
            foreach (char c in s)
                if (c < 32) return null;
            return s;
        }
        catch (Exception)
        {
            return null;
        }
    }
}

/// <summary>记录的类型码。数值来自对官方报文与二进制字符串表的核对。</summary>
public enum RecordType : byte
{
    /// <summary>容器：后续 payload 本身又是一串记录。</summary>
    Container = 0x00,

    /// <summary>u32 值记录（请求编号、命令码等）。</summary>
    UInt32 = 0x01,

    /// <summary>节点 ID 记录，头是 <c>02 00 01 e1</c>，载荷 8 字节大端。</summary>
    NodeId = 0x02,

    /// <summary>字符串记录（UTF-16BE + 00 01）。</summary>
    String = 0x03,

    /// <summary>u64 记录（部分场景下的节点 ID）。</summary>
    UInt64 = 0x08,

    /// <summary>u32 记录，多用于标志位/枚举值。</summary>
    UInt32Alt = 0x0b,

    /// <summary>16 字节 GUID 记录（网络标识）。</summary>
    Guid = 0x0d,
}

/// <summary>字段号。所有数值都是实测报文里出现过的。</summary>
public static class Field
{
    /// <summary>请求编号；服务端日志里显示为 <c>[req:N]</c>。</summary>
    public const byte RequestId = 0x4a;

    /// <summary>命令码。</summary>
    public const byte Command = 0x00;

    /// <summary>别名字符串。</summary>
    public const byte Alias = 0x04;

    /// <summary>网络名字符串。</summary>
    public const byte NetworkName = 0x06;

    /// <summary>网络 GUID。</summary>
    public const byte NetworkGuid = 0x09;

    /// <summary>节点的 u64 ID。</summary>
    public const byte NodeId = 0xe1;

    /// <summary>网络启用/禁用标志（0=禁用 1=启用）。</summary>
    public const byte Enabled = 0x16;

    /// <summary>VPN 电源标志（0=关 1=开）。</summary>
    public const byte Power = 0x11;

    /// <summary>加入网络的常量字段，实测恒为 1。</summary>
    public const byte JoinFlag = 0x3f;

    /// <summary>创建网络的常量字段，实测恒为 0。</summary>
    public const byte CreateFlag = 0x08;

    /// <summary>创建网络时 28 字节随机密钥的字段号。</summary>
    public const byte NetworkKey = 0x0d;

    /// <summary>部分容器里携带的附加 u32。</summary>
    public const byte Extra = 0x76;
}

/// <summary>容器标签的高 3 字节固定是 <c>00 00 13</c>，低字节区分消息类型。</summary>
public static class ContainerTag
{
    /// <summary>加入网络。</summary>
    public const uint Join = 0x0000_131b;

    /// <summary>创建网络。</summary>
    public const uint Create = 0x0000_132b;

    /// <summary>网络条目（GUID + 名字 + 成员）。</summary>
    public const uint Network = 0x0000_1323;

    /// <summary>节点条目。</summary>
    public const uint Node = 0x0000_1322;

    /// <summary>节点可见性/连接更新。</summary>
    public const uint NodeUpdate = 0x0000_1344;
}

/// <summary>按线格式逐字节构造一条消息。</summary>
public sealed class FrameWriter
{
    private readonly MemoryStream _buf = new();

    /// <summary>已写入的字节数。</summary>
    public int Length => (int)_buf.Length;

    /// <summary>取到底层字节。</summary>
    public byte[] ToArray() => _buf.ToArray();

    private FrameWriter Raw(ReadOnlySpan<byte> data)
    {
        _buf.Write(data);
        return this;
    }

    private void U8(byte v) => _buf.WriteByte(v);

    private void U32Be(uint v)
    {
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tmp, v);
        Raw(tmp);
    }

    /// <summary>写 8 字节记录头。</summary>
    public FrameWriter Header(uint size, RecordType type, byte field)
    {
        U32Be(size);
        U8((byte)type);
        U8(Wire.Pad);
        U8(Wire.Tag);
        U8(field);
        return this;
    }

    /// <summary>写一条 u32 记录（类型 <see cref="RecordType.UInt32"/>）。</summary>
    public FrameWriter U32(byte field, uint value)
        => Header(4, RecordType.UInt32, field).Raw(Pad4(value));

    /// <summary>写一条 u32 记录（类型 <see cref="RecordType.UInt32Alt"/>）。</summary>
    public FrameWriter U32Alt(byte field, uint value)
        => Header(4, RecordType.UInt32Alt, field).Raw(Pad4(value));

    /// <summary>写一条 16 字节 GUID 记录。</summary>
    public FrameWriter Guid(byte field, ReadOnlySpan<byte> guid)
    {
        if (guid.Length != 16)
            throw new ArgumentException("GUID 必须是 16 字节", nameof(guid));
        Header(16, RecordType.Guid, field);
        Raw(guid);
        return this;
    }

    /// <summary>写一条字符串记录。</summary>
    public FrameWriter Str(byte field, string text)
    {
        byte[] payload = Wire.EncodeString(text);
        Header((uint)payload.Length, RecordType.String, field);
        Raw(payload);
        return this;
    }

    /// <summary>写一条节点 ID 记录（头为 <c>02 00 01 e1</c>）。</summary>
    public FrameWriter NodeId(ulong nodeId)
    {
        U32Be(8);
        U8((byte)RecordType.NodeId);
        U8(0x00);
        U8(0x01);
        U8(Field.NodeId);
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(tmp, nodeId);
        Raw(tmp);
        return this;
    }

    /// <summary>写一条任意字节块记录（类型 <paramref name="type"/>）。</summary>
    public FrameWriter Blob(byte field, RecordType type, ReadOnlySpan<byte> payload)
    {
        Header((uint)payload.Length, type, field);
        Raw(payload);
        return this;
    }

    /// <summary>把一段已构造好的子记录整体包进容器。</summary>
    public FrameWriter Container(uint tag, ReadOnlySpan<byte> inner)
    {
        U32Be((uint)inner.Length);
        U32Be(tag);
        Raw(inner);
        return this;
    }

    private static byte[] Pad4(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }
}

/// <summary>从线上字节读回一条记录。</summary>
/// <param name="Field">字段号。</param>
/// <param name="Type">类型码。</param>
/// <param name="Payload">载荷。</param>
/// <param name="Children">容器记录的子记录；非容器为 null。</param>
public readonly record struct Record(byte Field, byte Type, byte[] Payload, IReadOnlyList<Record>? Children)
{
    /// <summary>是否为容器。</summary>
    public bool IsContainer => Children is not null;

    /// <summary>把载荷当成 u32（大端）读取。</summary>
    public uint AsUInt32()
        => Payload.Length >= 4 ? BinaryPrimitives.ReadUInt32BigEndian(Payload) : 0;

    /// <summary>把载荷当成 u64（大端）读取。</summary>
    public ulong AsUInt64()
        => Payload.Length >= 8 ? BinaryPrimitives.ReadUInt64BigEndian(Payload) : 0;

    /// <summary>把载荷当成字符串读取。</summary>
    public string? AsString() => Wire.DecodeString(Payload);
}

/// <summary>记录流解析器。</summary>
public static class FrameReader
{
    /// <summary>
    /// 把一段字节解析成记录序列。遇到容器会递归展开（容器判定：类型码 0x00
    /// 且记录头第 4 字节为 0x13）。
    /// </summary>
    public static List<Record> Parse(ReadOnlySpan<byte> data)
    {
        var list = new List<Record>();
        int off = 0;
        while (off + 8 <= data.Length)
        {
            uint size = BinaryPrimitives.ReadUInt32BigEndian(data[off..]);
            byte type = data[off + 4];
            byte pad = data[off + 5];
            byte tag = data[off + 6];
            byte field = data[off + 7];

            if (size > data.Length - off - 8) break;   // 长度不合法，截断

            byte[] payload = data.Slice(off + 8, (int)size).ToArray();
            List<Record>? children = null;
            if (type == (byte)RecordType.Container && tag == 0x13)
                children = Parse(payload);

            list.Add(new Record(field, type, payload, children));
            off += 8 + (int)size;
        }
        return list;
    }

    /// <summary>
    /// 把整条管道流拆成帧。流是多帧拼接的，每帧前有 4 字节小端长度。
    /// </summary>
    public static List<byte[]> SplitFrames(ReadOnlySpan<byte> stream)
    {
        var frames = new List<byte[]>();
        int off = 0;
        while (off + 4 <= stream.Length)
        {
            uint len = BinaryPrimitives.ReadUInt32LittleEndian(stream[off..]);
            if (len == 0 || len > stream.Length - off - 4) break;
            frames.Add(stream.Slice(off + 4, (int)len).ToArray());
            off += 4 + (int)len;
        }
        return frames;
    }

    /// <summary>取出帧里的请求编号（第一条记录的字段 0x4a）。</summary>
    public static uint RequestId(ReadOnlySpan<byte> frame)
    {
        foreach (var r in Parse(frame))
            if (r.Field == global::RvpnKit.Core.Field.RequestId && r.Type == (byte)RecordType.UInt32)
                return r.AsUInt32();
        return 0xFFFF_FFFF;
    }
}
