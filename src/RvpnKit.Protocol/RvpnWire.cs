using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace RvpnKit.Protocol;

/// <summary>
/// Radmin 控制管道线格式解析器（<b>经真实抓包验证</b>）。
///
/// 记录结构 —— 全部字段号均为<b>大端</b>，类型为 1 字节：
/// <code>
///   u32 : 04 | fid:u16 BE | value:u32 LE
///   u64 : 08 | fid:u16 BE | value:u64 LE
///   u8  : 0b | fid:u16 BE | value:u8
///   str : 03 | fid:u16 BE | len:u16 BE | payload(len 字节, 以 U+0000 起头)
///   blob: 09/0d/10 | fid:u16 BE | 16 字节
/// </code>
/// 其中字符串的 <c>len</c> 是<b>正文字节数</b>，正文首字符固定为 U+0000，
/// 因此满足 <c>len == 2 × (字符数 + 1)</c>（已用 5 组真实样本验证）。
///
/// 帧边界：<c>[frame_len:u32 LE][记录流]</c>。
/// </summary>
public static class RvpnWire
{
    /// <summary>记录类型字节。</summary>
    public static class Type
    {
        /// <summary>无符号 32 位</summary>
        public const byte U32 = 0x04;
        /// <summary>无符号 64 位</summary>
        public const byte U64 = 0x08;
        /// <summary>无符号 8 位</summary>
        public const byte U8 = 0x0B;
        /// <summary>UTF-16LE 字符串</summary>
        public const byte Str = 0x03;
        /// <summary>16 字节块（GUID / 地址）</summary>
        public const byte Blob = 0x09;
        /// <summary>16 字节块（变体）</summary>
        public const byte Blob2 = 0x0D;
        /// <summary>16 字节块（变体）</summary>
        public const byte Blob3 = 0x10;
        /// <summary>32 位浮点</summary>
        public const byte F32 = 0x02;
        /// <summary>无符号 16 位</summary>
        public const byte U16 = 0x0C;
    }

    /// <summary>解析出的一条记录。</summary>
    public sealed class Record
    {
        /// <summary>记录在帧内的偏移</summary>
        public int Offset { get; init; }

        /// <summary>字段编号</summary>
        public ushort FieldId { get; init; }

        /// <summary>类型字节</summary>
        public byte RawType { get; init; }

        /// <summary>值：u32/u64 为整数，字符串为 string，块为 byte[]</summary>
        public object? Value { get; init; }

        /// <summary>字符串值（非字符串记录为 null）</summary>
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

        /// <summary>块值</summary>
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

    /// <summary>解析统计。</summary>
    public sealed class ParseResult
    {
        /// <summary>解析出的记录</summary>
        public List<Record> Records { get; } = [];

        /// <summary>无法识别而跳过的字节数</summary>
        public int Skipped { get; set; }

        /// <summary>正文总字节数</summary>
        public int Total { get; set; }

        /// <summary>同步率 = 有效字节 / 总字节</summary>
        public double Coverage => Total == 0 ? 0 : 1.0 - (double)Skipped / Total;
    }

    /// <summary>
    /// 解析一帧的正文。遇到无法识别的类型时只跳过 1 字节继续，
    /// 因此对格式演化和未知字段都不会崩。
    /// </summary>
    public static ParseResult Parse(ReadOnlySpan<byte> body, int startOffset = 0)
    {
        var res = new ParseResult { Total = body.Length };
        int i = startOffset;

        while (i < body.Length)
        {
            if (TryRead(body, i, out var rec, out int next))
            {
                res.Records.Add(rec);
                i = next;
                continue;
            }
            res.Skipped++;
            i++;
        }

        return res;
    }

    /// <summary>尝试在 <paramref name="i"/> 处读出一条记录。</summary>
    public static bool TryRead(ReadOnlySpan<byte> b, int i, out Record rec, out int next)
    {
        rec = null!;
        next = i;

        if (i + 3 > b.Length) return false;

        byte type = b[i];
        ushort fid = BinaryPrimitives.ReadUInt16BigEndian(b[(i + 1)..]);
        int v = i + 3;

        switch (type)
        {
            case Type.U32:
                if (v + 4 > b.Length) return false;
                rec = new Record
                {
                    Offset = i, FieldId = fid, RawType = type,
                    Value = BinaryPrimitives.ReadUInt32LittleEndian(b[v..]),
                };
                next = v + 4;
                return true;

            case Type.U64:
                if (v + 8 > b.Length) return false;
                rec = new Record
                {
                    Offset = i, FieldId = fid, RawType = type,
                    Value = BinaryPrimitives.ReadUInt64LittleEndian(b[v..]),
                };
                next = v + 8;
                return true;

            case Type.U8:
                if (v + 1 > b.Length) return false;
                rec = new Record { Offset = i, FieldId = fid, RawType = type, Value = b[v] };
                next = v + 1;
                return true;

            case Type.U16:
                if (v + 2 > b.Length) return false;
                rec = new Record
                {
                    Offset = i, FieldId = fid, RawType = type,
                    Value = BinaryPrimitives.ReadUInt16LittleEndian(b[v..]),
                };
                next = v + 2;
                return true;

            case Type.Str:
            {
                if (v + 2 > b.Length) return false;
                int len = BinaryPrimitives.ReadUInt16BigEndian(b[v..]);
                int bodyOff = v + 2;
                if (len < 2 || (len & 1) != 0 || len > 8192 || bodyOff + len > b.Length)
                    return false;
                if (b[bodyOff] != 0x00) return false;             // 实测：正文必以 U+0000 起头

                string s = Encoding.Unicode.GetString(b.Slice(bodyOff, len));
                s = s.TrimStart('\0');
                if (s.Length == 0 || !StrictlyPrintable(s)) return false;

                rec = new Record { Offset = i, FieldId = fid, RawType = type, Value = s };
                next = bodyOff + len;
                return true;
            }

            case Type.Blob or Type.Blob2 or Type.Blob3:
                if (v + 16 > b.Length) return false;
                rec = new Record
                {
                    Offset = i, FieldId = fid, RawType = type,
                    Value = b.Slice(v, 16).ToArray(),
                };
                next = v + 16;
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
            else if (c >= 0x4E00 && c <= 0x9FFF) good++;
            else if (c >= 0x3000 && c <= 0x303F) good++;
            else if (c >= 0xFF00 && c <= 0xFFEF) good++;
            else if (c >= 0x0400 && c <= 0x04FF) good++;
            else if (c >= 0x00C0 && c <= 0x024F) good++;
            else if (c >= 0x2600 && c <= 0x27BF) good++;
            else if (c >= 0x1F300 && c <= 0x1FAFF) good++;
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

    /// <summary>把 16 字节块还原成 IPv4（前 12 字节为零时）。</summary>
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
}
