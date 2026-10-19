using System.Buffers.Binary;
using System.Text;

namespace RvpnKit.Protocol;

/// <summary>
/// 线格式布局假设。字符串记录存在若干"前导空字符/填充"变体，靠
/// <see cref="AutoCalibrator"/> 在真实数据上以「可读产出最大化」为准则自动定标。
/// </summary>
public sealed record WireFormat(
    byte U32Type,
    byte U64Type,
    byte U8Type,
    byte StringType,
    int LengthWidth,
    bool LengthBigEndian,
    int PayloadSkip,
    int HeaderSkip,
    int Blob16Size)
{
    /// <summary>基于实测的默认假设（已在真实抓包上验证）。</summary>
    public static readonly WireFormat Default = new(
        U32Type: 0x04,
        U64Type: 0x08,
        U8Type: 0x0B,
        StringType: 0x03,
        LengthWidth: 2,
        LengthBigEndian: true,
        PayloadSkip: 1,
        HeaderSkip: 0,
        Blob16Size: 16);

    public override string ToString() =>
        $"u32=0x{U32Type:x2} u64=0x{U64Type:x2} u8=0x{U8Type:x2} str=0x{StringType:x2} " +
        $"len={LengthWidth}b{(LengthBigEndian ? "BE" : "LE")} skip={PayloadSkip} hdrs={HeaderSkip}";
}

/// <summary>
/// 自适应解码器。<b>设计原则：对真实数据永不崩溃</b> —— 遇到不认识的类型就跳一
/// 个字节重新同步；解析出的结果只在「通过语义校验」时才被采纳。
/// </summary>
public sealed class AdaptiveDecoder(WireFormat format)
{
    private readonly WireFormat _f = format;

    /// <summary>解码统计，用于给布局假设打分。</summary>
    public sealed class Stats
    {
        /// <summary>成功解析的字段数</summary>
        public int Fields;

        /// <summary>成功解析的字符串数</summary>
        public int Strings;

        /// <summary>字符串正文合计字节数</summary>
        public int StringBytes;

        /// <summary>失步次数</summary>
        public int Desyncs;

        /// <summary>被跳过的字节数</summary>
        public int Skipped;

        /// <summary>解析到的有效字节数</summary>
        public int Consumed;

        /// <summary>
        /// 质量分：可读产出越多越高，跳字节越多越低。
        /// 用于在候选布局之间做选择。
        /// </summary>
        public double Score => Strings * 10.0 + StringBytes / 8.0 - Skipped * 4.0 - Desyncs * 10.0;

        /// <summary>跳过字节占比</summary>
        public double SkipRatio(int total) => total == 0 ? 1.0 : (double)Skipped / total;
    }

    /// <summary>解析帧正文。</summary>
    public (List<RvpnField> Fields, Stats Stats) Decode(ReadOnlySpan<byte> body)
    {
        var fields = new List<RvpnField>(256);
        var stats = new Stats();
        int offset = _f.HeaderSkip;

        while (offset < body.Length)
        {
            int before = offset;
            if (TryReadField(body, ref offset, out var field, stats))
            {
                fields.Add(field);
                continue;
            }

            stats.Desyncs++;
            stats.Skipped++;
            offset = before + 1;

            // 跳过比例过高说明这组假设是错的，提前止损
            if (stats.Skipped > 256 && stats.SkipRatio(body.Length) > 0.5)
                break;
        }

        stats.Consumed = offset - stats.Skipped;
        stats.Fields = fields.Count;
        return (fields, stats);
    }

    /// <summary>尝试读出一个字段。</summary>
    public bool TryReadField(ReadOnlySpan<byte> b, ref int offset, out RvpnField field, Stats? stats)
    {
        field = null!;
        int i = offset;
        if (i + 3 > b.Length) return false;

        byte type = b[i];

        if (type == _f.StringType)
        {
            if (TryReadString(b, i, out ushort sfid, out string? s, out int end))
            {
                field = new RvpnField { Id = sfid, RawType = type, Value = s };
                offset = end;
                if (stats is not null)
                {
                    stats.Strings++;
                    stats.StringBytes += end - i;
                }
                return true;
            }
            return false;
        }

        // ── 标量类型：字段号取小端（实测）
        ushort fid = BinaryPrimitives.ReadUInt16LittleEndian(b[(i + 1)..]);
        int v = i + 3;

        if (type == _f.U32Type)
        {
            if (v + 4 > b.Length) return false;
            field = new RvpnField
            {
                Id = fid, RawType = type,
                Value = BinaryPrimitives.ReadUInt32LittleEndian(b[v..]),
            };
            offset = v + 4;
            return true;
        }

        if (type == _f.U64Type)
        {
            if (v + 8 > b.Length) return false;
            field = new RvpnField
            {
                Id = fid, RawType = type,
                Value = BinaryPrimitives.ReadUInt64LittleEndian(b[v..]),
            };
            offset = v + 8;
            return true;
        }

        if (type == _f.U8Type)
        {
            if (v + 1 > b.Length) return false;
            field = new RvpnField { Id = fid, RawType = type, Value = b[v] };
            offset = v + 1;
            return true;
        }

        return false;
    }

    /// <summary>
    /// 解析字符串记录。
    ///
    /// 实测布局：
    /// <code>
    ///   [03] [fid:u16 LE] [00 00] [len:u16 BE] [00] [UTF-16LE len 字节]
    ///                      └─ 固定填充 ─┘            └─ 前导空字符 ─┘
    /// </code>
    /// 其中 <c>len</c> 是正文字节数，正文首个字符为 U+0000。
    /// <see cref="WireFormat"/> 的 <c>LengthWidth/PayloadSkip</c> 控制变体，
    /// 以便在别的版本上也能定标。
    /// </summary>
    public bool TryReadString(ReadOnlySpan<byte> b, int t,
                              out ushort fid, out string? value, out int end)
    {
        fid = 0;
        value = null;
        end = t;

        int p = t + 1;
        if (p + 2 > b.Length) return false;
        fid = BinaryPrimitives.ReadUInt16LittleEndian(b[p..]);
        p += 2;

        // 固定 2 字节填充（实测恒为 00 00，但不强求，便于兼容变体）
        p += 2;
        if (p + _f.LengthWidth > b.Length) return false;

        int len = _f.LengthWidth switch
        {
            1 => b[p],
            2 => _f.LengthBigEndian
                    ? BinaryPrimitives.ReadUInt16BigEndian(b[p..])
                    : BinaryPrimitives.ReadUInt16LittleEndian(b[p..]),
            3 => _f.LengthBigEndian
                    ? (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]
                    : b[p] | (b[p + 1] << 8) | (b[p + 2] << 16),
            4 => _f.LengthBigEndian
                    ? BinaryPrimitives.ReadInt32BigEndian(b[p..])
                    : BinaryPrimitives.ReadInt32LittleEndian(b[p..]),
            _ => -1,
        };
        p += _f.LengthWidth;

        if (len <= 0 || (len & 1) != 0 || len > 8192) return false;

        int body = p + _f.PayloadSkip;
        if (body + len > b.Length) return false;

        string s = Encoding.Unicode.GetString(b.Slice(body, len));

        // 语义校验：正文应当以 U+0000 起头（实测规律），且整体可打印
        if (!Plausible(s)) return false;

        value = s;
        end = body + len;
        return true;
    }

    /// <summary>合理性校验，用于拒绝「偶然对齐」的假阳性。</summary>
    internal static bool Plausible(string s)
    {
        if (s.Length == 0) return false;

        // 允许开头有一个空字符（实测存在），其余必须可打印
        int start = s[0] == '\0' ? 1 : 0;
        if (s.Length - start < 1) return false;

        int bad = 0;
        int total = 0;
        for (int k = start; k < s.Length; k++)
        {
            char c = s[k];
            total++;
            if (char.IsControl(c) && c is not ('\t' or '\r' or '\n')) bad++;
            else if (char.GetUnicodeCategory(c) is System.Globalization.UnicodeCategory.PrivateUse
                     or System.Globalization.UnicodeCategory.OtherNotAssigned) bad++;
        }

        return total > 0 && bad == 0;
    }
}

/// <summary>
/// 在真实抓包上给多种布局假设打分，挑出自洽度最高的一组。
/// 这是「把编解码器交给真实数据裁决」的落地 —— 不靠人工肉眼推断。
/// </summary>
public static class AutoCalibrator
{
    /// <summary>一个候选布局及其评分。</summary>
    public sealed record Candidate(WireFormat Format, double Score, int Strings, int Fields,
                                   int Skipped, int Desyncs);

    /// <summary>枚举候选布局并返回按分值降序的排名。</summary>
    public static IReadOnlyList<Candidate> Rank(IEnumerable<byte[]> frames)
    {
        var list = frames.ToList();
        var results = new List<Candidate>();

        foreach (int lenWidth in new[] { 2, 1, 3, 4 })
            foreach (bool be in new[] { true, false })
                foreach (int skip in new[] { 1, 0, 2 })
                    foreach (int hdr in new[] { 0, 1, 2, 3 })
                    {
                        var fmt = WireFormat.Default with
                        {
                            LengthWidth = lenWidth,
                            LengthBigEndian = be,
                            PayloadSkip = skip,
                            HeaderSkip = hdr,
                        };
                        var dec = new AdaptiveDecoder(fmt);

                        int strings = 0, skipped = 0, desyncs = 0, fields = 0;
                        double score = 0;

                        foreach (var body in list)
                        {
                            var (fs, st) = dec.Decode(body);
                            fields += fs.Count;
                            strings += st.Strings;
                            skipped += st.Skipped;
                            desyncs += st.Desyncs;
                            score += st.Score;
                        }

                        results.Add(new Candidate(fmt, score, strings, fields, skipped, desyncs));
                    }

        return results.OrderByDescending(r => r.Score).ToList();
    }

    /// <summary>把带 u32 LE 长度前缀的字节流切分成帧。</summary>
    public static List<byte[]> SplitFrames(byte[] data, int maxFrames = int.MaxValue)
    {
        var frames = new List<byte[]>();
        int off = 0;
        while (off + 4 <= data.Length && frames.Count < maxFrames)
        {
            int len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(off));
            if (len <= 0 || off + 4 + len > data.Length) break;
            frames.Add(data.AsSpan(off + 4, len).ToArray());
            off += 4 + len;
        }
        return frames;
    }
}
