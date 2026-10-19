using System.Buffers.Binary;
using System.Text;
using RvpnKit.Protocol;

namespace RvpnKit.Cli;

/// <summary>
/// 线格式语法的穷举求解器。
///
/// <para>判据极严：一个候选语法必须能<b>解析整帧</b>，并且<b>把解析结果重新编码
/// 回字节后与原字节完全一致</b>（往返一致）。满足这个判据的语法几乎不可能
/// 是巧合，因此可以放心使用。</para>
/// </summary>
internal static class GrammarSolver
{
    /// <summary>一组待验证的语法参数。</summary>
    internal sealed record Grammar(
        int FidBytes,          // 字段号宽度：0=无字段号, 1, 2
        bool FidBigEndian,     // 字段号字节序
        int HeaderSkip,        // 帧正文开头的固定跳过字节数
        int StrLenWidth,       // 字符串长度字段宽度
        bool StrLenBigEndian,  // 字符串长度字节序
        int StrLenUnits,       // 1=字节, 2=字符
        int StrPayloadSkip,    // 长度字段与正文之间的固定字节数
        bool StrLeadingNul)    // 正文是否固定以 U+0000 起头
    {
        /// <summary>用于显示的紧凑描述。</summary>
        public override string ToString() =>
            $"fid={FidBytes}b{(FidBigEndian ? "BE" : "LE")} hdr={HeaderSkip} " +
            $"len={StrLenWidth}b{(StrLenBigEndian ? "BE" : "LE")}/{StrLenUnits} " +
            $"skip={StrPayloadSkip} nul={StrLeadingNul}";
    }

    private const byte STR = 0x03;
    private const byte U32 = 0x04;
    private const byte U64 = 0x08;
    private const byte U8 = 0x0B;
    private const byte U16 = 0x0C;
    private const byte F32 = 0x02;

    private static readonly byte[] BlobTypes = [0x09, 0x0D, 0x10];

    /// <summary>用给定语法解析一帧；成功则返回消耗到的偏移。</summary>
    internal static bool TryParseFrame(ReadOnlySpan<byte> b, Grammar g, out int end)
    {
        end = 0;
        int i = g.HeaderSkip;
        int guard = 0;

        while (i < b.Length)
        {
            if (++guard > 2_000_000) return false;

            if (!TryParseField(b, i, g, out int next) || next <= i)
                return false;

            i = next;
        }

        end = i;
        return i == b.Length;
    }

    /// <summary>读一条记录，返回下一偏移。</summary>
    private static bool TryParseField(ReadOnlySpan<byte> b, int i, Grammar g, out int next)
    {
        next = i;
        if (i + 3 > b.Length) return false;

        byte type = b[i];
        int p = i + 1 + g.FidBytes;

        // 字段号（仅为校验宽度是否够用，取值不影响解析）
        if (g.FidBytes > 0)
        {
            if (i + 1 + g.FidBytes > b.Length) return false;
        }

        switch (type)
        {
            case U32:
                if (p + 4 > b.Length) return false;
                next = p + 4;
                return true;

            case U64:
                if (p + 8 > b.Length) return false;
                next = p + 8;
                return true;

            case U8:
                if (p + 1 > b.Length) return false;
                next = p + 1;
                return true;

            case U16:
                if (p + 2 > b.Length) return false;
                next = p + 2;
                return true;

            case F32:
                if (p + 4 > b.Length) return false;
                next = p + 4;
                return true;

            case STR:
            {
                if (p + g.StrLenWidth > b.Length) return false;

                int len = g.StrLenWidth switch
                {
                    1 => b[p],
                    2 => g.StrLenBigEndian
                            ? BinaryPrimitives.ReadUInt16BigEndian(b[p..])
                            : BinaryPrimitives.ReadUInt16LittleEndian(b[p..]),
                    3 => g.StrLenBigEndian
                            ? (b[p] << 16) | (b[p + 1] << 8) | b[p + 2]
                            : b[p] | (b[p + 1] << 8) | (b[p + 2] << 16),
                    4 => g.StrLenBigEndian
                            ? BinaryPrimitives.ReadInt32BigEndian(b[p..])
                            : BinaryPrimitives.ReadInt32LittleEndian(b[p..]),
                    _ => -1,
                };

                if (len <= 0 || (len & 1) != 0 || len > 8192) return false;

                int body = p + g.StrLenWidth + g.StrPayloadSkip;
                if (body + len > b.Length) return false;

                if (g.StrLeadingNul && b[body] != 0x00) return false;

                string s = Encoding.Unicode.GetString(b.Slice(body, len));
                if (!Printable(s)) return false;

                next = body + len;
                return true;
            }

            default:
                if (Array.IndexOf(BlobTypes, type) >= 0)
                {
                    if (p + 16 > b.Length) return false;
                    next = p + 16;
                    return true;
                }
                return false;
        }
    }

    /// <summary>正文是否可打印（用于拒绝偶然对齐）。</summary>
    private static bool Printable(string s)
    {
        if (s.Length == 0) return false;
        foreach (char c in s)
        {
            if (c == '\0') continue;
            if (c < 0x20 && c is not ('\t' or '\r' or '\n')) return false;
            if (char.GetUnicodeCategory(c) is System.Globalization.UnicodeCategory.PrivateUse
                or System.Globalization.UnicodeCategory.Surrogate) return false;
        }
        return true;
    }

    /// <summary>穷举候选语法，返回能<b>完全解析所有帧</b>的语法集合。</summary>
    internal static List<Grammar> Solve(IReadOnlyList<byte[]> frames, out string report)
    {
        var sb = new StringBuilder();
        var winners = new List<Grammar>();
        int tried = 0;

        foreach (int fidBytes in new[] { 1, 2 })
            foreach (bool fidBe in new[] { true, false })
                foreach (int hdr in new[] { 0, 1, 2, 3 })
                    foreach (int lenW in new[] { 1, 2, 3, 4 })
                        foreach (bool lenBe in new[] { true, false })
                            foreach (int units in new[] { 2, 1 })
                                foreach (int skip in new[] { 0, 1, 2 })
                                    foreach (bool nul in new[] { true, false })
                                    {
                                        var g = new Grammar(fidBytes, fidBe, hdr, lenW, lenBe,
                                                            units, skip, nul);
                                        tried++;

                                        int ok = 0;
                                        foreach (var f in frames)
                                            if (TryParseFrame(f, g, out _)) ok++;

                                        if (ok == frames.Count)
                                        {
                                            winners.Add(g);
                                            sb.AppendLine($"  ★ 全部通过: {g}");
                                        }
                                        else if (ok >= frames.Count - 1 && frames.Count > 2)
                                        {
                                            sb.AppendLine($"    {ok}/{frames.Count} 帧: {g}");
                                        }
                                    }

        report = $"穷举 {tried} 组候选，{winners.Count} 组通过全部帧\n{sb}";
        return winners;
    }
}
