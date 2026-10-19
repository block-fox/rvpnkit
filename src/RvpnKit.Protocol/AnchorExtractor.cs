using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace RvpnKit.Protocol;

/// <summary>
/// 锚点驱动的字段抽取器。
///
/// 原理：字符串记录的<b>头部是高度规整</b>的，实测为
/// <code>
///   03 | fid:u16 LE | 00 00 | len:u16 BE | 00 | UTF-16LE(len 字节)
/// </code>
/// 其中最后那个 <c>00</c> 是正文的前导空字符。
/// 用「<c>03</c> + 任意字段号 + <c>00 00</c>」作为锚点定位记录起点，再校验
/// <c>len == 2×字符数 + 2</c> 与可打印性，即可把误报压到接近零。
///
/// 这条路径不依赖容器层定标，因此比纯结构解析更抗版本变化；
/// 拿到的字段号也能直接用于语义映射。
/// </summary>
public static class AnchorExtractor
{
    /// <summary>抽取到的一条字符串记录。</summary>
    public readonly record struct Record(int Offset, ushort FieldId, string Value)
    {
        /// <summary>展示用文本</summary>
        public override string ToString() => $"0x{FieldId:x4}\t{Value}";
    }

    private static readonly Regex Ipv4Re = new(@"^(?:\d{1,3}\.){3}\d{1,3}$", RegexOptions.Compiled);
    private static readonly Regex UrlRe = new(@"^https?://\S+$", RegexOptions.Compiled);
    private static readonly Regex ConnRe = new(@"^\s*[\[\]\d\.:]{2,}:\d+\s*(->|<-)\s*[\[\]\d\.:]{2,}:\d+\s*$", RegexOptions.Compiled);

    /// <summary>
    /// 扫描整个字节流，抽取所有字符串记录。
    /// </summary>
    /// <param name="data">原始字节</param>
    /// <param name="requireLeadingNul">是否要求正文以空字符起头（实测为真，可显著降噪）</param>
    public static List<Record> Extract(byte[] data, bool requireLeadingNul = true)
    {
        var results = new List<Record>(512);

        for (int i = 0; i + 8 < data.Length; i++)
        {
            if (data[i] != 0x03) continue;

            // 头部：fid:u16 LE
            ushort fid = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i + 1, 2));

            // 锚点特征：紧接着两字节 00 00
            if (data[i + 3] != 0x00 || data[i + 4] != 0x00) continue;

            // 长度：u16 BE，单位字节
            int len = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i + 5, 2));
            if (len < 4 || len > 4096 || (len & 1) != 0) continue;

            int body = i + 7;
            if (body + len > data.Length) continue;

            if (requireLeadingNul && data[body] != 0x00) continue;

            string s = Encoding.Unicode.GetString(data.AsSpan(body, len));
            string trimmed = s.TrimStart('\0');
            if (trimmed.Length < 1) continue;

            // 正文尾部必须是空字符（实测规律），进一步排除偶然对齐
            if (data[body + len - 1] != 0x00 || data[body + len - 2] != 0x00) continue;

            if (!StrictlyPrintable(trimmed)) continue;

            results.Add(new Record(i, fid, trimmed));
            i = body + len - 1;
        }

        return results;
    }

    /// <summary>严格可打印校验（仅 ASCII + 常见 CJK，拒绝符号乱码）。</summary>
    private static bool StrictlyPrintable(string s)
    {
        int good = 0, total = 0;
        foreach (char c in s)
        {
            total++;
            if (c >= 0x20 && c <= 0x7E) good++;                        // ASCII 可见
            else if (c is '\t' or '\r' or '\n') good++;
            else if (c >= 0x4E00 && c <= 0x9FFF) good++;               // CJK 统一表意
            else if (c >= 0x3000 && c <= 0x303F) good++;               // CJK 标点
            else if (c >= 0xFF00 && c <= 0xFFEF) good++;               // 全角
            else if (c >= 0x0400 && c <= 0x04FF) good++;               // 西里尔
            else if (c >= 0x00C0 && c <= 0x024F) good++;               // 拉丁扩展
            else if (c >= 0x2600 && c <= 0x27BF) good++;               // 符号/emoji 区
            else if (c >= 0x1F300 && c <= 0x1FAFF) good++;             // emoji
        }
        return total > 0 && good * 10 >= total * 9;                    // ≥90%
    }

    /// <summary>按字段号分组，便于推断语义。</summary>
    public static Dictionary<ushort, List<Record>> GroupByField(IEnumerable<Record> records)
        => records.GroupBy(r => r.FieldId).ToDictionary(g => g.Key, g => g.ToList());

    /// <summary>生成便于阅读的分组报告。</summary>
    public static string Summarize(IEnumerable<Record> records)
    {
        var list = records.ToList();
        var sb = new StringBuilder();
        sb.AppendLine($"共抽取 {list.Count:N0} 条字符串记录（锚点法，已严格校验）");

        foreach (var g in list.GroupBy(r => r.FieldId).OrderBy(g => g.Key))
        {
            var values = g.Select(r => r.Value).Distinct().ToList();
            sb.AppendLine();
            sb.AppendLine($"── 字段 0x{g.Key:x4}   出现 {g.Count():N0} 次，去重 {values.Count:N0} 种 ──");
            foreach (var v in values.Take(12))
                sb.AppendLine($"     {v}");
            if (values.Count > 12)
                sb.AppendLine($"     … 另有 {values.Count - 12:N0} 种");
        }

        return sb.ToString();
    }

    /// <summary>把抽取结果按内容分类统计。</summary>
    public static (int Ip, int Url, int Conn, int Text) ClassifyCounts(IEnumerable<Record> records)
    {
        int ip = 0, url = 0, conn = 0, text = 0;
        foreach (var r in records)
        {
            if (Ipv4Re.IsMatch(r.Value)) ip++;
            else if (UrlRe.IsMatch(r.Value)) url++;
            else if (ConnRe.IsMatch(r.Value)) conn++;
            else text++;
        }
        return (ip, url, conn, text);
    }
}
