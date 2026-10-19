using System.Text;
using System.Text.RegularExpressions;

namespace RvpnKit.Protocol;

/// <summary>
/// 内容驱动的字段抽取器。
///
/// 线格式的容器层还有细节未完全定标，但**字符串内容是自证的** ——
/// 一条真正的 UTF-16LE 字符串必然是可打印字符的长游程。因此这里不依赖
/// 结构对齐，直接扫描可打印长游程并按内容分类，从而稳定拿到业务数据。
///
/// 这比「先解对结构再取数据」更抗版本变化，代价是拿不到字段编号的完整语义。
/// 两者结合：结构化解码（<see cref="AdaptiveDecoder"/>）用于我们<em>自己发出的</em>
/// 报文（格式已知），内容抽取用于解析服务端回包。
/// </summary>
public static class ContentHarvester
{
    /// <summary>抽取到的一条字符串及其上下文。</summary>
    public readonly record struct Hit(int Offset, string Value, HarvestKind Kind)
    {
        /// <summary>用于展示的格式化文本。</summary>
        public override string ToString() => $"[0x{Offset:x6}] {Kind}: {Value}";
    }

    /// <summary>按内容判定的类别。</summary>
    public enum HarvestKind
    {
        /// <summary>无法归类但确实是可读文本</summary>
        Text,

        /// <summary>IPv4 地址</summary>
        IPv4,

        /// <summary>IPv6 地址</summary>
        IPv6,

        /// <summary>连接映射，形如 host:port -> host:port</summary>
        Connection,

        /// <summary>主机名 / 版本号之类的标识</summary>
        Identifier,

        /// <summary>URL</summary>
        Url,
    }

    private static readonly Regex Ipv4Re = new(@"^(?:\d{1,3}\.){3}\d{1,3}$", RegexOptions.Compiled);
    private static readonly Regex ConnRe = new(@"^\s*[\[\.\d:]{3,}:\d+\s*(->|<-)\s*[\[\.\d:]{3,}:\d+\s*$", RegexOptions.Compiled);
    private static readonly Regex UrlRe = new(@"https?://", RegexOptions.Compiled);
    private static readonly Regex IdentRe = new(@"^[A-Za-z0-9_\-\.\u4e00-\u9fff \[\]\(\)!！？?]{2,64}$", RegexOptions.Compiled);

    /// <summary>
    /// 扫描一段字节，返回所有可读字符串。只接受**严格可打印**的游程，
    /// 因此对任意二进制数据都不会产生乱码噪声。
    /// </summary>
    public static List<Hit> Harvest(byte[] data, int minChars = 3, int maxChars = 512)
    {
        var hits = new List<Hit>();
        int i = 0;
        int n = data.Length;

        while (i + 2 <= n)
        {
            // 尝试从 i 开始读一段 UTF-16LE 可打印游程
            var sb = new StringBuilder();
            int j = i;
            while (j + 2 <= n)
            {
                char c = (char)(data[j] | (data[j + 1] << 8));
                if (IsAcceptable(c))
                {
                    sb.Append(c);
                    j += 2;
                    if (sb.Length > maxChars) break;
                }
                else break;
            }

            if (sb.Length >= minChars)
            {
                string s = sb.ToString();
                // 去掉前导空白/空字符再判定
                string trimmed = s.TrimStart('\0', ' ', '\t');
                if (trimmed.Length >= minChars)
                    hits.Add(new Hit(i, trimmed, Classify(trimmed)));
                i = j;
            }
            else
            {
                i += 1;
            }
        }

        return hits;
    }

    /// <summary>判断字符是否允许出现在抽取结果里。</summary>
    private static bool IsAcceptable(char c)
    {
        if (c == '\0') return false;                       // 空字符一律当分隔
        if (c is '\r' or '\n' or '\t') return true;
        if (c < 0x20 || c == 0x7F) return false;           // 其他控制字符拒绝
        var cat = char.GetUnicodeCategory(c);
        return cat switch
        {
            System.Globalization.UnicodeCategory.Control => false,
            System.Globalization.UnicodeCategory.PrivateUse => false,
            System.Globalization.UnicodeCategory.OtherNotAssigned => false,
            System.Globalization.UnicodeCategory.Surrogate => false,
            _ => true,
        };
    }

    /// <summary>按内容给字符串归类。</summary>
    public static HarvestKind Classify(string s)
    {
        if (UrlRe.IsMatch(s)) return HarvestKind.Url;
        if (ConnRe.IsMatch(s)) return HarvestKind.Connection;
        if (Ipv4Re.IsMatch(s)) return HarvestKind.IPv4;
        if (s.Contains(':') && s.Count(c => c == ':') >= 2 && s.All(c => "0123456789abcdefABCDEF:.[]%".Contains(c)))
            return HarvestKind.IPv6;
        if (IdentRe.IsMatch(s)) return HarvestKind.Identifier;
        return HarvestKind.Text;
    }

    /// <summary>把一次抽取结果整理成便于阅读的分组报告。</summary>
    public static string Summarize(IEnumerable<Hit> hits)
    {
        var list = hits.ToList();
        var sb = new StringBuilder();
        sb.AppendLine($"共抽取到 {list.Count:N0} 条可读字符串");

        foreach (var group in list.GroupBy(h => h.Kind).OrderByDescending(g => g.Count()))
        {
            sb.AppendLine();
            sb.AppendLine($"── {group.Key}  共 {group.Count():N0} 条 ──");
            foreach (var hit in group.Take(25))
                sb.AppendLine($"   {hit.Value}");
            if (group.Count() > 25)
                sb.AppendLine($"   … 另有 {group.Count() - 25:N0} 条");
        }

        return sb.ToString();
    }

    /// <summary>
    /// 从抽取结果里还原「节点连接表」：形如
    /// <c>::57162 -&gt; 2408:820c:a938:fd90:24c8:f639:c32a:a290</c> 的记录。
    /// 这是判断节点当前走了直连 / 中继 / UDP 打洞的关键依据。
    /// </summary>
    public static List<(string Local, string Remote)> ParseConnections(IEnumerable<Hit> hits)
    {
        var result = new List<(string, string)>();
        foreach (var h in hits)
        {
            if (h.Kind != HarvestKind.Connection) continue;
            var parts = h.Value.Split("->", StringSplitOptions.TrimEntries);
            if (parts.Length == 2)
                result.Add((parts[0], parts[1]));
        }
        return result;
    }
}
