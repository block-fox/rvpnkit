using System.Buffers.Binary;
using System.Text;

namespace RvpnKit.Client;

/// <summary>
/// 把虚拟 IP 与节点别名关联起来。
///
/// <para><b>背景：</b>数据源天然是割裂的 —— 网卡邻居表有 IP 没有身份，
/// 服务日志有身份没有 IP。两者的交集只能从控制管道的状态快照里挖。</para>
///
/// <para><b>已确认的规律（实测）：</b></para>
/// <list type="bullet">
/// <item>虚拟 IP 在管道流中以 <b>4 字节原始形式</b>出现（如 26.169.61.178 →
/// <c>1a a9 3d b2</c>），且每个 IP 在一次快照里出现约 2 次。</item>
/// <item>别名以 <b>UTF-16LE</b> 出现，且起点可能是<b>奇数对齐</b>
/// （这一点早期漏掉，导致别名几乎全部漏检）。</item>
/// <item>同一条节点记录里，别名与 IP 相距约 100~170 字节，但分布并不单峰，
/// 因此<b>纯邻近配对不可靠</b>。</item>
/// </list>
///
/// <para><b>本类采用的强判据：</b>用服务日志里的已知别名做白名单，
/// 只接受在流中<b>精确命中</b>的别名文本，再与邻近 IP 配对。
/// 这样能剔除大量由二进制块误解码产生的假别名（如 <c>谚粶</c>）。</para>
/// </summary>
public static class AliasResolver
{
    /// <summary>一条 IP ↔ 别名 关联结果。</summary>
    public sealed class Binding
    {
        /// <summary>虚拟 IP</summary>
        public required string Ip { get; init; }

        /// <summary>节点别名</summary>
        public required string Alias { get; init; }

        /// <summary>别名与 IP 在流中的字节距离</summary>
        public int Distance { get; init; }

        /// <summary>是否命中已知别名白名单</summary>
        public bool Confirmed { get; init; }

        /// <inheritdoc/>
        public override string ToString() => $"{Ip} ←→ {Alias} (Δ{Distance})";
    }

    /// <summary>Radmin 虚拟网段首字节。</summary>
    private const byte RadminFirstOctet = 26;

    /// <summary>邻居表里找 IP 时使用的搜索窗口（字节）。</summary>
    private const int PairWindow = 300;

    /// <summary>
    /// 从管道状态流中解析出 IP ↔ 别名 的关联。
    /// </summary>
    /// <param name="streamBytes">控制管道的原始字节流</param>
    /// <param name="knownAliases">
    /// 已知别名白名单（通常来自服务日志）。传入空集合时退化为纯邻近配对，
    /// 置信度显著下降。
    /// </param>
    public static List<Binding> Resolve(byte[] streamBytes, IReadOnlySet<string> knownAliases)
    {
        if (streamBytes.Length == 0) return [];

        var ipAnchors = FindIpHits(streamBytes);
        if (ipAnchors.Count == 0) return [];

        var nameHits = FindAliasHits(streamBytes, knownAliases);
        if (nameHits.Count == 0) return [];

        var offsets = nameHits.Select(h => h.Offset).ToArray();
        Array.Sort(offsets);

        var best = new Dictionary<string, Binding>(StringComparer.Ordinal);

        foreach (var (ipOffset, ip) in ipAnchors)
        {
            // 在 IP 附近找最近的别名命中
            int lo = LowerBound(offsets, ipOffset - PairWindow);
            Binding? pick = null;

            for (int k = lo; k < nameHits.Count && k < lo + 12; k++)
            {
                var h = nameHits[k];
                int d = Math.Abs(h.Offset - ipOffset);
                if (d > PairWindow) continue;

                // 同一别名被多个 IP 吸附时，取距离最近者
                if (pick is null || d < pick.Distance)
                {
                    pick = new Binding
                    {
                        Ip = ip,
                        Alias = h.Alias,
                        Distance = d,
                        Confirmed = h.Confirmed,
                    };
                }
            }

            if (pick is null) continue;

            // 每个 IP 只保留最优（距离最近）的一条
            if (!best.TryGetValue(ip, out var cur) || pick.Distance < cur.Distance)
                best[ip] = pick;
        }

        // 反向去重：同一别名不应同时属于两个 IP（取距离更近者）
        var byAlias = new Dictionary<string, Binding>(StringComparer.Ordinal);
        foreach (var b in best.Values.OrderBy(x => x.Distance))
        {
            if (!byAlias.ContainsKey(b.Alias))
                byAlias[b.Alias] = b;
        }

        return byAlias.Values
            .OrderBy(b => b.Ip, Comparer<string>.Create(CompareIp))
            .ToList();
    }

    /// <summary>比较两个 IPv4 字符串的数值顺序。</summary>
    private static int CompareIp(string? a, string? b)
    {
        if (!TryParseIpv4(a, out var pa)) return -1;
        if (!TryParseIpv4(b, out var pb)) return 1;
        for (int i = 0; i < 4; i++)
        {
            int c = pa[i].CompareTo(pb[i]);
            if (c != 0) return c;
        }
        return 0;
    }

    private static bool TryParseIpv4(string? s, out byte[] parts)
    {
        parts = [];
        if (string.IsNullOrEmpty(s)) return false;
        var seg = s.Split('.');
        if (seg.Length != 4) return false;
        parts = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (!byte.TryParse(seg[i], out parts[i])) return false;
        }
        return true;
    }

    /// <summary>扫描流中所有 4 字节形态的虚拟 IP。</summary>
    private static List<(int Offset, string Ip)> FindIpHits(byte[] b)
    {
        var hits = new List<(int, string)>();

        for (int i = 0; i + 3 < b.Length; i++)
        {
            if (b[i] != RadminFirstOctet) continue;

            byte x = b[i + 1], y = b[i + 2], z = b[i + 3];

            // 排除明显不是地址的形态：后三字节全 0（网段本身）、
            // 或看起来是 UTF-16 文本的一部分（交替出现 0x00）
            if (x == 0 && y == 0 && z == 0) continue;
            if (y == 0x00 && z == 0x00) continue;

            hits.Add((i, $"{RadminFirstOctet}.{x}.{y}.{z}"));
        }

        return hits;
    }

    /// <summary>流中精确命中的别名。</summary>
    private readonly record struct NameHit(int Offset, string Alias, bool Confirmed);

    /// <summary>
    /// 扫描流中所有 UTF-16LE 可读游程，并筛选出「像别名」的片段。
    ///
    /// <para>两种对齐都要扫：实测别名的起始偏移可能是奇数。</para>
    /// </summary>
    private static List<NameHit> FindAliasHits(byte[] b, IReadOnlySet<string> known)
    {
        var hits = new List<NameHit>(512);
        var seen = new HashSet<(int, string)>();

        for (int phase = 0; phase < 2; phase++)
        {
            int i = phase;
            while (i + 2 <= b.Length)
            {
                // 尝试读一段 UTF-16LE
                var sb = new StringBuilder(64);
                int j = i;
                while (j + 2 <= b.Length && sb.Length < 64)
                {
                    char c = (char)(b[j] | (b[j + 1] << 8));
                    if (!IsTextChar(c)) break;
                    sb.Append(c);
                    j += 2;
                }

                string s = sb.ToString().Trim();
                if (s.Length >= 2)
                {
                    if (IsAliasLike(s))
                    {
                        bool confirmed = known.Contains(s);
                        if (confirmed || known.Count == 0)
                        {
                            if (seen.Add((i, s)))
                                hits.Add(new NameHit(i, s, confirmed));
                        }
                    }
                    i = j > i ? j : i + 2;
                }
                else
                {
                    i += 2;
                }
            }
        }

        hits.Sort((a, b2) => a.Offset.CompareTo(b2.Offset));
        return hits;
    }

    /// <summary>判断字符是否可能出现在正常文本中。</summary>
    private static bool IsTextChar(char c)
    {
        if (c == '\0') return false;
        if (c is '\t' or '\r' or '\n') return true;
        if (c < 0x20 || c == 0x7F) return false;

        var cat = char.GetUnicodeCategory(c);
        return cat switch
        {
            System.Globalization.UnicodeCategory.Control => false,
            System.Globalization.UnicodeCategory.Format => false,
            System.Globalization.UnicodeCategory.PrivateUse => false,
            System.Globalization.UnicodeCategory.Surrogate => false,
            System.Globalization.UnicodeCategory.OtherNotAssigned => false,
            System.Globalization.UnicodeCategory.SpaceSeparator => false,
            _ => true,
        };
    }

    /// <summary>形如别名的字符串：含字母数字或汉字，长度合理，不是纯十六进制。</summary>
    private static bool IsAliasLike(string s)
    {
        if (s.Length is < 2 or > 60) return false;

        bool hasAlnum = false;
        bool hasLetter = false;
        foreach (char c in s)
        {
            if (char.IsLetterOrDigit(c))
            {
                hasAlnum = true;
                if (char.IsLetter(c)) hasLetter = true;
            }
            else if (c is not ('_' or '-' or '.' or ' ' or '[' or ']' or '(' or ')'
                              or '!' or '?' or '！' or '？' or '，' or '。' or '、'
                              or '~' or '§' or '·'))
            {
                return false;
            }
        }

        if (!hasAlnum || !hasLetter) return false;

        // 排除看起来很长的十六进制串（GUID 残片）
        if (s.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F')
                       or '-' or ':'))
            return false;

        return true;
    }

    /// <summary>在有序数组中找第一个 >= value 的下标。</summary>
    private static int LowerBound(int[] arr, int value)
    {
        int lo = 0, hi = arr.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) >> 1;
            if (arr[mid] < value) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }
}
