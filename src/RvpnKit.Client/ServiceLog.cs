using System.Text;
using System.Text.RegularExpressions;
using RvpnKit.Protocol;

namespace RvpnKit.Client;

/// <summary>
/// 从 Radmin 控制服务的日志里提取节点身份与连接方式。
///
/// <para>服务会把每个对端的连接过程写进
/// <c>C:\ProgramData\Famatech\Radmin VPN\service*.log</c>，格式为：</para>
/// <code>
///   2026.10.18 12:06:03.552  INFO  Connected to 171124252/'CHINAMI-CK8R6D3' via TCP/outgoing
///   2026.10.18 12:06:04.202  WARNING  Failed to connect to 91583269/'DESKTOP-HNJLNLL' (error: 0x7000003ed)
///   2026.10.18 12:06:07.842  INFO  Connected to 106307912/'服务器…' via UDP/outgoing
/// </code>
/// <para>日志是<b>只读</b>来源，且包含日期，因此可以判定节点是否近期活跃。</para>
/// </summary>
public static class ServiceLog
{
    /// <summary>默认日志目录。</summary>
    public const string DefaultDirectory = @"C:\ProgramData\Famatech\Radmin VPN";

    /// <summary>一条节点连接记录。</summary>
    public sealed class Entry
    {
        /// <summary>日志时间</summary>
        public DateTime Timestamp { get; init; }

        /// <summary>节点 ID</summary>
        public ulong NodeId { get; init; }

        /// <summary>节点别名 / 主机名</summary>
        public string Alias { get; init; } = "";

        /// <summary>连接方式（TCP / UDP / TcpRelay / …）</summary>
        public string Via { get; init; } = "";

        /// <summary>是否连接成功</summary>
        public bool Connected { get; init; }

        /// <summary>失败原因（成功时为空）</summary>
        public string Error { get; init; } = "";

        /// <summary>连接方式的通俗说明。</summary>
        public string ViaText
        {
            get
            {
                // 失败的记录没有 Via 字段，直接说明比显示「—」更有信息量
                if (!Connected) return "未连接（离线）";

                return Via switch
                {
                    var v when v.StartsWith("UDP", StringComparison.OrdinalIgnoreCase)
                        => "UDP 直连（打洞成功，最快）",
                    var v when v.StartsWith("TcpRelay", StringComparison.OrdinalIgnoreCase)
                        => "中继转发（较慢）",
                    var v when v.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)
                        => "TCP 直连",
                    "" => "已连接（方式未记录）",
                    _ => Via,
                };
            }
        }

        /// <inheritdoc/>
        public override string ToString() =>
            $"{Alias} (#{NodeId}) {ViaText}";
    }

    // 2026.10.18 12:06:03.552	INFO	Connected to 171124252/'CHIRAMI' via TCP/outgoing
    private static readonly Regex ConnectedRe = new(
        @"^(?<ts>\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\w+\s+" +
        @"Connected to (?<id>\d+)/'(?<alias>.*?)' via (?<via>\S+)",
        RegexOptions.Compiled);

    private static readonly Regex FailedRe = new(
        @"^(?<ts>\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\w+\s+" +
        @"Failed to connect to (?<id>\d+)/'(?<alias>.*?)'",
        RegexOptions.Compiled);

    /// <summary>
    /// 读取日志目录下所有 <c>service*.log</c>，解析出节点连接记录。
    /// 只读操作，不会修改或删除任何日志。
    /// </summary>
    /// <param name="directory">日志目录，默认 <see cref="DefaultDirectory"/></param>
    /// <param name="maxFiles">最多读取最新的多少个日志文件</param>
    /// <remarks>
    /// <b>编码说明：</b>服务写出的日志是 <b>UTF-16LE（带 BOM）</b>，
    /// 早期按 UTF-8 读取会丢掉一半字节。这里通过 BOM 自动判定编码，
    /// 同时兼容可能的 UTF-8 变体。
    /// </remarks>
    public static List<Entry> Read(string directory = DefaultDirectory, int maxFiles = 8)
    {
        var entries = new List<Entry>();
        if (!Directory.Exists(directory)) return entries;

        var files = new DirectoryInfo(directory).GetFiles("service*.log")
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(maxFiles);

        foreach (var file in files)
        {
            try
            {
                // 日志可能正被服务写入，用共享读方式打开
                using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                                              FileShare.ReadWrite);
                using var reader = new StreamReader(fs, DetectEncoding(fs), detectEncodingFromByteOrderMarks: true);

                while (reader.ReadLine() is { } line)
                {
                    if (ConnectedRe.Match(line) is { Success: true } m)
                    {
                        entries.Add(new Entry
                        {
                            Timestamp = ParseTimestamp(m.Groups["ts"].Value),
                            NodeId = ulong.Parse(m.Groups["id"].Value),
                            Alias = m.Groups["alias"].Value,
                            Via = m.Groups["via"].Value,
                            Connected = true,
                        });
                    }
                    else if (FailedRe.Match(line) is { Success: true } f)
                    {
                        entries.Add(new Entry
                        {
                            Timestamp = ParseTimestamp(f.Groups["ts"].Value),
                            NodeId = ulong.Parse(f.Groups["id"].Value),
                            Alias = f.Groups["alias"].Value,
                            Connected = false,
                        });
                    }
                }
            }
            catch (IOException)
            {
                // 文件被独占时跳过，不影响其它日志
            }
        }

        return entries;
    }

    /// <summary>按 BOM 判定日志编码；无语义前缀时退回 UTF-16LE（服务实际写法）。</summary>
    private static Encoding DetectEncoding(FileStream fs)
    {
        Span<byte> head = stackalloc byte[4];
        long pos = fs.Position;
        int n = fs.Read(head);
        fs.Position = pos;

        if (n >= 2)
        {
            if (head[0] == 0xFF && head[1] == 0xFE) return Encoding.Unicode;        // UTF-16LE
            if (head[0] == 0xFE && head[1] == 0xFF) return Encoding.BigEndianUnicode;
        }
        if (n >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF)
            return Encoding.UTF8;

        // 无 BOM：若第 2 字节为 0 说明是 UTF-16LE 文本
        return n >= 2 && head[1] == 0x00 ? Encoding.Unicode : Encoding.UTF8;
    }

    /// <summary>把记录按节点 ID 归并，保留每个节点最近一次成功的连接。</summary>
    public static Dictionary<ulong, Entry> LatestByNode(IEnumerable<Entry> entries)
    {
        var best = new Dictionary<ulong, Entry>();
        foreach (var e in entries)
        {
            if (!best.TryGetValue(e.NodeId, out var cur)) { best[e.NodeId] = e; continue; }
            // 优先保留成功记录；都成功则取更新的
            if (e.Connected && !cur.Connected) best[e.NodeId] = e;
            else if (e.Connected == cur.Connected && e.Timestamp > cur.Timestamp) best[e.NodeId] = e;
        }
        return best;
    }

    /// <summary>别名 → 记录 的索引（便于用别名关联其它数据源）。</summary>
    public static Dictionary<string, Entry> ByAlias(IEnumerable<Entry> entries)
    {
        var map = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            if (string.IsNullOrEmpty(e.Alias)) continue;
            if (!map.TryGetValue(e.Alias, out var cur) || e.Timestamp > cur.Timestamp)
                map[e.Alias] = e;
        }
        return map;
    }

    private static DateTime ParseTimestamp(string s)
        => DateTime.TryParseExact(s, "yyyy.MM.dd HH:mm:ss.fff", null,
                                  System.Globalization.DateTimeStyles.None, out var dt)
            ? dt
            : DateTime.MinValue;
}
