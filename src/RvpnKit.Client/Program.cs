using System.Text;
using RvpnKit.Client;
using RvpnKit.Protocol;

Console.OutputEncoding = Encoding.UTF8;

// ── 参数处理必须在任何横幅输出之前完成，
//    否则 --json 的输出会被横幅污染，无法被脚本解析。
if (args.Length > 0)
{
    switch (args[0])
    {
        case "--json":
            return await JsonAsync();
        case "--list":
            return await ListAsync();
        case "--probe-write":
            return await ProbeWriteAsync();
        case "--monitor":
            return await MonitorAsync();
        case "--help" or "-h":
            PrintHelp();
            return 0;
    }
}

Console.WriteLine("RvpnKit — Radmin VPN 第三方客户端");
Console.WriteLine("多源聚合：控制管道 + 网卡邻居表 + 服务日志");
Console.WriteLine(new string('═', 78));

static void PrintHelp()
{
    Console.WriteLine("""
        RvpnKit — Radmin VPN 第三方客户端

        用法:
          rvpnkit              显示完整报告（网卡 / 对端 / 节点 / 管道）
          rvpnkit --list       简洁列表输出（制表符分隔，便于脚本处理）
          rvpnkit --json       输出 JSON，便于其它程序消费
          rvpnkit --monitor    实时监控对端接入/离开与节点活动
          rvpnkit --probe-write  验证控制管道写入是否被服务接收
          rvpnkit --help       显示本帮助

        说明:
          · 本工具只读取本机已授权的数据（自己的账号与自己加入的网络）
          · 需要 Radmin VPN 服务运行中
          · 命令下发功能尚未实现（协议格式未完成逆向，详见 docs/OPEN_ISSUE_commands.md）
        """);
}

/// <summary>
/// 实时监控：持续显示对端上线/下线与节点身份变化。
///
/// <para>这是"查看网络的人"的完整形态 —— 原版界面只给一份静态列表，
/// 这里能看到成员何时接入、何时离开，以及接入方式。</para>
/// </summary>
static async Task<int> MonitorAsync()
{
    var monitor = new NetworkMonitor(TimeSpan.FromSeconds(2));

    string Stamp() => DateTime.Now.ToString("HH:mm:ss");

    // 先解析一次「IP → 别名」，这样事件里能直接显示是谁
    Console.WriteLine("正在解析成员身份…");
    var byNode = ServiceLog.LatestByNode(ServiceLog.Read());
    var known = new HashSet<string>(
        byNode.Values.Select(e => e.Alias).Where(a => !string.IsNullOrWhiteSpace(a)),
        StringComparer.Ordinal);
    var (bindings, _, _) = await CollectBindingsAsync(known, TimeSpan.FromSeconds(6));
    monitor.SetAliases(bindings);
    Console.WriteLine($"已识别 {bindings.Count} 个成员身份。");

    string Who(string ip)
    {
        string? alias = monitor.AliasOf(ip);
        return alias is null ? "（未知）" : alias;
    }

    monitor.PeerAppeared += p =>
        Console.WriteLine($"[{Stamp()}] ＋ 上线  {p.Address,-16} {Who(p.Address.ToString()),-24} " +
                          $"{p.Mac}");

    monitor.PeerDisappeared += p =>
        Console.WriteLine($"[{Stamp()}] － 下线  {p.Address,-16} {Who(p.Address.ToString()),-24} " +
                          $"{p.Mac}");

    monitor.NodeSeen += e =>
        Console.WriteLine($"[{Stamp()}] ● 活动  #{e.NodeId,-11} {e.Alias,-24} " +
                          $"（{e.ViaText}）");

    Console.WriteLine();
    Console.WriteLine("RvpnKit 实时监控");
    Console.WriteLine(new string('─', 74));

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    await monitor.RunAsync(Console.WriteLine, cts.Token);
    return 0;
}

/// <summary>
/// 抓取控制管道状态流并解析 IP ↔ 别名 关联。
///
/// <para>这是 <c>--json</c>、<c>--list</c> 与默认报告共用的采集逻辑，
/// 避免三处各写一遍。</para>
/// </summary>
/// <param name="knownAliases">别名白名单（来自服务日志）</param>
/// <param name="window">读取窗口；快照约 370 KB，2 秒内可读完</param>
static async Task<(List<AliasResolver.Binding> Bindings, int Bytes, int Frames)>
    CollectBindingsAsync(IReadOnlySet<string> knownAliases, TimeSpan window)
{
    var raw = new List<byte>(400_000);
    int frames = 0;

    using var pipe = new RvpnPipe();
    using var cts = new CancellationTokenSource(window);

    try
    {
        pipe.Connect();
    }
    catch (IOException)
    {
        return ([], 0, 0);
    }

    try
    {
        int idle = 0;
        while (true)
        {
            byte[] chunk;
            try
            {
                chunk = await pipe.ReadChunkAsync(TimeSpan.FromMilliseconds(400), cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (chunk.Length > 0) raw.AddRange(chunk);

            if (chunk.Length == 0)
            {
                if (++idle >= 4 && pipe.PendingBytes == 0) break;
            }
            else idle = 0;

            while (true)
            {
                try
                {
                    if (!pipe.TryTakeFrame(out _)) break;
                    frames++;
                }
                catch (InvalidDataException)
                {
                    pipe.ResetBuffer();
                    break;
                }
            }

            if (pipe.ReaderCompleted) break;
        }
    }
    catch (IOException) { /* 读取中断，用已有数据 */ }

    var bindings = raw.Count > 0
        ? AliasResolver.Resolve([.. raw], knownAliases)
        : [];

    return (bindings, raw.Count, frames);
}

/// <summary>输出 JSON，便于脚本与其它程序消费。</summary>
static async Task<int> JsonAsync()
{
    var localIp = PeerTable.LocalVirtualAddress();
    var peers = PeerTable.Read(localIp);
    var byNode = ServiceLog.LatestByNode(ServiceLog.Read());

    var known = new HashSet<string>(
        byNode.Values.Select(e => e.Alias).Where(a => !string.IsNullOrWhiteSpace(a)),
        StringComparer.Ordinal);

    var (bindings, pipeBytes, pipeFrames) =
        await CollectBindingsAsync(known, TimeSpan.FromSeconds(6));
    var aliasByIp = bindings.ToDictionary(b => b.Ip, b => b.Alias, StringComparer.Ordinal);

    var doc = new
    {
        adapter = new
        {
            name = "Radmin VPN",
            up = PeerTable.IsAdapterUp(),
            localVirtualIp = localIp?.ToString(),
        },
        peers = peers
            .Where(p => p.HasValidMac)
            .OrderBy(p => p.Address.ToString(), Comparer<string>.Create(
                (a, b) => string.CompareOrdinal(a.PadLeft(15, '0'), b.PadLeft(15, '0'))))
            .Select(p => new
            {
                ip = p.Address.ToString(),
                mac = p.Mac,
                state = p.StateText,
                // 已能关联到别名时给出身份；否则为 null
                alias = aliasByIp.GetValueOrDefault(p.Address.ToString()),
            })
            .ToArray(),
        nodes = byNode.Values
            .OrderByDescending(e => e.Timestamp)
            .Select(e => new
            {
                nodeId = e.NodeId,
                alias = e.Alias,
                via = e.Via,
                viaText = e.ViaText,
                connected = e.Connected,
                lastSeen = e.Timestamp == DateTime.MinValue
                    ? null
                    : e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            })
            .ToArray(),
        stats = new
        {
            peerCount = peers.Count,
            peerResolved = peers.Count(p => p.HasValidMac),
            knownNodes = byNode.Count,
            identifiedPeers = bindings.Count,
            pipeBytes,
            pipeFrames,
        },
    };

    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(doc,
        new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }));
    return 0;
}

/// <summary>简洁列表输出。</summary>
static async Task<int> ListAsync()
{
    var localIp = PeerTable.LocalVirtualAddress();
    var peers = PeerTable.Read(localIp);
    var byNode = ServiceLog.LatestByNode(ServiceLog.Read());

    var known = new HashSet<string>(
        byNode.Values.Select(e => e.Alias).Where(a => !string.IsNullOrWhiteSpace(a)),
        StringComparer.Ordinal);

    var (bindings, _, _) = await CollectBindingsAsync(known, TimeSpan.FromSeconds(6));
    var aliasByIp = bindings.ToDictionary(b => b.Ip, b => b.Alias, StringComparer.Ordinal);

    Console.WriteLine($"# 本机虚拟 IP: {localIp?.ToString() ?? "(无)"}");
    Console.WriteLine($"# 对端 {peers.Count(p => p.HasValidMac)} 个，" +
                      $"已知节点 {byNode.Count} 个，" +
                      $"已识别身份 {bindings.Count} 个");
    Console.WriteLine();
    Console.WriteLine("# 对端（虚拟 IP / 别名 / MAC / 状态）");
    foreach (var p in peers.Where(p => p.HasValidMac)
                           .OrderBy(p => p.Address.ToString(), Comparer<string>.Create(
                               (a, b) => string.CompareOrdinal(a.PadLeft(15, '0'), b.PadLeft(15, '0')))))
    {
        string alias = aliasByIp.GetValueOrDefault(p.Address.ToString()) ?? "-";
        Console.WriteLine($"{p.Address}\t{alias}\t{p.Mac}\t{p.StateText}");
    }

    Console.WriteLine();
    Console.WriteLine("# 已知节点（节点ID / 别名 / 连接方式 / 最近活动）");
    foreach (var e in byNode.Values.OrderByDescending(x => x.Timestamp).Take(200))
        Console.WriteLine($"{e.NodeId}\t{e.Alias}\t{e.ViaText}\t" +
                          $"{(e.Timestamp == DateTime.MinValue ? "—" : e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))}");

    return 0;
}

/// <summary>
/// 验证「向控制管道写入」是否真的被服务处理。
///
/// <para>做法：记录服务日志当前的尾部，发送一个<b>最小畸形帧</b>，随后观察日志是否
/// 出现新的 <c>[req:N] ...</c> 记录。服务对每个请求都会编号并记录成功/失败，
/// 因此只要出现新记录，就证明写入路径已经打通。</para>
///
/// <para>发送畸形帧是刻意的：它最不可能被误解释为有效命令，从而把对真实网络状态的
/// 影响降到最低。</para>
/// </summary>
static async Task<int> ProbeWriteAsync()
{
    var logDir = ServiceLog.DefaultDirectory;
    Console.WriteLine("═══ 管道写入探测 ═══");
    Console.WriteLine($"日志目录: {logDir}");
    Console.WriteLine();

    // 1. 记录探测前的日志状态
    var before = SnapshotLogs(logDir);
    Console.WriteLine($"探测前：{before.Count} 个日志文件");

    using var pipe = new RvpnPipe();
    try
    {
        pipe.Connect();
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"✗ 连接失败: {ex.Message}");
        return 1;
    }

    Console.WriteLine($"✓ 已连接（可写: {pipe.CanWrite}）");

    // 2. 发送最小畸形帧：长度为 1，正文只有一个 0x00
    //    服务解析必然失败，只会在日志里留一条失败记录
    byte[] probe = [0x00];
    try
    {
        int sent = await pipe.SendAsync(probe, CancellationToken.None);
        Console.WriteLine($"✓ 已写入 {sent} 字节（长度前缀 + 1 字节正文）");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"✗ 写入失败: {ex.GetType().Name}: {ex.Message}");
        return 2;
    }

    // 3. 观察日志变化（最多 8 秒）
    Console.WriteLine("观察服务日志变化…");
    var deadline = DateTime.UtcNow.AddSeconds(8);
    bool sawNew = false;
    while (DateTime.UtcNow < deadline)
    {
        await Task.Delay(500);
        var now = SnapshotLogs(logDir);

        foreach (var (file, size) in now)
        {
            if (before.TryGetValue(file, out long oldSize) && size > oldSize)
            {
                var added = ReadTail(file, oldSize, size);
                if (added.Any(l => l.Contains("[req:", StringComparison.Ordinal)))
                {
                    Console.WriteLine();
                    Console.WriteLine("★ 服务日志出现新请求记录：");
                    foreach (var line in added.Where(l => l.Contains("[req:", StringComparison.Ordinal)).Take(5))
                        Console.WriteLine("   " + line.Trim());
                    sawNew = true;
                }
            }
            else if (!before.ContainsKey(file))
            {
                Console.WriteLine($"  （出现新日志文件: {Path.GetFileName(file)}）");
            }
        }

        if (sawNew) break;
        if (pipe.ReaderCompleted)
        {
            Console.WriteLine($"  （服务已关闭读端，Win32 错误 {pipe.ReadError}）");
            break;
        }
    }

    Console.WriteLine();
    if (sawNew)
    {
        Console.WriteLine("═══ 结论 ═══");
        Console.WriteLine("✓ 写入路径已打通：服务接收并处理了我们发送的数据。");
        Console.WriteLine("  下一步只需构造格式正确的命令报文即可实现「加入网络」等写操作。");
        return 0;
    }

    Console.WriteLine("═══ 结论 ═══");
    Console.WriteLine("未观察到服务记录新请求。可能原因：");
    Console.WriteLine("  · 服务直接丢弃了无法解析的帧（未记日志）");
    Console.WriteLine("  · 日志写入有缓冲延迟，8 秒窗口不够");
    Console.WriteLine("  · 帧格式要求比预期更严格（例如需要完整的头部）");
    return 3;
}

/// <summary>记录日志目录下各文件的大小。</summary>
static Dictionary<string, long> SnapshotLogs(string dir)
{
    var map = new Dictionary<string, long>();
    if (!Directory.Exists(dir)) return map;
    foreach (var f in Directory.GetFiles(dir, "service*.log"))
    {
        try { map[f] = new FileInfo(f).Length; } catch (IOException) { }
    }
    return map;
}

/// <summary>读取一个日志文件在 [from, to) 区间内新增的文本行。</summary>
static List<string> ReadTail(string path, long from, long to)
{
    var lines = new List<string>();
    try
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        fs.Seek(from, SeekOrigin.Begin);
        using var reader = new StreamReader(fs, Encoding.UTF8);
        while (reader.ReadLine() is { } line && fs.Position <= to)
            lines.Add(line);
    }
    catch (IOException) { }
    return lines;
}

// ── ① 网络状态 ───────────────────────────────────────────────
var localIp = PeerTable.LocalVirtualAddress();
bool adapterUp = PeerTable.IsAdapterUp();

Console.WriteLine();
Console.WriteLine("【网络状态】");
Console.WriteLine($"  虚拟网卡   : Radmin VPN —— {(adapterUp ? "已启用 (Up)" : "已禁用/未连接")}");
Console.WriteLine($"  本机虚拟 IP: {localIp?.ToString() ?? "（未分配）"}");

if (localIp is null)
{
    Console.WriteLine("  ⚠ 未取得虚拟 IP，网络可能已关闭。");
}

// ── ② 邻居表：实时对端 ───────────────────────────────────────
var peers = PeerTable.Read(localIp);
var resolved = peers.Where(p => p.HasValidMac).ToList();

Console.WriteLine();
Console.WriteLine("【邻居缓存中的对端】（来自网卡驱动，数据面事实来源）");
Console.WriteLine($"  条目总数 {peers.Count}，其中已解析出 MAC 的 {resolved.Count}");

// ── ③ 服务日志：节点身份 ─────────────────────────────────────
var logEntries = ServiceLog.Read();
var byNode = ServiceLog.LatestByNode(logEntries);
Console.WriteLine();
Console.WriteLine("【服务日志】");
Console.WriteLine($"  解析出连接记录 {logEntries.Count:N0} 条，涉及节点 {byNode.Count:N0} 个");

// ── ④ 控制管道：读取状态流并解析 IP ↔ 别名 ───────────────────
var pipeIps = new List<string>();
var nodeIds = new List<ulong>();
var pipeRaw = new List<byte>(400_000);
int pipeBytes = 0, pipeFrames = 0;
List<AliasResolver.Binding> bindings = [];

// 已知别名白名单：用于剔除由二进制块误解码产生的假别名
var knownAliases = new HashSet<string>(
    byNode.Values.Select(e => e.Alias).Where(a => !string.IsNullOrWhiteSpace(a)),
    StringComparer.Ordinal);

Console.WriteLine();
Console.WriteLine("【控制管道】");
try
{
    using var pipe = new RvpnPipe();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

    try
    {
        pipe.Connect();
        Console.WriteLine($"  ✓ 已连接 {RvpnPipe.PipeName}" +
                          (pipe.IsReadOnly ? "（只读）" : "（可写）"));

        int idle = 0;
        while (true)
        {
            byte[] chunk;
            try
            {
                chunk = await pipe.ReadChunkAsync(TimeSpan.FromMilliseconds(500), cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;   // 窗口到期：用已收集的数据继续
            }

            pipeBytes += chunk.Length;
            if (chunk.Length > 0) pipeRaw.AddRange(chunk);

            if (chunk.Length == 0)
            {
                if (++idle >= 4 && pipe.PendingBytes == 0) break;
            }
            else idle = 0;

            while (true)
            {
                byte[] frame;
                try
                {
                    if (!pipe.TryTakeFrame(out frame)) break;
                }
                catch (InvalidDataException)
                {
                    pipe.ResetBuffer();
                    break;
                }

                pipeFrames++;
                var res = RvpnWire.Parse(frame);

                foreach (var r in res.Records)
                {
                    if (r.RawType == RvpnWire.Type.U64 && r.Num is ulong n && n > 1000)
                        nodeIds.Add(n);
                    if (r.Bytes is { Length: 16 } b &&
                        RvpnWire.TryBlobToIPv4(b) is string ip &&
                        ip.StartsWith("26.", StringComparison.Ordinal))
                        pipeIps.Add(ip);
                }
            }

            if (pipe.ReaderCompleted) break;
        }
    }
    catch (IOException ex)
    {
        Console.WriteLine($"  ✗ 连接失败：{ex.Message}");
    }

    Console.WriteLine($"  读到 {pipeBytes:N0} 字节 / {pipeFrames} 帧");
    Console.WriteLine($"  提取虚拟 IP {pipeIps.Distinct().Count()} 个，" +
                      $"节点 ID {nodeIds.Distinct().Count()} 个");

    // ── 关键：把虚拟 IP 与节点别名关联起来（即使读取窗口到期也照常执行）
    if (pipeRaw.Count > 0)
    {
        bindings = AliasResolver.Resolve([.. pipeRaw], knownAliases);
        Console.WriteLine($"  ✓ 建立 IP ↔ 别名 关联 {bindings.Count} 条" +
                          $"（白名单 {knownAliases.Count:N0} 个别名）");
    }
    else
    {
        Console.WriteLine("  （本窗口未读到数据，跳过身份关联）");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  ✗ 管道处理异常：{ex.GetType().Name}: {ex.Message}");
}

// ── ⑤ 汇总：成员列表（IP + 别名 + MAC）──────────────────────
var aliasByIp = bindings.ToDictionary(b => b.Ip, b => b.Alias, StringComparer.Ordinal);

Console.WriteLine();
Console.WriteLine(new string('═', 78));
Console.WriteLine("【成员列表】");
Console.WriteLine();

if (resolved.Count == 0)
{
    Console.WriteLine("  当前没有已解析出的对端。");
    Console.WriteLine("  （Radmin 按需建连：无通信时邻居条目可能全零/过期）");
}
else
{
    // 有别名关联的对端优先展示，并给出连接方式
    var withAlias = resolved
        .Where(p => aliasByIp.ContainsKey(p.Address.ToString()))
        .OrderBy(p => p.Address.ToString(), Comparer<string>.Create(
            (a, b) => string.CompareOrdinal(a.PadLeft(15, '0'), b.PadLeft(15, '0'))))
        .ToList();

    Console.WriteLine($"  {"虚拟 IP",-16} {"别名",-26} {"MAC 地址",-19} 状态");
    Console.WriteLine($"  {new string('─', 15)} {new string('─', 25)} {new string('─', 18)} {new string('─', 12)}");

    foreach (var p in withAlias)
    {
        string alias = aliasByIp[p.Address.ToString()];
        Console.WriteLine($"  {p.Address,-16} {alias,-26} {p.Mac,-19} {p.StateText}");
    }

    var noAlias = resolved.Count - withAlias.Count;
    if (noAlias > 0)
    {
        Console.WriteLine();
        Console.WriteLine($"  另有 {noAlias} 个对端只有 IP/MAC、未关联到别名" +
                          $"（多为历史缓存条目，当前无活跃会话）");
    }

    Console.WriteLine();
    Console.WriteLine($"  合计 {resolved.Count} 个对端，其中 {withAlias.Count} 个已识别身份");
}

// ── ⑥ 已知节点的身份信息（来自日志）──────────────────────────
Console.WriteLine();
Console.WriteLine("【已知节点身份】（来自服务日志，按最近活动排序）");
Console.WriteLine();
var top = byNode.Values
    .OrderByDescending(e => e.Timestamp)
    .Take(20)
    .ToList();

Console.WriteLine($"  {"节点 ID",-12} {"最近活动",-22} {"连接方式",-26} 别名");
Console.WriteLine($"  {new string('─', 11)} {new string('─', 21)} {new string('─', 25)} {new string('─', 24)}");

foreach (var e in top)
{
    string when = e.Timestamp == DateTime.MinValue ? "—" : e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    Console.WriteLine($"  {e.NodeId,-12} {when,-22} {e.ViaText,-26} {e.Alias}");
}

Console.WriteLine();
Console.WriteLine($"  合计 {byNode.Count:N0} 个已知节点，此处显示最近活跃的 {top.Count} 个");

// ── ⑦ 数据源说明 ─────────────────────────────────────────────
Console.WriteLine();
Console.WriteLine(new string('═', 78));
Console.WriteLine("【数据源与限制】");
Console.WriteLine("  ✓ 网卡邻居表 : 实时对端 IP + MAC + 可达状态");
Console.WriteLine("  ✓ 服务日志   : 节点 ID + 别名 + 连接方式（含精确时间）");
Console.WriteLine("  ✓ 控制管道   : 状态快照 + 增量事件；用于把 IP 与别名关联");
Console.WriteLine();
Console.WriteLine("  IP ↔ 别名 关联方法：");
Console.WriteLine("    管道快照里每个节点的虚拟 IP 以 4 字节原始形式出现，");
Console.WriteLine("    别名以 UTF-16LE 出现（起始偏移可能是奇数）。");
Console.WriteLine("    以服务日志的已知别名作为白名单做精确匹配，再按邻近性配对，");
Console.WriteLine("    可剔除二进制块误解码产生的假别名。");
Console.WriteLine();
Console.WriteLine("  ⚠ 命令下发（加入网络 / 启用禁用 / 踢人）尚未实现：");
Console.WriteLine("     服务对非法报文静默丢弃且不记日志，命令格式仍需完成逆向。");
Console.WriteLine("     详见 docs/OPEN_ISSUE_commands.md");

return 0;
