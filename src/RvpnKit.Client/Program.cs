using System.Text;
using RvpnKit.Client;
using RvpnKit.Protocol;
using static RvpnKit.Client.Ui;

Console.OutputEncoding = Encoding.UTF8;

// ── 参数处理必须在任何横幅输出之前完成，
//    否则 --json 的输出会被横幅污染，无法被脚本解析。
bool showAll = false;
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
        case "--join" when args.Length > 1:
            return await JoinNetworkAsync(args[1],
                args.Length > 2 && args[2] is "--dump");
        case "--join":
            Console.Error.WriteLine("用法: rvpnkit --join \"网络名\"");
            return 2;
        case "--monitor":
            return await MonitorAsync();
        case "--no-color":
            Ui.DisableColor();
            break;                       // 继续走默认报告
        case "--all":
            showAll = true;              // 成员列表不截断
            break;
        case "--help" or "-h":
            PrintHelp();
            return 0;
    }
}

Ui.Banner("Radmin VPN 第三方客户端 · 多源聚合监控");

static void PrintHelp()
{
    Ui.Banner("命令行帮助");
    Console.WriteLine("  用法");
    Console.WriteLine();
    var t = new Ui.Table(["命令", "作用"]);
    t.Add("rvpnkit", "完整报告：网卡 / 对端 / 成员身份 / 活跃节点");
    t.Add("rvpnkit --all", "同上，但成员列表不截断（默认只显示前 30）");
    t.Add("rvpnkit --json", "JSON 输出，便于其它程序消费（无装饰）");
    t.Add("rvpnkit --list", "制表符分隔列表（无装饰，便于脚本处理）");
    t.Add("rvpnkit --monitor", "实时监控：成员上线 / 下线 / 节点活动");
    t.Add("rvpnkit --probe-write", "验证控制管道写入是否被服务接收");
    t.Add("rvpnkit --join \"网络名\"", "加入指定网络（命令格式已逆向并验证）");
    t.Add("rvpnkit --join \"网络名\" --dump", "同上，并打印构造出的命令帧十六进制");
    t.Add("rvpnkit --no-color", "关闭配色（也尊重 NO_COLOR 环境变量）");
    t.Add("rvpnkit --help", "显示本帮助");
    t.Render();

    Console.WriteLine();
    Console.WriteLine("  " + Paint("说明", Sgr.Bold));
    Console.WriteLine("    " + Paint("· 只读取本机已授权的数据（自己的账号与自己加入的网络）", Sgr.Grey));
    Console.WriteLine("    " + Paint("· 需要 Radmin VPN 服务运行中", Sgr.Grey));
    Console.WriteLine("    " + Paint("· 命令下发功能尚未实现，原因见 docs/OPEN_ISSUE_commands.md", Sgr.Grey));
    Console.WriteLine();
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

    string Stamp() => Paint(DateTime.Now.ToString("HH:mm:ss"), Sgr.Grey);

    Ui.Banner("实时监控 · 成员上下线与节点活动");

    // 先解析一次「IP → 别名」，这样事件里能直接显示是谁
    Console.WriteLine("  " + Paint("正在解析成员身份…", Sgr.Dim));
    var byNode = ServiceLog.LatestByNode(ServiceLog.Read());
    var known = new HashSet<string>(
        byNode.Values.Select(e => e.Alias).Where(a => !string.IsNullOrWhiteSpace(a)),
        StringComparer.Ordinal);
    var (bindings, _, _) = await CollectBindingsAsync(known, TimeSpan.FromSeconds(6));
    monitor.SetAliases(bindings);
    Console.WriteLine("  " + Paint("✓", Sgr.Green) + " 已识别 " +
                      Paint($"{bindings.Count}", Sgr.Bold + Sgr.Magenta) +
                      " 个成员身份");

    string Who(string ip)
    {
        string? alias = monitor.AliasOf(ip);
        return alias is null ? Paint("（未知）", Sgr.Grey) : Paint(alias, Sgr.Magenta);
    }

    // 事件行统一宽度，让时间戳与箭头对齐
    const int ipWidth = 17;
    const int whoWidth = 26;

    monitor.PeerAppeared += p =>
    {
        string ip = p.Address.ToString();
        Console.WriteLine($"  [{Stamp()}] {Paint("＋", Sgr.Green)} " +
                          $"{Paint(PadRight(ip, ipWidth), Sgr.Cyan)} " +
                          $"{PadRight(Who(ip), whoWidth)} " +
                          $"{Paint(p.Mac, Sgr.Grey)}");
    };

    monitor.PeerDisappeared += p =>
    {
        string ip = p.Address.ToString();
        Console.WriteLine($"  [{Stamp()}] {Paint("－", Sgr.Red)} " +
                          $"{Paint(PadRight(ip, ipWidth), Sgr.Cyan)} " +
                          $"{PadRight(Who(ip), whoWidth)} " +
                          $"{Paint(p.Mac, Sgr.Grey)}");
    };

    monitor.NodeSeen += e =>
    {
        string mark = e.ViaText.Contains("UDP") ? Paint("◆", Sgr.Green)
                    : e.ViaText.Contains("中继") ? Paint("◆", Sgr.Yellow)
                    : Paint("◆", Sgr.Cyan);
        Console.WriteLine($"  [{Stamp()}] {mark} " +
                          $"{Paint(PadLeft("#" + e.NodeId, ipWidth), Sgr.Grey)} " +
                          $"{Paint(PadRight(e.Alias, whoWidth), Sgr.Magenta)} " +
                          $"{Paint(e.ViaText, Sgr.Dim)}");
    };

    Console.WriteLine();
    Console.WriteLine("  " + Paint("图例", Sgr.Bold) + "  " +
                      Paint("＋ 上线", Sgr.Green) + "   " +
                      Paint("－ 下线", Sgr.Red) + "   " +
                      Paint("◆ 节点活动", Sgr.Cyan));
    Console.WriteLine("  " + Paint("Ctrl+C 退出", Sgr.Grey));
    Console.WriteLine();

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    await monitor.RunAsync(line => Console.WriteLine("  " + Paint(line, Sgr.Dim)), cts.Token);
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
/// 加入一个 Radmin VPN 网络。
///
/// <para>命令帧由 <see cref="CommandBuilder.JoinNetwork"/> 按真实报文逆向出的格式
/// 构造：整体是「请求 ID 记录 + 命令码记录 + 容器记录」，容器里带一个 u8 字段和
/// 一个 UTF-16LE 的网络名。服务端会为每个请求编号，成功的加入会写
/// <c>[req:N] Requested to join network '...'</c> 与
/// <c>You joined gaming network '...'</c> 两条日志，因此可以直接用它验证结果。</para>
/// </summary>
/// <param name="name">要加入的网络名（需与服务器上的完全一致）。</param>
/// <param name="dump">是否把构造出的命令帧按十六进制打印出来。</param>
static async Task<int> JoinNetworkAsync(string name, bool dump)
{
    Ui.Banner("加入网络");

    // 请求编号取当前时间的毫秒低 16 位：服务端只把它当标识回显，
    // 不需要全局唯一，但要避免与官方 GUI 的递增值撞车得太频繁。
    uint reqId = (uint)(DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond) & 0xFFFF;
    byte[] frame = CommandBuilder.JoinNetwork(name, reqId);

    Console.WriteLine();
    Console.WriteLine($"  网络名    {name}");
    Console.WriteLine($"  请求编号  {reqId} (0x{reqId:x})");
    Console.WriteLine($"  帧长度    {frame.Length} 字节（正文，不含 4 字节长度前缀）");
    Console.WriteLine($"  编码后名  {System.Text.Encoding.Unicode.GetByteCount(name)} 字节 UTF-16LE");
    Console.WriteLine();

    if (dump)
    {
        Console.WriteLine("  帧内容：");
        Console.Write(CommandBuilder.ToHexDump(frame));
        Console.WriteLine();
    }

    var logDir = ServiceLog.DefaultDirectory;
    var before = SnapshotLogs(logDir);

    using var pipe = new RvpnPipe();
    try
    {
        pipe.Connect();
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"✗ 连接控制管道失败: {ex.Message}");
        return 1;
    }

    if (!pipe.CanWrite)
    {
        Console.Error.WriteLine("✗ 当前连接是只读的，无法下发命令。");
        Console.Error.WriteLine("  请先关闭官方 Radmin VPN 界面再重试（管道实例被它占用）。");
        return 2;
    }

    try
    {
        int sent = await pipe.SendAsync(frame, CancellationToken.None);
        Console.WriteLine($"  ✓ 已写入 {sent} 字节");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"✗ 写入失败: {ex.GetType().Name}: {ex.Message}");
        return 3;
    }

    Console.WriteLine();
    Console.WriteLine("  等待服务处理…");

    // 观察服务日志，确认请求被接受
    var deadline = DateTime.UtcNow.AddSeconds(10);
    string? joined = null;
    while (DateTime.UtcNow < deadline)
    {
        await Task.Delay(400);
        foreach (var (file, size) in SnapshotLogs(logDir))
        {
            if (!before.TryGetValue(file, out long oldSize) || size <= oldSize) continue;
            foreach (string line in ReadTail(file, oldSize, size))
            {
                if (line.Contains($"[req:{reqId}]", StringComparison.Ordinal) &&
                    line.Contains("Succeeded", StringComparison.Ordinal))
                    joined = line;
                if (line.Contains("You joined", StringComparison.Ordinal))
                    joined = line;
            }
        }
        if (joined is not null) break;
    }

    Console.WriteLine();
    if (joined is not null)
    {
        Console.WriteLine($"  ✓ 加入成功：{joined.Trim()}");
        return 0;
    }

    Console.WriteLine("  ⚠ 未在服务日志中看到确认。");
    Console.WriteLine("    可能原因：网络名不匹配、网络需要密码、或服务端已满。");
    Console.WriteLine($"    可直接查看: {logDir}");
    return 4;
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

Ui.Section("网络状态");
Ui.KeyValue("虚拟网卡", "Radmin VPN", Sgr.Cyan);
Ui.KeyValue("链路状态",
    adapterUp ? "● 已启用 (Up)" : "○ 已禁用 / 未连接",
    adapterUp ? Sgr.Green : Sgr.Red);
Ui.KeyValue("本机虚拟 IP",
    localIp?.ToString() ?? "（未分配）",
    localIp is null ? Sgr.Red : Sgr.Bold + Sgr.Cyan);

if (localIp is null)
{
    Console.WriteLine();
    Console.WriteLine("    " + Paint("⚠", Sgr.Yellow) +
                      " 未取得虚拟 IP —— Radmin VPN 网络可能处于关闭状态。");
}

// ── ② 邻居表：实时对端 ───────────────────────────────────────
var peers = PeerTable.Read(localIp);
var resolved = peers.Where(p => p.HasValidMac).ToList();

Ui.Section("邻居缓存中的对端",
           "来自网卡驱动，数据面的事实来源；Radmin 按需建连，无通信的条目会过期");
Ui.KeyValue("缓存条目", $"{peers.Count}", Sgr.Bold);
Ui.KeyValue("已解析 MAC", $"{resolved.Count}", Sgr.Green);
Console.WriteLine($"    {Paint("覆盖比例", Sgr.Grey)}  " +
                  $"{Ui.Bar(resolved.Count, Math.Max(peers.Count, 1))}  " +
                  Paint($"{(peers.Count > 0 ? 100.0 * resolved.Count / peers.Count : 0):F0}%", Sgr.Dim));

// ── ③ 服务日志：节点身份 ─────────────────────────────────────
var logEntries = ServiceLog.Read();
var byNode = ServiceLog.LatestByNode(logEntries);

Ui.Section("服务日志", "解析节点身份、连接方式与活动时间");
Ui.KeyValue("连接记录", $"{logEntries.Count:N0}", Sgr.Bold);
Ui.KeyValue("涉及节点", $"{byNode.Count:N0}", Sgr.Bold);

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

Ui.Section("控制管道", "读取状态快照，并把虚拟 IP 与成员身份关联起来");
try
{
    using var pipe = new RvpnPipe();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

    try
    {
        pipe.Connect();
        Console.WriteLine("    " + Paint("✓", Sgr.Green) + " 已连接 " +
                          Paint(RvpnPipe.PipeName, Sgr.Cyan) +
                          (pipe.IsReadOnly
                              ? "  " + Paint("（只读）", Sgr.Grey)
                              : "  " + Paint("（可写）", Sgr.Green)));

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
        Console.WriteLine("    " + Paint("✗", Sgr.Red) + " 连接失败：" + ex.Message);
    }

    Ui.KeyValue("读取字节", $"{pipeBytes:N0}  ({Ui.Bytes(pipeBytes)})", Sgr.Bold);
    Ui.KeyValue("切出帧数", $"{pipeFrames:N0}", Sgr.Bold);
    Ui.KeyValue("节点 ID", $"{nodeIds.Distinct().Count():N0} 个", Sgr.Bold);

    // ── 关键：把虚拟 IP 与节点别名关联起来（即使读取窗口到期也照常执行）
    if (pipeRaw.Count > 0)
    {
        bindings = AliasResolver.Resolve([.. pipeRaw], knownAliases);
        Console.WriteLine();
        Console.WriteLine("    " + Paint("✓", Sgr.Green) + " 身份关联完成： " +
                          Paint($"{bindings.Count} 条", Sgr.Bold + Sgr.Magenta) +
                          Paint($"  （白名单 {knownAliases.Count:N0} 个别名）", Sgr.Grey));
    }
    else
    {
        Console.WriteLine("    " + Paint("（本窗口未读到数据，跳过身份关联）", Sgr.Grey));
    }
}
catch (Exception ex)
{
    Console.WriteLine("    " + Paint("✗", Sgr.Red) +
                      $" 管道处理异常：{ex.GetType().Name}: {ex.Message}");
}

// ── ⑤ 汇总：成员列表（IP + 别名 + MAC）──────────────────────
var aliasByIp = bindings.ToDictionary(b => b.Ip, b => b.Alias, StringComparer.Ordinal);

if (resolved.Count == 0)
{
    Ui.Section("成员列表");
    Console.WriteLine("    " + Paint("当前没有已解析出的对端。", Sgr.Yellow));
    Console.WriteLine("    " + Paint("Radmin 按需建连：无通信时邻居条目可能全零或过期。", Sgr.Grey));
}
else
{
    // 有别名关联的对端优先展示
    var withAlias = resolved
        .Where(p => aliasByIp.ContainsKey(p.Address.ToString()))
        .OrderBy(p => p.Address.ToString(), Comparer<string>.Create(
            (a, b) => string.CompareOrdinal(a.PadLeft(15, '0'), b.PadLeft(15, '0'))))
        .ToList();

    // 默认只列前 30 行，避免几百行刷屏；--all 显示全部
    const int pageSize = 30;
    var shown = showAll ? withAlias : withAlias.Take(pageSize).ToList();

    Ui.Section("成员列表",
               $"已识别身份 {withAlias.Count} 个 / 对端共 {resolved.Count} 个" +
               (showAll || withAlias.Count <= pageSize
                    ? ""
                    : $"  ·  下面只显示前 {pageSize} 个，用 --all 看全部"));

    var table = new Ui.Table(
        ["虚拟 IP", "别名", "MAC 地址", "状态"],
        [
            s => Paint(s, Sgr.Cyan),
            s => Paint(s, Sgr.Magenta),
            s => Paint(s, Sgr.Grey),
            s => s.Contains("曾有") ? Paint(s, Sgr.Yellow) : Paint(s, Sgr.Green),
        ]);

    foreach (var p in shown)
    {
        string ip = p.Address.ToString();
        table.Add(ip, aliasByIp[ip], p.Mac, p.StateText);
    }

    table.Render();

    if (!showAll && withAlias.Count > pageSize)
    {
        Console.WriteLine();
        Console.WriteLine($"    {Paint($"… 还有 {withAlias.Count - pageSize} 个已识别成员未显示", Sgr.Grey)}");
    }

    var noAlias = resolved.Count - withAlias.Count;
    Console.WriteLine();
    Console.WriteLine($"    {Paint("身份覆盖率", Sgr.Grey)}  " +
                      $"{Ui.Bar(withAlias.Count, resolved.Count)}  " +
                      Paint($"{withAlias.Count}/{resolved.Count}", Sgr.Bold));
    if (noAlias > 0)
        Console.WriteLine($"    {Paint($"另有 {noAlias} 个对端只有 IP/MAC（多为历史缓存，当前无会话）", Sgr.Grey)}");
}

// ── ⑥ 已知节点的身份信息（来自日志）──────────────────────────
var top = byNode.Values
    .OrderByDescending(e => e.Timestamp)
    .Take(20)
    .ToList();

Ui.Section("最近活跃的节点", $"共 {byNode.Count:N0} 个已知节点，此处显示最近 {top.Count} 个");

var nodeTable = new Ui.Table(
    ["节点 ID", "最近活动", "连接方式", "别名"],
    [
        s => Paint(s, Sgr.Grey),
        s => Paint(s, Sgr.Dim),
        s => s.Contains("UDP") ? Paint(s, Sgr.Green)
           : s.Contains("TCP 直连") ? Paint(s, Sgr.Cyan)
           : s.Contains("中继") ? Paint(s, Sgr.Yellow)
           : Paint(s, Sgr.Grey),
        s => Paint(s, Sgr.Magenta),
    ]);

foreach (var e in top)
{
    string when = e.Timestamp == DateTime.MinValue
        ? "—"
        : e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    nodeTable.Add(e.NodeId.ToString(), when, e.ViaText, e.Alias);
}

nodeTable.Render();

// ── ⑦ 数据源与限制说明 ───────────────────────────────────────
Ui.Section("数据源说明");

var sourceTable = new Ui.Table(["数据源", "提供的内容", "可靠性"]);
sourceTable.Add("网卡邻居表", "对端虚拟 IP + MAC + 可达状态", "高");
sourceTable.Add("服务日志", "节点 ID + 别名 + 连接方式 + 时间", "高");
sourceTable.Add("控制管道", "状态快照 + 增量事件（用于关联身份）", "高");
sourceTable.Render();

Console.WriteLine();
Console.WriteLine("    " + Paint("IP ↔ 别名 关联方法", Sgr.Bold));
Console.WriteLine("    " + Paint("· 虚拟 IP 在快照里以 4 字节原始形式出现", Sgr.Grey));
Console.WriteLine("    " + Paint("· 别名以 UTF-16LE 出现，起始偏移可能是奇数", Sgr.Grey));
Console.WriteLine("    " + Paint("· 以服务日志的已知别名作白名单精确匹配，再按邻近性配对", Sgr.Grey));
Console.WriteLine("    " + Paint("· 双向去重，保证严格一对一", Sgr.Grey));

Console.WriteLine();
Console.WriteLine("    " + Paint("⚠ 未实现：命令下发（加入网络 / 启用禁用 / 踢人）", Sgr.Yellow));
Console.WriteLine("    " + Paint("服务对非法报文静默丢弃且不记日志，命令格式仍需完成逆向。", Sgr.Grey));
Console.WriteLine("    " + Paint("详见 docs/OPEN_ISSUE_commands.md", Sgr.Grey));
Console.WriteLine();
Console.WriteLine("    " + Paint($"提示：使用 --json / --list 可获得无装饰的机器可读输出；" +
                                    "--no-color 关闭配色", Sgr.Grey));
Console.WriteLine();

return 0;
