using System.Text;
using RvpnKit.Client;
using RvpnKit.Protocol;

Console.OutputEncoding = Encoding.UTF8;

Console.WriteLine("RvpnKit — Radmin VPN 第三方客户端");
Console.WriteLine("多源聚合：控制管道 + 网卡邻居表 + 服务日志");
Console.WriteLine(new string('═', 78));

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

// ── ④ 控制管道：虚拟 IP 表 ───────────────────────────────────
var pipeIps = new List<string>();
var nodeIds = new List<ulong>();
int pipeBytes = 0, pipeFrames = 0;

Console.WriteLine();
Console.WriteLine("【控制管道】");
try
{
    using var pipe = new RvpnPipe();
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));

    try
    {
        pipe.Connect();
        Console.WriteLine($"  ✓ 已连接 {RvpnPipe.PipeName}（只读）");

        int idle = 0;
        while (true)
        {
            var chunk = await pipe.ReadChunkAsync(TimeSpan.FromMilliseconds(500), cts.Token);
            pipeBytes += chunk.Length;

            if (chunk.Length == 0)
            {
                if (++idle >= 3 && pipe.PendingBytes == 0) break;
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

        Console.WriteLine($"  读到 {pipeBytes:N0} 字节 / {pipeFrames} 帧");
        Console.WriteLine($"  提取虚拟 IP {pipeIps.Distinct().Count()} 个，" +
                          $"节点 ID {nodeIds.Distinct().Count()} 个");
    }
    catch (OperationCanceledException) { Console.WriteLine("  （读取窗口结束）"); }
}
catch (IOException ex)
{
    Console.WriteLine($"  ✗ 连接失败：{ex.Message}");
}

// ── ⑤ 汇总：成员列表 ─────────────────────────────────────────
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
    Console.WriteLine($"  {"虚拟 IP",-16} {"MAC 地址",-19} 状态");
    Console.WriteLine($"  {new string('─', 15)} {new string('─', 18)} {new string('─', 20)}");

    foreach (var p in resolved.OrderBy(p => p.Address.GetAddressBytes()[3]))
        Console.WriteLine($"  {p.Address,-16} {p.Mac,-19} {p.StateText}");
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
Console.WriteLine("  ✓ 网卡邻居表 : 实时对端 IP + MAC + 可达状态（可靠）");
Console.WriteLine("  ✓ 服务日志   : 节点 ID + 别名 + 连接方式（可靠，含时间）");
Console.WriteLine("  ⚠ 控制管道   : 已能连接并读到状态流，但容器层格式尚未完全对齐，");
Console.WriteLine("                 因此暂未用于成员身份关联");
Console.WriteLine();
Console.WriteLine("  待完成：把邻居表的 IP 与日志的别名通过管道字段关联起来，");
Console.WriteLine("          即可得到「IP ←→ 别名 ←→ 连接方式」的完整成员视图。");

return 0;
