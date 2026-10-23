using System.Text;
using RvpnKit.Protocol;

namespace RvpnKit.Client;

/// <summary>
/// 实时监控：持续跟踪对端与节点的上下线变化。
///
/// <para>数据源组合：</para>
/// <list type="bullet">
/// <item>网卡邻居表 —— 反映数据面的实时变化（谁会话建立/消失了）</item>
/// <item>控制管道 —— 服务推送的状态事件流（增量）</item>
/// <item>服务日志 —— 节点身份与连接方式</item>
/// </list>
///
/// <para>Radmin 是<b>按需建连</b>的：只有发生通信才会在对端之间建立隧道。
/// 因此"邻居表出现新条目"约等于"该节点刚上线或被访问"，
/// "条目消失"意味着会话结束。这正是原版界面不提供的能力。</para>
/// </summary>
public sealed class NetworkMonitor
{
    private readonly TimeSpan _interval;
    private readonly Dictionary<string, PeerTable.Peer> _known = new();
    private readonly Dictionary<ulong, ServiceLog.Entry> _nodeCache = new();
    private Dictionary<string, string> _aliasByIp = new(StringComparer.Ordinal);
    private DateTime _lastLogScan = DateTime.MinValue;

    /// <summary>创建监控器。</summary>
    /// <param name="interval">轮询间隔，默认 2 秒</param>
    public NetworkMonitor(TimeSpan? interval = null)
    {
        _interval = interval ?? TimeSpan.FromSeconds(2);
    }

    /// <summary>
    /// 注入「虚拟 IP → 别名」映射，用于在上线/下线事件里显示成员身份。
    /// 由调用方通过 <see cref="AliasResolver"/> 预先算好。
    /// </summary>
    public void SetAliases(IEnumerable<AliasResolver.Binding> bindings)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var b in bindings)
            map[b.Ip] = b.Alias;
        _aliasByIp = map;
    }

    /// <summary>查询某个虚拟 IP 对应的别名；未知时返回 null。</summary>
    public string? AliasOf(string ip) => _aliasByIp.GetValueOrDefault(ip);

    /// <summary>对端上线事件。</summary>
    public event Action<PeerTable.Peer>? PeerAppeared;

    /// <summary>对端下线事件。</summary>
    public event Action<PeerTable.Peer>? PeerDisappeared;

    /// <summary>邻居表发生变化（新增或消失）。</summary>
    public event Action<string>? Notice;

    /// <summary>节点信息发生变化（有新节点出现在日志里）。</summary>
    public event Action<ServiceLog.Entry>? NodeSeen;

    /// <summary>当前已知对端快照。</summary>
    public IReadOnlyDictionary<string, PeerTable.Peer> KnownPeers => _known;

    /// <summary>当前已知节点快照。</summary>
    public IReadOnlyDictionary<ulong, ServiceLog.Entry> KnownNodes => _nodeCache;

    /// <summary>
    /// 静默建立基线：把当前已存在的对端与节点填入缓存，<b>但不触发事件</b>。
    ///
    /// <para>否则启动瞬间会把所有历史对端都报成"刚刚上线"，产生大量噪声。
    /// 只有基线之后出现的差异才是真正的变化。</para>
    /// </summary>
    public void EstablishBaseline()
    {
        var localIp = PeerTable.LocalVirtualAddress();
        foreach (var p in PeerTable.Read(localIp).Where(p => p.HasValidMac))
            _known[p.Address.ToString()] = p;

        foreach (var (id, e) in ServiceLog.LatestByNode(ServiceLog.Read(maxFiles: 1)))
            _nodeCache[id] = e;

        _lastLogScan = DateTime.UtcNow;
    }

    /// <summary>
    /// 轮询一次，返回本次的变化数量。
    /// </summary>
    public int PollOnce()
    {
        int changes = 0;

        // ── 邻居表
        var localIp = PeerTable.LocalVirtualAddress();
        var current = PeerTable.Read(localIp)
            .Where(p => p.HasValidMac)
            .ToDictionary(p => p.Address.ToString());

        // 新增
        foreach (var (ip, peer) in current)
        {
            if (!_known.ContainsKey(ip))
            {
                _known[ip] = peer;
                PeerAppeared?.Invoke(peer);
                changes++;
            }
        }

        // 消失
        foreach (var ip in _known.Keys.ToList())
        {
            if (!current.ContainsKey(ip))
            {
                var gone = _known[ip];
                _known.Remove(ip);
                PeerDisappeared?.Invoke(gone);
                changes++;
            }
        }

        // ── 服务日志：滚动扫描新出现的节点
        var cutoff = DateTime.Now.AddMinutes(-3);
        if ((DateTime.UtcNow - _lastLogScan).TotalSeconds > 10)
        {
            _lastLogScan = DateTime.UtcNow;
            var entries = ServiceLog.Read(maxFiles: 1);
            foreach (var e in entries.Where(x => x.Timestamp >= cutoff))
            {
                if (!_nodeCache.ContainsKey(e.NodeId))
                {
                    _nodeCache[e.NodeId] = e;
                    NodeSeen?.Invoke(e);
                    changes++;
                }
                else if (_nodeCache[e.NodeId].Via != e.Via)
                {
                    _nodeCache[e.NodeId] = e;
                    NodeSeen?.Invoke(e);
                    changes++;
                }
            }
        }

        return changes;
    }

    /// <summary>
    /// 持续监控，直到取消。
    /// </summary>
    public async Task RunAsync(Action<string> output, CancellationToken ct)
    {
        // 先建立基线，避免启动时把所有已有对端都报成"上线"
        EstablishBaseline();

        output($"已建立基线：对端 {_known.Count} 个，节点 {_nodeCache.Count} 个");
        output("开始监控（Ctrl+C 退出）…");
        output("");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            PollOnce();
        }

        output("");
        output("监控结束。");
    }
}
