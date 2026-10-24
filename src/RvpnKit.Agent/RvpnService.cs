using RvpnKit.Core;

namespace RvpnKit.Agent;

/// <summary>
/// 把协议内核的能力包装成「一次调用 = 一次管道连接」的服务。
///
/// <para>为什么要每次重连：Radmin 服务的管道实例数有限，长期占着会影响官方 GUI
/// 重连。命令都是毫秒级操作，重连成本可以接受。快照读取较慢（服务在连接时会
/// 推 ~600KB），所以加了缓存。</para>
/// </summary>
public sealed class RvpnService
{
    private readonly object _lock = new();
    private SnapshotState? _cache;
    private DateTime _cacheAt = DateTime.MinValue;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(5);

    /// <summary>最近一次读取是否处于只读连接（只读时命令会失败）。</summary>
    public bool LastReadOnly { get; private set; } = true;

    /// <summary>读一次快照（带缓存）。</summary>
    public async Task<SnapshotState> GetStateAsync(bool refresh, CancellationToken ct)
    {
        lock (_lock)
        {
            if (!refresh && _cache is not null && DateTime.UtcNow - _cacheAt < CacheTtl)
                return _cache;
        }

        await using var tp = NamedPipeTransport.Connect();
        LastReadOnly = !tp.CanWrite;
        byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(3), ct);
        SnapshotState st = Snapshot.Parse(raw);

        lock (_lock)
        {
            _cache = st;
            _cacheAt = DateTime.UtcNow;
        }
        return st;
    }

    /// <summary>枚举公共网络：已加入的会被排除。</summary>
    public async Task<IReadOnlyList<string>> GetPublicAsync(string? search, CancellationToken ct)
    {
        SnapshotState st = await GetStateAsync(refresh: true, ct);
        var joined = st.Networks.Select(n => n.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        await using var tp = NamedPipeTransport.Connect();
        if (!tp.CanWrite)
        {
            throw new RvpnTransportException(
                "只读连接无法枚举公共网络：枚举请求必须可写。" +
                "请用普通用户身份直接运行 agent（受限环境会把进程降到 Low 完整性，管道只给读）。");
        }

        // 先请求枚举，再读响应
        await tp.SendAsync(Commands.EnumPublicNetworks("", NewRequestId()), ct);

        byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(3), ct);
        IReadOnlyList<string> all = PublicNetworks.ExtractNames(raw);

        IEnumerable<string> q = all.Where(n => !joined.Contains(n));
        if (!string.IsNullOrWhiteSpace(search))
            q = q.Where(n => n.Contains(search, StringComparison.OrdinalIgnoreCase));

        return q.Distinct(StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal).ToList();
    }

    /// <summary>下发一条命令，返回请求编号。</summary>
    public async Task<uint> SendAsync(byte[] frameBody, CancellationToken ct)
    {
        await using var tp = NamedPipeTransport.Connect();
        if (!tp.CanWrite)
            throw new RvpnTransportException(
                "当前为只读连接，无法下发命令（管道读写打开被拒）。");
        await tp.SendAsync(frameBody, ct);
        return FrameReader.RequestId(frameBody);
    }

    /// <summary>生成请求编号。</summary>
    public static uint NewRequestId()
        => (uint)Random.Shared.Next(1, 0xFFFF);
}
