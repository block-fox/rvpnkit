namespace RvpnKit.App.Services;

using RvpnKit.Core;

/// <summary>
/// 直连后端：进程内通过命名管道和 Radmin 服务通信。
///
/// <para>这是最快的路径 —— 没有 HTTP 往返、没有 JSON 序列化、没有中间进程，
/// 命令帧直接从本进程写进管道。仅 Windows 可用。</para>
///
/// <para>为了不长期霸占管道实例（服务端实例数有限，占着会影响官方 GUI 重连），
/// 每次操作都新建连接、用完即关。快照读取较慢（服务连上就推 ~600KB），
/// 所以加了几秒缓存。</para>
/// </summary>
public sealed class DirectControlService : IControlService
{
    private readonly object _gate = new();
    private SnapshotState? _cache;
    private DateTime _cacheAt = DateTime.MinValue;
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(4);

    /// <inheritdoc />
    public string Name => "直连管道";

    /// <inheritdoc />
    public bool CanWrite { get; private set; } = true;

    /// <summary>探测当前环境能否直连（能打开管道即可）。</summary>
    public static bool Probe()
    {
        if (!OperatingSystem.IsWindows()) return false;
        NamedPipeTransport? tp = null;
        try
        {
            tp = NamedPipeTransport.Connect();
            return true;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (tp is not null) _ = tp.DisposeAsync();
        }
    }

    /// <inheritdoc />
    public async Task<SnapshotState> GetStateAsync(bool refresh, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (!refresh && _cache is not null && DateTime.UtcNow - _cacheAt < Ttl)
                return _cache;
        }

        await using NamedPipeTransport tp = NamedPipeTransport.Connect();
        CanWrite = tp.CanWrite;
        byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(3), ct);
        SnapshotState st = Snapshot.Parse(raw);

        lock (_gate)
        {
            _cache = st;
            _cacheAt = DateTime.UtcNow;
        }
        return st;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetPublicNetworksAsync(string? search,
                                                                    CancellationToken ct = default)
    {
        SnapshotState st = await GetStateAsync(refresh: true, ct);
        var joined = st.Networks.Select(n => n.Name)
                                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        await using NamedPipeTransport tp = NamedPipeTransport.Connect();
        if (!tp.CanWrite)
            throw new InvalidOperationException(
                "只读连接无法枚举公共网络。若程序运行在受限环境（Low 完整性），" +
                "请改用普通用户身份直接启动。");

        await tp.SendAsync(Commands.EnumPublicNetworks("", NextId()), ct);
        byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(3), ct);
        IReadOnlyList<string> all = PublicNetworks.ExtractNames(raw);

        IEnumerable<string> q = all.Where(n => !joined.Contains(n));
        if (!string.IsNullOrWhiteSpace(search))
            q = q.Where(n => n.Contains(search, StringComparison.OrdinalIgnoreCase));

        return q.Distinct(StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal).ToList();
    }

    // ── 写操作

    /// <inheritdoc />
    public Task PowerAsync(bool on, CancellationToken ct = default)
        => SendAsync(Commands.SwitchPower(on, NextId()), ct);

    /// <inheritdoc />
    public Task SetAliasAsync(string alias, CancellationToken ct = default)
        => SendAsync(Commands.ChangeAlias(alias, NextId()), ct);

    /// <inheritdoc />
    public Task JoinAsync(string name, CancellationToken ct = default)
        => SendAsync(Commands.JoinNetwork(name, NextId()), ct);

    /// <inheritdoc />
    public Task CreateAsync(string name, CancellationToken ct = default)
        => SendAsync(Commands.CreateNetwork(name, NextId()), ct);

    /// <inheritdoc />
    public Task LeaveAsync(string guidHex, CancellationToken ct = default)
        => SendAsync(Commands.LeaveNetwork(ParseGuid(guidHex), NextId()), ct);

    /// <inheritdoc />
    public Task DeleteAsync(string guidHex, CancellationToken ct = default)
        => SendAsync(Commands.DeleteNetwork(ParseGuid(guidHex), NextId()), ct);

    /// <inheritdoc />
    public Task SetEnabledAsync(string guidHex, bool enabled, CancellationToken ct = default)
        => SendAsync(Commands.SetNetworkEnabled(ParseGuid(guidHex), enabled, NextId()), ct);

    /// <inheritdoc />
    public Task MemberOpAsync(string op, string guidHex, ulong nodeId, string networkName,
                              CancellationToken ct = default)
    {
        CommandCode code = op.ToLowerInvariant() switch
        {
            "kick" or "remove" => CommandCode.KickNode,
            "approve" => CommandCode.ApproveJoin,
            "grant" or "grantadmin" => CommandCode.GrantAdmin,
            "revoke" or "revokeadmin" => CommandCode.RevokeAdmin,
            _ => throw new ArgumentException($"不支持的操作: {op}", nameof(op)),
        };
        return SendAsync(Commands.MemberOperation(code, ParseGuid(guidHex), nodeId,
                                                  networkName, NextId()), ct);
    }

    private async Task SendAsync(byte[] frame, CancellationToken ct)
    {
        await using NamedPipeTransport tp = NamedPipeTransport.Connect();
        if (!tp.CanWrite)
            throw new InvalidOperationException(
                "当前为只读连接，无法下发命令。若运行在受限环境（Low 完整性），" +
                "请用普通用户身份直接启动本程序。");
        await tp.SendAsync(frame, ct);

        // 命令生效后状态会变，丢掉缓存
        lock (_gate) { _cacheAt = DateTime.MinValue; }
    }

    private static uint NextId() => (uint)Random.Shared.Next(1, 0xFFFF);

    private static byte[] ParseGuid(string hex)
    {
        string s = hex.Replace("-", "");
        if (s.Length != 32) throw new ArgumentException("GUID 必须是 32 位十六进制", nameof(hex));
        return Convert.FromHexString(s);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
