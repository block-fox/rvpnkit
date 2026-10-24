namespace RvpnKit.App.Services;

using RvpnKit.Core;

/// <summary>
/// 控制面后端抽象。
///
/// <para>两种实现共用同一套界面：</para>
/// <list type="bullet">
///   <item><see cref="DirectControlService"/> —— 进程内直连命名管道，走
///         <see cref="NamedPipeTransport"/>。没有 HTTP、没有 JSON、没有额外进程，
///         延迟最低。仅 Windows 可用。</item>
///   <item><see cref="HttpControlService"/> —— 通过 <c>rvpnkit-agent</c> 的 REST 接口。
///         任何平台、任何机器都能用，适合远程管理或 Linux/macOS。</item>
/// </list>
/// </summary>
public interface IControlService : IAsyncDisposable
{
    /// <summary>后端名称，显示在状态栏。</summary>
    string Name { get; }

    /// <summary>是否能下发命令（只读时为 false）。</summary>
    bool CanWrite { get; }

    /// <summary>读取当前状态。</summary>
    Task<SnapshotState> GetStateAsync(bool refresh, CancellationToken ct = default);

    /// <summary>枚举可加入的公共网络（已排除已加入的）。</summary>
    Task<IReadOnlyList<string>> GetPublicNetworksAsync(string? search, CancellationToken ct = default);

    /// <summary>开关 VPN 电源。</summary>
    Task PowerAsync(bool on, CancellationToken ct = default);

    /// <summary>修改本机别名。</summary>
    Task SetAliasAsync(string alias, CancellationToken ct = default);

    /// <summary>加入网络。</summary>
    Task JoinAsync(string name, CancellationToken ct = default);

    /// <summary>创建网络。</summary>
    Task CreateAsync(string name, CancellationToken ct = default);

    /// <summary>离开网络。</summary>
    Task LeaveAsync(string guidHex, CancellationToken ct = default);

    /// <summary>删除网络。</summary>
    Task DeleteAsync(string guidHex, CancellationToken ct = default);

    /// <summary>启用/禁用网络。</summary>
    Task SetEnabledAsync(string guidHex, bool enabled, CancellationToken ct = default);

    /// <summary>成员操作：kick / approve / grant / revoke。</summary>
    Task MemberOpAsync(string op, string guidHex, ulong nodeId, string networkName,
                       CancellationToken ct = default);
}
