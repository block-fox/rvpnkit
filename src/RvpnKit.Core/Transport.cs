namespace RvpnKit.Core;

/// <summary>
/// 控制面传输抽象。
///
/// <para>把「怎么把帧送到 Radmin 服务」与「帧长什么样」解耦。有了这层，
/// 同一套协议内核可以跑在多种传输之上：</para>
/// <list type="bullet">
///   <item><see cref="NamedPipeTransport"/> —— Windows 上直连官方服务的命名管道</item>
///   <item>远程 Agent 的 HTTP/WebSocket 传输 —— 让 Linux / macOS / 手机 / 游戏内也能控制</item>
///   <item>抓包回放传输 —— 离线调试用</item>
/// </list>
/// </summary>
public interface IRvpnTransport : IAsyncDisposable
{
    /// <summary>传输是否可写（能否下发命令）。</summary>
    bool CanWrite { get; }

    /// <summary>描述当前传输，用于界面显示。</summary>
    string Describe { get; }

    /// <summary>发送一条命令正文（不含 4 字节长度前缀，由实现负责补）。</summary>
    ValueTask SendAsync(ReadOnlyMemory<byte> frameBody, CancellationToken ct = default);

    /// <summary>读取一段快照数据（实现负责在必要时先发枚举请求）。</summary>
    ValueTask<byte[]> ReadSnapshotAsync(TimeSpan timeout, CancellationToken ct = default);
}

/// <summary>传输层错误。</summary>
public sealed class RvpnTransportException : Exception
{
    /// <summary>Win32 错误码（如果有）。</summary>
    public int Win32Error { get; }

    /// <summary>构造。</summary>
    public RvpnTransportException(string message, int win32Error = 0, Exception? inner = null)
        : base(message, inner) => Win32Error = win32Error;
}
