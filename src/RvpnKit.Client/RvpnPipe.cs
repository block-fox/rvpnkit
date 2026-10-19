using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace RvpnKit.Client;

/// <summary>
/// Radmin VPN 控制管道的客户端连接。
///
/// <para><b>重要限制：</b>服务端 <c>RvControlSvc.exe</c> 只创建
/// <b>1 个</b>管道实例（实测：第 2 次连接立即失败）。因此本客户端与官方 GUI
/// <b>互斥</b> —— 必须先关闭 Radmin VPN 主界面，才能接管该管道。</para>
///
/// <para><b>I/O 模式：</b>服务端把管道实例创建为字节流同步模式，以
/// <c>FILE_FLAG_OVERLAPPED</c> 打开会被拒绝。这里用<b>同步句柄 + 专用读线程</b>：
/// 读线程阻塞在 <c>ReadFile</c> 上，把数据推入无界通道；调用方按自身节奏从通道取。
/// 释放时关闭句柄即可让阻塞的读立即返回。</para>
///
/// <para>目前只支持<b>读取</b>。写路径（加入网络等命令）尚未实现，本类故意不暴露
/// 发送接口 —— 在命令格式经真实验证之前，不发出可能扰乱服务状态的字节。</para>
/// </summary>
public sealed class RvpnPipe : IDisposable
{
    /// <summary>管道名称（实测确认）。</summary>
    public const string PipeName = @"\\.\pipe\RadminVpnGuiChannel";

    // ── P/Invoke 常量
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    // ── Win32 错误码
    private const int ERROR_FILE_NOT_FOUND = 2;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_BROKEN_PIPE = 109;
    private const int ERROR_BUSY = 170;
    private const int ERROR_PIPE_BUSY = 231;
    private const int ERROR_PIPE_NOT_CONNECTED = 233;

    /// <summary>连接失败时存放在 <see cref="Exception.Data"/> 里的错误码键名。</summary>
    public const string Win32ErrorKey = "Win32Error";

    private readonly Channel<byte[]> _incoming =
        Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleWriter = true,
            SingleReader = true,
        });

    private readonly List<byte> _pending = new(1 << 16);
    private SafeFileHandle? _handle;
    private Thread? _reader;
    private volatile bool _disposed;
    private volatile bool _readerDone;
    private int _readError;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle hFile, byte[] buffer,
                                        int nBytesToRead, out int nBytesRead,
                                        IntPtr lpOverlapped);

    /// <summary>是否已连接且读线程仍在工作。</summary>
    public bool IsConnected =>
        !_disposed && _handle is { IsInvalid: false, IsClosed: false } && !_readerDone;

    /// <summary>待解析缓冲区中的字节数。</summary>
    public int PendingBytes => _pending.Count;

    /// <summary>连接期间遇到的 Win32 读错误码（0 表示无错误）。</summary>
    public int ReadError => _readError;

    /// <summary>读线程是否已结束（对端关闭或出错）。</summary>
    public bool ReaderCompleted => _readerDone;

    /// <summary>
    /// 连接控制管道。
    ///
    /// <para><b>关键：必须以「只读」权限打开。</b>实测该管道的 ACL 只授予读权限，
    /// 请求 <c>GENERIC_READ | GENERIC_WRITE</c> 会被拒绝（Win32 错误 5）。
    /// 探测结果：只读 ✓ / 读写 ✗ / 只写 ✗ / 0 权限 → 231。</para>
    ///
    /// <para>这也说明<b>写路径需要别的途径</b>：本客户端无法通过该管道下发命令。</para>
    /// </summary>
    /// <exception cref="IOException">连接失败，异常数据里带 Win32 错误码。</exception>
    public void Connect()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var h = CreateFileW(PipeName, GENERIC_READ, 0, IntPtr.Zero,
                            OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            var ex = new IOException(DescribeConnectError(err), err);
            ex.Data[Win32ErrorKey] = err;
            throw ex;
        }

        _handle = h;
        _reader = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name = "rvpn-pipe-reader",
        };
        _reader.Start();
    }

    /// <summary>带重试的连接：管道忙时反复尝试，直到超时。</summary>
    /// <returns>成功返回 true；超时返回 false。</returns>
    public async Task<bool> ConnectWithRetryAsync(TimeSpan timeout,
                                                  CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow + timeout;
        var delay = TimeSpan.FromMilliseconds(200);

        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            try
            {
                Connect();
                return true;
            }
            catch (IOException ex)
                when (ex.Data[Win32ErrorKey] is int code
                      && (code == ERROR_BUSY || code == ERROR_PIPE_BUSY))
            {
                // 唯一实例被其它客户端占用，稍后重试
            }

            await Task.Delay(delay, ct).ConfigureAwait(false);
            if (delay < TimeSpan.FromSeconds(1))
                delay += TimeSpan.FromMilliseconds(150);
        }

        return false;
    }

    /// <summary>把 Win32 错误码翻译成可操作的中文说明。</summary>
    public static string DescribeConnectError(int err) => err switch
    {
        ERROR_FILE_NOT_FOUND =>
            $"无法连接 {PipeName}：官方 Radmin VPN 服务似乎未运行（错误 2）。",
        ERROR_ACCESS_DENIED =>
            $"无法连接 {PipeName}：访问被拒绝（错误 5）。",
        ERROR_BUSY or ERROR_PIPE_BUSY =>
            $"无法连接 {PipeName}：管道忙（错误 {err}）。\n" +
            "  服务端只提供【1 个】管道实例，官方 GUI 或其他客户端正在占用。\n" +
            "  解决办法：关闭 Radmin VPN 主界面后重试。",
        _ => $"无法连接 {PipeName}：Win32 错误 {err}。",
    };

    /// <summary>专用读线程：同步阻塞读，把数据推入通道。</summary>
    private void ReaderLoop()
    {
        var buffer = new byte[64 * 1024];

        try
        {
            while (!_disposed)
            {
                var h = _handle;
                if (h is null || h.IsInvalid || h.IsClosed) break;

                if (!ReadFile(h, buffer, buffer.Length, out int n, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err is ERROR_BROKEN_PIPE or ERROR_PIPE_NOT_CONNECTED) break;
                    if (_disposed) break;
                    _readError = err;
                    break;
                }

                if (n <= 0) break;

                var chunk = new byte[n];
                Array.Copy(buffer, chunk, n);
                if (!_incoming.Writer.TryWrite(chunk)) break;
            }
        }
        catch (ObjectDisposedException)
        {
            // 释放期间的正常终止
        }
        finally
        {
            _readerDone = true;
            _incoming.Writer.TryComplete();
        }
    }

    /// <summary>读取一批字节，超时返回空数组。新数据同时追加进待解析缓冲区。</summary>
    public async Task<byte[]> ReadChunkAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // 不用 CancelAfter + 事件过滤器：Channel 的异步等待在取消时抛出的
        // OperationCanceledException 其 Token 不保证等于我们传入的那个，
        // 用过滤器会漏判。这里改为显式判定「外部是否要求取消」。
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        try
        {
            var chunk = await _incoming.Reader.ReadAsync(timeoutCts.Token).ConfigureAwait(false);
            _pending.AddRange(chunk);
            return chunk;
        }
        catch (OperationCanceledException)
        {
            // 外部取消要如实抛出；仅超时则视为「本轮无数据」
            ct.ThrowIfCancellationRequested();
            return [];
        }
        catch (ChannelClosedException)
        {
            return [];   // 读线程已结束（对端关闭）
        }
    }

    /// <summary>从缓冲区取出一整帧（剥离 4 字节长度前缀）。</summary>
    /// <returns>false 表示数据还不够一整帧。</returns>
    public bool TryTakeFrame(out byte[] frame)
    {
        frame = [];
        if (_pending.Count < 4) return false;

        int len = BinaryPrimitives.ReadInt32LittleEndian(CollectionsMarshal.AsSpan(_pending));
        if (len <= 0 || len > 64 * 1024 * 1024)
            throw new InvalidDataException($"帧长度非法: {len}（缓冲区可能已失步）");

        if (_pending.Count < 4 + len) return false;

        frame = _pending.GetRange(4, len).ToArray();
        _pending.RemoveRange(0, 4 + len);
        return true;
    }

    /// <summary>丢弃待解析缓冲区，用于失步后重新同步。</summary>
    public void ResetBuffer() => _pending.Clear();

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // 关闭句柄会让阻塞中的 ReadFile 立刻返回，从而唤醒读线程
        _handle?.Dispose();
        _handle = null;

        _incoming.Writer.TryComplete();

        if (_reader is { IsAlive: true } && Thread.CurrentThread != _reader)
            _reader.Join(TimeSpan.FromSeconds(2));

        _reader = null;
    }
}
