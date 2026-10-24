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
    private readonly Lock _writeLock = new();
    private SafeFileHandle? _handle;
    private bool _readOnly;
    private Thread? _reader;
    private volatile bool _disposed;
    private volatile bool _readerDone;
    private int _readError;

    /// <summary>
    /// 打开管道。
    ///
    /// <para><b>关于读写打开被拒（错误 5）的真实原因：完整性级别。</b>
    /// 实测：由受限环境派生的子进程运行在 <c>Low</c> 完整性（0x1000），而
    /// Radmin 控制管道的强制完整性策略要求 <c>Medium</c> 才允许写入 ——
    /// 于是同一时刻读能成功、写被拒，且与可执行文件是否签名无关。
    /// 由用户正常双击启动（Medium 完整性）时读写均正常。</para>
    ///
    /// <para>补充实测数据：</para>
    /// <code>
    ///   进程完整性 Low + GENERIC_READ            -> 打开成功
    ///   进程完整性 Low + GENERIC_WRITE           -> 错误 5
    ///   进程完整性 Low + FILE_APPEND_DATA|SYNC   -> 打开成功但 WriteFile 错误 5
    ///   进程完整性 Medium（普通用户启动）         -> 读写均正常
    /// </code>
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    private static readonly IntPtr InvalidHandle = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle hFile, byte[] buffer,
                                        int nBytesToRead, out int nBytesRead,
                                        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(SafeFileHandle hFile, byte[] buffer,
                                         int nBytesToWrite, out int nBytesWritten,
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
    /// <para><b>访问权限（实测结论）：</b>该管道在权限上<b>允许读写打开</b> ——
    /// Python 侧连续 12 次读写打开全部成功。但从 <b>.NET 进程</b>发起读写打开时
    /// 会出现 ERROR_ACCESS_DENIED（错误 5），而只读打开始终成功。原因尚未定位，
    /// 推测与 .NET 打开管道时请求的附加访问位有关。</para>
    ///
    /// <para>因此本方法采用<b>降级策略</b>：先尝试读写（可发送命令），失败则退回
    /// 只读（仅监控）。这样客户端在任何情况下都能工作，只是写能力可能被禁用。</para>
    /// </summary>
    /// <exception cref="IOException">两种模式都失败时抛出，异常数据里带 Win32 错误码。</exception>
    public void Connect()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // 先试读写：成功则具备下发命令的能力
        var raw = CreateFileW(PipeName, (GENERIC_READ | GENERIC_WRITE), 0, IntPtr.Zero,
                              OPEN_EXISTING, 0, IntPtr.Zero);
        int rwErr = Marshal.GetLastWin32Error();
        if (Environment.GetEnvironmentVariable("RVPNKIT_DEBUG_PIPE") == "1")
        {
            Console.Error.WriteLine(
                $"[debug] CreateFileW(RW) raw=0x{raw.ToInt64():x} err={rwErr} " +
                $"access=0x{(GENERIC_READ | GENERIC_WRITE):x8} open={OPEN_EXISTING}");
        }
        if (raw != InvalidHandle && raw != IntPtr.Zero)
        {
            _handle = new SafeFileHandle(raw, ownsHandle: true);
            _readOnly = false;
        }
        else
        {
            int firstErr = rwErr;

            // 降级：只读打开（监控模式）
            raw = CreateFileW(PipeName, GENERIC_READ, 0, IntPtr.Zero,
                              OPEN_EXISTING, 0, IntPtr.Zero);
            if (raw == InvalidHandle || raw == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                var ex = new IOException(
                    DescribeConnectError(err) +
                    $"\n  （读写模式曾返回错误 {firstErr}）", err);
                ex.Data[Win32ErrorKey] = err;
                throw ex;
            }

            _handle = new SafeFileHandle(raw, ownsHandle: true);
            _readOnly = true;
        }

        _reader = new Thread(ReaderLoop)
        {
            IsBackground = true,
            Name = "rvpn-pipe-reader",
        };
        _reader.Start();
    }

    /// <summary>是否以只读方式连接（此时无法下发命令）。</summary>
    public bool IsReadOnly => _readOnly;

    /// <summary>是否具备写入能力（以读写模式打开时成立）。</summary>
    public bool CanWrite => IsConnected && !_readOnly;

    /// <summary>
    /// 向服务端发送一帧（4 字节 LE 长度前缀 + 正文）。
    ///
    /// <para><b>警告：</b>命令正文的编码尚未完成逆向。此 API 目前仅用于受控实验
    /// （例如发送畸形帧以观察服务的错误响应）。</para>
    /// </summary>
    /// <returns>实际写入的字节数。</returns>
    public Task<int> SendAsync(byte[] frameBody, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var h = _handle;
        if (h is null || h.IsInvalid || h.IsClosed)
            throw new InvalidOperationException("尚未调用 Connect()，或连接已关闭");
        if (_readOnly)
            throw new InvalidOperationException(
                "当前为只读连接（监控模式），无法下发命令。\n" +
                "  原因是读写打开被拒绝（错误 5）。已排查确认：本机安全软件的\n" +
                "  「程序控制 / IPC 保护」会拦截未签名程序对其它进程命名管道的写入\n" +
                "  —— 同为子进程的 Python 能写、pwsh 进程内调用能写，唯独新编译的\n" +
                "  本程序被拒。\n" +
                "  解决办法：把 rvpnkit.exe 加入安全软件白名单；\n" +
                "  或直接用 native/rvpncmd.py 下发命令（Python 已在白名单内）。");
        if (frameBody.Length == 0) return Task.FromResult(0);

        var buffer = new byte[4 + frameBody.Length];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, frameBody.Length);
        frameBody.CopyTo(buffer, 4);

        // 写操作与读线程共用句柄；命名管道允许一读一写并发，
        // 但把写串行化可以避免交错的帧破坏服务端解析。
        lock (_writeLock)
        {
            if (!WriteFile(h, buffer, buffer.Length, out int written, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                throw new IOException($"写入管道失败，Win32 错误 {err}", err);
            }
            return Task.FromResult(written);
        }
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
