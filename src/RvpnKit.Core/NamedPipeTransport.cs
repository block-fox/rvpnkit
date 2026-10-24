using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RvpnKit.Core;

/// <summary>
/// Windows 上直连官方服务控制管道的传输。
///
/// <para>默认按读写打开；失败时降级为只读（仍能监控，但不能下发命令）。
/// 读写打开被拒通常是**完整性级别**问题：受限环境派生的进程运行在 Low，
/// 而该管道要求 Medium 才允许写入。由用户正常启动时为 Medium，读写均正常。</para>
/// </summary>
public sealed class NamedPipeTransport : IRvpnTransport
{
    /// <summary>默认管道路径。</summary>
    public const string DefaultPipe = @"\\.\pipe\RadminVpnGuiChannel";

    private const uint GenericRead = 0x8000_0000;
    private const uint GenericWrite = 0x4000_0000;
    private const uint OpenExisting = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle h, byte[] buf, int n,
                                        out int got, IntPtr ov);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(SafeFileHandle h, byte[] buf, int n,
                                         out int wrote, IntPtr ov);

    private readonly string _pipeName;
    private readonly SafeFileHandle _handle;

    /// <inheritdoc />
    public bool CanWrite { get; }

    /// <inheritdoc />
    public string Describe => $"{_pipeName}{(CanWrite ? "（读写）" : "（只读）")}";

    private NamedPipeTransport(string pipeName, SafeFileHandle handle, bool canWrite)
    {
        _pipeName = pipeName;
        _handle = handle;
        CanWrite = canWrite;
    }

    /// <summary>连接控制管道。</summary>
    /// <param name="pipeName">管道路径，默认 <see cref="DefaultPipe"/>。</param>
    public static NamedPipeTransport Connect(string pipeName = DefaultPipe)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("命名管道传输仅支持 Windows");

        IntPtr raw = CreateFileW(pipeName, GenericRead | GenericWrite, 0, IntPtr.Zero,
                                 OpenExisting, 0, IntPtr.Zero);
        if (raw != new IntPtr(-1) && raw != IntPtr.Zero)
            return new NamedPipeTransport(pipeName, new SafeFileHandle(raw, true), true);

        int firstErr = Marshal.GetLastWin32Error();

        raw = CreateFileW(pipeName, GenericRead, 0, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (raw == new IntPtr(-1) || raw == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new RvpnTransportException(
                $"打开管道失败（错误 {err}）；读写模式曾返回 {firstErr}。" +
                "若是 Low 完整性环境，请用普通用户身份直接运行程序。", err);
        }

        return new NamedPipeTransport(pipeName, new SafeFileHandle(raw, true), false);
    }

    /// <inheritdoc />
    public ValueTask SendAsync(ReadOnlyMemory<byte> frameBody, CancellationToken ct = default)
    {
        if (!CanWrite)
            throw new RvpnTransportException("当前为只读连接，无法下发命令");

        var buf = new byte[4 + frameBody.Length];
        BinaryPrimitives.WriteInt32LittleEndian(buf, frameBody.Length);
        frameBody.Span.CopyTo(buf.AsSpan(4));

        if (!WriteFile(_handle, buf, buf.Length, out int wrote, IntPtr.Zero))
        {
            int err = Marshal.GetLastWin32Error();
            throw new RvpnTransportException($"写入管道失败（错误 {err}）", err);
        }
        if (wrote != buf.Length)
            throw new RvpnTransportException($"写入不完整：{wrote}/{buf.Length}");
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<byte[]> ReadSnapshotAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        var buf = new byte[1 << 20];
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var ms = new MemoryStream();

        while (!cts.IsCancellationRequested)
        {
            if (!ReadFile(_handle, buf, buf.Length, out int got, IntPtr.Zero)) break;
            if (got == 0) break;
            ms.Write(buf, 0, got);
        }
        return ValueTask.FromResult(ms.ToArray());
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        _handle.Dispose();
        return ValueTask.CompletedTask;
    }
}
