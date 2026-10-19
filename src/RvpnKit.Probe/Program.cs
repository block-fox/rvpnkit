using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

Console.OutputEncoding = Encoding.UTF8;

const string Pipe = @"\\.\pipe\RadminVpnGuiChannel";
const uint GENERIC_READ = 0x80000000;
const uint GENERIC_WRITE = 0x40000000;
const uint GENERIC_ALL = 0x10000000;
const uint FILE_GENERIC_READ = 0x120089;
const uint FILE_GENERIC_WRITE = 0x120116;
const uint OPEN_EXISTING = 3;

Console.WriteLine("=== .NET 管道访问隔离实验 ===");
Console.WriteLine($"进程位数: {(Environment.Is64BitProcess ? 64 : 32)}");
Console.WriteLine($"用户: {System.Security.Principal.WindowsIdentity.GetCurrent().Name}");
Console.WriteLine();

Console.WriteLine("--- 逐种权限尝试（间隔 1.2s，仅对 BUSY 重试）---");

var cases = new (string Label, uint Access)[]
{
    ("只读 GENERIC_READ                    ", GENERIC_READ),
    ("读写 GENERIC_READ|GENERIC_WRITE      ", GENERIC_READ | GENERIC_WRITE),
    ("FILE_GENERIC_READ （具体权限位）      ", FILE_GENERIC_READ),
    ("FILE_GENERIC_WRITE（具体权限位）      ", FILE_GENERIC_WRITE),
    ("FILE_GENERIC_READ|FILE_GENERIC_WRITE ", FILE_GENERIC_READ | FILE_GENERIC_WRITE),
    ("GENERIC_ALL                          ", GENERIC_ALL),
    ("0（仅查询）                          ", 0),
};

foreach (var (label, access) in cases)
{
    int ok = 0;
    int lastErr = 0;
    for (int attempt = 0; attempt < 4; attempt++)
    {
        Thread.Sleep(1200);
        var h = CreateFileW(Pipe, access, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid)
        {
            lastErr = Marshal.GetLastWin32Error();
            if (lastErr != 231) break;   // 非 BUSY 无需重试
        }
        else
        {
            ok++;
            h.Dispose();
            break;
        }
    }

    Console.WriteLine(ok > 0
        ? $"  ✓ OK      {label}"
        : $"  ✗ err={lastErr,-4} {Describe(lastErr),-22} {label}");
}

Console.WriteLine();
Console.WriteLine("--- .NET 自带 NamedPipeClientStream ---");
foreach (var opt in new[]
{
    System.IO.Pipes.PipeOptions.None,
    System.IO.Pipes.PipeOptions.Asynchronous,
    System.IO.Pipes.PipeOptions.WriteThrough,
})
{
    try
    {
        using var s = new System.IO.Pipes.NamedPipeClientStream(
            ".", "RadminVpnGuiChannel", System.IO.Pipes.PipeDirection.InOut, opt);
        s.Connect(2000);
        Console.WriteLine($"  ✓ OK      PipeOptions.{opt}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  ✗ {ex.GetType().Name,-16} PipeOptions.{opt} — {ex.Message}");
    }
    Thread.Sleep(600);
}

static string Describe(int err) => err switch
{
    2 => "文件不存在",
    5 => "访问被拒绝",
    231 => "管道忙",
    _ => "(其它)",
};

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
    uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);
