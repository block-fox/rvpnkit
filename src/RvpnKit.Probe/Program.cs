using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

Console.OutputEncoding = Encoding.UTF8;

const string Pipe = @"\\.\pipe\RadminVpnGuiChannel";
const uint GENERIC_READ = 0x80000000;
const uint GENERIC_WRITE = 0x40000000;
const uint OPEN_EXISTING = 3;
const uint FILE_FLAG_OVERLAPPED = 0x40000000;

Console.WriteLine("C# 侧管道打开方式探测");
Console.WriteLine(new string('─', 60));
Console.WriteLine($"进程位数: {(Environment.Is64BitProcess ? 64 : 32)}");
Console.WriteLine($"当前用户: {System.Security.Principal.WindowsIdentity.GetCurrent().Name}");
Console.WriteLine();

// ── 1. 直接 P/Invoke，GENERIC_READ|GENERIC_WRITE（与 Python 完全一致的参数）
Oper(Pipe, GENERIC_READ | GENERIC_WRITE, 0, 0, "P/Invoke  RW  sync");

// ── 2. 只要读权限
Oper(Pipe, GENERIC_READ, 0, 0, "P/Invoke  R   sync");

// ── 3. 只要写权限
Oper(Pipe, GENERIC_WRITE, 0, 0, "P/Invoke  W   sync");

// ── 4. 0 权限（只查询）
Oper(Pipe, 0, 0, 0, "P/Invoke  -   sync");

// ── 5. 带 FILE_FLAG_OVERLAPPED
Oper(Pipe, GENERIC_READ | GENERIC_WRITE, 0, FILE_FLAG_OVERLAPPED, "P/Invoke  RW  overlapped");

// ── 6. 先 WaitNamedPipeW 再打开
Console.WriteLine();
Console.WriteLine("── 先 WaitNamedPipeW(5s) 再打开 ──");
WaitNamedPipeW(Pipe, 5000);
Oper(Pipe, GENERIC_READ | GENERIC_WRITE, 0, 0, "WaitNamedPipe RW  sync");

// ── 7. 用 .NET 自带的 NamedPipeClientStream
Console.WriteLine();
Console.WriteLine("── .NET NamedPipeClientStream ──");
TryManaged(Pipe + @"\".Replace(@"\\", @"\"));

static void Oper(string path, uint access, uint share, uint flags, string label)
{
    var h = CreateFileW(path, access, share, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
    if (h.IsInvalid)
    {
        int err = Marshal.GetLastWin32Error();
        Console.WriteLine($"✗ err={err,-4} {Describe(err),-34} {label}");
    }
    else
    {
        Console.WriteLine($"✓ OK          {"",-34} {label}");
        h.Dispose();
    }
}

static string Describe(int err) => err switch
{
    2 => "文件/管道不存在",
    5 => "访问被拒绝",
    231 => "管道忙（实例已用）",
    _ => "(其他)",
};

static void TryManaged(string path)
{
    string name = path.StartsWith(@"\\.\pipe\") ? path[9..] : path;

    foreach (var (dir, label) in new[]
    {
        (System.IO.Pipes.PipeDirection.InOut, "InOut"),
        (System.IO.Pipes.PipeDirection.In, "In"),
    })
    {
        try
        {
            using var s = new System.IO.Pipes.NamedPipeClientStream(
                ".", name, dir, System.IO.Pipes.PipeOptions.None);
            s.Connect(3000);
            Console.WriteLine($"✓ OK          {label,-34} NamedPipeClientStream({label})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ {ex.GetType().Name,-12} {(ex.Message.Length > 40 ? ex.Message[..40] : ex.Message),-34} NamedPipeClientStream({label})");
        }
    }
}

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
    uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);
