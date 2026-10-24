using System;
using System.Runtime.InteropServices;

// 读取进程令牌的完整性级别（Integrity Level），用来解释「为什么只有 Python
// 能写 Radmin 控制管道」。ASCII-only 注释，避免 PowerShell Add-Type 的
// ANSI 读取把中文注释截断。
public class Integrity
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf,
                                           int len, out int needed);

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    public static string Of(uint pid)
    {
        IntPtr proc = OpenProcess(0x1000, false, pid);        // PROCESS_QUERY_LIMITED_INFORMATION
        if (proc == IntPtr.Zero) return "打不开进程 err=" + Marshal.GetLastWin32Error();
        try
        {
            IntPtr tok;
            if (!OpenProcessToken(proc, 0x0008, out tok))     // TOKEN_QUERY
                return "打不开令牌 err=" + Marshal.GetLastWin32Error();
            try
            {
                int needed;
                GetTokenInformation(tok, 18, IntPtr.Zero, 0, out needed); // TokenIntegrityLevel
                IntPtr buf = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!GetTokenInformation(tok, 18, buf, needed, out needed))
                        return "GetTokenInformation 失败 err=" + Marshal.GetLastWin32Error();

                    SID_AND_ATTRIBUTES sa = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(buf);
                    // SID 布局：Revision(1) SubAuthorityCount(1) IdentifierAuthority(6)
                    //           然后紧跟 count 个 4 字节 SubAuthority。完整性级别在最后一个。
                    int count = Marshal.ReadByte(sa.Sid, 1);
                    uint rid = (uint)Marshal.ReadInt32(sa.Sid, 8 + (count - 1) * 4);

                    string name;
                    if (rid == 0x0000) name = "Untrusted";
                    else if (rid == 0x1000) name = "Low";
                    else if (rid == 0x2000) name = "Medium";
                    else if (rid == 0x2100) name = "Medium-Plus";
                    else if (rid == 0x3000) name = "High";
                    else if (rid == 0x4000) name = "System";
                    else name = "0x" + rid.ToString("x");
                    return name + " (0x" + rid.ToString("x") + ")";
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(tok); }
        }
        finally { CloseHandle(proc); }
    }
}
