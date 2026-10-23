using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Physical mouse control plus window lookup.
// ASCII-only comments on purpose: PowerShell's Add-Type reads the source with the
// system ANSI code page, and non-ASCII comments get truncated mid-byte, which
// then swallows the following newline and breaks compilation.
public class Phys
{
    public delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, IntPtr e);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int L, T, R, B; }

    public static string[] All(uint pid)
    {
        List<string> res = new List<string>();
        EnumWindows(delegate (IntPtr h, IntPtr l)
        {
            uint p;
            GetWindowThreadProcessId(h, out p);
            if (p != pid) return true;
            StringBuilder t = new StringBuilder(256); GetWindowTextW(h, t, 256);
            StringBuilder c = new StringBuilder(256); GetClassNameW(h, c, 256);
            RECT r; GetWindowRect(h, out r);
            res.Add(h.ToInt64() + "|" + c.ToString() + "|" + t.ToString() + "|vis=" + IsWindowVisible(h)
                    + "|" + r.L + "," + r.T + "|" + (r.R - r.L) + "x" + (r.B - r.T));
            return true;
        }, IntPtr.Zero);
        return res.ToArray();
    }

    public static IntPtr FindMain(uint pid)
    {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate (IntPtr h, IntPtr l)
        {
            uint p;
            GetWindowThreadProcessId(h, out p);
            if (p != pid) return true;
            StringBuilder t = new StringBuilder(256); GetWindowTextW(h, t, 256);
            StringBuilder c = new StringBuilder(256); GetClassNameW(h, c, 256);
            if (t.ToString() == "Radmin LAN" && c.ToString().IndexOf("QWindowIcon") >= 0)
            {
                found = h;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    public static int[] Rect(IntPtr h)
    {
        RECT r; GetWindowRect(h, out r);
        return new int[] { r.L, r.T, r.R - r.L, r.B - r.T };
    }

    // Bring window to front: topmost, activated, then restore normal z-order.
    public static bool Front(IntPtr h)
    {
        ShowWindow(h, 9);                                  // SW_RESTORE
        SetWindowPos(h, (IntPtr)(-1), 0, 0, 0, 0, 0x43);    // HWND_TOPMOST|NOMOVE|NOSIZE|SHOWWINDOW
        BringWindowToTop(h);
        bool ok = SetForegroundWindow(h);
        SetWindowPos(h, (IntPtr)(-2), 0, 0, 0, 0, 0x43);    // HWND_NOTOPMOST
        return ok;
    }

    public static void Click(int x, int y)
    {
        SetCursorPos(x, y);
        System.Threading.Thread.Sleep(180);
        mouse_event(0x0002, 0, 0, 0, IntPtr.Zero);
        System.Threading.Thread.Sleep(90);
        mouse_event(0x0004, 0, 0, 0, IntPtr.Zero);
    }
}
