using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// Post mouse messages straight to a window handle, bypassing window z-order.
// Physical clicks depend on the target actually being on top; PostMessage does
// not, which matters here because SetForegroundWindow is often refused.
public class WinMsg
{
    public delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int L, T, R, B; }

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

    public static int[] ClientSize(IntPtr h)
    {
        RECT r; GetClientRect(h, out r);
        return new int[] { r.R - r.L, r.B - r.T };
    }

    // lParam packs client x in low word and y in high word
    static IntPtr MakeLParam(int x, int y)
    {
        return (IntPtr)((y << 16) | (x & 0xFFFF));
    }

    public static void ClickAt(IntPtr h, int x, int y)
    {
        PostMessageW(h, 0x0201, (IntPtr)1, MakeLParam(x, y));   // WM_LBUTTONDOWN
        System.Threading.Thread.Sleep(80);
        PostMessageW(h, 0x0202, IntPtr.Zero, MakeLParam(x, y)); // WM_LBUTTONUP
    }

    public static void RightClickAt(IntPtr h, int x, int y)
    {
        PostMessageW(h, 0x0204, (IntPtr)2, MakeLParam(x, y));   // WM_RBUTTONDOWN
        System.Threading.Thread.Sleep(80);
        PostMessageW(h, 0x0205, IntPtr.Zero, MakeLParam(x, y)); // WM_RBUTTONUP
    }

    public static void KeyPress(IntPtr h, int vk)
    {
        PostMessageW(h, 0x0100, (IntPtr)vk, IntPtr.Zero);       // WM_KEYDOWN
        System.Threading.Thread.Sleep(50);
        PostMessageW(h, 0x0101, (IntPtr)vk, IntPtr.Zero);       // WM_KEYUP
    }
}
