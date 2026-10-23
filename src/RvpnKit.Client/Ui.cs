using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace RvpnKit.Client;

/// <summary>
/// 终端视觉呈现层。
///
/// <para><b>设计原则：</b></para>
/// <list type="bullet">
/// <item><b>不污染机器输出</b> —— <c>--json</c> / <c>--list</c> 完全不经过本类，
/// 保证可被脚本解析。所有装饰只作用于人类阅读的报告与监控。</item>
/// <item><b>颜色自适应</b> —— 输出被重定向到文件或管道时自动关闭颜色，
/// 并尊重 <c>NO_COLOR</c> 环境变量（该约定见 no-color.org）。</item>
/// <item><b>CJK 对齐</b> —— 中文在终端占两格，用 <see cref="Width"/> 计算显示宽度，
/// 否则表格会错位。</item>
/// </list>
/// </summary>
public static class Ui
{
    // ── 控制台 VT 模式（Windows 上启用 ANSI 转义的前提）

    private const int StdOutputHandle = -11;
    private const uint EnableVirtualTerminalProcessing = 0x0004;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    private static bool? _colorEnabled;

    /// <summary>是否启用彩色输出。</summary>
    public static bool ColorEnabled
    {
        get
        {
            _colorEnabled ??= DetectColor();
            return _colorEnabled.Value;
        }
    }

    /// <summary>判断当前终端是否适合输出颜色。</summary>
    private static bool DetectColor()
    {
        // 显式关闭：NO_COLOR 约定，或输出被重定向（写进文件/管道）
        if (Environment.GetEnvironmentVariable("NO_COLOR") is { Length: > 0 })
            return false;
        if (Console.IsOutputRedirected)
            return false;
        if (Environment.GetEnvironmentVariable("TERM") is "dumb")
            return false;

        // Windows 上尝试开启 VT 处理；失败则退回无色
        if (OperatingSystem.IsWindows())
        {
            IntPtr h = GetStdHandle(StdOutputHandle);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
                return false;
            if (!GetConsoleMode(h, out uint mode))
                return false;
            if ((mode & EnableVirtualTerminalProcessing) == 0)
            {
                if (!SetConsoleMode(h, mode | EnableVirtualTerminalProcessing))
                    return false;
            }
        }

        return true;
    }

    /// <summary>强制关闭颜色（供 <c>--no-color</c> 使用）。</summary>
    public static void DisableColor() => _colorEnabled = false;

    // ── 语义色板

    /// <summary>ANSI 样式片段。颜色关闭时全部返回空串。</summary>
    public static class Sgr
    {
        private static string Wrap(string code) => ColorEnabled ? code : "";

        /// <summary>重置</summary>
        public static string Reset => Wrap("\u001b[0m");
        /// <summary>加粗</summary>
        public static string Bold => Wrap("\u001b[1m");
        /// <summary>暗淡</summary>
        public static string Dim => Wrap("\u001b[2m");
        /// <summary>青色（IP、标识符）</summary>
        public static string Cyan => Wrap("\u001b[36m");
        /// <summary>绿色（在线、成功）</summary>
        public static string Green => Wrap("\u001b[32m");
        /// <summary>黄色（注意、中继）</summary>
        public static string Yellow => Wrap("\u001b[33m");
        /// <summary>红色（离线、失败）</summary>
        public static string Red => Wrap("\u001b[31m");
        /// <summary>洋红（身份、别名）</summary>
        public static string Magenta => Wrap("\u001b[35m");
        /// <summary>蓝色（标题装饰）</summary>
        public static string Blue => Wrap("\u001b[34m");
        /// <summary>灰蓝（次要信息）</summary>
        public static string Grey => Wrap("\u001b[90m");
    }

    /// <summary>给文本套一层颜色并自动复位。</summary>
    public static string Paint(string text, string sgr)
        => ColorEnabled ? sgr + text + Sgr.Reset : text;

    // ── 显示宽度（CJK 占两格）

    /// <summary>计算字符串在终端里的显示宽度（东亚宽字符计 2）。</summary>
    public static int Width(string? s)
    {
        if (string.IsNullOrEmpty(s)) return 0;

        int w = 0;
        foreach (char c in s)
            w += IsWide(c) ? 2 : 1;
        return w;
    }

    /// <summary>判断是否为终端里占两格的字符。</summary>
    private static bool IsWide(char c)
    {
        // 常见东亚宽字符区间（覆盖中文、日文、韩文、全角标点）
        return c switch
        {
            >= '\u1100' and <= '\u115F' => true,   // 韩文字母
            >= '\u2E80' and <= '\u303E' => true,   // 中日韩部首与符号
            >= '\u3041' and <= '\u33FF' => true,   // 假名、注音、兼容字符
            >= '\u3400' and <= '\u4DBF' => true,   // 扩展 A
            >= '\u4E00' and <= '\u9FFF' => true,   // 基本汉字
            >= '\uA000' and <= '\uA4CF' => true,   // 彝文
            >= '\uAC00' and <= '\uD7A3' => true,   // 韩文音节
            >= '\uF900' and <= '\uFAFF' => true,   // 兼容汉字
            >= '\uFE30' and <= '\uFE6F' => true,   // 兼容形式
            >= '\uFF00' and <= '\uFF60' => true,   // 全角 ASCII
            >= '\uFFE0' and <= '\uFFE6' => true,   // 全角符号
            _ => false,
        };
    }

    /// <summary>按显示宽度右侧补空格。</summary>
    public static string PadRight(string s, int width)
    {
        int gap = width - Width(s);
        return gap > 0 ? s + new string(' ', gap) : s;
    }

    /// <summary>按显示宽度左侧补空格。</summary>
    public static string PadLeft(string s, int width)
    {
        int gap = width - Width(s);
        return gap > 0 ? new string(' ', gap) + s : s;
    }

    /// <summary>按显示宽度居中。</summary>
    public static string PadCenter(string s, int width)
    {
        int gap = width - Width(s);
        if (gap <= 0) return s;
        int left = gap / 2;
        return new string(' ', left) + s + new string(' ', gap - left);
    }

    /// <summary>截断到指定显示宽度（超出部分用 … 表示）。</summary>
    public static string Truncate(string s, int width)
    {
        if (Width(s) <= width) return s;

        var sb = new StringBuilder();
        int w = 0;
        foreach (char c in s)
        {
            int cw = IsWide(c) ? 2 : 1;
            if (w + cw > width - 1) break;
            sb.Append(c);
            w += cw;
        }
        return sb + "…";
    }

    /// <summary>终端可用宽度（用于分隔线长度），限制在 40~100。</summary>
    public static int ConsoleSpan
    {
        get
        {
            try
            {
                int w = Console.WindowWidth;
                if (w <= 0) return 78;
                return Math.Clamp(w - 2, 40, 100);
            }
            catch (IOException)
            {
                return 78;   // 无控制台（重定向）时用固定宽度
            }
        }
    }

    // ── 版面构件

    /// <summary>
    /// 横幅字形表：每个字母是 6 行、等高宽的块字符画。
    ///
    /// <para><b>为什么用表而不是一整段字符串：</b>手写 figlet 极易出现某行短一
    /// 两个字符的情况（本项目就踩过 —— 最后一个 T 被截断，导致行宽 55/52 不齐、
    /// 字母错位、右侧框线参差）。用等宽字形表程序化拼接可以从根本上避免。</para>
    /// </summary>
    private static readonly string[][] Glyphs =
    [
        // R
        ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
        // V
        ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚═══╝  "],
        // P
        ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
        // N
        ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
        // K
        ["██╗  ██╗ ", "██║ ██╔╝ ", "█████╔╝  ", "██╔═██╗  ", "██║  ██╗ ", "╚═╝  ╚═╝ "],
        // I
        ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
        // T
        ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    ];

    /// <summary>字形行数。</summary>
    private const int GlyphRows = 6;

    /// <summary>把字形表横向拼成完整艺术字。</summary>
    private static string[] BuildBannerArt()
    {
        var lines = new string[GlyphRows];
        for (int r = 0; r < GlyphRows; r++)
            lines[r] = string.Join(" ", Glyphs.Select(g => g[r]));
        return lines;
    }

    /// <summary>
    /// 打印顶部横幅：ASCII 艺术字 + 副标题 + 外层双线框。
    /// 框与内文按显示宽度自动对齐，中文副标题也不会错位。
    /// </summary>
    public static void Banner(string subtitle)
    {
        string[] art = BuildBannerArt();

        int artWidth = art.Max(a => Width(a));
        int inner = Math.Max(artWidth, Width(subtitle)) + 6;   // 左右各留 3 格

        string padTo(int contentWidth) => new string(' ', Math.Max(0, inner - 6 - contentWidth));

        string edge = Paint("║", Sgr.Blue);
        string blank = "  " + edge + new string(' ', inner) + edge;

        Console.WriteLine();
        Console.WriteLine("  " + Paint("╔" + new string('═', inner) + "╗", Sgr.Blue));
        Console.WriteLine(blank);

        foreach (string line in art)
        {
            // 先按显示宽度补空格，再着色 —— 着色不能影响宽度计算
            Console.WriteLine("  " + edge + "   " +
                              Paint(line + padTo(Width(line)), Sgr.Bold + Sgr.Cyan) +
                              "   " + edge);
        }

        Console.WriteLine(blank);
        Console.WriteLine("  " + edge + "   " +
                          Paint(subtitle + padTo(Width(subtitle)), Sgr.Dim) +
                          "   " + edge);
        Console.WriteLine(blank);
        Console.WriteLine("  " + Paint("╚" + new string('═', inner) + "╝", Sgr.Blue));
        Console.WriteLine();
    }

    /// <summary>打印章节标题，带左侧竖条与上下留白。</summary>
    public static void Section(string title, string? note = null)
    {
        Console.WriteLine();
        Console.WriteLine("  " + Paint("▌", Sgr.Cyan) + " " + Paint(title, Sgr.Bold));
        if (!string.IsNullOrEmpty(note))
            Console.WriteLine("    " + Paint(note, Sgr.Grey));
    }

    /// <summary>打印一条细分隔线。</summary>
    public static void Rule(int span, string ch = "─")
    {
        Console.WriteLine("    " + Paint(new string(ch[0], Math.Min(span, 96)), Sgr.Grey));
    }

    /// <summary>打印键值对（键右对齐，值着色）。</summary>
    public static void KeyValue(string key, string value, string? valueColor = null, int keyWidth = 14)
    {
        string painted = valueColor is null ? value : Paint(value, valueColor);
        Console.WriteLine($"    {Paint(PadLeft(key, keyWidth), Sgr.Grey)}  {painted}");
    }

    /// <summary>把 0~1 的比例画成进度条。</summary>
    public static string Bar(int value, int total, int width = 18)
    {
        if (total <= 0) return Paint(new string('░', width), Sgr.Grey);

        double ratio = Math.Clamp((double)value / total, 0, 1);
        int filled = (int)Math.Round(ratio * width);
        return Paint(new string('█', filled), Sgr.Cyan)
             + Paint(new string('░', width - filled), Sgr.Grey);
    }

    /// <summary>状态徽标：把状态文字映射成带颜色的简短标记。</summary>
    public static string Badge(string text, string color)
        => Paint($" {text} ", color);

    // ── 表格

    /// <summary>
    /// 按显示宽度自动对齐的表格。
    /// 每列可单独指定着色函数，避免把 ANSI 转义算进宽度。
    /// </summary>
    public sealed class Table
    {
        private readonly string[] _headers;
        private readonly List<string[]> _rows = [];
        private readonly List<Func<string, string>?> _painters;
        private readonly bool _autoIndex;

        /// <summary>创建表格。</summary>
        /// <param name="headers">列标题</param>
        /// <param name="painters">每列的着色函数，可为 null</param>
        public Table(string[] headers, Func<string, string>?[]? painters = null)
        {
            _headers = headers;
            _painters = painters is null
                ? Enumerable.Repeat<Func<string, string>?>(null, headers.Length).ToList()
                : [.. painters];
            _autoIndex = false;
        }

        /// <summary>追加一行。列数不足会自动补空。</summary>
        public void Add(params string[] cells)
        {
            var row = new string[_headers.Length];
            for (int i = 0; i < row.Length; i++)
                row[i] = i < cells.Length ? cells[i] ?? "" : "";
            _rows.Add(row);
        }

        /// <summary>渲染表格（含表头与对齐）。</summary>
        public void Render()
        {
            if (_rows.Count == 0) return;

            // 计算每列宽度（用未着色文本，避免转义序列干扰）
            var widths = new int[_headers.Length];
            for (int c = 0; c < _headers.Length; c++)
                widths[c] = Width(_headers[c]);

            foreach (var row in _rows)
                for (int c = 0; c < _headers.Length; c++)
                    widths[c] = Math.Max(widths[c], Width(row[c]));

            // 表头
            var headLine = new StringBuilder("    ");
            for (int c = 0; c < _headers.Length; c++)
                headLine.Append(PadRight(_headers[c], widths[c])).Append("  ");
            Console.WriteLine(Paint(headLine.ToString().TrimEnd(), Sgr.Bold));

            // 分隔线
            var sep = new StringBuilder("    ");
            for (int c = 0; c < _headers.Length; c++)
                sep.Append(new string('─', widths[c])).Append("  ");
            Console.WriteLine(Paint(sep.ToString().TrimEnd(), Sgr.Grey));

            // 数据行
            foreach (var row in _rows)
            {
                var line = new StringBuilder("    ");
                for (int c = 0; c < _headers.Length; c++)
                {
                    string cell = PadRight(row[c], widths[c]);
                    var painter = _painters[c];
                    line.Append(painter is null ? cell : painter(cell)).Append("  ");
                }
                Console.WriteLine(line.ToString().TrimEnd());
            }
        }
    }

    /// <summary>把字节数格式化成易读单位。</summary>
    public static string Bytes(long bytes) => bytes switch
    {
        >= 1L << 30 => (bytes / (double)(1L << 30)).ToString("F1", CultureInfo.InvariantCulture) + " GB",
        >= 1L << 20 => (bytes / (double)(1L << 20)).ToString("F1", CultureInfo.InvariantCulture) + " MB",
        >= 1L << 10 => (bytes / (double)(1L << 10)).ToString("F1", CultureInfo.InvariantCulture) + " KB",
        _ => bytes + " B",
    };
}
