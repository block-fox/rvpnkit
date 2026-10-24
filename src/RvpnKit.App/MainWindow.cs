using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using RvpnKit.App.Services;
using RvpnKit.Core;

namespace RvpnKit.App;

/// <summary>
/// 主窗口。界面全部用代码构建。
///
/// <para>布局：</para>
/// <code>
/// ┌──────────────────────────────────────────────────────────┐
/// │ 状态栏：电源开关 / 本机信息 / 别名 / 刷新 / 后端       │
/// ├──────────────────┬───────────────────────────────────────┤
/// │ 网络列表         │ 成员列表（节点ID / 别名 / 公网IP）     │
/// │ + 加入/创建      │ + 踢出 / 授权 / 撤权 / 批准            │
/// ├──────────────────┴───────────────────────────────────────┤
/// │ 公共网络：搜索 + 结果 + 一键加入                         │
/// └──────────────────────────────────────────────────────────┘
/// </code>
/// </summary>
public sealed class MainWindow : Window
{
    // ── 后端
    private IControlService? _svc;
    private SnapshotState? _state;
    private NetworkInfo? _selectedNetwork;

    // ── 界面元素
    private readonly TextBlock _statusText = new() { VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _backendText = new()
    {
        VerticalAlignment = VerticalAlignment.Center,
        Foreground = Brush.Parse("#7aa2f7"),
        FontSize = 12,
    };
    private readonly ToggleSwitch _powerToggle = new() { Content = "VPN 电源", IsChecked = true };
    private readonly TextBox _aliasBox = new() { Watermark = "新别名", Width = 150 };
    private readonly ListBox _networkList = new();
    private readonly TextBlock _memberHeader = new() { FontWeight = FontWeight.SemiBold };
    private readonly ListBox _memberList = new();
    private readonly TextBox _joinBox = new() { Watermark = "网络名", Width = 190 };
    private readonly TextBox _publicBox = new() { Watermark = "搜索公共网络（如 DOTA / Minecraft）", Width = 300 };
    private readonly ListBox _publicList = new() { Height = 150 };
    private readonly List<Button> _writeButtons = [];
    private readonly ProgressBar _busy = new()
    {
        IsIndeterminate = true,
        Height = 3,
        IsVisible = false,
    };

    /// <summary>构造窗口。</summary>
    public MainWindow()
    {
        Title = "RvpnKit · Radmin VPN 客户端";
        Width = 1060;
        Height = 720;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Brush.Parse("#12151c");

        Content = BuildLayout();
        Opened += async (_, _) => await ConnectAndRefreshAsync();
    }

    // ─────────────────────────────────────────────────────── 界面构建

    private Control BuildLayout()
    {
        var header = new WrapPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(12, 10, 12, 6),
            ItemWidth = double.NaN,
        };
        header.Children.Add(_powerToggle);
        header.Children.Add(Sep());
        header.Children.Add(_aliasBox);
        header.Children.Add(MakeButton("改名", () => RunAsync(async () =>
        {
            if (string.IsNullOrWhiteSpace(_aliasBox.Text)) return;
            await Svc.SetAliasAsync(_aliasBox.Text!.Trim());
            SetStatus($"已请求改名 → {_aliasBox.Text}");
            await RefreshAsync(force: true);
        }), 8));
        header.Children.Add(Sep());
        header.Children.Add(MakeButton("刷新", () => RunAsync(() => RefreshAsync(force: true))));
        header.Children.Add(Sep());
        header.Children.Add(_statusText);

        var left = new DockPanel { Width = 360, Margin = new Thickness(12, 0, 6, 8) };

        var leftTop = new TextBlock
        {
            Text = "网络",
            FontWeight = FontWeight.SemiBold,
            Margin = new Thickness(0, 0, 0, 6),
        };
        DockPanel.SetDock(leftTop, Dock.Top);
        left.Children.Add(leftTop);

        var leftBottom = new StackPanel { Spacing = 6, Margin = new Thickness(0, 6, 0, 0) };
        var joinRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        joinRow.Children.Add(_joinBox);
        joinRow.Children.Add(MakeButton("加入", () => RunAsync(async () =>
        {
            string? n = _joinBox.Text?.Trim();
            if (string.IsNullOrEmpty(n)) return;
            await Svc.JoinAsync(n);
            SetStatus($"已请求加入 {n}");
            await RefreshAsync(force: true);
        })));
        joinRow.Children.Add(MakeButton("创建", () => RunAsync(async () =>
        {
            string? n = _joinBox.Text?.Trim();
            if (string.IsNullOrEmpty(n)) return;
            await Svc.CreateAsync(n);
            SetStatus($"已请求创建 {n}");
            await RefreshAsync(force: true);
        })));
        leftBottom.Children.Add(joinRow);

        var netOps = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        netOps.Children.Add(MakeButton("启用", () => RunAsync(() => ToggleNetworkAsync(true))));
        netOps.Children.Add(MakeButton("禁用", () => RunAsync(() => ToggleNetworkAsync(false))));
        netOps.Children.Add(MakeButton("离开", () => RunAsync(() => LeaveAsync(false))));
        netOps.Children.Add(MakeButton("删除", () => RunAsync(() => LeaveAsync(true))));
        leftBottom.Children.Add(netOps);

        DockPanel.SetDock(leftBottom, Dock.Bottom);
        left.Children.Add(leftBottom);

        _networkList.ItemTemplate = new FuncDataTemplate<NetworkInfo>((n, _) =>
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
            var name = new TextBlock
            {
                Text = n?.Name ?? "",
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
            };
            var count = new TextBlock
            {
                Text = n is null ? "" : $"{n.Members.Count}",
                Foreground = Brush.Parse("#8b98ab"),
                FontSize = 12,
                Margin = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
            };
            Grid.SetColumn(name, 0);
            Grid.SetColumn(count, 1);
            grid.Children.Add(name);
            grid.Children.Add(count);
            return grid;
        });
        _networkList.SelectionChanged += (_, _) =>
        {
            _selectedNetwork = _networkList.SelectedItem as NetworkInfo;
            RenderMembers();
        };
        left.Children.Add(_networkList);

        // ── 右侧：成员
        var right = new DockPanel { Margin = new Thickness(6, 0, 12, 8) };

        var rightTop = new StackPanel { Spacing = 6 };
        rightTop.Children.Add(_memberHeader);
        var memberOps = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        memberOps.Children.Add(MakeButton("踢出", () => RunAsync(() => MemberOpAsync("kick"))));
        memberOps.Children.Add(MakeButton("授权", () => RunAsync(() => MemberOpAsync("grant"))));
        memberOps.Children.Add(MakeButton("撤权", () => RunAsync(() => MemberOpAsync("revoke"))));
        memberOps.Children.Add(MakeButton("批准", () => RunAsync(() => MemberOpAsync("approve"))));
        rightTop.Children.Add(memberOps);
        DockPanel.SetDock(rightTop, Dock.Top);
        right.Children.Add(rightTop);

        _memberList.ItemTemplate = new FuncDataTemplate<MemberInfo>((m, _) =>
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("110,*,150") };
            var id = new TextBlock
            {
                Text = m is null ? "" : m.NodeId.ToString(),
                Foreground = Brush.Parse("#7aa2f7"),
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
            };
            var alias = new TextBlock
            {
                Text = m?.Alias ?? "-",
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
            };
            var ip = new TextBlock
            {
                Text = m?.PublicIp ?? "-",
                Foreground = Brush.Parse("#9ece6a"),
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center,
            };
            Grid.SetColumn(id, 0);
            Grid.SetColumn(alias, 1);
            Grid.SetColumn(ip, 2);
            grid.Children.Add(id);
            grid.Children.Add(alias);
            grid.Children.Add(ip);
            return grid;
        });
        right.Children.Add(_memberList);

        // ── 底部：公共网络
        var bottom = new StackPanel
        {
            Spacing = 6,
            Margin = new Thickness(12, 0, 12, 10),
        };
        var pubRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        pubRow.Children.Add(new TextBlock
        {
            Text = "公共网络",
            FontWeight = FontWeight.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
        });
        pubRow.Children.Add(_publicBox);
        pubRow.Children.Add(MakeButton("搜索", () => RunAsync(SearchPublicAsync)));
        pubRow.Children.Add(MakeButton("一键加入", () => RunAsync(async () =>
        {
            if (_publicList.SelectedItem is not string name) { SetStatus("先选中一个公共网络"); return; }
            await Svc.JoinAsync(name);
            SetStatus($"已请求加入 {name}");
            await RefreshAsync(force: true);
        })));
        pubRow.Children.Add(_backendText);
        bottom.Children.Add(pubRow);
        _publicList.ItemTemplate = new FuncDataTemplate<string>((s, _) => new TextBlock { Text = s ?? "" });
        _publicList.DoubleTapped += (_, _) => RunAsync(async () =>
        {
            if (_publicList.SelectedItem is not string name) return;
            await Svc.JoinAsync(name);
            SetStatus($"已请求加入 {name}");
            await RefreshAsync(force: true);
        });
        bottom.Children.Add(_publicList);
        DockPanel.SetDock(bottom, Dock.Bottom);

        var root = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(header);
        root.Children.Add(bottom);

        var body = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        Grid.SetColumn(left, 0);
        Grid.SetColumn(right, 1);
        body.Children.Add(left);
        body.Children.Add(right);
        root.Children.Add(body);

        var outer = new DockPanel();
        DockPanel.SetDock(_busy, Dock.Top);
        outer.Children.Add(_busy);
        outer.Children.Add(root);
        return outer;
    }

    private static Control Sep() => new Border
    {
        Width = 1,
        Height = 20,
        Margin = new Thickness(10, 0, 10, 0),
        Background = Brush.Parse("#2a3040"),
    };

    private Button MakeButton(string text, Action onClick, double leftMargin = 0, bool write = true)
    {
        var b = new Button
        {
            Content = text,
            Padding = new Thickness(12, 6, 12, 6),
            Margin = new Thickness(leftMargin, 0, 0, 0),
        };
        b.Click += (_, _) => onClick();
        return b;
    }

    // ─────────────────────────────────────────────────────── 后端连接

    private IControlService Svc => _svc
        ?? throw new InvalidOperationException("后端尚未连接");

    private string? _agentUrl;
    private string? _agentToken;

    private async Task ConnectAndRefreshAsync()
    {
        string[] args = Environment.GetCommandLineArgs();

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--agent" && i + 1 < args.Length) _agentUrl = args[++i];
            else if (args[i] == "--token" && i + 1 < args.Length) _agentToken = args[++i];
        }

        _busy.IsVisible = true;
        try
        {
            // 优先直连：零 HTTP 开销，延迟最低
            if (string.IsNullOrEmpty(_agentUrl) && DirectControlService.Probe())
            {
                _svc = new DirectControlService();
                _backendText.Text = "后端：直连管道（最快）";
            }
            else
            {
                string url = _agentUrl
                    ?? Environment.GetEnvironmentVariable("RVPNKIT_AGENT")
                    ?? "http://127.0.0.1:8770";
                string? token = _agentToken ?? Environment.GetEnvironmentVariable("RVPNKIT_TOKEN");

                if (!await HttpControlService.ProbeAsync(url, token))
                    throw new InvalidOperationException(
                        $"直连管道不可用，agent 也连不上（{url}）。\n" +
                        "请在本机运行 rvpnkit-agent，或用 --agent <地址> 指定。");

                _svc = new HttpControlService(url, token);
                _backendText.Text = $"后端：HTTP {url}";
            }

            await RefreshAsync(force: true);
        }
        catch (Exception ex)
        {
            SetStatus($"✗ {ex.Message}");
        }
        finally
        {
            _busy.IsVisible = false;
        }
    }

    // ─────────────────────────────────────────────────────── 数据

    private async Task RefreshAsync(bool force)
    {
        _busy.IsVisible = true;
        try
        {
            SnapshotState st = await Svc.GetStateAsync(force);
            _state = st;

            // 保持选中项
            string? keep = _selectedNetwork?.GuidHex;
            _networkList.ItemsSource = st.Networks;
            if (keep is not null)
            {
                var again = st.Networks.FirstOrDefault(n => n.GuidHex == keep);
                if (again is not null) _networkList.SelectedItem = again;
            }
            if (_networkList.SelectedItem is null && st.Networks.Count > 0)
                _networkList.SelectedIndex = 0;

            string self = st.Self is null
                ? "本机信息不可用"
                : $"{st.Self.Alias ?? "?"} · #{st.Self.NodeId} · {st.Self.PublicIp ?? "?"}";

            _statusText.Text = $"{self}    |    网络 {st.Networks.Count} · 成员 {st.MemberCount} · 节点 {st.Nodes.Count}"
                             + (Svc.CanWrite ? "" : "    |    只读");

            RenderMembers();
        }
        catch (Exception ex)
        {
            SetStatus($"✗ 刷新失败：{ex.Message}");
        }
        finally
        {
            _busy.IsVisible = false;
        }
    }

    private void RenderMembers()
    {
        NetworkInfo? n = _selectedNetwork;
        if (n is null)
        {
            _memberHeader.Text = "成员";
            _memberList.ItemsSource = null;
            return;
        }
        _memberHeader.Text = $"成员 · {n.Name}（{n.Members.Count}）";
        _memberList.ItemsSource = n.Members;
    }

    private async Task SearchPublicAsync()
    {
        _busy.IsVisible = true;
        try
        {
            IReadOnlyList<string> list = await Svc.GetPublicNetworksAsync(_publicBox.Text?.Trim());
            _publicList.ItemsSource = list;
            SetStatus($"公共网络 {list.Count} 个");
        }
        catch (Exception ex)
        {
            SetStatus($"✗ 搜索失败：{ex.Message}");
        }
        finally
        {
            _busy.IsVisible = false;
        }
    }

    // ─────────────────────────────────────────────────────── 操作

    private async Task ToggleNetworkAsync(bool enabled)
    {
        NetworkInfo? n = _selectedNetwork;
        if (n is null) { SetStatus("先选中一个网络"); return; }
        await Svc.SetEnabledAsync(n.GuidHex, enabled);
        SetStatus($"已请求{(enabled ? "启用" : "禁用")} {n.Name}");
        await RefreshAsync(force: true);
    }

    private async Task LeaveAsync(bool delete)
    {
        NetworkInfo? n = _selectedNetwork;
        if (n is null) { SetStatus("先选中一个网络"); return; }
        if (delete) await Svc.DeleteAsync(n.GuidHex);
        else await Svc.LeaveAsync(n.GuidHex);
        SetStatus($"已请求{(delete ? "删除" : "离开")} {n.Name}");
        await RefreshAsync(force: true);
    }

    private async Task MemberOpAsync(string op)
    {
        NetworkInfo? n = _selectedNetwork;
        if (n is null) { SetStatus("先选中一个网络"); return; }
        if (_memberList.SelectedItem is not MemberInfo m) { SetStatus("先选中一个成员"); return; }

        await Svc.MemberOpAsync(op, n.GuidHex, m.NodeId, n.Name);
        SetStatus($"已请求 {op} → {m.Label}");
    }

    // ─────────────────────────────────────────────────────── 工具

    /// <summary>只读连接时把写操作按钮灰掉，避免点了才报错。</summary>
    private void ApplyWritable(bool canWrite)
    {
        foreach (Button b in _writeButtons)
            b.IsEnabled = canWrite;
        _backendHint = canWrite ? "" : "   （只读：请用普通用户身份启动）";
        if (!canWrite) _backendText.Text += _backendHint;
    }

    private string _backendHint = "";

    private void SetStatus(string text) => _statusText.Text = text;

    private void RunAsync(Func<Task> work)
    {
        _ = RunAsync(work, null);
    }

    private async Task RunAsync(Func<Task> work, object? _)
    {
        try
        {
            await work();
        }
        catch (Exception ex)
        {
            SetStatus($"✗ {ex.Message}");
        }
    }
}
