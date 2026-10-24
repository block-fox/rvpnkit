using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Themes.Fluent;

namespace RvpnKit.App;

/// <summary>
/// Avalonia 应用入口。
///
/// <para>界面全部用 C# 代码构建（不用 XAML），这样没有 XAML 编译器这一环，
/// 构建失败面最小，也方便后面按需拼装。</para>
/// </summary>
public sealed class RvpnApp : Application
{
    /// <inheritdoc />
    public override void Initialize()
    {
        Styles.Add(new FluentTheme());
        RequestedThemeVariant = Avalonia.Styling.ThemeVariant.Dark;
    }

    /// <inheritdoc />
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.MainWindow = new MainWindow();

        base.OnFrameworkInitializationCompleted();
    }
}

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
        => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<RvpnApp>()
                     .UsePlatformDetect()
                     .With(new Win32PlatformOptions
                     {
                         // 保持默认渲染后端，避免某些机器上 GPU 初始化失败
                     })
                     .LogToTrace();
}
