using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace RvpnKit.Client;

/// <summary>
/// 读取 Radmin VPN 虚拟网卡上的<b>对端邻居表</b>。
///
/// <para>实现说明：本类最初尝试直接 P/Invoke <c>GetIpNetTable2</c>，但
/// <c>MIB_IPNET_ROW2</c> 含有内嵌 <c>SOCKADDR_INET</c>，手工推算的结构体布局
/// 始终得不到数据（返回 0 条）。改用 <c>arp -a</c> 的文本输出解析后稳定可用，
/// 因此这里选择<b>可靠性优先</b>：解析系统自带工具的输出，而不是继续猜结构体布局。</para>
///
/// <para>这条路径的价值在于：邻居表由网卡驱动维护，是<b>数据面的事实来源</b>，
/// 不受控制管道格式变化影响。</para>
/// </summary>
public static class PeerTable
{
    /// <summary>对端的可达状态（由 arp 输出的类型字段推断）。</summary>
    public enum NeighborState
    {
        /// <summary>动态条目（曾有通信）</summary>
        Dynamic,
        /// <summary>静态条目</summary>
        Static,
        /// <summary>无效条目</summary>
        Invalid,
    }

    /// <summary>一个对端。</summary>
    public sealed class Peer
    {
        /// <summary>虚拟 IP</summary>
        public required IPAddress Address { get; init; }

        /// <summary>链路层地址（MAC）</summary>
        public string Mac { get; init; } = "—";

        /// <summary>条目类型</summary>
        public NeighborState State { get; init; }

        /// <summary>MAC 是否为有效单播地址（全零表示未解析出对端）</summary>
        public bool HasValidMac =>
            Mac is not ("—" or "")
            && !Mac.StartsWith("00-00-00", StringComparison.Ordinal)
            && !Mac.Equals("FF-FF-FF-FF-FF-FF", StringComparison.OrdinalIgnoreCase);

        /// <summary>状态的中文描述</summary>
        public string StateText => HasValidMac
            ? State switch
            {
                NeighborState.Dynamic => "曾有通信",
                NeighborState.Static => "静态条目",
                _ => "未知",
            }
            : "未解析（可能离线）";

        /// <inheritdoc/>
        public override string ToString() => $"{Address,-16} {Mac,-18} {StateText}";
    }

    /// <summary>Radmin 使用的虚拟网段首字节。</summary>
    private const byte RadminFirstOctet = 26;

    private static readonly Regex InterfaceRe = new(
        @"^\s*(?:Interface|接口)\s*[:：]\s*(?<ip>\d+\.\d+\.\d+\.\d+)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex RowRe = new(
        @"^\s*(?<ip>\d+\.\d+\.\d+\.\d+)\s+(?<mac>[0-9a-fA-F-]{17})\s+(?<type>\S+)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    /// <summary>
    /// 读取邻居表。<paramref name="localVirtualIp"/> 用于只保留目标网段的条目。
    /// </summary>
    public static List<Peer> Read(IPAddress? localVirtualIp = null)
    {
        localVirtualIp ??= LocalVirtualAddress();

        string output;
        try
        {
            var psi = new ProcessStartInfo("arp.exe", "-a")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.Default,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return [];
            output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
        }
        catch (Exception)
        {
            return [];
        }

        // 只取 Radmin 网卡那一段（其接口地址就是我们自己的虚拟 IP）
        string section = output;
        if (localVirtualIp is not null)
        {
            string marker = localVirtualIp.ToString();
            int idx = output.IndexOf(marker, StringComparison.Ordinal);
            if (idx >= 0)
            {
                int end = output.IndexOf("Interface", idx + marker.Length, StringComparison.OrdinalIgnoreCase);
                if (end < 0) end = output.IndexOf("接口", idx + marker.Length, StringComparison.Ordinal);
                section = end > idx ? output[idx..end] : output[idx..];
            }
        }

        var peers = new List<Peer>();
        var seen = new HashSet<string>();

        foreach (Match m in RowRe.Matches(section))
        {
            string ipText = m.Groups["ip"].Value;
            if (!IPAddress.TryParse(ipText, out var ip)) continue;
            if (ip.GetAddressBytes()[0] != RadminFirstOctet) continue;
            if (localVirtualIp is not null && ip.Equals(localVirtualIp)) continue;
            if (!seen.Add(ipText)) continue;

            string type = m.Groups["type"].Value;
            var state = type.StartsWith("static", StringComparison.OrdinalIgnoreCase)
                        || type.StartsWith("静态", StringComparison.Ordinal)
                ? NeighborState.Static
                : NeighborState.Dynamic;

            peers.Add(new Peer
            {
                Address = ip,
                Mac = m.Groups["mac"].Value.ToUpperInvariant(),
                State = state,
            });
        }

        return peers;
    }

    /// <summary>获取本机在 Radmin 网段上的虚拟 IP。</summary>
    public static IPAddress? LocalVirtualAddress()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            bool isRadmin =
                ni.Description.Contains("Radmin VPN", StringComparison.OrdinalIgnoreCase) ||
                ni.Name.Contains("Radmin VPN", StringComparison.OrdinalIgnoreCase);
            if (!isRadmin) continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                    ua.Address.GetAddressBytes()[0] == RadminFirstOctet)
                    return ua.Address;
            }
        }
        return null;
    }

    /// <summary>Radmin 虚拟网卡是否处于启用状态。</summary>
    public static bool IsAdapterUp()
    {
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            bool isRadmin =
                ni.Description.Contains("Radmin VPN", StringComparison.OrdinalIgnoreCase) ||
                ni.Name.Contains("Radmin VPN", StringComparison.OrdinalIgnoreCase);
            if (isRadmin)
                return ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up;
        }
        return false;
    }
}
