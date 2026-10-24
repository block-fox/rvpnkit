namespace RvpnKit.Core;

/// <summary>
/// 发给 RvpnControlSvc 的命令码。
///
/// <para>数值来源：对官方 GUI 做 IAT hook 抓包得到真实报文，再用服务端日志
/// <c>[req:N] ...</c> 的行逐条核对语义；随后又用「命令码扫描 + 分组二分」
/// 补齐了抓包没覆盖到的几条。</para>
/// </summary>
public enum CommandCode : uint
{
    /// <summary>创建网络。<c>Requested to create network</c></summary>
    CreateNetwork = 0x02,

    /// <summary>加入网络。<c>Requested to join network</c></summary>
    JoinNetwork = 0x03,

    /// <summary>VPN 总开关。<c>Switched On/Off</c></summary>
    SwitchPower = 0x04,

    /// <summary>离开网络。<c>Requested to leave network</c></summary>
    LeaveNetwork = 0x05,

    /// <summary>踢出成员。<c>Requested to remove ... from network</c></summary>
    KickNode = 0x06,

    /// <summary>启用/禁用网络。<c>Enabled/Disabled network</c></summary>
    SetNetworkEnabled = 0x08,

    /// <summary>批准加入。<c>Requested to approve join</c></summary>
    ApproveJoin = 0x0a,

    /// <summary>删除网络。<c>Requested to delete network</c></summary>
    DeleteNetwork = 0x0f,

    /// <summary>授予管理员。<c>Requested to grant admin</c></summary>
    GrantAdmin = 0x10,

    /// <summary>撤销管理员。<c>Requested to revoke admin</c></summary>
    RevokeAdmin = 0x11,

    /// <summary>修改本机别名。<c>Requested to change alias</c></summary>
    ChangeAlias = 0x12,

    /// <summary>枚举公共网络。结果以管道响应返回，不写日志。</summary>
    EnumPublicNetworks = 0x13,
}

/// <summary>构造各类命令帧。返回的是「正文」，发送时要由传输层补 4 字节长度前缀。</summary>
public static class Commands
{
    private static FrameWriter Head(uint requestId, CommandCode code)
        => new FrameWriter()
            .U32(Field.RequestId, requestId)
            .U32(Field.Command, (uint)code);

    /// <summary>创建网络。</summary>
    /// <param name="name">网络名。</param>
    /// <param name="requestId">请求编号，会回显在服务端日志的 <c>[req:N]</c> 里。</param>
    /// <param name="key">28 字节网络密钥；为 null 时随机生成（实测任意值均可）。</param>
    public static byte[] CreateNetwork(string name, uint requestId, byte[]? key = null)
    {
        key ??= System.Security.Cryptography.RandomNumberGenerator.GetBytes(28);
        if (key.Length != 28) throw new ArgumentException("网络密钥必须是 28 字节", nameof(key));

        var inner = new FrameWriter()
            .U32Alt(Field.CreateFlag, 0)
            .Str(Field.NetworkName, name)
            .Blob(Field.NetworkKey, RecordType.UInt64, key)
            .ToArray();

        return Head(requestId, CommandCode.CreateNetwork)
            .Container(ContainerTag.Create, inner)
            .ToArray();
    }

    /// <summary>加入网络。</summary>
    public static byte[] JoinNetwork(string name, uint requestId)
    {
        var inner = new FrameWriter()
            .U32Alt(Field.JoinFlag, 1)
            .Str(Field.NetworkName, name)
            .ToArray();

        return Head(requestId, CommandCode.JoinNetwork)
            .Container(ContainerTag.Join, inner)
            .ToArray();
    }

    /// <summary>VPN 总开关。</summary>
    public static byte[] SwitchPower(bool on, uint requestId)
        => Head(requestId, CommandCode.SwitchPower)
            .U32Alt(Field.Power, on ? 1u : 0u)
            .ToArray();

    /// <summary>离开网络。</summary>
    public static byte[] LeaveNetwork(ReadOnlySpan<byte> networkGuid, uint requestId)
        => Head(requestId, CommandCode.LeaveNetwork)
            .Guid(Field.NetworkGuid, networkGuid)
            .ToArray();

    /// <summary>删除网络。</summary>
    public static byte[] DeleteNetwork(ReadOnlySpan<byte> networkGuid, uint requestId)
        => Head(requestId, CommandCode.DeleteNetwork)
            .Guid(Field.NetworkGuid, networkGuid)
            .ToArray();

    /// <summary>启用/禁用网络。</summary>
    public static byte[] SetNetworkEnabled(ReadOnlySpan<byte> networkGuid, bool enabled, uint requestId)
        => Head(requestId, CommandCode.SetNetworkEnabled)
            .Guid(Field.NetworkGuid, networkGuid)
            .U32Alt(Field.Enabled, enabled ? 1u : 0u)
            .ToArray();

    /// <summary>修改别名。</summary>
    public static byte[] ChangeAlias(string alias, uint requestId)
        => Head(requestId, CommandCode.ChangeAlias)
            .Str(Field.Alias, alias)
            .ToArray();

    /// <summary>枚举公共网络；<paramref name="prefix"/> 作过滤前缀，空串表示全部。</summary>
    public static byte[] EnumPublicNetworks(string prefix, uint requestId)
        => Head(requestId, CommandCode.EnumPublicNetworks)
            .Str(Field.NetworkName, prefix)
            .ToArray();

    /// <summary>
    /// 成员类操作：踢人 / 批准加入 / 授予管理员 / 撤销管理员。
    /// 四者载荷形状相同：网络 GUID + 节点 ID + 网络名。
    /// </summary>
    public static byte[] MemberOperation(CommandCode code, ReadOnlySpan<byte> networkGuid,
                                         ulong nodeId, string networkName, uint requestId)
    {
        if (code is not (CommandCode.KickNode or CommandCode.ApproveJoin
                         or CommandCode.GrantAdmin or CommandCode.RevokeAdmin))
            throw new ArgumentException($"不支持的成员操作: {code}", nameof(code));

        return Head(requestId, code)
            .Guid(Field.NetworkGuid, networkGuid)
            .NodeId(nodeId)
            .Str(Field.NetworkName, networkName)
            .ToArray();
    }
}
