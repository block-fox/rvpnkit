namespace RvpnKit.Core;

/// <summary>一个 Radmin 网络。</summary>
/// <param name="Name">网络名。</param>
/// <param name="Guid">16 字节网络标识，删除/启停/离开等命令要用它。</param>
/// <param name="Members">该网络下的成员。</param>
public sealed record NetworkInfo(string Name, byte[] Guid, IReadOnlyList<MemberInfo> Members)
{
    /// <summary>GUID 的十六进制表示（无连字符），便于命令行长传参。</summary>
    public string GuidHex => Convert.ToHexString(Guid).ToLowerInvariant();
}

/// <summary>网络成员。</summary>
/// <param name="NodeId">节点 ID，踢人/授管等命令要用它。</param>
/// <param name="Alias">对方别名（可能为空）。</param>
/// <param name="VirtualIp">虚拟 IP（来自网卡邻居表，可能为空）。</param>
public sealed record MemberInfo(ulong NodeId, string? Alias, string? VirtualIp);

/// <summary>从管道快照里解析出来的整体状态。</summary>
/// <param name="Networks">已加入的网络。</param>
/// <param name="Nodes">快照里出现过的所有节点 ID。</param>
public sealed record SnapshotState(IReadOnlyList<NetworkInfo> Networks, IReadOnlyList<ulong> Nodes);

/// <summary>
/// 快照解析器。
///
/// <para>快照是一串「多帧拼接」的数据：每帧 <c>[u32 LE 长度][正文]</c>，
/// 正文里是之前那种记录流。先拆帧再逐帧展开。</para>
///
/// <para>识别规则：</para>
/// <list type="bullet">
///   <item>网络 = 同一个容器里既有 16 字节 GUID（字段 <c>0x09</c>）又有名字（字段 <c>0x06</c>）</item>
///   <item>节点 = 形如 <c>00 00 00 08 02 00 01 e1 &lt;u64&gt;</c> 的记录</item>
/// </list>
/// </summary>
public static class Snapshot
{
    /// <summary>解析快照。</summary>
    public static SnapshotState Parse(ReadOnlySpan<byte> raw)
    {
        var networks = new List<NetworkInfo>();
        var nodes = new SortedSet<ulong>();
        var seenGuid = new HashSet<string>(StringComparer.Ordinal);

        List<byte[]> frames = FrameReader.SplitFrames(raw);
        if (frames.Count == 0)
            frames = [raw.ToArray()];

        foreach (byte[] frame in frames)
            Walk(FrameReader.Parse(frame), networks, nodes, seenGuid, parent: null);

        return new SnapshotState(networks, nodes.ToList());
    }

    private static void Walk(List<Record> records, List<NetworkInfo> networks,
                             SortedSet<ulong> nodes, HashSet<string> seenGuid,
                             string? parent)
    {
        byte[]? guid = null;
        string? name = null;

        foreach (Record r in records)
        {
            if (r.Type == (byte)RecordType.Guid && r.Payload.Length == 16)
                guid ??= r.Payload;

            if (r.Type == (byte)RecordType.String)
            {
                string? s = r.AsString();
                if (s is { Length: > 0 } && name is null && Guid.TryParseLike(s))
                    name = s;
            }

            // 节点记录：size=8  type=0x02  pad=0x00  tag=0x01  field=0xe1，载荷是 8 字节 u64。
            // 注意它的 tag 字节是 0x01 而不是普通记录的 0x03，容易看漏。
            if (r.Type == (byte)RecordType.NodeId && r.Field == Field.NodeId
                && r.Payload.Length == 8)
            {
                ulong id = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(r.Payload);
                if (id != 0) nodes.Add(id);
            }

            if (r.Children is not null)
                Walk([.. r.Children], networks, nodes, seenGuid, parent);
        }

        if (guid is not null && name is not null)
        {
            string hex = Convert.ToHexString(guid).ToLowerInvariant();
            if (seenGuid.Add(hex))
                networks.Add(new NetworkInfo(name, guid, []));
        }
    }
}

internal static class Guid
{
    /// <summary>名字的合理性检查：非空、可打印、长度合理。</summary>
    internal static bool TryParseLike(string s) => s.Length is > 0 and <= 128;
}
