namespace RvpnKit.Core;

/// <summary>一个 Radmin 网络。</summary>
/// <param name="Name">网络名。</param>
/// <param name="Guid">16 字节网络标识，删除/启停/离开等命令要用它。</param>
/// <param name="Token">快照字段 0x47 的字符串。<b>含义未确认</b>：13 个网络的取值完全相同，且其中多个是免密码加入的，所以它大概率不是密码，更像某种会话令牌。</param>
/// <param name="Members">该网络下的成员。</param>
public sealed record NetworkInfo(string Name, byte[] Guid, string? Token,
                                 IReadOnlyList<MemberInfo> Members,
                                 uint? NetworkType = null)
{
    /// <summary>GUID 的十六进制表示（无连字符），便于命令行/HTTP 传参。</summary>
    public string GuidHex => Convert.ToHexString(Guid).ToLowerInvariant();
}

/// <summary>网络成员。</summary>
/// <param name="NodeId">节点 ID，踢人/授管等命令要用它。</param>
/// <param name="Alias">对方别名，可能为空。</param>
/// <param name="PublicIp">对方的公网出口 IP（快照字段 0xc9）。</param>
public sealed record MemberInfo(ulong NodeId, string? Alias, string? PublicIp,
                                string? VirtualIp = null, string? VirtualIpv6 = null,
                                uint? ConnectionStatus = null, uint? ChannelType = null,
                                uint? LatencyMs = null)
{
    /// <summary>便于显示的标签。</summary>
    public string Label => Alias is { Length: > 0 } ? Alias
        : PublicIp is { Length: > 0 } ? PublicIp
        : $"#{NodeId}";

    public bool? Online => ConnectionStatus switch
    {
        0 => false,
        1 => true,
        _ => null,
    };

    public string ConnectionText => Online == false ? "未连接" : ChannelType switch
    {
        0 => "直连",
        1 => "中继",
        _ when Online == true => "已连接",
        _ => "连接未知",
    };
}

/// <summary>本机信息。</summary>
/// <param name="NodeId">本机节点 ID。</param>
/// <param name="Alias">本机别名。</param>
/// <param name="PublicIp">本机公网出口 IP。</param>
public sealed record SelfInfo(ulong NodeId, string? Alias, string? PublicIp,
                              string? VirtualIp = null, string? VirtualIpv6 = null);

/// <summary>从管道快照里解析出来的整体状态。</summary>
/// <param name="Self">本机信息。</param>
/// <param name="Networks">已加入的网络（含成员）。</param>
/// <param name="Nodes">快照里出现过的所有节点 ID。</param>
public sealed record SnapshotState(SelfInfo? Self, IReadOnlyList<NetworkInfo> Networks,
                                   IReadOnlyList<ulong> Nodes)
{
    /// <summary>所有网络的成员总数。</summary>
    public int MemberCount => Networks.Sum(n => n.Members.Count);
}

/// <summary>
/// 快照解析器。
///
/// <para>快照是「多帧拼接」：每帧 <c>[u32 LE 长度][正文]</c>，正文是记录流。
/// 先拆帧再逐帧递归展开。</para>
///
/// <para><b>关键结构（实测，注意网络与成员档案在<b>不同</b>帧里）：</b></para>
/// <code>
/// 网络     容器 field 0x23
///            field 0x09 (type 0x0d) 16 字节 GUID
///            field 0x06 名字    field 0x47 密码
///            field 0x24 容器 × N   ← 成员，每个含 field 0xe1 节点 ID
///
/// 成员档案 容器 field 0x22
///            field 0xe1 节点 ID / field 0x04 别名 / field 0xc9 公网 IP
///
/// 本机     容器 field 0x20 顶层的 field 0xe1 + 0x04 + 0xc9
/// </code>
/// <para>所以关联方式是：网络 → 子容器里的节点 ID（结构性，可靠）→ 再按节点 ID
/// 去合并成员档案。一开始我按「成员里的 GUID 字段」去关联，结果一个都对不上 ——
/// 那个字段不是网络 GUID。</para>
/// </summary>
public static class Snapshot
{
    private const byte FieldSelfAlias = 0x04;
    private const byte FieldNetworkName = 0x06;
    private const byte FieldNetworkGuid = 0x09;
    private const byte FieldContainerNetwork = 0x23;
    private const byte FieldContainerMember = 0x24;
    private const byte FieldContainerProfile = 0x22;
    private const byte FieldToken = 0x47;
    private const byte FieldPublicIp = 0xc9;
    private const byte FieldNodeId = 0xe1;

    /// <summary>解析快照。</summary>
    public static SnapshotState Parse(ReadOnlySpan<byte> raw)
    {
        var networkSeeds = new List<(string Name, byte[] Guid, string? Token, uint? NetworkType, List<ulong> MemberIds)>();
        var profiles = new Dictionary<ulong, (string? Alias, string? Ip, string? V4, string? V6, uint? Status, uint? Channel, uint? Latency)>();
        var nodes = new SortedSet<ulong>();
        SelfInfo? self = null;

        List<byte[]> frames = FrameReader.SplitFrames(raw);
        if (frames.Count == 0) frames = [raw.ToArray()];

        foreach (byte[] frame in frames)
            Walk(FrameReader.Parse(frame), networkSeeds, profiles, nodes, ref self, depth: 0);

        var networks = networkSeeds.Select(seed => new NetworkInfo(
            seed.Name, seed.Guid, seed.Token,
            seed.MemberIds.Select(id =>
            {
                profiles.TryGetValue(id, out var p);
                return new MemberInfo(id, p.Alias, p.Ip, p.V4, p.V6, p.Status, p.Channel, p.Latency);
            }).ToList(), seed.NetworkType)).ToList();

        return new SnapshotState(self, networks, nodes.ToList());
    }

    private static void Walk(List<Record> records,
                             List<(string, byte[], string?, uint?, List<ulong>)> networks,
                             Dictionary<ulong, (string?, string?, string?, string?, uint?, uint?, uint?)> profiles,
                             SortedSet<ulong> nodes,
                             ref SelfInfo? self,
                             int depth)
    {
        // 先把这一层里的标量字段聚起来（可能属于本机条目）
        ulong? localNode = null;
        string? localAlias = null;
        string? localIp = null;
        (string? V4, string? V6) localAddresses = Addresses(records);

        foreach (Record r in records)
        {
            if (r.Type == (byte)RecordType.String)
            {
                string? s = r.AsString();
                if (s is { Length: > 0 and <= 256 })
                {
                    if (r.Field == FieldSelfAlias) localAlias ??= s;
                    else if (r.Field == FieldPublicIp) localIp ??= s;
                }
            }
            if (r.Type == (byte)RecordType.NodeId && r.Field == FieldNodeId && r.Payload.Length == 8)
            {
                ulong id = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(r.Payload);
                if (id != 0) { localNode ??= id; nodes.Add(id); }
            }
        }

        if (depth <= 1 && localNode is not null && self is null)
            self = new SelfInfo(localNode.Value, localAlias, localIp, localAddresses.V4, localAddresses.V6);

        if (localNode is not null && depth >= 2 && localAlias is not null)
            profiles.TryAdd(localNode.Value, (localAlias, localIp, localAddresses.V4, localAddresses.V6,
                Scalar(records, 0x21), Scalar(records, 0x26), Scalar(records, 0x3e)));

        foreach (Record r in records)
        {
            if (r.Children is null) continue;

            if (r.Field == FieldContainerNetwork) { ParseNetwork(r.Children, networks, nodes); continue; }
            if (r.Field == FieldContainerProfile)
            {
                ParseProfile(r.Children, profiles, nodes);
                continue;
            }
            Walk([.. r.Children], networks, profiles, nodes, ref self, depth + 1);
        }
    }

    private static void ParseNetwork(IReadOnlyList<Record> children,
                             List<(string, byte[], string?, uint?, List<ulong>)> networks,
                                     SortedSet<ulong> nodes)
    {
        string? name = null;
        string? password = null;
        byte[]? guid = null;
        uint? networkType = null;
        var members = new List<ulong>();

        foreach (Record c in children)
        {
            if (c.Type == (byte)RecordType.Guid && c.Field == FieldNetworkGuid
                && c.Payload.Length == 16)
                guid = c.Payload;

            if (c.Type == (byte)RecordType.String)
            {
                string? s = c.AsString();
                if (s is { Length: > 0 })
                {
                    if (c.Field == FieldNetworkName) name ??= s;
                    else if (c.Field == FieldToken) password ??= s;
                }
            }

            if (c.Field == 0x0a && (c.Type == (byte)RecordType.UInt32 || c.Type == (byte)RecordType.UInt32Alt))
                networkType = c.AsUInt32();

            if (c.Field == FieldContainerMember && c.Children is not null)
            {
                foreach (Record m in c.Children)
                {
                    if (m.Type == (byte)RecordType.NodeId && m.Field == FieldNodeId
                        && m.Payload.Length == 8)
                    {
                        ulong id = System.Buffers.Binary.BinaryPrimitives
                            .ReadUInt64BigEndian(m.Payload);
                        if (id != 0) { members.Add(id); nodes.Add(id); }
                    }
                }
            }
        }

        if (guid is not null && name is not null)
            networks.Add((name, guid, password, networkType, members));
    }

    private static void ParseProfile(IReadOnlyList<Record> children,
                                     Dictionary<ulong, (string?, string?, string?, string?, uint?, uint?, uint?)> profiles,
                                     SortedSet<ulong> nodes)
    {
        ulong? node = null;
        string? alias = null;
        string? ip = null;

        foreach (Record c in children)
        {
            if (c.Type == (byte)RecordType.NodeId && c.Field == FieldNodeId && c.Payload.Length == 8)
            {
                ulong id = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(c.Payload);
                if (id != 0) { node ??= id; nodes.Add(id); }
            }
            if (c.Type == (byte)RecordType.String)
            {
                string? s = c.AsString();
                if (s is { Length: > 0 and <= 128 })
                {
                    if (c.Field == FieldSelfAlias) alias ??= s;
                    else if (c.Field == FieldPublicIp) ip ??= s;
                }
            }
        }

        if (node is not null)
        var addresses = Addresses(children);
        profiles.TryAdd(node.Value, (alias, ip, addresses.V4, addresses.V6,
            Scalar(children, 0x21), Scalar(children, 0x26), Scalar(children, 0x3e)));
    }

    private static uint? Scalar(IReadOnlyList<Record> records, byte field)
    {
        foreach (Record record in records)
            if (record.Field == field
                && (record.Type == (byte)RecordType.UInt32 || record.Type == (byte)RecordType.UInt32Alt)
                && record.Payload.Length >= 4)
                return record.AsUInt32();
        return null;
    }

    private static (string? V4, string? V6) Addresses(IReadOnlyList<Record> records)
    {
        string? v4 = null;
        string? v6 = null;
        foreach (Record record in records)
        {
            if (record.Field != 5) continue;
            if ((record.Type == (byte)RecordType.UInt32 || record.Type == (byte)RecordType.UInt32Alt)
                && record.Payload.Length >= 4)
            {
                Span<byte> bytes = stackalloc byte[4];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes, record.AsUInt32());
                v4 = new System.Net.IPAddress(bytes).ToString();
            }
            else if (record.Type == 9 && record.Payload.Length == 16)
            {
                v6 = new System.Net.IPAddress(record.Payload).ToString();
            }
        }
        return (v4, v6);
    }
}

/// <summary>从枚举响应里抽出所有网络名（含未加入的公共网络）。</summary>
public static class PublicNetworks
{
    /// <summary>
    /// 收集响应里所有字段 <c>0x06</c> 的字符串。
    ///
    /// <para>公共网络列表不在「网络容器（0x23）」里，所以
    /// <see cref="Snapshot.Parse"/> 看不到它们；但它们的名字同样带字段 0x06，
    /// 直接全量收集再减去已加入的即可。实测能拿到 299 个名字。</para>
    /// </summary>
    public static IReadOnlyList<string> ExtractNames(ReadOnlySpan<byte> raw)
    {
        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        List<byte[]> frames = FrameReader.SplitFrames(raw);
        if (frames.Count == 0) frames = [raw.ToArray()];

        foreach (byte[] frame in frames) Visit(FrameReader.Parse(frame), names, seen);
        return names;
    }

    private static void Visit(List<Record> records, List<string> names, HashSet<string> seen)
    {
        foreach (Record r in records)
        {
            if (r.Type == (byte)RecordType.String && r.Field == 0x06)
            {
                string? s = r.AsString();
                if (s is { Length: > 0 and <= 128 } && seen.Add(s)) names.Add(s);
            }
            if (r.Children is not null) Visit([.. r.Children], names, seen);
        }
    }
}
