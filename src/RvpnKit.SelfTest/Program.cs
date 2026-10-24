using System.Text;
using RvpnKit.Core;

// 协议内核自检：拿抓包得到的真实字节逐字节比对，确保 Core 的编码与线上一致。
// 这些期望值全部来自 docs/PROTOCOL_COMMANDS.md 里记录的实际报文。

int pass = 0, fail = 0;

void Check(string name, byte[] actual, string expectedHex)
{
    byte[] expected = Convert.FromHexString(expectedHex.Replace(" ", ""));
    bool ok = actual.AsSpan().SequenceEqual(expected);
    string status = ok ? "✓" : "✗";
    Console.WriteLine($"  {status} {name,-34} 实际 {actual.Length,4} 字节 / 期望 {expected.Length,4} 字节");

    if (!ok)
    {
        fail++;
        // 定位第一处差异，便于排查
        int n = Math.Min(actual.Length, expected.Length);
        for (int i = 0; i < n; i++)
        {
            if (actual[i] != expected[i])
            {
                Console.WriteLine($"      首个差异 @{i}: 实际 0x{actual[i]:x2} / 期望 0x{expected[i]:x2}");
                break;
            }
        }
        Console.WriteLine($"      实际: {Convert.ToHexString(actual).ToLowerInvariant()}");
        Console.WriteLine($"      期望: {Convert.ToHexString(expected).ToLowerInvariant()}");
    }
    else pass++;
}

Console.WriteLine("═══ RvpnKit.Core 协议内核自检 ═══");
Console.WriteLine();

// ── 1. 加入网络：reqId=0x17，名字 "Minecraft [Português 10]"，实测 102 字节
byte[] join = Commands.JoinNetwork("Minecraft [Português 10]", 0x17);
Check("加入网络 join", join,
    "000000040100034a00000017" +
    "000000040100030000000003" +
    "000000460000131b" +
    "000000040b00033f00000001" +
    "0000003203000306" +
    "004d0069006e0065006300720061006600740020005b0050006f00720074007500670075" +
    "00ea007300200031003000 5d 0001".Replace(" ", ""));

// ── 2. 改别名：reqId=0x1a，别名 "快乐狐狸1"，实测 44 字节
byte[] alias = Commands.ChangeAlias("快乐狐狸1", 0x1a);
Check("改别名 alias", alias,
    "000000040100034a0000001a" +
    "000000040100030000000012" +
    "0000000c03000304" +
    "5feb4e5072d072f800310001");

// ── 3. VPN 总开关：reqId=0x2f，关闭，实测 36 字节
byte[] powerOff = Commands.SwitchPower(false, 0x2f);
Check("总开关 power off", powerOff,
    "000000040100034a0000002f" +
    "000000040100030000000004" +
    "000000040b00031100000000");

// ── 4. 总开关开启
byte[] powerOn = Commands.SwitchPower(true, 0x30);
Check("总开关 power on", powerOn,
    "000000040100034a00000030" +
    "000000040100030000000004" +
    "000000040b00031100000001");

// ── 5. 启用网络：GUID + 字段 0x16=1，实测 60 字节
byte[] guid = Convert.FromHexString("89c588a86f14437aab52fd112f18efba");
byte[] enable = Commands.SetNetworkEnabled(guid, true, 0x30);
Check("启用网络 enable", enable,
    "000000040100034a00000030" +
    "000000040100030000000008" +
    "000000100d00030989c588a86f14437aab52fd112f18efba" +
    "000000040b00031600000001");

// ── 6. 删除网络：实测 48 字节
byte[] del = Commands.DeleteNetwork(guid, 0x33);
Check("删除网络 delete", del,
    "000000040100034a00000033" +
    "00000004010003000000000f" +
    "000000100d00030989c588a86f14437aab52fd112f18efba");

// ── 7. 解析器回读：把 join 帧拆开，验证字段与名字都对
Console.WriteLine();
var recs = FrameReader.Parse(join);
Console.WriteLine($"  解析 join 得到 {recs.Count} 条顶层记录:");
foreach (var r in recs)
    Console.WriteLine($"    field=0x{r.Field:x2} type=0x{r.Type:x2} size={r.Payload.Length}" +
                      (r.Children is null ? "" : $" 容器，含 {r.Children.Count} 条子记录"));

uint rid = FrameReader.RequestId(join);
bool ridOk = rid == 0x17;
Console.WriteLine($"  {(ridOk ? "✓" : "✗")} 请求编号 = 0x{rid:x} （期望 0x17）");
if (ridOk) pass++; else fail++;

// 从容器里把网络名读回来
string? parsedName = null;
foreach (var r in recs)
    if (r.Children is not null)
        foreach (var c in r.Children)
            if (c.Field == Field.NetworkName)
                parsedName = c.AsString();
bool nameOk = parsedName == "Minecraft [Português 10]";
Console.WriteLine($"  {(nameOk ? "✓" : "✗")} 网络名 = \"{parsedName}\"");
if (nameOk) pass++; else fail++;

// ── 8. 字符串编解码往返（含非 ASCII）
Console.WriteLine();
foreach (string s in new[] { "abc", "快乐狐狸", "Minecraft [Português 10]", "a" })
{
    byte[] enc = Wire.EncodeString(s);
    string? dec = Wire.DecodeString(enc);
    bool ok = dec == s;
    Console.WriteLine($"  {(ok ? "✓" : "✗")} 往返 \"{s}\" → {Convert.ToHexString(enc)} → \"{dec}\"");
    if (ok) pass++; else fail++;
}

Console.WriteLine();
Console.WriteLine($"═══ 通过 {pass} / 失败 {fail} ═══");

// ── 9. 活体快照解析（可选：--live）
if (args.Contains("--live"))
{
    Console.WriteLine();
    Console.WriteLine("═══ 活体快照解析 ═══");
    try
    {
        await using var tp = NamedPipeTransport.Connect();
        Console.WriteLine($"  传输: {tp.Describe}");
        byte[] raw = await tp.ReadSnapshotAsync(TimeSpan.FromSeconds(4));
        Console.WriteLine($"  收到 {raw.Length:N0} 字节，{FrameReader.SplitFrames(raw).Count} 帧");

        var st = Snapshot.Parse(raw);
        Console.WriteLine($"  解析出网络 {st.Networks.Count} 个，节点 {st.Nodes.Count} 个");
        foreach (var n in st.Networks.Take(5))
            Console.WriteLine($"    {n.Name,-34} {n.GuidHex}");
        if (st.Networks.Count > 0) pass++; else fail++;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  ✗ {ex.GetType().Name}: {ex.Message}");
        fail++;
    }
    Console.WriteLine();
    Console.WriteLine($"═══ 总计 通过 {pass} / 失败 {fail} ═══");
}

return fail == 0 ? 0 : 1;
