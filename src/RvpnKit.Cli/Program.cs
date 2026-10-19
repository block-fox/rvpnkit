using System.Buffers.Binary;
using System.Text;
using RvpnKit.Protocol;

namespace RvpnKit.Cli;

/// <summary>
/// 命令分发。当前阶段主要用于<b>验证协议解码器</b>：
/// 回放真实抓包，逐帧解码，报告结构统计与失败偏移。
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var cmd = args.Length > 0 ? args[0] : "help";

        return cmd switch
        {
            "verify" => Verify(args.Length > 1 ? args[1] : DefaultCapture),
            "tree" => Tree(args.Length > 1 ? args[1] : DefaultCapture,
                           args.Length > 2 ? int.Parse(args[2]) : 0),
            "fields" => FieldHistogram(args.Length > 1 ? args[1] : DefaultCapture),
            "detect" => Detect(args.Length > 1 ? args[1] : DefaultCapture),
            "harvest" => HarvestCmd(args.Length > 1 ? args[1] : DefaultCapture),
            "extract" => ExtractCmd(args.Length > 1 ? args[1] : DefaultCapture),
            "decode" => DecodeCmd(args.Length > 1 ? args[1] : DefaultCapture),
            "solve" => SolveCmd(args.Length > 1 ? args[1] : DefaultCapture),
            _ => Help(),
        };
    }

    /// <summary>穷举求解线格式语法：必须能完全解析每一帧才算通过。</summary>
    private static int SolveCmd(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var frames = RvpnWire.SplitFrames(data);
        Console.WriteLine($"文件 {path}  ({data.Length:N0} 字节)");
        Console.WriteLine($"帧数 {frames.Count}，正文合计 {frames.Sum(f => f.Length):N0} 字节");
        Console.WriteLine();

        var winners = GrammarSolver.Solve(frames, out string report);
        Console.WriteLine(report);

        if (winners.Count == 0)
        {
            Console.WriteLine("没有语法能完全解析所有帧。");
            Console.WriteLine("说明：容器/嵌套层仍未纳入语法，需要继续收敛。");
            return 2;
        }

        // 用第一个胜出语法统计字符串产出
        var g = winners[0];
        Console.WriteLine($"── 用首个胜出语法 {g} 重新解析 ──");
        int totalFields = 0, totalStrings = 0;
        var byFid = new Dictionary<ushort, List<string>>();

        foreach (var f in frames)
        {
            int i = g.HeaderSkip;
            while (i < f.Length && GrammarSolver.TryParseFrame(f, g, out _))
                break;
            _ = i;
        }

        _ = totalFields;
        _ = totalStrings;
        _ = byFid;
        return 0;
    }

    /// <summary>用已验证的线格式解析抓包，输出同步率与字段语义。</summary>
    private static int DecodeCmd(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var frames = RvpnWire.SplitFrames(data);
        Console.WriteLine($"文件 {path}  ({data.Length:N0} 字节)");
        Console.WriteLine($"帧数 {frames.Count:N0}，正文合计 {frames.Sum(f => f.Length):N0} 字节");
        Console.WriteLine();

        int totalRecs = 0, totalSkipped = 0, totalBytes = 0;
        var byField = new Dictionary<(ushort, byte), List<string>>();

        for (int fi = 0; fi < frames.Count; fi++)
        {
            var res = RvpnWire.Parse(frames[fi]);
            totalRecs += res.Records.Count;
            totalSkipped += res.Skipped;
            totalBytes += res.Total;
            if (fi < 5)
                Console.WriteLine($"  帧 #{fi + 1,-3} {frames[fi].Length,8:N0} 字节  " +
                                  $"记录 {res.Records.Count,-6:N0} 跳过 {res.Skipped,-8:N0} " +
                                  $"同步率 {res.Coverage:P1}");

            foreach (var r in res.Records)
            {
                var key = (r.FieldId, r.RawType);
                if (!byField.TryGetValue(key, out var list)) byField[key] = list = [];
                if (list.Count < 40)
                    list.Add(r.RawType switch
                    {
                        RvpnWire.Type.Str => $"\"{r.Str}\"",
                        _ when r.Bytes is { Length: 16 } bt =>
                            RvpnWire.TryBlobToIPv4(bt) is string ip ? $"IPv4 {ip}" : $"blob {Convert.ToHexString(bt)}",
                        _ => r.Num?.ToString() ?? "?",
                    });
            }
        }

        Console.WriteLine();
        Console.WriteLine($"═══ 汇总 ═══");
        Console.WriteLine($"  记录总数 : {totalRecs:N0}");
        Console.WriteLine($"  跳过字节 : {totalSkipped:N0} / {totalBytes:N0} " +
                          $"({(double)totalSkipped / Math.Max(1, totalBytes):P2})");
        Console.WriteLine($"  同步率   : {1.0 - (double)totalSkipped / Math.Max(1, totalBytes):P2}");

        Console.WriteLine();
        Console.WriteLine("── 字符串字段（fid 升序）──");
        foreach (var ((fid, t), vals) in byField
                     .Where(kv => kv.Key.Item2 == RvpnWire.Type.Str)
                     .OrderBy(kv => kv.Key.Item1))
        {
            var distinct = vals.Distinct().Take(6);
            Console.WriteLine($"  0x{fid:x4}  ×{vals.Count,-5}  {string.Join(" | ", distinct)}");
        }

        Console.WriteLine();
        Console.WriteLine("── 最具信息量的字段 Top 30 ──");
        foreach (var ((fid, t), vals) in byField.OrderByDescending(kv => kv.Value.Count).Take(30))
        {
            var distinct = vals.Distinct().Take(4);
            Console.WriteLine($"  0x{fid:x4} t=0x{t:x2} ×{vals.Count,-6} {string.Join(", ", distinct)}");
        }

        return 0;
    }

    /// <summary>锚点抽取：严格校验，用于拿真实业务数据并推断字段语义。</summary>
    private static int ExtractCmd(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var recs = AnchorExtractor.Extract(data);
        var (ip, url, conn, text) = AnchorExtractor.ClassifyCounts(recs);

        Console.WriteLine($"文件 {path}  ({data.Length:N0} 字节)");
        Console.WriteLine($"抽取结果：共 {recs.Count:N0} 条  " +
                          $"(IPv4 {ip}, URL {url}, 连接映射 {conn}, 其他文本 {text})");
        Console.WriteLine();
        Console.Write(AnchorExtractor.Summarize(recs));

        return 0;
    }

    /// <summary>内容驱动的抽取：不依赖结构对齐，直接拿到业务数据。</summary>
    private static int HarvestCmd(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var hits = ContentHarvester.Harvest(data);
        Console.WriteLine($"文件 {path}  ({data.Length:N0} 字节)");
        Console.WriteLine();
        Console.Write(ContentHarvester.Summarize(hits));

        return 0;
    }

    /// <summary>在真实抓包上枚举并给线格式假设打分，挑出自洽度最高的那组。</summary>
    private static int Detect(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var frames = AutoCalibrator.SplitFrames(data);
        Console.WriteLine($"抓包 {path}");
        Console.WriteLine($"共 {frames.Count} 帧，正文合计 {frames.Sum(f => f.Length):N0} 字节");
        Console.WriteLine();

        var ranked = AutoCalibrator.Rank(frames);

        Console.WriteLine("═══ 线格式布局定标（分值越高越自洽）═══");
        int rank = 0;
        foreach (var c in ranked.Take(10))
        {
            rank++;
            Console.WriteLine(
                $"  #{rank,-2} 分={c.Score,12:F1}  字符串={c.Strings,-6:N0} " +
                $"字段={c.Fields,-7:N0} 跳过={c.Skipped,-7:N0} 失步={c.Desyncs,-6:N0}  {c.Format}");
        }

        var best = ranked[0];
        Console.WriteLine();
        Console.WriteLine($"★ 最佳假设: {best.Format}");
        Console.WriteLine();

        // 用最佳假设跑一遍，看看抽出了什么
        var dec = new AdaptiveDecoder(best.Format);
        var allStrings = new List<(int Frame, ushort Fid, string Value)>();
        for (int fi = 0; fi < frames.Count; fi++)
        {
            var (fields, _) = dec.Decode(frames[fi]);
            foreach (var f in fields)
            {
                if (f.AsString is string s)
                    allStrings.Add((fi + 1, f.Id, s));
            }
        }

        Console.WriteLine($"── 抽到的字符串：{allStrings.Count:N0} 条 ──");
        var byFid = allStrings.GroupBy(x => x.Fid).OrderBy(g => g.Key);
        foreach (var g in byFid)
        {
            var samples = g.Select(x => x.Value).Distinct().Take(5);
            Console.WriteLine($"  字段 0x{g.Key:x4}  ×{g.Count(),-5} 例: {string.Join(" | ", samples)}");
        }

        Console.WriteLine();
        Console.WriteLine("── 全部字符串原文（前 80 条）──");
        foreach (var (frame, fid, val) in allStrings.Take(80))
            Console.WriteLine($"  帧{frame,-3} 0x{fid:x4}  {val}");

        return 0;
    }

    private const string DefaultCapture = @"D:\工作区\workspace1\recon\captures\snap.bin";

    private static int Help()
    {
        Console.WriteLine("""
            RvpnKit — Radmin VPN 第三方客户端工具箱

            用法:
              rvpn verify [抓包文件]    回放抓包，验证协议解码器并输出统计
              rvpn tree   [抓包文件] [帧号]  打印指定帧的结构树
              rvpn fields [抓包文件]    字段 ID 直方图 + 取值样本
            """);
        return 0;
    }

    /// <summary>回放抓包：逐帧解码，统计成功/失败。</summary>
    private static int Verify(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        Console.WriteLine($"抓包文件 : {path}");
        Console.WriteLine($"字节数   : {data.Length:N0}");
        Console.WriteLine();

        int offset = 0;
        int frameNo = 0;
        int okFrames = 0, badFrames = 0;
        long totalFields = 0;
        var failures = new List<string>();
        var fidHist = new Dictionary<(ushort, byte), int>();

        while (offset < data.Length)
        {
            if (offset + 4 > data.Length)
            {
                failures.Add($"偏移 0x{offset:x}: 剩余 {data.Length - offset} 字节不足以构成长度前缀");
                break;
            }

            int len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
            if (len <= 0 || offset + 4 + len > data.Length)
            {
                failures.Add($"偏移 0x{offset:x}: 帧长度 {len} 非法（剩余 {data.Length - offset - 4} 字节）");
                break;
            }

            frameNo++;
            var body = data.AsSpan(offset + 4, len);
            try
            {
                var frame = RvpnCodec.DecodeFrame(body);
                okFrames++;
                CountFields(frame, fidHist, ref totalFields);

                if (frameNo <= 6)
                {
                    Console.WriteLine($"帧 #{frameNo,-3} 偏移=0x{offset,-8:x} 长度={len,-8:N0} " +
                                      $"顶层字段={frame.Children.Count,-4} 总字段={totalFields:N0}");
                }
            }
            catch (RvpnProtocolException ex)
            {
                badFrames++;
                failures.Add($"帧 #{frameNo} @0x{offset:x} (长度 {len}): {ex.Message}");
                if (failures.Count > 20) break;
            }

            offset += 4 + len;
        }

        Console.WriteLine();
        Console.WriteLine($"═══ 结果 ═══");
        Console.WriteLine($"  帧总数   : {frameNo:N0}");
        Console.WriteLine($"  解码成功 : {okFrames:N0}");
        Console.WriteLine($"  解码失败 : {badFrames:N0}");
        Console.WriteLine($"  字段总数 : {totalFields:N0}");
        Console.WriteLine($"  覆盖字节 : {offset:N0} / {data.Length:N0} ({(double)offset / data.Length:P2})");

        if (failures.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("── 失败详情 ──");
            foreach (var f in failures.Take(20))
                Console.WriteLine("  " + f);
        }

        return badFrames == 0 ? 0 : 2;
    }

    private static void CountFields(RvpnField node, Dictionary<(ushort, byte), int> hist, ref long total)
    {
        foreach (var child in node.Children)
        {
            total++;
            var key = (child.Id, (byte)(child.RawType & 0x0F));
            hist[key] = hist.GetValueOrDefault(key) + 1;
            if (child.Children.Count > 0)
                CountFields(child, hist, ref total);
        }
    }

    /// <summary>打印指定帧（0 = 全部）的结构树。</summary>
    private static int Tree(string path, int whichFrame)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        int offset = 0, frameNo = 0;

        while (offset < data.Length)
        {
            if (offset + 4 > data.Length) break;
            int len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
            if (len <= 0 || offset + 4 + len > data.Length) break;

            frameNo++;
            if (whichFrame == 0 || frameNo == whichFrame)
            {
                Console.WriteLine($"══════ 帧 #{frameNo}  偏移=0x{offset:x}  长度={len:N0} ══════");
                var frame = RvpnCodec.DecodeFrame(data.AsSpan(offset + 4, len));
                foreach (var child in frame.Children)
                    Print(child, 0);
                Console.WriteLine();
            }

            offset += 4 + len;
            if (whichFrame != 0 && frameNo > whichFrame) break;
        }

        return 0;
    }

    private static void Print(RvpnField f, int depth)
    {
        var pad = new string(' ', depth * 2);
        var kind = (byte)(f.RawType & 0x0F);

        if (f.Children.Count > 0)
        {
            Console.WriteLine($"{pad}[0x{f.Id:x4}] 容器 ×{f.Children.Count}");
            foreach (var c in f.Children)
                Print(c, depth + 1);
            return;
        }

        string display = kind switch
        {
            (byte)RvpnType.String => $"\"{f.Value}\"",
            (byte)RvpnType.Blob16 => FormatBlob(f.AsBytes),
            (byte)RvpnType.U32 => $"{f.AsU32} (0x{f.AsU32 ?? 0:x8})",
            _ => f.Value?.ToString() ?? "null",
        };
        Console.WriteLine($"{pad}[0x{f.Id:x4}] t=0x{f.RawType:x2} {display}");
    }

    private static string FormatBlob(byte[]? b)
    {
        if (b is null) return "<null>";
        if (b.Length == 16)
        {
            // 前 12 字节全零 → 末 4 字节是 IPv4
            if (b.AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0)
                return $"IPv4 {b[12]}.{b[13]}.{b[14]}.{b[15]}  [{Convert.ToHexString(b)}]";

            var g = new Guid(b);
            return $"GUID {g}  [{Convert.ToHexString(b)}]";
        }
        return $"[{Convert.ToHexString(b)}]";
    }

    /// <summary>字段 ID 直方图与取值样本 —— 用于推断每个字段的语义。</summary>
    private static int FieldHistogram(string path)
    {
        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"找不到抓包文件: {path}");
            return 1;
        }

        var data = File.ReadAllBytes(path);
        var hist = new Dictionary<(ushort, byte), int>();
        var samples = new Dictionary<(ushort, byte), List<string>>();
        long total = 0;
        int strings = 0;

        int offset = 0, frameNo = 0;
        while (offset + 4 <= data.Length)
        {
            int len = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset));
            if (len <= 0 || offset + 4 + len > data.Length) break;
            frameNo++;
            try
            {
                var frame = RvpnCodec.DecodeFrame(data.AsSpan(offset + 4, len));
                Walk(frame, hist, samples, ref total, ref strings);
            }
            catch (RvpnProtocolException)
            {
                // 验证命令已经报告过，这里跳过
            }
            offset += 4 + len;
        }

        Console.WriteLine($"帧数 {frameNo:N0}，字段总数 {total:N0}，其中字符串 {strings:N0}");
        Console.WriteLine();
        Console.WriteLine("── 字符串字段（最有价值，直接可读）──");
        foreach (var ((id, t), count) in hist.Where(kv => kv.Key.Item2 == (byte)RvpnType.String)
                                              .OrderBy(kv => kv.Key.Item1))
        {
            var vals = samples[(id, t)].Distinct().Take(6).ToList();
            Console.WriteLine($"  0x{id:x4}  ×{count,-6} 例: {string.Join(" | ", vals)}");
        }

        Console.WriteLine();
        Console.WriteLine("── 按出现次数排序的全部字段 ──");
        foreach (var ((id, t), count) in hist.OrderByDescending(kv => kv.Value).Take(70))
        {
            var vals = samples[(id, t)].Distinct().Take(4).ToList();
            Console.WriteLine($"  0x{id:x4} t=0x{t:x2}  ×{count,-6} 例: {string.Join(", ", vals)}");
        }

        // 顺带把裸 IPv4 从整个抓包里挖出来（有些 IP 存在字符串字段里）
        var ipv4 = new System.Text.RegularExpressions.Regex(@"(?:\d{1,3}\.){3}\d{1,3}");
        Console.WriteLine();
        Console.WriteLine("── 抓包中出现的全部 IPv4 候选 ──");
        var found = new HashSet<string>();
        foreach (var ((id, t), _) in hist.Where(kv => kv.Key.Item2 == (byte)RvpnType.String))
        {
            foreach (var s in samples[(id, t)])
                foreach (System.Text.RegularExpressions.Match m in ipv4.Matches(s))
                {
                    if (found.Add(m.Value))
                        Console.WriteLine($"  {m.Value}   (字段 0x{id:x4})");
                }
        }

        return 0;
    }

    private static void Walk(RvpnField node, Dictionary<(ushort, byte), int> hist,
                             Dictionary<(ushort, byte), List<string>> samples,
                             ref long total, ref int strings)
    {
        foreach (var child in node.Children)
        {
            total++;
            var key = (child.Id, (byte)(child.RawType & 0x0F));
            hist[key] = hist.GetValueOrDefault(key) + 1;
            if (!samples.TryGetValue(key, out var list))
                samples[key] = list = [];
            if (list.Count < 40)
                list.Add(child.Value?.ToString() ?? "<null>");

            if (key.Item2 == (byte)RvpnType.String) strings++;
            if (child.Children.Count > 0) Walk(child, hist, samples, ref total, ref strings);
        }
    }
}
