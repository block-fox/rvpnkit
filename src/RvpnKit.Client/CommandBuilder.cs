using System.Buffers.Binary;
using System.Text;

namespace RvpnKit.Client;

/// <summary>
/// 构造发给 RvpnControlSvc 的命令帧。
///
/// <para>帧格式是通过 IAT hook 截获官方 GUI 的真实报文逆向出来的，
/// 并用服务端日志 <c>[req:N] Requested to join network '...'</c> 验证过。</para>
///
/// <para>一条命令帧由若干「记录」拼成。每条记录的通用形状是：</para>
/// <code>
/// [size:u32 BE] [flags:u16 BE] [type:u8] [field:u8] [payload]
/// </code>
/// <para>其中 <c>size</c> 是 payload 的字节数；<c>flags</c> 目前观察到的常量是
/// <c>0x0001</c>；<c>type</c> 决定 payload 的解释方式（3 = 字符串，0x0b = u8，
/// 0x08 = u64，0x02 ≈ guid/字节块）。</para>
///
/// <para>「加入网络」命令的整体结构（实测 102 字节，网络名 24 个字符时）：</para>
/// <code>
/// 记录1  size=4   type=0x03 field=0x4a  payload=reqId(u32 BE)
/// 记录2  size=4   type=0x03 field=0x00  payload=命令码(u32 BE)   // 3 = 加入
/// 容器   size=N   type=0x13 field=0x1b  payload=下面的内容
///   记录3 size=4  type=0x0b field=0x3f  payload=1(u8)
///   记录4 size=M  type=0x03 field=0x06  payload=00 + 网络名(UTF-16LE) + 01
/// </code>
///
/// <para>长度关系（nameBytes = 网络名的 UTF-16LE 字节数）：</para>
/// <list type="bullet">
///   <item>记录4 的 size = nameBytes + 2</item>
///   <item>容器的 size   = 12 + (nameBytes + 10)</item>
///   <item>整帧 body     = nameBytes + 54</item>
/// </list>
/// </summary>
public static class CommandBuilder
{
    /// <summary>命令码：加入网络（实测确认）。</summary>
    public const uint CmdJoinNetwork = 3;

    /// <summary>容器记录里的固定类型标记。</summary>
    private const uint ContainerTag = 0x0000131b;

    /// <summary>
    /// 构造「加入网络」命令帧的正文（不含最外层的 4 字节长度前缀，
    /// 那一层由 <see cref="RvpnPipe.SendAsync"/> 负责）。
    /// </summary>
    /// <param name="networkName">网络名，任意 Unicode。</param>
    /// <param name="requestId">请求编号；服务端日志里显示为 <c>[req:N]</c>。</param>
    public static byte[] JoinNetwork(string networkName, uint requestId)
    {
        ArgumentException.ThrowIfNullOrEmpty(networkName);

        byte[] nameBytes = Encoding.Unicode.GetBytes(networkName);

        // 记录4：字符串记录。payload = 00 + 名字 + 01
        int strPayload = nameBytes.Length + 2;
        int strRecord = 4 + 4 + strPayload;          // size + flags/type/field + payload

        // 容器 payload = 记录3(12) + 记录4
        int containerPayload = 12 + strRecord;

        int bodyLen = 12 + 12 + 8 + containerPayload;
        var buf = new byte[bodyLen];
        var w = new SpanWriter(buf);

        // 记录1：请求 ID
        w.RecordU32(0x4a, requestId);

        // 记录2：命令码
        w.RecordU32(0x00, CmdJoinNetwork);

        // 容器头：size + 固定 tag
        w.U32Be((uint)containerPayload);
        w.U32Be(ContainerTag);

        // 记录3：u32 字段 = 1（类型码 0x0b）
        w.RecordHeader(4, 0x0b, 0x3f);
        w.U32Be(0x01);

        // 记录4：字符串
        w.RecordHeader((uint)strPayload, 0x03, 0x06);
        w.U8(0x00);            // 前缀
        w.Bytes(nameBytes);
        w.U8(0x01);            // 后缀

        return buf;
    }

    /// <summary>
    /// 把一段正文按十六进制打印出来，便于和抓包结果逐字节比对。
    /// </summary>
    public static string ToHexDump(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append("  ").Append(i.ToString("x4")).Append("  ");
            for (int j = i; j < Math.Min(i + 16, data.Length); j++)
                sb.Append(data[j].ToString("x2")).Append(' ');
            sb.AppendLine();
        }
        return sb.ToString();
    }

    /// <summary>大端写入的小工具，避免每处都手写 BinaryPrimitives。</summary>
    private ref struct SpanWriter(Span<byte> target)
    {
        private readonly Span<byte> _buf = target;
        private int _pos = 0;

        public void U8(byte v) => _buf[_pos++] = v;

        public void U32Be(uint v)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_buf[_pos..], v);
            _pos += 4;
        }

        public void Bytes(ReadOnlySpan<byte> v)
        {
            v.CopyTo(_buf[_pos..]);
            _pos += v.Length;
        }

        /// <summary>
        /// 写 8 字节记录头：<c>[size:u32 BE][类型码:u8][00][03][字段:u8]</c>。
        ///
        /// <para>注意第 3、4 字节固定是 <c>00 03</c>，第 5 字节才是字段号。
        /// 早期版本把类型码写成 16 位大端，得到 <c>00 01</c>，与真实报文的
        /// <c>01 00</c> 不符 —— 逐字节比对抓包时才发现的。</para>
        /// </summary>
        public void RecordHeader(uint size, byte typeCode, byte field)
        {
            U32Be(size);
            U8(typeCode);
            U8(0x00);
            U8(0x03);
            U8(field);
        }

        /// <summary>写一条 u32 值记录（类型码 0x01）。</summary>
        public void RecordU32(byte field, uint value)
        {
            RecordHeader(4, 0x01, field);
            U32Be(value);
        }
    }
}
