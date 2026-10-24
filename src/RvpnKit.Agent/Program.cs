using System.Text.Json;
using RvpnKit.Agent;
using RvpnKit.Core;

// ── 参数解析（极简，不引第三方命令行库）
string host = "127.0.0.1";
int port = 8770;
bool noAuth = false;
string? token = Environment.GetEnvironmentVariable("RVPNKIT_TOKEN");

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--host" when i + 1 < args.Length: host = args[++i]; break;
        case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
        case "--no-auth": noAuth = true; break;
        case "--token" when i + 1 < args.Length: token = args[++i]; break;
        case "--help" or "-h":
            Console.WriteLine("""
                rvpnkit-agent —— Radmin VPN 控制面 HTTP API

                用法: rvpnkit-agent [选项]

                  --host <地址>    监听地址，默认 127.0.0.1
                  --port <端口>    监听端口，默认 8770
                  --token <令牌>   API 访问令牌（也可用环境变量 RVPNKIT_TOKEN）
                  --no-auth        关闭鉴权（仅建议本机调试用）

                接口:
                  GET  /health
                  GET  /api/state[?refresh=1]
                  GET  /api/public[?search=]
                  POST /api/power            {"on":true}
                  POST /api/alias            {"alias":"名字"}
                  POST /api/networks/join    {"name":"网络名"}
                  POST /api/networks/create  {"name":"网络名"}
                  POST /api/networks/{guid}/leave
                  POST /api/networks/{guid}/delete
                  POST /api/networks/{guid}/enabled  {"enabled":true}
                  POST /api/networks/{guid}/members/{nodeId}/kick|approve|grant|revoke
                """);
            return 0;
    }
}

// 没给令牌就随机生成一个并打印出来，避免裸奔在局域网
bool authOn = !noAuth;
string effectiveToken = token ?? Convert.ToHexString(
    System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

var builder = WebApplication.CreateBuilder();
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.UseUrls($"http://{host}:{port}");
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    o.SerializerOptions.DefaultIgnoreCondition =
        System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
});
builder.Services.AddSingleton<RvpnService>();
builder.Services.AddResponseCompression();

var app = builder.Build();
app.UseResponseCompression();

// ── 鉴权：请求头 X-Api-Token 或查询串 ?token=
app.Use(async (ctx, next) =>
{
    if (!authOn || ctx.Request.Path == "/health")
    {
        await next();
        return;
    }

    string? provided = ctx.Request.Headers["X-Api-Token"].FirstOrDefault()
                       ?? ctx.Request.Query["token"].FirstOrDefault();

    if (!string.Equals(provided, effectiveToken, StringComparison.Ordinal))
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await ctx.Response.WriteAsJsonAsync(new { error = "令牌无效或缺失" });
        return;
    }
    await next();
});

// ── 结果包装
static IResult Ok(object? data) => Results.Json(new { ok = true, data });

static IResult Fail(string message, int status = StatusCodes.Status400BadRequest)
    => Results.Json(new { ok = false, error = message }, statusCode: status);

// ── 健康检查
app.MapGet("/health", (RvpnService svc) => Ok(new
{
    version = "0.1.0",
    pipe = NamedPipeTransport.DefaultPipe,
    hint = authOn ? "需要 X-Api-Token 请求头" : "鉴权已关闭",
}));

// ── 状态
app.MapGet("/api/state", async (RvpnService svc, bool? refresh, CancellationToken ct) =>
{
    try
    {
        SnapshotState st = await svc.GetStateAsync(refresh == true, ct);
        return Ok(new
        {
            self = st.Self,
            networkCount = st.Networks.Count,
            memberCount = st.MemberCount,
            nodeCount = st.Nodes.Count,
            canWrite = !svc.LastReadOnly,
            networks = st.Networks.Select(n => new
            {
                name = n.Name,
                guid = n.GuidHex,
                token = n.Token,
                memberCount = n.Members.Count,
                members = n.Members.Select(m => new
                {
                    nodeId = m.NodeId,
                    alias = m.Alias,
                    publicIp = m.PublicIp,
                }),
            }),
        });
    }
    catch (Exception ex)
    {
        return Fail($"读取快照失败: {ex.Message}", StatusCodes.Status502BadGateway);
    }
});

// ── 公共网络
app.MapGet("/api/public", async (RvpnService svc, string? search, CancellationToken ct) =>
{
    try
    {
        IReadOnlyList<string> list = await svc.GetPublicAsync(search, ct);
        return Ok(new { count = list.Count, networks = list });
    }
    catch (Exception ex)
    {
        return Fail($"枚举公共网络失败: {ex.Message}", StatusCodes.Status502BadGateway);
    }
});

// ── 总开关
app.MapPost("/api/power", async (PowerRequest req, RvpnService svc, CancellationToken ct) =>
{
    try
    {
        uint rid = await svc.SendAsync(Commands.SwitchPower(req.On, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, power = req.On });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

// ── 改别名
app.MapPost("/api/alias", async (AliasRequest req, RvpnService svc, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(req.Alias)) return Fail("alias 不能为空");
    try
    {
        uint rid = await svc.SendAsync(Commands.ChangeAlias(req.Alias, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, alias = req.Alias });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

// ── 加入 / 创建
app.MapPost("/api/networks/join", async (NameRequest req, RvpnService svc, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(req.Name)) return Fail("name 不能为空");
    try
    {
        uint rid = await svc.SendAsync(Commands.JoinNetwork(req.Name, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, joined = req.Name });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

app.MapPost("/api/networks/create", async (NameRequest req, RvpnService svc, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(req.Name)) return Fail("name 不能为空");
    try
    {
        uint rid = await svc.SendAsync(Commands.CreateNetwork(req.Name, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, created = req.Name });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

// ── 离开 / 删除 / 启停
app.MapPost("/api/networks/{guid}/leave", async (string guid, RvpnService svc, CancellationToken ct) =>
{
    if (!TryGuid(guid, out byte[] g)) return Fail("guid 需要是 32 位十六进制");
    try
    {
        uint rid = await svc.SendAsync(Commands.LeaveNetwork(g, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, left = guid });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

app.MapPost("/api/networks/{guid}/delete", async (string guid, RvpnService svc, CancellationToken ct) =>
{
    if (!TryGuid(guid, out byte[] g)) return Fail("guid 需要是 32 位十六进制");
    try
    {
        uint rid = await svc.SendAsync(Commands.DeleteNetwork(g, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, deleted = guid });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

app.MapPost("/api/networks/{guid}/enabled",
    async (string guid, EnabledRequest req, RvpnService svc, CancellationToken ct) =>
{
    if (!TryGuid(guid, out byte[] g)) return Fail("guid 需要是 32 位十六进制");
    try
    {
        uint rid = await svc.SendAsync(
            Commands.SetNetworkEnabled(g, req.Enabled, RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, guid, enabled = req.Enabled });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

// ── 成员操作
app.MapPost("/api/networks/{guid}/members/{nodeId}/{op}",
    async (string guid, ulong nodeId, string op, RvpnService svc, string? name,
           CancellationToken ct) =>
{
    if (!TryGuid(guid, out byte[] g)) return Fail("guid 需要是 32 位十六进制");

    CommandCode? code = op.ToLowerInvariant() switch
    {
        "kick" or "remove" => CommandCode.KickNode,
        "approve" => CommandCode.ApproveJoin,
        "grant" or "grantadmin" => CommandCode.GrantAdmin,
        "revoke" or "revokeadmin" => CommandCode.RevokeAdmin,
        _ => null,
    };
    if (code is null) return Fail("op 支持 kick / approve / grant / revoke");

    try
    {
        uint rid = await svc.SendAsync(
            Commands.MemberOperation(code.Value, g, nodeId, name ?? "", RvpnService.NewRequestId()), ct);
        return Ok(new { requestId = rid, guid, nodeId, op });
    }
    catch (Exception ex) { return Fail(ex.Message, StatusCodes.Status409Conflict); }
});

// ── 根路径给个极简说明页
app.MapGet("/", (HttpContext ctx) => Results.Content("""
    <!doctype html><meta charset="utf-8">
    <title>rvpnkit-agent</title>
    <style>
      body{font:14px/1.6 ui-monospace,Consolas,monospace;background:#12151c;color:#c8d2e0;
           max-width:760px;margin:48px auto;padding:0 20px}
      h1{color:#7aa2f7;font-size:18px} code{background:#1d2230;padding:2px 6px;border-radius:4px}
      .m{color:#8b98ab} a{color:#9ece6a}
    </style>
    <h1>rvpnkit-agent</h1>
    <p class="m">Radmin VPN 控制面 HTTP API</p>
    <p><code>GET /api/state</code> 状态与成员　
       <code>GET /api/public</code> 公共网络</p>
    <p><code>POST /api/power</code> <code>POST /api/networks/join</code>
       <code>POST /api/networks/{guid}/enabled</code></p>
    <p class="m">鉴权：请求头 <code>X-Api-Token</code></p>
    """, "text/html; charset=utf-8"));

static bool TryGuid(string s, out byte[] guid)
{
    guid = [];
    string hex = s.Replace("-", "");
    if (hex.Length != 32) return false;
    try { guid = Convert.FromHexString(hex); return true; }
    catch (FormatException) { return false; }
}

app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine();
    Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  rvpnkit-agent  ·  Radmin VPN 控制面 API         ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
    Console.WriteLine();
    Console.WriteLine($"  监听      http://{host}:{port}");
    Console.WriteLine($"  管道      {NamedPipeTransport.DefaultPipe}");
    if (authOn && token is null)
    {
        Console.WriteLine($"  API 令牌  {effectiveToken}");
        Console.WriteLine("            （随机生成；用 X-Api-Token 请求头传递）");
    }
    else if (authOn)
    {
        Console.WriteLine("  API 令牌  已由参数/环境变量指定");
    }
    else
    {
        Console.WriteLine("  API 令牌  未启用（--no-auth，仅限本机调试）");
    }
    Console.WriteLine();
});

await app.RunAsync();
return 0;

// ── 请求体类型
internal sealed record PowerRequest(bool On);
internal sealed record AliasRequest(string Alias);
internal sealed record NameRequest(string Name);
internal sealed record EnabledRequest(bool Enabled);
