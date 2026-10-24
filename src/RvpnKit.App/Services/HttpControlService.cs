namespace RvpnKit.App.Services;

using System.Net.Http.Json;
using System.Text.Json;
using RvpnKit.Core;

/// <summary>
/// 走 <c>rvpnkit-agent</c> 的 REST 后端。
///
/// <para>用于两种情况：非 Windows 平台（没有命名管道），或管理远处的 Windows 主机。
/// 协议细节全在 agent 里，这里只做 HTTP 转译。</para>
/// </summary>
public sealed class HttpControlService : IControlService
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    /// <inheritdoc />
    public string Name => $"HTTP（{_baseUrl}）";

    /// <inheritdoc />
    public bool CanWrite { get; private set; } = true;

    /// <summary>构造。</summary>
    /// <param name="baseUrl">例如 <c>http://127.0.0.1:8770</c>。</param>
    /// <param name="token">API 令牌，可为空（agent 用 --no-auth 时）。</param>
    public HttpControlService(string baseUrl, string? token)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { BaseAddress = new Uri(_baseUrl), Timeout = TimeSpan.FromSeconds(60) };
        if (!string.IsNullOrWhiteSpace(token))
            _http.DefaultRequestHeaders.Add("X-Api-Token", token);
    }

    /// <summary>探测某个 agent 是否可达。</summary>
    public static async Task<bool> ProbeAsync(string baseUrl, string? token, CancellationToken ct = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            if (!string.IsNullOrWhiteSpace(token))
                http.DefaultRequestHeaders.Add("X-Api-Token", token);
            var resp = await http.GetAsync($"{baseUrl.TrimEnd('/')}/health", ct);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private async Task<T> GetAsync<T>(string path, CancellationToken ct)
    {
        using HttpResponseMessage resp = await _http.GetAsync(path, ct);
        await EnsureOkAsync(resp);
        Envelope<T>? env = await resp.Content.ReadFromJsonAsync<Envelope<T>>(Json, ct);
        if (env is null || env.Data is null)
            throw new InvalidOperationException("agent 返回了空数据");
        return env.Data;
    }

    private async Task PostAsync(string path, object? body, CancellationToken ct)
    {
        using HttpResponseMessage resp = body is null
            ? await _http.PostAsync(path, null, ct)
            : await _http.PostAsJsonAsync(path, body, Json, ct);
        await EnsureOkAsync(resp);
    }

    private static async Task EnsureOkAsync(HttpResponseMessage resp)
    {
        if (resp.IsSuccessStatusCode) return;

        string detail = await resp.Content.ReadAsStringAsync();
        try
        {
            using JsonDocument doc = JsonDocument.Parse(detail);
            if (doc.RootElement.TryGetProperty("error", out JsonElement err))
                detail = err.GetString() ?? detail;
        }
        catch (JsonException) { /* 保持原文 */ }

        throw new InvalidOperationException($"agent 返回 {(int)resp.StatusCode}: {detail}");
    }

    // ── 查询

    /// <inheritdoc />
    public async Task<SnapshotState> GetStateAsync(bool refresh, CancellationToken ct = default)
    {
        StateDto? dto = await GetAsync<StateDto?>($"api/state{(refresh ? "?refresh=1" : "")}", ct);
        if (dto is null) throw new InvalidOperationException("agent 返回空状态");

        CanWrite = dto.CanWrite;
        SelfInfo? self = dto.Self is null
            ? null
            : new SelfInfo(dto.Self.NodeId, dto.Self.Alias, dto.Self.PublicIp);

        var networks = new List<NetworkInfo>();
        foreach (NetworkDto n in dto.Networks ?? [])
        {
            var members = new List<MemberInfo>();
            foreach (MemberDto m in n.Members ?? [])
                members.Add(new MemberInfo(m.NodeId, m.Alias, m.PublicIp));

            networks.Add(new NetworkInfo(n.Name ?? "", ParseGuid(n.Guid), n.Token, members));
        }

        var nodes = networks.SelectMany(n => n.Members).Select(m => m.NodeId)
                            .Distinct().OrderBy(x => x).ToList();
        return new SnapshotState(self, networks, nodes);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetPublicNetworksAsync(string? search,
                                                                    CancellationToken ct = default)
    {
        string q = string.IsNullOrWhiteSpace(search) ? "" : $"?search={Uri.EscapeDataString(search)}";
        PublicDto? dto = await GetAsync<PublicDto?>($"api/public{q}", ct);
        return dto?.Networks ?? [];
    }

    // ── 写操作

    /// <inheritdoc />
    public Task PowerAsync(bool on, CancellationToken ct = default)
        => PostAsync("api/power", new { on }, ct);

    /// <inheritdoc />
    public Task SetAliasAsync(string alias, CancellationToken ct = default)
        => PostAsync("api/alias", new { alias }, ct);

    /// <inheritdoc />
    public Task JoinAsync(string name, CancellationToken ct = default)
        => PostAsync("api/networks/join", new { name }, ct);

    /// <inheritdoc />
    public Task CreateAsync(string name, CancellationToken ct = default)
        => PostAsync("api/networks/create", new { name }, ct);

    /// <inheritdoc />
    public Task LeaveAsync(string guidHex, CancellationToken ct = default)
        => PostAsync($"api/networks/{guidHex}/leave", null, ct);

    /// <inheritdoc />
    public Task DeleteAsync(string guidHex, CancellationToken ct = default)
        => PostAsync($"api/networks/{guidHex}/delete", null, ct);

    /// <inheritdoc />
    public Task SetEnabledAsync(string guidHex, bool enabled, CancellationToken ct = default)
        => PostAsync($"api/networks/{guidHex}/enabled", new { enabled }, ct);

    /// <inheritdoc />
    public Task MemberOpAsync(string op, string guidHex, ulong nodeId, string networkName,
                              CancellationToken ct = default)
    {
        string path = $"api/networks/{guidHex}/members/{nodeId}/{op}" +
                      (string.IsNullOrEmpty(networkName)
                          ? "" : $"?name={Uri.EscapeDataString(networkName)}");
        return PostAsync(path, null, ct);
    }

    private static byte[] ParseGuid(string? hex)
    {
        string s = (hex ?? "").Replace("-", "");
        if (s.Length != 32) return new byte[16];
        try { return Convert.FromHexString(s); }
        catch (FormatException) { return new byte[16]; }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }

    // ── agent 的 DTO
    private sealed class Envelope<T>
    {
        public bool Ok { get; set; }
        public T? Data { get; set; }
        public string? Error { get; set; }
    }

    private sealed class StateDto
    {
        public SelfDto? Self { get; set; }
        public bool CanWrite { get; set; }
        public List<NetworkDto>? Networks { get; set; }
    }

    private sealed class SelfDto
    {
        public ulong NodeId { get; set; }
        public string? Alias { get; set; }
        public string? PublicIp { get; set; }
    }

    private sealed class NetworkDto
    {
        public string? Name { get; set; }
        public string? Guid { get; set; }
        public string? Token { get; set; }
        public List<MemberDto>? Members { get; set; }
    }

    private sealed class MemberDto
    {
        public ulong NodeId { get; set; }
        public string? Alias { get; set; }
        public string? PublicIp { get; set; }
    }

    private sealed class PublicDto
    {
        public int Count { get; set; }
        public List<string>? Networks { get; set; }
    }
}
