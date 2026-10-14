using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SignedUpdater.Tests;

/// <summary>Serves a fake GitHub release from memory.</summary>
internal sealed class FakeGitHub : HttpMessageHandler
{
    public Dictionary<string, byte[]> Files = new();
    public string IndexJson = "{}";
    public List<string> Requested = new();

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri!.ToString();
        Requested.Add(url);
        if (url.EndsWith("/releases/latest")) return Task.FromResult(Ok(Encoding.UTF8.GetBytes(IndexJson)));
        return Task.FromResult(Files.TryGetValue(url, out var b) ? Ok(b) : new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static HttpResponseMessage Ok(byte[] b) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(b) };
}

public class UpdaterTests : IDisposable
{
    private const string Base = "https://github.com/me/app-releases/releases/download/v2/";
    private readonly string _pub, _priv;
    private readonly string _stage = Path.Combine(Path.GetTempPath(), "su-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] _exe = RandomNumberGenerator.GetBytes(300_000);

    public UpdaterTests() { (_pub, _priv) = SignatureVerifier.GenerateKeyPair(); }
    public void Dispose() { try { Directory.Delete(_stage, true); } catch { } }

    private string Sha(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    private FakeGitHub Release(string version = "2.0.0", byte[]? exe = null, string? signWith = null,
        long? size = null, string? sha = null, string baseUrl = Base, string file = "app.exe")
    {
        exe ??= _exe;
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version, file, sha256 = sha ?? Sha(_exe), size = size ?? exe.Length, notes = "n"
        });
        var sig = Convert.ToBase64String(SignatureVerifier.Sign(manifest, signWith ?? _priv));
        var gh = new FakeGitHub();
        gh.IndexJson = JsonSerializer.Serialize(new
        {
            assets = new[]
            {
                new { name = "release.json", browser_download_url = baseUrl + "release.json" },
                new { name = "release.sig", browser_download_url = baseUrl + "release.sig" },
                new { name = file, browser_download_url = baseUrl + file },
            }
        });
        gh.Files[baseUrl + "release.json"] = manifest;
        gh.Files[baseUrl + "release.sig"] = Encoding.UTF8.GetBytes(sig);
        gh.Files[baseUrl + file] = exe;
        return gh;
    }

    private GitHubUpdater Updater(FakeGitHub gh, string current = "1.0.0", string? key = null) =>
        new(Version.Parse(current), new UpdaterOptions { Repo = "me/app-releases", PublicKey = key ?? _pub, Handler = gh });

    [Fact]
    public async Task ValidRelease_IsAvailable_ThenDownloadsAndStages()
    {
        var u = Updater(Release());
        var info = await u.CheckAsync();
        Assert.Equal(UpdateStatus.Available, info.Status);
        Assert.Equal(new Version(2, 0, 0), info.Version);

        var staged = await u.DownloadAndStageAsync(info, _stage);
        Assert.Equal(UpdateStatus.Staged, staged.Status);
        Assert.Equal(_exe, File.ReadAllBytes(Path.Combine(_stage, "app.pending.exe")));
    }

    [Fact]
    public async Task SameOrOlderVersion_IsUpToDate()
    {
        Assert.Equal(UpdateStatus.UpToDate, (await Updater(Release("2.0.0"), "2.0.0").CheckAsync()).Status);
        Assert.Equal(UpdateStatus.UpToDate, (await Updater(Release("1.5.0"), "2.0.0").CheckAsync()).Status);
    }

    [Fact]
    public async Task ManifestSignedWithAnotherKey_IsRejected()
    {
        var (_, attackerPriv) = SignatureVerifier.GenerateKeyPair();
        var info = await Updater(Release(signWith: attackerPriv)).CheckAsync();
        Assert.Equal(UpdateStatus.Failed, info.Status);
        Assert.Contains("signature", info.Message);
    }

    [Fact]
    public async Task TamperedManifest_IsRejected()
    {
        var gh = Release();
        var key = Base + "release.json";
        gh.Files[key] = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(gh.Files[key]).Replace("\"n\"", "\"x\""));
        Assert.Equal(UpdateStatus.Failed, (await Updater(gh).CheckAsync()).Status);
    }

    [Fact]
    public async Task SwappedExe_WithValidManifest_IsDiscardedAndNothingIsStaged()
    {
        var evil = RandomNumberGenerator.GetBytes(300_000);   // same size, different content
        var gh = Release();
        gh.Files[Base + "app.exe"] = evil;
        var u = Updater(gh);
        var res = await u.DownloadAndStageAsync(await u.CheckAsync(), _stage);
        Assert.Equal(UpdateStatus.Failed, res.Status);
        Assert.False(File.Exists(Path.Combine(_stage, "app.pending.exe")));
        Assert.False(File.Exists(Path.Combine(_stage, "app.pending.exe.part")));
    }

    [Fact]
    public async Task ExeLargerThanSignedSize_IsAbortedWhileStreaming()
    {
        var gh = Release(size: 1000, sha: Sha(_exe));
        var u = Updater(gh);
        var res = await u.DownloadAndStageAsync(await u.CheckAsync(), _stage);
        Assert.Equal(UpdateStatus.Failed, res.Status);
        Assert.False(File.Exists(Path.Combine(_stage, "app.pending.exe")));
    }

    [Fact]
    public async Task NonAllowListedHost_IsRefused_AndNeverContacted()
    {
        var gh = Release(baseUrl: "https://evil.example.com/dl/");
        var info = await Updater(gh).CheckAsync();
        Assert.Equal(UpdateStatus.Failed, info.Status);
        Assert.DoesNotContain(gh.Requested, r => r.Contains("evil.example.com"));
    }

    [Fact]
    public async Task PlainHttp_IsRefused()
    {
        var info = await Updater(Release(baseUrl: "http://github.com/dl/")).CheckAsync();
        Assert.Equal(UpdateStatus.Failed, info.Status);
    }

    [Fact]
    public async Task Disabled_WithoutKeyOrRepo()
    {
        var u = new GitHubUpdater(new Version(1, 0), new UpdaterOptions { Repo = "me/app", PublicKey = "" });
        Assert.Equal(UpdateStatus.Disabled, (await u.CheckAsync()).Status);
    }

    [Fact]
    public void Verify_NeverThrows_OnGarbage()
    {
        Assert.False(SignatureVerifier.Verify(new byte[] { 1 }, new byte[] { 2 }, "not base64!!"));
        Assert.False(SignatureVerifier.Verify(new byte[] { 1 }, new byte[] { 2 }, _pub));
        Assert.False(SignatureVerifier.Verify(null, null, null));
    }

    [Fact]
    public void TryApplyStaged_CorruptedStagedFile_IsDiscardedAndNotRun()
    {
        Directory.CreateDirectory(_stage);
        File.WriteAllBytes(Path.Combine(_stage, "app.pending.exe"), new byte[] { 1, 2, 3 });
        File.WriteAllText(Path.Combine(_stage, "pending.json"),
            JsonSerializer.Serialize(new { Version = "9.0.0", Sha256 = new string('0', 64) }));
        var u = Updater(new FakeGitHub());
        Assert.False(u.TryApplyStaged(@"C:\app\app.exe", _stage, out _));
        Assert.False(File.Exists(Path.Combine(_stage, "app.pending.exe")));   // removed, never executed
    }

    [Fact]
    public void TryApplyStaged_NotNewer_IsDiscarded()
    {
        Directory.CreateDirectory(_stage);
        var f = Path.Combine(_stage, "app.pending.exe");
        File.WriteAllBytes(f, _exe);
        File.WriteAllText(Path.Combine(_stage, "pending.json"),
            JsonSerializer.Serialize(new { Version = "1.0.0", Sha256 = Sha(_exe) }));
        Assert.False(Updater(new FakeGitHub(), "1.0.0").TryApplyStaged(@"C:\app\app.exe", _stage, out _));
        Assert.False(File.Exists(f));
    }

    [Fact]
    public void SwapScript_BacksUp_Restores_AndEscapesPercent()
    {
        var s = GitHubUpdater.BuildSwapScript(1234, @"C:\s\app.pending.exe", @"C:\Program Files\100%\app.exe", @"C:\s\pending.json");
        Assert.Contains("tasklist /fi \"PID eq 1234\"", s);
        Assert.Contains("copy /y \"C:\\Program Files\\100%%\\app.exe\" \"C:\\Program Files\\100%%\\app.exe.old\"", s);
        Assert.Contains(":failed", s);
        Assert.Contains("move /y \"C:\\Program Files\\100%%\\app.exe.old\" \"C:\\Program Files\\100%%\\app.exe\"", s);   // rollback
        Assert.True(s.IndexOf("copy /y", StringComparison.Ordinal) < s.IndexOf("move /y \"C:\\s\\app.pending.exe\"", StringComparison.Ordinal));
    }
}
