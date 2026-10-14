using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SignedUpdater;

public sealed class UpdaterOptions
{
    /// <summary>"owner/repo" of the releases (a repo that only holds downloads is a good idea).</summary>
    public string Repo { get; set; } = "";
    /// <summary>Base64 SubjectPublicKeyInfo of the key that signs releases. Empty = updater disabled.</summary>
    public string PublicKey { get; set; } = "";
    public string UserAgent { get; set; } = "SignedUpdater";
    public string ApiBase { get; set; } = "https://api.github.com";
    /// <summary>Hosts downloads may come from. A leading dot admits subdomains.</summary>
    public string[] AllowedHosts { get; set; } = { "api.github.com", "github.com", ".githubusercontent.com" };
    /// <summary>Cap when the signed manifest declares no size.</summary>
    public long MaxBytes { get; set; } = 400L * 1024 * 1024;
    public string PendingExeName { get; set; } = "app.pending.exe";
    public string PendingInfoName { get; set; } = "pending.json";
    /// <summary>For tests: replaces the HTTP stack.</summary>
    public HttpMessageHandler? Handler { get; set; }
}

/// <summary>
/// Safe self-update. Golden rule: a downloaded binary is NEVER run before it is verified.
/// Flow: read the latest release from GitHub, fetch release.json + release.sig, check the ECDSA P-256
/// signature against the embedded public key. Only if the signature is valid AND the SHA-256 of the
/// downloaded executable equals the one in the signed manifest is the file staged; it is installed on
/// next start. A hijacked GitHub account or a network attacker cannot make the app run a binary
/// that was not signed with the private key.
/// </summary>
public sealed class GitHubUpdater
{
    private static readonly Regex RepoPattern = new(@"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$");
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };

    private readonly UpdaterOptions _o;
    private readonly Version _current;
    private readonly string[] _hosts;

    public GitHubUpdater(Version? current, UpdaterOptions options)
    {
        _o = options;
        _current = current ?? new Version(0, 0, 0);
        _hosts = options.AllowedHosts.Select(h => h.ToLowerInvariant()).ToArray();
    }

    public bool IsConfigured => _o.Repo.Trim().Length > 0 && !string.IsNullOrWhiteSpace(_o.PublicKey);

    /// <summary>HTTPS only, and only allow-listed hosts: not http://, not a foreign server even if the release JSON asks.</summary>
    public bool IsAllowedUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return false;
        var host = u.Host.ToLowerInvariant();
        return _hosts.Any(a => host == a || (a.StartsWith('.') && host.EndsWith(a, StringComparison.Ordinal)));
    }

    private static UpdateInfo Fail(string message) => new() { Status = UpdateStatus.Failed, Message = message };

    // Expected failures (network, disk, malformed data) must never take the host app down.
    private static bool IsExpected(Exception ex, CancellationToken ct) =>
        ex is HttpRequestException || (ex is TaskCanceledException && !ct.IsCancellationRequested) || ex is JsonException
        || ex is FormatException || ex is UriFormatException || ex is IOException || ex is UnauthorizedAccessException
        || ex is InvalidOperationException;

    private HttpClient NewClient(TimeSpan timeout)
    {
        var http = _o.Handler != null ? new HttpClient(_o.Handler, false) : new HttpClient();
        http.Timeout = timeout;
        http.DefaultRequestHeaders.UserAgent.ParseAdd(_o.UserAgent);
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    }

    /// <summary>Check the latest release, verify the manifest signature and say whether a newer version exists. Does not download the exe.</summary>
    public async Task<UpdateInfo> CheckAsync(CancellationToken ct = default)
    {
        if (!IsConfigured) return new UpdateInfo { Status = UpdateStatus.Disabled, Message = "Updater not configured" };
        var repo = _o.Repo.Trim().Trim('/');
        var apiBase = _o.ApiBase.TrimEnd('/');
        if (!RepoPattern.IsMatch(repo)) return Fail("Invalid update repository.");
        if (!IsAllowedUrl(apiBase)) return Fail("The update server must be HTTPS and allow-listed.");
        try
        {
            using var http = NewClient(TimeSpan.FromSeconds(20));
            var indexJson = await http.GetStringAsync($"{apiBase}/repos/{repo}/releases/latest", ct);
            var manifestUrl = UrlOfAsset(indexJson, "release.json");
            var sigUrl = UrlOfAsset(indexJson, "release.sig");
            if (manifestUrl == null || sigUrl == null) return Fail("The release has no signed release.json.");
            if (!IsAllowedUrl(manifestUrl) || !IsAllowedUrl(sigUrl)) return Fail("The release points to a URL that is not allowed.");

            var manifestBytes = await http.GetByteArrayAsync(manifestUrl, ct);
            var signature = Convert.FromBase64String((await http.GetStringAsync(sigUrl, ct)).Trim());
            if (!SignatureVerifier.Verify(manifestBytes, signature, _o.PublicKey))
                return Fail("The update signature is not valid: ignored.");

            var m = JsonSerializer.Deserialize<ReleaseManifest>(manifestBytes, Json);
            if (m == null || !Version.TryParse((m.Version ?? "").TrimStart('v', 'V'), out var version)
                || string.IsNullOrWhiteSpace(m.Sha256) || string.IsNullOrWhiteSpace(m.File))
                return Fail("Invalid release manifest.");
            if (m.Size < 0 || m.Size > _o.MaxBytes) return Fail("The size declared in the manifest is not valid.");

            // The exe is looked up by the SIGNED name, not by whatever GitHub lists first.
            var exeUrl = UrlOfAsset(indexJson, m.File);
            if (exeUrl == null) return Fail($"The release does not include {m.File}.");
            if (!IsAllowedUrl(exeUrl)) return Fail("The installer points to a URL that is not allowed.");

            if (version <= _current) return new UpdateInfo { Status = UpdateStatus.UpToDate, Version = version };
            return new UpdateInfo
            {
                Status = UpdateStatus.Available, Version = version, ExeUrl = exeUrl,
                Sha256 = m.Sha256, FileName = m.File, Size = m.Size, Notes = m.Notes,
            };
        }
        catch (Exception ex) when (IsExpected(ex, ct)) { return Fail(ex.Message); }
    }

    /// <summary>
    /// Stream the exe to disk (hash computed on the fly, size capped; never loaded whole into memory), check
    /// its SHA-256 against the SIGNED manifest and stage it in <paramref name="stageDir"/>. On any mismatch nothing is kept.
    /// </summary>
    public async Task<UpdateInfo> DownloadAndStageAsync(UpdateInfo? info, string stageDir, CancellationToken ct = default)
    {
        if (info == null || info.Status != UpdateStatus.Available)
            return info ?? new UpdateInfo { Status = UpdateStatus.Failed };
        if (!IsAllowedUrl(info.ExeUrl)) return Fail("The installer points to a URL that is not allowed.");
        long limit = info.Size > 0 ? info.Size : _o.MaxBytes;
        string? tmp = null;
        try
        {
            using var http = NewClient(Timeout.InfiniteTimeSpan);   // total time is bounded by cts below
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(10));

            using var resp = await http.GetAsync(info.ExeUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            resp.EnsureSuccessStatusCode();
            if (resp.Content.Headers.ContentLength is long declared && declared > limit)
                return Fail("The installer is larger than declared: discarded.");

            Directory.CreateDirectory(stageDir);
            tmp = Path.Combine(stageDir, _o.PendingExeName + ".part");
            long total = 0;
            string hash;
            using (var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                using (var src = await resp.Content.ReadAsStreamAsync(cts.Token))
                using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true))
                {
                    var buffer = new byte[81920];
                    int n;
                    while ((n = await src.ReadAsync(buffer, cts.Token)) > 0)
                    {
                        total += n;
                        if (total > limit) return DiscardPart(tmp, "The installer exceeds the allowed size: discarded.");
                        hasher.AppendData(buffer, 0, n);
                        await dst.WriteAsync(buffer.AsMemory(0, n), cts.Token);
                    }
                }
                hash = Convert.ToHexString(hasher.GetHashAndReset());
            }
            if (info.Size > 0 && total != info.Size)
                return DiscardPart(tmp, "The installer size does not match the signed manifest: discarded.");
            if (!string.Equals(hash, info.Sha256, StringComparison.OrdinalIgnoreCase))
                return DiscardPart(tmp, "The downloaded installer does not match the signature: discarded.");

            File.Move(tmp, Path.Combine(stageDir, _o.PendingExeName), true);
            tmp = null;
            File.WriteAllText(Path.Combine(stageDir, _o.PendingInfoName),
                JsonSerializer.Serialize(new PendingUpdate { Version = info.Version!.ToString(), Sha256 = info.Sha256 }));
            return new UpdateInfo { Status = UpdateStatus.Staged, Version = info.Version, Notes = info.Notes };
        }
        catch (Exception ex) when (IsExpected(ex, ct))
        {
            if (tmp != null) try { File.Delete(tmp); } catch { /* best effort */ }
            return Fail(ex.Message);
        }
    }

    private static UpdateInfo DiscardPart(string tmp, string message)
    {
        try { File.Delete(tmp); } catch { /* best effort */ }
        return Fail(message);
    }

    public sealed class PendingUpdate { public string? Version { get; set; } public string? Sha256 { get; set; } }

    /// <summary>
    /// Call at start-up, before opening any window. If a staged exe exists, is newer, and still hashes to what
    /// was signed, launch the swap script and return true; the caller must then exit. Anything off: the staged
    /// files are removed and nothing runs. <paramref name="stageDir"/> MUST be a trusted folder that only
    /// administrators can write to, or a local attacker could replace the staged exe after the check.
    /// </summary>
    public bool TryApplyStaged(string currentExe, string stageDir, out string? error)
    {
        error = null;
        var staged = Path.Combine(stageDir, _o.PendingExeName);
        var infoPath = Path.Combine(stageDir, _o.PendingInfoName);
        if (!File.Exists(staged) || !File.Exists(infoPath)) return false;
        try
        {
            var pending = JsonSerializer.Deserialize<PendingUpdate>(File.ReadAllText(infoPath), Json);
            bool newer = pending != null && Version.TryParse(pending.Version, out var v) && v > _current;
            bool intact = pending != null && string.Equals(HashFile(staged), pending.Sha256, StringComparison.OrdinalIgnoreCase);
            if (!newer || !intact) { Discard(stageDir); return false; }
            if (!OperatingSystem.IsWindows()) return false;

            var script = Path.Combine(stageDir, "apply-update.cmd");
            File.WriteAllText(script, BuildSwapScript(Environment.ProcessId, staged, currentExe, infoPath));
            var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            Process.Start(new ProcessStartInfo(cmd, $"/c \"{script}\"")
            { CreateNoWindow = true, UseShellExecute = false, WorkingDirectory = stageDir });
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(fs));   // streaming: the exe may be hundreds of MB
    }

    public void Discard(string stageDir)
    {
        foreach (var f in new[] { _o.PendingExeName, _o.PendingInfoName })
            try { File.Delete(Path.Combine(stageDir, f)); } catch { /* best effort */ }
    }

    /// <summary>
    /// .cmd script: waits (at most ~90 s) for the running process to exit, keeps a copy of the current exe,
    /// replaces it, relaunches and deletes itself. If the replacement fails (antivirus, full disk...) it restores
    /// the copy and relaunches the old version: the app never ends up without an exe. It only moves a file that
    /// was ALREADY verified.
    /// </summary>
    public static string BuildSwapScript(int pid, string stagedExe, string targetExe, string pendingInfo)
    {
        string image = Path.GetFileName(targetExe.Replace('\\', '/'));
        string log = Path.Combine(Path.GetDirectoryName(stagedExe.Replace('\\', '/')) ?? "", "update.log").Replace('/', '\\');
        static string S(string s) => s.Replace("%", "%%");   // in a .cmd, % in a path would expand
        return
            "@echo off\r\n" +
            "set /a tries=0\r\n" +
            ":wait\r\n" +
            $"tasklist /fi \"PID eq {pid}\" /nh 2>nul | find /i \"{S(image)}\" >nul\r\n" +
            "if errorlevel 1 goto swap\r\n" +
            "set /a tries+=1\r\n" +
            "if %tries% geq 45 goto leave\r\n" +
            "ping -n 3 127.0.0.1 >nul\r\n" +
            "goto wait\r\n" +
            ":swap\r\n" +
            $"copy /y \"{S(targetExe)}\" \"{S(targetExe)}.old\" >nul 2>&1\r\n" +
            $"move /y \"{S(stagedExe)}\" \"{S(targetExe)}\" >nul\r\n" +
            "if errorlevel 1 goto failed\r\n" +
            $"del /q \"{S(targetExe)}.old\" >nul 2>&1\r\n" +
            $"del /q \"{S(pendingInfo)}\" >nul 2>&1\r\n" +
            "goto launch\r\n" +
            ":failed\r\n" +
            $"echo %date% %time% could not replace the executable; keeping the previous version >> \"{S(log)}\"\r\n" +
            $"if exist \"{S(targetExe)}.old\" move /y \"{S(targetExe)}.old\" \"{S(targetExe)}\" >nul\r\n" +
            ":launch\r\n" +
            $"start \"\" \"{S(targetExe)}\"\r\n" +
            ":leave\r\n" +
            "(goto) 2>nul & del \"%~f0\"\r\n";
    }

    // ---- GitHub release index (external data: asset names are treated as data) ----
    private static string? UrlOfAsset(string indexJson, string name)
    {
        using var doc = JsonDocument.Parse(indexJson);
        if (doc.RootElement.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
            foreach (var a in assets.EnumerateArray())
                if (string.Equals(Str(a, "name"), name, StringComparison.OrdinalIgnoreCase)) return Str(a, "browser_download_url");
        return null;
    }

    private static string? Str(JsonElement e, string prop) => e.TryGetProperty(prop, out var v) ? v.GetString() : null;
}
