namespace SignedUpdater;

public enum UpdateStatus { Disabled, UpToDate, Available, Staged, Failed }

public sealed class UpdateInfo
{
    public UpdateStatus Status { get; set; }
    public Version? Version { get; set; }
    public string? ExeUrl { get; set; }
    public string? Sha256 { get; set; }
    public string? FileName { get; set; }
    public long Size { get; set; }
    public string? Notes { get; set; }
    public string? Message { get; set; }
}

/// <summary>
/// <c>release.json</c>, published next to the release and signed (<c>release.sig</c>, base64 ECDSA over the exact bytes).
/// Everything the updater trusts comes from here, never from GitHub's own JSON.
/// </summary>
public sealed class ReleaseManifest
{
    public string? Version { get; set; }
    public string? File { get; set; }     // name of the executable among the release assets
    public string? Sha256 { get; set; }   // hex SHA-256 of the executable
    public long Size { get; set; }        // bytes (optional; if 0 the MaxBytes cap applies)
    public string? Notes { get; set; }
}
