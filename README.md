# SignedUpdater

Self-update for Windows desktop apps shipped as GitHub Releases, built around one rule:
**a downloaded binary is never executed before it is verified.** .NET 8, no dependencies.

```csharp
var updater = new GitHubUpdater(currentVersion, new UpdaterOptions
{
    Repo = "you/your-app-releases",
    PublicKey = "<base64 SubjectPublicKeyInfo>",   // embedded in the app
    PendingExeName = "yourapp.pending.exe",
});

// 1) at start-up, BEFORE any window: install what was staged last time
if (updater.TryApplyStaged(Environment.ProcessPath!, stageDir, out _)) return;   // swap script is running

// 2) in the background: check, then stage
var info = await updater.CheckAsync();
if (info.Status == UpdateStatus.Available)
    await updater.DownloadAndStageAsync(info, stageDir);   // installed on next start
```

## How it protects users

1. The release carries `release.json` (version, file name, SHA-256, size) and `release.sig`
   (base64 **ECDSA P-256** over the exact manifest bytes).
2. The app checks the signature with the public key it ships with. The private key never
   touches GitHub or CI, so a **hijacked GitHub account cannot ship a binary the app will run**.
3. The exe is found by the **signed** file name and streamed to disk with the hash computed on the fly,
   under a size cap. A hash or size mismatch deletes the partial file.
4. Only **HTTPS** and an **allow-list of hosts** (GitHub by default) are accepted, even if the
   release JSON asks for something else.
5. Install happens at next start via a `.cmd` swap script that backs up the current exe, replaces it,
   **rolls back and relaunches the old version if the replace fails**, and cleans up after itself.
   `TryApplyStaged` re-hashes the staged file right before swapping; if it is not newer or not intact it is
   deleted, never run.
6. Network, disk and JSON errors come back as `UpdateStatus.Failed` with a message. The updater never throws
   into your app for expected failures.

## Signing releases

```csharp
var (pub, priv) = SignatureVerifier.GenerateKeyPair();      // keep `priv` offline
var manifest = File.ReadAllBytes("release.json");
File.WriteAllText("release.sig", Convert.ToBase64String(SignatureVerifier.Sign(manifest, priv)));
```

`release.json`:

```json
{ "version": "2.0.0", "file": "yourapp.exe", "sha256": "<hex>", "size": 123456, "notes": "What changed" }
```

Upload `yourapp.exe`, `release.json` and `release.sig` as assets of the release.

## Threat model and limits (read this)

- **Stage directory trust.** `TryApplyStaged` verifies the file, then runs a script that moves it. If a
  local unprivileged user can write to `stageDir`, they can race that gap. Use a folder only administrators can
  write to (for example under `Program Files`, or an ACL-hardened ProgramData folder).
- **Rollback protection is version-based**: only strictly newer versions install. It does not stop an attacker
  who holds an old signed release from replaying it as long as its version is newer than the installed one.
- **Key rotation is not built in.** If the private key leaks you must ship a new build with a new public key
  through another channel.
- It does not code-sign the exe. Authenticode is a separate layer (SmartScreen, enterprise policy) and is
  recommended in addition.
- Windows only for the swap step. Check/download/stage work anywhere .NET runs.

## Develop

```bash
dotnet test tests/SignedUpdater.Tests    # 13 tests, in-memory fake GitHub, no network
```

Tests cover: valid flow, wrong-key signature, tampered manifest, swapped exe with a valid manifest, oversize
streaming abort, non-allow-listed host (never contacted), plain HTTP, disabled state, garbage keys, discarding a
corrupt or not-newer staged file, and the swap script (backup, rollback, `%` escaping).

## Provenance

Generalised from the auto-updater of a Windows tuning tool I build
([Sothe Windows Optimizer](https://github.com/ImSothe/Sothe-Windows-Optimizer)), with product-specific names,
keys and URLs removed. Built with AI-assisted development; the behaviour is pinned by the tests.

## Licence

MIT
