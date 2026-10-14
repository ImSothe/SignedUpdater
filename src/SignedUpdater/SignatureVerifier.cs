using System.Security.Cryptography;

namespace SignedUpdater;

/// <summary>ECDSA P-256 / SHA-256 signing helpers. Keys travel as base64 (SubjectPublicKeyInfo / PKCS#8).</summary>
public static class SignatureVerifier
{
    /// <summary>
    /// True only if <paramref name="signature"/> (raw r||s) is a valid signature of <paramref name="data"/>
    /// by the key <paramref name="publicKeyBase64"/>. Any malformed input returns false, never throws.
    /// </summary>
    public static bool Verify(byte[]? data, byte[]? signature, string? publicKeyBase64)
    {
        if (data is null || signature is null || string.IsNullOrWhiteSpace(publicKeyBase64)) return false;
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        catch (FormatException) { return false; }         // key badly copied
        catch (CryptographicException) { return false; }  // key or signature has an invalid format
    }

    /// <summary>Generate a key pair. Keep the private key OFF the build server and out of the repo.</summary>
    public static (string PublicKeyBase64, string PrivateKeyBase64) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()),
                Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey()));
    }

    public static byte[] Sign(byte[] data, string privateKeyBase64)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }
}
