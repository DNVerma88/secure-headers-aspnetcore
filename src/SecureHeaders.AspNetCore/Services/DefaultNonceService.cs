using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;

namespace SecureHeaders.AspNetCore.Services;

/// <summary>
/// Default <see cref="INonceService"/> that generates a 32-byte (256-bit)
/// cryptographically-random, base64-encoded nonce once per HTTP request and
/// caches it in <see cref="HttpContext.Items"/>.
/// </summary>
internal sealed class DefaultNonceService : INonceService
{
    private const string ItemKey = "__SecureHeaders_Nonce";

    /// <inheritdoc />
    public string GetNonce(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Items.TryGetValue(ItemKey, out var cached) && cached is string existing)
            return existing;

        // 32 bytes → 44-character base64 string. Using stackalloc avoids heap allocation.
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        var nonce = Convert.ToBase64String(bytes);

        context.Items[ItemKey] = nonce;
        return nonce;
    }
}
