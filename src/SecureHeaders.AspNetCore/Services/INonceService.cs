using Microsoft.AspNetCore.Http;

namespace SecureHeaders.AspNetCore.Services;

/// <summary>
/// Provides a cryptographically-random, per-request nonce for injection into
/// <c>Content-Security-Policy</c> headers.
/// </summary>
/// <remarks>
/// Register the default implementation by calling
/// <c>builder.Services.AddSecureHeaders()</c>. The generated nonce is stored
/// in <c>HttpContext.Items</c> and can be read by Razor tag helpers or minimal
/// API middleware to emit <c>script</c> or <c>style</c> tags with matching nonces.
///
/// Usage in <c>CspPolicy</c>: include the literal token <c>__nonce__</c> where
/// you want the nonce substituted, e.g.:
/// <code>
/// options.CspPolicy = "script-src 'self' 'nonce-__nonce__'; object-src 'none';";
/// options.EnableCspNonce = true;
/// </code>
/// </remarks>
public interface INonceService
{
    /// <summary>
    /// The placeholder token used in <see cref="Options.SecureHeadersOptions.CspPolicy"/>
    /// that is replaced at request-time with the actual base64-encoded nonce value.
    /// </summary>
    const string Placeholder = "__nonce__";

    /// <summary>
    /// Returns the nonce for the current HTTP request.
    /// Successive calls within the same request return the same value.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    string GetNonce(HttpContext context);
}
