using System.Buffers;
using System.Text;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Internal;

namespace SecureHeaders.AspNetCore.Builders;

/// <summary>
/// Fluent builder for constructing a <c>Content-Security-Policy</c> header value.
/// </summary>
/// <example>
/// <code>
/// var policy = new CspBuilder()
///     .AddDefaultSrcSelf()
///     .AddScriptSrcSelf()
///     .AddObjectSrcNone()
///     .Build();
/// </code>
/// </example>
public sealed class CspBuilder
{
    private readonly Dictionary<string, List<string>> _directives = new(StringComparer.OrdinalIgnoreCase);

    // -------------------------------------------------------------------------
    // Convenience factory methods for common directives
    // -------------------------------------------------------------------------

    /// <summary>Adds <c>default-src 'self'</c>.</summary>
    public CspBuilder AddDefaultSrcSelf() => AddSource("default-src", "'self'");

    /// <summary>Adds <c>script-src 'self'</c>.</summary>
    public CspBuilder AddScriptSrcSelf() => AddSource("script-src", "'self'");

    /// <summary>Adds <c>style-src 'self'</c>.</summary>
    public CspBuilder AddStyleSrcSelf() => AddSource("style-src", "'self'");

    /// <summary>Adds <c>img-src 'self'</c>.</summary>
    public CspBuilder AddImgSrcSelf() => AddSource("img-src", "'self'");

    /// <summary>Adds <c>img-src data:</c> (needed for inline SVG data URIs).</summary>
    public CspBuilder AddImgSrcData() => AddSource("img-src", "data:");

    /// <summary>Adds <c>font-src 'self'</c>.</summary>
    public CspBuilder AddFontSrcSelf() => AddSource("font-src", "'self'");

    /// <summary>Adds <c>connect-src 'self'</c>.</summary>
    public CspBuilder AddConnectSrcSelf() => AddSource("connect-src", "'self'");

    /// <summary>Adds <c>object-src 'none'</c>.</summary>
    public CspBuilder AddObjectSrcNone() => AddSource("object-src", "'none'");

    /// <summary>Adds <c>base-uri 'self'</c>.</summary>
    public CspBuilder AddBaseUriSelf() => AddSource("base-uri", "'self'");

    /// <summary>Adds <c>form-action 'self'</c>.</summary>
    public CspBuilder AddFormActionSelf() => AddSource("form-action", "'self'");

    /// <summary>Adds <c>frame-ancestors 'none'</c>.</summary>
    public CspBuilder AddFrameAncestorsNone() => AddSource("frame-ancestors", "'none'");

    /// <summary>Adds <c>frame-ancestors 'self'</c>.</summary>
    public CspBuilder AddFrameAncestorsSelf() => AddSource("frame-ancestors", "'self'");

    /// <summary>Adds <c>upgrade-insecure-requests</c> (no value).</summary>
    public CspBuilder AddUpgradeInsecureRequests() => AddDirectiveFlag("upgrade-insecure-requests");

    /// <summary>Adds <c>block-all-mixed-content</c> (no value).</summary>
    public CspBuilder AddBlockAllMixedContent() => AddDirectiveFlag("block-all-mixed-content");

    /// <summary>Adds <c>script-src 'unsafe-inline'</c>.</summary>
    public CspBuilder AddScriptSrcUnsafeInline() => AddSource("script-src", "'unsafe-inline'");

    /// <summary>Adds <c>script-src 'unsafe-eval'</c>.</summary>
    public CspBuilder AddScriptSrcUnsafeEval() => AddSource("script-src", "'unsafe-eval'");

    /// <summary>Adds a nonce source to the given directive, e.g. <c>script-src 'nonce-abc123'</c>.</summary>
    /// <param name="directive">The CSP directive name, e.g. <c>script-src</c>.</param>
    /// <param name="nonceBase64">Must be a base64-encoded value; characters outside [A-Za-z0-9+/=] are rejected
    /// to prevent semicolons or quotes from injecting additional CSP directives.</param>
    public CspBuilder AddNonce(string directive, string nonceBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nonceBase64);
        if (!IsValidBase64(nonceBase64))
            throw new ArgumentException(
                "Nonce value must be a valid base64-encoded string. " +
                "Characters outside [A-Za-z0-9+/=] (including ';' and \"'\") could inject " +
                "additional CSP directives and weaken the policy.",
                nameof(nonceBase64));
        return AddSource(directive, $"'nonce-{nonceBase64}'");
    }

    /// <summary>Adds a hash source to the given directive, e.g. <c>script-src 'sha256-abc123'</c>.</summary>
    /// <param name="directive">The CSP directive name, e.g. <c>script-src</c>.</param>
    /// <param name="algorithm">Must be one of: <c>sha256</c>, <c>sha384</c>, <c>sha512</c>.</param>
    /// <param name="hashBase64">Must be a base64-encoded value.</param>
    public CspBuilder AddHash(string directive, string algorithm, string hashBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(hashBase64);
        if (!IsKnownHashAlgorithm(algorithm))
            throw new ArgumentException(
                "Hash algorithm must be one of: sha256, sha384, sha512.",
                nameof(algorithm));
        if (!IsValidBase64(hashBase64))
            throw new ArgumentException(
                "Hash value must be a valid base64-encoded string.",
                nameof(hashBase64));
        return AddSource(directive, $"'{algorithm.ToLowerInvariant()}-{hashBase64}'");
    }

    // -------------------------------------------------------------------------
    // Generic / extensible methods
    // -------------------------------------------------------------------------

    /// <summary>
    /// Adds one or more sources to a CSP directive.
    /// </summary>
    /// <param name="directive">The directive name, e.g. <c>script-src</c>.</param>
    /// <param name="sources">One or more source expressions.</param>
    /// <exception cref="ArgumentException">
    /// Thrown if <paramref name="directive"/> or any source contains CR, LF, or NUL characters
    /// (HTTP response splitting risk).
    /// </exception>
    public CspBuilder AddSource(string directive, params string[] sources)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directive);
        if (HeaderSecurity.ContainsInvalidChars(directive))
            throw new ArgumentException(
                "CSP directive name must not contain CR/LF/NUL characters (HTTP response splitting risk).",
                nameof(directive));

        if (!_directives.TryGetValue(directive, out var list))
        {
            list = [];
            _directives[directive] = list;
        }

        foreach (var source in sources)
        {
            if (string.IsNullOrWhiteSpace(source)) continue;
            if (HeaderSecurity.ContainsInvalidChars(source))
                throw new ArgumentException(
                    "CSP source expression must not contain CR/LF/NUL characters (HTTP response splitting risk).",
                    nameof(sources));
            if (!list.Contains(source, StringComparer.Ordinal))
                list.Add(source);
        }

        return this;
    }

    /// <summary>
    /// Adds a value-less flag directive (e.g. <c>upgrade-insecure-requests</c>).
    /// </summary>
    public CspBuilder AddDirectiveFlag(string directive)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directive);
        if (HeaderSecurity.ContainsInvalidChars(directive))
            throw new ArgumentException(
                "CSP directive name must not contain CR/LF/NUL characters (HTTP response splitting risk).",
                nameof(directive));
        _directives.TryAdd(directive, []);
        return this;
    }

    /// <summary>
    /// Adds a <c>report-uri</c> directive.
    /// </summary>
    public CspBuilder AddReportUri(string uri)
        => AddSource("report-uri", uri);

    /// <summary>
    /// Adds a <c>report-to</c> directive.
    /// </summary>
    public CspBuilder AddReportTo(string groupName)
        => AddSource("report-to", groupName);

    // -------------------------------------------------------------------------
    // Build
    // -------------------------------------------------------------------------

    /// <summary>
    /// Builds the complete CSP header value string.
    /// </summary>
    /// <returns>A semicolon-separated CSP policy string.</returns>
    public string Build()
    {
        if (_directives.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();

        foreach (var (directive, sources) in _directives)
        {
            if (sb.Length > 0)
                sb.Append("; ");

            sb.Append(directive);

            if (sources.Count > 0)
            {
                sb.Append(' ');
                sb.Append(string.Join(' ', sources));
            }
        }

        sb.Append(';');
        return sb.ToString();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    // Valid base64 characters: A-Z, a-z, 0-9, +, /, =
    private static readonly SearchValues<char> s_base64Chars =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");

    private static bool IsValidBase64(string value) =>
        value.Length > 0 && value.AsSpan().IndexOfAnyExcept(s_base64Chars) < 0;

    private static bool IsKnownHashAlgorithm(string algorithm) =>
        algorithm.Equals("sha256", StringComparison.OrdinalIgnoreCase) ||
        algorithm.Equals("sha384", StringComparison.OrdinalIgnoreCase) ||
        algorithm.Equals("sha512", StringComparison.OrdinalIgnoreCase);
}
