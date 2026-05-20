using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Models;

namespace SecureHeaders.AspNetCore.Options;

/// <summary>
/// Configuration options for <c>SecureHeaders.AspNetCore</c> middleware.
/// </summary>
public sealed class SecureHeadersOptions
{
    // -------------------------------------------------------------------------
    // HSTS
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Strict-Transport-Security</c> header.
    /// When <see langword="true"/> the header is only sent in a Production
    /// environment (configurable via <see cref="EnforceHstsInDevelopment"/>).
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnableHsts { get; set; } = true;

    /// <summary>
    /// The <c>max-age</c> directive value.
    /// Default: 365 days.
    /// </summary>
    public TimeSpan HstsMaxAge { get; set; } = TimeSpan.FromDays(365);

    /// <summary>
    /// Append the <c>includeSubDomains</c> directive.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool HstsIncludeSubDomains { get; set; } = true;

    /// <summary>
    /// Append the <c>preload</c> directive.
    /// Note: requires <c>max-age</c> ≥ 63 072 000 and <see cref="HstsIncludeSubDomains"/> = <see langword="true"/>.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool HstsPreload { get; set; }

    /// <summary>
    /// When <see langword="true"/>, HSTS is sent even in non-Production environments.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool EnforceHstsInDevelopment { get; set; }

    // -------------------------------------------------------------------------
    // X-Content-Type-Options
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>X-Content-Type-Options: nosniff</c> header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnableXContentTypeOptions { get; set; } = true;

    // -------------------------------------------------------------------------
    // X-Frame-Options
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>X-Frame-Options</c> header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnableXFrameOptions { get; set; } = true;

    /// <summary>
    /// The value for the <c>X-Frame-Options</c> header.
    /// Default: <c>SAMEORIGIN</c>.
    /// </summary>
    public string XFrameOptionsValue { get; set; } = HeaderDefaults.XFrameOptionsSameOrigin;

    // -------------------------------------------------------------------------
    // Referrer-Policy
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Referrer-Policy</c> header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnableReferrerPolicy { get; set; } = true;

    /// <summary>
    /// The <c>Referrer-Policy</c> directive value.
    /// Default: <c>strict-origin-when-cross-origin</c>.
    /// </summary>
    public string ReferrerPolicyValue { get; set; } = HeaderDefaults.ReferrerPolicyStrictOriginWhenCrossOrigin;

    // -------------------------------------------------------------------------
    // Content-Security-Policy
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Content-Security-Policy</c> (or report-only) header.
    /// Default: <see langword="false"/> (opt-in because CSP requires per-app tuning).
    /// </summary>
    public bool EnableCsp { get; set; }

    /// <summary>
    /// The raw CSP policy string. Use <see cref="Builders.CspBuilder"/> to construct it fluently.
    /// </summary>
    public string? CspPolicy { get; set; }

    /// <summary>
    /// When <see langword="true"/> the header is sent as
    /// <c>Content-Security-Policy-Report-Only</c> instead of the enforcing header.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool EnableCspReportOnly { get; set; }

    /// <summary>
    /// Convenience property to append a <c>report-uri</c> directive to the CSP.
    /// If <see cref="CspPolicy"/> already contains <c>report-uri</c> this is ignored.
    /// </summary>
    public string? CspReportUri { get; set; }

    // -------------------------------------------------------------------------
    // Permissions-Policy
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Permissions-Policy</c> header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnablePermissionsPolicy { get; set; } = true;

    /// <summary>
    /// The <c>Permissions-Policy</c> value.
    /// Default: restricts camera, microphone, geolocation, and payment.
    /// </summary>
    public string PermissionsPolicyValue { get; set; } = HeaderDefaults.PermissionsPolicyBasic;

    // -------------------------------------------------------------------------
    // Cross-Origin-Opener-Policy (COOP)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Cross-Origin-Opener-Policy</c> header.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool EnableCrossOriginOpenerPolicy { get; set; }

    /// <summary>
    /// The <c>Cross-Origin-Opener-Policy</c> value.
    /// Default: <c>same-origin</c>.
    /// </summary>
    public string CrossOriginOpenerPolicyValue { get; set; } = HeaderDefaults.CoopSameOrigin;

    // -------------------------------------------------------------------------
    // Cross-Origin-Resource-Policy (CORP)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Cross-Origin-Resource-Policy</c> header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool EnableCrossOriginResourcePolicy { get; set; } = true;

    /// <summary>
    /// The <c>Cross-Origin-Resource-Policy</c> value.
    /// Default: <c>same-origin</c>.
    /// </summary>
    public string CrossOriginResourcePolicyValue { get; set; } = HeaderDefaults.CorpSameOrigin;

    // -------------------------------------------------------------------------
    // Cross-Origin-Embedder-Policy (COEP)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enable the <c>Cross-Origin-Embedder-Policy</c> header.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool EnableCrossOriginEmbedderPolicy { get; set; }

    /// <summary>
    /// The <c>Cross-Origin-Embedder-Policy</c> value.
    /// Default: <c>unsafe-none</c>.
    /// </summary>
    public string CrossOriginEmbedderPolicyValue { get; set; } = HeaderDefaults.CoepUnsafeNone;

    // -------------------------------------------------------------------------
    // Header removal
    // -------------------------------------------------------------------------

    /// <summary>
    /// Remove the <c>Server</c> response header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool RemoveServerHeader { get; set; } = true;

    /// <summary>
    /// Remove the <c>X-Powered-By</c> response header.
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool RemoveXPoweredByHeader { get; set; } = true;

    /// <summary>
    /// Additional response headers to remove.
    /// </summary>
    public IList<string> RemoveHeaders { get; set; } = [];

    // -------------------------------------------------------------------------
    // Custom headers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Additional custom headers to append to every response.
    /// </summary>
    public IList<CustomHeader> CustomHeaders { get; set; } = [];

    // -------------------------------------------------------------------------
    // Override behaviour
    // -------------------------------------------------------------------------

    /// <summary>
    /// When <see langword="false"/> (default), the middleware skips writing a
    /// header if the response already contains one with the same name.
    /// Set to <see langword="true"/> to always overwrite existing headers.
    /// </summary>
    public bool OverrideExistingHeaders { get; set; }
}
