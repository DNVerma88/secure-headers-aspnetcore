namespace SecureHeaders.AspNetCore.Presets;

/// <summary>
/// Built-in security header configuration presets.
/// </summary>
public enum SecurityHeaderPreset
{
    /// <summary>
    /// Safe production defaults suitable for most web applications.
    /// Enables HSTS (production only), X-Content-Type-Options, X-Frame-Options,
    /// Referrer-Policy, Permissions-Policy, and CORP.
    /// </summary>
    Basic = 0,

    /// <summary>
    /// Optimised for JSON APIs. Enables HSTS, X-Content-Type-Options,
    /// Referrer-Policy, CORP, and COOP. Omits X-Frame-Options and CSP
    /// directives that are browser-oriented.
    /// </summary>
    ApiOnly = 1,

    /// <summary>
    /// React / Angular / Vue SPA-friendly profile. Enables common headers
    /// while avoiding settings that break SPA asset loading, WASM, or
    /// common CDN patterns (e.g. keeps COEP as unsafe-none).
    /// </summary>
    Spa = 2,

    /// <summary>
    /// Strictest available isolation. Enables all headers with the most
    /// restrictive values including HSTS preload, COOP same-origin,
    /// COEP require-corp, strict Permissions-Policy, and a restrictive
    /// default CSP policy.
    /// </summary>
    Strict = 3,
}
