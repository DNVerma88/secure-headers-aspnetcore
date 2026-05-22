namespace SecureHeaders.AspNetCore.Constants;

/// <summary>
/// Well-known HTTP security header names.
/// </summary>
public static class HeaderNames
{
    /// <summary>Strict-Transport-Security</summary>
    public const string StrictTransportSecurity = "Strict-Transport-Security";

    /// <summary>X-Content-Type-Options</summary>
    public const string XContentTypeOptions = "X-Content-Type-Options";

    /// <summary>X-Frame-Options</summary>
    public const string XFrameOptions = "X-Frame-Options";

    /// <summary>Referrer-Policy</summary>
    public const string ReferrerPolicy = "Referrer-Policy";

    /// <summary>Content-Security-Policy</summary>
    public const string ContentSecurityPolicy = "Content-Security-Policy";

    /// <summary>Content-Security-Policy-Report-Only</summary>
    public const string ContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only";

    /// <summary>Permissions-Policy</summary>
    public const string PermissionsPolicy = "Permissions-Policy";

    /// <summary>Cross-Origin-Opener-Policy</summary>
    public const string CrossOriginOpenerPolicy = "Cross-Origin-Opener-Policy";

    /// <summary>Cross-Origin-Resource-Policy</summary>
    public const string CrossOriginResourcePolicy = "Cross-Origin-Resource-Policy";

    /// <summary>Cross-Origin-Embedder-Policy</summary>
    public const string CrossOriginEmbedderPolicy = "Cross-Origin-Embedder-Policy";

    /// <summary>Server</summary>
    public const string Server = "Server";

    /// <summary>X-Powered-By</summary>
    public const string XPoweredBy = "X-Powered-By";

    /// <summary>X-XSS-Protection</summary>
    public const string XXssProtection = "X-XSS-Protection";

    /// <summary>Reporting-Endpoints</summary>
    public const string ReportingEndpoints = "Reporting-Endpoints";
}
