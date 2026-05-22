using Microsoft.AspNetCore.Http;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Internal;

/// <summary>
/// Pre-computes and caches static header values derived from <see cref="SecureHeadersOptions"/>
/// to avoid repeated string allocations on every request.
/// </summary>
internal sealed class HeaderValueCache
{
    internal readonly string? HstsValue;
    internal readonly string? CspValue;
    internal readonly string? CspReportOnlyValue;

    internal readonly bool EmitXContentTypeOptions;
    internal readonly bool EmitXFrameOptions;
    internal readonly string? XFrameOptionsValue;
    internal readonly bool EmitReferrerPolicy;
    internal readonly string? ReferrerPolicyValue;
    internal readonly bool EmitPermissionsPolicy;
    internal readonly string? PermissionsPolicyValue;
    internal readonly bool EmitCoop;
    internal readonly string? CoopValue;
    internal readonly bool EmitCorp;
    internal readonly string? CorpValue;
    internal readonly bool EmitCoep;
    internal readonly string? CoepValue;
    internal readonly bool EmitXssProtection;
    internal readonly string? XssProtectionValue;
    internal readonly bool EmitReportingEndpoints;
    internal readonly string? ReportingEndpointsValue;

    internal readonly IReadOnlyList<string> HeadersToRemove;
    internal readonly IReadOnlyList<PathString> ExcludedPaths;

    internal readonly bool OverrideExistingHeaders;

    internal readonly bool EmitHsts;
    internal readonly bool EmitCsp;
    internal readonly bool EmitCspReportOnly;

    /// <summary>
    /// When <see langword="true"/> the CSP header value must be built
    /// per-request by substituting the nonce via <see cref="Services.INonceService"/>.
    /// </summary>
    internal readonly bool CspNonceEnabled;

    /// <summary>
    /// The raw CSP policy string (may contain the <c>__nonce__</c> placeholder).
    /// Used as the template when <see cref="CspNonceEnabled"/> is true.
    /// </summary>
    internal readonly string? CspPolicyTemplate;

    internal HeaderValueCache(SecureHeadersOptions options, bool isProduction)
    {
        OverrideExistingHeaders = options.OverrideExistingHeaders;

        // HSTS
        EmitHsts = options.EnableHsts && (isProduction || options.EnforceHstsInDevelopment);
        if (EmitHsts)
        {
            var maxAge = (long)options.HstsMaxAge.TotalSeconds;
            HstsValue = options.HstsIncludeSubDomains
                ? options.HstsPreload
                    ? $"max-age={maxAge}; includeSubDomains; preload"
                    : $"max-age={maxAge}; includeSubDomains"
                : $"max-age={maxAge}";
        }

        // X-Content-Type-Options
        EmitXContentTypeOptions = options.EnableXContentTypeOptions;

        // X-Frame-Options
        EmitXFrameOptions = options.EnableXFrameOptions;
        XFrameOptionsValue = options.XFrameOptionsValue;

        // Referrer-Policy
        EmitReferrerPolicy = options.EnableReferrerPolicy;
        ReferrerPolicyValue = options.ReferrerPolicyValue;

        // CSP
        EmitCsp = options.EnableCsp && !options.EnableCspReportOnly;
        EmitCspReportOnly = options.EnableCsp && options.EnableCspReportOnly;
        CspNonceEnabled = options.EnableCsp && options.EnableCspNonce;

        if (options.EnableCsp)
        {
            var policy = options.CspPolicy ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(options.CspReportUri)
                && !policy.Contains("report-uri", StringComparison.OrdinalIgnoreCase))
            {
                policy = policy.TrimEnd(' ', ';') + $"; report-uri {options.CspReportUri};";
            }

            if (CspNonceEnabled)
            {
                // Store as template; nonce substitution happens per-request in middleware.
                CspPolicyTemplate = policy;
            }
            else if (options.EnableCspReportOnly)
            {
                CspReportOnlyValue = policy;
            }
            else
            {
                CspValue = policy;
            }
        }

        // Permissions-Policy
        EmitPermissionsPolicy = options.EnablePermissionsPolicy;
        PermissionsPolicyValue = options.PermissionsPolicyValue;

        // COOP
        EmitCoop = options.EnableCrossOriginOpenerPolicy;
        CoopValue = options.CrossOriginOpenerPolicyValue;

        // CORP
        EmitCorp = options.EnableCrossOriginResourcePolicy;
        CorpValue = options.CrossOriginResourcePolicyValue;

        // COEP
        EmitCoep = options.EnableCrossOriginEmbedderPolicy;
        CoepValue = options.CrossOriginEmbedderPolicyValue;

        // X-XSS-Protection
        EmitXssProtection = options.EnableXssProtectionHeader;
        XssProtectionValue = options.XssProtectionValue;

        // Reporting-Endpoints
        EmitReportingEndpoints = options.EnableReportingEndpoints
            && !string.IsNullOrWhiteSpace(options.ReportingEndpointsValue);
        ReportingEndpointsValue = options.ReportingEndpointsValue;

        // Header removal
        var removeList = new List<string>();
        if (options.RemoveServerHeader)
            removeList.Add(HeaderNames.Server);
        if (options.RemoveXPoweredByHeader)
            removeList.Add(HeaderNames.XPoweredBy);
        foreach (var h in options.RemoveHeaders)
        {
            if (!string.IsNullOrWhiteSpace(h))
                removeList.Add(h);
        }

        HeadersToRemove = removeList;

        // Path exclusions
        var paths = new List<PathString>(options.ExcludePaths.Count);
        foreach (var p in options.ExcludePaths)
        {
            if (!string.IsNullOrWhiteSpace(p))
                paths.Add(new PathString(p));
        }

        ExcludedPaths = paths;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the supplied <paramref name="requestPath"/>
    /// matches any entry in <see cref="ExcludedPaths"/> (case-insensitive segment prefix).
    /// </summary>
    internal bool IsExcluded(PathString requestPath)
    {
        if (ExcludedPaths.Count == 0) return false;

        foreach (var excluded in ExcludedPaths)
        {
            if (requestPath.StartsWithSegments(excluded, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
