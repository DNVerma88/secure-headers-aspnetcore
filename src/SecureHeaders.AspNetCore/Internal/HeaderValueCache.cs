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

    internal readonly bool RemoveServerHeader;
    internal readonly bool RemoveXPoweredByHeader;
    internal readonly IReadOnlyList<string> HeadersToRemove;

    internal readonly bool OverrideExistingHeaders;

    internal readonly bool EmitHsts;
    internal readonly bool EmitCsp;
    internal readonly bool EmitCspReportOnly;

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

        if (options.EnableCsp)
        {
            var policy = options.CspPolicy ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(options.CspReportUri)
                && !policy.Contains("report-uri", StringComparison.OrdinalIgnoreCase))
            {
                policy = policy.TrimEnd(' ', ';') + $"; report-uri {options.CspReportUri};";
            }

            if (options.EnableCspReportOnly)
                CspReportOnlyValue = policy;
            else
                CspValue = policy;
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

        // Header removal
        RemoveServerHeader = options.RemoveServerHeader;
        RemoveXPoweredByHeader = options.RemoveXPoweredByHeader;

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
    }
}
