using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Models;
using SecureHeaders.AspNetCore.Services;

namespace SecureHeaders.AspNetCore.Internal;

/// <summary>
/// Shared logic for writing security headers to an <see cref="IHeaderDictionary"/>.
/// Used by both <see cref="Middleware.SecureHeadersMiddleware"/> and
/// <see cref="Extensions.EndpointConventionBuilderExtensions"/>.
/// </summary>
internal static class SecureHeadersApplicator
{
    /// <summary>
    /// Applies all enabled security headers and removes unwanted headers.
    /// </summary>
    internal static void Apply(
        IHeaderDictionary headers,
        HeaderValueCache cache,
        IReadOnlyList<CustomHeader> customHeaders,
        HttpContext context,
        ILogger? logger = null)
    {
        // ── Remove informational headers ──────────────────────────────────────
        foreach (var name in cache.HeadersToRemove)
        {
            if (headers.Remove(name))
                logger?.LogTrace("Removed response header: {HeaderName}", name);
        }

        // ── Static security headers ───────────────────────────────────────────
        SetHeader(headers, HeaderNames.StrictTransportSecurity, cache.HstsValue, cache.EmitHsts, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.XContentTypeOptions, HeaderDefaults.XContentTypeOptionsValue, cache.EmitXContentTypeOptions, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.XFrameOptions, cache.XFrameOptionsValue, cache.EmitXFrameOptions, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.ReferrerPolicy, cache.ReferrerPolicyValue, cache.EmitReferrerPolicy, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.PermissionsPolicy, cache.PermissionsPolicyValue, cache.EmitPermissionsPolicy, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.CrossOriginOpenerPolicy, cache.CoopValue, cache.EmitCoop, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.CrossOriginResourcePolicy, cache.CorpValue, cache.EmitCorp, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.CrossOriginEmbedderPolicy, cache.CoepValue, cache.EmitCoep, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.XXssProtection, cache.XssProtectionValue, cache.EmitXssProtection, cache.OverrideExistingHeaders, logger);
        SetHeader(headers, HeaderNames.ReportingEndpoints, cache.ReportingEndpointsValue, cache.EmitReportingEndpoints, cache.OverrideExistingHeaders, logger);

        // ── CSP (static or nonce-enabled per-request) ─────────────────────────
        if (cache.CspNonceEnabled)
        {
            var nonceService = context.RequestServices.GetService<INonceService>();
            if (nonceService is not null && cache.CspPolicyTemplate is not null)
            {
                var nonce = nonceService.GetNonce(context);
                var cspValue = cache.CspPolicyTemplate.Replace(INonceService.Placeholder, nonce,
                    StringComparison.Ordinal);

                var headerName = cache.EmitCspReportOnly
                    ? HeaderNames.ContentSecurityPolicyReportOnly
                    : HeaderNames.ContentSecurityPolicy;

                SetHeader(headers, headerName, cspValue, enabled: true, cache.OverrideExistingHeaders, logger);
                logger?.LogTrace("Applied nonce-enabled CSP header: {HeaderName}", headerName);
            }
            else if (nonceService is null)
            {
                logger?.LogWarning(
                    "EnableCspNonce is true but {ServiceName} is not registered in DI. " +
                    "Call builder.Services.AddSecureHeaders() to register it. " +
                    "The CSP header will be skipped for this request.",
                    nameof(INonceService));
            }
        }
        else
        {
            SetHeader(headers, HeaderNames.ContentSecurityPolicy, cache.CspValue, cache.EmitCsp, cache.OverrideExistingHeaders, logger);
            SetHeader(headers, HeaderNames.ContentSecurityPolicyReportOnly, cache.CspReportOnlyValue, cache.EmitCspReportOnly, cache.OverrideExistingHeaders, logger);
        }

        // ── Custom headers ────────────────────────────────────────────────────
        for (var i = 0; i < customHeaders.Count; i++)
        {
            var ch = customHeaders[i];
            if (ch.Override || !headers.ContainsKey(ch.Name))
            {
                headers[ch.Name] = ch.Value;
                logger?.LogTrace("Applied custom header: {HeaderName}", ch.Name);
            }
        }
    }

    private static void SetHeader(
        IHeaderDictionary headers,
        string name,
        string? value,
        bool enabled,
        bool overrideExisting,
        ILogger? logger)
    {
        if (!enabled || value is null) return;

        if (!overrideExisting && headers.ContainsKey(name))
        {
            logger?.LogTrace("Skipped header {HeaderName}: already present and OverrideExistingHeaders is false.", name);
            return;
        }

        headers[name] = value;
        logger?.LogTrace("Set response header: {HeaderName}", name);
    }
}
