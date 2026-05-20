using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Models;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Middleware;

/// <summary>
/// ASP.NET Core middleware that adds security-related HTTP response headers to every response.
/// </summary>
public sealed class SecureHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HeaderValueCache _cache;
    private readonly IReadOnlyList<CustomHeader> _customHeaders;

    /// <summary>
    /// Initializes a new instance of <see cref="SecureHeadersMiddleware"/>.
    /// </summary>
    public SecureHeadersMiddleware(
        RequestDelegate next,
        IOptions<SecureHeadersOptions> options,
        IWebHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(environment);

        _next = next;
        var opts = options.Value;
        bool isProduction = environment.IsProduction();
        _cache = new HeaderValueCache(opts, isProduction);
        _customHeaders = [.. opts.CustomHeaders];
    }

    /// <summary>
    /// Processes the HTTP request, adds security headers, then calls the next middleware.
    /// </summary>
    public Task InvokeAsync(HttpContext context)
    {
        // Register a callback so headers are written before the response body starts.
        context.Response.OnStarting(ApplyHeaders, context);
        return _next(context);
    }

    private Task ApplyHeaders(object state)
    {
        var context = (HttpContext)state;
        var headers = context.Response.Headers;

        // Remove unwanted informational headers first.
        foreach (var name in _cache.HeadersToRemove)
            headers.Remove(name);

        // Write security headers.
        SetHeader(headers, HeaderNames.StrictTransportSecurity, _cache.HstsValue, _cache.EmitHsts);
        SetHeader(headers, HeaderNames.XContentTypeOptions, HeaderDefaults.XContentTypeOptionsValue, _cache.EmitXContentTypeOptions);
        SetHeader(headers, HeaderNames.XFrameOptions, _cache.XFrameOptionsValue, _cache.EmitXFrameOptions);
        SetHeader(headers, HeaderNames.ReferrerPolicy, _cache.ReferrerPolicyValue, _cache.EmitReferrerPolicy);
        SetHeader(headers, HeaderNames.PermissionsPolicy, _cache.PermissionsPolicyValue, _cache.EmitPermissionsPolicy);
        SetHeader(headers, HeaderNames.CrossOriginOpenerPolicy, _cache.CoopValue, _cache.EmitCoop);
        SetHeader(headers, HeaderNames.CrossOriginResourcePolicy, _cache.CorpValue, _cache.EmitCorp);
        SetHeader(headers, HeaderNames.CrossOriginEmbedderPolicy, _cache.CoepValue, _cache.EmitCoep);
        SetHeader(headers, HeaderNames.ContentSecurityPolicy, _cache.CspValue, _cache.EmitCsp);
        SetHeader(headers, HeaderNames.ContentSecurityPolicyReportOnly, _cache.CspReportOnlyValue, _cache.EmitCspReportOnly);

        // Custom headers.
        for (int i = 0; i < _customHeaders.Count; i++)
        {
            var ch = _customHeaders[i];
            if (ch.Override || !headers.ContainsKey(ch.Name))
                headers[ch.Name] = ch.Value;
        }

        return Task.CompletedTask;
    }

    private void SetHeader(IHeaderDictionary headers, string name, string? value, bool enabled)
    {
        if (!enabled || value is null)
            return;

        if (!_cache.OverrideExistingHeaders && headers.ContainsKey(name))
            return;

        headers[name] = value;
    }
}
