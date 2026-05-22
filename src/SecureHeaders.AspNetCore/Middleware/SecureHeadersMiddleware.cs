using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Models;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Middleware;

/// <summary>
/// ASP.NET Core middleware that adds security-related HTTP response headers to every response.
/// Paths listed in <see cref="SecureHeadersOptions.ExcludePaths"/> are passed through unchanged.
/// </summary>
public sealed class SecureHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HeaderValueCache _cache;
    private readonly IReadOnlyList<CustomHeader> _customHeaders;
    private readonly ILogger<SecureHeadersMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="SecureHeadersMiddleware"/>.
    /// </summary>
    public SecureHeadersMiddleware(
        RequestDelegate next,
        IOptions<SecureHeadersOptions> options,
        IWebHostEnvironment environment,
        ILogger<SecureHeadersMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(logger);

        _next = next;
        _logger = logger;
        var opts = options.Value;
        var isProduction = environment.IsProduction();
        _cache = new HeaderValueCache(opts, isProduction);
        // Snapshot the list at construction time; runtime mutations to options have no effect.
        _customHeaders = [.. opts.CustomHeaders];
    }

    /// <summary>
    /// Processes the HTTP request, adds security headers, then calls the next middleware.
    /// Skips header injection for paths that match <see cref="SecureHeadersOptions.ExcludePaths"/>.
    /// </summary>
    public Task InvokeAsync(HttpContext context)
    {
        if (_cache.IsExcluded(context.Request.Path))
        {
            _logger.LogTrace(
                "SecureHeaders: skipping path {Path} (matched ExcludePaths).",
                context.Request.Path);
            return _next(context);
        }

        // Register callback before passing control downstream so headers are
        // written just before the response body starts.
        context.Response.OnStarting(ApplyHeaders, context);
        return _next(context);
    }

    private Task ApplyHeaders(object state)
    {
        var context = (HttpContext)state;
        _logger.LogTrace("SecureHeaders: applying headers for {Path}.", context.Request.Path);
        SecureHeadersApplicator.Apply(
            context.Response.Headers,
            _cache,
            _customHeaders,
            context,
            _logger);
        return Task.CompletedTask;
    }
}

