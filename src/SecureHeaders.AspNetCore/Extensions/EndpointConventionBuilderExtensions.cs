using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Options;
using SecureHeaders.AspNetCore.Presets;

namespace SecureHeaders.AspNetCore.Extensions;

/// <summary>
/// Extension methods for applying secure headers to individual Minimal API endpoints
/// without adding the middleware to the entire pipeline.
/// </summary>
/// <example>
/// <code>
/// app.MapGet("/api/data", () => Results.Ok(data))
///    .WithSecureHeaders(SecurityHeaderPreset.ApiOnly);
///
/// app.MapGet("/ui", () => Results.Ok())
///    .WithSecureHeaders(opts => opts.EnableCsp = true);
/// </code>
/// </example>
public static class EndpointConventionBuilderExtensions
{
    /// <summary>
    /// Applies the specified security-header preset to this endpoint.
    /// </summary>
    public static TBuilder WithSecureHeaders<TBuilder>(
        this TBuilder builder,
        SecurityHeaderPreset preset = SecurityHeaderPreset.Basic)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        var options = PresetFactory.CreateOptions(preset);
        return AddSecureHeadersViaFinally(builder, options);
    }

    /// <summary>
    /// Applies security headers configured by the supplied delegate to this endpoint.
    /// </summary>
    public static TBuilder WithSecureHeaders<TBuilder>(
        this TBuilder builder,
        Action<SecureHeadersOptions> configure)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new SecureHeadersOptions();
        configure(options);
        return AddSecureHeadersViaFinally(builder, options);
    }

    private static TBuilder AddSecureHeadersViaFinally<TBuilder>(
        TBuilder builder,
        SecureHeadersOptions options)
        where TBuilder : IEndpointConventionBuilder
    {
        // Use Finally so the RequestDelegate is already compiled when we wrap it.
        builder.Finally(endpointBuilder =>
        {
            var originalDelegate = endpointBuilder.RequestDelegate;
            if (originalDelegate is null)
                return;

            endpointBuilder.RequestDelegate = async context =>
            {
                context.Response.OnStarting(() =>
                {
                    var env = context.RequestServices.GetRequiredService<IWebHostEnvironment>();
                    var cache = new HeaderValueCache(options, env.IsProduction());
                    SecureHeadersApplicator.Apply(
                        context.Response.Headers,
                        cache,
                        [],
                        context);
                    return Task.CompletedTask;
                });
                await originalDelegate(context);
            };
        });
        return builder;
    }
}
