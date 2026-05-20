using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using SecureHeaders.AspNetCore.Middleware;
using SecureHeaders.AspNetCore.Options;
using SecureHeaders.AspNetCore.Presets;

namespace SecureHeaders.AspNetCore.Extensions;

/// <summary>
/// Extension methods for adding <see cref="SecureHeadersMiddleware"/> to the request pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the secure headers middleware using default <see cref="SecureHeadersOptions"/>.
    /// </summary>
    public static IApplicationBuilder UseSecureHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        EnsureOptionsRegistered(app);
        return app.UseMiddleware<SecureHeadersMiddleware>();
    }

    /// <summary>
    /// Adds the secure headers middleware with the supplied configuration delegate.
    /// The options are built directly from the delegate — no call to
    /// <c>AddSecureHeaders()</c> is required when using this overload.
    /// </summary>
    public static IApplicationBuilder UseSecureHeaders(
        this IApplicationBuilder app,
        Action<SecureHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new SecureHeadersOptions();
        configure(options);

        return app.UseMiddleware<SecureHeadersMiddleware>(
            Microsoft.Extensions.Options.Options.Create(options));
    }

    /// <summary>
    /// Adds the secure headers middleware configured for the supplied preset.
    /// </summary>
    public static IApplicationBuilder UseSecureHeaders(
        this IApplicationBuilder app,
        SecurityHeaderPreset preset)
    {
        ArgumentNullException.ThrowIfNull(app);

        var options = PresetFactory.CreateOptions(preset);
        return app.UseMiddleware<SecureHeadersMiddleware>(
            Microsoft.Extensions.Options.Options.Create(options));
    }

    /// <summary>
    /// Adds the secure headers middleware configured for the supplied preset,
    /// with additional overrides applied via <paramref name="configure"/>.
    /// </summary>
    public static IApplicationBuilder UseSecureHeaders(
        this IApplicationBuilder app,
        SecurityHeaderPreset preset,
        Action<SecureHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(configure);

        var options = PresetFactory.CreateOptions(preset);
        configure(options);
        return app.UseMiddleware<SecureHeadersMiddleware>(
            Microsoft.Extensions.Options.Options.Create(options));
    }

    private static void EnsureOptionsRegistered(IApplicationBuilder app)
    {
        // Ensure IOptions<SecureHeadersOptions> is resolvable. If the caller already
        // called AddSecureHeaders() on the service collection this is a no-op.
        var optionsService = app.ApplicationServices
            .GetService<Microsoft.Extensions.Options.IOptions<SecureHeadersOptions>>();

        if (optionsService is null)
        {
            throw new InvalidOperationException(
                "SecureHeaders services are not registered. Call builder.Services.AddSecureHeaders() before app.UseSecureHeaders().");
        }
    }
}
