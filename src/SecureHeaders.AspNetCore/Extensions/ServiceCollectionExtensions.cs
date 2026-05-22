using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Options;
using SecureHeaders.AspNetCore.Services;

namespace SecureHeaders.AspNetCore.Extensions;

/// <summary>
/// Extension methods for registering secure-header services with the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the secure headers options with default values, the startup options
    /// validator, and the per-request nonce service.
    /// </summary>
    /// <remarks>
    /// Calling this is optional when using the <c>UseSecureHeaders(Action&lt;…&gt;)</c> or
    /// preset overloads. Use this overload when you want to configure options via
    /// <c>appsettings.json</c>, <see cref="IConfigureOptions{TOptions}"/>, or when
    /// <see cref="SecureHeadersOptions.EnableCspNonce"/> is <see langword="true"/>.
    /// </remarks>
    public static IServiceCollection AddSecureHeaders(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<SecureHeadersOptions>()
                .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SecureHeadersOptions>, SecureHeadersOptionsValidator>();
        services.AddSingleton<INonceService, DefaultNonceService>();
        return services;
    }

    /// <summary>
    /// Registers the secure headers options, applying the supplied configuration delegate,
    /// the startup options validator, and the per-request nonce service.
    /// </summary>
    public static IServiceCollection AddSecureHeaders(
        this IServiceCollection services,
        Action<SecureHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SecureHeadersOptions>()
                .Configure(configure)
                .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SecureHeadersOptions>, SecureHeadersOptionsValidator>();
        services.AddSingleton<INonceService, DefaultNonceService>();
        return services;
    }
}

