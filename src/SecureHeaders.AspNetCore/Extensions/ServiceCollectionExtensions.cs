using Microsoft.Extensions.DependencyInjection;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Extensions;

/// <summary>
/// Extension methods for registering secure-header services with the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the secure headers options with default values.
    /// </summary>
    /// <remarks>
    /// Calling this is optional — <c>app.UseSecureHeaders()</c> will register the services
    /// automatically if they have not already been registered. Use this overload when you
    /// want to configure options via <c>appsettings.json</c> or other
    /// <see cref="Microsoft.Extensions.Options.IConfigureOptions{TOptions}"/> mechanisms.
    /// </remarks>
    public static IServiceCollection AddSecureHeaders(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddOptions<SecureHeadersOptions>();
        return services;
    }

    /// <summary>
    /// Registers the secure headers options, applying the supplied configuration delegate.
    /// </summary>
    public static IServiceCollection AddSecureHeaders(
        this IServiceCollection services,
        Action<SecureHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SecureHeadersOptions>().Configure(configure);
        return services;
    }
}
