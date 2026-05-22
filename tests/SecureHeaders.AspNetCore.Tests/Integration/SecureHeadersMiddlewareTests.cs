using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Extensions;
using SecureHeaders.AspNetCore.Options;
using SecureHeaders.AspNetCore.Presets;
using System.Net.Http;
using Xunit;

namespace SecureHeaders.AspNetCore.Tests.Integration;

public sealed class SecureHeadersMiddlewareTests
{
    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static async Task<HttpResponseMessage> SendRequestAsync(
        Action<SecureHeadersOptions>? configure = null,
        SecurityHeaderPreset? preset = null,
        bool isProduction = true)
    {
        var env = isProduction ? Environments.Production : Environments.Development;

        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(env);
                webHost.ConfigureServices(services =>
                {
                    services.AddSecureHeaders();
                });
                webHost.Configure(app =>
                {
                    if (preset.HasValue && configure is not null)
                        app.UseSecureHeaders(preset.Value, configure);
                    else if (preset.HasValue)
                        app.UseSecureHeaders(preset.Value);
                    else if (configure is not null)
                        app.UseSecureHeaders(configure);
                    else
                        app.UseSecureHeaders();

                    app.Run(ctx =>
                    {
                        ctx.Response.StatusCode = 200;
                        return Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        return await client.GetAsync("/");
    }

    private static IEnumerable<string> GetHeaderValues(HttpResponseMessage response, string headerName)
    {
        try
        {
            if (response.Headers.TryGetValues(headerName, out var values))
                return values;
        }
        catch (InvalidOperationException) { }

        try
        {
            if (response.Content.Headers.TryGetValues(headerName, out var contentValues))
                return contentValues;
        }
        catch (InvalidOperationException) { }

        return [];
    }

    private static bool HasHeader(HttpResponseMessage response, string headerName)
    {
        try
        {
            if (response.Headers.TryGetValues(headerName, out var vals) && vals.Any())
                return true;
        }
        catch (InvalidOperationException) { }

        try
        {
            if (response.Content.Headers.TryGetValues(headerName, out var cVals) && cVals.Any())
                return true;
        }
        catch (InvalidOperationException) { }

        return false;
    }

    // -------------------------------------------------------------------------
    // Default behaviour
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Default_XContentTypeOptions_IsNoSniff()
    {
        var response = await SendRequestAsync();
        HasHeader(response, HeaderNames.XContentTypeOptions).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.XContentTypeOptions).Should().Contain("nosniff");
    }

    [Fact]
    public async Task Default_XFrameOptions_IsSameOrigin()
    {
        var response = await SendRequestAsync();
        HasHeader(response, HeaderNames.XFrameOptions).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.XFrameOptions).Should().Contain("SAMEORIGIN");
    }

    [Fact]
    public async Task Default_ReferrerPolicy_IsStrictOriginWhenCrossOrigin()
    {
        var response = await SendRequestAsync();
        HasHeader(response, HeaderNames.ReferrerPolicy).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.ReferrerPolicy)
            .Should().Contain("strict-origin-when-cross-origin");
    }

    [Fact]
    public async Task Default_HstsPresent_InProduction()
    {
        var response = await SendRequestAsync(isProduction: true);
        HasHeader(response, HeaderNames.StrictTransportSecurity).Should().BeTrue();
    }

    [Fact]
    public async Task Default_HstsAbsent_InDevelopment()
    {
        var response = await SendRequestAsync(isProduction: false);
        HasHeader(response, HeaderNames.StrictTransportSecurity).Should().BeFalse();
    }

    [Fact]
    public async Task Default_CspAbsent_ByDefault()
    {
        var response = await SendRequestAsync();
        HasHeader(response, HeaderNames.ContentSecurityPolicy).Should().BeFalse();
    }

    [Fact]
    public async Task Default_ServerHeader_IsRemoved()
    {
        var response = await SendRequestAsync();
        // Server is a typed header on HttpResponseHeaders — check via the typed collection
        response.Headers.Server.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // CSP
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Csp_EnforcingHeader_WhenEnabled()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "default-src 'self'";
        });

        HasHeader(response, HeaderNames.ContentSecurityPolicy).Should().BeTrue();
        HasHeader(response, HeaderNames.ContentSecurityPolicyReportOnly).Should().BeFalse();
    }

    [Fact]
    public async Task Csp_ReportOnlyHeader_WhenReportOnlyEnabled()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableCsp = true;
            o.EnableCspReportOnly = true;
            o.CspPolicy = "default-src 'self'";
        });

        HasHeader(response, HeaderNames.ContentSecurityPolicy).Should().BeFalse();
        HasHeader(response, HeaderNames.ContentSecurityPolicyReportOnly).Should().BeTrue();
    }

    [Fact]
    public async Task Csp_ReportUri_IsAppendedAutomatically()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "default-src 'self'";
            o.CspReportUri = "/csp-report";
        });

        var cspValue = GetHeaderValues(response, HeaderNames.ContentSecurityPolicy).Single();
        cspValue.Should().Contain("report-uri /csp-report");
    }

    // -------------------------------------------------------------------------
    // HSTS
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Hsts_EnforceInDevelopment_WhenEnabled()
    {
        var response = await SendRequestAsync(
            o => o.EnforceHstsInDevelopment = true,
            isProduction: false);

        HasHeader(response, HeaderNames.StrictTransportSecurity).Should().BeTrue();
    }

    [Fact]
    public async Task Hsts_ContainsPreload_WhenEnabled()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableHsts = true;
            o.HstsPreload = true;
            o.HstsIncludeSubDomains = true;
        });

        var value = GetHeaderValues(response, HeaderNames.StrictTransportSecurity).Single();
        value.Should().Contain("preload");
        value.Should().Contain("includeSubDomains");
    }

    // -------------------------------------------------------------------------
    // Override / preserve existing headers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ExistingHeader_IsPreserved_WhenOverrideDisabled()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s => s.AddSecureHeaders());
                webHost.Configure(app =>
                {
                    app.UseSecureHeaders(o => o.OverrideExistingHeaders = false);
                    app.Run(async ctx =>
                    {
                        ctx.Response.Headers[HeaderNames.XFrameOptions] = "DENY";
                        ctx.Response.StatusCode = 200;
                        await Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/");

        var values = GetHeaderValues(response, HeaderNames.XFrameOptions).ToList();
        values.Should().ContainSingle();
        values.Single().Should().Be("DENY");
    }

    [Fact]
    public async Task ExistingHeader_IsOverwritten_WhenOverrideEnabled()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s => s.AddSecureHeaders());
                webHost.Configure(app =>
                {
                    app.UseSecureHeaders(o =>
                    {
                        o.OverrideExistingHeaders = true;
                        o.EnableXFrameOptions = true;
                        o.XFrameOptionsValue = "SAMEORIGIN";
                    });
                    app.Run(async ctx =>
                    {
                        ctx.Response.Headers[HeaderNames.XFrameOptions] = "DENY";
                        ctx.Response.StatusCode = 200;
                        await Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/");

        var values = GetHeaderValues(response, HeaderNames.XFrameOptions).ToList();
        values.Should().ContainSingle();
        values.Single().Should().Be("SAMEORIGIN");
    }

    // -------------------------------------------------------------------------
    // No duplicate headers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Headers_AreNotDuplicated()
    {
        var response = await SendRequestAsync();

        foreach (var header in response.Headers)
        {
            header.Value.Should().HaveCount(1,
                $"header '{header.Key}' should not appear more than once");
        }
    }

    // -------------------------------------------------------------------------
    // Custom headers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CustomHeader_IsAdded()
    {
        var response = await SendRequestAsync(o =>
        {
            o.CustomHeaders.Add(new Models.CustomHeader("X-Tenant", "acme-corp"));
        });

        HasHeader(response, "X-Tenant").Should().BeTrue();
        GetHeaderValues(response, "X-Tenant").Should().Contain("acme-corp");
    }

    // -------------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(SecurityHeaderPreset.Basic)]
    [InlineData(SecurityHeaderPreset.ApiOnly)]
    [InlineData(SecurityHeaderPreset.Spa)]
    [InlineData(SecurityHeaderPreset.Strict)]
    public async Task AllPresets_ReturnSuccessResponse(SecurityHeaderPreset preset)
    {
        var response = await SendRequestAsync(preset: preset);
        response.IsSuccessStatusCode.Should().BeTrue();
    }

    [Fact]
    public async Task Preset_Strict_HasCsp()
    {
        var response = await SendRequestAsync(preset: SecurityHeaderPreset.Strict);
        HasHeader(response, HeaderNames.ContentSecurityPolicy).Should().BeTrue();
    }

    [Fact]
    public async Task Preset_ApiOnly_NoXFrameOptions()
    {
        var response = await SendRequestAsync(preset: SecurityHeaderPreset.ApiOnly);
        HasHeader(response, HeaderNames.XFrameOptions).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Header removal
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RemoveHeaders_AreMissing()
    {
        var response = await SendRequestAsync(o =>
        {
            o.RemoveHeaders.Add("X-Custom-Remove-Me");
        });

        HasHeader(response, "X-Custom-Remove-Me").Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Cross-Origin headers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Corp_IsPresent_WhenEnabled()
    {
        var response = await SendRequestAsync();
        HasHeader(response, HeaderNames.CrossOriginResourcePolicy).Should().BeTrue();
    }

    [Fact]
    public async Task Coop_IsPresent_WhenEnabled()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableCrossOriginOpenerPolicy = true;
            o.CrossOriginOpenerPolicyValue = "same-origin";
        });

        HasHeader(response, HeaderNames.CrossOriginOpenerPolicy).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.CrossOriginOpenerPolicy).Should().Contain("same-origin");
    }

    [Fact]
    public async Task Coep_IsPresent_WhenEnabled()
    {
        var response = await SendRequestAsync(o =>
        {
            o.EnableCrossOriginEmbedderPolicy = true;
            o.CrossOriginEmbedderPolicyValue = "require-corp";
        });

        HasHeader(response, HeaderNames.CrossOriginEmbedderPolicy).Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // X-XSS-Protection
    // -------------------------------------------------------------------------

    [Fact]
    public async Task XssProtection_IsZero_WhenEnabled()
    {
        var response = await SendRequestAsync(o => o.EnableXssProtectionHeader = true);
        HasHeader(response, HeaderNames.XXssProtection).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.XXssProtection).Should().Contain("0");
    }

    [Fact]
    public async Task XssProtection_IsAbsent_WhenDisabled()
    {
        var response = await SendRequestAsync(o => o.EnableXssProtectionHeader = false);
        HasHeader(response, HeaderNames.XXssProtection).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Reporting-Endpoints
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ReportingEndpoints_IsPresent_WhenEnabled()
    {
        const string endpointsValue = "default=\"https://reporting.example.com/\"";
        var response = await SendRequestAsync(o =>
        {
            o.EnableReportingEndpoints = true;
            o.ReportingEndpointsValue = endpointsValue;
        });

        HasHeader(response, HeaderNames.ReportingEndpoints).Should().BeTrue();
        GetHeaderValues(response, HeaderNames.ReportingEndpoints).Should().Contain(endpointsValue);
    }

    [Fact]
    public async Task ReportingEndpoints_IsAbsent_WhenDisabled()
    {
        var response = await SendRequestAsync(o => o.EnableReportingEndpoints = false);
        HasHeader(response, HeaderNames.ReportingEndpoints).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Path exclusion
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ExcludedPath_DoesNotReceiveSecureHeaders()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s => s.AddSecureHeaders());
                webHost.Configure(app =>
                {
                    app.UseSecureHeaders(o =>
                    {
                        o.EnableXContentTypeOptions = true;
                        o.ExcludePaths.Add("/healthz");
                    });
                    app.Run(ctx =>
                    {
                        ctx.Response.StatusCode = 200;
                        return Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/healthz");

        HasHeader(response, HeaderNames.XContentTypeOptions).Should().BeFalse();
    }

    [Fact]
    public async Task NonExcludedPath_ReceivesSecureHeaders_EvenWhenOtherPathsExcluded()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s => s.AddSecureHeaders());
                webHost.Configure(app =>
                {
                    app.UseSecureHeaders(o =>
                    {
                        o.EnableXContentTypeOptions = true;
                        o.ExcludePaths.Add("/healthz");
                    });
                    app.Run(ctx =>
                    {
                        ctx.Response.StatusCode = 200;
                        return Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/api/data");

        HasHeader(response, HeaderNames.XContentTypeOptions).Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // CSP Nonce
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CspNonce_IsSubstituted_InCspHeader()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Development);
                webHost.ConfigureServices(s =>
                {
                    s.AddSecureHeaders(o =>
                    {
                        o.EnableCsp = true;
                        o.CspPolicy = "script-src 'nonce-__nonce__';";
                        o.EnableCspNonce = true;
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseSecureHeaders();
                    app.Run(ctx =>
                    {
                        ctx.Response.StatusCode = 200;
                        return Task.CompletedTask;
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response1 = await client.GetAsync("/");
        var response2 = await client.GetAsync("/");

        var csp1 = GetHeaderValues(response1, HeaderNames.ContentSecurityPolicy).Single();
        var csp2 = GetHeaderValues(response2, HeaderNames.ContentSecurityPolicy).Single();

        // Nonce placeholder must be replaced
        csp1.Should().NotContain("__nonce__");
        csp2.Should().NotContain("__nonce__");

        // Each request must get a different nonce (probabilistic but base64-32-byte is unique)
        csp1.Should().NotBe(csp2);
    }

    // -------------------------------------------------------------------------
    // WithSecureHeaders endpoint filter
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithSecureHeaders_EndpointFilter_AppliesHeaders()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddSecureHeaders();
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", async ctx =>
                        {
                            ctx.Response.StatusCode = 200;
                            await ctx.Response.WriteAsync("ok");
                        }).WithSecureHeaders(SecurityHeaderPreset.ApiOnly);
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/secure");

        HasHeader(response, HeaderNames.XContentTypeOptions).Should().BeTrue();
    }

    [Fact]
    public async Task WithSecureHeaders_EndpointFilter_WithCustomOptions()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.UseEnvironment(Environments.Production);
                webHost.ConfigureServices(s =>
                {
                    s.AddRouting();
                    s.AddSecureHeaders();
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", async ctx =>
                        {
                            ctx.Response.StatusCode = 200;
                            await ctx.Response.WriteAsync("ok");
                        }).WithSecureHeaders(o =>
                                 {
                                     o.EnableCsp = true;
                                     o.CspPolicy = "default-src 'self';";
                                 });
                    });
                });
            })
            .StartAsync();

        var client = host.GetTestClient();
        var response = await client.GetAsync("/secure");

        HasHeader(response, HeaderNames.ContentSecurityPolicy).Should().BeTrue();
    }
}

