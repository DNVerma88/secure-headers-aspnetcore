using FluentAssertions;
using Microsoft.AspNetCore.Http;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Options;
using Xunit;

namespace SecureHeaders.AspNetCore.Tests.Unit;

public sealed class HeaderValueCacheTests
{
    // ── HSTS ─────────────────────────────────────────────────────────────

    [Fact]
    public void HstsValue_IsNull_InDevelopment_WhenEnforceHstsIsDisabled()
    {
        var opts = new SecureHeadersOptions { EnableHsts = true, HstsMaxAge = TimeSpan.FromDays(365) };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitHsts.Should().BeFalse();
        cache.HstsValue.Should().BeNull();
    }

    [Fact]
    public void HstsValue_IsSet_InProduction()
    {
        var opts = new SecureHeadersOptions
        {
            EnableHsts = true,
            HstsMaxAge = TimeSpan.FromDays(365),
            HstsIncludeSubDomains = true,
        };
        var cache = new HeaderValueCache(opts, isProduction: true);
        cache.EmitHsts.Should().BeTrue();
        cache.HstsValue.Should().Be("max-age=31536000; includeSubDomains");
    }

    [Fact]
    public void HstsValue_IncludesPreload_WhenEnabled()
    {
        var opts = new SecureHeadersOptions
        {
            EnableHsts = true,
            HstsMaxAge = TimeSpan.FromDays(730),
            HstsIncludeSubDomains = true,
            HstsPreload = true,
        };
        var cache = new HeaderValueCache(opts, isProduction: true);
        cache.HstsValue.Should().Be("max-age=63072000; includeSubDomains; preload");
    }

    // ── CSP ──────────────────────────────────────────────────────────────

    [Fact]
    public void CspValue_IsSetWhenEnabled_AndNotReportOnly()
    {
        var policy = "default-src 'self';";
        var opts = new SecureHeadersOptions { EnableCsp = true, CspPolicy = policy };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitCsp.Should().BeTrue();
        cache.EmitCspReportOnly.Should().BeFalse();
        cache.CspValue.Should().Be(policy);
    }

    [Fact]
    public void CspReportOnlyValue_IsSet_WhenReportOnlyEnabled()
    {
        var policy = "default-src 'self';";
        var opts = new SecureHeadersOptions
        {
            EnableCsp = true,
            CspPolicy = policy,
            EnableCspReportOnly = true,
        };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitCspReportOnly.Should().BeTrue();
        cache.EmitCsp.Should().BeFalse();
        cache.CspReportOnlyValue.Should().Be(policy);
    }

    [Fact]
    public void CspValue_AppendsReportUri_WhenNotAlreadyPresent()
    {
        var opts = new SecureHeadersOptions
        {
            EnableCsp = true,
            CspPolicy = "default-src 'self'",
            CspReportUri = "https://csp.example.com/report",
        };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.CspValue.Should().Contain("report-uri https://csp.example.com/report");
    }

    [Fact]
    public void CspValue_DoesNotDuplicateReportUri_WhenAlreadyPresent()
    {
        var policy = "default-src 'self'; report-uri https://existing.example.com/;";
        var opts = new SecureHeadersOptions
        {
            EnableCsp = true,
            CspPolicy = policy,
            CspReportUri = "https://other.example.com/report",
        };
        var cache = new HeaderValueCache(opts, isProduction: false);
        // Should NOT append a second report-uri directing to the new URI
        cache.CspValue.Should().NotBeNull();
        cache.CspValue.Should().NotContain("report-uri https://other.example.com/report");
        cache.CspValue.Should().Contain("report-uri https://existing.example.com");
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\0")]
    public void CspReportUri_WithInvalidChars_ThrowsInvalidOperationException(string injection)
    {
        var opts = new SecureHeadersOptions
        {
            EnableCsp = true,
            CspPolicy = "default-src 'self'",
            CspReportUri = "https://csp.example.com/report" + injection + "X-Injected: evil",
        };
        var act = () => new HeaderValueCache(opts, isProduction: false);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*CspReportUri*");
    }

    // ── X-XSS-Protection ─────────────────────────────────────────────────

    [Fact]
    public void EmitXssProtection_IsTrue_WhenEnabled()
    {
        var opts = new SecureHeadersOptions { EnableXssProtectionHeader = true };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitXssProtection.Should().BeTrue();
        cache.XssProtectionValue.Should().Be("0");
    }

    [Fact]
    public void EmitXssProtection_IsFalse_WhenDisabled()
    {
        var opts = new SecureHeadersOptions { EnableXssProtectionHeader = false };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitXssProtection.Should().BeFalse();
    }

    // ── Reporting-Endpoints ───────────────────────────────────────────────

    [Fact]
    public void EmitReportingEndpoints_IsTrue_WhenEnabledWithValue()
    {
        var opts = new SecureHeadersOptions
        {
            EnableReportingEndpoints = true,
            ReportingEndpointsValue = "default=\"https://reporting.example.com/\"",
        };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.EmitReportingEndpoints.Should().BeTrue();
        cache.ReportingEndpointsValue.Should().Be(opts.ReportingEndpointsValue);
    }

    // ── Path exclusion ────────────────────────────────────────────────────

    [Theory]
    [InlineData("/healthz", "/healthz", true)]
    [InlineData("/healthz/live", "/healthz", true)]   // prefix match
    [InlineData("/api/data", "/healthz", false)]
    [InlineData("/HEALTHZ", "/healthz", true)]          // case-insensitive
    public void IsExcluded_MatchesExpected(string requestPath, string excludedPath, bool expected)
    {
        var opts = new SecureHeadersOptions { ExcludePaths = [excludedPath] };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.IsExcluded(new PathString(requestPath)).Should().Be(expected);
    }

    [Fact]
    public void IsExcluded_ReturnsFalse_WhenNoPathsConfigured()
    {
        var opts = new SecureHeadersOptions();
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.IsExcluded(new PathString("/anything")).Should().BeFalse();
    }

    // ── Header removal ────────────────────────────────────────────────────

    [Fact]
    public void HeadersToRemove_ContainsServer_WhenRemoveServerHeaderEnabled()
    {
        var opts = new SecureHeadersOptions { RemoveServerHeader = true };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.HeadersToRemove.Should().Contain(HeaderNames.Server);
    }

    [Fact]
    public void HeadersToRemove_ContainsXPoweredBy_WhenRemoveXPoweredByEnabled()
    {
        var opts = new SecureHeadersOptions { RemoveXPoweredByHeader = true };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.HeadersToRemove.Should().Contain(HeaderNames.XPoweredBy);
    }

    // ── Nonce ─────────────────────────────────────────────────────────────

    [Fact]
    public void CspNonceEnabled_SetsTemplate_NotStaticValue()
    {
        var opts = new SecureHeadersOptions
        {
            EnableCsp = true,
            CspPolicy = "default-src 'self' 'nonce-__nonce__';",
            EnableCspNonce = true,
        };
        var cache = new HeaderValueCache(opts, isProduction: false);
        cache.CspNonceEnabled.Should().BeTrue();
        cache.CspPolicyTemplate.Should().Contain("__nonce__");
        // Static CspValue must NOT be set when nonce is in use
        cache.CspValue.Should().BeNull();
    }
}
