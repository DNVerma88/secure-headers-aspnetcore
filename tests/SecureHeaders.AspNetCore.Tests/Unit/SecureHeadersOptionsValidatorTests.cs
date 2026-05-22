using FluentAssertions;
using Microsoft.Extensions.Options;
using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Internal;
using SecureHeaders.AspNetCore.Options;
using Xunit;

namespace SecureHeaders.AspNetCore.Tests.Unit;

public sealed class SecureHeadersOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(Action<SecureHeadersOptions> configure)
    {
        var opts = new SecureHeadersOptions();
        configure(opts);
        var validator = new SecureHeadersOptionsValidator();
        return validator.Validate(null, opts);
    }

    [Fact]
    public void ValidOptions_ShouldSucceed()
    {
        var result = Validate(_ => { });
        result.Succeeded.Should().BeTrue();
    }

    // ── HSTS ─────────────────────────────────────────────────────────────

    [Fact]
    public void HstsMaxAge_Zero_ShouldFail()
    {
        var result = Validate(o =>
        {
            o.EnableHsts = true;
            o.HstsMaxAge = TimeSpan.Zero;
        });
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("HstsMaxAge");
    }

    [Fact]
    public void HstsPreload_WithoutIncludeSubDomains_ShouldFail()
    {
        var result = Validate(o =>
        {
            o.EnableHsts = true;
            o.HstsPreload = true;
            o.HstsIncludeSubDomains = false;
            o.HstsMaxAge = TimeSpan.FromDays(365);
        });
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("HstsIncludeSubDomains");
    }

    [Fact]
    public void HstsPreload_WithMaxAgeLessThanOneYear_ShouldFail()
    {
        var result = Validate(o =>
        {
            o.EnableHsts = true;
            o.HstsPreload = true;
            o.HstsIncludeSubDomains = true;
            o.HstsMaxAge = TimeSpan.FromDays(100); // < 365 days
        });
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("31,536,000");
    }

    // ── CSP ──────────────────────────────────────────────────────────────

    [Fact]
    public void EnableCsp_WithEmptyPolicy_ShouldFail()
    {
        var result = Validate(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = string.Empty;
        });
        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("CspPolicy");
    }

    [Fact]
    public void EnableCsp_WithWhitespacePolicy_ShouldFail()
    {
        var result = Validate(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "   ";
        });
        result.Failed.Should().BeTrue();
    }

    [Fact]
    public void EnableCsp_WithValidPolicy_ShouldSucceed()
    {
        var result = Validate(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "default-src 'self';";
        });
        result.Succeeded.Should().BeTrue();
    }

    // ── CRLF injection on string properties ──────────────────────────────

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\0")]
    public void CspPolicy_WithInvalidChars_ShouldFail(string injection)
    {
        var result = Validate(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "default-src 'self'" + injection;
        });
        result.Failed.Should().BeTrue();
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    public void ReferrerPolicyValue_WithInvalidChars_ShouldFail(string injection)
    {
        var result = Validate(o =>
        {
            o.EnableReferrerPolicy = true;
            o.ReferrerPolicyValue = HeaderDefaults.ReferrerPolicyStrictOriginWhenCrossOrigin + injection;
        });
        result.Failed.Should().BeTrue();
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\0")]
    public void CspReportUri_WithInvalidChars_ShouldFail(string injection)
    {
        var result = Validate(o =>
        {
            o.EnableCsp = true;
            o.CspPolicy = "default-src 'self';";
            o.CspReportUri = "https://reports.example.com/csp" + injection + "X-Injected: evil";
        });
        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains(nameof(SecureHeadersOptions.CspReportUri)));
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    public void CustomHeaders_WithInvalidCharsInName_ShouldThrow(string injection)
    {
        // CRLF in CustomHeader name/value is caught in the constructor.
        var act = () => new Models.CustomHeader("X-Safe" + injection, "value");
        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("\r")]
    [InlineData("\n")]
    public void CustomHeaders_WithInvalidCharsInValue_ShouldThrow(string injection)
    {
        var act = () => new Models.CustomHeader("X-Safe", "value" + injection);
        act.Should().Throw<ArgumentException>();
    }
}
