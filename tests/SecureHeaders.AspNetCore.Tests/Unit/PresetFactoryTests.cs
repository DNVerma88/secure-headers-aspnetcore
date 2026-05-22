using FluentAssertions;
using SecureHeaders.AspNetCore.Options;
using SecureHeaders.AspNetCore.Presets;
using Xunit;

namespace SecureHeaders.AspNetCore.Tests.Unit;

public sealed class PresetFactoryTests
{
    [Fact]
    public void Basic_EnablesHsts()
    {
        var opts = GetOptions(SecurityHeaderPreset.Basic);
        opts.EnableHsts.Should().BeTrue();
    }

    [Fact]
    public void Basic_EnablesXContentTypeOptions()
    {
        var opts = GetOptions(SecurityHeaderPreset.Basic);
        opts.EnableXContentTypeOptions.Should().BeTrue();
    }

    [Fact]
    public void Basic_EnablesXFrameOptions_SameOrigin()
    {
        var opts = GetOptions(SecurityHeaderPreset.Basic);
        opts.EnableXFrameOptions.Should().BeTrue();
        opts.XFrameOptionsValue.Should().Be("SAMEORIGIN");
    }

    [Fact]
    public void Basic_CspIsDisabledByDefault()
    {
        var opts = GetOptions(SecurityHeaderPreset.Basic);
        opts.EnableCsp.Should().BeFalse();
    }

    [Fact]
    public void ApiOnly_XFrameOptionsIsDisabled()
    {
        var opts = GetOptions(SecurityHeaderPreset.ApiOnly);
        opts.EnableXFrameOptions.Should().BeFalse();
    }

    [Fact]
    public void ApiOnly_CoopIsEnabled()
    {
        var opts = GetOptions(SecurityHeaderPreset.ApiOnly);
        opts.EnableCrossOriginOpenerPolicy.Should().BeTrue();
    }

    [Fact]
    public void Spa_CoopAllowsPopups()
    {
        var opts = GetOptions(SecurityHeaderPreset.Spa);
        opts.CrossOriginOpenerPolicyValue.Should().Be("same-origin-allow-popups");
    }

    [Fact]
    public void Spa_CoepIsUnsafeNone()
    {
        var opts = GetOptions(SecurityHeaderPreset.Spa);
        opts.EnableCrossOriginEmbedderPolicy.Should().BeTrue();
        opts.CrossOriginEmbedderPolicyValue.Should().Be("unsafe-none");
    }

    [Fact]
    public void Strict_HstsPreloadEnabled()
    {
        var opts = GetOptions(SecurityHeaderPreset.Strict);
        opts.HstsPreload.Should().BeTrue();
        opts.HstsMaxAge.Should().Be(TimeSpan.FromDays(730));
    }

    [Fact]
    public void Strict_XFrameOptionsDeny()
    {
        var opts = GetOptions(SecurityHeaderPreset.Strict);
        opts.XFrameOptionsValue.Should().Be("DENY");
    }

    [Fact]
    public void Strict_CspIsEnabled()
    {
        var opts = GetOptions(SecurityHeaderPreset.Strict);
        opts.EnableCsp.Should().BeTrue();
        opts.CspPolicy.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Strict_CoepRequireCorp()
    {
        var opts = GetOptions(SecurityHeaderPreset.Strict);
        opts.CrossOriginEmbedderPolicyValue.Should().Be("require-corp");
    }

    [Fact]
    public void AllPresets_RemoveServerHeader()
    {
        foreach (var preset in Enum.GetValues<SecurityHeaderPreset>())
        {
            var opts = GetOptions(preset);
            opts.RemoveServerHeader.Should().BeTrue($"preset {preset} should remove Server header");
        }
    }

    [Theory]
    [InlineData(SecurityHeaderPreset.Basic)]
    [InlineData(SecurityHeaderPreset.ApiOnly)]
    [InlineData(SecurityHeaderPreset.Spa)]
    [InlineData(SecurityHeaderPreset.Strict)]
    public void AllPresets_HstsMaxAge_IsAtLeast730Days(SecurityHeaderPreset preset)
    {
        var opts = GetOptions(preset);
        opts.HstsMaxAge.Should().BeGreaterThanOrEqualTo(TimeSpan.FromDays(730),
            "OWASP recommends a minimum HSTS max-age of 2 years (730 days)");
    }

    [Fact]
    public void UnknownPresetValue_Throws_ArgumentOutOfRangeException()
    {
        var unknownPreset = (SecurityHeaderPreset)999;
        var act = () => PresetFactory.CreateOptions(unknownPreset);
        act.Should().Throw<ArgumentOutOfRangeException>()
           .WithMessage("*Unknown SecurityHeaderPreset*");
    }

    private static SecureHeadersOptions GetOptions(SecurityHeaderPreset preset)
        => PresetFactory.CreateOptions(preset);
}
