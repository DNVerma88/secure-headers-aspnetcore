using FluentAssertions;
using SecureHeaders.AspNetCore.Builders;
using Xunit;

namespace SecureHeaders.AspNetCore.Tests.Unit;

public sealed class CspBuilderTests
{
    [Fact]
    public void Build_EmptyBuilder_ReturnsEmptyString()
    {
        var policy = new CspBuilder().Build();
        policy.Should().BeEmpty();
    }

    [Fact]
    public void Build_DefaultSrcSelf_ContainsDirective()
    {
        var policy = new CspBuilder()
            .AddDefaultSrcSelf()
            .Build();

        policy.Should().Contain("default-src 'self'");
    }

    [Fact]
    public void Build_MultipleDirectives_AreAllPresent()
    {
        var policy = new CspBuilder()
            .AddDefaultSrcSelf()
            .AddScriptSrcSelf()
            .AddObjectSrcNone()
            .Build();

        policy.Should().Contain("default-src 'self'");
        policy.Should().Contain("script-src 'self'");
        policy.Should().Contain("object-src 'none'");
    }

    [Fact]
    public void Build_FlagDirective_HasNoValue()
    {
        var policy = new CspBuilder()
            .AddUpgradeInsecureRequests()
            .Build();

        policy.Should().Contain("upgrade-insecure-requests");
        // Should not have trailing space before semicolon
        policy.Should().NotContain("upgrade-insecure-requests ;");
    }

    [Fact]
    public void Build_DuplicateSources_AreDeduped()
    {
        var policy = new CspBuilder()
            .AddSource("script-src", "'self'")
            .AddSource("script-src", "'self'")
            .Build();

        // Count occurrences of 'self' in script-src
        var scriptSrcPart = policy.Split(';')
            .First(p => p.TrimStart().StartsWith("script-src"));
        scriptSrcPart.Split(' ').Count(s => s == "'self'").Should().Be(1);
    }

    [Fact]
    public void Build_ReportUri_IsAppended()
    {
        var policy = new CspBuilder()
            .AddDefaultSrcSelf()
            .AddReportUri("/csp-report")
            .Build();

        policy.Should().Contain("report-uri /csp-report");
    }

    [Fact]
    public void Build_MultipleSourcesOnSameDirective_AreSpaceSeparated()
    {
        var policy = new CspBuilder()
            .AddSource("img-src", "'self'", "data:", "https://cdn.example.com")
            .Build();

        policy.Should().Contain("img-src 'self' data: https://cdn.example.com");
    }

    [Fact]
    public void Build_EndsWithSemicolon()
    {
        var policy = new CspBuilder()
            .AddDefaultSrcSelf()
            .Build();

        policy.Should().EndWith(";");
    }

    [Fact]
    public void AddSource_NullOrWhitespaceDirective_Throws()
    {
        var builder = new CspBuilder();
        var act = () => builder.AddSource("  ", "'self'");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddHash_FormatsCorrectly()
    {
        var policy = new CspBuilder()
            .AddHash("script-src", "sha256", "abc123==")
            .Build();

        policy.Should().Contain("'sha256-abc123=='");
    }

    [Fact]
    public void AddNonce_FormatsCorrectly()
    {
        var policy = new CspBuilder()
            .AddNonce("script-src", "randomNonce")
            .Build();

        policy.Should().Contain("'nonce-randomNonce'");
    }
}
