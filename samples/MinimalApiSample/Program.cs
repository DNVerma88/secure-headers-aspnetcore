using SecureHeaders.AspNetCore.Builders;
using SecureHeaders.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Register SecureHeaders services (optional when passing a configure delegate,
// but required when calling UseSecureHeaders() with no arguments).
builder.Services.AddSecureHeaders();

var app = builder.Build();

// Configure via inline delegate — no call to AddSecureHeaders() needed for this overload.
app.UseSecureHeaders(options =>
{
    options.EnableHsts = true;
    options.HstsMaxAge = TimeSpan.FromDays(365);
    options.HstsIncludeSubDomains = true;

    options.EnableXContentTypeOptions = true;
    options.EnableXFrameOptions = true;
    options.EnableReferrerPolicy = true;

    // Build a strict CSP using the fluent builder.
    options.EnableCsp = true;
    options.CspPolicy = new CspBuilder()
        .AddDefaultSrcSelf()
        .AddScriptSrcSelf()
        .AddStyleSrcSelf()
        .AddImgSrcSelf()
        .AddImgSrcData()
        .AddObjectSrcNone()
        .AddBaseUriSelf()
        .AddFormActionSelf()
        .AddFrameAncestorsNone()
        .AddUpgradeInsecureRequests()
        .Build();

    options.RemoveServerHeader = true;
    options.RemoveXPoweredByHeader = true;
});

app.MapGet("/", () => Results.Ok(new { Message = "Hello from MinimalApi sample with SecureHeaders!" }));
app.MapGet("/health", () => Results.Ok(new { Status = "Healthy" }));

app.Run();
