using SecureHeaders.AspNetCore.Extensions;
using SecureHeaders.AspNetCore.Presets;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSecureHeaders();

var app = builder.Build();

// Use the SPA preset — keeps COEP as unsafe-none so CDN assets load normally,
// and sets COOP to same-origin-allow-popups for OAuth pop-up flows.
app.UseSecureHeaders(SecurityHeaderPreset.Spa, options =>
{
    // Extend the preset with a custom header for branding.
    options.CustomHeaders.Add(new SecureHeaders.AspNetCore.Models.CustomHeader("X-App", "my-spa"));
});

app.UseStaticFiles();

app.MapGet("/api/ping", () => Results.Ok(new { Message = "pong" }));

// Fallback to index.html for SPA client-side routing
app.MapFallbackToFile("index.html");

app.Run();
