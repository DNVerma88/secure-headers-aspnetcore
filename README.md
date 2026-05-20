# SecureHeaders.AspNetCore

[![NuGet](https://img.shields.io/nuget/v/SecureHeaders.AspNetCore.svg)](https://www.nuget.org/packages/SecureHeaders.AspNetCore)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SecureHeaders.AspNetCore.svg)](https://www.nuget.org/packages/SecureHeaders.AspNetCore)
[![Build](https://github.com/DNVerma88/secure-headers-aspnetcore/actions/workflows/build.yml/badge.svg)](https://github.com/DNVerma88/secure-headers-aspnetcore/actions/workflows/build.yml)
[![Security](https://github.com/DNVerma88/secure-headers-aspnetcore/actions/workflows/security.yml/badge.svg)](https://github.com/DNVerma88/secure-headers-aspnetcore/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Lightweight, high-performance, security-focused HTTP headers middleware for ASP.NET Core.

One line secures your application against the most common browser-based attacks:

```csharp
app.UseSecureHeaders();
```

## Features

- **Zero heavy dependencies** — only standard `Microsoft.AspNetCore.App` framework references
- **Multi-targeting** — supports .NET 8 and .NET 10 (future-compatible)
- **Presets** — `Basic`, `ApiOnly`, `Spa`, `Strict` for common scenarios
- **Fluent CSP builder** — strongly-typed Content-Security-Policy construction
- **Minimal allocations** — header values are pre-computed and cached at startup
- **Thread-safe** — safe for high-concurrency workloads
- **HSTS Production Guard** — HSTS is only sent in Production by default
- **Non-destructive** — existing response headers are preserved unless you opt in to override

### Headers managed

| Header | Default |
|---|---|
| `Strict-Transport-Security` | Enabled (Production only) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | camera, mic, geolocation, payment off |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Content-Security-Policy` | Off by default (opt-in) |
| `Cross-Origin-Opener-Policy` | Off by default (opt-in) |
| `Cross-Origin-Embedder-Policy` | Off by default (opt-in) |

---

## Installation

```bash
dotnet add package SecureHeaders.AspNetCore
```

---

## Quick Start

### Minimal (defaults)

```csharp
// Program.cs
builder.Services.AddSecureHeaders();

app.UseSecureHeaders();
```

### Inline configuration

```csharp
app.UseSecureHeaders(options =>
{
    options.EnableHsts = true;
    options.HstsMaxAge = TimeSpan.FromDays(365);
    options.EnableCsp = true;
    options.CspPolicy = "default-src 'self'; object-src 'none';";
});
```

### Preset usage

```csharp
// Safe production defaults
app.UseSecureHeaders(SecurityHeaderPreset.Basic);

// Optimised for REST APIs
app.UseSecureHeaders(SecurityHeaderPreset.ApiOnly);

// React / Angular / Vue SPA backend
app.UseSecureHeaders(SecurityHeaderPreset.Spa);

// Maximum isolation
app.UseSecureHeaders(SecurityHeaderPreset.Strict);
```

### Preset + override

```csharp
app.UseSecureHeaders(SecurityHeaderPreset.Strict, options =>
{
    // Relax CSP for a specific third-party analytics script
    options.CspPolicy = "default-src 'self'; script-src 'self' https://analytics.example.com;";
});
```

---

## CSP Fluent Builder

Use `CspBuilder` to construct type-safe Content-Security-Policy strings:

```csharp
using SecureHeaders.AspNetCore.Builders;

var policy = new CspBuilder()
    .AddDefaultSrcSelf()
    .AddScriptSrcSelf()
    .AddStyleSrcSelf()
    .AddImgSrcSelf()
    .AddImgSrcData()          // allow inline SVG data URIs
    .AddFontSrcSelf()
    .AddConnectSrcSelf()
    .AddObjectSrcNone()
    .AddBaseUriSelf()
    .AddFormActionSelf()
    .AddFrameAncestorsNone()
    .AddUpgradeInsecureRequests()
    .Build();

app.UseSecureHeaders(options =>
{
    options.EnableCsp = true;
    options.CspPolicy = policy;
});
```

### Nonce & hash support

```csharp
// Nonce-based inline script allowance
var policy = new CspBuilder()
    .AddDefaultSrcSelf()
    .AddNonce("script-src", nonceBase64Value)
    .AddObjectSrcNone()
    .Build();

// Hash-based inline script allowance
var policy = new CspBuilder()
    .AddDefaultSrcSelf()
    .AddHash("script-src", "sha256", scriptHashBase64)
    .Build();
```

### CSP Report-Only mode

```csharp
app.UseSecureHeaders(options =>
{
    options.EnableCsp = true;
    options.EnableCspReportOnly = true;        // sends Content-Security-Policy-Report-Only
    options.CspPolicy = "default-src 'self'";
    options.CspReportUri = "/security/csp-report";
});
```

---

## SPA Configuration

For React, Angular, or Vue applications:

```csharp
app.UseSecureHeaders(SecurityHeaderPreset.Spa);
```

The `Spa` preset configures:
- `Cross-Origin-Opener-Policy: same-origin-allow-popups` (allows OAuth pop-ups)
- `Cross-Origin-Embedder-Policy: unsafe-none` (avoids breaking CDN asset loading)
- `Cross-Origin-Resource-Policy: same-site`
- `Referrer-Policy: same-origin`
- HSTS enabled in Production

---

## API-Only Configuration

For JSON REST APIs that serve no browser-rendered HTML:

```csharp
app.UseSecureHeaders(SecurityHeaderPreset.ApiOnly);
```

The `ApiOnly` preset:
- Omits `X-Frame-Options` (browser-only concept for APIs)
- Sets `Referrer-Policy: no-referrer`
- Enables COOP `same-origin`
- Leaves CSP disabled

---

## Configuration Reference

### `SecureHeadersOptions`

| Property | Type | Default | Description |
|---|---|---|---|
| `EnableHsts` | `bool` | `true` | Enable `Strict-Transport-Security` |
| `HstsMaxAge` | `TimeSpan` | 365 days | HSTS `max-age` |
| `HstsIncludeSubDomains` | `bool` | `true` | Append `includeSubDomains` |
| `HstsPreload` | `bool` | `false` | Append `preload` (requires ≥730 days) |
| `EnforceHstsInDevelopment` | `bool` | `false` | Send HSTS outside Production |
| `EnableXContentTypeOptions` | `bool` | `true` | Send `nosniff` |
| `EnableXFrameOptions` | `bool` | `true` | Enable framing policy |
| `XFrameOptionsValue` | `string` | `SAMEORIGIN` | Frame policy value |
| `EnableReferrerPolicy` | `bool` | `true` | Enable referrer policy |
| `ReferrerPolicyValue` | `string` | `strict-origin-when-cross-origin` | Policy value |
| `EnableCsp` | `bool` | `false` | Enable CSP (opt-in) |
| `CspPolicy` | `string?` | `null` | Raw CSP policy string |
| `EnableCspReportOnly` | `bool` | `false` | Use report-only mode |
| `CspReportUri` | `string?` | `null` | Auto-appends `report-uri` |
| `EnablePermissionsPolicy` | `bool` | `true` | Enable Permissions-Policy |
| `PermissionsPolicyValue` | `string` | See defaults | Policy value |
| `EnableCrossOriginOpenerPolicy` | `bool` | `false` | Enable COOP |
| `CrossOriginOpenerPolicyValue` | `string` | `same-origin` | COOP value |
| `EnableCrossOriginResourcePolicy` | `bool` | `true` | Enable CORP |
| `CrossOriginResourcePolicyValue` | `string` | `same-origin` | CORP value |
| `EnableCrossOriginEmbedderPolicy` | `bool` | `false` | Enable COEP |
| `CrossOriginEmbedderPolicyValue` | `string` | `unsafe-none` | COEP value |
| `RemoveServerHeader` | `bool` | `true` | Remove `Server` header |
| `RemoveXPoweredByHeader` | `bool` | `true` | Remove `X-Powered-By` header |
| `RemoveHeaders` | `IList<string>` | `[]` | Additional headers to remove |
| `CustomHeaders` | `IList<CustomHeader>` | `[]` | Additional headers to add |
| `OverrideExistingHeaders` | `bool` | `false` | Overwrite pre-existing headers |

### Custom headers

```csharp
app.UseSecureHeaders(options =>
{
    // Add a custom header
    options.CustomHeaders.Add(new CustomHeader("X-Tenant", "acme-corp"));

    // Override an existing header (if the response already has it)
    options.CustomHeaders.Add(new CustomHeader("X-Frame-Options", "DENY", overrideExisting: true));

    // Remove a header
    options.RemoveHeaders.Add("X-AspNet-Version");
});
```

---

## DI registration (`AddSecureHeaders`)

Calling `AddSecureHeaders()` is **optional** when you pass a configure delegate or a preset directly to `UseSecureHeaders()`. It is **required** when calling `app.UseSecureHeaders()` with no arguments (so that `IOptions<SecureHeadersOptions>` is available in the DI container).

```csharp
// Required when using UseSecureHeaders() with no arguments:
builder.Services.AddSecureHeaders();

// Also supports configuring via DI (e.g. appsettings.json binding):
builder.Services.AddSecureHeaders(options =>
{
    options.EnableCsp = true;
    options.CspPolicy = builder.Configuration["Security:CspPolicy"];
});
```

---

## Performance

The middleware pre-computes all header values into a `HeaderValueCache` at startup. Per-request work is limited to:
- Iterating a small fixed list of header names
- Calling `IHeaderDictionary[name] = value` for each enabled header
- No allocations for pre-computed header values

---

## Version Compatibility

| Package version | .NET | ASP.NET Core |
|---|---|---|
| 1.x | .NET 8, .NET 10 | 8.x, 10.x |

The package uses only stable `IApplicationBuilder`, `HttpContext`, and `IHeaderDictionary` abstractions, making it forward-compatible with future .NET versions.

---

## Security Considerations

- **HSTS preload**: enabling `HstsPreload = true` registers your domain permanently with browser HSTS preload lists. This cannot be easily undone. Only enable once you are fully committed to HTTPS on all subdomains.
- **CSP**: CSP requires careful tuning per application. Start with report-only mode and monitor reports before switching to enforcing mode.
- **COEP**: `require-corp` may break pages that load cross-origin resources (CDN images, fonts) that do not return `Cross-Origin-Resource-Policy` headers.

---

## Contributing

Pull requests are welcome at [github.com/DNVerma88/secure-headers-aspnetcore](https://github.com/DNVerma88/secure-headers-aspnetcore). Please ensure:
- All tests pass on both `net8.0` and `net10.0`
- New public API surface includes XML documentation
- No new runtime dependencies are introduced
- `TreatWarningsAsErrors` remains satisfied

---

## License

[MIT](LICENSE)
