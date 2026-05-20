# Architecture Overview

## Package structure

```
src/SecureHeaders.AspNetCore/
│
├── Constants/
│   ├── HeaderDefaults.cs       — Default values for each security header (internal)
│   └── HeaderNames.cs          — Well-known HTTP security header name constants (public)
│
├── Options/
│   └── SecureHeadersOptions.cs — Strongly-typed configuration class (public)
│
├── Models/
│   └── CustomHeader.cs         — Immutable custom header name/value model (public)
│
├── Builders/
│   └── CspBuilder.cs           — Fluent Content-Security-Policy builder (public)
│
├── Presets/
│   ├── SecurityHeaderPreset.cs — Preset enum (public)
│   └── PresetFactory.cs        — Creates SecureHeadersOptions from a preset (internal)
│
├── Internal/
│   ├── HeaderValueCache.cs     — Pre-computes static header values at startup (internal)
│   └── InternalsVisibleTo.cs   — Assembly-level InternalsVisibleTo for tests (internal)
│
├── Middleware/
│   └── SecureHeadersMiddleware.cs — Core ASP.NET Core middleware (public)
│
└── Extensions/
    ├── ApplicationBuilderExtensions.cs — IApplicationBuilder.UseSecureHeaders(...) (public)
    └── ServiceCollectionExtensions.cs  — IServiceCollection.AddSecureHeaders(...) (public)
```

## Request pipeline

```
Incoming request
      │
      ▼
SecureHeadersMiddleware.InvokeAsync
      │  Registers Response.OnStarting callback
      ▼
Next middleware / route handler
      │
      ▼
Response is about to start being written
      │
      ▼
ApplyHeaders callback executes:
  1. Remove headers (Server, X-Powered-By, custom removals)
  2. Set HSTS (if enabled and Production)
  3. Set X-Content-Type-Options
  4. Set X-Frame-Options
  5. Set Referrer-Policy
  6. Set Permissions-Policy
  7. Set Cross-Origin-Opener-Policy
  8. Set Cross-Origin-Resource-Policy
  9. Set Cross-Origin-Embedder-Policy
  10. Set Content-Security-Policy / CSP-Report-Only
  11. Set custom headers
      │
      ▼
Response body written to client
```

## Header value caching

`HeaderValueCache` is constructed once per middleware instance (at app startup) from a
`SecureHeadersOptions` snapshot. It pre-computes all header value strings so that
per-request work involves only cheap string assignments to `IHeaderDictionary`.

No allocations occur for pre-computed values on the hot path.

## Dependency injection flow

```
builder.Services.AddSecureHeaders()
         ↓
  registers IOptions<SecureHeadersOptions>

app.UseSecureHeaders()
         ↓
  app.UseMiddleware<SecureHeadersMiddleware>()
         ↓
  DI resolves: RequestDelegate, IOptions<SecureHeadersOptions>, IWebHostEnvironment
         ↓
  SecureHeadersMiddleware ctor → new HeaderValueCache(options, isProduction)
```

When `UseSecureHeaders(Action<SecureHeadersOptions>)` or
`UseSecureHeaders(SecurityHeaderPreset)` is called, a fresh `SecureHeadersOptions`
is constructed directly from the delegate / preset factory and wrapped in
`Options.Create(options)` — bypassing the DI container. This means
`AddSecureHeaders()` is not required for those overloads.

## Design decisions

| Decision | Rationale |
|---|---|
| `OnStarting` callback | Ensures headers are set after the handler runs but before bytes leave the server |
| Pre-computed `HeaderValueCache` | Zero per-request allocations for static header values |
| No third-party runtime dependencies | Minimises vulnerability surface and supply-chain risk |
| CSP opt-in | CSP requires per-app tuning; a wrong default would break applications |
| HSTS Production-only default | Prevents accidentally sending HSTS over HTTP in development |
| `OverrideExistingHeaders = false` | Preserves headers set by the application handler |
