# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **X-XSS-Protection header** (`EnableXssProtectionHeader`, defaults to `true` / value `0`).
  Instructs modern browsers to disable the legacy XSS auditor (recommended by OWASP).
- **Reporting-Endpoints header** (`EnableReportingEndpoints`, `ReportingEndpointsValue`).
  Supports the Reporting API for aggregating CSP and other policy violation reports.
- **Path exclusion** (`ExcludePaths`). Middleware skips header injection for listed
  path prefixes (e.g. `/healthz`, `/metrics`). Matching is case-insensitive.
- **Per-request CSP nonce** (`EnableCspNonce`). Use the `__nonce__` placeholder in your
  CSP policy and a unique cryptographic nonce (32 bytes, base-64 encoded) is substituted
  at runtime. Requires `AddSecureHeaders()` for DI.
- **`INonceService`** public interface. Can be overridden in DI for custom nonce strategies.
- **`WithSecureHeaders()` endpoint filter** for Minimal API routes. Applies security headers
  to individual endpoints without requiring the middleware in the pipeline.
- **Startup options validation** via `IValidateOptions<SecureHeadersOptions>`. Invalid
  configurations (e.g. HSTS preload without includeSubDomains, empty CSP policy) now cause
  a fast-fail exception at application startup.
- **CRLF / NUL injection prevention** for all user-supplied header values
  (`HeaderSecurity` internal utility). Blocks OWASP A03 header injection attacks.
- **`ILogger<SecureHeadersMiddleware>`** injected into the middleware. Logs at `Trace`
  level when headers are applied or a path is excluded.

### Changed
- `AddSecureHeaders()` now registers `IValidateOptions<SecureHeadersOptions>` and
  `INonceService` automatically. No breaking changes for existing callers.
- All built-in presets now set `EnableXssProtectionHeader = true`.
- `ServiceCollectionExtensions.AddSecureHeaders()` now calls `ValidateOnStart()` to
  surface configuration errors before the first request arrives.

---

## [1.0.0] — 2025-01-01

### Added
- Initial release.
- Core middleware with HSTS, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, CORP, COOP, COEP, CSP headers.
- Four built-in presets: `Basic`, `ApiOnly`, `Spa`, `Strict`.
- Custom header support.
- Header removal (Server, X-Powered-By, plus custom list).
- `CspBuilder` fluent API for constructing Content-Security-Policy values.
- Multi-targeting for .NET 8 and .NET 10.
- GitHub Actions CI (build, test, security scan, release).

[unreleased]: https://github.com/DNVerma88/secure-headers-aspnetcore/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/DNVerma88/secure-headers-aspnetcore/releases/tag/v1.0.0
