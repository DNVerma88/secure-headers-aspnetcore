# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ Active support |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's **private vulnerability reporting** feature:

1. Go to https://github.com/DNVerma88/secure-headers-aspnetcore/security/advisories
2. Click **Report a vulnerability**
3. Fill in the details — expected response time is 48 hours

Alternatively send a direct message to [@DNVerma88](https://github.com/DNVerma88).

## Scope

Security reports are welcome for:
- Vulnerabilities in the `SecureHeaders.AspNetCore` package itself
- Incorrect or dangerous default header values
- Issues that could allow a header to be bypassed or silently omitted
- Dependency vulnerabilities in `Microsoft.SourceLink.GitHub` (build-only dependency)

Out of scope: vulnerabilities in applications built _using_ this package but not caused by the package itself.

## Disclosure policy

We follow coordinated disclosure. Once a fix is released we will:
1. Publish a GitHub Security Advisory
2. Issue a new patch release
3. Credit the reporter (unless they prefer to remain anonymous)
