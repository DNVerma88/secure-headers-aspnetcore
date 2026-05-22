# Contributing to SecureHeaders.AspNetCore

Thank you for your interest in contributing! This document explains how to get
started and what is expected of contributors.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How to Contribute](#how-to-contribute)
3. [Development Setup](#development-setup)
4. [Build & Test](#build--test)
5. [Coding Guidelines](#coding-guidelines)
6. [Pull Request Process](#pull-request-process)
7. [Security Issues](#security-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/)
Code of Conduct. By participating you are expected to uphold this standard.
Report unacceptable behaviour to the maintainers.

---

## How to Contribute

| Type | What to do |
|------|-----------|
| Bug report | Open a GitHub Issue using the **Bug Report** template |
| Feature request | Open a GitHub Issue using the **Feature Request** template |
| Documentation fix | Open a Pull Request directly — no issue needed |
| Code change | Open an issue first, then link your PR to it |

---

## Development Setup

**Prerequisites**

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (minimum)
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (for multi-targeting)
- Git ≥ 2.40

**Clone & restore**

```bash
git clone https://github.com/DNVerma88/secure-headers-aspnetcore.git
cd secure-headers-aspnetcore
dotnet restore
```

---

## Build & Test

```bash
# Build the library
dotnet build src/SecureHeaders.AspNetCore/SecureHeaders.AspNetCore.csproj \
  --configuration Release

# Run the full test suite (both TFMs)
dotnet test --configuration Release --verbosity normal

# Run tests with code coverage
dotnet test --configuration Release \
  --collect:"XPlat Code Coverage" \
  --results-directory ./coverage
```

---

## Coding Guidelines

- **Style** — follow the existing code style (4-space indents, file-scoped
  namespaces, `var` where the type is obvious).
- **Nullability** — all code must compile with `<Nullable>enable</Nullable>`.
- **Warnings as errors** — `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` is
  enforced in CI. Your PR must produce zero warnings.
- **Security** — any new user-controlled string written to HTTP response headers
  **must** pass through `HeaderSecurity.EnsureNoInvalidChars()` to prevent
  CRLF/NUL injection (OWASP A03).
- **Tests** — new behaviour must be covered by at least one unit test and, where
  appropriate, one integration test using `Microsoft.AspNetCore.TestHost`.
- **Public API surface** — discuss additions to the public API in an issue before
  implementation. Reducing the public API (breaking changes) requires a major version
  bump.

---

## Pull Request Process

1. Fork the repository and create a feature branch off `main`.
2. Make your changes with tests.
3. Run the full test suite locally (`dotnet test`). All tests must pass.
4. Update `CHANGELOG.md` under `[Unreleased]` with a concise description.
5. Open a Pull Request targeting `main`.
6. A maintainer will review your PR. Automated CI checks must be green before merging.

---

## Security Issues

**Do not open a public GitHub Issue for security vulnerabilities.**

Please review [SECURITY.md](SECURITY.md) for instructions on how to report
a security issue responsibly.
