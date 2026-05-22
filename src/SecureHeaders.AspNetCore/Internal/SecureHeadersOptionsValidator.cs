using Microsoft.Extensions.Options;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Internal;

/// <summary>
/// Validates <see cref="SecureHeadersOptions"/> at application startup, providing
/// fast-fail error messages for common misconfigurations.
/// </summary>
internal sealed class SecureHeadersOptionsValidator : IValidateOptions<SecureHeadersOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, SecureHeadersOptions options)
    {
        var errors = new List<string>();

        // ── HSTS ─────────────────────────────────────────────────────────────
        if (options.EnableHsts)
        {
            if (options.HstsMaxAge <= TimeSpan.Zero)
                errors.Add($"{nameof(SecureHeadersOptions.HstsMaxAge)} must be greater than zero.");

            if (options.HstsPreload)
            {
                if (!options.HstsIncludeSubDomains)
                    errors.Add(
                        $"HSTS preload requires {nameof(SecureHeadersOptions.HstsIncludeSubDomains)} " +
                        "to be true (required by the HSTS preload list submission criteria).");

                if (options.HstsMaxAge.TotalSeconds < 31_536_000)
                    errors.Add(
                        $"HSTS preload requires {nameof(SecureHeadersOptions.HstsMaxAge)} to be " +
                        "at least 365 days (31,536,000 seconds). Current value: " +
                        $"{options.HstsMaxAge.TotalSeconds:N0} seconds.");
            }
        }

        // ── CSP ───────────────────────────────────────────────────────────────
        if (options.EnableCsp && string.IsNullOrWhiteSpace(options.CspPolicy))
            errors.Add(
                $"{nameof(SecureHeadersOptions.EnableCsp)} is true but " +
                $"{nameof(SecureHeadersOptions.CspPolicy)} is null or empty. " +
                "Build a policy with CspBuilder and assign it to CspPolicy.");

        // ── CRLF / NUL injection checks ───────────────────────────────────────
        CheckCrlf(errors, nameof(options.XFrameOptionsValue), options.XFrameOptionsValue);
        CheckCrlf(errors, nameof(options.ReferrerPolicyValue), options.ReferrerPolicyValue);
        CheckCrlf(errors, nameof(options.PermissionsPolicyValue), options.PermissionsPolicyValue);
        CheckCrlf(errors, nameof(options.CrossOriginOpenerPolicyValue), options.CrossOriginOpenerPolicyValue);
        CheckCrlf(errors, nameof(options.CrossOriginResourcePolicyValue), options.CrossOriginResourcePolicyValue);
        CheckCrlf(errors, nameof(options.CrossOriginEmbedderPolicyValue), options.CrossOriginEmbedderPolicyValue);
        CheckCrlf(errors, nameof(options.XssProtectionValue), options.XssProtectionValue);

        if (!string.IsNullOrEmpty(options.CspPolicy))
            CheckCrlf(errors, nameof(options.CspPolicy), options.CspPolicy);

        if (!string.IsNullOrEmpty(options.ReportingEndpointsValue))
            CheckCrlf(errors, nameof(options.ReportingEndpointsValue), options.ReportingEndpointsValue);

        // ── Custom headers CRLF check ─────────────────────────────────────────
        for (var i = 0; i < options.CustomHeaders.Count; i++)
        {
            var h = options.CustomHeaders[i];
            if (HeaderSecurity.ContainsInvalidChars(h.Name))
                errors.Add($"CustomHeaders[{i}].Name contains invalid CR/LF/NUL characters.");
            if (HeaderSecurity.ContainsInvalidChars(h.Value))
                errors.Add($"CustomHeaders[{i}].Value contains invalid CR/LF/NUL characters.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }

    private static void CheckCrlf(List<string> errors, string propertyName, string? value)
    {
        if (!string.IsNullOrEmpty(value) && HeaderSecurity.ContainsInvalidChars(value))
            errors.Add($"{propertyName} contains invalid CR/LF/NUL characters (HTTP response splitting risk).");
    }
}
