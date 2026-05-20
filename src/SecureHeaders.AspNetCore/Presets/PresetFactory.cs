using SecureHeaders.AspNetCore.Constants;
using SecureHeaders.AspNetCore.Options;

namespace SecureHeaders.AspNetCore.Presets;

/// <summary>
/// Produces <see cref="SecureHeadersOptions"/> instances for each built-in preset.
/// </summary>
internal static class PresetFactory
{
    internal static SecureHeadersOptions CreateOptions(SecurityHeaderPreset preset) => preset switch
    {
        SecurityHeaderPreset.Basic => Basic(),
        SecurityHeaderPreset.ApiOnly => ApiOnly(),
        SecurityHeaderPreset.Spa => Spa(),
        SecurityHeaderPreset.Strict => Strict(),
        _ => Basic(),
    };

    private static SecureHeadersOptions Basic() => new()
    {
        EnableHsts = true,
        HstsMaxAge = TimeSpan.FromDays(365),
        HstsIncludeSubDomains = true,
        HstsPreload = false,

        EnableXContentTypeOptions = true,

        EnableXFrameOptions = true,
        XFrameOptionsValue = HeaderDefaults.XFrameOptionsSameOrigin,

        EnableReferrerPolicy = true,
        ReferrerPolicyValue = HeaderDefaults.ReferrerPolicyStrictOriginWhenCrossOrigin,

        EnablePermissionsPolicy = true,
        PermissionsPolicyValue = HeaderDefaults.PermissionsPolicyBasic,

        EnableCrossOriginResourcePolicy = true,
        CrossOriginResourcePolicyValue = HeaderDefaults.CorpSameOrigin,

        EnableCrossOriginOpenerPolicy = false,
        EnableCrossOriginEmbedderPolicy = false,

        EnableCsp = false,
        RemoveServerHeader = true,
        RemoveXPoweredByHeader = true,
    };

    private static SecureHeadersOptions ApiOnly() => new()
    {
        EnableHsts = true,
        HstsMaxAge = TimeSpan.FromDays(365),
        HstsIncludeSubDomains = true,
        HstsPreload = false,

        EnableXContentTypeOptions = true,

        EnableXFrameOptions = false,

        EnableReferrerPolicy = true,
        ReferrerPolicyValue = HeaderDefaults.ReferrerPolicyNoReferrer,

        EnablePermissionsPolicy = false,

        EnableCrossOriginResourcePolicy = true,
        CrossOriginResourcePolicyValue = HeaderDefaults.CorpSameOrigin,

        EnableCrossOriginOpenerPolicy = true,
        CrossOriginOpenerPolicyValue = HeaderDefaults.CoopSameOrigin,

        EnableCrossOriginEmbedderPolicy = false,

        EnableCsp = false,
        RemoveServerHeader = true,
        RemoveXPoweredByHeader = true,
    };

    private static SecureHeadersOptions Spa() => new()
    {
        EnableHsts = true,
        HstsMaxAge = TimeSpan.FromDays(365),
        HstsIncludeSubDomains = true,
        HstsPreload = false,

        EnableXContentTypeOptions = true,

        EnableXFrameOptions = true,
        XFrameOptionsValue = HeaderDefaults.XFrameOptionsSameOrigin,

        EnableReferrerPolicy = true,
        ReferrerPolicyValue = HeaderDefaults.ReferrerPolicySameOrigin,

        EnablePermissionsPolicy = true,
        PermissionsPolicyValue = HeaderDefaults.PermissionsPolicyBasic,

        EnableCrossOriginResourcePolicy = true,
        CrossOriginResourcePolicyValue = HeaderDefaults.CorpSameSite,

        EnableCrossOriginOpenerPolicy = true,
        CrossOriginOpenerPolicyValue = HeaderDefaults.CoopSameOriginAllowPopups,

        // COEP unsafe-none to avoid breaking SPA asset loading from CDNs
        EnableCrossOriginEmbedderPolicy = true,
        CrossOriginEmbedderPolicyValue = HeaderDefaults.CoepUnsafeNone,

        EnableCsp = false,
        RemoveServerHeader = true,
        RemoveXPoweredByHeader = true,
    };

    private static SecureHeadersOptions Strict() => new()
    {
        EnableHsts = true,
        HstsMaxAge = TimeSpan.FromDays(730),
        HstsIncludeSubDomains = true,
        HstsPreload = true,

        EnableXContentTypeOptions = true,

        EnableXFrameOptions = true,
        XFrameOptionsValue = HeaderDefaults.XFrameOptionsDeny,

        EnableReferrerPolicy = true,
        ReferrerPolicyValue = HeaderDefaults.ReferrerPolicyNoReferrer,

        EnablePermissionsPolicy = true,
        PermissionsPolicyValue = HeaderDefaults.PermissionsPolicyStrict,

        EnableCrossOriginResourcePolicy = true,
        CrossOriginResourcePolicyValue = HeaderDefaults.CorpSameOrigin,

        EnableCrossOriginOpenerPolicy = true,
        CrossOriginOpenerPolicyValue = HeaderDefaults.CoopSameOrigin,

        EnableCrossOriginEmbedderPolicy = true,
        CrossOriginEmbedderPolicyValue = HeaderDefaults.CoepRequireCorp,

        EnableCsp = true,
        CspPolicy = "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;",

        RemoveServerHeader = true,
        RemoveXPoweredByHeader = true,
    };
}
