namespace SecureHeaders.AspNetCore.Constants;

/// <summary>
/// Default values used for each security header.
/// </summary>
internal static class HeaderDefaults
{
    internal const string HstsValue = "max-age=31536000; includeSubDomains";
    internal const string HstsPreloadValue = "max-age=63072000; includeSubDomains; preload";
    internal const string XContentTypeOptionsValue = "nosniff";
    internal const string XFrameOptionsDeny = "DENY";
    internal const string XFrameOptionsSameOrigin = "SAMEORIGIN";
    internal const string ReferrerPolicyStrictOriginWhenCrossOrigin = "strict-origin-when-cross-origin";
    internal const string ReferrerPolicyNoReferrer = "no-referrer";
    internal const string ReferrerPolicySameOrigin = "same-origin";
    internal const string PermissionsPolicyBasic = "camera=(), microphone=(), geolocation=(), payment=()";
    internal const string PermissionsPolicyStrict = "accelerometer=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()";
    internal const string CoopSameOrigin = "same-origin";
    internal const string CoopSameOriginAllowPopups = "same-origin-allow-popups";
    internal const string CoopUnsafeNone = "unsafe-none";
    internal const string CorpSameOrigin = "same-origin";
    internal const string CorpSameSite = "same-site";
    internal const string CorpCrossOrigin = "cross-origin";
    internal const string CoepRequireCorp = "require-corp";
    internal const string CoepUnsafeNone = "unsafe-none";
}
