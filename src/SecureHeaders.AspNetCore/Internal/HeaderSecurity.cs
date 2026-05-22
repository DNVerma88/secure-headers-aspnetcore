using System.Buffers;

namespace SecureHeaders.AspNetCore.Internal;

/// <summary>
/// Utilities for validating HTTP header names and values.
/// </summary>
internal static class HeaderSecurity
{
    // RFC 7230 §3.2 prohibits CR (%0D), LF (%0A), and NUL (%00) in header field names/values.
    private static readonly SearchValues<char> s_invalidChars =
        SearchValues.Create("\r\n\0");

    /// <summary>
    /// Throws <see cref="ArgumentException"/> if <paramref name="value"/>
    /// contains carriage-return, line-feed, or null characters.
    /// </summary>
    internal static void EnsureNoInvalidChars(string value, string paramName)
    {
        if (value.AsSpan().IndexOfAny(s_invalidChars) >= 0)
        {
            throw new ArgumentException(
                "Header names and values must not contain carriage return (\\r), " +
                "line feed (\\n), or null (\\0) characters. " +
                "Allowing such characters would enable HTTP response splitting attacks.",
                paramName);
        }
    }

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="value"/> contains
    /// any character that is invalid in an HTTP header name or value.
    /// </summary>
    internal static bool ContainsInvalidChars(string value) =>
        value.AsSpan().IndexOfAny(s_invalidChars) >= 0;
}
