using SecureHeaders.AspNetCore.Internal;

namespace SecureHeaders.AspNetCore.Models;

/// <summary>
/// Represents a custom HTTP header with a name and value.
/// </summary>
public sealed class CustomHeader
{
    /// <summary>
    /// The HTTP header name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// The HTTP header value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Whether this header should override an existing header of the same name.
    /// </summary>
    public bool Override { get; }

    /// <summary>
    /// Initializes a new <see cref="CustomHeader"/>.
    /// </summary>
    /// <param name="name">Header name.</param>
    /// <param name="value">Header value.</param>
    /// <param name="overrideExisting">When true, replaces any existing header of the same name.</param>
    public CustomHeader(string name, string value, bool overrideExisting = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        HeaderSecurity.EnsureNoInvalidChars(name, nameof(name));
        HeaderSecurity.EnsureNoInvalidChars(value, nameof(value));
        Name = name;
        Value = value;
        Override = overrideExisting;
    }
}
