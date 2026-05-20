using SecureHeaders.AspNetCore.Extensions;
using SecureHeaders.AspNetCore.Presets;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Option A: register via DI and configure in middleware
builder.Services.AddSecureHeaders();

var app = builder.Build();

// Use the ApiOnly preset optimised for JSON REST APIs.
// HSTS, X-Content-Type-Options, Referrer-Policy, CORP, and COOP are enabled.
// X-Frame-Options is omitted (not relevant for pure APIs).
app.UseSecureHeaders(SecurityHeaderPreset.ApiOnly);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast(
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
