using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using System;

namespace SecureAPIs;

/// <summary>
/// ASP.NET Core middleware for SecureAPIs security checks
/// </summary>
public class SecureAPIsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecureAPIs _secureAPIs;

    public SecureAPIsMiddleware(RequestDelegate next, IOptions<SecureAPIsConfig> config)
    {
        _next = next;
        _secureAPIs = new SecureAPIs(config.Value);
    }

    /// <summary>
    /// Process the HTTP request through security checks
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        // Run security check
        var result = _secureAPIs.CheckRequest(context.Request);

        if (!result.Allowed)
        {
            // Request blocked - return error response
            context.Response.StatusCode = result.StatusCode;
            context.Response.ContentType = "application/json";

            var errorResponse = new
            {
                error = result.ErrorMessage ?? "Request blocked by security policy",
                statusCode = result.StatusCode,
                timestamp = DateTime.UtcNow
            };

            await context.Response.WriteAsJsonAsync(errorResponse);
            return;
        }

        // Request allowed - add security headers if provided
        if (!string.IsNullOrEmpty(result.HeadersJson))
        {
            try
            {
                var headers = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(result.HeadersJson);
                if (headers != null)
                {
                    foreach (var header in headers)
                    {
                        context.Response.Headers[header.Key] = header.Value;
                    }
                }
            }
            catch
            {
                // Ignore header parsing errors
            }
        }

        // Continue to next middleware
        await _next(context);
    }
}

/// <summary>
/// Extension methods for adding SecureAPIs middleware
/// </summary>
public static class SecureAPIsMiddlewareExtensions
{
    /// <summary>
    /// Add SecureAPIs middleware with default configuration
    /// </summary>
    public static IApplicationBuilder UseSecureAPIs(
        this IApplicationBuilder builder)
    {
        var config = SecureAPIsConfig.Load();
        return builder.UseSecureAPIs(config);
    }

    /// <summary>
    /// Add SecureAPIs middleware with custom configuration
    /// </summary>
    public static IApplicationBuilder UseSecureAPIs(
        this IApplicationBuilder builder,
        Action<SecureAPIsConfig> configure)
    {
        var config = new SecureAPIsConfig();
        configure(config);

        builder.UseMiddleware<SecureAPIsMiddleware>(
            Options.Create(config));

        return builder;
    }

    /// <summary>
    /// Add SecureAPIs middleware with configuration from JSON file
    /// </summary>
    public static IApplicationBuilder UseSecureAPIs(
        this IApplicationBuilder builder,
        string configFilePath)
    {
        var config = SecureAPIsConfig.Load(configFilePath);
        return builder.UseSecureAPIs(config);
    }

    /// <summary>
    /// Add SecureAPIs middleware with configuration from IConfiguration
    /// </summary>
    public static IApplicationBuilder UseSecureAPIs(
        this IApplicationBuilder builder,
        IConfiguration configuration)
    {
        var config = SecureAPIsConfig.FromConfiguration(configuration);
        return builder.UseSecureAPIs(config);
    }

    /// <summary>
    /// Add SecureAPIs middleware with configuration object
    /// </summary>
    public static IApplicationBuilder UseSecureAPIs(
        this IApplicationBuilder builder,
        SecureAPIsConfig config)
    {
        builder.UseMiddleware<SecureAPIsMiddleware>(
            Options.Create(config));

        return builder;
    }
}