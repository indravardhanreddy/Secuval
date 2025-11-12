using System.Runtime.InteropServices;
using System.Text.Json;
using System.IO;
using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Linq;

namespace SecureAPIs;

/// <summary>
/// Comprehensive configuration for SecureAPIs security checks
/// Supports JSON files, environment variables, and dynamic configuration
/// </summary>
public class SecureAPIsConfig
{
    // Rate Limiting
    public int RateLimitRequests { get; set; } = 100;
    public int RateLimitWindowSeconds { get; set; } = 60;
    public bool EnableRateLimiting { get; set; } = true;

    // Authentication
    public string? JwtSecret { get; set; }
    public string? JwtIssuer { get; set; }
    public string? JwtAudience { get; set; }
    public bool EnableJwtValidation { get; set; } = false;
    public List<string>? ApiKeys { get; set; }

    // Input Validation
    public bool EnableInputValidation { get; set; } = true;
    public bool EnableSqlInjectionDetection { get; set; } = true;
    public bool EnableXssDetection { get; set; } = true;
    public bool EnableCommandInjectionDetection { get; set; } = true;
    public bool EnablePathTraversalDetection { get; set; } = true;
    public int MaxRequestBodySize { get; set; } = 1048576; // 1MB
    public int MaxUrlLength { get; set; } = 2048;

    // CORS
    public bool EnableCors { get; set; } = false;
    public List<string>? AllowedOrigins { get; set; }
    public List<string>? AllowedMethods { get; set; }
    public List<string>? AllowedHeaders { get; set; }

    // Security Headers
    public bool EnableSecurityHeaders { get; set; } = true;
    public bool EnableHsts { get; set; } = true;
    public bool EnableCsp { get; set; } = false;
    public string? CspPolicy { get; set; }

    // Threat Detection
    public bool EnableThreatDetection { get; set; } = true;
    public List<string>? BlockedIPs { get; set; }
    public List<string>? BlockedUserAgents { get; set; }
    public int MaxRequestsPerMinute { get; set; } = 60;

    // Logging & Monitoring
    public bool EnableLogging { get; set; } = true;
    public string LogLevel { get; set; } = "Info";
    public bool EnableMetrics { get; set; } = true;

    // Advanced Settings
    public bool StrictMode { get; set; } = false;
    public int RequestTimeoutSeconds { get; set; } = 30;
    public bool EnableIpReputation { get; set; } = false;

    /// <summary>
    /// Load configuration from JSON file
    /// </summary>
    public static SecureAPIsConfig FromJsonFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Configuration file not found: {filePath}");
        }

        var json = File.ReadAllText(filePath);
        var config = JsonSerializer.Deserialize<SecureAPIsConfig>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip
        });

        return config ?? new SecureAPIsConfig();
    }

    /// <summary>
    /// Load configuration from environment variables
    /// </summary>
    public static SecureAPIsConfig FromEnvironment()
    {
        var config = new SecureAPIsConfig();

        // Rate limiting
        config.RateLimitRequests = GetEnvInt("SECUREAPIS_RATE_LIMIT_REQUESTS", config.RateLimitRequests);
        config.RateLimitWindowSeconds = GetEnvInt("SECUREAPIS_RATE_LIMIT_WINDOW_SECONDS", config.RateLimitWindowSeconds);
        config.EnableRateLimiting = GetEnvBool("SECUREAPIS_ENABLE_RATE_LIMITING", config.EnableRateLimiting);

        // Authentication
        config.JwtSecret = GetEnvString("SECUREAPIS_JWT_SECRET", config.JwtSecret);
        config.JwtIssuer = GetEnvString("SECUREAPIS_JWT_ISSUER", config.JwtIssuer);
        config.JwtAudience = GetEnvString("SECUREAPIS_JWT_AUDIENCE", config.JwtAudience);
        config.EnableJwtValidation = GetEnvBool("SECUREAPIS_ENABLE_JWT_VALIDATION", config.EnableJwtValidation);
        config.ApiKeys = GetEnvStringList("SECUREAPIS_API_KEYS", config.ApiKeys);

        // Input validation
        config.EnableInputValidation = GetEnvBool("SECUREAPIS_ENABLE_INPUT_VALIDATION", config.EnableInputValidation);
        config.EnableSqlInjectionDetection = GetEnvBool("SECUREAPIS_ENABLE_SQL_INJECTION_DETECTION", config.EnableSqlInjectionDetection);
        config.EnableXssDetection = GetEnvBool("SECUREAPIS_ENABLE_XSS_DETECTION", config.EnableXssDetection);
        config.EnableCommandInjectionDetection = GetEnvBool("SECUREAPIS_ENABLE_COMMAND_INJECTION_DETECTION", config.EnableCommandInjectionDetection);
        config.EnablePathTraversalDetection = GetEnvBool("SECUREAPIS_ENABLE_PATH_TRAVERSAL_DETECTION", config.EnablePathTraversalDetection);
        config.MaxRequestBodySize = GetEnvInt("SECUREAPIS_MAX_REQUEST_BODY_SIZE", config.MaxRequestBodySize);
        config.MaxUrlLength = GetEnvInt("SECUREAPIS_MAX_URL_LENGTH", config.MaxUrlLength);

        // CORS
        config.EnableCors = GetEnvBool("SECUREAPIS_ENABLE_CORS", config.EnableCors);
        config.AllowedOrigins = GetEnvStringList("SECUREAPIS_ALLOWED_ORIGINS", config.AllowedOrigins);
        config.AllowedMethods = GetEnvStringList("SECUREAPIS_ALLOWED_METHODS", config.AllowedMethods);
        config.AllowedHeaders = GetEnvStringList("SECUREAPIS_ALLOWED_HEADERS", config.AllowedHeaders);

        // Security headers
        config.EnableSecurityHeaders = GetEnvBool("SECUREAPIS_ENABLE_SECURITY_HEADERS", config.EnableSecurityHeaders);
        config.EnableHsts = GetEnvBool("SECUREAPIS_ENABLE_HSTS", config.EnableHsts);
        config.EnableCsp = GetEnvBool("SECUREAPIS_ENABLE_CSP", config.EnableCsp);
        config.CspPolicy = GetEnvString("SECUREAPIS_CSP_POLICY", config.CspPolicy);

        // Threat detection
        config.EnableThreatDetection = GetEnvBool("SECUREAPIS_ENABLE_THREAT_DETECTION", config.EnableThreatDetection);
        config.BlockedIPs = GetEnvStringList("SECUREAPIS_BLOCKED_IPS", config.BlockedIPs);
        config.BlockedUserAgents = GetEnvStringList("SECUREAPIS_BLOCKED_USER_AGENTS", config.BlockedUserAgents);
        config.MaxRequestsPerMinute = GetEnvInt("SECUREAPIS_MAX_REQUESTS_PER_MINUTE", config.MaxRequestsPerMinute);

        // Logging & monitoring
        config.EnableLogging = GetEnvBool("SECUREAPIS_ENABLE_LOGGING", config.EnableLogging);
        config.LogLevel = GetEnvString("SECUREAPIS_LOG_LEVEL", config.LogLevel) ?? config.LogLevel;
        config.EnableMetrics = GetEnvBool("SECUREAPIS_ENABLE_METRICS", config.EnableMetrics);

        // Advanced
        config.StrictMode = GetEnvBool("SECUREAPIS_STRICT_MODE", config.StrictMode);
        config.RequestTimeoutSeconds = GetEnvInt("SECUREAPIS_REQUEST_TIMEOUT_SECONDS", config.RequestTimeoutSeconds);
        config.EnableIpReputation = GetEnvBool("SECUREAPIS_ENABLE_IP_REPUTATION", config.EnableIpReputation);

        return config;
    }

    /// <summary>
    /// Load configuration from ASP.NET Core IConfiguration
    /// </summary>
    public static SecureAPIsConfig FromConfiguration(IConfiguration configuration)
    {
        var config = new SecureAPIsConfig();

        var section = configuration.GetSection("SecureAPIs");
        if (section.Exists())
        {
            section.Bind(config);
        }

        return config;
    }

    /// <summary>
    /// Load configuration with fallback: JSON file -> Environment -> Defaults
    /// </summary>
    public static SecureAPIsConfig Load(string? jsonFilePath = null)
    {
        SecureAPIsConfig config;

        // Try JSON file first
        if (!string.IsNullOrEmpty(jsonFilePath) && File.Exists(jsonFilePath))
        {
            try
            {
                config = FromJsonFile(jsonFilePath);
            }
            catch
            {
                config = new SecureAPIsConfig();
            }
        }
        else
        {
            config = new SecureAPIsConfig();
        }

        // Override with environment variables
        var envConfig = FromEnvironment();

        // Merge configurations (environment takes precedence)
        MergeConfigurations(config, envConfig);

        return config;
    }

    private static void MergeConfigurations(SecureAPIsConfig target, SecureAPIsConfig source)
    {
        // Rate limiting
        if (source.RateLimitRequests != 100) target.RateLimitRequests = source.RateLimitRequests;
        if (source.RateLimitWindowSeconds != 60) target.RateLimitWindowSeconds = source.RateLimitWindowSeconds;
        if (source.EnableRateLimiting != true) target.EnableRateLimiting = source.EnableRateLimiting;

        // Authentication
        if (!string.IsNullOrEmpty(source.JwtSecret)) target.JwtSecret = source.JwtSecret;
        if (!string.IsNullOrEmpty(source.JwtIssuer)) target.JwtIssuer = source.JwtIssuer;
        if (!string.IsNullOrEmpty(source.JwtAudience)) target.JwtAudience = source.JwtAudience;
        if (source.EnableJwtValidation != false) target.EnableJwtValidation = source.EnableJwtValidation;
        if (source.ApiKeys != null) target.ApiKeys = source.ApiKeys;

        // Input validation
        if (source.EnableInputValidation != true) target.EnableInputValidation = source.EnableInputValidation;
        if (source.EnableSqlInjectionDetection != true) target.EnableSqlInjectionDetection = source.EnableSqlInjectionDetection;
        if (source.EnableXssDetection != true) target.EnableXssDetection = source.EnableXssDetection;
        if (source.EnableCommandInjectionDetection != true) target.EnableCommandInjectionDetection = source.EnableCommandInjectionDetection;
        if (source.EnablePathTraversalDetection != true) target.EnablePathTraversalDetection = source.EnablePathTraversalDetection;
        if (source.MaxRequestBodySize != 1048576) target.MaxRequestBodySize = source.MaxRequestBodySize;
        if (source.MaxUrlLength != 2048) target.MaxUrlLength = source.MaxUrlLength;

        // CORS
        if (source.EnableCors != false) target.EnableCors = source.EnableCors;
        if (source.AllowedOrigins != null) target.AllowedOrigins = source.AllowedOrigins;
        if (source.AllowedMethods != null) target.AllowedMethods = source.AllowedMethods;
        if (source.AllowedHeaders != null) target.AllowedHeaders = source.AllowedHeaders;

        // Security headers
        if (source.EnableSecurityHeaders != true) target.EnableSecurityHeaders = source.EnableSecurityHeaders;
        if (source.EnableHsts != true) target.EnableHsts = source.EnableHsts;
        if (source.EnableCsp != false) target.EnableCsp = source.EnableCsp;
        if (!string.IsNullOrEmpty(source.CspPolicy)) target.CspPolicy = source.CspPolicy;

        // Threat detection
        if (source.EnableThreatDetection != true) target.EnableThreatDetection = source.EnableThreatDetection;
        if (source.BlockedIPs != null) target.BlockedIPs = source.BlockedIPs;
        if (source.BlockedUserAgents != null) target.BlockedUserAgents = source.BlockedUserAgents;
        if (source.MaxRequestsPerMinute != 60) target.MaxRequestsPerMinute = source.MaxRequestsPerMinute;

        // Logging & monitoring
        if (source.EnableLogging != true) target.EnableLogging = source.EnableLogging;
        if (source.LogLevel != "Info") target.LogLevel = source.LogLevel;
        if (source.EnableMetrics != true) target.EnableMetrics = source.EnableMetrics;

        // Advanced
        if (source.StrictMode != false) target.StrictMode = source.StrictMode;
        if (source.RequestTimeoutSeconds != 30) target.RequestTimeoutSeconds = source.RequestTimeoutSeconds;
        if (source.EnableIpReputation != false) target.EnableIpReputation = source.EnableIpReputation;
    }

    private static int GetEnvInt(string key, int defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(key);
        return int.TryParse(value, out var result) ? result : defaultValue;
    }

    private static bool GetEnvBool(string key, bool defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(key);
        return bool.TryParse(value, out var result) ? result : defaultValue;
    }

    private static string? GetEnvString(string key, string? defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(key);
        return string.IsNullOrEmpty(value) ? defaultValue : value;
    }

    private static List<string>? GetEnvStringList(string key, List<string>? defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrEmpty(value))
            return defaultValue;

        return value.Split(',', StringSplitOptions.RemoveEmptyEntries)
                   .Select(s => s.Trim())
                   .ToList();
    }
}

/// <summary>
/// Internal result structure for P/Invoke marshaling
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SecurityCheckResultInternal
{
    public int Allowed;
    public int StatusCode;
    public IntPtr ErrorMessage;
    public IntPtr HeadersJson;
}

/// <summary>
/// Main SecureAPIs class with P/Invoke bindings to Rust
/// </summary>
public class SecureAPIs : IDisposable
{
    private IntPtr _securityLayer;
    private bool _disposed = false;

    static SecureAPIs()
    {
        // Set the DLL directory to ensure the native library is found
        string assemblyDir = Path.GetDirectoryName(typeof(SecureAPIs).Assembly.Location) ?? AppContext.BaseDirectory;
        string dllDir = Path.Combine(assemblyDir, "runtimes", "win-x64", "native");
        if (Directory.Exists(dllDir))
        {
            SetDllDirectory(dllDir);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    // P/Invoke declarations
    [DllImport("C:\\projects\\secureapis\\bindings\\csharp\\runtimes\\win-x64\\native\\secureapis.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "secureapis_create_config")]
    private static extern IntPtr secureapis_create_config(IntPtr configJson);

    [DllImport("C:\\projects\\secureapis\\bindings\\csharp\\runtimes\\win-x64\\native\\secureapis.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "secureapis_check_request")]
    private static extern IntPtr secureapis_check_request(
        IntPtr securityLayer,
        IntPtr method,
        IntPtr url,
        IntPtr headersJson,
        IntPtr body,
        IntPtr ip);

    [DllImport("C:\\projects\\secureapis\\bindings\\csharp\\runtimes\\win-x64\\native\\secureapis.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "secureapis_free_security_layer")]
    private static extern void secureapis_free_security_layer(IntPtr securityLayer);

    [DllImport("C:\\projects\\secureapis\\bindings\\csharp\\runtimes\\win-x64\\native\\secureapis.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "secureapis_free_result")]
    private static extern void secureapis_free_result(IntPtr result);

    [DllImport("C:\\projects\\secureapis\\bindings\\csharp\\runtimes\\win-x64\\native\\secureapis.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "secureapis_free_string")]
    private static extern void secureapis_free_string(IntPtr str);

    /// <summary>
    /// Create a new SecureAPIs instance with configuration
    /// </summary>
    public SecureAPIs(SecureAPIsConfig config)
    {
        var configJson = JsonSerializer.Serialize(config);
        var configJsonPtr = Marshal.StringToHGlobalAnsi(configJson);

        try
        {
            _securityLayer = secureapis_create_config(configJsonPtr);
            if (_securityLayer == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create SecureAPIs security layer");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(configJsonPtr);
        }
    }

    /// <summary>
    /// Check if a request is allowed by security rules
    /// </summary>
    public SecurityCheckResult CheckRequest(HttpRequest request)
    {
        // Extract request data
        var method = request.Method;
        var url = request.Path + request.QueryString;
        var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";

        // Extract headers as JSON
        var headers = new Dictionary<string, string>();
        foreach (var header in request.Headers)
        {
            headers[header.Key] = header.Value.ToString();
        }
        var headersJson = JsonSerializer.Serialize(headers);

        // Read body if present
        string body = "";
        if (request.ContentLength > 0 && request.Body != null)
        {
            // Reset position to beginning in case it was read before
            if (request.Body.CanSeek)
            {
                request.Body.Position = 0;
            }

            using var reader = new StreamReader(request.Body);
            body = reader.ReadToEnd();
        }

        // Convert to pointers
        var methodPtr = Marshal.StringToHGlobalAnsi(method);
        var urlPtr = Marshal.StringToHGlobalAnsi(url);
        var headersJsonPtr = Marshal.StringToHGlobalAnsi(headersJson);
        var bodyPtr = Marshal.StringToHGlobalAnsi(body);
        var ipPtr = Marshal.StringToHGlobalAnsi(ip);

        IntPtr resultPtr = IntPtr.Zero;

        try
        {
            resultPtr = secureapis_check_request(
                _securityLayer,
                methodPtr,
                urlPtr,
                headersJsonPtr,
                bodyPtr,
                ipPtr);

            if (resultPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Security check failed");
            }

            var result = Marshal.PtrToStructure<SecurityCheckResultInternal>(resultPtr);

            return new SecurityCheckResult
            {
                Allowed = result.Allowed == 1,
                StatusCode = result.StatusCode,
                ErrorMessage = result.ErrorMessage != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(result.ErrorMessage)
                    : null,
                HeadersJson = result.HeadersJson != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(result.HeadersJson)
                    : null
            };
        }
        finally
        {
            // Free allocated strings
            Marshal.FreeHGlobal(methodPtr);
            Marshal.FreeHGlobal(urlPtr);
            Marshal.FreeHGlobal(headersJsonPtr);
            Marshal.FreeHGlobal(bodyPtr);
            Marshal.FreeHGlobal(ipPtr);

            // Free result if allocated
            if (resultPtr != IntPtr.Zero)
            {
                secureapis_free_result(resultPtr);
            }
        }
    }

    /// <summary>
    /// Dispose of the SecureAPIs instance
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (_securityLayer != IntPtr.Zero)
            {
                secureapis_free_security_layer(_securityLayer);
                _securityLayer = IntPtr.Zero;
            }
            _disposed = true;
        }
    }

    ~SecureAPIs()
    {
        Dispose(false);
    }
}

/// <summary>
/// Result of a security check operation
/// </summary>
public class SecurityCheckResult
{
    /// <summary>
    /// Whether the request is allowed
    /// </summary>
    public bool Allowed { get; set; }

    /// <summary>
    /// HTTP status code to return if blocked
    /// </summary>
    public int StatusCode { get; set; }

    /// <summary>
    /// Error message if request is blocked
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Additional headers to add (JSON)
    /// </summary>
    public string? HeadersJson { get; set; }
}