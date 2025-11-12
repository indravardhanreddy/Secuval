# SecureAPIs C# Bindings - Usage Guide

This guide shows how to use SecureAPIs in your .NET Core/ASP.NET Core applications.

## Installation

### Option 1: Build from Source

1. **Clone and build the Rust library:**
```bash
git clone https://github.com/secureapis/secureapis.git
cd secureapis
.\build_csharp_bindings.bat
```

2. **Reference the built DLL in your project:**
```xml
<ItemGroup>
  <Reference Include="..\secureapis\bindings\csharp\bin\Release\net6.0\SecureAPIs.dll" />
</ItemGroup>
```

### Option 2: NuGet Package (Future)

Once published to NuGet:
```bash
dotnet add package SecureAPIs
```

## Basic Usage

### 1. Configure Services

In `Program.cs` or `Startup.cs`:

```csharp
using SecureAPIs;

var builder = WebApplication.CreateBuilder(args);

// Configure SecureAPIs
builder.Services.Configure<SecureAPIsConfig>(config =>
{
    config.RateLimitRequests = 100;        // 100 requests
    config.RateLimitWindowSeconds = 60;    // per 60 seconds
    config.JwtSecret = "your-jwt-secret";  // For JWT validation
    config.EnableInputValidation = true;   // SQL injection, XSS protection
    config.EnableSecurityHeaders = true;   // Add security headers
});

var app = builder.Build();
```

### 2. Add Middleware to Pipeline

```csharp
// Add SecureAPIs middleware (recommended: early in pipeline)
app.UseSecureAPIs();

// Your other middleware
app.UseRouting();
app.UseAuthorization();

app.MapGet("/api/data", () => "Hello, secure world!");
```

## Advanced Configuration

### Custom Configuration

```csharp
app.UseSecureAPIs(config =>
{
    config.RateLimitRequests = 1000;
    config.RateLimitWindowSeconds = 300;  // 5 minutes
    config.JwtSecret = builder.Configuration["JwtSecret"];
    config.EnableCors = true;
    config.EnableInputValidation = true;
});
```

### Environment-Based Configuration

```csharp
// appsettings.json
{
  "SecureAPIs": {
    "RateLimitRequests": 500,
    "RateLimitWindowSeconds": 60,
    "JwtSecret": "your-secret-key",
    "EnableInputValidation": true,
    "EnableSecurityHeaders": true
  }
}

// Program.cs
builder.Services.Configure<SecureAPIsConfig>(
    builder.Configuration.GetSection("SecureAPIs"));
```

## Complete Example

### Program.cs

```csharp
using SecureAPIs;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();

// Configure SecureAPIs
builder.Services.Configure<SecureAPIsConfig>(config =>
{
    config.RateLimitRequests = 100;
    config.RateLimitWindowSeconds = 60;
    config.JwtSecret = "your-super-secret-jwt-key";
    config.EnableInputValidation = true;
    config.EnableSecurityHeaders = true;
});

var app = builder.Build();

// Security middleware (add early)
app.UseSecureAPIs();

// Other middleware
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthorization();

app.MapControllers();

app.Run();
```

### Controller Example

```csharp
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet]
    public IActionResult GetUsers()
    {
        // SecureAPIs has already:
        // ✓ Checked rate limits
        // ✓ Validated JWT token (if present)
        // ✓ Added security headers
        // ✓ Scanned for threats

        return Ok(new[] {
            new { id = 1, name = "John Doe" },
            new { id = 2, name = "Jane Smith" }
        });
    }

    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        // SecureAPIs has already:
        // ✓ Validated input (SQL injection, XSS)
        // ✓ Checked request size
        // ✓ Scanned for malicious patterns

        // Your business logic here
        return Created($"/api/users/1", new { id = 1, name = request.Name });
    }
}

public class CreateUserRequest
{
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
}
```

## Dynamic Configuration (NEW)

SecureAPIs now supports multiple configuration sources for maximum flexibility:

### Configuration Sources (in order of precedence)

1. **Environment Variables** (highest precedence)
2. **JSON Configuration File**
3. **ASP.NET Core IConfiguration**
4. **Code-based Configuration** (lowest precedence)

### JSON Configuration File

Create a `secureapis.config.json` file in your application directory:

```json
{
  "rateLimitRequests": 100,
  "rateLimitWindowSeconds": 60,
  "enableRateLimiting": true,
  "enableInputValidation": true,
  "enableSqlInjectionDetection": true,
  "enableXssDetection": true,
  "enableThreatDetection": true,
  "enableSecurityHeaders": true,
  "enableLogging": true,
  "logLevel": "Info"
}
```

#### Usage in ASP.NET Core

```csharp
// Option 1: Load from JSON file
app.UseSecureAPIs("secureapis.config.json");

// Option 2: Load from default location (secureapis.config.json in app directory)
app.UseSecureAPIs();
```

### Environment Variables

Set environment variables with the `SECUREAPIS_` prefix:

```bash
# Rate limiting
export SECUREAPIS_RATE_LIMIT_REQUESTS=50
export SECUREAPIS_RATE_LIMIT_WINDOW_SECONDS=30
export SECUREAPIS_ENABLE_RATE_LIMITING=true

# Authentication
export SECUREAPIS_JWT_SECRET="your-secret"
export SECUREAPIS_ENABLE_JWT_VALIDATION=true
export SECUREAPIS_API_KEYS="key1,key2,key3"

# Threat detection
export SECUREAPIS_BLOCKED_IPS="192.168.1.100,10.0.0.1"
export SECUREAPIS_ENABLE_THREAT_DETECTION=true
```

### ASP.NET Core Configuration

Configure via `appsettings.json`:

```json
{
  "SecureAPIs": {
    "rateLimitRequests": 200,
    "enableRateLimiting": true,
    "enableInputValidation": true,
    "blockedIPs": ["192.168.1.100"]
  }
}
```

#### Usage in ASP.NET Core

```csharp
// Load from IConfiguration
app.UseSecureAPIs(Configuration);
```

### Configuration Priority

When multiple configuration sources are used, they are merged in this order:

1. **Environment Variables** override everything
2. **JSON File** settings are used where environment variables don't specify
3. **IConfiguration** settings fill in remaining gaps
4. **Code-based** configuration provides defaults

### Complete Dynamic Configuration Example

```csharp
// Program.cs or Startup.cs
using SecureAPIs;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();

var app = builder.Build();

// Configure SecureAPIs with multiple sources
// 1. Load from JSON file if it exists
// 2. Override with environment variables
// 3. Use ASP.NET Core configuration as fallback
app.UseSecureAPIs("secureapis.config.json");

app.UseAuthorization();
app.MapControllers();

app.Run();
```

### All Configuration Properties

#### Rate Limiting
- `rateLimitRequests`: Maximum requests per window (default: 100)
- `rateLimitWindowSeconds`: Time window in seconds (default: 60)
- `enableRateLimiting`: Enable/disable rate limiting (default: true)

#### Authentication
- `jwtSecret`: JWT signing secret
- `jwtIssuer`: JWT issuer claim
- `jwtAudience`: JWT audience claim
- `enableJwtValidation`: Enable JWT validation (default: false)
- `apiKeys`: List of valid API keys

#### Input Validation
- `enableInputValidation`: Enable input validation (default: true)
- `enableSqlInjectionDetection`: Detect SQL injection (default: true)
- `enableXssDetection`: Detect XSS attacks (default: true)
- `enableCommandInjectionDetection`: Detect command injection (default: true)
- `enablePathTraversalDetection`: Detect path traversal (default: true)
- `maxRequestBodySize`: Maximum request body size in bytes (default: 1MB)
- `maxUrlLength`: Maximum URL length (default: 2048)

#### CORS
- `enableCors`: Enable CORS validation (default: false)
- `allowedOrigins`: List of allowed origins
- `allowedMethods`: List of allowed HTTP methods
- `allowedHeaders`: List of allowed headers

#### Security Headers
- `enableSecurityHeaders`: Add security headers (default: true)
- `enableHsts`: Enable HSTS header (default: true)
- `enableCsp`: Enable Content Security Policy (default: false)
- `cspPolicy`: Custom CSP policy string

#### Threat Detection
- `enableThreatDetection`: Enable threat detection (default: true)
- `blockedIPs`: List of blocked IP addresses
- `blockedUserAgents`: List of blocked user agents
- `maxRequestsPerMinute`: Maximum requests per minute (default: 60)

#### Logging & Monitoring
- `enableLogging`: Enable logging (default: true)
- `logLevel`: Log level (Info, Debug, Warn, Error)
- `enableMetrics`: Enable metrics collection (default: true)

#### Advanced
- `strictMode`: Enable strict security mode (default: false)
- `requestTimeoutSeconds`: Request timeout in seconds (default: 30)
- `enableIpReputation`: Enable IP reputation checking (default: false)

### Rate Limiting
- **Config:** `RateLimitRequests` and `RateLimitWindowSeconds`
- **Behavior:** Returns 429 when exceeded
- **Scope:** Per IP address

### JWT Authentication
- **Config:** `JwtSecret`
- **Behavior:** Validates Authorization header
- **Response:** 401 for invalid/missing tokens

### Input Validation
- **Config:** `EnableInputValidation`
- **Checks:** SQL injection, XSS, command injection
- **Response:** 400 for malicious input

### Security Headers
- **Config:** `EnableSecurityHeaders`
- **Headers:** `X-Content-Type-Options`, `X-Frame-Options`, etc.
- **Behavior:** Added to all responses

### Threat Detection
- **Automatic:** Pattern matching for known attacks
- **Response:** 403 for detected threats

## Error Responses

When SecureAPIs blocks a request, it returns JSON:

```json
// Rate limit exceeded
{
  "error": "Rate limit exceeded. Retry after 60 seconds",
  "statusCode": 429
}

// Invalid input
{
  "error": "Invalid input: Potential SQL injection detected",
  "statusCode": 400
}

// Authentication failed
{
  "error": "Invalid JWT token",
  "statusCode": 401
}
```

## Performance

- **Overhead:** ~50-100 microseconds per request
- **Memory:** ~50MB for the security engine
- **CPU:** Minimal additional load
- **Scaling:** Handles thousands of requests/second

## Troubleshooting

### "Unable to load DLL 'secureapis'"
- Ensure the DLL is in the output directory
- Check that you're using the correct platform (x64)

### "AccessViolationException"
- Check that strings passed to FFI are properly null-terminated
- Ensure the Rust library was built with the same configuration

### Rate limiting not working
- Verify `RateLimitRequests` and `RateLimitWindowSeconds` are set
- Check that requests are coming from different IP addresses

### JWT validation failing
- Ensure `JwtSecret` matches your token signing key
- Check that tokens are sent in `Authorization: Bearer <token>` header

## Building for Production

### Windows
```bash
# Build release version
cargo build --release --target x86_64-pc-windows-msvc
```

### Linux
```bash
# Cross-compile for Linux
cargo build --release --target x86_64-unknown-linux-gnu
```

### macOS
```bash
# Cross-compile for macOS
cargo build --release --target x86_64-apple-darwin
```

## Contributing

To contribute to the C# bindings:

1. Make changes to `bindings/csharp/`
2. Test with a sample ASP.NET Core app
3. Submit a pull request

## License

MIT License - see LICENSE file for details.